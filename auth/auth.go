package auth

import (
	"context"
	// "os"
	"sync"
	"time"

	"github.com/coocood/freecache"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2868"

	logger "github.com/xtls/xray-core/common/errors"
)

const AuthError string = "Bad request: authentication error"

const radiusTTL = 60 * 60 // 60 minutes
const blockTTL = 10 * 60  // 10 minutes

type Authenticator struct {
	// The target address: ws://host:port/path
	remoteAddr    string
	blockedKeys   *freecache.Cache //cache keys that are blocked
	radiusKeys    *freecache.Cache //cache radius accepts for keys
	inAuthKeys    *sync.Map
	radiusSecret  []byte
	radiusAddr    string
	sessions      *sync.Map
	trafficMap    *sync.Map
	trafficChan   chan ClientWorkerData
	authorizeChan chan ClientWorkerData
	sockets       map[string]map[string]bool
	socketsChan   chan SocketWorkerData
	blockedIPs    *freecache.Cache // cache for blocked IPs
	rejectCounts  *freecache.Cache // cache for reject counts per IP
}

type Session struct {
	Key       string `json:"key"`
	Identity  string `json:"identity"`
	ClientIp  string `json:"clientIp"`
	ServerIp  string `json:"serverIp"`
	CreatedAt int64  `json:"createdAt"`
	LastSync  int64  `json:"lastSync"`
	Traffic   int64  `json:"traffic"`
}

type SocketWorkerData struct {
	key        string
	remoteAddr string //unique ip:port combination for each connection
	count      int
}

type DisconnectData struct {
	Key string `json:"key"`
}

var (
	authenticator    *Authenticator
	resolvedRadiusIP string
)

func InitAuthenticator() {
	authenticator = &Authenticator{
		// logger:        log.New(os.Stderr, "", log.LstdFlags),
		blockedKeys:   freecache.NewCache(15 * 1024 * 1024),
		radiusKeys:    freecache.NewCache(15 * 1024 * 1024),
		inAuthKeys:    &sync.Map{},
		radiusSecret:  []byte("Mkn@123456"),
		radiusAddr:    "radius.vitapin.top:1812",
		sessions:      &sync.Map{},
		authorizeChan: make(chan ClientWorkerData, 10000), // Increased to handle more authorization requests
		trafficMap:    &sync.Map{},
		trafficChan:   make(chan ClientWorkerData, 30000), // Increased to handle more traffic
		sockets:       make(map[string]map[string]bool),
		socketsChan:   make(chan SocketWorkerData, 30000),   // Increased to handle more socket connections
		blockedIPs:    freecache.NewCache(10 * 1024 * 1024), // for IP blocks
		rejectCounts:  freecache.NewCache(10 * 1024 * 1024), // for reject counts
	}

	GetPublicIp() // Initialize the public IP

	go socketsWorker()
	go trafficWorker()
	go radiusWorker()

	//print initialization message
	println("Authenticator initialized")

	InitApi() // Initialize the API
}

func SetRadiusAddr(addr string) {
	if addr != "" {
		authenticator.radiusAddr = addr
	}
}

func socketsWorker() {
	for swData := range authenticator.socketsChan {
		if swData.count < 0 {
			if _, ok := authenticator.sockets[swData.key]; ok {
				if _, ok := authenticator.sockets[swData.key][swData.remoteAddr]; ok {
					//remove socketKey from the map
					delete(authenticator.sockets[swData.key], swData.remoteAddr)
					//if map is empty remove the map
					if len(authenticator.sockets[swData.key]) == 0 {
						delete(authenticator.sockets, swData.key)
					}
				}
			}
		} else {

			if _, ok := authenticator.sockets[swData.key]; !ok {
				authenticator.sockets[swData.key] = make(map[string]bool)
			}

			//add socketKey to the map
			if _, ok := authenticator.sockets[swData.key][swData.remoteAddr]; !ok {
				authenticator.sockets[swData.key][swData.remoteAddr] = true
			}
		}
	}
}

func trafficWorker() {
	for data := range authenticator.trafficChan {
		val, loaded := authenticator.trafficMap.LoadOrStore(data.Key, data.Traffic)
		if loaded {
			authenticator.trafficMap.Store(data.Key, val.(int64)+data.Traffic)
		}
	}
}

func Authenticate(clientData ClientWorkerData) bool {
	if isBlocked(clientData) {
		return false
	}

	if _, error := authenticator.radiusKeys.Get([]byte(clientData.Key)); error == nil {
		return true
	}

	if _, loaded := authenticator.inAuthKeys.LoadOrStore(clientData.Key, 0); !loaded {
		select {
		case authenticator.authorizeChan <- clientData:
			// Successfully added to the queue
		default:
			logger.LogError(context.Background(), "Authorization queue is full")
			//remove from inAuthKeys
			authenticator.inAuthKeys.Delete(clientData.Key)
		}
	}

	return true //we handle radius in background
}

func AddSession(clientData ClientWorkerData) {
	if clientData.Identity != "" && clientData.Key != "" {
		currentUnixTime := time.Now().Unix()
		authenticator.sessions.LoadOrStore(clientData.Key, Session{
			Key:       clientData.Key,
			Identity:  clientData.Identity,
			ClientIp:  clientData.ClientIp,
			ServerIp:  GetPublicIp(),
			CreatedAt: currentUnixTime,
			LastSync:  currentUnixTime,
			Traffic:   0,
		})
	}
}

func UpdateSocketCount(key string, remoteAddr string, count int) {
	authenticator.socketsChan <- SocketWorkerData{
		key:        key,
		remoteAddr: remoteAddr,
		count:      count,
	}
}

func UpdateTraffic(key string, traffic int64) {
	if traffic > 0 {
		select {
		case authenticator.trafficChan <- ClientWorkerData{
			Key:     key,
			Traffic: traffic,
		}:
			// Successfully added to the queue
		default:
			// Queue is full, drop or handle accordingly
			logger.LogError(context.Background(), "Traffic queue is full for key")
		}
	}
}

func radiusWorker() {
	for clientData := range authenticator.authorizeChan {
		radiusClient(clientData)
	}
}

func radiusClient(clientData ClientWorkerData) {
	defer authenticator.inAuthKeys.Delete(clientData.Key)

	if isBlocked(clientData) {
		return
	}

	if _, err := authenticator.radiusKeys.Get([]byte(clientData.Key)); err == nil {
		// AddSession(clientData)
		return // Use radius cache
	}

	packet := radius.New(radius.CodeAccessRequest, authenticator.radiusSecret)
	rfc2865.UserName_SetString(packet, clientData.Identity)
	rfc2865.UserPassword_SetString(packet, clientData.Password)
	rfc2865.NASIdentifier_SetString(packet, clientData.Key)
	rfc2868.TunnelClientEndpoint_SetString(packet, uint8(0), clientData.ClientIp)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	response, err := radius.Exchange(ctx, packet, authenticator.radiusAddr)
	if err != nil {
		logger.LogError(context.Background(), "Radius exchange error :", err.Error())
		return
	}

	switch response.Code {
	case radius.CodeAccessAccept:
		authenticator.radiusKeys.Set([]byte(clientData.Key), []byte("accepted"), radiusTTL)
		authenticator.blockedKeys.Del([]byte(clientData.Key))
		// AddSession(clientData)
	case radius.CodeAccessReject:
		// Count rejects for this IP in 15s window
		ip := clientData.ClientIp
		if ip != "" {
			countBytes, _ := authenticator.rejectCounts.Get([]byte(ip))
			count := 0
			if len(countBytes) == 4 {
				count = bytesToInt(countBytes)
			}
			count++
			//5 * 3 = 15 seconds max , can run fake address maximum 5 times per 15 seconds
			authenticator.rejectCounts.Set([]byte(ip), intToBytes(count), 3)
			if count > 5 {
				authenticator.blockedIPs.Set([]byte(ip), []byte("blocked"), 600) // block for 10min
				logger.LogError(context.Background(), "IP blocked for 10min:", ip)
			}
		}
		newTTL := blockTTL
		if _, err := authenticator.blockedKeys.Get([]byte(clientData.Key)); err == nil {
			newTTL = blockTTL * 3
		}
		authenticator.blockedKeys.Set([]byte(clientData.Key), []byte("blocked"), newTTL)
		logger.LogError(context.Background(), "Radius Reject - Identity: ", clientData.Identity,
			" Path: ", clientData.Path, " ClientIp: ", clientData.ClientIp, " BlockTTL(seconds): ", newTTL)

	default:
		logger.LogError(context.Background(), "Unexpected radius response code for key", clientData.Key, ":", response.Code)
	}
}

// func renewRadiusKey(clientData ClientWorkerData) {
// 	time.AfterFunc(radiusTTL, func() {
// 		if _, ok := authenticator.sessions.Load(clientData.Key); ok {
// 			if !isBlocked(clientData) {
// 				renewRadiusKey(clientData)
// 			}
// 		} else {
// 			authenticator.radiusKeys.Delete(clientData.Key)
// 			cleanupSession(clientData.Key)
// 		}
// 	})
// }

// Checks if a key or IP is blocked
func IsKeyBlocked(key string) bool {
	ttl, err := authenticator.blockedKeys.TTL([]byte(key))
	return err == nil && ttl > 10
}

func isIPBlocked(clientIp string) bool {
	if clientIp == "" {
		return false
	}
	_, err := authenticator.blockedIPs.Get([]byte(clientIp))
	return err == nil
}

func isBlocked(clientData ClientWorkerData) bool {
	return IsKeyBlocked(clientData.Key) || isIPBlocked(clientData.ClientIp)
}

// Converts int to byte slice (big endian, 4 bytes)
func intToBytes(n int) []byte {
	b := make([]byte, 4)
	b[0] = byte(n >> 24)
	b[1] = byte(n >> 16)
	b[2] = byte(n >> 8)
	b[3] = byte(n)
	return b
}

// Converts 4-byte slice to int (big endian)
func bytesToInt(b []byte) int {
	if len(b) != 4 {
		return 0
	}
	return int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
}
