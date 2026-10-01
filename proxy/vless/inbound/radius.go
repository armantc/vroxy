package inbound

import (
	"context"
	"crypto/md5"
	cryptorand "crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	stdnet "net"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	radiusCodeAccessRequest    = 1
	radiusAccessAccept         = 2
	radiusAccessReject         = 3
	radiusUserName             = 1
	radiusUserPassword         = 2
	radiusNASIdentifier        = 32
	radiusTunnelClientEndpoint = 66
	radiusTunnelServerEndpoint = 67
	radiusMaxConcurrentAuth    = 256
	radiusMaxCachedStates      = 65536
	radiusAPIAddress           = "127.0.0.1:8585"
	radiusSessionsPath         = "/api/sessions"
	radiusDisconnectPath       = "/api/disconnect"
	radiusReleasePath          = "/api/release"
)

type radiusAccessRequester func(server, secret, userName, nasIdentifier, clientIP, publicIP string, timeout time.Duration) (bool, error)

// radiusValidator admits an unknown UUID once, then caches the RADIUS result.
// This preserves VLESS's non-blocking handshake while preventing a rejected ID
// from opening subsequent connections during the cache period.
type radiusValidator struct {
	vless.Validator
	server, secret, publicIP, flow string
	timeout, cacheTTL              time.Duration
	stateMu                        sync.Mutex
	states                         map[string]*radiusState // keyed by session key
	sessionMu                      sync.Mutex
	blocked                        map[string]time.Time
	sessions                       map[string]map[uint64]*radiusSession
	closedSessions                 map[string]*closedRadiusSession
	nextSessionID                  uint64
	authSlots                      chan struct{}
	stopCleanup                    chan struct{}
	closeOnce                      sync.Once
	closed                         atomic.Bool
	accessRequest                  radiusAccessRequester
}

type radiusState struct {
	expires time.Time
}

func newRadiusValidator(base vless.Validator, c *Config) (*radiusValidator, error) {
	timeout := time.Duration(c.RadiusTimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	cacheTTL := time.Duration(c.RadiusCacheSeconds) * time.Second
	if cacheTTL == 0 {
		cacheTTL = 20 * time.Minute
	}
	v := &radiusValidator{
		Validator:      base,
		server:         c.RadiusServer,
		secret:         c.RadiusSecret,
		publicIP:       c.RadiusPublicIp,
		flow:           c.RadiusFlow,
		timeout:        timeout,
		cacheTTL:       cacheTTL,
		states:         make(map[string]*radiusState),
		blocked:        make(map[string]time.Time),
		sessions:       make(map[string]map[uint64]*radiusSession),
		closedSessions: make(map[string]*closedRadiusSession),
		authSlots:      make(chan struct{}, radiusMaxConcurrentAuth),
		stopCleanup:    make(chan struct{}),
		accessRequest:  radiusAccessRequest,
	}
	if err := radiusControl.register(v); err != nil {
		return nil, err
	}
	go v.cleanupLoop()
	return v, nil
}

func (v *radiusValidator) Get(id uuid.UUID) *protocol.MemoryUser {
	return v.get(id)
}

func (v *radiusValidator) get(id uuid.UUID) *protocol.MemoryUser {
	if user := v.Validator.Get(id); user != nil {
		return user
	}
	return &protocol.MemoryUser{Email: id.String(), Account: &vless.MemoryAccount{ID: protocol.NewID(id), Flow: v.flow}}
}

func (v *radiusValidator) authorizeAsync(id uuid.UUID, key, clientIP, publicIP string) {
	if v.closed.Load() {
		v.disconnect(key)
		return
	}
	now := time.Now()
	pending := &radiusState{expires: now.Add(v.timeout)}
	v.stateMu.Lock()
	if state := v.states[key]; state != nil && now.Before(state.expires) {
		v.stateMu.Unlock()
		return
	}
	if len(v.states) >= radiusMaxCachedStates {
		for cachedKey, state := range v.states {
			if !now.Before(state.expires) {
				delete(v.states, cachedKey)
			}
		}
	}
	if len(v.states) >= radiusMaxCachedStates {
		v.stateMu.Unlock()
		errors.LogWarning(context.Background(), "VLESS RADIUS authorization cache is full; allowing user without a new check: ", id.String())
		return
	}
	v.states[key] = pending
	v.stateMu.Unlock()
	select {
	case v.authSlots <- struct{}{}:
	default:
		if v.deleteStateIfCurrent(key, pending) {
			errors.LogWarning(context.Background(), "VLESS RADIUS authorization queue is full; allowing user without a new check: ", id.String())
		}
		return
	}
	go func() {
		defer func() { <-v.authSlots }()
		// The session key is transported in RADIUS's standard NAS-Identifier
		// attribute; the endpoint attributes retain the real addresses.
		accepted, err := v.accessRequest(v.server, v.secret, id.String(), key, clientIP, publicIP, v.timeout)
		if v.closed.Load() {
			v.deleteStateIfCurrent(key, pending)
			return
		}
		if err != nil {
			if v.deleteStateIfCurrent(key, pending) {
				errors.LogWarning(context.Background(), "VLESS RADIUS request failed for ", id.String(), ": ", err)
			}
			return
		}
		if !v.replaceStateIfCurrent(key, pending, &radiusState{expires: time.Now().Add(v.cacheTTL)}) {
			return
		}
		if !accepted {
			errors.LogInfo(context.Background(), "VLESS RADIUS rejected user ", id.String())
			v.block(key)
		} else {
			errors.LogInfo(context.Background(), "VLESS RADIUS accepted user ", id.String())
		}
	}()
}

func (v *radiusValidator) deleteStateIfCurrent(key string, expected *radiusState) bool {
	v.stateMu.Lock()
	defer v.stateMu.Unlock()
	if v.states[key] != expected {
		return false
	}
	delete(v.states, key)
	return true
}

func (v *radiusValidator) replaceStateIfCurrent(key string, expected, replacement *radiusState) bool {
	v.stateMu.Lock()
	defer v.stateMu.Unlock()
	if v.states[key] != expected {
		return false
	}
	v.states[key] = replacement
	return true
}

func (v *radiusValidator) close() {
	v.closeOnce.Do(func() {
		v.closed.Store(true)
		close(v.stopCleanup)
		radiusControl.unregister(v)
		v.disconnectAll()
	})
}

func (v *radiusValidator) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			v.cleanup(now)
		case <-v.stopCleanup:
			return
		}
	}
}

func (v *radiusValidator) cleanup(now time.Time) {
	v.stateMu.Lock()
	for key, state := range v.states {
		if !now.Before(state.expires) {
			delete(v.states, key)
		}
	}
	v.stateMu.Unlock()
	v.sessionMu.Lock()
	for key, expires := range v.blocked {
		if !now.Before(expires) {
			delete(v.blocked, key)
		}
	}
	for key, closed := range v.closedSessions {
		if len(v.sessions[key]) == 0 && now.Sub(closed.closedAt) >= radiusSessionGrace {
			delete(v.closedSessions, key)
		}
	}
	v.sessionMu.Unlock()
}

func (v *radiusValidator) radiusPublicIP(localIP string) string {
	publicIP := v.publicIP
	if publicIP == "" {
		publicIP = localIP
	}
	return publicIP
}

// sessionKey is a compact, deterministic FNV-1a hash. It is deliberately
// restricted to lowercase hexadecimal so it can safely be used as both the
// local API key and RADIUS's NAS-Identifier.
func (v *radiusValidator) sessionKey(id uuid.UUID, clientIP, publicIP string) string {
	const offset64 = uint64(14695981039346656037)
	const prime64 = uint64(1099511628211)
	hash := uint64(offset64)
	for _, value := range []string{id.String(), clientIP, publicIP} {
		for i := 0; i < len(value); i++ {
			hash ^= uint64(value[i])
			hash *= prime64
		}
		hash ^= 0
		hash *= prime64
	}
	const hex = "0123456789abcdef"
	var encoded [16]byte
	for i := len(encoded) - 1; i >= 0; i-- {
		encoded[i] = hex[hash&0x0f]
		hash >>= 4
	}
	return string(encoded[:])
}

type radiusTrafficConnection struct {
	stdnet.Conn
	read, written radiusCounter
	closeOnce     sync.Once
	callbackMu    sync.Mutex
	onClose       func()
	closed        bool
}

// UnwrapWithCounters lets Vision's direct-copy path reach the original TLS
// transport while continuing to charge copied bytes to this session.
func (c *radiusTrafficConnection) UnwrapWithCounters() (stdnet.Conn, stats.Counter, stats.Counter) {
	return stat.TryUnwrapStatsConn(c.Conn), &c.read, &c.written
}

func (c *radiusTrafficConnection) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, err
}

func (c *radiusTrafficConnection) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(int64(n))
	return n, err
}

func (c *radiusTrafficConnection) setOnClose(callback func()) {
	c.callbackMu.Lock()
	if !c.closed {
		c.onClose = callback
		c.callbackMu.Unlock()
		return
	}
	c.callbackMu.Unlock()
	callback()
}

func (c *radiusTrafficConnection) Close() error {
	err := c.Conn.Close()
	c.notifyClosed()
	return err
}

func (c *radiusTrafficConnection) notifyClosed() {
	c.closeOnce.Do(func() {
		c.callbackMu.Lock()
		c.closed = true
		callback := c.onClose
		c.callbackMu.Unlock()
		if callback != nil {
			callback()
		}
	})
}

type radiusCounter struct{ value atomic.Int64 }

func (c *radiusCounter) Value() int64          { return c.value.Load() }
func (c *radiusCounter) Set(value int64) int64 { return c.value.Swap(value) }
func (c *radiusCounter) Add(value int64) int64 {
	return c.value.Add(value) - value
}

type radiusSession struct {
	conn                              stdnet.Conn
	key, identity, clientIP, serverIP string
	createdAt                         time.Time
	traffic                           *radiusTrafficConnection
	readAtStart, writtenAtStart       int64
}

type closedRadiusSession struct {
	Session
	closedAt time.Time
}

const radiusSessionGrace = 5 * time.Second

func (s *radiusSession) response() Session {
	upload := s.traffic.read.Value() - s.readAtStart
	download := s.traffic.written.Value() - s.writtenAtStart
	return Session{Key: s.key, Identity: s.identity, ClientIP: s.clientIP, ServerIP: s.serverIP, CreatedAt: s.createdAt.Unix(), Traffic: upload + download}
}

func (v *radiusValidator) beginSession(key, identity, clientIP, serverIP string, conn stdnet.Conn, traffic *radiusTrafficConnection) (uint64, bool) {
	v.sessionMu.Lock()
	defer v.sessionMu.Unlock()
	if expires, blocked := v.blocked[key]; blocked && time.Now().Before(expires) {
		return 0, false
	} else if blocked {
		delete(v.blocked, key)
	}
	hasActiveSession := len(v.sessions[key]) != 0
	if closed := v.closedSessions[key]; closed != nil && !hasActiveSession && time.Since(closed.closedAt) >= radiusSessionGrace {
		delete(v.closedSessions, key)
	}
	v.nextSessionID++
	id := v.nextSessionID
	if v.sessions[key] == nil {
		v.sessions[key] = make(map[uint64]*radiusSession)
	}
	v.sessions[key][id] = &radiusSession{conn: conn, key: key, identity: identity, clientIP: clientIP, serverIP: serverIP, createdAt: time.Now().UTC(), traffic: traffic, readAtStart: traffic.read.Value(), writtenAtStart: traffic.written.Value()}
	return id, true
}

func (v *radiusValidator) endSession(key string, id uint64) {
	v.sessionMu.Lock()
	defer v.sessionMu.Unlock()
	if sessions := v.sessions[key]; sessions != nil {
		if session, ok := sessions[id]; ok {
			response := session.response()
			key := response.Key
			if closed := v.closedSessions[key]; closed != nil {
				closed.Traffic += response.Traffic
				if response.CreatedAt < closed.CreatedAt {
					closed.CreatedAt = response.CreatedAt
					closed.Key = response.Key
				}
				closed.closedAt = time.Now()
			} else {
				v.closedSessions[key] = &closedRadiusSession{Session: response, closedAt: time.Now()}
			}
			delete(sessions, id)
		}
		if len(sessions) == 0 {
			delete(v.sessions, key)
		}
	}
}

func (v *radiusValidator) block(key string) {
	v.blockFor(key, v.cacheTTL)
}

func (v *radiusValidator) blockFor(key string, duration time.Duration) {
	now := time.Now()
	v.sessionMu.Lock()
	if _, exists := v.blocked[key]; exists || len(v.blocked) < radiusMaxCachedStates {
		v.blocked[key] = now.Add(duration)
	} else {
		for blockedKey, expires := range v.blocked {
			if !now.Before(expires) {
				delete(v.blocked, blockedKey)
			}
		}
		if len(v.blocked) < radiusMaxCachedStates {
			v.blocked[key] = now.Add(duration)
		}
	}
	v.sessionMu.Unlock()
	v.disconnect(key)
}

func (v *radiusValidator) disconnect(key string) {
	v.sessionMu.Lock()
	connections := make([]stdnet.Conn, 0, len(v.sessions[key]))
	for _, session := range v.sessions[key] {
		connections = append(connections, session.conn)
	}
	v.sessionMu.Unlock()
	for _, conn := range connections {
		if conn != nil {
			_ = conn.Close()
		}
	}
}

func (v *radiusValidator) disconnectAll() {
	v.sessionMu.Lock()
	connections := make([]stdnet.Conn, 0)
	for _, sessions := range v.sessions {
		for _, session := range sessions {
			connections = append(connections, session.conn)
		}
	}
	v.sessionMu.Unlock()
	for _, conn := range connections {
		if conn != nil {
			_ = conn.Close()
		}
	}
}

type Session struct {
	Key       string `json:"key"`
	Identity  string `json:"identity"`
	ClientIP  string `json:"clientIp"`
	ServerIP  string `json:"serverIp"`
	CreatedAt int64  `json:"createdAt"`
	Traffic   int64  `json:"traffic"`
	LastSync  int64  `json:"lastSync"`
}

func (v *radiusValidator) activeSessions() []Session {
	v.sessionMu.Lock()
	defer v.sessionMu.Unlock()
	aggregated := make(map[string]Session)
	active := make(map[string]bool)
	for _, sessions := range v.sessions {
		for _, session := range sessions {
			response := session.response()
			key := response.Key
			active[key] = true
			mergeRadiusSession(aggregated, key, response)
		}
	}
	now := time.Now()
	for key, closed := range v.closedSessions {
		if !active[key] && now.Sub(closed.closedAt) >= radiusSessionGrace {
			delete(v.closedSessions, key)
			continue
		}
		mergeRadiusSession(aggregated, key, closed.Session)
	}
	result := make([]Session, 0, len(aggregated))
	for _, session := range aggregated {
		result = append(result, session)
	}
	return result
}

func mergeRadiusSession(sessions map[string]Session, key string, response Session) {
	if current, ok := sessions[key]; ok {
		current.Traffic += response.Traffic
		if response.CreatedAt < current.CreatedAt {
			current.CreatedAt = response.CreatedAt
			current.Key = response.Key
		}
		sessions[key] = current
	} else {
		sessions[key] = response
	}
}

func (v *radiusValidator) release(key string) {
	v.stateMu.Lock()
	delete(v.states, key)
	v.stateMu.Unlock()
	v.sessionMu.Lock()
	delete(v.blocked, key)
	v.sessionMu.Unlock()
}

type radiusControlAPI struct {
	mu         sync.RWMutex
	validators map[*radiusValidator]struct{}
	once       sync.Once
	startErr   error
}

var radiusControl = radiusControlAPI{validators: make(map[*radiusValidator]struct{})}

func (a *radiusControlAPI) register(v *radiusValidator) error {
	a.once.Do(func() {
		listener, err := stdnet.Listen("tcp", radiusAPIAddress)
		if err != nil {
			a.startErr = err
			return
		}
		server := &http.Server{
			Handler:           http.HandlerFunc(a.serveHTTP),
			ReadHeaderTimeout: 3 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
		go func() {
			if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
				errors.LogError(context.Background(), "VLESS RADIUS control API stopped: ", err)
			}
		}()
	})
	if a.startErr != nil {
		return a.startErr
	}
	a.mu.Lock()
	a.validators[v] = struct{}{}
	a.mu.Unlock()
	return nil
}

func (a *radiusControlAPI) unregister(v *radiusValidator) {
	a.mu.Lock()
	delete(a.validators, v)
	a.mu.Unlock()
}

func (a *radiusControlAPI) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == radiusSessionsPath {
		a.writeSessions(w)
		return
	}
	if r.Method != http.MethodPost || (r.URL.Path != radiusDisconnectPath && r.URL.Path != radiusReleasePath) {
		http.NotFound(w, r)
		return
	}
	defer r.Body.Close()
	var request struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&request); err != nil || request.Key == "" {
		http.Error(w, "JSON body must contain key", http.StatusBadRequest)
		return
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	for validator := range a.validators {
		if r.URL.Path == radiusDisconnectPath {
			validator.block(request.Key)
		} else {
			validator.release(request.Key)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (a *radiusControlAPI) writeSessions(w http.ResponseWriter) {
	lastSync := time.Now().Unix()
	a.mu.RLock()
	sessions := make([]Session, 0)
	for validator := range a.validators {
		sessions = append(sessions, validator.activeSessions()...)
	}
	a.mu.RUnlock()
	aggregated := make(map[string]Session)
	for _, session := range sessions {
		key := session.Key
		if current, ok := aggregated[key]; ok {
			current.Traffic += session.Traffic
			if session.CreatedAt < current.CreatedAt {
				current.CreatedAt = session.CreatedAt
				current.Key = session.Key
			}
			aggregated[key] = current
		} else {
			aggregated[key] = session
		}
	}
	sessions = sessions[:0]
	for _, session := range aggregated {
		session.LastSync = lastSync
		sessions = append(sessions, session)
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].CreatedAt < sessions[j].CreatedAt })
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sessions)
}

func radiusAccessRequest(server, secret, userName, nasIdentifier, clientIP, publicIP string, timeout time.Duration) (bool, error) {
	conn, err := stdnet.DialTimeout("udp", server, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var requestAuth [16]byte
	if _, err := cryptorand.Read(requestAuth[:]); err != nil {
		return false, err
	}
	attrs := append(radiusAttribute(radiusUserName, userName), radiusUserPasswordAttribute("*", secret, requestAuth)...)
	attrs = append(attrs, radiusAttribute(radiusNASIdentifier, nasIdentifier)...)
	attrs = append(attrs, radiusTaggedAttribute(radiusTunnelClientEndpoint, 0, clientIP)...)
	attrs = append(attrs, radiusTaggedAttribute(radiusTunnelServerEndpoint, 0, publicIP)...)
	packet := make([]byte, 20+len(attrs))
	packet[0] = radiusCodeAccessRequest
	if _, err := cryptorand.Read(packet[1:2]); err != nil {
		return false, err
	}
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[4:20], requestAuth[:])
	copy(packet[20:], attrs)
	if _, err := conn.Write(packet); err != nil {
		return false, err
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return false, err
	}
	response = response[:n]
	if n < 20 || int(binary.BigEndian.Uint16(response[2:4])) != n || response[1] != packet[1] {
		return false, fmt.Errorf("invalid RADIUS response")
	}
	h := md5.New()
	_, _ = h.Write(response[:4])
	_, _ = h.Write(requestAuth[:])
	_, _ = h.Write(response[20:])
	_, _ = h.Write([]byte(secret))
	if subtle.ConstantTimeCompare(h.Sum(nil), response[4:20]) != 1 {
		return false, fmt.Errorf("invalid RADIUS response authenticator")
	}
	switch response[0] {
	case radiusAccessAccept:
		return true, nil
	case radiusAccessReject:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected RADIUS response code %d", response[0])
	}
}

func radiusAttribute(kind byte, value string) []byte {
	if len(value) > 253 {
		value = value[:253]
	}
	attribute := make([]byte, len(value)+2)
	attribute[0], attribute[1] = kind, byte(len(attribute))
	copy(attribute[2:], value)
	return attribute
}

// Tunnel endpoint attributes are tagged strings (RFC 2868, sections 3.1/3.2).
func radiusTaggedAttribute(kind, tag byte, value string) []byte {
	if len(value) > 252 {
		value = value[:252]
	}
	attribute := make([]byte, len(value)+3)
	attribute[0], attribute[1], attribute[2] = kind, byte(len(attribute)), tag
	copy(attribute[3:], value)
	return attribute
}

// radiusUserPasswordAttribute encodes User-Password per RFC 2865 section 5.2.
// The caller uses "*" as the password required by this RADIUS integration.
func radiusUserPasswordAttribute(password, secret string, requestAuth [16]byte) []byte {
	plain := []byte(password)
	length := ((len(plain) + 15) / 16) * 16
	if length == 0 {
		length = 16
	}
	plain = append(plain, make([]byte, length-len(plain))...)
	ciphertext := make([]byte, length)
	previous := requestAuth[:]
	for offset := 0; offset < length; offset += md5.Size {
		hash := md5.New()
		_, _ = hash.Write([]byte(secret))
		_, _ = hash.Write(previous)
		mask := hash.Sum(nil)
		for i := 0; i < md5.Size; i++ {
			ciphertext[offset+i] = plain[offset+i] ^ mask[i]
		}
		previous = ciphertext[offset : offset+md5.Size]
	}
	attribute := make([]byte, len(ciphertext)+2)
	attribute[0], attribute[1] = radiusUserPassword, byte(len(attribute))
	copy(attribute[2:], ciphertext)
	return attribute
}

func hostFromAddr(addr stdnet.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := stdnet.SplitHostPort(addr.String())
	if err == nil {
		return host
	}
	return addr.String()
}
