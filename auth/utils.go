package auth

import (
	// "encoding/base64"

	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"
)

func GetRandomInt(max int) int {
	source := rand.NewSource(time.Now().UnixNano())
	r := rand.New(source)
	randomNum := r.Intn(max) + 1
	return randomNum
}

func GenUniqueSessionKey(userOrStaticKey, password, clientIp string, nanoKey string) string {
	base64Str := base64.StdEncoding.EncodeToString([]byte(userOrStaticKey + password + clientIp + publicIp))

	base64Str = strings.ReplaceAll(base64Str, "+", "A")
	base64Str = strings.ReplaceAll(base64Str, "/", "B")
	base64Str = strings.TrimRight(base64Str, "=")

	return base64Str + nanoKey
}

func GetClientIpFromRemoteAddr(remoteAddr net.Addr) string {
	addr := remoteAddr.String()
	addr = strings.ReplaceAll(addr, "::ffff:", "")
	addr = strings.Split(addr, ":")[0]

	return addr
}

func GetClientIpFromRequest(r *http.Request) string {
	addr := r.Header.Get("X-FORWARDED-FOR")
	if addr == "" {
		addr = r.RemoteAddr
	}

	addr = strings.ReplaceAll(addr, "::ffff:", "")
	addr = strings.Split(addr, ":")[0]

	return addr
}

// Auth ساختار احراز هویت
type ClientWorkerData struct {
	Key      string
	Traffic  int64
	Identity string
	Password string
	ClientIp string
	Path     string
}

func SleepRandom(min int, max int) {
	randomDuration := time.Duration(min+rand.Intn(max-min)) * time.Millisecond
	time.Sleep(randomDuration)
}

func GetAuthFromReq(req *http.Request) (ClientWorkerData, error) {
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	partsLength := len(parts)

	var nanoKey = ""

	if partsLength <= 1 || partsLength >= 4 {
		return ClientWorkerData{}, errors.New("invalid format. The string should be in the format '/user/pass/nano_key'")
	}

	var originalPath = req.URL.Path
	req.URL.Path = "/"

	if partsLength == 3 {
		nanoKey = parts[2]

		if len(nanoKey) > 16 {
			nanoKey = "0"
			req.URL.Path = "/" + strings.Join(parts[2:], "/")
		} else if partsLength > 3 {
			req.URL.Path = "/" + strings.Join(parts[3:], "/")
		}
	}

	var clientIp = GetClientIpFromRequest(req)

	// استخراج کاربر و رمز عبور از بخش‌های URL
	return ClientWorkerData{
		Identity: parts[0],
		Password: parts[1],
		Key:      GenUniqueSessionKey(parts[0], parts[1], clientIp, nanoKey),
		ClientIp: clientIp,
		Traffic:  0,
		Path:     originalPath,
	}, nil
}

var publicIp string

func GetPublicIp() string {

	if publicIp != "" {
		return publicIp
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error:", err)
		return "127.0.0.1"
	}

	for _, iface := range interfaces {
		// چک می‌کنیم که اینترفیس UP و نه Loopback باشد
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 &&
			!strings.HasPrefix(iface.Name, "tap") && !strings.HasPrefix(iface.Name, "tun") &&
			!strings.HasPrefix(iface.Name, "veth") && !strings.HasPrefix(iface.Name, "br-") &&
			!strings.HasPrefix(iface.Name, "docker") && !strings.HasPrefix(iface.Name, "lo") {
			addrs, err := iface.Addrs()
			if err != nil {
				fmt.Println("Error:", err)
				continue
			}

			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}

				if ip != nil && ip.To4() != nil && !ip.IsLoopback() &&
					!strings.HasPrefix(ip.String(), "192.168.") &&
					!strings.HasPrefix(ip.String(), "10.") &&
					!strings.HasPrefix(ip.String(), "169.254.") &&
					!strings.HasPrefix(ip.String(), "172.") {
					fmt.Println("Server Public IP:", ip.String())
					publicIp = ip.String()
					return ip.String()
				}
			}
		}
	}

	return "127.0.0.1"
}
