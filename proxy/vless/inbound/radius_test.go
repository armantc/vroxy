package inbound

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/uuid"
)

func TestRadiusControlDisconnectAndRelease(t *testing.T) {
	validator := &radiusValidator{cacheTTL: time.Minute, blocked: make(map[string]time.Time), sessions: make(map[string]map[uint64]*radiusSession), closedSessions: make(map[string]*closedRadiusSession)}
	control := radiusControlAPI{validators: map[*radiusValidator]struct{}{validator: {}}}
	client, server := net.Pipe()
	defer client.Close()

	nas := "uuid=test;client_ip=192.0.2.1;public_ip=198.51.100.1"
	traffic := &radiusTrafficConnection{Conn: server}
	if _, allowed := validator.beginSession(nas, "test", "192.0.2.1", "198.51.100.1", server, traffic); !allowed {
		t.Fatal("new session unexpectedly blocked")
	}
	request := httptest.NewRequest(http.MethodPost, radiusDisconnectPath, strings.NewReader(`{"key":"`+nas+`"}`))
	response := httptest.NewRecorder()
	control.serveHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("disconnect status = %d", response.Code)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("disconnect did not close active session")
	}
	if _, allowed := validator.beginSession(nas, "test", "192.0.2.1", "198.51.100.1", server, traffic); allowed {
		t.Fatal("blocked NAS-Identifier opened a session")
	}

	request = httptest.NewRequest(http.MethodPost, radiusReleasePath, strings.NewReader(`{"key":"`+nas+`"}`))
	response = httptest.NewRecorder()
	control.serveHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("release status = %d", response.Code)
	}
	if _, allowed := validator.beginSession(nas, "test", "192.0.2.1", "198.51.100.1", server, traffic); !allowed {
		t.Fatal("released NAS-Identifier remained blocked")
	}
}

func TestRadiusSessionsResponseIncludesLastSync(t *testing.T) {
	validator := &radiusValidator{
		blocked:        make(map[string]time.Time),
		sessions:       make(map[string]map[uint64]*radiusSession),
		closedSessions: make(map[string]*closedRadiusSession),
	}
	traffic := &radiusTrafficConnection{}
	if _, allowed := validator.beginSession("key", "identity", "192.0.2.1", "198.51.100.1", nil, traffic); !allowed {
		t.Fatal("new session unexpectedly blocked")
	}
	control := radiusControlAPI{validators: map[*radiusValidator]struct{}{validator: {}}}
	request := httptest.NewRequest(http.MethodGet, radiusSessionsPath, nil)
	response := httptest.NewRecorder()
	before := time.Now().Unix()
	control.serveHTTP(response, request)
	after := time.Now().Unix()

	var sessions []Session
	if err := json.NewDecoder(response.Body).Decode(&sessions); err != nil {
		t.Fatalf("decode sessions response: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %+v, want one session", sessions)
	}
	if got := sessions[0].LastSync; got < before || got > after {
		t.Fatalf("lastSync = %d, want current Unix timestamp between %d and %d", got, before, after)
	}
}

func TestRadiusSessionKey(t *testing.T) {
	validator := &radiusValidator{}
	first := validator.sessionKey([16]byte{1}, "192.0.2.1", "198.51.100.1")
	if first != validator.sessionKey([16]byte{1}, "192.0.2.1", "198.51.100.1") {
		t.Fatal("session key is not deterministic")
	}
	if len(first) != 16 || strings.Trim(first, "0123456789abcdef") != "" {
		t.Fatalf("session key %q is not 16 lowercase hexadecimal characters", first)
	}
	if first == validator.sessionKey([16]byte{2}, "192.0.2.1", "198.51.100.1") {
		t.Fatal("distinct sessions received the same key")
	}
}

func TestRadiusAccessRequestAttributes(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	const secret = "test-secret"
	requestPacket := make(chan []byte, 1)
	serverErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, 4096)
		n, peer, err := listener.ReadFrom(buffer)
		if err != nil {
			serverErr <- err
			return
		}
		request := append([]byte(nil), buffer[:n]...)
		requestPacket <- request
		response := make([]byte, 20)
		response[0], response[1] = radiusAccessAccept, request[1]
		binary.BigEndian.PutUint16(response[2:4], uint16(len(response)))
		hash := md5.New()
		_, _ = hash.Write(response[:4])
		_, _ = hash.Write(request[4:20])
		_, _ = hash.Write([]byte(secret))
		copy(response[4:20], hash.Sum(nil))
		_, err = listener.WriteTo(response, peer)
		serverErr <- err
	}()

	accepted, err := radiusAccessRequest(listener.LocalAddr().String(), secret, "identity", "0123456789abcdef", "192.0.2.1", "198.51.100.1", time.Second)
	if err != nil || !accepted {
		t.Fatalf("RADIUS request: accepted=%v err=%v", accepted, err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	request := <-requestPacket
	attributes := parseRadiusTestAttributes(t, request[20:])
	if got := string(attributes[radiusUserName][0][2:]); got != "identity" {
		t.Fatalf("User-Name = %q", got)
	}
	if got := string(attributes[radiusNASIdentifier][0][2:]); got != "0123456789abcdef" {
		t.Fatalf("NAS-Identifier = %q", got)
	}
	if got := string(attributes[radiusTunnelClientEndpoint][0][3:]); got != "192.0.2.1" {
		t.Fatalf("Tunnel-Client-Endpoint = %q", got)
	}
	if got := string(attributes[radiusTunnelServerEndpoint][0][3:]); got != "198.51.100.1" {
		t.Fatalf("Tunnel-Server-Endpoint = %q", got)
	}
	password := attributes[radiusUserPassword][0]
	if len(password) != 18 || string(password[2:]) == "*" {
		t.Fatalf("User-Password is not an encrypted 16-byte block")
	}
}

func parseRadiusTestAttributes(t *testing.T, payload []byte) map[byte][][]byte {
	t.Helper()
	attributes := make(map[byte][][]byte)
	for len(payload) != 0 {
		if len(payload) < 2 || int(payload[1]) < 2 || int(payload[1]) > len(payload) {
			t.Fatalf("invalid RADIUS attribute payload")
		}
		length := int(payload[1])
		attribute := append([]byte(nil), payload[:length]...)
		attributes[attribute[0]] = append(attributes[attribute[0]], attribute)
		payload = payload[length:]
	}
	return attributes
}

func TestRadiusTrafficIsNotDoubleCounted(t *testing.T) {
	validator := &radiusValidator{
		blocked:        make(map[string]time.Time),
		sessions:       make(map[string]map[uint64]*radiusSession),
		closedSessions: make(map[string]*closedRadiusSession),
	}
	key := "0123456789abcdef"
	traffic := &radiusTrafficConnection{}
	id, allowed := validator.beginSession(key, "identity", "192.0.2.1", "198.51.100.1", nil, traffic)
	if !allowed {
		t.Fatal("session unexpectedly blocked")
	}
	traffic.read.Add(10)
	traffic.written.Add(60)

	sessions := validator.activeSessions()
	if len(sessions) != 1 || sessions[0].Traffic != 70 {
		t.Fatalf("active traffic = %+v, want 70", sessions)
	}

	validator.endSession(key, id)
	sessions = validator.activeSessions()
	if len(sessions) != 1 || sessions[0].Traffic != 70 {
		t.Fatalf("closed traffic = %+v, want 70", sessions)
	}

	secondTraffic := &radiusTrafficConnection{}
	_, allowed = validator.beginSession(key, "identity", "192.0.2.1", "198.51.100.1", nil, secondTraffic)
	if !allowed {
		t.Fatal("second session unexpectedly blocked")
	}
	secondTraffic.written.Add(30)
	sessions = validator.activeSessions()
	if len(sessions) != 1 || sessions[0].Traffic != 100 {
		t.Fatalf("aggregated traffic = %+v, want 100", sessions)
	}
}

func TestRadiusAuthorizationCacheIsScopedBySessionKey(t *testing.T) {
	requests := make(chan string, 3)
	validator := &radiusValidator{
		cacheTTL:       time.Minute,
		timeout:        time.Second,
		states:         make(map[string]*radiusState),
		blocked:        make(map[string]time.Time),
		sessions:       make(map[string]map[uint64]*radiusSession),
		closedSessions: make(map[string]*closedRadiusSession),
		authSlots:      make(chan struct{}, radiusMaxConcurrentAuth),
		accessRequest: func(_, _, _, key, _, _ string, _ time.Duration) (bool, error) {
			requests <- key
			return true, nil
		},
	}
	id := uuid.UUID{1}
	validator.authorizeAsync(id, "key-a", "192.0.2.1", "198.51.100.1")
	if key := waitRadiusRequest(t, requests); key != "key-a" {
		t.Fatalf("first RADIUS key = %q", key)
	}
	waitRadiusIdle(t, validator)

	validator.authorizeAsync(id, "key-a", "192.0.2.1", "198.51.100.1")
	select {
	case key := <-requests:
		t.Fatalf("cached key unexpectedly requested again: %q", key)
	case <-time.After(20 * time.Millisecond):
	}

	validator.authorizeAsync(id, "key-b", "192.0.2.2", "198.51.100.1")
	if key := waitRadiusRequest(t, requests); key != "key-b" {
		t.Fatalf("second RADIUS key = %q", key)
	}
	waitRadiusIdle(t, validator)
}

func TestRadiusRejectDisconnectsAllKeyConnections(t *testing.T) {
	validator := &radiusValidator{
		cacheTTL:       time.Minute,
		timeout:        time.Second,
		states:         make(map[string]*radiusState),
		blocked:        make(map[string]time.Time),
		sessions:       make(map[string]map[uint64]*radiusSession),
		closedSessions: make(map[string]*closedRadiusSession),
		authSlots:      make(chan struct{}, radiusMaxConcurrentAuth),
		accessRequest: func(_, _, _, _, _, _ string, _ time.Duration) (bool, error) {
			return false, nil
		},
	}
	key := "same-key"
	clients := make([]net.Conn, 0, 2)
	for i := 0; i < 2; i++ {
		client, server := net.Pipe()
		clients = append(clients, client)
		traffic := &radiusTrafficConnection{Conn: server}
		if _, allowed := validator.beginSession(key, "identity", "192.0.2.1", "198.51.100.1", traffic, traffic); !allowed {
			t.Fatal("session unexpectedly blocked before RADIUS response")
		}
	}
	validator.authorizeAsync(uuid.UUID{1}, key, "192.0.2.1", "198.51.100.1")
	for _, client := range clients {
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := client.Read(make([]byte, 1)); err == nil {
			t.Fatal("RADIUS reject left a connection open")
		}
		_ = client.Close()
	}
	validator.sessionMu.Lock()
	_, blocked := validator.blocked[key]
	validator.sessionMu.Unlock()
	if !blocked {
		t.Fatal("RADIUS reject did not cache the block")
	}
}

func TestRadiusRequestErrorDoesNotRejectSession(t *testing.T) {
	validator := &radiusValidator{
		cacheTTL:       time.Minute,
		timeout:        time.Second,
		states:         make(map[string]*radiusState),
		blocked:        make(map[string]time.Time),
		sessions:       make(map[string]map[uint64]*radiusSession),
		closedSessions: make(map[string]*closedRadiusSession),
		authSlots:      make(chan struct{}, radiusMaxConcurrentAuth),
		accessRequest: func(_, _, _, _, _, _ string, _ time.Duration) (bool, error) {
			return false, net.ErrClosed
		},
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	traffic := &radiusTrafficConnection{Conn: server}
	if _, allowed := validator.beginSession("key", "identity", "192.0.2.1", "198.51.100.1", traffic, traffic); !allowed {
		t.Fatal("session unexpectedly blocked")
	}
	validator.authorizeAsync(uuid.UUID{1}, "key", "192.0.2.1", "198.51.100.1")
	waitRadiusIdle(t, validator)

	validator.sessionMu.Lock()
	_, blocked := validator.blocked["key"]
	validator.sessionMu.Unlock()
	if blocked {
		t.Fatal("RADIUS network error blocked the session")
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte{1})
		writeDone <- err
	}()
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if _, err := server.Read(buffer); err != nil {
		t.Fatalf("RADIUS network error closed the session: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("client write failed after RADIUS network error: %v", err)
	}
}

func TestRadiusCleanupRemovesExpiredEntries(t *testing.T) {
	validator := &radiusValidator{
		states:         map[string]*radiusState{"expired": {expires: time.Now().Add(-time.Second)}},
		blocked:        map[string]time.Time{"expired": time.Now().Add(-time.Second)},
		sessions:       make(map[string]map[uint64]*radiusSession),
		closedSessions: map[string]*closedRadiusSession{"expired": {closedAt: time.Now().Add(-time.Minute)}},
	}
	validator.cleanup(time.Now())
	if _, ok := validator.states["expired"]; ok {
		t.Fatal("expired authorization state was retained")
	}
	if len(validator.blocked) != 0 || len(validator.closedSessions) != 0 {
		t.Fatalf("expired session data retained: blocked=%d closed=%d", len(validator.blocked), len(validator.closedSessions))
	}
}

func TestRadiusCloseCallbackSetAfterClose(t *testing.T) {
	for i := 0; i < 1000; i++ {
		traffic := &radiusTrafficConnection{}
		var calls atomic.Int32
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			traffic.notifyClosed()
		}()
		go func() {
			defer wait.Done()
			traffic.setOnClose(func() { calls.Add(1) })
		}()
		wait.Wait()
		if calls.Load() != 1 {
			t.Fatalf("close callback calls = %d, want 1", calls.Load())
		}
	}
}

func waitRadiusRequest(t *testing.T, requests <-chan string) string {
	t.Helper()
	select {
	case key := <-requests:
		return key
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for RADIUS request")
		return ""
	}
}

func waitRadiusIdle(t *testing.T, validator *radiusValidator) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for len(validator.authSlots) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for RADIUS worker")
		}
		time.Sleep(time.Millisecond)
	}
}
