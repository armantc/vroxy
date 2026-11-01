package inbound_test

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/vless/inbound"
)

func TestRadiusInboundLifecycle(t *testing.T) {
	// Use real UDP authorization and TCP proxy traffic to cover configuration,
	// dynamic UUID admission, accounting, disconnect, and release together.
	radius, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer radius.Close()
	authorized := make(chan struct{}, 8)
	go func() {
		packet := make([]byte, 4096)
		for {
			n, peer, err := radius.ReadFrom(packet)
			if err != nil {
				return
			}
			if n < 20 {
				continue
			}
			response := []byte{2, packet[1], 0, 20}
			hash := md5.New()
			hash.Write(response)
			hash.Write(packet[4:20])
			hash.Write([]byte("integration-secret"))
			response = append(response, hash.Sum(nil)...)
			radius.WriteTo(response, peer)
			authorized <- struct{}{}
		}
	}()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	// Reserve an ephemeral inbound port before handing it to Xray.
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	config := fmt.Sprintf(`{
 "inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{
 "decryption":"none","radius":{"server":%q,"secret":"integration-secret","cacheSeconds":60}}}],
 "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}}]
 }`, port, radius.LocalAddr().String())
	instance, err := core.StartInstance("json", []byte(config))
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	id := uuid.New()
	targetPort := target.Addr().(*net.TCPAddr).Port
	open := func() net.Conn {
		t.Helper()
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		header := append([]byte{0}, id[:]...)
		header = append(header, 0, 1, byte(targetPort>>8), byte(targetPort), 1, 127, 0, 0, 1)
		if _, err := conn.Write(header); err != nil {
			t.Fatal(err)
		}
		return conn
	}
	echo := func(conn net.Conn) {
		t.Helper()
		payload := strings.Repeat("radius-traffic", 1024)
		if _, err := io.WriteString(conn, payload); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, 2+len(payload))
		if _, err := io.ReadFull(conn, response); err != nil {
			t.Fatal(err)
		}
		if response[0] != 0 || response[1] != 0 || string(response[2:]) != payload {
			t.Fatal("VLESS echo response differs from request")
		}
	}
	conn := open()
	echo(conn)
	select {
	case <-authorized:
	case <-time.After(3 * time.Second):
		t.Fatal("no RADIUS authorization received")
	}
	client := &http.Client{Timeout: time.Second}
	sessions := func() []inbound.Session {
		t.Helper()
		response, err := client.Get("http://127.0.0.1:8585/api/sessions")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result []inbound.Session
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	active := sessions()
	if len(active) != 1 || active[0].Identity != id.String() || active[0].Traffic < int64(2*len(strings.Repeat("radius-traffic", 1024))) {
		t.Fatalf("missing session or traffic: %+v", active)
	}
	key := active[0].Key
	control := func(action string) {
		t.Helper()
		response, err := client.Post("http://127.0.0.1:8585/api/"+action, "application/json", strings.NewReader(fmt.Sprintf(`{"key":%q}`, key)))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("%s returned %s", action, response.Status)
		}
	}
	control("disconnect")
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("disconnect left the connection open")
	}
	blocked := open()
	if _, err := blocked.Read(make([]byte, 2)); err == nil {
		t.Fatal("blocked session was admitted")
	}
	control("release")
	released := open()
	echo(released)
	select {
	case <-authorized:
	case <-time.After(3 * time.Second):
		t.Fatal("release did not trigger new authorization")
	}
	// Ensure the API's last-sync field and cumulative traffic remain available.
	after := sessions()
	if len(after) != 1 || after[0].Traffic <= active[0].Traffic || after[0].LastSync == 0 {
		t.Fatalf("released session lost accounting: %+v", after)
	}
}
