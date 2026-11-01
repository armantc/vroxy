package conf_test

import (
	"encoding/json"
	"fmt"
	"google.golang.org/protobuf/proto"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vless/outbound"
)

func TestVLessOutbound(t *testing.T) {
	creator := func() Buildable {
		return new(VLessOutboundConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"vnext": [{
					"address": "example.com",
					"port": 443,
					"users": [
						{
							"id": "27848739-7e62-4138-9fd3-098a63964b6b",
							"flow": "xtls-rprx-vision-udp443",
							"encryption": "none",
							"level": 0
						}
					]
				}]
			}`,
			Parser: loadJSON(creator),
			Output: &outbound.Config{
				Vnext: &protocol.ServerEndpoint{
					Address: &net.IPOrDomain{
						Address: &net.IPOrDomain_Domain{
							Domain: "example.com",
						},
					},
					Port: 443,
					User: &protocol.User{
						Account: serial.ToTypedMessage(&vless.Account{
							Id:         "27848739-7e62-4138-9fd3-098a63964b6b",
							Flow:       "xtls-rprx-vision-udp443",
							Encryption: "none",
						}),
						Level: 0,
					},
				},
			},
		},
		{
			Input: `{
				"address": "example.com",
				"port": 443,
				"id": "27848739-7e62-4138-9fd3-098a63964b6b",
				"flow": "xtls-rprx-vision-udp443",
				"encryption": "none",
				"level": 0
			}`,
			Parser: loadJSON(creator),
			Output: &outbound.Config{
				Vnext: &protocol.ServerEndpoint{
					Address: &net.IPOrDomain{
						Address: &net.IPOrDomain_Domain{
							Domain: "example.com",
						},
					},
					Port: 443,
					User: &protocol.User{
						Account: serial.ToTypedMessage(&vless.Account{
							Id:         "27848739-7e62-4138-9fd3-098a63964b6b",
							Flow:       "xtls-rprx-vision-udp443",
							Encryption: "none",
						}),
						Level: 0,
					},
				},
			},
		},
	})
}

func TestVLessInbound(t *testing.T) {
	creator := func() Buildable {
		return new(VLessInboundConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"clients": [
					{
						"id": "27848739-7e62-4138-9fd3-098a63964b6b",
						"flow": "xtls-rprx-vision",
						"level": 0,
						"email": "love@example.com"
					}
				],
				"decryption": "none",
				"fallbacks": [
					{
						"dest": 80
					},
					{
						"alpn": "h2",
						"dest": "@/dev/shm/domain.socket",
						"xver": 2
					},
					{
						"path": "/innerws",
						"dest": "serve-ws-none"
					}
				]
			}`,
			Parser: loadJSON(creator),
			Output: &inbound.Config{
				Users: []*protocol.User{
					{
						Account: serial.ToTypedMessage(&vless.Account{
							Id:   "27848739-7e62-4138-9fd3-098a63964b6b",
							Flow: "xtls-rprx-vision",
						}),
						Level: 0,
						Email: "love@example.com",
					},
				},
				Decryption: "none",
				Fallbacks: []*inbound.Fallback{
					{
						Alpn: "",
						Path: "",
						Type: "tcp",
						Dest: "localhost:80",
						Xver: 0,
					},
					{
						Alpn: "h2",
						Path: "",
						Type: "unix",
						Dest: "@/dev/shm/domain.socket",
						Xver: 2,
					},
					{
						Alpn: "",
						Path: "/innerws",
						Type: "serve",
						Dest: "serve-ws-none",
						Xver: 0,
					},
				},
			},
		},
	})
}

func TestVLessInboundRadius(t *testing.T) {
	config := &VLessInboundConfig{
		Decryption: "none",
		Radius: &VLessRadiusConfig{
			Server:         "127.0.0.1:1812",
			Secret:         "shared-secret",
			TimeoutSeconds: 2,
			CacheSeconds:   30,
			PublicIP:       "198.51.100.1",
			Flow:           vless.XRV,
		},
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	radiusConfig := built.(*inbound.Config)
	if radiusConfig.RadiusServer != "127.0.0.1:1812" || radiusConfig.RadiusSecret != "shared-secret" || radiusConfig.RadiusTimeoutSeconds != 2 || radiusConfig.RadiusCacheSeconds != 30 || radiusConfig.RadiusPublicIp != "198.51.100.1" || radiusConfig.RadiusFlow != vless.XRV {
		t.Fatalf("RADIUS configuration was not preserved: %#v", radiusConfig)
	}
}

func TestVLessInboundRadiusValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		radius VLessRadiusConfig
	}{
		{"missing server", VLessRadiusConfig{Secret: "secret"}},
		{"missing secret", VLessRadiusConfig{Server: "127.0.0.1:1812"}},
		{"invalid flow", VLessRadiusConfig{Server: "127.0.0.1:1812", Secret: "secret", Flow: "invalid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := &VLessInboundConfig{Decryption: "none", Radius: &tc.radius}
			if _, err := config.Build(); err == nil {
				t.Fatal("invalid RADIUS configuration accepted")
			}
		})
	}
}

func TestVLessInboundRadiusUsersCompatibility(t *testing.T) {
	for _, field := range []string{"clients", "users"} {
		t.Run(field, func(t *testing.T) {
			var config VLessInboundConfig
			input := fmt.Sprintf(`{"decryption":"none","flow":"xtls-rprx-vision",%q:[{"id":"27848739-7e62-4138-9fd3-098a63964b6b"}],"radius":{"server":"127.0.0.1:1812","secret":"secret"}}`, field)
			if err := json.Unmarshal([]byte(input), &config); err != nil {
				t.Fatal(err)
			}
			built, err := config.Build()
			if err != nil {
				t.Fatal(err)
			}
			// Check the generated descriptor too: Xray passes this config through a
			// typed protobuf message before constructing the inbound handler.
			wire, err := proto.Marshal(built)
			if err != nil {
				t.Fatal(err)
			}
			decoded := new(inbound.Config)
			if err := proto.Unmarshal(wire, decoded); err != nil {
				t.Fatal(err)
			}
			if len(decoded.Users) != 1 || decoded.RadiusFlow != vless.XRV || decoded.RadiusServer != "127.0.0.1:1812" || decoded.RadiusSecret != "secret" {
				t.Fatalf("RADIUS or %s configuration lost in protobuf round trip: %v", field, decoded)
			}
		})
	}
}
