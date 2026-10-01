package inbound

import (
	stdnet "net"
	"time"
)

const radiusDeadPeerTimeout = 15 * time.Second

// configureRadiusKeepAlive detects an unreachable idle peer without treating
// an application-idle but reachable VLESS connection as dead. Keepalive probes
// are handled by TCP and are not exposed to the client application.
func configureRadiusKeepAlive(conn *stdnet.TCPConn) error {
	return conn.SetKeepAliveConfig(stdnet.KeepAliveConfig{
		Enable:   true,
		Idle:     5 * time.Second,
		Interval: 5 * time.Second,
		Count:    2,
	})
}
