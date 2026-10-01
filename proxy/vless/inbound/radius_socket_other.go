//go:build !linux

package inbound

import stdnet "net"

func configureRadiusSocket(conn *stdnet.TCPConn) error {
	return configureRadiusKeepAlive(conn)
}
