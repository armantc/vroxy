package inbound

import (
	"fmt"
	stdnet "net"

	"golang.org/x/sys/unix"
)

func configureRadiusSocket(conn *stdnet.TCPConn) error {
	if err := configureRadiusKeepAlive(conn); err != nil {
		return err
	}

	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockoptErr error
	if err := raw.Control(func(fd uintptr) {
		sockoptErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(radiusDeadPeerTimeout.Milliseconds()))
	}); err != nil {
		return err
	}
	if sockoptErr != nil {
		return fmt.Errorf("set TCP_USER_TIMEOUT: %w", sockoptErr)
	}
	return nil
}
