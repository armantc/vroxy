package stat

import (
	"errors"
	"net"

	"github.com/xtls/xray-core/auth"
	"github.com/xtls/xray-core/features/stats"
)

type Connection interface {
	net.Conn
}

type CounterConnection struct {
	Connection
	ReadCounter  stats.Counter
	WriteCounter stats.Counter
	key          string
	traffic      int64
	closed       bool
}

func (c *CounterConnection) Read(b []byte) (int, error) {
	nBytes, err := c.Connection.Read(b)
	// if c.ReadCounter != nil {
	// 	c.ReadCounter.Add(int64(nBytes))
	// }

	if nBytes > 0 && !c.closed && c.key != "" {
		// upload traffic
		c.traffic += int64(nBytes)

		if c.traffic > 1*1024*1024 {
			auth.UpdateTraffic(c.key, c.traffic)
			c.traffic = 0

			if auth.IsKeyBlocked(c.key) { // every 1MB, check if the key is blocked
				c.Close()
				return 0, errors.New("connection closed due to key being blocked")
			}
		}
	}

	return nBytes, err
}

func (c *CounterConnection) Write(b []byte) (int, error) {
	nBytes, err := c.Connection.Write(b)
	// if c.WriteCounter != nil {
	// 	c.WriteCounter.Add(int64(nBytes))
	// }

	if nBytes > 0 && !c.closed && c.key != "" {
		c.traffic += int64(nBytes)
		if c.traffic > 1*1024*1024 && !c.closed { // every 1MB, update traffic
			auth.UpdateTraffic(c.key, c.traffic)
			c.traffic = 0
		}
	}

	return nBytes, err
}

func (c *CounterConnection) AuthenticateConnection(identity string) bool {

	sessionKey := identity[0:8]

	clientWD := auth.ClientWorkerData{
		Identity: identity,
		Password: "*", // * used to radius server detect uuid as user
		Key:      auth.GenUniqueSessionKey(sessionKey, "", auth.GetClientIpFromRemoteAddr(c.Connection.RemoteAddr()), ""),
		ClientIp: auth.GetClientIpFromRemoteAddr(c.Connection.RemoteAddr()),
		Traffic:  0,
	}

	authSuccess := auth.Authenticate(clientWD)

	if !authSuccess {
		return false
	}

	auth.UpdateSocketCount(clientWD.Key, c.Connection.RemoteAddr().String(), 1)
	auth.AddSession(clientWD)
	c.key = clientWD.Key
	c.traffic = 0
	c.closed = false

	return true
}

func (c *CounterConnection) Close() error {
	if !c.closed {
		auth.UpdateTraffic(c.key, c.traffic)
		c.traffic = 0
		auth.UpdateSocketCount(c.key, c.Connection.RemoteAddr().String(), -1)
		c.closed = true
	}
	return c.Connection.Close()
}

func TryUnwrapStatsConn(conn net.Conn) net.Conn {
	if conn == nil {
		return conn
	}
	if conn, ok := conn.(*CounterConnection); ok {
		return conn.Connection
	}
	return conn
}
