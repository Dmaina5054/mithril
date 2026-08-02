package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// Credentials authenticates to the upstream SOCKS5 proxy via RFC 1929.
// Username/Password are the full geo/session-prefixed strings the
// Session B Phase 3 router builds — this package treats them as opaque.
type Credentials struct {
	Username string
	Password string
}

// DialUpstream connects to a SOCKS5 upstream (host:port), performs the
// RFC 1928 handshake requesting username/password auth, completes the
// RFC 1929 subnegotiation with creds, then issues a CONNECT for target
// and returns the established connection ready to relay.
func DialUpstream(upstreamAddr string, creds Credentials, target Target, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", upstreamAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("socks5 upstream: dial %s: %w", upstreamAddr, err)
	}

	method, err := clientGreeting(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := clientAuth(conn, method, creds); err != nil {
		conn.Close()
		return nil, err
	}
	if err := clientConnect(conn, target); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func clientGreeting(conn net.Conn) (byte, error) {
	// Offer both no-auth and username/password; upstream is expected to
	// select username/password (0x02) since IPRoyal requires auth.
	if _, err := conn.Write([]byte{socks5Version, 2, methodNoAuth, methodUserPass}); err != nil {
		return 0, fmt.Errorf("socks5 upstream: write greeting: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return 0, fmt.Errorf("socks5 upstream: read greeting response: %w", err)
	}
	if resp[0] != socks5Version {
		return 0, fmt.Errorf("socks5 upstream: unsupported version 0x%02x", resp[0])
	}
	switch resp[1] {
	case methodUserPass, methodNoAuth:
		return resp[1], nil
	case methodNoAcceptable:
		return 0, fmt.Errorf("socks5 upstream: server rejected all offered auth methods")
	default:
		return 0, fmt.Errorf("socks5 upstream: server selected unsupported method 0x%02x", resp[1])
	}
}

func clientAuth(conn net.Conn, selectedMethod byte, creds Credentials) error {
	if selectedMethod == methodNoAuth {
		return nil
	}

	if len(creds.Username) > 255 || len(creds.Password) > 255 {
		return fmt.Errorf("socks5 upstream: username/password must each be <= 255 bytes (RFC 1929)")
	}

	buf := make([]byte, 0, 3+len(creds.Username)+len(creds.Password))
	buf = append(buf, userPassAuthVersion, byte(len(creds.Username)))
	buf = append(buf, creds.Username...)
	buf = append(buf, byte(len(creds.Password)))
	buf = append(buf, creds.Password...)

	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("socks5 upstream: write auth: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5 upstream: read auth response: %w", err)
	}
	if resp[1] != authStatusSuccess {
		return fmt.Errorf("socks5 upstream: authentication failed (status 0x%02x) — check credential string", resp[1])
	}
	return nil
}

func clientConnect(conn net.Conn, target Target) error {
	buf := []byte{socks5Version, cmdConnect, 0x00}

	if ip := net.ParseIP(target.Host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, atypIPv4)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, atypIPv6)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(target.Host) > 255 {
			return fmt.Errorf("socks5 upstream: domain name too long: %s", target.Host)
		}
		buf = append(buf, atypDomain, byte(len(target.Host)))
		buf = append(buf, target.Host...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, target.Port)
	buf = append(buf, portBytes...)

	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("socks5 upstream: write CONNECT: %w", err)
	}

	// Reply: VER REP RSV ATYP BND.ADDR BND.PORT — read header first to
	// learn ATYP, then consume the correctly-sized address + port.
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("socks5 upstream: read CONNECT reply header: %w", err)
	}
	if hdr[0] != socks5Version {
		return fmt.Errorf("socks5 upstream: unsupported reply version 0x%02x", hdr[0])
	}
	if hdr[1] != replySuccess {
		return fmt.Errorf("socks5 upstream: CONNECT failed, reply code 0x%02x", hdr[1])
	}

	var addrLen int
	switch hdr[3] {
	case atypIPv4:
		addrLen = 4
	case atypIPv6:
		addrLen = 16
	case atypDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return fmt.Errorf("socks5 upstream: read reply domain length: %w", err)
		}
		addrLen = int(lenByte[0])
	default:
		return fmt.Errorf("socks5 upstream: unsupported reply address type 0x%02x", hdr[3])
	}

	if _, err := io.ReadFull(conn, make([]byte, addrLen+2)); err != nil { // +2 for BND.PORT
		return fmt.Errorf("socks5 upstream: read reply address/port: %w", err)
	}

	return nil
}
