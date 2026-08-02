// Package proxy implements the SOCKS5 handler: RFC 1928 (protocol) on
// both sides — server side accepts local apps with no auth required
// (listeners are 127.0.0.1-only), client side dials the IPRoyal upstream
// using RFC 1929 username/password auth. Router/session/credential
// construction (Session B Phase 3) plugs into Dial via the Credentials
// passed to Handle.
package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	socks5Version = 0x05

	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	replySuccess              = 0x00
	replyGeneralFailure       = 0x01
	replyCommandNotSupported  = 0x07
	replyAddrTypeNotSupported = 0x08

	userPassAuthVersion = 0x01
	authStatusSuccess   = 0x00
	authStatusFailure   = 0x01
)

// Target is a parsed SOCKS5 CONNECT destination.
type Target struct {
	Host string // domain name or IP literal, whichever the client sent
	Port uint16
}

func (t Target) Addr() string {
	return fmt.Sprintf("%s:%d", t.Host, t.Port)
}

// ServerHandshake performs the RFC 1928 server-side greeting (no auth
// required — callers are local, 127.0.0.1-only listeners) and reads the
// CONNECT request. On success it returns the requested target; the
// caller is responsible for dialing upstream and calling ServerReply.
func ServerHandshake(conn net.Conn) (Target, error) {
	if err := serverGreeting(conn); err != nil {
		return Target{}, err
	}
	return readConnectRequest(conn)
}

func serverGreeting(conn net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("socks5: read greeting header: %w", err)
	}
	if hdr[0] != socks5Version {
		return fmt.Errorf("socks5: unsupported version 0x%02x", hdr[0])
	}
	nMethods := int(hdr[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("socks5: read methods: %w", err)
	}

	found := false
	for _, m := range methods {
		if m == methodNoAuth {
			found = true
			break
		}
	}
	if !found {
		_, _ = conn.Write([]byte{socks5Version, methodNoAcceptable})
		return fmt.Errorf("socks5: client did not offer no-auth method")
	}
	_, err := conn.Write([]byte{socks5Version, methodNoAuth})
	return err
}

func readConnectRequest(conn net.Conn) (Target, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return Target{}, fmt.Errorf("socks5: read request header: %w", err)
	}
	if hdr[0] != socks5Version {
		return Target{}, fmt.Errorf("socks5: unsupported version 0x%02x", hdr[0])
	}
	if hdr[1] != cmdConnect {
		_ = writeReply(conn, replyCommandNotSupported)
		return Target{}, fmt.Errorf("socks5: unsupported command 0x%02x (only CONNECT is implemented)", hdr[1])
	}
	// hdr[2] is reserved (0x00)

	host, err := readAddr(conn, hdr[3])
	if err != nil {
		_ = writeReply(conn, replyAddrTypeNotSupported)
		return Target{}, err
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return Target{}, fmt.Errorf("socks5: read port: %w", err)
	}

	return Target{Host: host, Port: binary.BigEndian.Uint16(portBytes)}, nil
}

func readAddr(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", fmt.Errorf("socks5: read ipv4: %w", err)
		}
		return net.IP(b).String(), nil
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", fmt.Errorf("socks5: read ipv6: %w", err)
		}
		return net.IP(b).String(), nil
	case atypDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return "", fmt.Errorf("socks5: read domain length: %w", err)
		}
		b := make([]byte, lenByte[0])
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", fmt.Errorf("socks5: read domain: %w", err)
		}
		return string(b), nil
	default:
		return "", fmt.Errorf("socks5: unsupported address type 0x%02x", atyp)
	}
}

// ServerReply sends the RFC 1928 reply for a CONNECT request. bindAddr
// may be nil, in which case 0.0.0.0:0 is sent — acceptable for CONNECT
// per RFC 1928, most clients ignore it.
func ServerReply(conn net.Conn, code byte, bindAddr *net.TCPAddr) error {
	return writeReplyWithAddr(conn, code, bindAddr)
}

func writeReply(conn net.Conn, code byte) error {
	return writeReplyWithAddr(conn, code, nil)
}

func writeReplyWithAddr(conn net.Conn, code byte, bindAddr *net.TCPAddr) error {
	ip := net.IPv4zero
	port := uint16(0)
	if bindAddr != nil {
		if v4 := bindAddr.IP.To4(); v4 != nil {
			ip = v4
		} else {
			ip = bindAddr.IP
		}
		port = uint16(bindAddr.Port)
	}

	atyp := byte(atypIPv4)
	ipBytes := ip.To4()
	if ipBytes == nil {
		atyp = atypIPv6
		ipBytes = ip.To16()
	}

	buf := make([]byte, 0, 6+len(ipBytes))
	buf = append(buf, socks5Version, code, 0x00, atyp)
	buf = append(buf, ipBytes...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	buf = append(buf, portBytes...)

	_, err := conn.Write(buf)
	return err
}
