package proxy

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestServerHandshake_Domain(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan struct{})
	var gotTarget Target
	var gotErr error
	go func() {
		gotTarget, gotErr = ServerHandshake(server)
		close(done)
	}()

	// Greeting: VER=5, NMETHODS=1, METHODS=[no-auth]
	writeAll(t, client, []byte{socks5Version, 1, methodNoAuth})
	readAndCheck(t, client, []byte{socks5Version, methodNoAuth})

	// CONNECT request: VER CMD RSV ATYP DOMAIN_LEN DOMAIN PORT
	host := "example.com"
	req := []byte{socks5Version, cmdConnect, 0x00, atypDomain, byte(len(host))}
	req = append(req, host...)
	req = append(req, 0x01, 0xBB) // port 443
	writeAll(t, client, req)

	<-done
	if gotErr != nil {
		t.Fatalf("ServerHandshake returned error: %v", gotErr)
	}
	if gotTarget.Host != host {
		t.Errorf("Host = %q, want %q", gotTarget.Host, host)
	}
	if gotTarget.Port != 443 {
		t.Errorf("Port = %d, want 443", gotTarget.Port)
	}
}

func TestServerHandshake_IPv4(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan struct{})
	var gotTarget Target
	var gotErr error
	go func() {
		gotTarget, gotErr = ServerHandshake(server)
		close(done)
	}()

	writeAll(t, client, []byte{socks5Version, 1, methodNoAuth})
	readAndCheck(t, client, []byte{socks5Version, methodNoAuth})

	req := []byte{socks5Version, cmdConnect, 0x00, atypIPv4, 93, 184, 216, 34} // example.com's old IP
	req = append(req, 0x00, 0x50)                                              // port 80
	writeAll(t, client, req)

	<-done
	if gotErr != nil {
		t.Fatalf("ServerHandshake returned error: %v", gotErr)
	}
	if gotTarget.Host != "93.184.216.34" {
		t.Errorf("Host = %q, want 93.184.216.34", gotTarget.Host)
	}
	if gotTarget.Port != 80 {
		t.Errorf("Port = %d, want 80", gotTarget.Port)
	}
}

func TestServerHandshake_IPv6(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan struct{})
	var gotTarget Target
	var gotErr error
	go func() {
		gotTarget, gotErr = ServerHandshake(server)
		close(done)
	}()

	writeAll(t, client, []byte{socks5Version, 1, methodNoAuth})
	readAndCheck(t, client, []byte{socks5Version, methodNoAuth})

	ip := net.ParseIP("2001:db8::1").To16()
	req := []byte{socks5Version, cmdConnect, 0x00, atypIPv6}
	req = append(req, ip...)
	req = append(req, 0x01, 0xBB)
	writeAll(t, client, req)

	<-done
	if gotErr != nil {
		t.Fatalf("ServerHandshake returned error: %v", gotErr)
	}
	if gotTarget.Host != "2001:db8::1" {
		t.Errorf("Host = %q, want 2001:db8::1", gotTarget.Host)
	}
}

func TestServerHandshake_NoAcceptableMethod(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := ServerHandshake(server)
		errCh <- err
	}()

	// Offer only username/password — server only implements no-auth.
	writeAll(t, client, []byte{socks5Version, 1, methodUserPass})
	readAndCheck(t, client, []byte{socks5Version, methodNoAcceptable})

	if err := <-errCh; err == nil {
		t.Fatal("expected error when no acceptable method offered, got nil")
	}
}

func TestServerHandshake_UnsupportedCommand(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := ServerHandshake(server)
		errCh <- err
	}()

	writeAll(t, client, []byte{socks5Version, 1, methodNoAuth})
	readAndCheck(t, client, []byte{socks5Version, methodNoAuth})

	// BIND (0x02) instead of CONNECT (0x01) — not implemented. The server
	// only reads the 4-byte header before bailing out, so it never drains
	// the rest of this message; net.Pipe's Write blocks until every byte
	// from a single Write call is read, so this write must happen in its
	// own goroutine or it would deadlock against the server's early exit.
	go writeAllBestEffort(client, []byte{socks5Version, 0x02, 0x00, atypIPv4, 1, 2, 3, 4, 0, 80})

	// The server also writes a "command not supported" reply on this
	// error path — drain it (best-effort, don't care about content here)
	// so that write can complete and unblock ServerHandshake's return.
	go func() {
		buf := make([]byte, 10)
		_, _ = io.ReadFull(client, buf)
	}()

	if err := <-errCh; err == nil {
		t.Fatal("expected error for unsupported command, got nil")
	}
}

func TestServerReply_EncodesIPv4(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_ = ServerReply(server, replySuccess, &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1080})
	}()

	buf := make([]byte, 10)
	readFull(t, client, buf)

	if buf[0] != socks5Version || buf[1] != replySuccess {
		t.Fatalf("unexpected reply header: % x", buf[:4])
	}
	if buf[3] != atypIPv4 {
		t.Fatalf("ATYP = 0x%02x, want IPv4", buf[3])
	}
	gotIP := net.IP(buf[4:8]).String()
	if gotIP != "10.0.0.1" {
		t.Errorf("bind IP = %s, want 10.0.0.1", gotIP)
	}
	gotPort := binary.BigEndian.Uint16(buf[8:10])
	if gotPort != 1080 {
		t.Errorf("bind port = %d, want 1080", gotPort)
	}
}

// writeAllBestEffort writes without failing the test on error/timeout —
// used where the peer is expected to stop reading partway through.
func writeAllBestEffort(conn net.Conn, b []byte) {
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write(b)
}

func writeAll(t *testing.T, conn net.Conn, b []byte) {
	t.Helper()
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func readFull(t *testing.T, conn net.Conn, buf []byte) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n := 0
	for n < len(buf) {
		m, err := conn.Read(buf[n:])
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		n += m
	}
}

func readAndCheck(t *testing.T, conn net.Conn, want []byte) {
	t.Helper()
	buf := make([]byte, len(want))
	readFull(t, conn, buf)
	for i := range want {
		if buf[i] != want[i] {
			t.Fatalf("response = % x, want % x", buf, want)
		}
	}
}
