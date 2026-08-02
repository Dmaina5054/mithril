package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"math/rand"
	"net"
	"testing"
	"time"
)

// captureRealClientHello starts a listener, drives a real crypto/tls
// handshake attempt against it from a real client (which will fail once
// it doesn't get a ServerHello back — irrelevant, we only need the
// ClientHello bytes it sends), and returns exactly what hit the wire.
// Authoritative by construction: these are real bytes from Go's own
// TLS stack, not hand-crafted or recalled from memory.
func captureRealClientHello(t *testing.T, sni string) []byte {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			return
		}
		defer conn.Close()
		client := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		client.SetDeadline(time.Now().Add(2 * time.Second))
		_ = client.Handshake() // expected to fail — nothing on the other end speaks TLS back
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	buf := make([]byte, sniPeekSize)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read ClientHello: %v", err)
	}
	return buf[:n]
}

func TestPeekSNI_RealClientHello(t *testing.T) {
	hello := captureRealClientHello(t, "sni-test.example.com")

	br := bufio.NewReaderSize(&byteConn{data: hello}, sniPeekSize)
	sni, err := PeekSNI(br)
	if err != nil {
		t.Fatalf("PeekSNI: %v", err)
	}
	if sni != "sni-test.example.com" {
		t.Errorf("SNI = %q, want sni-test.example.com", sni)
	}

	// Non-consuming: the buffered reader must still yield the same
	// bytes afterward, unconsumed by the peek.
	after, err := br.Peek(len(hello))
	if err != nil {
		t.Fatalf("second Peek: %v", err)
	}
	if string(after) != string(hello) {
		t.Error("PeekSNI consumed bytes — a second Peek should return the identical data")
	}
}

func TestPeekSNI_DifferentHostnames(t *testing.T) {
	for _, host := range []string{"a.example.com", "another-name.co.uk", "x.y.z.example.org"} {
		t.Run(host, func(t *testing.T) {
			hello := captureRealClientHello(t, host)
			br := bufio.NewReaderSize(&byteConn{data: hello}, sniPeekSize)
			sni, err := PeekSNI(br)
			if err != nil {
				t.Fatalf("PeekSNI: %v", err)
			}
			if sni != host {
				t.Errorf("SNI = %q, want %q", sni, host)
			}
		})
	}
}

func TestParseSNI_NotTLS(t *testing.T) {
	// Plain HTTP request line — first byte 'G' (0x47), not 0x16.
	if got := parseSNI([]byte("GET / HTTP/1.1\r\n")); got != "" {
		t.Errorf("parseSNI(non-TLS) = %q, want empty", got)
	}
}

func TestParseSNI_EmptyInput(t *testing.T) {
	if got := parseSNI(nil); got != "" {
		t.Errorf("parseSNI(nil) = %q, want empty", got)
	}
}

func TestParseSNI_TruncatedRecordHeader(t *testing.T) {
	if got := parseSNI([]byte{0x16, 0x03}); got != "" {
		t.Errorf("parseSNI(truncated) = %q, want empty", got)
	}
}

func TestParseSNI_HandshakeTypeNotClientHello(t *testing.T) {
	buf := []byte{
		0x16, 0x03, 0x01, 0x00, 0x10, // record header, type=Handshake
		0x02, 0x00, 0x00, 0x0b, // handshake type=0x02 (ServerHello, not ClientHello)
	}
	if got := parseSNI(buf); got != "" {
		t.Errorf("parseSNI(non-ClientHello handshake) = %q, want empty", got)
	}
}

// TestParseSNI_NoPanicOnGarbage feeds random bytes through the parser —
// a proxy sees arbitrary/adversarial input on every new connection, so
// "never panics" matters as much as "extracts correctly on real input."
func TestParseSNI_NoPanicOnGarbage(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		n := rng.Intn(sniPeekSize + 1)
		buf := make([]byte, n)
		rng.Read(buf)
		if n > 0 {
			buf[0] = 0x16 // bias toward the TLS-handshake path, where the real parsing logic lives
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseSNI panicked on garbage input (len=%d): %v\nbuf: % x", n, r, buf)
				}
			}()
			parseSNI(buf)
		}()
	}
}

// byteConn adapts a fixed byte slice to net.Conn for feeding into
// bufio.Reader in tests — only Read is exercised. Tracks an offset and
// returns io.EOF once exhausted, like a real connection whose peer
// closed after sending exactly this much.
type byteConn struct {
	data []byte
	pos  int
}

func (b *byteConn) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}
func (b *byteConn) Write(p []byte) (int, error)        { return len(p), nil }
func (b *byteConn) Close() error                       { return nil }
func (b *byteConn) LocalAddr() net.Addr                { return nil }
func (b *byteConn) RemoteAddr() net.Addr               { return nil }
func (b *byteConn) SetDeadline(t time.Time) error      { return nil }
func (b *byteConn) SetReadDeadline(t time.Time) error  { return nil }
func (b *byteConn) SetWriteDeadline(t time.Time) error { return nil }
