package proxy

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// TestHandle_ShortPayloadDoesNotStallRelay is a regression test for a
// real bug caught during development: PeekSNI's underlying
// bufio.Reader.Peek(sniPeekSize) blocks until it accumulates the FULL
// window or the read errors — not "at least 1 byte" like the spec's
// original sketch implied. Without handler.go's bounded read deadline
// around the peek, any connection whose first flight is shorter than
// sniPeekSize (plain HTTP, a small ClientHello with nothing sent right
// after) would hang before relay even starts. This proves it doesn't.
func TestHandle_ShortPayloadDoesNotStallRelay(t *testing.T) {
	// Handle/Relay legitimately never return for a live connection's
	// whole lifetime (Relay only ends on close) — that's correct, not
	// the bug. What must be bounded is whether the short payload reaches
	// upstream promptly, so the fake upstream reports its result over a
	// channel rather than via t directly from its background goroutine.
	type result struct {
		got string
		err error
	}
	resultCh := make(chan result, 1)

	upstreamAddr := fakeUpstream(t, func(t *testing.T, conn net.Conn) {
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		hdr := make([]byte, 2)
		readFull(t, conn, hdr)
		readFull(t, conn, make([]byte, hdr[1])) // methods
		writeAll(t, conn, []byte{socks5Version, methodNoAuth})

		reqHdr := make([]byte, 4)
		readFull(t, conn, reqHdr)
		if reqHdr[3] != atypDomain {
			resultCh <- result{err: fmt.Errorf("expected domain ATYP, got 0x%02x", reqHdr[3])}
			return
		}
		lenByte := make([]byte, 1)
		readFull(t, conn, lenByte)
		readFull(t, conn, make([]byte, int(lenByte[0])+2)) // domain bytes + port(2)
		writeAll(t, conn, []byte{socks5Version, replySuccess, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})

		// Relay direction under test: read whatever the client sent,
		// a short payload well under sniPeekSize, with nothing sent
		// after it — the exact shape that used to block inside PeekSNI.
		buf := make([]byte, 32)
		n, err := conn.Read(buf)
		if err != nil {
			resultCh <- result{err: err}
			return
		}
		resultCh <- result{got: string(buf[:n])}
	})

	client, server := net.Pipe()
	defer client.Close()

	resolver := StaticResolver{UpstreamAddr: upstreamAddr, Creds: Credentials{Username: "u", Password: "p"}}
	go Handle(server, resolver)

	client.SetDeadline(time.Now().Add(3 * time.Second))
	writeAll(t, client, []byte{socks5Version, 1, methodNoAuth})
	readAndCheck(t, client, []byte{socks5Version, methodNoAuth})

	host := "target.com"
	req := []byte{socks5Version, cmdConnect, 0x00, atypDomain, byte(len(host))}
	req = append(req, host...)
	req = append(req, 0x01, 0xBB)
	writeAll(t, client, req)

	reply := make([]byte, 10)
	readFull(t, client, reply)
	if reply[1] != replySuccess {
		t.Fatalf("CONNECT reply code = 0x%02x, want success", reply[1])
	}

	writeAll(t, client, []byte("short-msg"))

	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("fake upstream error: %v", res.err)
		}
		if res.got != "short-msg" {
			t.Errorf("upstream got %q, want short-msg", res.got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("short payload did not reach upstream within 2s — relay stalled inside PeekSNI (regression)")
	}
}
