package proxy

import (
	"io"
	"net"
	"testing"
	"time"
)

// fakeUpstream starts a listener that plays the server side of one
// SOCKS5 client-auth-connect exchange, then hands the accepted conn to
// fn for custom reply behavior. Returns the listener address.
func fakeUpstream(t *testing.T, fn func(t *testing.T, conn net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fn(t, conn)
	}()

	return ln.Addr().String()
}

func TestDialUpstream_Success(t *testing.T) {
	addr := fakeUpstream(t, func(t *testing.T, conn net.Conn) {
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		// Greeting
		hdr := make([]byte, 2)
		readFull(t, conn, hdr)
		methods := make([]byte, hdr[1])
		readFull(t, conn, methods)
		writeAll(t, conn, []byte{socks5Version, methodUserPass})

		// Auth subnegotiation
		authHdr := make([]byte, 2)
		readFull(t, conn, authHdr)
		uname := make([]byte, authHdr[1])
		readFull(t, conn, uname)
		plenByte := make([]byte, 1)
		readFull(t, conn, plenByte)
		passwd := make([]byte, plenByte[0])
		readFull(t, conn, passwd)

		if string(uname) != "geo-us_session-abc123" {
			t.Errorf("upstream got username %q, want geo-us_session-abc123", uname)
		}
		if string(passwd) != "secretpass" {
			t.Errorf("upstream got password %q, want secretpass", passwd)
		}
		writeAll(t, conn, []byte{userPassAuthVersion, authStatusSuccess})

		// CONNECT request
		reqHdr := make([]byte, 4)
		readFull(t, conn, reqHdr)
		if reqHdr[3] != atypDomain {
			t.Fatalf("expected domain ATYP, got 0x%02x", reqHdr[3])
		}
		lenByte := make([]byte, 1)
		readFull(t, conn, lenByte)
		domain := make([]byte, lenByte[0])
		readFull(t, conn, domain)
		port := make([]byte, 2)
		readFull(t, conn, port)
		if string(domain) != "httpbin.org" {
			t.Errorf("upstream got CONNECT domain %q, want httpbin.org", domain)
		}

		// Success reply, IPv4 bind addr
		writeAll(t, conn, []byte{socks5Version, replySuccess, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	})

	creds := Credentials{Username: "geo-us_session-abc123", Password: "secretpass"}
	conn, err := DialUpstream(addr, creds, Target{Host: "httpbin.org", Port: 443}, 2*time.Second)
	if err != nil {
		t.Fatalf("DialUpstream: %v", err)
	}
	conn.Close()
}

func TestDialUpstream_AuthFailure(t *testing.T) {
	addr := fakeUpstream(t, func(t *testing.T, conn net.Conn) {
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		hdr := make([]byte, 2)
		readFull(t, conn, hdr)
		methods := make([]byte, hdr[1])
		readFull(t, conn, methods)
		writeAll(t, conn, []byte{socks5Version, methodUserPass})

		authHdr := make([]byte, 2)
		readFull(t, conn, authHdr)
		_ = drain(t, conn, int(authHdr[1]))
		plenByte := make([]byte, 1)
		readFull(t, conn, plenByte)
		_ = drain(t, conn, int(plenByte[0]))

		// Auth failure — wrong credentials.
		writeAll(t, conn, []byte{userPassAuthVersion, authStatusFailure})
	})

	creds := Credentials{Username: "wrong", Password: "wrong"}
	_, err := DialUpstream(addr, creds, Target{Host: "httpbin.org", Port: 443}, 2*time.Second)
	if err == nil {
		t.Fatal("expected error on auth failure, got nil")
	}
}

func TestDialUpstream_NoAcceptableMethod(t *testing.T) {
	addr := fakeUpstream(t, func(t *testing.T, conn net.Conn) {
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		hdr := make([]byte, 2)
		readFull(t, conn, hdr)
		methods := make([]byte, hdr[1])
		readFull(t, conn, methods)
		writeAll(t, conn, []byte{socks5Version, methodNoAcceptable})
	})

	creds := Credentials{Username: "u", Password: "p"}
	_, err := DialUpstream(addr, creds, Target{Host: "httpbin.org", Port: 443}, 2*time.Second)
	if err == nil {
		t.Fatal("expected error when upstream rejects all methods, got nil")
	}
}

func drain(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if n == 0 {
		return buf
	}
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("drain: %v", err)
	}
	return buf
}
