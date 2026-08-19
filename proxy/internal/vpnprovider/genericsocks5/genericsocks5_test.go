package genericsocks5

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/dmaina5054/mithril/proxy/internal/vpnprovider"
)

// fakeNoAuthUpstream starts a minimal SOCKS5 server that accepts
// no-auth connections and any CONNECT. Self-contained on purpose — see
// the equivalent helper in internal/vpnprovider/iproyal for why this
// isn't shared across provider packages.
func fakeNoAuthUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))

				hdr := make([]byte, 2)
				if _, err := readFull(conn, hdr); err != nil {
					return
				}
				methods := make([]byte, hdr[1])
				if _, err := readFull(conn, methods); err != nil {
					return
				}
				conn.Write([]byte{0x05, 0x00}) // select no-auth

				reqHdr := make([]byte, 4)
				if _, err := readFull(conn, reqHdr); err != nil {
					return
				}
				lenByte := make([]byte, 1)
				if _, err := readFull(conn, lenByte); err != nil {
					return
				}
				domainAndPort := make([]byte, int(lenByte[0])+2)
				if _, err := readFull(conn, domainAndPort); err != nil {
					return
				}
				conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // CONNECT success
			}(conn)
		}
	}()

	return ln.Addr().String()
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := conn.Read(buf[n:])
		if err != nil {
			return n, err
		}
		n += m
	}
	return n, nil
}

func TestNew_RequiresUpstreamAddr(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error for missing upstream_addr, got nil")
	}
}

func TestProvider_Dial_IgnoresRouteOptions(t *testing.T) {
	addr := fakeNoAuthUpstream(t)
	p, err := New(Config{UpstreamAddr: addr})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Two very different RouteOptions must behave identically — this
	// provider has no way to act on either, and must not error just
	// because a routing.yaml rule asked for something it can't do.
	for _, opts := range []vpnprovider.RouteOptions{
		{},
		{Country: "us", SessionID: "abc123", Lifetime: "2h"},
	} {
		conn, err := p.Dial(context.Background(), "target.example.com", 443, opts)
		if err != nil {
			t.Fatalf("Dial(%+v): %v", opts, err)
		}
		conn.Close()
	}

	if p.Name() != "socks5" {
		t.Errorf("Name() = %q, want socks5", p.Name())
	}
}
