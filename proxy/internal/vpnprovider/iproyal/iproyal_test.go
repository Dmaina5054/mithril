package iproyal

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dmaina5054/mithril/proxy/internal/vpnprovider"
)

// fakeUpstreamSOCKS5 starts a minimal SOCKS5 server that accepts
// username/password auth and any CONNECT, recording the credentials it
// saw. Deliberately self-contained rather than importing
// internal/proxy's test helpers — this package is meant to depend on
// internal/proxy only for DialUpstream/Credentials/Target, the same as
// production code, not its test internals.
func fakeUpstreamSOCKS5(t *testing.T) (addr string, gotUsername, gotPassword *string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	var username, password string
	gotUsername, gotPassword = &username, &password

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
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
		conn.Write([]byte{0x05, 0x02}) // select username/password

		authHdr := make([]byte, 2)
		if _, err := readFull(conn, authHdr); err != nil {
			return
		}
		uname := make([]byte, authHdr[1])
		if _, err := readFull(conn, uname); err != nil {
			return
		}
		plenByte := make([]byte, 1)
		if _, err := readFull(conn, plenByte); err != nil {
			return
		}
		passwd := make([]byte, plenByte[0])
		if _, err := readFull(conn, passwd); err != nil {
			return
		}
		username, password = string(uname), string(passwd)
		conn.Write([]byte{0x01, 0x00}) // auth success

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
	}()

	return ln.Addr().String(), gotUsername, gotPassword
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

func TestNew_ValidatesRequiredFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing username", Config{Password: "p", UpstreamAddr: "x:1"}},
		{"missing password", Config{Username: "u", UpstreamAddr: "x:1"}},
		{"missing upstream_addr", Config{Username: "u", Password: "p"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestProvider_Dial_EncodesRouteOptionsIntoPassword(t *testing.T) {
	addr, gotUsername, gotPassword := fakeUpstreamSOCKS5(t)

	p, err := New(Config{Username: "kioolabs", Password: "basepass", UpstreamAddr: addr})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	conn, err := p.Dial(context.Background(), "target.example.com", 443, vpnprovider.RouteOptions{
		Country:   "us",
		SessionID: "sess1234",
		Lifetime:  "2h",
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()

	if *gotUsername != "kioolabs" {
		t.Errorf("upstream saw username %q, want kioolabs (profile username is never modified)", *gotUsername)
	}
	if !strings.Contains(*gotPassword, "_country-us") || !strings.Contains(*gotPassword, "_session-sess1234") || !strings.Contains(*gotPassword, "_lifetime-2h") {
		t.Errorf("upstream saw password %q, missing expected targeting suffix", *gotPassword)
	}
	if p.Name() != "iproyal" {
		t.Errorf("Name() = %q, want iproyal", p.Name())
	}
}

func TestProvider_Dial_RejectsAlreadyCanceledContext(t *testing.T) {
	addr, _, _ := fakeUpstreamSOCKS5(t)
	p, err := New(Config{Username: "u", Password: "p", UpstreamAddr: addr})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := p.Dial(ctx, "target.example.com", 443, vpnprovider.RouteOptions{}); err == nil {
		t.Fatal("expected error for already-canceled context, got nil")
	}
}
