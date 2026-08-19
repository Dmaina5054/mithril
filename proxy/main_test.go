package main

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/dmaina5054/mithril/proxy/config"
	"github.com/dmaina5054/mithril/proxy/internal/proxy"
	"github.com/dmaina5054/mithril/proxy/internal/vpnprovider"
)

// fakeSOCKS5Upstream starts a minimal SOCKS5 server accepting username/
// password auth and any CONNECT, recording the credentials it saw and
// echoing back whatever it receives after CONNECT — enough to prove a
// real byte payload makes it all the way through Handle's relay, not
// just that the handshake completes. Self-contained, matching the
// pattern already used in internal/vpnprovider/{iproyal,brightdata}'s
// own tests.
func fakeSOCKS5Upstream(t *testing.T) (addr string, gotUsername, gotPassword *string) {
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
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		hdr := make([]byte, 2)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		methods := make([]byte, hdr[1])
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
		conn.Write([]byte{0x05, 0x02}) // select username/password

		authHdr := make([]byte, 2)
		if _, err := io.ReadFull(conn, authHdr); err != nil {
			return
		}
		uname := make([]byte, authHdr[1])
		if _, err := io.ReadFull(conn, uname); err != nil {
			return
		}
		plenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, plenByte); err != nil {
			return
		}
		passwd := make([]byte, plenByte[0])
		if _, err := io.ReadFull(conn, passwd); err != nil {
			return
		}
		username, password = string(uname), string(passwd)
		conn.Write([]byte{0x01, 0x00}) // auth success

		reqHdr := make([]byte, 4)
		if _, err := io.ReadFull(conn, reqHdr); err != nil {
			return
		}
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return
		}
		domainAndPort := make([]byte, int(lenByte[0])+2)
		if _, err := io.ReadFull(conn, domainAndPort); err != nil {
			return
		}
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // CONNECT success

		// Echo back whatever the client relays through — proves real
		// application data crosses the whole pipeline, not just the
		// handshake.
		io.Copy(conn, conn)
	}()

	return ln.Addr().String(), gotUsername, gotPassword
}

// TestBuildProvider_BrightDataProfile proves a profiles.yaml entry
// naming `provider: brightdata` actually produces a working Provider
// through main.go's own buildProvider — the exact function main()
// calls per profile — not a reimplementation of that wiring in the
// test.
func TestBuildProvider_BrightDataProfile(t *testing.T) {
	addr, gotUsername, gotPassword := fakeSOCKS5Upstream(t)

	p := config.Profile{
		Provider:   "brightdata",
		ListenPort: 1083,
		ProviderConfig: map[string]any{
			"customer_id":   "hl_test123",
			"zone":          "residential1",
			"password":      "zonepass",
			"upstream_addr": addr,
		},
	}

	provider, err := buildProvider("scrape-eu", p, "")
	if err != nil {
		t.Fatalf("buildProvider: %v", err)
	}
	if provider.Name() != "brightdata" {
		t.Fatalf("provider.Name() = %q, want brightdata", provider.Name())
	}

	conn, err := provider.Dial(t.Context(), "target.example.com", 8443, vpnprovider.RouteOptions{Country: "de"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()

	wantUsername := "brd-customer-hl_test123-zone-residential1-country-de"
	if *gotUsername != wantUsername {
		t.Errorf("upstream saw username %q, want %q", *gotUsername, wantUsername)
	}
	if *gotPassword != "zonepass" {
		t.Errorf("upstream saw password %q, want unmodified zonepass", *gotPassword)
	}
}

// TestBuildProvider_LegacyIProyalProfile is a regression test for
// buildProvider's backward-compatibility path: a profile with no
// `provider`/`provider_config` at all (every profiles.yaml written
// before the plugin layer existed) must still resolve to the iproyal
// provider, built from the profile's legacy top-level fields.
func TestBuildProvider_LegacyIProyalProfile(t *testing.T) {
	p := config.Profile{
		Username:   "legacy-user",
		Password:   "legacy-pass",
		ListenPort: 1080,
	}

	provider, err := buildProvider("default", p, "entry.iproyal.example:12345")
	if err != nil {
		t.Fatalf("buildProvider: %v", err)
	}
	if provider.Name() != "iproyal" {
		t.Errorf("provider.Name() = %q, want iproyal", provider.Name())
	}
}

// TestEndToEnd_SOCKS5ClientThroughBrightDataProvider drives a real
// client-side SOCKS5 conversation against proxy.Handle — the exact
// function every accepted connection on a profile's listener goes
// through in production (see main.go's Serve loop) — backed by a
// Router configured with a brightdata Provider built via
// buildProvider and a routing.yaml rule that targets Germany. Proves
// the full pipeline config.Profile -> buildProvider -> vpnprovider ->
// Router (routing.yaml match) -> Handle -> real relayed bytes, using
// only this repo's own production code, not a parallel
// reimplementation of any of it.
func TestEndToEnd_SOCKS5ClientThroughBrightDataProvider(t *testing.T) {
	addr, gotUsername, _ := fakeSOCKS5Upstream(t)

	profile := config.Profile{
		Provider:   "brightdata",
		ListenPort: 1083,
		ProviderConfig: map[string]any{
			"customer_id":   "hl_test123",
			"zone":          "residential1",
			"password":      "zonepass",
			"upstream_addr": addr,
		},
	}
	provider, err := buildProvider("scrape-eu", profile, "")
	if err != nil {
		t.Fatalf("buildProvider: %v", err)
	}

	routing := &config.RoutingConfig{
		Rules: []config.RoutingRule{
			{Pattern: "*.de.example.com", Country: "de", Session: config.SessionRotating},
		},
		Default: config.RoutingRule{Session: config.SessionRotating},
	}
	router := &proxy.Router{
		Name:     "scrape-eu",
		Provider: provider,
		Routing:  routing,
		Sessions: proxy.NewSessionStore(),
	}

	client, server := net.Pipe()
	defer client.Close()
	go proxy.Handle(server, router)

	client.SetDeadline(time.Now().Add(3 * time.Second))

	// RFC 1928 client greeting: version 5, 1 method, no-auth — this
	// proxy's local-facing listeners never require client auth (see
	// internal/proxy/socks5.go's package doc comment).
	writeAll(t, client, []byte{0x05, 0x01, 0x00})
	greetReply := make([]byte, 2)
	readFullT(t, client, greetReply)
	if greetReply[0] != 0x05 || greetReply[1] != 0x00 {
		t.Fatalf("greeting reply = % x, want version 5 / no-auth selected", greetReply)
	}

	// CONNECT request to a host that matches routing.yaml's German
	// rule above. Port 8443, not 443 — Bright Data's SOCKS5 endpoint
	// rejects target ports <= 1024 (see brightdata.Provider.Dial), and
	// this test wants to reach the fake upstream, not exercise that
	// rejection.
	host := "shop.de.example.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, 0x20, 0xFB) // port 8443 (0x20FB), big-endian
	writeAll(t, client, req)

	reply := make([]byte, 10)
	readFullT(t, client, reply)
	if reply[1] != 0x00 {
		t.Fatalf("CONNECT reply code = 0x%02x, want 0x00 success", reply[1])
	}

	// Real application data through the relay, echoed back by
	// fakeSOCKS5Upstream — proves this isn't just a successful
	// handshake with no actual data path.
	writeAll(t, client, []byte("GET / HTTP/1.1\r\n"))
	echo := make([]byte, len("GET / HTTP/1.1\r\n"))
	readFullT(t, client, echo)
	if string(echo) != "GET / HTTP/1.1\r\n" {
		t.Errorf("echoed payload = %q, want the request line back", echo)
	}

	wantUsername := "brd-customer-hl_test123-zone-residential1-country-de"
	if *gotUsername != wantUsername {
		t.Errorf("upstream saw username %q, want %q (routing.yaml's country=de rule should have reached the brightdata provider)", *gotUsername, wantUsername)
	}
}

func writeAll(t *testing.T, conn net.Conn, buf []byte) {
	t.Helper()
	if _, err := conn.Write(buf); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func readFullT(t *testing.T, conn net.Conn, buf []byte) {
	t.Helper()
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
}
