package brightdata

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
// saw. Self-contained, same pattern as the equivalent helper in
// internal/vpnprovider/iproyal — this package depends on
// internal/proxy only for DialUpstream/Credentials/Target, same as
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
		{"missing customer_id", Config{Zone: "z", Password: "p"}},
		{"missing zone", Config{CustomerID: "c", Password: "p"}},
		{"missing password", Config{CustomerID: "c", Zone: "z"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// TestBuildUsername_MatchesBrightDataDocs reproduces the worked
// examples from docs.brightdata.com/proxy-networks/config-options and
// .../api-reference/proxy/geolocation-targeting and .../rotate_ips —
// not invented.
func TestBuildUsername_MatchesBrightDataDocs(t *testing.T) {
	cases := []struct {
		name       string
		customerID string
		zone       string
		opts       vpnprovider.RouteOptions
		want       string
	}{
		{
			name:       "no targeting — base username unchanged",
			customerID: "123",
			zone:       "residential1",
			opts:       vpnprovider.RouteOptions{},
			want:       "brd-customer-123-zone-residential1",
		},
		{
			name:       "country",
			customerID: "123",
			zone:       "residential1",
			opts:       vpnprovider.RouteOptions{Country: "us"},
			want:       "brd-customer-123-zone-residential1-country-us",
		},
		{
			name:       "country + state",
			customerID: "123",
			zone:       "residential1",
			opts:       vpnprovider.RouteOptions{Country: "us", State: "ny"},
			want:       "brd-customer-123-zone-residential1-country-us-state-ny",
		},
		{
			name:       "country + city",
			customerID: "123",
			zone:       "residential1",
			opts:       vpnprovider.RouteOptions{Country: "fr", City: "paris"},
			want:       "brd-customer-123-zone-residential1-country-fr-city-paris",
		},
		{
			name:       "country + session (sticky IP)",
			customerID: "123",
			zone:       "residential1",
			opts:       vpnprovider.RouteOptions{Country: "us", SessionID: "abc123"},
			want:       "brd-customer-123-zone-residential1-country-us-session-abc123",
		},
		{
			name:       "session only, no country",
			customerID: "hl_7abed23d",
			zone:       "web_unlocker1",
			opts:       vpnprovider.RouteOptions{SessionID: "mystring12345"},
			want:       "brd-customer-hl_7abed23d-zone-web_unlocker1-session-mystring12345",
		},
		{
			name:       "lifetime and forcerandom have no Bright Data equivalent — ignored",
			customerID: "123",
			zone:       "residential1",
			opts:       vpnprovider.RouteOptions{Country: "us", SessionID: "abc123", Lifetime: "2h", ForceRandom: true},
			want:       "brd-customer-123-zone-residential1-country-us-session-abc123",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildUsername(tc.customerID, tc.zone, tc.opts)
			if got != tc.want {
				t.Errorf("buildUsername(%q, %q, %+v) = %q, want %q", tc.customerID, tc.zone, tc.opts, got, tc.want)
			}
		})
	}
}

func TestProvider_Dial_SendsBrightDataUsernameAndUnmodifiedPassword(t *testing.T) {
	addr, gotUsername, gotPassword := fakeUpstreamSOCKS5(t)

	p, err := New(Config{CustomerID: "123", Zone: "residential1", Password: "zonepass", UpstreamAddr: addr})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	conn, err := p.Dial(context.Background(), "target.example.com", 8443, vpnprovider.RouteOptions{
		Country:   "us",
		SessionID: "sess1234",
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()

	wantUsername := "brd-customer-123-zone-residential1-country-us-session-sess1234"
	if *gotUsername != wantUsername {
		t.Errorf("upstream saw username %q, want %q", *gotUsername, wantUsername)
	}
	// Unlike iproyal, the password must be sent completely unmodified —
	// Bright Data's targeting lives in the username, never the password.
	if *gotPassword != "zonepass" {
		t.Errorf("upstream saw password %q, want unmodified zonepass", *gotPassword)
	}
	if p.Name() != Name {
		t.Errorf("Name() = %q, want %q", p.Name(), Name)
	}
}

func TestProvider_Dial_RejectsPortAt1024OrBelow(t *testing.T) {
	p, err := New(Config{CustomerID: "123", Zone: "z", Password: "p", UpstreamAddr: "127.0.0.1:1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, port := range []uint16{1, 80, 1024} {
		if _, err := p.Dial(context.Background(), "target.example.com", port, vpnprovider.RouteOptions{}); err == nil {
			t.Errorf("port %d: expected error (Bright Data SOCKS5 requires >1024), got nil", port)
		} else if !strings.Contains(err.Error(), "1024") {
			t.Errorf("port %d: error %q doesn't mention the port constraint", port, err)
		}
	}
}

func TestProvider_Dial_RejectsIPLiteralTargets(t *testing.T) {
	p, err := New(Config{CustomerID: "123", Zone: "z", Password: "p", UpstreamAddr: "127.0.0.1:1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, host := range []string{"93.184.216.34", "::1"} {
		if _, err := p.Dial(context.Background(), host, 8443, vpnprovider.RouteOptions{}); err == nil {
			t.Errorf("host %q: expected error (Bright Data SOCKS5 blocks IP-literal targets), got nil", host)
		}
	}
}

func TestProvider_Dial_AllowsPortsAbove1024AndDomainTargets(t *testing.T) {
	addr, _, _ := fakeUpstreamSOCKS5(t)
	p, err := New(Config{CustomerID: "123", Zone: "z", Password: "p", UpstreamAddr: addr})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	conn, err := p.Dial(context.Background(), "target.example.com", 8443, vpnprovider.RouteOptions{})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()
}
