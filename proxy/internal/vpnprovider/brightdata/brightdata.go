// Package brightdata implements vpnprovider.Provider for Bright Data's
// residential/ISP/datacenter proxy network — a real third-party vendor
// integration (unlike genericsocks5, which is a deliberately trivial
// proof of concept), added specifically to test the plugin layer
// against a provider whose shape genuinely differs from IPRoyal's:
//
//   - Geo/session targeting is encoded into the USERNAME
//     ("brd-customer-<id>-zone-<zone>-country-us-session-abc123"), not
//     appended to the password like IPRoyal's suffix scheme — the
//     opposite half of the credential pair carries the same kind of
//     information. Confirmed against docs.brightdata.com/proxy-
//     networks/config-options,
//     docs.brightdata.com/api-reference/proxy/geolocation-targeting,
//     and docs.brightdata.com/api-reference/proxy/rotate_ips (session).
//   - The upstream is a fixed, vendor-operated host
//     (brd.superproxy.io:22228 for SOCKS5, confirmed against
//     docs.brightdata.com/proxy-networks/socks5) — there's no per-
//     account entry-node discovery step the way IPRoyal's
//     internal/iproyal.Client (not wired into iproyal's provider
//     either, for what it's worth) implies.
//   - Bright Data's SOCKS5 endpoint has its own hard constraints,
//     confirmed against the same SOCKS5 doc page: target ports must be
//     > 1024, and targets must be domain names, not IP literals (the
//     vendor blocks IP-literal CONNECT requests outright). Both are
//     validated here with a clear error rather than left to fail
//     confusingly against the real upstream.
//
// Session lifetime (IPRoyal's `-session-x_lifetime-y`) has no Bright
// Data equivalent in the username — Bright Data controls sticky-
// session duration from the zone's dashboard settings, not a per-
// request parameter — so RouteOptions.Lifetime is silently ignored
// here, same "ignore what you can't act on" contract every provider
// follows (see vpnprovider.RouteOptions's doc comment). ForceRandom
// and Geolocation (IPRoyal-specific parameter names) have no
// documented Bright Data equivalent either and are likewise ignored.
package brightdata

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/dmaina5054/mithril/proxy/internal/proxy"
	"github.com/dmaina5054/mithril/proxy/internal/vpnprovider"
)

// Name is the provider name profiles.yaml's `provider:` field selects.
const Name = "brightdata"

// defaultUpstreamAddr is Bright Data's fixed SOCKS5 endpoint — see this
// package's doc comment. Overridable via Config.UpstreamAddr, mainly
// so tests can point Dial at a fake upstream instead.
const defaultUpstreamAddr = "brd.superproxy.io:22228"

func init() {
	vpnprovider.Register(Name, func(raw map[string]any) (vpnprovider.Provider, error) {
		var cfg Config
		if err := vpnprovider.DecodeConfig(raw, &cfg); err != nil {
			return nil, err
		}
		return New(cfg)
	})
}

// Config is provider_config's shape for `provider: brightdata`.
type Config struct {
	// CustomerID is the account identifier from Bright Data's Access
	// Details panel (docs' [ACCOUNT_ID], e.g. "hl_7abed23d").
	CustomerID string `yaml:"customer_id"`
	// Zone is the proxy zone's name (docs' [PROXY_NAME]/[ZONE_NAME]),
	// e.g. "residential1" — set once at zone creation, per Bright
	// Data's docs, and can't be renamed afterward.
	Zone string `yaml:"zone"`
	// Password is the zone's password from Access Details — sent
	// as-is; unlike IPRoyal, Bright Data's targeting parameters go in
	// the username, not here.
	Password string `yaml:"password"`
	// UpstreamAddr overrides Bright Data's fixed SOCKS5 host:port
	// (defaultUpstreamAddr) — leave unset in production; exists mainly
	// for tests.
	UpstreamAddr string `yaml:"upstream_addr,omitempty"`
}

func (c Config) validate() error {
	if c.CustomerID == "" {
		return fmt.Errorf("brightdata: customer_id is required")
	}
	if c.Zone == "" {
		return fmt.Errorf("brightdata: zone is required")
	}
	if c.Password == "" {
		return fmt.Errorf("brightdata: password is required")
	}
	return nil
}

func (c Config) upstreamAddr() string {
	if c.UpstreamAddr != "" {
		return c.UpstreamAddr
	}
	return defaultUpstreamAddr
}

// Provider implements vpnprovider.Provider for one Bright Data zone.
type Provider struct {
	cfg Config
}

// New validates cfg and returns a ready-to-use Provider.
func New(cfg Config) (*Provider, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Provider{cfg: cfg}, nil
}

func (p *Provider) Name() string { return Name }

// Dial encodes opts into a Bright Data username suffix (see
// buildUsername), validates the two hard SOCKS5-specific constraints
// Bright Data's docs call out (port > 1024, domain-name target only),
// and dials the fixed upstream via the shared SOCKS5 client-side
// implementation in internal/proxy — same DialUpstream both other
// reference providers use; Bright Data's SOCKS5 endpoint is a
// standard RFC 1928/1929 server like IPRoyal's and genericsocks5's,
// nothing bespoke needed at the wire-protocol layer.
func (p *Provider) Dial(ctx context.Context, host string, port uint16, opts vpnprovider.RouteOptions) (net.Conn, error) {
	if port <= 1024 {
		return nil, fmt.Errorf("brightdata: target port %d not supported — Bright Data's SOCKS5 endpoint only allows target ports above 1024", port)
	}
	if net.ParseIP(host) != nil {
		return nil, fmt.Errorf("brightdata: target %q is an IP literal — Bright Data's SOCKS5 endpoint requires a domain name target, IP literals are blocked upstream", host)
	}

	username := buildUsername(p.cfg.CustomerID, p.cfg.Zone, opts)
	creds := proxy.Credentials{Username: username, Password: p.cfg.Password}
	target := proxy.Target{Host: host, Port: port}

	conn, err := proxy.DialUpstream(p.cfg.upstreamAddr(), creds, target, proxy.DialTimeout)
	if err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	default:
		return conn, nil
	}
}

// buildUsername assembles Bright Data's
// "brd-customer-<id>-zone-<zone>-<param>-<value>-..." username, per
// this package's doc comment. Empty opts fields are omitted entirely,
// same convention as iproyal's buildPassword. Order (country, state,
// city, session) matches the sequence Bright Data's own docs show in
// worked examples; Bright Data's docs don't say order is significant,
// but keeping one fixed, documented order makes usernames
// deterministic and diffable in logs.
func buildUsername(customerID, zone string, opts vpnprovider.RouteOptions) string {
	var b strings.Builder
	fmt.Fprintf(&b, "brd-customer-%s-zone-%s", customerID, zone)

	if opts.Country != "" {
		fmt.Fprintf(&b, "-country-%s", opts.Country)
	}
	if opts.State != "" {
		fmt.Fprintf(&b, "-state-%s", opts.State)
	}
	if opts.City != "" {
		fmt.Fprintf(&b, "-city-%s", opts.City)
	}
	if opts.SessionID != "" {
		fmt.Fprintf(&b, "-session-%s", opts.SessionID)
	}

	return b.String()
}
