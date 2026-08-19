// Package genericsocks5 implements vpnprovider.Provider for any upstream
// that simply speaks SOCKS5 (RFC 1928), with optional RFC 1929
// username/password auth, and does whatever exit-node/geo selection it
// does out of band — a fixed-country subscription, a self-hosted relay,
// Tor's local SOCKS5 port, a corporate VPN's SOCKS5 endpoint, or any
// other "VPN capability" whose vendor doesn't expose IPRoyal's per-
// request password-suffix targeting scheme.
//
// This is the second reference provider (after
// internal/vpnprovider/iproyal), included specifically to prove the
// vpnprovider.Provider interface isn't secretly IPRoyal-shaped: it has
// no credential-encoding logic at all and ignores every
// vpnprovider.RouteOptions field, yet plugs into the exact same
// internal/proxy.Router / SOCKS5 handler with zero changes to either.
// Hooking up a real third-party VPN typically means writing something
// between this package's simplicity and iproyal's (own credential
// scheme, own entry-node API, maybe a non-SOCKS5 wire protocol) — see
// docs/diagrams/provider-plugin-architecture.md for the checklist.
package genericsocks5

import (
	"context"
	"fmt"
	"net"

	"github.com/dmaina5054/mithril/proxy/internal/proxy"
	"github.com/dmaina5054/mithril/proxy/internal/vpnprovider"
)

// Name is the provider name profiles.yaml's `provider:` field selects.
const Name = "socks5"

func init() {
	vpnprovider.Register(Name, func(raw map[string]any) (vpnprovider.Provider, error) {
		var cfg Config
		if err := vpnprovider.DecodeConfig(raw, &cfg); err != nil {
			return nil, err
		}
		return New(cfg)
	})
}

// Config is provider_config's shape for `provider: socks5`.
type Config struct {
	// UpstreamAddr is the SOCKS5 server to dial, host:port.
	UpstreamAddr string `yaml:"upstream_addr"`
	// Username/Password are optional RFC 1929 credentials. Leave both
	// empty for an upstream that accepts no-auth connections.
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

func (c Config) validate() error {
	if c.UpstreamAddr == "" {
		return fmt.Errorf("socks5: upstream_addr is required")
	}
	return nil
}

// Provider implements vpnprovider.Provider for a plain SOCKS5 upstream.
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

// Dial ignores opts entirely — this provider has no concept of per-
// request geo/session targeting. routing.yaml rules still match and
// run (Router still computes a RouteOptions), but its
// Country/Session/etc. fields are simply discarded here. That's a
// deliberate, documented limitation, not a bug: a provider that can't
// act on a RouteOptions field is expected to ignore it rather than
// error, so routing.yaml stays one shared config across every profile
// regardless of which provider it uses (see vpnprovider.RouteOptions's
// doc comment).
func (p *Provider) Dial(ctx context.Context, host string, port uint16, _ vpnprovider.RouteOptions) (net.Conn, error) {
	creds := proxy.Credentials{Username: p.cfg.Username, Password: p.cfg.Password}
	target := proxy.Target{Host: host, Port: port}

	conn, err := proxy.DialUpstream(p.cfg.UpstreamAddr, creds, target, proxy.DialTimeout)
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
