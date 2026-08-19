// Package iproyal implements vpnprovider.Provider for IPRoyal's
// residential SOCKS5 gateway. It is the reference implementation of the
// plugin interface — the only provider mithril-proxy spoke to before
// internal/vpnprovider existed — and the default when a profile omits
// `provider` entirely (see main.go's legacy-config fallback).
//
// Everything IPRoyal-specific lives here: the password-suffix geo/
// session targeting scheme (credential.go, confirmed against
// docs.iproyal.com) and the fixed upstream entry-node address. The
// actual wire protocol spoken to the upstream (SOCKS5 client-side,
// RFC 1928/1929) is NOT reimplemented here — it's generic enough that
// internal/proxy already provides it (DialUpstream), and other
// providers reuse the same helper; see genericsocks5 for a provider
// that uses it with none of this package's credential encoding at all.
package iproyal

import (
	"context"
	"fmt"
	"net"

	"github.com/dmaina5054/mithril/proxy/internal/proxy"
	"github.com/dmaina5054/mithril/proxy/internal/vpnprovider"
)

// Name is the provider name profiles.yaml's `provider:` field selects,
// and the zero-value default applied when that field is omitted.
const Name = "iproyal"

func init() {
	vpnprovider.Register(Name, func(raw map[string]any) (vpnprovider.Provider, error) {
		var cfg Config
		if err := vpnprovider.DecodeConfig(raw, &cfg); err != nil {
			return nil, err
		}
		return New(cfg)
	})
}

// Config is provider_config's shape for `provider: iproyal` — and, for
// backward compatibility, what main.go synthesizes from a profile's
// legacy top-level username/password/subuser_hash/upstream_addr fields
// when provider_config is omitted (see main.go's buildProvider).
type Config struct {
	Username string `yaml:"username"`
	// Password is the base IPRoyal sub-user password; Dial appends the
	// per-request geo/session suffix on top of it — the base password
	// alone is never sent upstream as-is.
	Password string `yaml:"password"`
	// SubuserHash is informational only today (from the IPRoyal
	// dashboard) — nothing in this package reads it yet; kept so
	// profiles.yaml round-trips the value operators already have on
	// hand for the corresponding sub-user.
	SubuserHash string `yaml:"subuser_hash,omitempty"`
	// UpstreamAddr is a fixed IPRoyal entry node (host:port). Automatic
	// selection via internal/iproyal.Client.EntryNodes() isn't wired in
	// yet — this has to be set explicitly, per profile or via main.go's
	// MITHRIL_UPSTREAM_ADDR fallback.
	UpstreamAddr string `yaml:"upstream_addr"`
}

func (c Config) validate() error {
	if c.Username == "" {
		return fmt.Errorf("iproyal: username is required")
	}
	if c.Password == "" {
		return fmt.Errorf("iproyal: password is required")
	}
	if c.UpstreamAddr == "" {
		return fmt.Errorf("iproyal: upstream_addr is required (an IPRoyal entry node host:port — automatic selection isn't wired up yet)")
	}
	return nil
}

// Provider implements vpnprovider.Provider for one IPRoyal sub-user.
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

// Dial encodes opts into an IPRoyal password suffix (see credential.go)
// and dials the configured upstream entry node via the shared SOCKS5
// client-side implementation in internal/proxy.
func (p *Provider) Dial(ctx context.Context, host string, port uint16, opts vpnprovider.RouteOptions) (net.Conn, error) {
	password := buildPassword(p.cfg.Password, credentialOptions{
		Country:     opts.Country,
		City:        opts.City,
		State:       opts.State,
		ISP:         opts.ISP,
		Region:      opts.Region,
		Geolocation: opts.Geolocation,
		SessionID:   opts.SessionID,
		Lifetime:    opts.Lifetime,
		ForceRandom: opts.ForceRandom,
	})
	creds := proxy.Credentials{Username: p.cfg.Username, Password: password}
	target := proxy.Target{Host: host, Port: port}

	conn, err := proxy.DialUpstream(p.cfg.UpstreamAddr, creds, target, proxy.DialTimeout)
	if err != nil {
		return nil, err
	}

	// proxy.DialUpstream predates context support and can't be
	// interrupted mid-handshake, but honor an already-canceled ctx
	// immediately rather than handing back a connection nobody wants.
	select {
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	default:
		return conn, nil
	}
}
