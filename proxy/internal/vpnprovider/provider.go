// Package vpnprovider defines the plugin boundary between mithril-proxy's
// SOCKS5 core (internal/proxy) and whatever upstream VPN/residential-
// proxy service actually carries traffic. Before this package existed,
// internal/proxy.Router talked to IPRoyal directly — it built an
// IPRoyal-specific password suffix (internal/proxy.BuildPassword) and
// dialed a fixed upstream address. That made IPRoyal load-bearing
// throughout the SOCKS5 core for no real reason: nothing about parsing
// a client's SOCKS5 request, matching routing.yaml, or relaying bytes
// is actually IPRoyal-specific.
//
// A Provider now owns everything that IS upstream-specific: how it
// authenticates, whether and how it accepts per-request geo/session
// targeting, and how a connection to it is actually established (SOCKS5
// with RFC 1929 auth, today — nothing here assumes that's the only
// option a future provider could use). internal/proxy depends only on
// the Provider interface below, so adding support for a new upstream —
// a different residential-proxy vendor, a plain SOCKS5/HTTP relay, a
// self-managed WireGuard tunnel — never requires touching
// internal/proxy, internal/proxy.Router, or the SOCKS5 handler.
//
// See docs/diagrams/provider-plugin-architecture.md for how this fits
// together, and internal/vpnprovider/iproyal for the reference
// implementation (the only provider that existed before this package
// did) and internal/vpnprovider/genericsocks5 for a second, drastically
// simpler one that proves the interface isn't secretly IPRoyal-shaped.
package vpnprovider

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"

	"gopkg.in/yaml.v3"
)

// RouteOptions carries routing.yaml's geo/session targeting intent to a
// Provider for one connection. Field names mirror IPRoyal's documented
// terms (docs.iproyal.com/proxies/residential/proxy/location and
// .../rotation) since IPRoyal is the first and best-documented provider
// this project integrates with, but the concepts — pick an exit
// country/city/ISP, optionally hold the same exit IP for a bounded
// lifetime — are common across most residential-proxy vendors (Bright
// Data, Smartproxy, Oxylabs all expose some equivalent). A Provider
// that doesn't support a given field, or doesn't support per-request
// targeting at all, is expected to silently ignore what it can't use
// rather than fail the connection — see genericsocks5 for the extreme
// case (ignores every field). That's what lets routing.yaml stay a
// single shared config across profiles that may use different
// providers, instead of needing a provider-specific dialect.
type RouteOptions struct {
	Country     string
	City        string
	State       string
	ISP         string
	Region      string
	Geolocation string
	SessionID   string // sticky session identifier; empty means rotating
	Lifetime    string // e.g. "2h" — only meaningful alongside SessionID
	ForceRandom bool
}

// Provider dials an upstream VPN/proxy service on behalf of one
// profiles.yaml profile. internal/proxy.Router holds exactly one
// Provider per profile (constructed once at startup, see main.go) and
// calls Dial for every accepted connection on that profile's listener —
// everything upstream-specific (credential encoding, entry-node
// selection, the wire protocol spoken to the upstream itself) lives
// entirely inside the implementation, never in internal/proxy.
type Provider interface {
	// Name identifies the provider, for logging — normally the same
	// string it was registered under (see Register).
	Name() string

	// Dial establishes a connection through this provider's upstream to
	// host:port, applying opts as best-effort routing intent per this
	// type's doc comment. ctx governs the dial itself, including any
	// out-of-band API calls a provider makes before opening the actual
	// data connection (e.g. resolving a fresh entry node) — it is NOT
	// expected to bound the lifetime of the returned net.Conn.
	Dial(ctx context.Context, host string, port uint16, opts RouteOptions) (net.Conn, error)
}

// Factory constructs a Provider from one profile's provider_config
// block, already decoded by gopkg.in/yaml.v3 into a generic map (see
// DecodeConfig for turning that back into a typed struct). Factories
// are expected to validate their own config and return a descriptive
// error rather than panic or leave a half-usable Provider.
type Factory func(config map[string]any) (Provider, error)

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
)

// Register makes a provider factory available under name, for
// config.Profile.Provider / New to look up by string at startup. This
// mirrors database/sql's driver registry: a provider package registers
// itself from init(), and main.go blank-imports every provider package
// it wants compiled into the binary —
//
//	import _ "github.com/dmaina5054/mithril/proxy/internal/vpnprovider/iproyal"
//
// Nothing is loaded dynamically at runtime (no Go plugin/.so loading —
// deliberately, that mechanism is fragile and Linux-distribution/
// toolchain-version sensitive); "pluggable" here means "implement one
// interface, register it, blank-import it," not hot-loading.
//
// Panics on an empty name or a duplicate registration — both are
// build-time programming errors in a provider package's init(), not
// something a Profile's YAML content could trigger.
func Register(name string, factory Factory) {
	mu.Lock()
	defer mu.Unlock()
	if name == "" {
		panic("vpnprovider: Register called with empty name")
	}
	if _, exists := factories[name]; exists {
		panic(fmt.Sprintf("vpnprovider: Register called twice for provider %q", name))
	}
	factories[name] = factory
}

// New builds the provider registered under name from config. Returns an
// error naming every currently-registered provider if name isn't
// found — that list only grows as more provider packages are blank-
// imported; this function never needs editing to support a new one.
func New(name string, config map[string]any) (Provider, error) {
	mu.RLock()
	factory, ok := factories[name]
	names := registeredLocked()
	mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("vpnprovider: unknown provider %q (registered: %v) — is its package blank-imported in main.go?", name, names)
	}
	p, err := factory(config)
	if err != nil {
		return nil, fmt.Errorf("vpnprovider: provider %q: %w", name, err)
	}
	return p, nil
}

// Registered returns every currently-registered provider name, sorted.
// Exported for startup logging and tests, not load-bearing for New.
func Registered() []string {
	mu.RLock()
	defer mu.RUnlock()
	return registeredLocked()
}

func registeredLocked() []string {
	names := make([]string, 0, len(factories))
	for n := range factories {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// DecodeConfig re-marshals raw — typically a profile's provider_config
// map, as produced by gopkg.in/yaml.v3 decoding profiles.yaml — into
// out, a pointer to a provider's own typed config struct. Implemented
// as a YAML round-trip rather than pulling in a dedicated map-to-struct
// library: gopkg.in/yaml.v3 is already a dependency (config package),
// provider configs are small, and this keeps `yaml:"..."` struct tags
// as the one place field names/defaults are declared, same as
// config.Profile itself.
func DecodeConfig(raw map[string]any, out any) error {
	b, err := yaml.Marshal(raw)
	if err != nil {
		return fmt.Errorf("vpnprovider: re-marshal config: %w", err)
	}
	if err := yaml.Unmarshal(b, out); err != nil {
		return fmt.Errorf("vpnprovider: decode config: %w", err)
	}
	return nil
}
