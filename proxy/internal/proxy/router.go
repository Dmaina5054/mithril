package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/dmaina5054/mithril/proxy/config"
	"github.com/dmaina5054/mithril/proxy/internal/vpnprovider"
)

// Router implements Resolver using routing.yaml's geo/session rules and
// one profiles.yaml entry's Provider. One Router per listening
// port/profile (see main.go) — Handle/Serve don't change between
// StaticResolver (used before Session B Phase 3 added routing) and
// this, and haven't changed again since the vpnprovider plugin layer
// replaced Router's direct IPRoyal dependency: Router now knows how to
// turn a routing.yaml match into a provider-agnostic RouteOptions, and
// nothing about IPRoyal specifically.
type Router struct {
	// Name is the profile name (profiles.yaml's map key) — used only as
	// a session-store key prefix, never sent upstream or passed to
	// Provider.
	Name     string
	Provider vpnprovider.Provider
	Routing  *config.RoutingConfig
	Sessions *SessionStore
}

// Dial implements Resolver: matches target.Host against Routing,
// resolves (and, for sticky rules, reuses) a session id, then hands
// the resulting RouteOptions to Provider.Dial.
func (r *Router) Dial(ctx context.Context, target Target, timeout time.Duration) (net.Conn, error) {
	if r.Provider == nil {
		return nil, fmt.Errorf("router: no provider configured for profile %q", r.Name)
	}
	if r.Routing == nil {
		return nil, fmt.Errorf("router: no routing config loaded")
	}

	rule := r.Routing.Match(target.Host)

	opts := vpnprovider.RouteOptions{
		Country: rule.Country,
		City:    rule.City,
		State:   rule.State,
		ISP:     rule.ISP,
		Region:  rule.Region,
	}

	if rule.Session == config.SessionSticky {
		lifetime := rule.Lifetime
		if lifetime == "" {
			lifetime = "2h" // spec default for sticky/image jobs
		}
		ttl, err := time.ParseDuration(lifetime)
		if err != nil {
			return nil, fmt.Errorf("router: invalid lifetime %q for host %q: %w", lifetime, target.Host, err)
		}

		sessionKey := r.Name + "|" + target.Host
		sessionID, err := r.Sessions.GetOrCreate(sessionKey, ttl)
		if err != nil {
			return nil, fmt.Errorf("router: %w", err)
		}
		opts.SessionID = sessionID
		opts.Lifetime = lifetime
	}
	// SessionRotating (or unset): no session/lifetime keys — providers
	// that support rotation at all treat "no SessionID" as the signal.

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := r.Provider.Dial(dialCtx, target.Host, target.Port, opts)
	if err != nil {
		return nil, fmt.Errorf("router: profile %q: provider %q: %w", r.Name, r.Provider.Name(), err)
	}
	return conn, nil
}
