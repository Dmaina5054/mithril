package proxy

import (
	"fmt"
	"time"

	"github.com/dmaina5054/mithril/proxy/config"
)

// Router implements Resolver using routing.yaml's geo/session rules and
// one profiles.yaml entry's base credentials. One Router per listening
// port/profile (see main.go) — Handle/Serve don't change between
// Phase 2's StaticResolver and this.
type Router struct {
	Profile config.Profile
	Routing *config.RoutingConfig
	// UpstreamAddr is a fixed IPRoyal entry node for now — Phase 1's
	// EntryNodes() benchmarking isn't wired into automatic selection
	// yet, that's follow-up work, not part of this phase's gate.
	UpstreamAddr string
	Sessions     *SessionStore
}

func (r *Router) Resolve(target Target) (string, Credentials, error) {
	if r.UpstreamAddr == "" {
		return "", Credentials{}, fmt.Errorf("router: no upstream address configured for profile %q", r.Profile.Username)
	}
	if r.Routing == nil {
		return "", Credentials{}, fmt.Errorf("router: no routing config loaded")
	}

	rule := r.Routing.Match(target.Host)

	opts := CredentialOptions{
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
			return "", Credentials{}, fmt.Errorf("router: invalid lifetime %q for host %q: %w", lifetime, target.Host, err)
		}

		sessionKey := r.Profile.Username + "|" + target.Host
		sessionID, err := r.Sessions.GetOrCreate(sessionKey, ttl)
		if err != nil {
			return "", Credentials{}, fmt.Errorf("router: %w", err)
		}
		opts.SessionID = sessionID
		opts.Lifetime = lifetime
	}
	// SessionRotating (or unset): no session/lifetime keys — IPRoyal's
	// docs are explicit that randomize rotation needs nothing added.

	password := BuildPassword(r.Profile.Password, opts)

	return r.UpstreamAddr, Credentials{Username: r.Profile.Username, Password: password}, nil
}
