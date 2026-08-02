// Package config loads routing.yaml and profiles.yaml. Runtime config on
// Minas Tirith lives at /etc/socks5-proxy/ — this package only implements
// the loader.
package config

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

type SessionMode string

const (
	SessionSticky   SessionMode = "sticky"
	SessionRotating SessionMode = "rotating"
)

// RoutingRule matches a destination hostname pattern (glob syntax per
// path.Match — "*.comfy.example.com") to IPRoyal geo-targeting and
// session parameters. Field names mirror IPRoyal's documented password
// suffix keys (docs.iproyal.com/proxies/residential/proxy/location and
// .../rotation) so the mapping in credential.go is a direct pass-through.
type RoutingRule struct {
	Pattern  string      `yaml:"pattern"`
	Country  string      `yaml:"country,omitempty"`
	City     string      `yaml:"city,omitempty"`
	State    string      `yaml:"state,omitempty"`
	ISP      string      `yaml:"isp,omitempty"`
	Region   string      `yaml:"region,omitempty"`
	Session  SessionMode `yaml:"session"`
	Lifetime string      `yaml:"lifetime,omitempty"` // e.g. "2h" — IPRoyal accepts 1s-7d, single unit
}

type RoutingConfig struct {
	Rules   []RoutingRule `yaml:"rules"`
	Default RoutingRule   `yaml:"default"`
}

var lifetimePattern = regexp.MustCompile(`^\d+[smhd]$`)

// Validate checks structural rules that yaml.Unmarshal won't catch:
// every pattern must be a valid glob, session must be sticky/rotating,
// sticky rules need a lifetime IPRoyal will actually accept (1s-7d,
// single unit).
func (c *RoutingConfig) Validate() error {
	all := append([]RoutingRule{c.Default}, c.Rules...)
	for i, r := range all {
		label := fmt.Sprintf("rule[%d] (pattern=%q)", i-1, r.Pattern)
		if i == 0 {
			label = "default"
		}

		if r.Pattern != "" {
			if _, err := path.Match(r.Pattern, "probe"); err != nil {
				return fmt.Errorf("routing: %s: invalid pattern: %w", label, err)
			}
		}

		switch r.Session {
		case SessionSticky, SessionRotating, "":
		default:
			return fmt.Errorf("routing: %s: session must be %q or %q, got %q", label, SessionSticky, SessionRotating, r.Session)
		}

		if r.Session == SessionSticky {
			lifetime := r.Lifetime
			if lifetime == "" {
				lifetime = "2h" // spec default for sticky/image jobs
			}
			if !lifetimePattern.MatchString(lifetime) {
				return fmt.Errorf("routing: %s: lifetime %q doesn't match IPRoyal's format (digits + one of s/m/h/d)", label, lifetime)
			}
			if _, err := time.ParseDuration(lifetime); err != nil {
				return fmt.Errorf("routing: %s: lifetime %q: %w", label, lifetime, err)
			}
		}
	}
	return nil
}

// Match returns the first rule whose Pattern matches hostname (glob,
// via path.Match), in the order rules are declared. Falls back to
// Default if nothing matches.
//
// path.Match treats '/' as the only separator character, and hostnames
// have none — so "*" matches across dots, not just one label. Pattern
// "*.example.com" matches both "api.example.com" and
// "a.b.example.com", unlike typical wildcard-cert semantics where "*"
// only ever covers one label. Write patterns with that in mind.
func (c *RoutingConfig) Match(hostname string) RoutingRule {
	for _, r := range c.Rules {
		if ok, err := path.Match(r.Pattern, hostname); err == nil && ok {
			return r
		}
	}
	return c.Default
}

func LoadRoutingConfig(configPath string) (*RoutingConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("routing: read %s: %w", configPath, err)
	}
	var cfg RoutingConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("routing: parse %s: %w", configPath, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
