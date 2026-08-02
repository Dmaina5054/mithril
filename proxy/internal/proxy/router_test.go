package proxy

import (
	"strings"
	"testing"

	"github.com/dmaina5054/mithril/proxy/config"
)

func TestRouter_StickyRuleAddsSessionAndReuses(t *testing.T) {
	routing := &config.RoutingConfig{
		Rules: []config.RoutingRule{
			{Pattern: "*.comfy.example.com", Country: "us", Session: config.SessionSticky, Lifetime: "2h"},
		},
		Default: config.RoutingRule{Session: config.SessionRotating},
	}
	r := &Router{
		Profile:      config.Profile{Username: "kioolabs", Password: "basepass"},
		Routing:      routing,
		UpstreamAddr: "upstream.example:1080",
		Sessions:     NewSessionStore(),
	}

	target := Target{Host: "api.comfy.example.com", Port: 443}

	addr, creds, err := r.Resolve(target)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if addr != "upstream.example:1080" {
		t.Errorf("addr = %q, want upstream.example:1080", addr)
	}
	if creds.Username != "kioolabs" {
		t.Errorf("Username = %q, want kioolabs (profile username is never modified)", creds.Username)
	}
	if !strings.Contains(creds.Password, "_country-us") {
		t.Errorf("password %q missing _country-us", creds.Password)
	}
	if !strings.Contains(creds.Password, "_lifetime-2h") {
		t.Errorf("password %q missing _lifetime-2h", creds.Password)
	}

	// Second resolve for the same host must reuse the same session id —
	// that's the entire point of "sticky".
	_, creds2, err := r.Resolve(target)
	if err != nil {
		t.Fatalf("Resolve (2nd): %v", err)
	}
	if creds.Password != creds2.Password {
		t.Errorf("sticky session password changed between calls:\n  1st: %s\n  2nd: %s", creds.Password, creds2.Password)
	}
}

func TestRouter_RotatingRuleOmitsSessionKeys(t *testing.T) {
	routing := &config.RoutingConfig{
		Rules: []config.RoutingRule{
			{Pattern: "*.scrape.example.com", Country: "us", Session: config.SessionRotating},
		},
		Default: config.RoutingRule{Session: config.SessionRotating},
	}
	r := &Router{
		Profile:      config.Profile{Username: "kioolabs", Password: "basepass"},
		Routing:      routing,
		UpstreamAddr: "upstream.example:1080",
		Sessions:     NewSessionStore(),
	}

	_, creds, err := r.Resolve(Target{Host: "job.scrape.example.com", Port: 443})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if strings.Contains(creds.Password, "_session-") || strings.Contains(creds.Password, "_lifetime-") {
		t.Errorf("rotating rule should not add session/lifetime keys, got %q", creds.Password)
	}
	if !strings.Contains(creds.Password, "_country-us") {
		t.Errorf("password %q missing _country-us", creds.Password)
	}
}

func TestRouter_DifferentHostsGetDifferentStickySessions(t *testing.T) {
	routing := &config.RoutingConfig{
		Default: config.RoutingRule{Session: config.SessionSticky, Lifetime: "1h"},
	}
	r := &Router{
		Profile:      config.Profile{Username: "kioolabs", Password: "basepass"},
		Routing:      routing,
		UpstreamAddr: "upstream.example:1080",
		Sessions:     NewSessionStore(),
	}

	_, credsA, err := r.Resolve(Target{Host: "a.example.com", Port: 443})
	if err != nil {
		t.Fatalf("Resolve a: %v", err)
	}
	_, credsB, err := r.Resolve(Target{Host: "b.example.com", Port: 443})
	if err != nil {
		t.Fatalf("Resolve b: %v", err)
	}
	if credsA.Password == credsB.Password {
		t.Error("different destination hosts got the same sticky session — sessions should be keyed per host")
	}
}

func TestRouter_NoUpstreamConfigured(t *testing.T) {
	r := &Router{
		Profile:  config.Profile{Username: "u", Password: "p"},
		Routing:  &config.RoutingConfig{Default: config.RoutingRule{Session: config.SessionRotating}},
		Sessions: NewSessionStore(),
	}
	if _, _, err := r.Resolve(Target{Host: "x.example.com", Port: 443}); err == nil {
		t.Fatal("expected error with no UpstreamAddr configured, got nil")
	}
}
