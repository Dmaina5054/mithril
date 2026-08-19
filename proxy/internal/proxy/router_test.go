package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/dmaina5054/mithril/proxy/config"
	"github.com/dmaina5054/mithril/proxy/internal/vpnprovider"
)

// fakeProvider is a vpnprovider.Provider test double that records every
// RouteOptions it's asked to Dial with. Router tests assert on those
// recorded options directly instead of reverse-engineering routing
// decisions from an upstream-specific credential string — this package
// no longer knows or cares that IPRoyal encodes targeting into a
// password suffix; that's entirely internal/vpnprovider/iproyal's
// concern now.
type fakeProvider struct {
	calls []vpnprovider.RouteOptions
}

func (f *fakeProvider) Name() string { return "fake" }

func (f *fakeProvider) Dial(_ context.Context, _ string, _ uint16, opts vpnprovider.RouteOptions) (net.Conn, error) {
	f.calls = append(f.calls, opts)
	client, server := net.Pipe()
	server.Close()
	return client, nil
}

func TestRouter_StickyRuleAddsSessionAndReuses(t *testing.T) {
	routing := &config.RoutingConfig{
		Rules: []config.RoutingRule{
			{Pattern: "*.comfy.example.com", Country: "us", Session: config.SessionSticky, Lifetime: "2h"},
		},
		Default: config.RoutingRule{Session: config.SessionRotating},
	}
	provider := &fakeProvider{}
	r := &Router{
		Name:     "kioo-labs",
		Provider: provider,
		Routing:  routing,
		Sessions: NewSessionStore(),
	}

	target := Target{Host: "api.comfy.example.com", Port: 443}

	if conn, err := r.Dial(context.Background(), target, time.Second); err != nil {
		t.Fatalf("Dial: %v", err)
	} else {
		conn.Close()
	}
	// Second dial for the same host must reuse the same session id —
	// that's the entire point of "sticky".
	if conn, err := r.Dial(context.Background(), target, time.Second); err != nil {
		t.Fatalf("Dial (2nd): %v", err)
	} else {
		conn.Close()
	}

	if len(provider.calls) != 2 {
		t.Fatalf("got %d Dial calls, want 2", len(provider.calls))
	}
	first, second := provider.calls[0], provider.calls[1]

	if first.Country != "us" {
		t.Errorf("Country = %q, want us", first.Country)
	}
	if first.Lifetime != "2h" {
		t.Errorf("Lifetime = %q, want 2h", first.Lifetime)
	}
	if first.SessionID == "" {
		t.Error("SessionID is empty for a sticky rule")
	}
	if first.SessionID != second.SessionID {
		t.Errorf("sticky session id changed between calls: %q vs %q", first.SessionID, second.SessionID)
	}
}

func TestRouter_RotatingRuleOmitsSessionKeys(t *testing.T) {
	routing := &config.RoutingConfig{
		Rules: []config.RoutingRule{
			{Pattern: "*.scrape.example.com", Country: "us", Session: config.SessionRotating},
		},
		Default: config.RoutingRule{Session: config.SessionRotating},
	}
	provider := &fakeProvider{}
	r := &Router{
		Name:     "kioo-labs",
		Provider: provider,
		Routing:  routing,
		Sessions: NewSessionStore(),
	}

	conn, err := r.Dial(context.Background(), Target{Host: "job.scrape.example.com", Port: 443}, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()

	if len(provider.calls) != 1 {
		t.Fatalf("got %d Dial calls, want 1", len(provider.calls))
	}
	got := provider.calls[0]
	if got.SessionID != "" || got.Lifetime != "" {
		t.Errorf("rotating rule should not set SessionID/Lifetime, got %+v", got)
	}
	if got.Country != "us" {
		t.Errorf("Country = %q, want us", got.Country)
	}
}

func TestRouter_DifferentHostsGetDifferentStickySessions(t *testing.T) {
	routing := &config.RoutingConfig{
		Default: config.RoutingRule{Session: config.SessionSticky, Lifetime: "1h"},
	}
	provider := &fakeProvider{}
	r := &Router{
		Name:     "kioo-labs",
		Provider: provider,
		Routing:  routing,
		Sessions: NewSessionStore(),
	}

	connA, err := r.Dial(context.Background(), Target{Host: "a.example.com", Port: 443}, time.Second)
	if err != nil {
		t.Fatalf("Dial a: %v", err)
	}
	connA.Close()
	connB, err := r.Dial(context.Background(), Target{Host: "b.example.com", Port: 443}, time.Second)
	if err != nil {
		t.Fatalf("Dial b: %v", err)
	}
	connB.Close()

	if len(provider.calls) != 2 {
		t.Fatalf("got %d Dial calls, want 2", len(provider.calls))
	}
	if provider.calls[0].SessionID == provider.calls[1].SessionID {
		t.Error("different destination hosts got the same sticky session — sessions should be keyed per host")
	}
}

func TestRouter_NoProviderConfigured(t *testing.T) {
	r := &Router{
		Name:     "default",
		Routing:  &config.RoutingConfig{Default: config.RoutingRule{Session: config.SessionRotating}},
		Sessions: NewSessionStore(),
	}
	if _, err := r.Dial(context.Background(), Target{Host: "x.example.com", Port: 443}, time.Second); err == nil {
		t.Fatal("expected error with no Provider configured, got nil")
	}
}

func TestRouter_NoRoutingConfigured(t *testing.T) {
	r := &Router{
		Name:     "default",
		Provider: &fakeProvider{},
		Sessions: NewSessionStore(),
	}
	if _, err := r.Dial(context.Background(), Target{Host: "x.example.com", Port: 443}, time.Second); err == nil {
		t.Fatal("expected error with no Routing configured, got nil")
	}
}
