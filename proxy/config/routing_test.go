package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempRouting(t *testing.T, yamlContent string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "routing.yaml")
	if err := os.WriteFile(p, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("write temp routing.yaml: %v", err)
	}
	return p
}

const sampleRouting = `
rules:
  - pattern: "*.comfy.example.com"
    country: "us"
    session: sticky
    lifetime: 2h
  - pattern: "*.scrape.example.com"
    country: "us"
    session: rotating
  - pattern: "api.exact.example.com"
    country: "gb"
    session: rotating
default:
  session: rotating
`

func TestLoadRoutingConfig_Valid(t *testing.T) {
	p := writeTempRouting(t, sampleRouting)
	cfg, err := LoadRoutingConfig(p)
	if err != nil {
		t.Fatalf("LoadRoutingConfig: %v", err)
	}
	if len(cfg.Rules) != 3 {
		t.Fatalf("got %d rules, want 3", len(cfg.Rules))
	}
}

func TestMatch_WildcardSubdomain(t *testing.T) {
	p := writeTempRouting(t, sampleRouting)
	cfg, err := LoadRoutingConfig(p)
	if err != nil {
		t.Fatalf("LoadRoutingConfig: %v", err)
	}

	rule := cfg.Match("api.comfy.example.com")
	if rule.Country != "us" || rule.Session != SessionSticky {
		t.Errorf("got %+v, want country=us session=sticky", rule)
	}
	if rule.Lifetime != "2h" {
		t.Errorf("lifetime = %q, want 2h", rule.Lifetime)
	}
}

func TestMatch_ExactHostname(t *testing.T) {
	p := writeTempRouting(t, sampleRouting)
	cfg, err := LoadRoutingConfig(p)
	if err != nil {
		t.Fatalf("LoadRoutingConfig: %v", err)
	}

	rule := cfg.Match("api.exact.example.com")
	if rule.Country != "gb" {
		t.Errorf("Country = %q, want gb", rule.Country)
	}
}

func TestMatch_FirstRuleWins(t *testing.T) {
	// Two rules that would both match the same hostname — first
	// declared must win, matching Match's documented iteration order.
	yamlContent := `
rules:
  - pattern: "*.example.com"
    country: "us"
    session: rotating
  - pattern: "*.example.com"
    country: "gb"
    session: rotating
default:
  session: rotating
`
	p := writeTempRouting(t, yamlContent)
	cfg, err := LoadRoutingConfig(p)
	if err != nil {
		t.Fatalf("LoadRoutingConfig: %v", err)
	}

	rule := cfg.Match("anything.example.com")
	if rule.Country != "us" {
		t.Errorf("Country = %q, want us (first rule should win)", rule.Country)
	}
}

func TestMatch_FallsBackToDefault(t *testing.T) {
	p := writeTempRouting(t, sampleRouting)
	cfg, err := LoadRoutingConfig(p)
	if err != nil {
		t.Fatalf("LoadRoutingConfig: %v", err)
	}

	rule := cfg.Match("totally-unrelated.other.net")
	if rule.Session != SessionRotating {
		t.Errorf("Session = %q, want rotating (the default)", rule.Session)
	}
	if rule.Country != "" {
		t.Errorf("Country = %q, want empty (default has no country)", rule.Country)
	}
}

func TestMatch_NoMatchAcrossUnrelatedDomains(t *testing.T) {
	p := writeTempRouting(t, sampleRouting)
	cfg, err := LoadRoutingConfig(p)
	if err != nil {
		t.Fatalf("LoadRoutingConfig: %v", err)
	}

	// Must NOT match *.comfy.example.com's rule just because it shares
	// a suffix — glob matching, not substring matching.
	rule := cfg.Match("comfy.example.com.evil.net")
	if rule.Country == "us" && rule.Session == SessionSticky {
		t.Errorf("hostname with comfy.example.com as a prefix incorrectly matched the comfy rule: %+v", rule)
	}
}

func TestValidate_RejectsBadSessionMode(t *testing.T) {
	yamlContent := `
rules:
  - pattern: "*.example.com"
    session: "not-a-real-mode"
default:
  session: rotating
`
	p := writeTempRouting(t, yamlContent)
	if _, err := LoadRoutingConfig(p); err == nil {
		t.Fatal("expected error for invalid session mode, got nil")
	}
}

func TestValidate_RejectsBadLifetimeFormat(t *testing.T) {
	yamlContent := `
rules:
  - pattern: "*.example.com"
    session: sticky
    lifetime: "2 hours"
default:
  session: rotating
`
	p := writeTempRouting(t, yamlContent)
	if _, err := LoadRoutingConfig(p); err == nil {
		t.Fatal("expected error for malformed lifetime, got nil")
	}
}

func TestValidate_RejectsBadPattern(t *testing.T) {
	yamlContent := `
rules:
  - pattern: "["
    session: rotating
default:
  session: rotating
`
	p := writeTempRouting(t, yamlContent)
	if _, err := LoadRoutingConfig(p); err == nil {
		t.Fatal("expected error for malformed glob pattern, got nil")
	}
}

func TestValidate_StickyWithoutLifetimeDefaultsTo2h(t *testing.T) {
	yamlContent := `
rules:
  - pattern: "*.example.com"
    session: sticky
default:
  session: rotating
`
	p := writeTempRouting(t, yamlContent)
	cfg, err := LoadRoutingConfig(p)
	if err != nil {
		t.Fatalf("LoadRoutingConfig: %v (sticky with no explicit lifetime should default to 2h, not fail)", err)
	}
	rule := cfg.Match("x.example.com")
	if rule.Lifetime != "" {
		t.Errorf("stored Lifetime = %q, want empty (default applied at use-time, not stored)", rule.Lifetime)
	}
	_ = cfg
}
