package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempProfiles(t *testing.T, yamlContent string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "profiles.yaml")
	if err := os.WriteFile(p, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("write temp profiles.yaml: %v", err)
	}
	return p
}

func TestLoadProfilesConfig_Valid(t *testing.T) {
	p := writeTempProfiles(t, `
profiles:
  default:
    username: "default-user"
    password: "default-pass"
    listen_port: 1080
    bandwidth_alert_gb: 1
  kioo-labs:
    subuser_hash: "abc123"
    username: "kioolabs"
    password: "kioolabs-pass"
    listen_port: 1081
    bandwidth_alert_gb: 0.5
`)
	cfg, err := LoadProfilesConfig(p)
	if err != nil {
		t.Fatalf("LoadProfilesConfig: %v", err)
	}
	if len(cfg.Profiles) != 2 {
		t.Fatalf("got %d profiles, want 2", len(cfg.Profiles))
	}
	kl, ok := cfg.Profiles["kioo-labs"]
	if !ok {
		t.Fatal("kioo-labs profile missing")
	}
	if kl.Username != "kioolabs" {
		t.Errorf("Username = %q, want kioolabs (no hyphen — must match IPRoyal exactly)", kl.Username)
	}
	if kl.ListenPort != 1081 {
		t.Errorf("ListenPort = %d, want 1081", kl.ListenPort)
	}
}

func TestValidate_RejectsDuplicatePort(t *testing.T) {
	p := writeTempProfiles(t, `
profiles:
  default:
    username: "u1"
    password: "p1"
    listen_port: 1080
  other:
    username: "u2"
    password: "p2"
    listen_port: 1080
`)
	if _, err := LoadProfilesConfig(p); err == nil {
		t.Fatal("expected error for duplicate listen_port, got nil")
	}
}

func TestValidate_RejectsMissingPassword(t *testing.T) {
	p := writeTempProfiles(t, `
profiles:
  default:
    username: "u1"
    listen_port: 1080
`)
	if _, err := LoadProfilesConfig(p); err == nil {
		t.Fatal("expected error for missing password, got nil")
	}
}

func TestValidate_RejectsInvalidPort(t *testing.T) {
	p := writeTempProfiles(t, `
profiles:
  default:
    username: "u1"
    password: "p1"
    listen_port: 99999
`)
	if _, err := LoadProfilesConfig(p); err == nil {
		t.Fatal("expected error for out-of-range port, got nil")
	}
}

func TestValidate_RejectsEmptyProfiles(t *testing.T) {
	p := writeTempProfiles(t, `profiles: {}`)
	if _, err := LoadProfilesConfig(p); err == nil {
		t.Fatal("expected error for empty profiles map, got nil")
	}
}
