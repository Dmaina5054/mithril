package vpnprovider

import (
	"context"
	"net"
	"strings"
	"testing"
)

// withCleanRegistry snapshots and restores the package-level factory
// registry around a test, so tests can Register without leaking
// providers into other tests (Register panics on duplicate names, so
// order-dependent leakage would otherwise make tests flaky).
func withCleanRegistry(t *testing.T) {
	t.Helper()
	mu.Lock()
	saved := factories
	factories = map[string]Factory{}
	mu.Unlock()

	t.Cleanup(func() {
		mu.Lock()
		factories = saved
		mu.Unlock()
	})
}

type stubProvider struct{ name string }

func (s stubProvider) Name() string { return s.name }
func (s stubProvider) Dial(context.Context, string, uint16, RouteOptions) (net.Conn, error) {
	return nil, nil
}

func TestRegisterAndNew(t *testing.T) {
	withCleanRegistry(t)

	var gotConfig map[string]any
	Register("stub", func(config map[string]any) (Provider, error) {
		gotConfig = config
		return stubProvider{name: "stub"}, nil
	})

	p, err := New("stub", map[string]any{"foo": "bar"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.Name() != "stub" {
		t.Errorf("Name() = %q, want stub", p.Name())
	}
	if gotConfig["foo"] != "bar" {
		t.Errorf("factory got config %+v, want foo=bar", gotConfig)
	}
}

func TestNew_UnknownProviderListsRegistered(t *testing.T) {
	withCleanRegistry(t)
	Register("alpha", func(map[string]any) (Provider, error) { return stubProvider{name: "alpha"}, nil })
	Register("beta", func(map[string]any) (Provider, error) { return stubProvider{name: "beta"}, nil })

	_, err := New("gamma", nil)
	if err == nil {
		t.Fatal("expected error for unknown provider, got nil")
	}
	if !strings.Contains(err.Error(), "gamma") {
		t.Errorf("error %q doesn't mention the requested name", err)
	}
	if !strings.Contains(err.Error(), "alpha") || !strings.Contains(err.Error(), "beta") {
		t.Errorf("error %q doesn't list registered providers", err)
	}
}

func TestNew_WrapsFactoryError(t *testing.T) {
	withCleanRegistry(t)
	Register("broken", func(map[string]any) (Provider, error) {
		return nil, errFactory
	})

	_, err := New("broken", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "broken") {
		t.Errorf("error %q doesn't name the provider", err)
	}
}

var errFactory = &testError{"factory exploded"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

func TestRegister_PanicsOnDuplicate(t *testing.T) {
	withCleanRegistry(t)
	Register("dup", func(map[string]any) (Provider, error) { return stubProvider{}, nil })

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate Register, got none")
		}
	}()
	Register("dup", func(map[string]any) (Provider, error) { return stubProvider{}, nil })
}

func TestRegister_PanicsOnEmptyName(t *testing.T) {
	withCleanRegistry(t)
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on empty name, got none")
		}
	}()
	Register("", func(map[string]any) (Provider, error) { return stubProvider{}, nil })
}

func TestRegistered_SortedAndReflectsRegistrations(t *testing.T) {
	withCleanRegistry(t)
	Register("zeta", func(map[string]any) (Provider, error) { return stubProvider{}, nil })
	Register("alpha", func(map[string]any) (Provider, error) { return stubProvider{}, nil })

	got := Registered()
	want := []string{"alpha", "zeta"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Registered() = %v, want %v", got, want)
	}
}

func TestDecodeConfig(t *testing.T) {
	type target struct {
		Username string `yaml:"username"`
		Retries  int    `yaml:"retries"`
	}

	raw := map[string]any{"username": "alice", "retries": 3}
	var got target
	if err := DecodeConfig(raw, &got); err != nil {
		t.Fatalf("DecodeConfig: %v", err)
	}
	if got.Username != "alice" || got.Retries != 3 {
		t.Errorf("got %+v, want {alice 3}", got)
	}
}
