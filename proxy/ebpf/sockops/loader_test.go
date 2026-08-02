package sockops

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestResolveComm_OwnPID(t *testing.T) {
	// Self-referential rather than asserting an exact expected string
	// (the test binary's own comm name isn't something worth hardcoding
	// and re-deriving here) — just confirms a real, currently-running
	// PID resolves to a real, non-empty, non-fallback name.
	got := resolveComm(uint32(os.Getpid()))
	if got == "" {
		t.Fatal("resolveComm(own pid) returned empty")
	}
	if strings.HasPrefix(got, "pid-") {
		t.Errorf("resolveComm(own pid) = %q, looks like the not-found fallback for a PID that definitely exists", got)
	}
}

func TestResolveComm_NonexistentPID_FallsBackGracefully(t *testing.T) {
	// PID 1 always exists (init/systemd) so isn't a safe "doesn't exist"
	// probe; use a PID far outside any realistic range instead.
	const bogusPID = uint32(4_000_000_000)
	got := resolveComm(bogusPID)
	want := fmt.Sprintf("pid-%d", bogusPID)
	if got != want {
		t.Errorf("resolveComm(nonexistent pid) = %q, want %q (the documented fallback)", got, want)
	}
}

// TestLoad_FailsGracefullyWithoutPrivileges doesn't (can't, in this
// environment) verify the eBPF program actually works — it verifies
// the one thing checkable without root: that attempting to load it
// without sufficient privileges returns a clean error rather than
// panicking. Real load/attach/map-read correctness needs verification
// with real privileges, which is outside what this test can cover.
func TestLoad_FailsGracefullyWithoutPrivileges(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — this test specifically checks the unprivileged failure path")
	}

	tracker, err := Load()
	if err == nil {
		if tracker != nil {
			tracker.Close()
		}
		t.Fatal("expected Load() to fail without root/CAP_BPF, got nil error — either privileges changed or something is wrong")
	}
	t.Logf("Load() failed as expected without privileges: %v", err)
}
