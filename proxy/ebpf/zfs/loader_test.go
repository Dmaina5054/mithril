package zfs

import (
	"os"
	"testing"
)

// TestLoad_FailsGracefullyWithoutPrivileges verifies that attempting to
// load the ZFS kprobe eBPF programs without sufficient privileges
// returns a clean error rather than panicking. Real load/attach/map-read
// correctness needs verification with real root/CAP_BPF, which is
// outside what this test can cover.
func TestLoad_FailsGracefullyWithoutPrivileges(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — this test specifically checks the unprivileged failure path")
	}

	probes, err := Load()
	if err == nil {
		if probes != nil {
			probes.Close()
		}
		t.Fatal("expected Load to fail without root/CAP_BPF, but it succeeded")
	}
	// Any error is acceptable: EPERM, "operation not permitted", etc.
	// The point is that Load doesn't panic and returns a meaningful error.
}
