package sockops

import (
	"os"
	"testing"
)

func TestCommToString(t *testing.T) {
	cases := []struct {
		name string
		in   [16]int8
		want string
	}{
		{
			name: "full 16 bytes, no terminator",
			in:   [16]int8{'c', 'o', 'm', 'f', 'y', 'u', 'i', '-', 'w', 'o', 'r', 'k', 'e', 'r', '0', '1'},
			want: "comfyui-worker01",
		},
		{
			name: "early null terminator",
			in:   [16]int8{'n', 'o', 'd', 'e', '_', 'e', 'x', 'p', 'o', 'r', 't', 'e', 'r', 0, 0, 0},
			want: "node_exporter",
		},
		{
			name: "empty",
			in:   [16]int8{},
			want: "",
		},
		{
			name: "single char",
			in:   [16]int8{'x', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			want: "x",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := commToString(tc.in)
			if got != tc.want {
				t.Errorf("commToString(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
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
