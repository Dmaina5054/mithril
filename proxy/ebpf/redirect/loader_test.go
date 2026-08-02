package redirect

import (
	"encoding/binary"
	"os"
	"testing"
)

// TestDecodeOriginalDest_RoundTrip simulates the full path end to end:
// bytes as the C program would actually write them (network byte
// order / big-endian for both IP and port), decoded the way cilium/
// ebpf's map Lookup naturally would on this little-endian host (a raw
// memory copy, Go's uint32/uint16 then interpret those bytes using
// NATIVE little-endian convention) — then verifies decodeOriginalDest
// recovers the correct values. This is a from-scratch simulation of
// the byte layout, not a restatement of decodeOriginalDest's own logic
// — an earlier draft of that function got the conversion direction
// backwards and this test would have caught it.
func TestDecodeOriginalDest_RoundTrip(t *testing.T) {
	cases := []struct {
		name         string
		ip           string
		ipBytes      [4]byte
		port         uint16
		portBytes    [2]byte
		profileIndex uint8
	}{
		{"127.0.0.1:19001", "127.0.0.1", [4]byte{127, 0, 0, 1}, 19001, [2]byte{0x4A, 0x39}, 0},
		{"93.184.216.34:443", "93.184.216.34", [4]byte{93, 184, 216, 34}, 443, [2]byte{0x01, 0xBB}, 1},
		{"1.1.1.1:80", "1.1.1.1", [4]byte{1, 1, 1, 1}, 80, [2]byte{0x00, 0x50}, 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate what cilium/ebpf's map Lookup would produce: the
			// C program wrote tc.ipBytes/tc.portBytes (network/big-endian
			// order) into kernel memory; a raw copy into the Go struct on
			// this little-endian host means Go's uint32/uint16 fields
			// interpret those same bytes using LittleEndian convention.
			// ProfileIndex is a single byte — no endianness to get wrong.
			raw := mithrilRedirectOriginalDest{
				Ip:           binary.LittleEndian.Uint32(tc.ipBytes[:]),
				Port:         binary.LittleEndian.Uint16(tc.portBytes[:]),
				ProfileIndex: tc.profileIndex,
			}

			got := decodeOriginalDest(raw)
			if got.IP.String() != tc.ip {
				t.Errorf("IP = %s, want %s", got.IP, tc.ip)
			}
			if got.Port != tc.port {
				t.Errorf("Port = %d, want %d", got.Port, tc.port)
			}
			if got.ProfileIndex != tc.profileIndex {
				t.Errorf("ProfileIndex = %d, want %d", got.ProfileIndex, tc.profileIndex)
			}
		})
	}
}

// TestLoad_FailsGracefullyWithoutPrivileges mirrors the same-named
// tests in ebpf/sockops and ebpf/snifilter — the one thing checkable
// without root: a clean error, not a panic. This package carries the
// most unverified risk of any eBPF phase so far (see Tracker's doc
// comment) — this test only rules out the crash class of failure, not
// whether the redirect mechanism actually works.
func TestLoad_FailsGracefullyWithoutPrivileges(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — this test specifically checks the unprivileged failure path")
	}

	tracker, err := Load()
	if err == nil {
		if tracker != nil {
			tracker.Close()
		}
		t.Fatal("expected Load() to fail without root/CAP_BPF, got nil error")
	}
	t.Logf("Load() failed as expected without privileges: %v", err)
}
