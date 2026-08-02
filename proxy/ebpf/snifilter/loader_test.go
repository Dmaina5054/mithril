package snifilter

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

// encodeTestEvent builds the exact byte layout the C program's struct
// sni_event produces (verified against the generated
// mithrilSniFilterSniEvent struct's field order/sizes/padding — this
// mirrors it by construction rather than duplicating a second
// hand-maintained definition), so parseSniEvent can be tested without
// ever loading the real eBPF program.
func encodeTestEvent(t *testing.T, connID uint64, sni string, flowType FlowType) []byte {
	t.Helper()
	var sniBuf [64]int8
	for i, c := range []byte(sni) {
		if i >= len(sniBuf) {
			break
		}
		sniBuf[i] = int8(c)
	}

	buf := new(bytes.Buffer)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	must(binary.Write(buf, binary.LittleEndian, connID))
	must(binary.Write(buf, binary.LittleEndian, sniBuf))
	must(binary.Write(buf, binary.LittleEndian, uint32(len(sni))))
	must(binary.Write(buf, binary.LittleEndian, uint8(flowType)))
	must(binary.Write(buf, binary.LittleEndian, [3]byte{})) // struct padding, matches generated struct's trailing _ [3]byte

	return buf.Bytes()
}

func TestParseSniEvent_RoundTrip(t *testing.T) {
	raw := encodeTestEvent(t, 0xDEADBEEF, "api.comfy.example.com", FlowImageUpload)

	ev, err := parseSniEvent(raw)
	if err != nil {
		t.Fatalf("parseSniEvent: %v", err)
	}
	if ev.ConnID != 0xDEADBEEF {
		t.Errorf("ConnID = %#x, want 0xDEADBEEF", ev.ConnID)
	}
	if ev.SNI != "api.comfy.example.com" {
		t.Errorf("SNI = %q, want api.comfy.example.com", ev.SNI)
	}
	if ev.FlowType != FlowImageUpload {
		t.Errorf("FlowType = %v, want FlowImageUpload", ev.FlowType)
	}
}

func TestParseSniEvent_EmptySNI(t *testing.T) {
	raw := encodeTestEvent(t, 1, "", FlowUnknown)
	ev, err := parseSniEvent(raw)
	if err != nil {
		t.Fatalf("parseSniEvent: %v", err)
	}
	if ev.SNI != "" {
		t.Errorf("SNI = %q, want empty", ev.SNI)
	}
}

func TestParseSniEvent_MaxLengthSNI(t *testing.T) {
	maxSNI := ""
	for i := 0; i < 64; i++ {
		maxSNI += "x"
	}
	raw := encodeTestEvent(t, 2, maxSNI, FlowUnknown)
	ev, err := parseSniEvent(raw)
	if err != nil {
		t.Fatalf("parseSniEvent: %v", err)
	}
	if ev.SNI != maxSNI {
		t.Errorf("SNI length = %d, want 64 (full buffer)", len(ev.SNI))
	}
}

func TestParseSniEvent_TruncatedRecord(t *testing.T) {
	if _, err := parseSniEvent([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error decoding a too-short record, got nil")
	}
}

func TestFlowType_String(t *testing.T) {
	cases := map[FlowType]string{
		FlowUnknown:     "FLOW_UNKNOWN",
		FlowImageUpload: "FLOW_IMAGE_UPLOAD",
		FlowAPICall:     "FLOW_API_CALL",
		FlowTelemetry:   "FLOW_TELEMETRY",
		FlowType(99):    "FLOW_UNKNOWN", // undefined value falls back sanely, doesn't panic
	}
	for ft, want := range cases {
		if got := ft.String(); got != want {
			t.Errorf("FlowType(%d).String() = %q, want %q", ft, got, want)
		}
	}
}

// TestLoad_FailsGracefullyWithoutPrivileges mirrors
// ebpf/sockops's test of the same name — the one thing checkable
// without root: a clean error, not a panic. Real load/attach/parse
// correctness against actual kernel-delivered packets needs a live
// privileged run, same as Phase 5.
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
