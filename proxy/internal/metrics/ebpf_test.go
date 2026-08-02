package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/dmaina5054/mithril/proxy/ebpf/sockops"
)

type fakeReader struct {
	snapshot map[sockops.ProcessKey]sockops.ProcessBytes
	err      error
}

func (f *fakeReader) ReadProcessBytes() (map[sockops.ProcessKey]sockops.ProcessBytes, error) {
	return f.snapshot, f.err
}

func counterValue(t *testing.T, vec *prometheus.CounterVec, label string) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := vec.WithLabelValues(label).Write(m); err != nil {
		t.Fatalf("read counter for %q: %v", label, err)
	}
	return m.GetCounter().GetValue()
}

func TestUpdateOnce_FirstSnapshotSetsBaseline(t *testing.T) {
	processBytesSent.Reset()
	processBytesRecv.Reset()
	seen := make(map[sockops.ProcessKey]lastSeen)

	reader := &fakeReader{snapshot: map[sockops.ProcessKey]sockops.ProcessBytes{
		{PID: 100, Comm: "comfyui"}: {BytesSent: 1000, BytesRecv: 500},
	}}
	updateOnce(reader, seen)

	if got := counterValue(t, processBytesSent, "comfyui"); got != 1000 {
		t.Errorf("bytes_sent = %v, want 1000", got)
	}
	if got := counterValue(t, processBytesRecv, "comfyui"); got != 500 {
		t.Errorf("bytes_recv = %v, want 500", got)
	}
}

func TestUpdateOnce_SecondSnapshotAddsDeltaOnly(t *testing.T) {
	processBytesSent.Reset()
	processBytesRecv.Reset()
	seen := make(map[sockops.ProcessKey]lastSeen)
	key := sockops.ProcessKey{PID: 100, Comm: "comfyui"}

	updateOnce(&fakeReader{snapshot: map[sockops.ProcessKey]sockops.ProcessBytes{
		key: {BytesSent: 1000, BytesRecv: 500},
	}}, seen)
	updateOnce(&fakeReader{snapshot: map[sockops.ProcessKey]sockops.ProcessBytes{
		key: {BytesSent: 1500, BytesRecv: 800},
	}}, seen)

	// Counter must reflect the CUMULATIVE total (1500/800), not the
	// delta alone (500/300) — Add() is additive on top of the first
	// snapshot's baseline.
	if got := counterValue(t, processBytesSent, "comfyui"); got != 1500 {
		t.Errorf("bytes_sent after 2 snapshots = %v, want 1500", got)
	}
	if got := counterValue(t, processBytesRecv, "comfyui"); got != 800 {
		t.Errorf("bytes_recv after 2 snapshots = %v, want 800", got)
	}
}

func TestUpdateOnce_MultiplePIDsSameCommAggregate(t *testing.T) {
	processBytesSent.Reset()
	processBytesRecv.Reset()
	seen := make(map[sockops.ProcessKey]lastSeen)

	// Two comfyui worker processes (different PIDs) must aggregate into
	// the same "process=comfyui" series, matching spec's label design
	// (labeled by comm, not PID — avoids per-PID cardinality explosion).
	reader := &fakeReader{snapshot: map[sockops.ProcessKey]sockops.ProcessBytes{
		{PID: 100, Comm: "comfyui"}: {BytesSent: 1000, BytesRecv: 0},
		{PID: 200, Comm: "comfyui"}: {BytesSent: 2000, BytesRecv: 0},
	}}
	updateOnce(reader, seen)

	if got := counterValue(t, processBytesSent, "comfyui"); got != 3000 {
		t.Errorf("bytes_sent = %v, want 3000 (aggregated across both PIDs)", got)
	}
}

func TestUpdateOnce_CounterResetTreatedAsNewBaseline(t *testing.T) {
	processBytesSent.Reset()
	seen := make(map[sockops.ProcessKey]lastSeen)
	key := sockops.ProcessKey{PID: 100, Comm: "comfyui"}

	updateOnce(&fakeReader{snapshot: map[sockops.ProcessKey]sockops.ProcessBytes{
		key: {BytesSent: 5000},
	}}, seen)
	// Value went "backwards" — e.g. PID reuse after process restart.
	// Must not underflow a uint64 subtraction into a huge bogus delta.
	updateOnce(&fakeReader{snapshot: map[sockops.ProcessKey]sockops.ProcessBytes{
		key: {BytesSent: 200},
	}}, seen)

	got := counterValue(t, processBytesSent, "comfyui")
	if got != 5200 {
		t.Errorf("bytes_sent = %v, want 5200 (5000 + 200 treated as a fresh baseline, not underflowed)", got)
	}
}

func TestUpdateOnce_ReaderErrorDoesNotPanic(t *testing.T) {
	seen := make(map[sockops.ProcessKey]lastSeen)
	reader := &fakeReader{err: assertErr{}}
	updateOnce(reader, seen) // must not panic
}

type assertErr struct{}

func (assertErr) Error() string { return "simulated read error" }
