// Package metrics implements Prometheus exposition. eBPF-sourced
// metrics (this file) are served on :9435, the "ebpf-exporter" port —
// separate from the main proxy's own /metrics on :9998 (Session B
// Phase 9) per spec section 4 and CLAUDE.md's port registry.
package metrics

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/dmaina5054/mithril/proxy/ebpf/sockops"
)

// ProcessBytesReader is satisfied by *sockops.Tracker — kept as an
// interface so RunEBPFExporter is testable with a fake reader, without
// needing real eBPF privileges.
type ProcessBytesReader interface {
	ReadProcessBytes() (map[sockops.ProcessKey]sockops.ProcessBytes, error)
}

var (
	processBytesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iproyal_process_bytes_sent_total",
			Help: "Cumulative bytes sent per process, from the sock_ops eBPF program (per-process bandwidth accounting).",
		},
		[]string{"process"},
	)
	processBytesRecv = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iproyal_process_bytes_recv_total",
			Help: "Cumulative bytes received per process, from the sock_ops eBPF program (per-process bandwidth accounting).",
		},
		[]string{"process"},
	)
)

// No "node" label here, deliberately — matches node_exporter's own
// convention of not self-labeling with the node identity. Prometheus's
// scrape config (observability/config/prometheus.yml, job ebpf-exporter)
// already attaches node=minas-tirith / workload=infra via static_configs
// labels; duplicating it here would be redundant with what the rest of
// this stack does everywhere else.
func init() {
	prometheus.MustRegister(processBytesSent, processBytesRecv)
}

// lastSeen tracks the last cumulative value we saw per process, so we
// can Add() the delta to the Counter rather than trying to Set() it —
// client_golang Counters only expose Inc()/Add(), on purpose (a
// Prometheus counter must only ever increase from the client's own
// perspective; the eBPF map already gives us a monotonic cumulative
// value per process for the lifetime of that process, so a delta
// against our own last-seen snapshot is the correct translation).
type lastSeen struct {
	sent uint64
	recv uint64
}

// RunEBPFExporter polls reader every interval and updates the Prometheus
// counters, until ctx is canceled. Intended to run in its own goroutine.
func RunEBPFExporter(ctx context.Context, reader ProcessBytesReader, interval time.Duration) {
	seen := make(map[sockops.ProcessKey]lastSeen)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			updateOnce(reader, seen)
		}
	}
}

func updateOnce(reader ProcessBytesReader, seen map[sockops.ProcessKey]lastSeen) {
	snapshot, err := reader.ReadProcessBytes()
	if err != nil {
		log.Printf("mithril-proxy: ebpf-exporter: read process_bytes: %v", err)
		return
	}

	for key, bytes := range snapshot {
		prev := seen[key]

		sentDelta := deltaOrReset(prev.sent, bytes.BytesSent)
		recvDelta := deltaOrReset(prev.recv, bytes.BytesRecv)

		if sentDelta > 0 {
			processBytesSent.WithLabelValues(key.Comm).Add(float64(sentDelta))
		}
		if recvDelta > 0 {
			processBytesRecv.WithLabelValues(key.Comm).Add(float64(recvDelta))
		}

		seen[key] = lastSeen{sent: bytes.BytesSent, recv: bytes.BytesRecv}
	}
}

// deltaOrReset handles the eBPF-side counter appearing to go backwards
// (process restarted and PID got reused with a fresh proc_bytes entry,
// or the map was cleared) — treat the current value as the delta rather
// than underflowing a uint64 subtraction into a huge bogus number.
func deltaOrReset(prev, current uint64) uint64 {
	if current >= prev {
		return current - prev
	}
	return current
}

// ServeEBPFMetrics starts an HTTP server on addr exposing /metrics via
// the default Prometheus registry (which processBytesSent/Recv register
// into via init() above). Blocks until the server errors or is shut down.
func ServeEBPFMetrics(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	log.Printf("mithril-proxy: ebpf-exporter listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}
