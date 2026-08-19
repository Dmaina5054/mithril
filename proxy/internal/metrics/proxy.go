// Package metrics: this file implements the main proxy's own /metrics
// endpoint (Session B Phase 9, per CLAUDE.md's port registry — :9998,
// 127.0.0.1 only, distinct from ebpf.go's :9435 ebpf-exporter).
package metrics

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

// proxyRegistry is deliberately its OWN prometheus.Registry, not
// prometheus.DefaultRegisterer (which ebpf.go's processBytesSent/Recv
// register into via prometheus.MustRegister). If this used the default
// registry too, ServeProxyMetrics and ebpf.go's ServeEBPFMetrics
// (both of which mount a bare promhttp.Handler(), the default-registry
// handler) would each expose EVERY metric registered anywhere in the
// process — meaning proxy_connection_errors_total would show up under
// Prometheus's "ebpf-exporter" job too, and iproyal_process_bytes_*
// under "socks5-proxy". Keeping proxy-native metrics on their own
// registry keeps each scrape endpoint honest about what it actually
// owns.
var proxyRegistry = prometheus.NewRegistry()

var connectionErrors = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "proxy_connection_errors_total",
		Help: "Count of SOCKS5/transparent connections that failed before a relay started, by failure reason.",
	},
	[]string{"reason"},
)

func init() {
	proxyRegistry.MustRegister(connectionErrors)
}

// RecordConnectionError increments proxy_connection_errors_total for
// reason (e.g. "handshake", "dial", "reply") — see the call sites in
// internal/proxy/handler.go. Unlike the eBPF-sourced metrics in
// ebpf.go, nothing here needs privileged loading, so internal/proxy
// calls this directly rather than through an interface main.go injects
// (cf. proxy.SNIFilter/proxy.ZFSSnapshot) — internal/metrics has no
// import of internal/proxy, so there's no cycle to avoid either way.
func RecordConnectionError(reason string) {
	connectionErrors.WithLabelValues(reason).Inc()
}

// ConnectionErrorCount returns proxy_connection_errors_total's current
// value for reason. Exported so internal/proxy's own tests can assert
// the metric side effect of a failed Handle/HandleTransparent call
// without this package needing a test-only interface-injection layer
// (cf. proxy.SNIFilter/proxy.ZFSSnapshot) just for a metrics counter.
// Not used by any production code path.
func ConnectionErrorCount(reason string) float64 {
	m := &dto.Metric{}
	if err := connectionErrors.WithLabelValues(reason).Write(m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// ServeProxyMetrics starts an HTTP server on addr exposing /metrics via
// proxyRegistry (NOT the default registry — see that var's comment).
// Blocks until the server errors or is shut down.
func ServeProxyMetrics(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(proxyRegistry, promhttp.HandlerOpts{}))
	log.Printf("mithril-proxy: /metrics listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}
