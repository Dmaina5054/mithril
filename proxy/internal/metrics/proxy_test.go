package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestRecordConnectionError_IncrementsByReason(t *testing.T) {
	connectionErrors.Reset()

	RecordConnectionError("dial")
	RecordConnectionError("dial")
	RecordConnectionError("handshake")

	if got := counterValue(t, connectionErrors, "dial"); got != 2 {
		t.Errorf("dial = %v, want 2", got)
	}
	if got := counterValue(t, connectionErrors, "handshake"); got != 1 {
		t.Errorf("handshake = %v, want 1", got)
	}
}

// TestProxyRegistry_IsIsolatedFromDefaultRegistry proves proxyRegistry
// doesn't leak the eBPF-sourced metrics (registered to
// prometheus.DefaultRegisterer by ebpf.go's init()) — see
// proxyRegistry's doc comment for why that isolation matters: without
// it, :9998 and :9435 would both expose every metric registered
// anywhere in the process, muddying which Prometheus job actually owns
// which series.
func TestProxyRegistry_IsIsolatedFromDefaultRegistry(t *testing.T) {
	connectionErrors.Reset()
	RecordConnectionError("dial")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	promhttp.HandlerFor(proxyRegistry, promhttp.HandlerOpts{}).ServeHTTP(rr, req)

	body, err := io.ReadAll(rr.Result().Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	got := string(body)

	if !strings.Contains(got, "proxy_connection_errors_total") {
		t.Errorf("response missing proxy_connection_errors_total:\n%s", got)
	}
	if strings.Contains(got, "iproyal_process_bytes") {
		t.Errorf("response leaked an eBPF-sourced metric (should only be on proxyRegistry's own registry):\n%s", got)
	}
}
