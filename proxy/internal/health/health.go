package health

import (
	"log"
	"net/http"
)

// Serve starts the /healthz HTTP endpoint on addr. Blocks until the
// server errors or is shut down — intended to run in its own
// goroutine, same pattern as internal/metrics.ServeProxyMetrics/
// ServeEBPFMetrics.
//
// Always responds 200 "ok" — this proxy has no downstream dependency
// (database, cache, ...) whose liveness could meaningfully vary the
// response. Existing is the only thing worth reporting here: that the
// process is up and its own HTTP server goroutine isn't wedged behind
// something else. If that changes — e.g. a future provider needs a
// live upstream-reachability check surfaced here — extend the handler
// then, not preemptively.
func Serve(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	log.Printf("mithril-proxy: /healthz listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}
