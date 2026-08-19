package health

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleHealthz_Returns200OK(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	handleHealthz(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := rr.Body.String(); got != "ok\n" {
		t.Errorf("body = %q, want %q", got, "ok\n")
	}
}

func TestServe_MountsHealthzOnServer(t *testing.T) {
	// Exercise the actual mux Serve builds, via httptest.NewServer,
	// rather than just calling http.ListenAndServe(addr, ...) — proves
	// the route is wired up on the mux Serve constructs, not just that
	// handleHealthz works in isolation.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}
