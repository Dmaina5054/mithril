// Command mithril-proxy is the SOCKS5 consumer proxy for IPRoyal
// residential proxies, built out phase-by-phase per docs/mithril-infra-spec.docx
// Session B.
//
// Phase 2 wiring only: a single static upstream/credential pair, no
// geo/session routing yet (that's Phase 3 — StaticResolver gets swapped
// for the real router without touching internal/proxy). Sufficient to
// prove the SOCKS5 core end-to-end: curl --socks5 through this binary
// should come back with a residential IP.
package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/dmaina5054/mithril/proxy/internal/proxy"
)

func main() {
	listenAddr := envOrDefault("MITHRIL_LISTEN_ADDR", "127.0.0.1:1080")
	upstreamAddr := os.Getenv("MITHRIL_UPSTREAM_ADDR")
	upstreamUser := os.Getenv("MITHRIL_UPSTREAM_USER")
	upstreamPass := os.Getenv("MITHRIL_UPSTREAM_PASS")

	if upstreamAddr == "" || upstreamUser == "" || upstreamPass == "" {
		fmt.Fprintln(os.Stderr, `mithril-proxy: Phase 2 needs MITHRIL_UPSTREAM_ADDR, MITHRIL_UPSTREAM_USER, MITHRIL_UPSTREAM_PASS set.

MITHRIL_UPSTREAM_ADDR is an IPRoyal entry node host:port (from GET
/access/entry-nodes — see cmd/apismoke output, or the IPRoyal dashboard).
MITHRIL_UPSTREAM_USER/PASS is the kioo-labs sub-user credential string
(see AI-03 — sub-user #89998755, username "kioolabs").

This is intentionally not hardcoded — no verified entry-node address is
known yet. Phase 3 replaces this with the real geo/session router.`)
		os.Exit(1)
	}

	resolver := proxy.StaticResolver{
		UpstreamAddr: upstreamAddr,
		Creds: proxy.Credentials{
			Username: upstreamUser,
			Password: upstreamPass,
		},
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("mithril-proxy: listen on %s: %v", listenAddr, err)
	}
	log.Printf("mithril-proxy: listening on %s, upstream %s (Phase 2 static resolver)", listenAddr, upstreamAddr)

	if err := proxy.Serve(ln, resolver); err != nil {
		log.Fatalf("mithril-proxy: %v", err)
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
