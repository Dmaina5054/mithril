// Command mithril-proxy is the SOCKS5 consumer proxy for IPRoyal
// residential proxies, built out phase-by-phase per docs/mithril-infra-spec.docx
// Session B.
//
// Phase 3: one listener per profiles.yaml entry, each backed by a
// Router that applies routing.yaml's geo/session rules per-request.
// Replaces Phase 2's single StaticResolver.
package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/dmaina5054/mithril/proxy/config"
	"github.com/dmaina5054/mithril/proxy/internal/proxy"
)

func main() {
	routingPath := envOrDefault("MITHRIL_ROUTING_CONFIG", "/etc/socks5-proxy/routing.yaml")
	profilesPath := envOrDefault("MITHRIL_PROFILES_CONFIG", "/etc/socks5-proxy/profiles.yaml")
	// Fixed entry node for now — Phase 1's EntryNodes() benchmarking
	// isn't wired into automatic startup/6h re-selection yet. Follow-up,
	// not part of Phase 3's gate (routing.yaml pattern matching).
	upstreamAddr := os.Getenv("MITHRIL_UPSTREAM_ADDR")

	if upstreamAddr == "" {
		fmt.Fprintln(os.Stderr, "mithril-proxy: MITHRIL_UPSTREAM_ADDR must be set (an IPRoyal entry node host:port — automatic selection isn't wired up yet)")
		os.Exit(1)
	}

	routing, err := config.LoadRoutingConfig(routingPath)
	if err != nil {
		log.Fatalf("mithril-proxy: %v", err)
	}
	profiles, err := config.LoadProfilesConfig(profilesPath)
	if err != nil {
		log.Fatalf("mithril-proxy: %v", err)
	}

	sessions := proxy.NewSessionStore() // shared across profiles — session keys are profile-username-prefixed, no collision risk

	errCh := make(chan error, len(profiles.Profiles))
	started := 0
	for name, p := range profiles.Profiles {
		listenAddr := fmt.Sprintf("127.0.0.1:%d", p.ListenPort)
		ln, err := net.Listen("tcp", listenAddr)
		if err != nil {
			log.Fatalf("mithril-proxy: profile %q: listen on %s: %v", name, listenAddr, err)
		}

		router := &proxy.Router{
			Profile:      p,
			Routing:      routing,
			UpstreamAddr: upstreamAddr,
			Sessions:     sessions,
		}

		log.Printf("mithril-proxy: profile %q listening on %s, upstream %s", name, listenAddr, upstreamAddr)
		started++
		go func(ln net.Listener, router *proxy.Router) {
			errCh <- proxy.Serve(ln, router)
		}(ln, router)
	}

	if started == 0 {
		log.Fatal("mithril-proxy: no profiles started")
	}

	// Any single listener returning ends the process — matches Phase 2's
	// behavior (no partial-degraded-mode handling yet).
	log.Fatal(<-errCh)
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
