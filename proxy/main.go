// Command mithril-proxy is the SOCKS5 consumer proxy for IPRoyal
// residential proxies, built out phase-by-phase per docs/mithril-infra-spec.docx
// Session B.
//
// Phase 3: one listener per profiles.yaml entry, each backed by a
// Router that applies routing.yaml's geo/session rules per-request.
// Phase 5: sock_ops eBPF program (per-process bandwidth accounting),
// loaded on startup and unloaded on graceful shutdown per spec section 4.
// Phase 6: socket_filter eBPF program (SNI extraction + coarse flow
// classification), attached per-connection via internal/proxy.SNIFilter;
// results are read from a ring buffer by one long-lived goroutine here
// and logged, per spec ("Go reads perf buffer, enriches proxy
// connection log") — independent of any single connection's lifecycle.
// eBPF failure is non-fatal for both — the core SOCKS5 proxy keeps
// running without them (e.g. missing CAP_BPF, kernel too old); an
// observability gap shouldn't take down request forwarding.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dmaina5054/mithril/proxy/config"
	"github.com/dmaina5054/mithril/proxy/ebpf/snifilter"
	"github.com/dmaina5054/mithril/proxy/ebpf/sockops"
	"github.com/dmaina5054/mithril/proxy/internal/metrics"
	"github.com/dmaina5054/mithril/proxy/internal/proxy"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	startEBPF(ctx)
	startSNIFilter(ctx)

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

	// Any single listener returning, or a shutdown signal, ends the
	// process. Listener errors still exit immediately (no partial-
	// degraded-mode handling yet) — only the signal path unwinds via
	// ctx cancellation, which startEBPF's cleanup goroutine also waits on.
	select {
	case err := <-errCh:
		log.Fatal(err)
	case <-ctx.Done():
		log.Print("mithril-proxy: shutdown signal received, exiting")
	}
}

// startEBPF loads and attaches the sock_ops program to the root cgroup
// (host-wide per-process accounting, per spec) and starts the :9435
// exporter. Logs and returns on any failure — never fatal, per this
// file's top comment. NOT LIVE-VERIFIED: loading/attaching requires
// root/CAP_BPF this author doesn't have; the eBPF C program compiles
// and the Go-side map reading/metrics logic is unit tested, but the
// actual kernel behavior (especially PID attribution on passive/inbound
// connections — see ebpf/sockops/sockops.c's handle_established doc
// comment) needs real privileged verification.
func startEBPF(ctx context.Context) {
	const cgroupRoot = "/sys/fs/cgroup"
	const ebpfExporterAddr = "127.0.0.1:9435"
	const readInterval = 5 * time.Second // spec: "Go reads map every 5s"

	tracker, err := sockops.Load()
	if err != nil {
		log.Printf("mithril-proxy: eBPF sock_ops disabled (per-process bandwidth accounting unavailable): %v", err)
		return
	}

	if err := tracker.AttachCgroup(cgroupRoot); err != nil {
		log.Printf("mithril-proxy: eBPF sock_ops disabled (cgroup attach failed): %v", err)
		tracker.Close()
		return
	}

	log.Printf("mithril-proxy: eBPF sock_ops attached to %s", cgroupRoot)

	go metrics.RunEBPFExporter(ctx, tracker, readInterval)
	go func() {
		if err := metrics.ServeEBPFMetrics(ebpfExporterAddr); err != nil {
			log.Printf("mithril-proxy: ebpf-exporter server stopped: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		if err := tracker.Close(); err != nil {
			log.Printf("mithril-proxy: eBPF cleanup error: %v", err)
		} else {
			log.Print("mithril-proxy: eBPF sock_ops unloaded")
		}
	}()
}

// startSNIFilter loads the socket_filter eBPF program and, if it loads,
// sets proxy.SNIFilter so Handle attaches it to each accepted
// connection, plus starts one long-lived goroutine reading the ring
// buffer and logging {conn_id, sni, flow_type} events until ctx is
// canceled. Non-fatal on failure, same as startEBPF. NOT LIVE-VERIFIED —
// see ebpf/snifilter/loader.go's Tracker doc comment for the specific,
// unresolved assumption about packet-offset semantics this needs a
// privileged run to confirm or refute.
func startSNIFilter(ctx context.Context) {
	tracker, err := snifilter.Load()
	if err != nil {
		log.Printf("mithril-proxy: eBPF SNI socket filter disabled (kernel-side flow classification unavailable): %v", err)
		return
	}

	reader, err := tracker.NewReader()
	if err != nil {
		log.Printf("mithril-proxy: eBPF SNI socket filter disabled (ring buffer reader failed): %v", err)
		tracker.Close()
		return
	}

	proxy.SNIFilter = tracker
	log.Print("mithril-proxy: eBPF SNI socket filter enabled")

	go func() {
		for {
			ev, err := reader.Read()
			if err != nil {
				log.Printf("mithril-proxy: sni-filter ring buffer closed: %v", err)
				return
			}
			log.Printf("mithril-proxy: sni=%s flow_type=%s conn_id=%d (eBPF)", ev.SNI, ev.FlowType, ev.ConnID)
		}
	}()

	go func() {
		<-ctx.Done()
		reader.Close()
		if err := tracker.Close(); err != nil {
			log.Printf("mithril-proxy: eBPF SNI socket filter cleanup error: %v", err)
		} else {
			log.Print("mithril-proxy: eBPF SNI socket filter unloaded")
		}
	}()
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
