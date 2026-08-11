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
// Phase 7: traffic interception enforcement — NOT spec's literal
// tc+iptables/nftables TPROXY mechanism (see ebpf/redirect/redirect.c's
// top comment for why, and the explicit user sign-off before building
// it that way). A BPF_CGROUP_INET4_CONNECT hook redirects configured
// PIDs' outbound connections to a transparent listener here, which
// recovers the true destination via an eBPF-populated correlation map
// and relays through the matching profile — same Resolver/DialUpstream/
// Relay pipeline the SOCKS5 path uses, just without a SOCKS5 handshake.
// eBPF failure is non-fatal for all three eBPF features — the core
// SOCKS5 proxy keeps running without them (e.g. missing CAP_BPF, kernel
// too old); an observability or enforcement gap shouldn't take down
// request forwarding.
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
	"github.com/dmaina5054/mithril/proxy/ebpf/redirect"
	"github.com/dmaina5054/mithril/proxy/ebpf/snifilter"
	"github.com/dmaina5054/mithril/proxy/ebpf/sockops"
	"github.com/dmaina5054/mithril/proxy/ebpf/zfs"
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
	startZFSKprobe(ctx)

	sessions := proxy.NewSessionStore() // shared across profiles — session keys are profile-username-prefixed, no collision risk

	// SortedNames gives deterministic profile index assignment — the
	// SAME ordering startRedirectEnforcement uses to populate
	// proxy_required_pids, so a profile's index here matches what the
	// eBPF connect4 hook records for its enforced PIDs.
	names := profiles.SortedNames()
	resolvers := make(proxy.ProfileResolvers, len(names))

	errCh := make(chan error, len(names))
	started := 0
	for i, name := range names {
		p := profiles.Profiles[name]
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
		resolvers[uint8(i)] = router

		log.Printf("mithril-proxy: profile %q (index %d) listening on %s, upstream %s", name, i, listenAddr, upstreamAddr)
		started++
		go func(ln net.Listener, router *proxy.Router) {
			errCh <- proxy.Serve(ln, router)
		}(ln, router)
	}

	if started == 0 {
		log.Fatal("mithril-proxy: no profiles started")
	}

	startRedirectEnforcement(ctx, profiles, resolvers, errCh)

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
	const ebpfExporterAddr = "0.0.0.0:9435" // bind all interfaces — Prometheus container needs host.docker.internal to reach it
	const readInterval = 5 * time.Second    // spec: "Go reads map every 5s"

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

// startZFSKprobe loads and attaches the ZFS I/O correlation kprobes
// (eBPF Feature 4 — zfs_read/zfs_write entry/return) and sets
// proxy.ZFSSnapshot so Handle reads the inflight counters at connection
// close. Non-fatal on failure: if ZFS isn't loaded on this host (which
// it isn't on the dev machine — ZFS lives on Minas Tirith), the kprobes
// simply won't fire and counters stay at 0, but the proxy still runs.
// NOT LIVE-VERIFIED — same root/CAP_BPF constraint as every other eBPF
// feature. ZFS module presence can't be tested on this dev box at all.
func startZFSKprobe(ctx context.Context) {
	probes, err := zfs.Load()
	if err != nil {
		log.Printf("mithril-proxy: ZFS kprobe disabled (eBPF Feature 4 unavailable): %v", err)
		return
	}

	if err := probes.AttachAll(); err != nil {
		log.Printf("mithril-proxy: ZFS kprobe disabled (kprobe attach failed — ZFS likely not loaded on this host): %v", err)
		probes.Close()
		return
	}

	proxy.ZFSSnapshot = probes
	log.Print("mithril-proxy: ZFS kprobes attached (zfs_read/zfs_write entry+return)")

	go func() {
		<-ctx.Done()
		if err := probes.Close(); err != nil {
			log.Printf("mithril-proxy: ZFS kprobe cleanup error: %v", err)
		} else {
			log.Print("mithril-proxy: ZFS kprobes unloaded")
		}
	}()
}

// transparentListenerAddr must match ebpf/redirect/redirect.c's
// TRANSPARENT_LISTENER_PORT #define — the eBPF program can't read this
// from config, so both sides hardcode the same value with a
// cross-reference comment. If this ever needs to change, it has to
// change in both places.
const transparentListenerAddr = "127.0.0.1:19001"

// startRedirectEnforcement loads and attaches the Phase 7 eBPF
// programs (connect4 redirect + sockops correlation bridge), populates
// proxy_required_pids from every profile's enforce_pids, and starts the
// transparent listener. Non-fatal on eBPF load/attach failure, same
// pattern as startEBPF/startSNIFilter — but unlike those, a failure
// here also means no PIDs get enforced at all, so it's logged more
// prominently. NOT LIVE-VERIFIED — this is the highest-risk, least-
// precedented eBPF phase in this project (see ebpf/redirect.Tracker's
// doc comment); errCh is passed through so the transparent listener's
// own Accept-loop failures surface the same way every other listener's
// does, not silently.
func startRedirectEnforcement(ctx context.Context, profiles *config.ProfilesConfig, resolvers proxy.ProfileResolvers, errCh chan<- error) {
	const cgroupRoot = "/sys/fs/cgroup"

	tracker, err := redirect.Load()
	if err != nil {
		log.Printf("mithril-proxy: eBPF traffic enforcement disabled (Phase 7 unavailable, direct-connection bypass NOT prevented): %v", err)
		return
	}

	if err := tracker.AttachCgroup(cgroupRoot); err != nil {
		log.Printf("mithril-proxy: eBPF traffic enforcement disabled (cgroup attach failed): %v", err)
		tracker.Close()
		return
	}

	names := profiles.SortedNames()
	enforced := 0
	for i, name := range names {
		p := profiles.Profiles[name]
		for _, pid := range p.EnforcePIDs {
			if err := tracker.AddRequiredPID(pid, uint8(i)); err != nil {
				log.Printf("mithril-proxy: failed to enforce pid %d for profile %q: %v", pid, name, err)
				continue
			}
			enforced++
		}
	}
	log.Printf("mithril-proxy: eBPF traffic enforcement attached to %s, %d PID(s) enforced", cgroupRoot, enforced)

	ln, err := net.Listen("tcp", transparentListenerAddr)
	if err != nil {
		log.Printf("mithril-proxy: transparent listener failed (redirected connections will fail to connect): %v", err)
		tracker.Close()
		return
	}
	log.Printf("mithril-proxy: transparent listener on %s", transparentListenerAddr)

	go func() {
		errCh <- proxy.ServeTransparent(ln, redirectLookupAdapter{tracker}, resolvers)
	}()

	go func() {
		<-ctx.Done()
		ln.Close()
		if err := tracker.Close(); err != nil {
			log.Printf("mithril-proxy: eBPF traffic enforcement cleanup error: %v", err)
		} else {
			log.Print("mithril-proxy: eBPF traffic enforcement unloaded")
		}
	}()
}

// redirectLookupAdapter adapts *redirect.Tracker's struct-returning
// LookupOriginalDest to proxy.RedirectLookup's primitive-returning
// signature — keeps internal/proxy free of an ebpf/redirect import,
// same pattern as SocketFilterAttacher for ebpf/snifilter.
type redirectLookupAdapter struct {
	tracker *redirect.Tracker
}

func (a redirectLookupAdapter) LookupOriginalDest(localPort uint16) (net.IP, uint16, uint8, bool, error) {
	dest, found, err := a.tracker.LookupOriginalDest(localPort)
	return dest.IP, dest.Port, dest.ProfileIndex, found, err
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
