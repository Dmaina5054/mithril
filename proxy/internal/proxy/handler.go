package proxy

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/dmaina5054/mithril/proxy/internal/metrics"
)

// SNIFilter, if set (by main.go, after successfully loading the eBPF
// socket_filter program), gets attached to each accepted connection
// alongside the pure-Go PeekSNI below — spec's two SNI mechanisms
// (Feature 2 kernel-side, Feature 5 pure-Go) run side by side, neither
// depends on the other. nil (the default) means the eBPF path is
// unavailable (e.g. no root) and Handle skips it entirely — same
// graceful-degradation approach as the sock_ops metrics path.
//
// Classification results are NOT read here: per spec, "Go reads perf
// buffer, enriches proxy connection log" independently — main.go runs
// one long-lived goroutine reading the ring buffer and logging events,
// not coupled to any single Handle() call. Attach/detach is all this
// package does.
var SNIFilter SocketFilterAttacher

// SocketFilterAttacher is satisfied by *snifilter.Tracker. Declared
// here (not imported directly) so internal/proxy doesn't need to
// import ebpf/snifilter just for this optional hook. Only AttachSocket
// is needed — see the no-explicit-detach note in Handle below for why.
type SocketFilterAttacher interface {
	AttachSocket(conn syscall.Conn) error
}

// ZFSReader is satisfied by *zfs.ProbeSet. Declared here so
// internal/proxy doesn't need to import ebpf/zfs just for this optional
// hook. ReadSnapshot returns the current ZFS inflight counters —
// called after Relay finishes to correlate proxy connection duration
// with concurrent ZFS I/O load.
type ZFSReader interface {
	ReadSnapshot() (readsInflight, writesInflight uint64, err error)
}

// ZFSSnapshot, if set (by main.go, after successfully loading the ZFS
// kprobe), is read at connection close to enrich the proxy connection
// log with ZFS inflight correlation data. nil (the default) means
// ZFS kprobes aren't loaded (e.g. no root, ZFS not on this host) and
// the log line omits ZFS fields entirely.
var ZFSSnapshot ZFSReader

// Resolver establishes an upstream connection for a client's requested
// Target. StaticResolver (below) is the simplest implementation — one
// fixed upstream/credential pair, predating routing.yaml entirely.
// *Router (router.go) is the real one: it matches routing.yaml's geo/
// session rules and delegates the actual dial to a
// vpnprovider.Provider, so swapping the upstream VPN/proxy vendor never
// requires a Resolver or Handle change — see
// docs/diagrams/provider-plugin-architecture.md.
type Resolver interface {
	Dial(ctx context.Context, target Target, timeout time.Duration) (net.Conn, error)
}

// StaticResolver always dials the same upstream with the same
// credentials, regardless of target. Sufficient to prove the SOCKS5
// core end-to-end without any routing or provider-plugin machinery —
// used by tests and small standalone setups, not by main.go anymore
// (which always goes through *Router, even for a single-profile setup).
type StaticResolver struct {
	UpstreamAddr string
	Creds        Credentials
}

func (s StaticResolver) Dial(_ context.Context, target Target, timeout time.Duration) (net.Conn, error) {
	if s.UpstreamAddr == "" {
		return nil, fmt.Errorf("static resolver: no upstream address configured")
	}
	return DialUpstream(s.UpstreamAddr, s.Creds, target, timeout)
}

// DialTimeout is the upstream connect timeout. Var, not const, so tests
// can shorten it.
var DialTimeout = 15 * time.Second

// Handle services one accepted local SOCKS5 connection end-to-end:
// server-side SOCKS5 handshake, resolve+dial the upstream (via
// resolver, whatever it's backed by), reply to the local client, then
// relay bytes until either side closes.
func Handle(conn net.Conn, resolver Resolver) {
	target, err := ServerHandshake(conn)
	if err != nil {
		log.Printf("mithril-proxy: handshake error from %s: %v", conn.RemoteAddr(), err)
		metrics.RecordConnectionError("handshake")
		conn.Close()
		return
	}

	upstream, err := resolver.Dial(context.Background(), target, DialTimeout)
	if err != nil {
		log.Printf("mithril-proxy: upstream dial error for %s: %v", target.Addr(), err)
		metrics.RecordConnectionError("dial")
		_ = writeReply(conn, replyGeneralFailure)
		conn.Close()
		return
	}

	if err := writeReply(conn, replySuccess); err != nil {
		log.Printf("mithril-proxy: reply write error for %s: %v", target.Addr(), err)
		metrics.RecordConnectionError("reply")
		conn.Close()
		upstream.Close()
		return
	}

	log.Printf("mithril-proxy: connected %s -> %s", conn.RemoteAddr(), target.Addr())
	attachSNIAndRelay(conn, upstream, target)
}

// HandleTransparent services one connection redirected by the eBPF
// Feature 1 connect4 hook (Session B Phase 7) — the connecting process
// never spoke SOCKS5 and doesn't know it's been redirected, so there's
// no handshake to perform and no protocol-level reply to send; target
// is already known (recovered by the caller via
// redirect.Tracker.LookupOriginalDest) rather than parsed from the
// connection itself. Everything after "target is known" — resolve,
// dial, eBPF/Go SNI, relay — is identical to the SOCKS5 path, hence
// sharing attachSNIAndRelay rather than duplicating it.
func HandleTransparent(conn net.Conn, target Target, resolver Resolver) {
	upstream, err := resolver.Dial(context.Background(), target, DialTimeout)
	if err != nil {
		log.Printf("mithril-proxy: (transparent) upstream dial error for %s: %v", target.Addr(), err)
		metrics.RecordConnectionError("dial")
		conn.Close()
		return
	}

	log.Printf("mithril-proxy: (transparent) connected %s -> %s", conn.RemoteAddr(), target.Addr())
	attachSNIAndRelay(conn, upstream, target)
}

// attachSNIAndRelay is the shared tail end of both Handle and
// HandleTransparent: attach the eBPF SNI filter, do the Go SNI peek,
// then relay until either side closes. Requires only that upstream is
// already dialed and conn is ready to have application data flow
// through it (SOCKS5's reply already sent, if applicable).
func attachSNIAndRelay(conn net.Conn, upstream net.Conn, target Target) {
	start := time.Now()

	// eBPF SNI socket filter (Feature 2): attach if loaded. Only TCP
	// connections implement syscall.Conn in a way link.AttachSocketFilter
	// accepts — true for everything this proxy accepts, but checked
	// rather than assumed. No explicit detach: Relay (below) closes conn
	// itself as part of its own cleanup, so a deferred detach here would
	// always run on an already-closed fd and always fail. Closing a
	// socket already detaches any attached BPF filter as a matter of
	// kernel socket teardown — nothing to do here beyond attaching.
	if SNIFilter != nil {
		if sc, ok := conn.(syscall.Conn); ok {
			if err := SNIFilter.AttachSocket(sc); err != nil {
				log.Printf("mithril-proxy: sni-filter attach failed for %s: %v", conn.RemoteAddr(), err)
			}
		}
	}

	// Go SNI peek (eBPF Feature 5): a pure-Go fallback/complement to the
	// eBPF socket-filter SNI extractor, for when that filter fires too
	// late or the handshake is non-standard. Must happen here, at the
	// start of relay — this is the first point any client application
	// data (as opposed to the SOCKS5 control channel) exists to peek at.
	// bufferedConn preserves the peeked bytes so Relay still sees them.
	//
	// bufio.Reader.Peek(n) blocks until it accumulates the full n bytes
	// or the underlying Read errors — NOT "at least 1 byte" like the
	// spec's original io.ReadAtLeast sketch. Without a bounded deadline
	// here, any connection whose first flight is under sniPeekSize bytes
	// (a short HTTP request, or a ClientHello record smaller than 512
	// with nothing sent immediately after) would stall relay entirely
	// waiting for bytes that aren't coming yet. 200ms is enough for a
	// same-flight TLS ClientHello to arrive; anything less just means
	// PeekSNI parses a partial buffer and likely returns "".
	buffered := &bufferedConn{Conn: conn, r: bufio.NewReaderSize(conn, sniPeekSize)}
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	sni, peekErr := PeekSNI(buffered.r)
	_ = conn.SetReadDeadline(time.Time{}) // clear before relay — no deadline on the actual data path
	if peekErr == nil && sni != "" {
		log.Printf("mithril-proxy: sni=%s conn=%s->%s", sni, conn.RemoteAddr(), target.Addr())
	}

	Relay(buffered, upstream)

	// ZFS I/O correlation (eBPF Feature 4): read inflight counters at
	// connection close. This gives a point-in-time snapshot of ZFS
	// concurrency at the moment the connection finished — a correlative
	// signal, not a precise measurement. Skipped entirely when ZFS
	// kprobes aren't loaded (ZFSSnapshot == nil, the default).
	if ZFSSnapshot != nil {
		reads, writes, err := ZFSSnapshot.ReadSnapshot()
		if err != nil {
			log.Printf("mithril-proxy: zfs snapshot read error for %s: %v", conn.RemoteAddr(), err)
		} else {
			log.Printf("mithril-proxy: conn=%s->%s duration_ms=%d zfs_reads=%d zfs_writes=%d",
				conn.RemoteAddr(), target.Addr(),
				time.Since(start).Milliseconds(),
				reads, writes)
		}
	}
}

// bufferedConn is a net.Conn whose Read goes through a bufio.Reader
// instead of the embedded Conn directly — used so bytes consumed by a
// Peek (e.g. PeekSNI) are still delivered to the next Read, rather than
// lost. Every other method (Write, Close, deadlines, ...) passes
// through to the embedded Conn unchanged.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

// Serve accepts connections on ln forever, handling each with resolver
// in its own goroutine. Blocks until ln.Accept returns a non-temporary
// error (typically because ln was closed).
func Serve(ln net.Listener, resolver Resolver) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("mithril-proxy: accept: %w", err)
		}
		go Handle(conn, resolver)
	}
}
