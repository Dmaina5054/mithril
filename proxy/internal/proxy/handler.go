package proxy

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
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

// Resolver maps a client's requested Target to an upstream SOCKS5 address
// and the credentials to authenticate with. Session B Phase 2 ships
// StaticResolver (one fixed upstream/credential pair); Phase 3 replaces
// it with the geo/session-aware router — Handle doesn't change.
type Resolver interface {
	Resolve(target Target) (upstreamAddr string, creds Credentials, err error)
}

// StaticResolver always returns the same upstream and credentials,
// regardless of target. Sufficient to prove the SOCKS5 core end-to-end
// (Phase 2 gate); Phase 3 replaces this with real geo/session routing.
type StaticResolver struct {
	UpstreamAddr string
	Creds        Credentials
}

func (s StaticResolver) Resolve(_ Target) (string, Credentials, error) {
	if s.UpstreamAddr == "" {
		return "", Credentials{}, fmt.Errorf("static resolver: no upstream address configured")
	}
	return s.UpstreamAddr, s.Creds, nil
}

// DialTimeout is the upstream connect timeout. Var, not const, so tests
// can shorten it.
var DialTimeout = 15 * time.Second

// Handle services one accepted local connection end-to-end: server-side
// SOCKS5 handshake, resolve the upstream, dial+auth upstream, reply to
// the local client, then relay bytes until either side closes.
func Handle(conn net.Conn, resolver Resolver) {
	target, err := ServerHandshake(conn)
	if err != nil {
		log.Printf("mithril-proxy: handshake error from %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	upstreamAddr, creds, err := resolver.Resolve(target)
	if err != nil {
		log.Printf("mithril-proxy: resolve error for %s: %v", target.Addr(), err)
		_ = writeReply(conn, replyGeneralFailure)
		conn.Close()
		return
	}

	upstream, err := DialUpstream(upstreamAddr, creds, target, DialTimeout)
	if err != nil {
		log.Printf("mithril-proxy: upstream dial error for %s via %s: %v", target.Addr(), upstreamAddr, err)
		_ = writeReply(conn, replyGeneralFailure)
		conn.Close()
		return
	}

	if err := writeReply(conn, replySuccess); err != nil {
		log.Printf("mithril-proxy: reply write error for %s: %v", target.Addr(), err)
		conn.Close()
		upstream.Close()
		return
	}

	log.Printf("mithril-proxy: connected %s -> %s via %s", conn.RemoteAddr(), target.Addr(), upstreamAddr)

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
