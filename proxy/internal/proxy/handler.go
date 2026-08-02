package proxy

import (
	"fmt"
	"log"
	"net"
	"time"
)

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
	Relay(conn, upstream)
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
