package proxy

import (
	"log"
	"net"
)

// RedirectLookup is satisfied by *redirect.Tracker. Declared here (not
// imported directly) so internal/proxy doesn't need to import
// ebpf/redirect, matching the SocketFilterAttacher pattern above.
type RedirectLookup interface {
	LookupOriginalDest(localPort uint16) (ip net.IP, port uint16, profileIndex uint8, found bool, err error)
}

// ProfileResolvers maps a profile index (see config.ProfilesConfig.SortedNames,
// eBPF Feature 1's proxy_required_pids/redirect_targets value) to the
// Resolver that profile's connections should use.
type ProfileResolvers map[uint8]Resolver

// ServeTransparent accepts connections on ln forever — each one is a
// process whose outbound connection the eBPF connect4 hook (Session B
// Phase 7) redirected here without the process's knowledge. Recovers
// the true destination and originating profile via lookup, then hands
// off to HandleTransparent. A connection with no correlation entry
// (lookup.found == false) means either it wasn't actually a redirected
// connection, or the eBPF sockops correlation bridge hasn't written it
// yet — logged and closed, never guessed at.
func ServeTransparent(ln net.Listener, lookup RedirectLookup, resolvers ProfileResolvers) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleTransparentAccept(conn, lookup, resolvers)
	}
}

func handleTransparentAccept(conn net.Conn, lookup RedirectLookup, resolvers ProfileResolvers) {
	tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		log.Printf("mithril-proxy: (transparent) non-TCP remote addr %v, closing", conn.RemoteAddr())
		conn.Close()
		return
	}

	// tcpAddr.Port here is the CONNECTING PROCESS's local port for this
	// connection (from the listener's side, the accepted connection's
	// remote port) — the same value the eBPF sockops correlation bridge
	// keyed redirect_targets by. See ebpf/redirect/redirect.c's
	// redirect_targets map comment for why this is the one value
	// genuinely shared between both ends of the same TCP connection.
	ip, port, profileIndex, found, err := lookup.LookupOriginalDest(uint16(tcpAddr.Port))
	if err != nil {
		log.Printf("mithril-proxy: (transparent) original-dest lookup error for local port %d: %v", tcpAddr.Port, err)
		conn.Close()
		return
	}
	if !found {
		log.Printf("mithril-proxy: (transparent) no original-dest entry for local port %d — not a redirected connection, or correlation not yet written", tcpAddr.Port)
		conn.Close()
		return
	}

	resolver, ok := resolvers[profileIndex]
	if !ok {
		log.Printf("mithril-proxy: (transparent) no resolver configured for profile index %d", profileIndex)
		conn.Close()
		return
	}

	target := Target{Host: ip.String(), Port: port}
	HandleTransparent(conn, target, resolver)
}
