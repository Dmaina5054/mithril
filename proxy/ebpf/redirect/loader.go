package redirect

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Tracker owns the loaded eBPF programs/maps and both cgroup
// attachments. LOADING AND ATTACHING REQUIRE ROOT/CAP_BPF — same
// situation as ebpf/sockops and ebpf/snifilter. This package carries
// the highest unverified risk of any eBPF phase in this project: it's
// the first one that redirects live traffic rather than only
// observing, and — unlike Phase 5 (had a working cilium/ebpf reference
// example) or Phase 6 (eventually got one narrowed down through live
// iteration) — there's no reference example for a
// BPF_CGROUP_INET4_CONNECT + bpf_sk_storage bridge to a second sockops
// program at all. Compiles clean and the struct/byte-order reasoning
// is documented throughout, but none of it has run against a real
// kernel yet.
type Tracker struct {
	objs         mithrilRedirectObjects
	connect4Link link.Link
	sockopsLink  link.Link
}

// Load reads the embedded eBPF object and loads its programs+maps into
// the kernel. Requires root or CAP_BPF.
func Load() (*Tracker, error) {
	var objs mithrilRedirectObjects
	if err := loadMithrilRedirectObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("redirect: load objects: %w", err)
	}
	return &Tracker{objs: objs}, nil
}

// AttachCgroup attaches both programs to cgroupPath (the root cgroup
// v2 mount, /sys/fs/cgroup, matching Phase 5's scope — host-wide, not
// just the proxy's own cgroup, since the whole point is catching OTHER
// processes' connections): the connect4 redirect hook, and the sockops
// correlation bridge. Independent bpf_link attachments — verified this
// kernel uses the bpf_link cgroup attachment mechanism (not the legacy
// PROG_ATTACH+flags one), which natively supports multiple programs on
// the same attach type without conflicting with Phase 5's own,
// separately-loaded sockops program on the same cgroup.
func (t *Tracker) AttachCgroup(cgroupPath string) error {
	connect4, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: t.objs.mithrilRedirectPrograms.MithrilConnect4,
	})
	if err != nil {
		return fmt.Errorf("redirect: attach connect4 to cgroup %s: %w", cgroupPath, err)
	}
	t.connect4Link = connect4

	sockops, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: t.objs.mithrilRedirectPrograms.MithrilRedirectSockops,
	})
	if err != nil {
		connect4.Close()
		t.connect4Link = nil
		return fmt.Errorf("redirect: attach sockops bridge to cgroup %s: %w", cgroupPath, err)
	}
	t.sockopsLink = sockops

	return nil
}

// AddRequiredPID marks pid as required to route through the proxy —
// profileIndex identifies which profiles.yaml entry's routing/upstream
// applies (see internal/proxy/transparent.go). The proxy's own PID must
// never be passed here — see redirect.c's top-of-map comment for why
// that alone is what prevents a redirect loop, no separate exclusion
// map needed.
func (t *Tracker) AddRequiredPID(pid uint32, profileIndex uint8) error {
	if err := t.objs.mithrilRedirectMaps.ProxyRequiredPids.Put(pid, profileIndex); err != nil {
		return fmt.Errorf("redirect: add required pid %d: %w", pid, err)
	}
	return nil
}

// RemoveRequiredPID stops enforcing pid.
func (t *Tracker) RemoveRequiredPID(pid uint32) error {
	if err := t.objs.mithrilRedirectMaps.ProxyRequiredPids.Delete(pid); err != nil {
		return fmt.Errorf("redirect: remove required pid %d: %w", pid, err)
	}
	return nil
}

// OriginalDest is a redirected connection's true intended destination,
// recovered by the transparent listener via LookupOriginalDest.
// ProfileIndex identifies which profiles.yaml entry's routing/upstream
// credentials the connecting PID was registered under (AddRequiredPID).
type OriginalDest struct {
	IP           net.IP
	Port         uint16
	ProfileIndex uint8
}

// LookupOriginalDest recovers the original destination for a redirected
// connection, keyed by localPort — the connecting process's local port
// for that connection, which is also the accepted connection's
// RemoteAddr port from the transparent listener's side (the one value
// genuinely shared between both ends of the same TCP connection; see
// redirect.c's redirect_targets map comment). Returns found=false if no
// entry exists — the listener should treat that as "not a redirected
// connection, or the correlation hasn't landed yet" and close, not
// guess.
func (t *Tracker) LookupOriginalDest(localPort uint16) (dest OriginalDest, found bool, err error) {
	var raw mithrilRedirectOriginalDest
	if err := t.objs.mithrilRedirectMaps.RedirectTargets.Lookup(localPort, &raw); err != nil {
		if err == ebpf.ErrKeyNotExist {
			return OriginalDest{}, false, nil
		}
		return OriginalDest{}, false, fmt.Errorf("redirect: lookup original dest for local port %d: %w", localPort, err)
	}

	return decodeOriginalDest(raw), true, nil
}

// decodeOriginalDest converts the raw struct as cilium/ebpf's map
// Lookup decoded it into the correct IP/port. Split out from
// LookupOriginalDest specifically so this byte-order math is unit
// testable without a live eBPF map.
//
// raw.Ip/raw.Port hold network-byte-order bytes (straight from the
// sockaddr the process originally tried to connect to), but the map
// Lookup does a raw memory copy into the Go struct — on this (little-
// endian, amd64) host, Go's uint32/uint16 then interpret those same
// bytes using NATIVE (little-endian) convention, backwards from what
// was intended. Fix: PutUint32/16 with LittleEndian reconstructs the
// ORIGINAL raw bytes (undoes Go's native-endian value interpretation,
// the exact inverse operation) — for the IP those bytes are then
// already correct, big-endian/network-order, directly usable as
// net.IP; for the port, THEN interpret those reconstructed bytes as
// BigEndian to get the correctly-valued port number.
func decodeOriginalDest(raw mithrilRedirectOriginalDest) OriginalDest {
	ipBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipBytes, raw.Ip)

	portBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(portBytes, raw.Port)
	port := binary.BigEndian.Uint16(portBytes)

	return OriginalDest{IP: net.IP(ipBytes), Port: port, ProfileIndex: raw.ProfileIndex}
}

// Close detaches both cgroup links and releases the loaded programs/maps.
func (t *Tracker) Close() error {
	var errs []error
	if t.connect4Link != nil {
		if err := t.connect4Link.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if t.sockopsLink != nil {
		if err := t.sockopsLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := t.objs.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("redirect: close: %v", errs)
	}
	return nil
}
