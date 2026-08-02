package snifilter

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// FlowType mirrors the C program's enum. FlowAPICall/FlowTelemetry are
// defined for parity with spec section 4 eBPF Feature 2's four named
// types but are never actually assigned by this program — see
// snifilter.c's top-of-file comment for why (receive-side-only
// visibility can't do bidirectional or cross-connection classification).
// Both would come through as FlowUnknown.
type FlowType uint8

const (
	FlowUnknown     FlowType = 0
	FlowImageUpload FlowType = 1
	FlowAPICall     FlowType = 2
	FlowTelemetry   FlowType = 3
)

func (f FlowType) String() string {
	switch f {
	case FlowImageUpload:
		return "FLOW_IMAGE_UPLOAD"
	case FlowAPICall:
		return "FLOW_API_CALL"
	case FlowTelemetry:
		return "FLOW_TELEMETRY"
	default:
		return "FLOW_UNKNOWN"
	}
}

// Event is the Go-native form of the eBPF program's struct sni_event.
type Event struct {
	ConnID   uint64 // = the socket cookie the program used as its map key
	SNI      string
	FlowType FlowType
}

// Tracker owns the loaded eBPF program/maps. LOADING AND ATTACHING
// REQUIRE ROOT/CAP_BPF — see ebpf/sockops.Tracker's doc comment, same
// situation here: compiles and the non-privileged pieces are unit
// tested, but real kernel behavior (notably the unverified assumption
// that a TCP-socket-attached SO_ATTACH_BPF filter sees skb->data
// starting at the TCP payload, headers already stripped — see
// snifilter.c's parsing entry point) needs a live privileged run.
type Tracker struct {
	objs mithrilSniFilterObjects
}

// Load reads the embedded eBPF object and loads its program+maps into
// the kernel. Requires root or CAP_BPF.
func Load() (*Tracker, error) {
	var objs mithrilSniFilterObjects
	if err := loadMithrilSniFilterObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("snifilter: load objects: %w", err)
	}
	return &Tracker{objs: objs}, nil
}

// AttachSocket attaches the socket_filter program to conn via
// SO_ATTACH_BPF. Per spec, this is the client-facing connection (the
// same one internal/proxy.PeekSNI reads from — this eBPF path
// complements that pure-Go one, operating on the same data).
func (t *Tracker) AttachSocket(conn syscall.Conn) error {
	if err := link.AttachSocketFilter(conn, t.objs.mithrilSniFilterPrograms.MithrilSnifilter); err != nil {
		return fmt.Errorf("snifilter: attach socket filter: %w", err)
	}
	return nil
}

// DetachSocket removes the filter — callers should do this once they've
// received this connection's Event (or the connection closes), so the
// kernel-side "already done, cheap exit" isn't relied on to bound
// per-packet cost forever.
func (t *Tracker) DetachSocket(conn syscall.Conn) error {
	if err := link.DetachSocketFilter(conn); err != nil {
		return fmt.Errorf("snifilter: detach socket filter: %w", err)
	}
	return nil
}

// Reader wraps the ring buffer — one per Tracker, read from a single
// goroutine per cilium/ebpf's ringbuf.Reader contract (matches the
// pattern in cilium/ebpf's own ringbuffer example: "a single goroutine
// blocking on epoll — no polling overhead", exactly the resource-cost
// note in spec section 4).
type Reader struct {
	rd *ringbuf.Reader
}

// NewReader opens a ring buffer reader for the loaded program's events map.
func (t *Tracker) NewReader() (*Reader, error) {
	rd, err := ringbuf.NewReader(t.objs.mithrilSniFilterMaps.SniEvents)
	if err != nil {
		return nil, fmt.Errorf("snifilter: open ringbuf reader: %w", err)
	}
	return &Reader{rd: rd}, nil
}

// Read blocks until the next event is available or the reader is closed.
func (r *Reader) Read() (Event, error) {
	record, err := r.rd.Read()
	if err != nil {
		return Event{}, err
	}

	raw, err := parseSniEvent(record.RawSample)
	if err != nil {
		return Event{}, fmt.Errorf("snifilter: parse ring buffer record: %w", err)
	}
	return raw, nil
}

// Close stops the reader (unblocks a pending Read with ringbuf.ErrClosed).
func (r *Reader) Close() error {
	return r.rd.Close()
}

// Close releases the loaded program/maps. Does not close any Readers or
// detach any sockets — callers own those and must clean them up first.
func (t *Tracker) Close() error {
	return t.objs.Close()
}

// parseSniEvent decodes one ring buffer record into the public Event
// type. LittleEndian matches this host's actual architecture (amd64) —
// same hardcoded choice cilium/ebpf's own ringbuffer example makes,
// not adapted per build tag; this project only ever deploys to
// Minas Tirith (amd64), so that's not a gap worth engineering around.
func parseSniEvent(raw []byte) (Event, error) {
	var ev mithrilSniFilterSniEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return Event{}, err
	}

	sniLen := ev.SniLen
	if sniLen > uint32(len(ev.Sni)) {
		sniLen = uint32(len(ev.Sni)) // defensive — a malformed/corrupt record shouldn't over-read
	}

	sni := make([]byte, 0, sniLen)
	for i := uint32(0); i < sniLen; i++ {
		sni = append(sni, byte(ev.Sni[i]))
	}

	return Event{
		ConnID:   ev.ConnId,
		SNI:      string(sni),
		FlowType: FlowType(ev.FlowType),
	}, nil
}
