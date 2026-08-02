package sockops

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Tracker owns the loaded eBPF program/maps and the cgroup attachment.
// LOADING AND ATTACHING REQUIRE ROOT/CAP_BPF — this package compiles and
// its non-privileged pieces (struct layout, map key encoding) are unit
// tested, but Load/Attach themselves have not been run against a live
// kernel by this author; that needs verification with real privileges.
type Tracker struct {
	objs mithrilSockopsObjects
	link link.Link
}

// Load reads the embedded eBPF object and loads its program+maps into
// the kernel. Requires root or CAP_BPF.
func Load() (*Tracker, error) {
	var objs mithrilSockopsObjects
	if err := loadMithrilSockopsObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("sockops: load objects: %w", err)
	}
	return &Tracker{objs: objs}, nil
}

// AttachCgroup attaches the sock_ops program to cgroupPath (typically
// the root cgroup v2 mount, /sys/fs/cgroup, to observe all processes on
// the host — matching the spec's "per-process bandwidth accounting"
// scope, not just the proxy's own cgroup). Requires root or CAP_BPF +
// CAP_NET_ADMIN.
func (t *Tracker) AttachCgroup(cgroupPath string) error {
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: t.objs.mithrilSockopsPrograms.MithrilSockops,
	})
	if err != nil {
		return fmt.Errorf("sockops: attach cgroup %s: %w", cgroupPath, err)
	}
	t.link = l
	return nil
}

// ProcessKey identifies one process for bandwidth accounting — the Go-
// native form of the eBPF map's struct proc_key.
type ProcessKey struct {
	PID  uint32
	Comm string
}

// ProcessBytes is the Go-native form of struct proc_bytes — cumulative
// totals as tracked by the eBPF program, not deltas.
type ProcessBytes struct {
	BytesSent uint64
	BytesRecv uint64
}

// ReadProcessBytes snapshots the process_bytes map. Safe to call
// concurrently with the eBPF program still running (map reads don't
// need to pause it) but not safe for concurrent calls to ReadProcessBytes
// itself on the same Tracker without external synchronization — callers
// (internal/metrics) use a single ticker goroutine, so this hasn't come
// up, but it's not a mutex-protected type.
func (t *Tracker) ReadProcessBytes() (map[ProcessKey]ProcessBytes, error) {
	out := make(map[ProcessKey]ProcessBytes)

	var key mithrilSockopsProcKey
	var val mithrilSockopsProcBytes
	iter := t.objs.mithrilSockopsMaps.ProcessBytes.Iterate()
	for iter.Next(&key, &val) {
		out[ProcessKey{PID: key.Pid, Comm: commToString(key.Comm)}] = ProcessBytes{
			BytesSent: val.BytesSent,
			BytesRecv: val.BytesRecv,
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("sockops: iterate process_bytes: %w", err)
	}
	return out, nil
}

// Close detaches the cgroup link and releases the loaded program/maps.
func (t *Tracker) Close() error {
	var errs []error
	if t.link != nil {
		if err := t.link.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := t.objs.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("sockops: close: %v", errs)
	}
	return nil
}

// commToString converts the kernel's fixed-size, NUL-padded comm buffer
// (bpf2go generates [16]int8 for the C `char comm[16]`) into a clean Go
// string.
func commToString(comm [16]int8) string {
	b := make([]byte, 0, 16)
	for _, c := range comm {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
