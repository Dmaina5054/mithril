package sockops

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Tracker owns the loaded eBPF program/maps and the cgroup attachment.
// LOADING AND ATTACHING REQUIRE ROOT/CAP_BPF — this package compiles and
// its non-privileged pieces (map key encoding, /proc comm resolution)
// are unit tested, but Load/Attach's actual kernel behavior has only
// been verified via a live privileged run by Gandalf, not by this
// author directly.
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

// ProcessKey identifies one process for bandwidth accounting.
//
// Comm is resolved here in Go, via /proc/<pid>/comm, NOT captured in
// the eBPF program: the kernel verifier rejects bpf_get_current_comm()
// (helper #16) for BPF_PROG_TYPE_SOCK_OPS on this kernel (6.12.95+deb13)
// — "invalid argument: program of this type cannot use helper
// bpf_get_current_comm#16", confirmed via a real privileged load
// attempt. bpf_get_current_pid_tgid() is fine, so the eBPF map is keyed
// by plain PID; this resolution step fills in the process name.
//
// Known tradeoff, not resolved: resolution happens at READ time (up to
// readInterval after the byte counts were actually recorded), not at
// connect time. If a short-lived process exits and its PID gets reused
// by an unrelated process before the next read, the reused process's
// name would be (incorrectly) attributed to the original process's
// bytes. Accepted as a rare edge case rather than engineering around it
// — the alternative (caching PID->comm at connect time in Go, which
// would require plumbing connect events out of the kernel some other
// way) is real added complexity for a narrow window of risk.
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

// ReadProcessBytes snapshots the process_bytes map, resolving each PID's
// comm via /proc. Safe to call concurrently with the eBPF program still
// running (map reads don't need to pause it) but not safe for
// concurrent calls to ReadProcessBytes itself on the same Tracker
// without external synchronization — callers (internal/metrics) use a
// single ticker goroutine, so this hasn't come up, but it's not a
// mutex-protected type.
func (t *Tracker) ReadProcessBytes() (map[ProcessKey]ProcessBytes, error) {
	out := make(map[ProcessKey]ProcessBytes)

	var pid uint32
	var val mithrilSockopsProcBytes
	iter := t.objs.mithrilSockopsMaps.ProcessBytes.Iterate()
	for iter.Next(&pid, &val) {
		out[ProcessKey{PID: pid, Comm: resolveComm(pid)}] = ProcessBytes{
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

// resolveComm reads /proc/<pid>/comm. Falls back to "pid-<N>" if the
// process has already exited by read time (ESRCH/ENOENT) — a labeled,
// visible fallback rather than silently dropping the data or panicking.
func resolveComm(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return fmt.Sprintf("pid-%d", pid)
	}
	return strings.TrimSpace(string(data))
}
