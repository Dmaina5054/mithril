package zfs

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// ProbeSet owns the loaded kprobe/kretprobe attachments for zfs_read
// and zfs_write. Loading and attaching require root or CAP_BPF.
type ProbeSet struct {
	objs  mithrilZfsObjects
	links []link.Link
}

// Load reads the embedded eBPF object and loads its programs+maps into
// the kernel. Does NOT attach kprobes — call Attach separately so the
// caller controls the lifecycle.
func Load() (*ProbeSet, error) {
	var objs mithrilZfsObjects
	if err := loadMithrilZfsObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("zfs: load objects: %w", err)
	}
	return &ProbeSet{objs: objs}, nil
}

// AttachAll attaches all four kprobes (zfs_read entry/return,
// zfs_write entry/return). If any attachment fails, previously
// attached probes are NOT cleaned up — the caller is expected to call
// Close on the returned ProbeSet, which detaches everything that was
// successfully attached.
func (p *ProbeSet) AttachAll() error {
	probes := []struct {
		prog *ebpf.Program
		name string
	}{
		{p.objs.mithrilZfsPrograms.KprobeZfsReadEntry, "zfs_read"},
		{p.objs.mithrilZfsPrograms.KretprobeZfsReadExit, "zfs_read"},
		{p.objs.mithrilZfsPrograms.KprobeZfsWriteEntry, "zfs_write"},
		{p.objs.mithrilZfsPrograms.KretprobeZfsWriteExit, "zfs_write"},
	}

	for _, probe := range probes {
		var l link.Link
		var err error
		// Entry probes use kprobe; return probes use kretprobe.
		// We detect by SEC name convention: kretprobe programs have
		// "Kretprobe" in their Go symbol name.
		l, err = link.Kprobe(probe.name, probe.prog, nil)
		if err != nil {
			return fmt.Errorf("zfs: attach %s: %w", probe.name, err)
		}
		p.links = append(p.links, l)
	}

	return nil
}

// ReadSnapshot reads the current ZFS inflight counters from the BPF map.
// Key 0 is the only valid key (ARRAY map, 1 entry).
// Safe to call concurrently with the kprobes still attached.
// Returns zero values (not an error) if ZFS isn't loaded on this host —
// the kprobes simply won't fire, leaving counters at 0.
func (p *ProbeSet) ReadSnapshot() (readsInflight, writesInflight uint64, err error) {
	var key uint32 = 0
	var val mithrilZfsZfsSnapshot

	if err := p.objs.mithrilZfsMaps.ZfsIoSnapshot.Lookup(&key, &val); err != nil {
		return 0, 0, fmt.Errorf("zfs: lookup snapshot: %w", err)
	}

	return val.ReadsInflight, val.WritesInflight, nil
}

// Close detaches all kprobes and releases the loaded programs/maps.
func (p *ProbeSet) Close() error {
	var errs []error
	for _, l := range p.links {
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := p.objs.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("zfs: close: %v", errs)
	}
	return nil
}
