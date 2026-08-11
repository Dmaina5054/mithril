//go:build ignore

#include "common.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Single global snapshot of ZFS I/O inflight counts.
// Key 0 is the only valid key (BPF_MAP_TYPE_ARRAY, 1 entry).
// Read by Go at proxy connection close to correlate proxy bytes
// with concurrent ZFS load.
struct zfs_snapshot {
	u64 reads_inflight;
	u64 writes_inflight;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct zfs_snapshot);
} zfs_io_snapshot SEC(".maps");

// zfs_read entry: one more reader in flight.
SEC("kprobe/zfs_read")
int kprobe_zfs_read_entry(struct pt_regs *ctx) {
	u32 key = 0;
	struct zfs_snapshot *snap = bpf_map_lookup_elem(&zfs_io_snapshot, &key);
	if (!snap)
		return 0;
	__sync_fetch_and_add(&snap->reads_inflight, 1);
	return 0;
}

// zfs_read return: one fewer reader in flight.
SEC("kretprobe/zfs_read")
int kretprobe_zfs_read_exit(struct pt_regs *ctx) {
	u32 key = 0;
	struct zfs_snapshot *snap = bpf_map_lookup_elem(&zfs_io_snapshot, &key);
	if (!snap)
		return 0;
	// Decrement. Underflow is theoretically possible if a kretprobe fires
	// without a matching kprobe entry (module unload race), but in practice
	// the kernel matches entry/return pairs. A stuck counter is benign —
	// the Grafana scatter plot uses this as a correlative signal, not a
	// precise metric.
	__sync_fetch_and_add(&snap->reads_inflight, (u64)-1);
	return 0;
}

// zfs_write entry: one more writer in flight.
SEC("kprobe/zfs_write")
int kprobe_zfs_write_entry(struct pt_regs *ctx) {
	u32 key = 0;
	struct zfs_snapshot *snap = bpf_map_lookup_elem(&zfs_io_snapshot, &key);
	if (!snap)
		return 0;
	__sync_fetch_and_add(&snap->writes_inflight, 1);
	return 0;
}

// zfs_write return: one fewer writer in flight.
SEC("kretprobe/zfs_write")
int kretprobe_zfs_write_exit(struct pt_regs *ctx) {
	u32 key = 0;
	struct zfs_snapshot *snap = bpf_map_lookup_elem(&zfs_io_snapshot, &key);
	if (!snap)
		return 0;
	__sync_fetch_and_add(&snap->writes_inflight, (u64)-1);
	return 0;
}
