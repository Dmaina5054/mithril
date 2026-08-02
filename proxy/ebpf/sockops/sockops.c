//go:build ignore

#include "common.h"
#include "bpf_endian.h"
#include "bpf_sockops.h"

#define AF_INET 2 // standard Linux AF_INET/PF_INET value — matches
                  // cilium/ebpf's own tcprtt_sockops.c reference example

#define MAX_ESTABLISHED_SOCKETS 65535
#define MAX_TRACKED_PROCESSES 10240

char __license[] SEC("license") = "Dual MIT/GPL";

// 4-tuple identifying one TCP connection — used to correlate later
// callbacks (RTT_CB, STATE_CB) back to the process that owned the
// socket at connect/accept time, since those later callbacks may not
// run in that process's context (see handle_established below).
struct sk_key {
	u32 local_ip4;
	u32 remote_ip4;
	u32 local_port;
	u32 remote_port;
};

// pid/comm captured once per socket, plus the last-seen cumulative
// byte counters so later callbacks can compute a delta instead of
// overwriting (a process can have many concurrent sockets, and we need
// to SUM their contributions, not let the latest one clobber the rest).
struct sk_owner {
	u32 pid;
	char comm[16];
	u64 last_bytes_acked;
	u64 last_bytes_received;
};

struct proc_key {
	u32 pid;
	char comm[16];
};

// This is the map named in the infra spec (section 4, eBPF Feature 3) —
// internal/ebpf's Go loader reads this one directly.
struct proc_bytes {
	u64 bytes_sent; // cumulative skops->bytes_acked deltas
	u64 bytes_recv; // cumulative skops->bytes_received deltas
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ESTABLISHED_SOCKETS);
	__type(key, struct sk_key);
	__type(value, struct sk_owner);
} established_sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TRACKED_PROCESSES);
	__type(key, struct proc_key);
	__type(value, struct proc_bytes);
} process_bytes SEC(".maps");

static inline void init_sk_key(struct bpf_sock_ops *skops, struct sk_key *key) {
	key->local_ip4 = bpf_ntohl(skops->local_ip4);
	key->remote_ip4 = bpf_ntohl(skops->remote_ip4);
	key->local_port = skops->local_port;
	key->remote_port = bpf_ntohl(skops->remote_port);
}

// Records which process owns this socket. Only safe to trust
// bpf_get_current_pid_tgid()/bpf_get_current_comm() here because these
// two callbacks are the ones sock_ops fires in (or very close to) the
// owning process's syscall context:
//
//   - BPF_SOCK_OPS_TCP_CONNECT_CB fires synchronously inside connect(),
//     in the calling process — reliable for outbound connections (the
//     proxy's own upstream dials, ComfyUI's outbound API calls, etc).
//
//   - BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB fires when a connection
//     transitions SYN_RECV -> ESTABLISHED, which happens on arrival of
//     the final handshake ACK — a kernel/softirq event, NOT necessarily
//     inside the accept()-ing process's context. This is a genuine,
//     documented uncertainty, not resolved here: PID attribution for
//     PASSIVE (inbound/accepted) connections — e.g. node_exporter being
//     scraped — may be wrong or missing. NEEDS LIVE VERIFICATION; if
//     inbound-heavy processes show up with pid=0 or wrong comm in
//     process_bytes, this is why, and the fix is a kprobe on something
//     like tcp_v4_rcv or accept() rather than sock_ops alone.
static inline void handle_established(struct bpf_sock_ops *skops) {
	if (skops->family != AF_INET)
		return;

	struct sk_key key = {};
	init_sk_key(skops, &key);

	struct sk_owner owner = {};
	owner.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&owner.comm, sizeof(owner.comm));
	owner.last_bytes_acked = 0;
	owner.last_bytes_received = 0;

	bpf_map_update_elem(&established_sockets, &key, &owner, BPF_ANY);
	bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_RTT_CB_FLAG | BPF_SOCK_OPS_STATE_CB_FLAG);
}

// Adds this socket's byte-count delta (since the last flush) into its
// owning process's running total. Safe to call from any callback/any
// context — only reads skops's byte-count fields and does map
// arithmetic, no process-context helpers.
static inline void flush_bytes(struct bpf_sock_ops *skops) {
	struct sk_key key = {};
	init_sk_key(skops, &key);

	struct sk_owner *owner = bpf_map_lookup_elem(&established_sockets, &key);
	if (!owner)
		return;

	u64 acked_now = skops->bytes_acked;
	u64 recv_now = skops->bytes_received;
	u64 sent_delta = acked_now > owner->last_bytes_acked ? acked_now - owner->last_bytes_acked : 0;
	u64 recv_delta = recv_now > owner->last_bytes_received ? recv_now - owner->last_bytes_received : 0;
	owner->last_bytes_acked = acked_now;
	owner->last_bytes_received = recv_now;

	if (sent_delta == 0 && recv_delta == 0)
		return;

	struct proc_key pkey = {};
	pkey.pid = owner->pid;
	__builtin_memcpy(pkey.comm, owner->comm, sizeof(pkey.comm));

	struct proc_bytes *bytes = bpf_map_lookup_elem(&process_bytes, &pkey);
	if (bytes) {
		__sync_fetch_and_add(&bytes->bytes_sent, sent_delta);
		__sync_fetch_and_add(&bytes->bytes_recv, recv_delta);
	} else {
		struct proc_bytes fresh = { .bytes_sent = sent_delta, .bytes_recv = recv_delta };
		bpf_map_update_elem(&process_bytes, &pkey, &fresh, BPF_NOEXIST);
	}
}

static inline void handle_state_change(struct bpf_sock_ops *skops) {
	// args[0] is the state being LEFT. Leaving ESTABLISHED means the
	// connection is closing — do a final flush so the last bit of
	// traffic isn't lost, then stop tracking this socket.
	if (skops->args[0] != TCP_ESTABLISHED)
		return;

	flush_bytes(skops);

	struct sk_key key = {};
	init_sk_key(skops, &key);
	bpf_map_delete_elem(&established_sockets, &key);
}

SEC("sockops")
int mithril_sockops(struct bpf_sock_ops *skops) {
	switch (skops->op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		handle_established(skops);
		break;
	case BPF_SOCK_OPS_RTT_CB:
		flush_bytes(skops);
		break;
	case BPF_SOCK_OPS_STATE_CB:
		handle_state_change(skops);
		break;
	}
	return 0;
}
