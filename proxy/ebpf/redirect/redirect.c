//go:build ignore

#include "common.h"
#include "bpf_endian.h"
#include "bpf_sockaddr.h"
#include "bpf_sockops.h"

// eBPF Feature 1 — Traffic Interception Enforcement, spec section 4.
//
// DEVIATES FROM SPEC'S LITERAL MECHANISM, deliberately, with explicit
// user sign-off before writing any of this: spec describes a tc
// program on interface egress + iptables/nftables SO_TRANSPARENT/TPROXY
// rules. That needs (a) a way to correlate a raw packet at the TC layer
// back to a PID, which TC hooks don't have natively and which spec
// doesn't specify a mechanism for, and (b) host iptables/nftables and
// kernel routing-table changes — a misconfiguration there risks
// breaking real network connectivity, not just this feature. This
// program instead uses a BPF_CGROUP_INET4_CONNECT hook: it runs in the
// connecting PROCESS's own context (native, reliable PID access,
// nothing to correlate), and rewrites the connection's destination
// directly — no iptables, no routing table changes. Achieves the same
// stated goal ("proxy becomes mandatory for configured workloads")
// with a smaller, more self-contained blast radius.
//
// IPv4 only. No BPF_CGROUP_INET6_CONNECT counterpart — a real, scoped
// gap, not an oversight; add one following the same pattern if IPv6
// enforcement is needed later.

#define AF_INET 2

// Missing from the vendored bpf_helper_defs.h/common.h (only mentioned
// in helper doc comments there, never actually defined as usable
// macros) — values confirmed against the real UAPI header
// (/usr/include/linux/bpf.h, linux-libc-dev 6.12.100-1), not guessed.
#define BPF_F_NO_PREALLOC 1
#define BPF_SK_STORAGE_GET_F_CREATE 1

// proxy_required_pids is the map spec names directly — key: PID,
// value: profile index (which profiles.yaml entry's routing/upstream
// applies). Populated by the Go control plane from profiles.yaml's
// enforce_pids lists; the proxy's own PID is never added here (there's
// no auto-discovery, only explicit config), which is what prevents the
// proxy's own outbound connections to the IPRoyal upstream from being
// redirected back into itself — no separate exclusion map needed.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, u8);
} proxy_required_pids SEC(".maps");

// original_dest: what a redirected connection's destination actually
// was, before this program rewrote it. Bridges the connect4 hook (which
// knows the original destination, but fires before the connection's
// local port is assigned) to the sockops hook below (which knows the
// local port, via TCP_CONNECT_CB, but wasn't the one that made the
// redirect decision) — both hooks run against the SAME underlying
// socket, so sk_storage carries the value across.
struct original_dest {
	u32 ip;   // network byte order
	u16 port; // network byte order
	u8 profile_index; // copied from proxy_required_pids at connect4 time —
	                    // the transparent listener needs this to know which
	                    // profiles.yaml entry's routing/credentials apply,
	                    // not just the raw destination.
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct original_dest);
} sk_original_dest SEC(".maps");

// redirect_targets is what the Go transparent listener actually reads:
// keyed by the CLIENT's local port for this connection (== the
// accepted connection's RemoteAddr port, from the listener's side —
// the one value genuinely shared between the connecting process's view
// and the accepting listener's view of the same TCP connection).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65535);
	__type(key, u16);
	__type(value, struct original_dest);
} redirect_targets SEC(".maps");

// TRANSPARENT_LISTENER_PORT must match internal/proxy's transparent
// listener — see internal/proxy/transparent.go. Not read from
// profiles.yaml/config here since eBPF programs can't read runtime
// config; if this ever needs to be configurable, it has to become a
// BPF global variable the Go loader sets before load, not a #define.
#define TRANSPARENT_LISTENER_PORT 19001

SEC("cgroup/connect4")
int mithril_connect4(struct bpf_sock_addr *ctx) {
	if (ctx->user_family != AF_INET)
		return 1; // not IPv4 — out of scope for this hook, allow unmodified

	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 *profile_index = bpf_map_lookup_elem(&proxy_required_pids, &pid);
	if (!profile_index)
		return 1; // not a configured/enforced PID — allow direct connection

	if (!ctx->sk)
		return 1; // no socket to attach original-dest tracking to — degrade to allow, never block

	struct original_dest orig = {};
	orig.ip = ctx->user_ip4;
	orig.port = (u16)ctx->user_port; // ctx->user_port is already network byte order, matches struct original_dest's convention
	orig.profile_index = *profile_index;

	struct original_dest *stored = bpf_sk_storage_get(&sk_original_dest, ctx->sk, &orig, BPF_SK_STORAGE_GET_F_CREATE);
	if (!stored)
		return 1; // sk_storage alloc failed — degrade to allow rather than block traffic

	// Rewrite to the transparent listener, loopback only — this program
	// only ever redirects to a LOCAL listener, never anywhere else.
	ctx->user_ip4 = bpf_htonl(0x7F000001); // 127.0.0.1
	ctx->user_port = bpf_htons(TRANSPARENT_LISTENER_PORT);

	return 1;
}

// Bridges sk_storage (written above) into redirect_targets, keyed by
// the now-known local port, once the redirected connection reaches
// TCP_CONNECT_CB — the same reliable-process-context callback Phase 5
// uses, though this is a SEPARATE loaded program from Phase 5's
// sockops.c, not an extension of it (both attach to the same cgroup
// via BPF_F_ALLOW_MULTI; see ebpf/redirect/loader.go).
SEC("sockops")
int mithril_redirect_sockops(struct bpf_sock_ops *skops) {
	if (skops->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
		return 0;
	if (!skops->sk)
		return 0;

	struct original_dest *orig = bpf_sk_storage_get(&sk_original_dest, skops->sk, NULL, 0);
	if (!orig)
		return 0; // not a redirected connection — nothing to bridge

	u16 local_port = (u16)skops->local_port;
	bpf_map_update_elem(&redirect_targets, &local_port, orig, BPF_ANY);
	bpf_sk_storage_delete(&sk_original_dest, skops->sk);

	return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
