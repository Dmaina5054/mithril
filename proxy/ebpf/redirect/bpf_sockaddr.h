/*
 * Full struct bpf_sock_addr, copied verbatim from this host's real
 * kernel BTF (bpftool btf dump file /sys/kernel/btf/vmlinux format c |
 * grep -A20 '^struct bpf_sock_addr {') — NOT a CO-RE-relocated minimal
 * subset.
 *
 * Deliberate choice, not an oversight: bpf_sock_ops (Phase 5) worked
 * fine with a minimal preserve_access_index subset; __sk_buff (Phase
 * 6) did not — CO-RE relocation apparently doesn't apply uniformly
 * across context struct types even when both look like reasonable
 * candidates going in. Rather than gamble on which category
 * bpf_sock_addr falls into, using the full real struct directly here
 * too, the pattern proven to actually work.
 */
#ifndef BPF_SOCKADDR_H
#define BPF_SOCKADDR_H

// Forward-declared, deliberately opaque — bpf_sk_storage_get/set take
// this as a `void *sk` argument and the verifier needs a genuine
// PTR_TO_SOCKET-typed value (not a scalar cast to a pointer, the exact
// class of problem Phase 6 hit repeatedly with __sk_buff). This program
// never dereferences the socket's fields itself, only passes the
// pointer through to the two helpers, so the full struct bpf_sock
// layout is never needed.
struct bpf_sock;

struct bpf_sock_addr {
	__u32 user_family;
	__u32 user_ip4;
	__u32 user_ip6[4];
	__u32 user_port;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 msg_src_ip4;
	__u32 msg_src_ip6[4];
	union {
		struct bpf_sock *sk;
	};
};

#endif
