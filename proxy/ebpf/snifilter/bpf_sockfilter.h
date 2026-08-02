/*
 * Full struct __sk_buff, copied verbatim from this host's real UAPI
 * header (/usr/include/linux/bpf.h, linux-libc-dev 6.12.100-1) — NOT a
 * minimal CO-RE-relocated subset like ebpf/sockops/bpf_sockops.h uses
 * for struct bpf_sock_ops.
 *
 * Real correction, confirmed live: a minimal 3-field version of this
 * struct (len/data/data_end only, __attribute__((preserve_access_index)))
 * compiled and loaded fine but was rejected by the kernel verifier at
 * runtime — "invalid bpf_context access off=80" — because CO-RE
 * relocation apparently doesn't apply to __sk_buff field access for
 * BPF_PROG_TYPE_SOCKET_FILTER the way it did for bpf_sock_ops in
 * ebpf/sockops (Phase 5). __sk_buff is specifically an ABI-stable UAPI
 * struct (unlike bpf_sock_ops) — the canonical approach, matching the
 * kernel's own samples/bpf/sockex1_kern.c, is the full real struct with
 * real fixed offsets, not a CO-RE-relocated partial one. `data` is
 * field #16 here (offset ~76-80 depending on padding), nowhere near the
 * offset 4 a minimal 3-field struct implied.
 */
#ifndef BPF_SOCKFILTER_H
#define BPF_SOCKFILTER_H

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;

	/* Accessed by BPF_PROG_TYPE_sk_skb types from here to ... */
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	/* ... here. */

	__u32 data_meta;
	__u64 flow_keys; /* __bpf_md_ptr(struct bpf_flow_keys *, flow_keys) — opaque here, unused */
	__u64 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
	__u64 sk; /* __bpf_md_ptr(struct bpf_sock *, sk) — opaque here, unused */
	__u32 gso_size;
	__u8 tstamp_type;
	__u32 padding_future_use : 24;
	__u64 hwtstamp;
};

#endif
