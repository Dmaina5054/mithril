//go:build ignore

#include "common.h"
#include "bpf_endian.h"
#include "bpf_sockfilter.h"

// CRITICAL: a socket_filter program's return value is how many bytes of
// the packet the kernel delivers to the socket — NOT a pass/fail verdict
// like classic tcpdump filters imply. Returning less than skb->len
// TRUNCATES real application data the proxy needs to relay. Every
// return path in mithril_snifilter below returns skb->len, full stop —
// this program only OBSERVES, it never filters.

#define TLS_HANDSHAKE 0x16
#define TLS_CLIENT_HELLO 0x01
#define TLS_EXT_SNI 0x0000
#define SNI_HOST_NAME 0x00

#define SNI_MAX_LEN 64
#define IMAGE_UPLOAD_THRESHOLD (100 * 1024)
// TLS ClientHello is virtually always the connection's first packet, but
// the actual bulk data an upload sends (what IMAGE_UPLOAD_THRESHOLD is
// trying to catch) only starts flowing AFTER the full handshake
// completes (ClientHello, ServerHello/cert exchange relayed the other
// way, Finished) — several round trips later. A small packet cap here
// would give up and classify as FLOW_UNKNOWN before any bulk data is
// even visible, making the large-burst detection useless in practice.
// 200 packets (~290KB at typical 1460-byte MSS) is a deliberately
// generous window to actually observe a real upload starting. A very
// slow/trickling large upload that takes longer than this to cross
// IMAGE_UPLOAD_THRESHOLD would still be misclassified as UNKNOWN —
// accepted as a limitation, not engineered around further.
#define MAX_PACKETS_BEFORE_CLASSIFY 200
#define MAX_TRACKED_CONNS 65535

// flow_type values — matches spec section 4 eBPF Feature 2 naming.
// FLOW_API_CALL and FLOW_TELEMETRY are defined but NOT assigned by this
// program: distinguishing them needs bidirectional byte counts (this is
// a receive-side-only filter — sock_queue_rcv_skb only sees INBOUND
// data) and/or cross-connection frequency ("New Relic pattern" implies
// observing multiple connections over time), neither of which a single
// per-connection receive-path filter can see. Both would show up as
// FLOW_UNKNOWN here; finer classification is Go-side future work, not
// attempted in-kernel. FLOW_IMAGE_UPLOAD (large single-connection burst)
// IS directly observable and is the only classification implemented.
enum {
	FLOW_UNKNOWN = 0,
	FLOW_IMAGE_UPLOAD = 1,
	FLOW_API_CALL = 2,
	FLOW_TELEMETRY = 3,
};

struct sni_event {
	u64 conn_id; // = the socket cookie; globally unique per socket for its lifetime
	char sni[SNI_MAX_LEN];
	u32 sni_len;
	u8 flow_type;
};

struct conn_track {
	u64 total_bytes;
	u32 packet_count;
	u8 sni_extracted;
	u8 done;
	u32 sni_len;
	char sni[SNI_MAX_LEN]; // persisted here, not just a local var — SNI is
	                        // typically found on packet 1 but we keep
	                        // tracking bytes across many more packets
	                        // afterward (see MAX_PACKETS_BEFORE_CLASSIFY),
	                        // so it must survive across invocations
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
	__type(value, struct sni_event);
} sni_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TRACKED_CONNS);
	__type(key, u64);
	__type(value, struct conn_track);
} conn_tracking SEC(".maps");

// try_parse_sni walks a TLS ClientHello starting at the packet's first
// byte, mirroring internal/proxy/sni.go's parseSNI logic but rewritten
// for the eBPF verifier: every pointer advance is bounds-checked against
// data_end before the byte at that position is read, and all loops have
// a small compile-time-visible upper bound. Returns 1 and fills
// sni_out/*sni_len_out if an SNI hostname was found, 0 otherwise (not
// TLS, truncated, no SNI extension — never treated as an error, just
// "nothing found here"). sni_out must point at a SNI_MAX_LEN buffer.
static __always_inline int try_parse_sni(void *data, void *data_end, char *sni_out, u32 *sni_len_out) {
	u8 *p = data;

	// TLS record header: type(1) version(2) length(2)
	if (p + 5 > (u8 *)data_end)
		return 0;
	if (p[0] != TLS_HANDSHAKE)
		return 0;
	p += 5;

	// Handshake header: type(1) length(3)
	if (p + 4 > (u8 *)data_end)
		return 0;
	if (p[0] != TLS_CLIENT_HELLO)
		return 0;
	p += 4;

	// client_version(2) + random(32)
	if (p + 34 > (u8 *)data_end)
		return 0;
	p += 34;

	// session_id
	if (p + 1 > (u8 *)data_end)
		return 0;
	u32 sid_len = p[0];
	p += 1;
	if (p + sid_len > (u8 *)data_end)
		return 0;
	p += sid_len;

	// cipher_suites
	if (p + 2 > (u8 *)data_end)
		return 0;
	u32 cs_len = ((u32)p[0] << 8) | p[1];
	p += 2;
	if (p + cs_len > (u8 *)data_end)
		return 0;
	p += cs_len;

	// compression_methods
	if (p + 1 > (u8 *)data_end)
		return 0;
	u32 cm_len = p[0];
	p += 1;
	if (p + cm_len > (u8 *)data_end)
		return 0;
	p += cm_len;

	// extensions total length
	if (p + 2 > (u8 *)data_end)
		return 0;
	u32 ext_total_len = ((u32)p[0] << 8) | p[1];
	p += 2;
	u8 *ext_end = p + ext_total_len;
	if (ext_end > (u8 *)data_end)
		ext_end = data_end; // truncated by our packet window — parse what we have

// #pragma unroll: extension list length is bounded by ext_total_len,
// but the verifier needs a compile-time-visible iteration cap, not a
// data-dependent one. 32 covers real-world ClientHellos comfortably
// (a handful of extensions is typical; if a client sends more than 32,
// SNI is virtually always near the front anyway per common client
// implementations, so we'd have found it well before hitting the cap).
#pragma unroll
	for (int i = 0; i < 32; i++) {
		if (p + 4 > ext_end)
			break;

		u32 ext_type = ((u32)p[0] << 8) | p[1];
		u32 ext_len = ((u32)p[2] << 8) | p[3];
		p += 4;

		if (p + ext_len > ext_end)
			break; // truncated mid-extension — stop, don't trust what's left

		if (ext_type == TLS_EXT_SNI) {
			u8 *list = p;
			// server_name_list: list_length(2) + entries{type(1), len(2), name}
			if (list + 2 > ext_end)
				return 0;
			list += 2;

			if (list + 3 > ext_end)
				return 0;
			u8 name_type = list[0];
			u32 name_len = ((u32)list[1] << 8) | list[2];
			list += 3;

			if (list + name_len > ext_end)
				return 0;
			if (name_type != SNI_HOST_NAME)
				return 0;

			u32 copy_len = name_len < SNI_MAX_LEN ? name_len : SNI_MAX_LEN;
// Bounded, verifier-friendly byte copy — no memcpy with a
// data-dependent length allowed here.
#pragma unroll
			for (u32 j = 0; j < SNI_MAX_LEN; j++) {
				if (j >= copy_len)
					break;
				if (list + j >= (u8 *)data_end)
					break;
				sni_out[j] = list[j];
			}
			*sni_len_out = copy_len;
			return 1;
		}

		p += ext_len;
	}

	return 0;
}

SEC("socket")
int mithril_snifilter(struct __sk_buff *skb) {
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	u64 cookie = bpf_get_socket_cookie(skb);
	if (cookie == 0)
		return skb->len; // no socket associated — nothing to track, pass through

	struct conn_track *track = bpf_map_lookup_elem(&conn_tracking, &cookie);
	struct conn_track fresh = {};
	if (!track) {
		bpf_map_update_elem(&conn_tracking, &cookie, &fresh, BPF_NOEXIST);
		track = bpf_map_lookup_elem(&conn_tracking, &cookie);
		if (!track)
			return skb->len; // map full or lost the race — degrade to pass-through, never drop data
	}

	if (track->done)
		return skb->len; // already classified this connection — cheap exit

	track->total_bytes += skb->len;
	track->packet_count += 1;

	// SNI is virtually always found on an early packet (the ClientHello),
	// but we deliberately do NOT finalize/submit yet when found — the
	// bulk data a large upload sends only starts flowing after the full
	// handshake completes, several packets later. Store the SNI and keep
	// tracking bytes; see MAX_PACKETS_BEFORE_CLASSIFY.
	if (!track->sni_extracted) {
		if (try_parse_sni(data, data_end, track->sni, &track->sni_len))
			track->sni_extracted = 1;
	}

	int large_burst = track->total_bytes > IMAGE_UPLOAD_THRESHOLD;
	// Give up and classify with whatever we have once we've inspected
	// enough packets — bounds EVERY connection (TLS or not, SNI found
	// or not, large burst or not) to a finite window of attention,
	// never the whole connection lifetime.
	int give_up = track->packet_count >= MAX_PACKETS_BEFORE_CLASSIFY;

	if (large_burst || give_up) {
		struct sni_event ev = {};
		ev.conn_id = cookie;
		ev.flow_type = large_burst ? FLOW_IMAGE_UPLOAD : FLOW_UNKNOWN;
		ev.sni_len = track->sni_len;
		// Fixed-size copy (compile-time-constant length) rather than a
		// variable-length byte-by-byte loop — clang optimizes the latter
		// into a memcpy() call the BPF backend rejects ("A call to
		// built-in function 'memcpy' is not supported"), confirmed by
		// actually trying it and hitting that exact compile error. Bytes
		// past track->sni_len are guaranteed zero (conn_track starts
		// zero-initialized via `fresh = {}` and try_parse_sni only ever
		// writes up to copy_len), so copying the full fixed buffer is
		// correct, not just convenient.
		__builtin_memcpy(ev.sni, track->sni, SNI_MAX_LEN);

		struct sni_event *reserved = bpf_ringbuf_reserve(&sni_events, sizeof(ev), 0);
		if (reserved) {
			*reserved = ev;
			bpf_ringbuf_submit(reserved, 0);
		}
		track->done = 1;
	}

	return skb->len; // always pass the full packet through — see file header
}

char __license[] SEC("license") = "Dual MIT/GPL";
