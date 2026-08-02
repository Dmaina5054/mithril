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
// byte, mirroring internal/proxy/sni.go's parseSNI logic. Rewritten a
// second time for this file: the original used direct pointer access
// (skb->data/data_end cast to a pointer, walked with bounds checks
// against data_end) — confirmed by live verifier testing to be
// rejected entirely for a socket_filter attached to a connected TCP
// socket on this kernel (6.12.95+deb13): "invalid bpf_context access
// off=76 size=4" for skb->data itself, not just data_end. Direct
// packet access (the data/data_end mechanism) appears unavailable for
// this specific attachment style, even though it's a fundamental,
// widely-used eBPF feature elsewhere (including for the SAME program
// type attached to AF_PACKET sockets, per samples/bpf/sockex1_kern.c).
//
// This version reads via bpf_skb_load_bytes(skb, offset, buf, len)
// instead — an offset/cursor-based helper that does its own bounds
// checking against skb->len internally (returns < 0 if offset+len
// exceeds it), rather than pointer arithmetic the verifier statically
// proves. No data/data_end access anywhere in this function.
//
// Returns 1 and fills sni_out/*sni_len_out if an SNI hostname was
// found, 0 otherwise (not TLS, truncated, no SNI extension, or a load
// failed — never treated as a hard error, just "nothing found here").
// sni_out must point at a SNI_MAX_LEN buffer.
static __always_inline int try_parse_sni(struct __sk_buff *skb, char *sni_out, u32 *sni_len_out) {
	u32 off = 0;

	// TLS record header: type(1) version(2) length(2) — only need byte 0
	u8 rec_type;
	if (bpf_skb_load_bytes(skb, off, &rec_type, 1) < 0)
		return 0;
	if (rec_type != TLS_HANDSHAKE)
		return 0;
	off += 5;

	// Handshake header: type(1) length(3) — only need byte 0
	u8 hs_type;
	if (bpf_skb_load_bytes(skb, off, &hs_type, 1) < 0)
		return 0;
	if (hs_type != TLS_CLIENT_HELLO)
		return 0;
	off += 4;

	// client_version(2) + random(32) — contents unused, skip over
	off += 34;

	// session_id: length(1) + bytes
	u8 sid_len;
	if (bpf_skb_load_bytes(skb, off, &sid_len, 1) < 0)
		return 0;
	off += 1 + sid_len;

	// cipher_suites: length(2) + bytes
	u8 cs_len_buf[2];
	if (bpf_skb_load_bytes(skb, off, cs_len_buf, sizeof(cs_len_buf)) < 0)
		return 0;
	u32 cs_len = ((u32)cs_len_buf[0] << 8) | cs_len_buf[1];
	off += 2 + cs_len;

	// compression_methods: length(1) + bytes
	u8 cm_len;
	if (bpf_skb_load_bytes(skb, off, &cm_len, 1) < 0)
		return 0;
	off += 1 + cm_len;

	// extensions total length(2)
	u8 ext_total_buf[2];
	if (bpf_skb_load_bytes(skb, off, ext_total_buf, sizeof(ext_total_buf)) < 0)
		return 0;
	u32 ext_total_len = ((u32)ext_total_buf[0] << 8) | ext_total_buf[1];
	off += 2;
	u32 ext_end = off + ext_total_len; // bpf_skb_load_bytes bounds-checks against
	                                    // the real skb->len itself on every read
	                                    // below — no separate data_end comparison needed.

// #pragma unroll: extension count is bounded by ext_total_len, but the
// verifier needs a compile-time-visible iteration cap. 32 covers
// real-world ClientHellos comfortably — see the original version's
// comment (unchanged reasoning, just re-implemented).
#pragma unroll
	for (int i = 0; i < 32; i++) {
		if (off + 4 > ext_end)
			break;

		u8 ext_hdr[4];
		if (bpf_skb_load_bytes(skb, off, ext_hdr, sizeof(ext_hdr)) < 0)
			break;
		u32 ext_type = ((u32)ext_hdr[0] << 8) | ext_hdr[1];
		u32 ext_len = ((u32)ext_hdr[2] << 8) | ext_hdr[3];
		off += 4;

		if (off + ext_len > ext_end)
			break; // truncated mid-extension — stop, don't trust what's left

		if (ext_type == TLS_EXT_SNI) {
			// server_name_list: list_length(2) + entries{type(1), len(2), name}
			u32 list_off = off + 2; // skip list_length — server_name_list is
			                          // basically always exactly one entry

			u8 entry_hdr[3];
			if (bpf_skb_load_bytes(skb, list_off, entry_hdr, sizeof(entry_hdr)) < 0)
				return 0;
			u8 name_type = entry_hdr[0];
			u32 name_len = ((u32)entry_hdr[1] << 8) | entry_hdr[2];
			list_off += 3;

			if (name_type != SNI_HOST_NAME)
				return 0;

			u32 copy_len = name_len < SNI_MAX_LEN ? name_len : SNI_MAX_LEN;
			// bpf_skb_load_bytes rejects a provably-zero-length read at
			// verify time (confirmed live: "R4 invalid zero-sized read:
			// u64=[0,63]") — copy_len's tracked range includes 0 since
			// name_len could legitimately be 0 (a malformed/empty SNI
			// hostname). An empty hostname isn't a meaningful SNI value
			// anyway, so treat it the same as "not found" rather than
			// special-casing a zero-length load.
			if (copy_len == 0)
				return 0;
			if (bpf_skb_load_bytes(skb, list_off, sni_out, copy_len) < 0)
				return 0;
			*sni_len_out = copy_len;
			return 1;
		}

		off += ext_len;
	}

	return 0;
}

SEC("socket")
int mithril_snifilter(struct __sk_buff *skb) {
	// No skb->data/data_end anywhere in this file — per Gandalf's live
	// verifier testing on this kernel (6.12.95+deb13), direct packet
	// access is rejected entirely for a socket_filter attached to a
	// connected TCP socket ("invalid bpf_context access off=76 size=4"
	// for skb->data itself, after data_end alone was already rejected
	// at offset 80). try_parse_sni below uses bpf_skb_load_bytes
	// instead, which does its own bounds checking against skb->len.

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
		if (try_parse_sni(skb, track->sni, &track->sni_len))
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
