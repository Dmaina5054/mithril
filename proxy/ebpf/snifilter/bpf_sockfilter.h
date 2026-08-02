/*
 * Minimal __sk_buff mirror — same pattern as
 * ebpf/sockops/bpf_sockops.h. Deliberately only declares the fields
 * this program actually uses (len, data, data_end), each verified
 * against this host's real kernel BTF (bpftool btf dump file
 * /sys/kernel/btf/vmlinux format c | grep -A5 '^struct __sk_buff {'),
 * not assumed from memory or copied wholesale from a struct definition
 * we don't otherwise need. preserve_access_index means CO-RE relocates
 * these fields by name at load time regardless of declared order.
 */
#ifndef BPF_SOCKFILTER_H
#define BPF_SOCKFILTER_H

struct __sk_buff {
	__u32 len;
	__u32 data;     // cast to (void *)(long)data — start of accessible payload
	__u32 data_end; // cast to (void *)(long)data_end — one past the last accessible byte
} __attribute__((preserve_access_index));

#endif
