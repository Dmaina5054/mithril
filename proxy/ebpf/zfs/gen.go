// Package zfs holds the ZFS I/O correlation kprobe (spec section 4,
// eBPF Feature 4) and its generated Go bindings. Run `go generate ./...`
// from proxy/ after editing zfs_kprobe.c — requires clang, bpftool, and
// readable /sys/kernel/btf/vmlinux.
package zfs

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -target bpfel,bpfeb -cc clang mithrilZfs zfs_kprobe.c -- -I.
