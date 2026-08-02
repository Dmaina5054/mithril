// Package sockops holds the sock_ops eBPF program (per-process bandwidth
// accounting, spec section 4 eBPF Feature 3) and its generated Go
// bindings. Run `go generate ./...` from proxy/ after editing sockops.c
// — requires clang, bpftool, and readable /sys/kernel/btf/vmlinux (none
// of which need root to just generate/compile).
package sockops

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb -cc clang mithrilSockops sockops.c -- -I.
