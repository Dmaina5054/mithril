// Package snifilter holds the socket_filter eBPF program (SNI
// extraction + coarse flow classification, spec section 4 eBPF Feature
// 2) and its generated Go bindings. Run `go generate ./...` from proxy/
// after editing snifilter.c — requires clang, bpftool, and readable
// /sys/kernel/btf/vmlinux (none need root to generate/compile).
package snifilter

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb -cc clang mithrilSniFilter snifilter.c -- -I.
