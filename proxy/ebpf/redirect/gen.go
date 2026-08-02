// Package redirect holds the traffic-interception-enforcement eBPF
// programs (spec section 4 eBPF Feature 1, implemented via a
// BPF_CGROUP_INET4_CONNECT hook rather than spec's literal tc+iptables
// mechanism — see redirect.c's top comment for why) and their generated
// Go bindings. Run `go generate ./...` from proxy/ after editing
// redirect.c.
package redirect

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb -cc clang mithrilRedirect redirect.c -- -I.
