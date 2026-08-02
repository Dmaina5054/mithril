Project: mithril-proxy v3

Node: Minas Tirith (Debian 6.12.95+deb13-amd64)

Role: SOCKS5 consumer proxy — client of IPRoyal residential proxies

eBPF: cilium/ebpf library, BTF+CO-RE available, kernel 6.12

eBPF programs: tc tproxy enforcement, socket SNI filter, sock_ops bandwidth, kprobe ZFS

Metrics: Prometheus on :9998 (proxy) and :9435 (eBPF exporter)

Observability stack: Docker Compose at /home/dm/Projects/learn/golang/mithril/observability scrapes both ports

Config: /etc/socks5-proxy/env + routing.yaml + profiles.yaml

Ports: :1080 (default), :1081 (kioo-labs), :9998 (/metrics), :9999 (/healthz)

Build: CGO_ENABLED=0 static for Go; eBPF C compiled with clang + bpf2go
