# eBPF Kernel/Userspace

> Generated during: Session B, Phase 5 — eBPF: Per-Process Bandwidth (sock_ops)
> Last updated: 2026-08-02

Shows all five eBPF-adjacent programs from spec section 4, their BPF
maps, and how Go userspace reads each one — perf/ring buffers shown
separately from hash maps since they're read completely differently
(blocking epoll wait vs periodic polling). Only Feature 3 (sock_ops) and
Feature 5 (Go SNI peek, no kernel) are built as of this phase; 2, 1, and
4 are marked planned.

---

```mermaid
flowchart TB
    subgraph kernel["Kernel"]
        F3["Feature 3 — sock_ops\n(BUILT, Phase 5)\ncgroup v2 attach\nTCP send/recv byte tracking"]
        F2["Feature 2 — socket_filter\n(PLANNED, Phase 6)\nTLS ClientHello SNI parse"]
        F1["Feature 1 — tc/tproxy\n(PLANNED, Phase 7)\nredirect enforcement"]
        F4["Feature 4 — kprobe\n(PLANNED, Phase 8)\nzfs_read/zfs_write"]
    end

    subgraph maps["BPF Maps"]
        M_ESTAB["established_sockets\nHASH, per-socket 4-tuple\n(internal bookkeeping only)"]
        M_PROC["process_bytes\nHASH, key={pid,comm}\nvalue={bytes_sent,bytes_recv}"]
        M_PIDS["proxy_required_pids\nHASH (planned)"]
        RB_SNI["perf ring buffer (planned)\n{conn_id, sni, flow_type}"]
        M_ZFS["zfs_io_snapshot\nARRAY, 1 entry (planned)"]
    end

    F3 --> M_ESTAB
    F3 --> M_PROC
    F1 -.-> M_PIDS
    F2 -.-> RB_SNI
    F4 -.-> M_ZFS

    subgraph userspace["Go Userspace (mithril-proxy)"]
        READER["sockops.Tracker.ReadProcessBytes()\n5s ticker poll (BUILT)"]
        EXPORT["internal/metrics.RunEBPFExporter\nCounterVec delta tracking (BUILT)"]
        SNIGO["internal/proxy.PeekSNI\npure Go, no kernel (BUILT, Phase 4)\ncomplements Feature 2"]
        RBREAD["ring buffer reader (planned)\nblocking epoll, 1 goroutine"]
        ZFSREAD["snapshot reader (planned)\nper-connection-close"]
    end

    M_PROC -->|"poll every 5s"| READER
    READER --> EXPORT
    EXPORT -->|"/metrics :9435"| PROM["Prometheus\nebpf-exporter job"]

    RB_SNI -.->|"blocking epoll wait"| RBREAD
    M_ZFS -.->|"read at connection close"| ZFSREAD

    SNIGO -.->|"enriches connection log\nindependent of kernel path"| LOG["proxy connection log"]
```

## Notes

- **Hash maps vs ring/perf buffers, read differently**: `process_bytes` is
  polled on a 5s ticker (`sockops.Tracker.ReadProcessBytes` →
  `internal/metrics.RunEBPFExporter`) — cheap, bounded, no blocking. The
  planned SNI ring buffer (Feature 2) is read via a single goroutine
  blocking on epoll, woken only when new events arrive — no polling
  overhead, per spec's own resource-cost note.
- `established_sockets` is **not** read by Go at all — it's purely
  kernel-internal bookkeeping the eBPF program uses to correlate later
  callbacks (RTT_CB, STATE_CB) back to the PID/comm captured at
  connect/accept time. Only `process_bytes` crosses into userspace.
- **Known unresolved uncertainty, not glossed over**: PID/comm capture
  for *passive* (inbound/accepted) connections happens at
  `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`, which may not run in the
  accepting process's context (a kernel/softirq event, not a syscall).
  Outbound connections (`BPF_SOCK_OPS_TCP_CONNECT_CB`, fires inside the
  `connect()` syscall) are reliable; inbound-heavy processes like
  `node_exporter` (which is scraped, not scraping) may show wrong or
  missing PIDs until this is verified against a real kernel. Documented
  in `ebpf/sockops/sockops.c`.
- `internal/proxy.PeekSNI` (Phase 4) is drawn as independent of the
  kernel eBPF path deliberately — it's a pure-Go fallback, not something
  Feature 2 depends on or feeds into.
- Feature 5 in spec section 4 numbering *is* the Go SNI peek — this
  diagram's title says "all five eBPF programs" per CLAUDE.md's diagram
  table wording, but Feature 5 itself has no kernel component to draw in
  the `kernel` subgraph, which is why it only appears in `userspace`.
