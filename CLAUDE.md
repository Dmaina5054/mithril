# MITHRIL — Claude Code Context

**Project:** mithril  
**Repo:** github.com/Dmaina5054/mithril  
**Dev root:** /home/dm/Projects/learn/golang/mithril/  
**Deploy target:** Minas Tirith (server — clone and run there after local dev)  
**Gatekeeper:** Gandalf (Hermes) — reads Obsidian build ledger, gates every phase  

---

## What This Project Is

Personal infrastructure stack — not Konnect, not work-related.

- **Go SOCKS5 proxy** — consumer client of IPRoyal residential proxies.
  Apps on the dev machine point at localhost:1080 or :1081. The proxy
  handles upstream auth, geo-targeting, session management, sub-user
  isolation, and bandwidth monitoring via the IPRoyal API.

- **eBPF programs** — kernel-level traffic enforcement (tc/tproxy),
  TLS SNI extraction (socket filter), per-process bandwidth accounting
  (sock_ops), ZFS I/O correlation (kprobe). Run on Debian 6.12.95 — BTF
  and CO-RE are available. cilium/ebpf is the Go userspace library.

- **Observability stack** — Prometheus + Grafana in Docker Compose,
  volume-mounted. Prometheus is localhost-only. Grafana is Tailscale-
  accessible on port 3001 (moved off 3000 — that port belongs to the
  Hermes WhatsApp bridge). All scrape targets carry node= and workload=
  labels. Future nodes (Gondor, Hermes) add a scrape config block —
  no new Grafana instance, no new dashboards from scratch.

---

## Project Structure

```
mithril/
├── proxy/              # Go module: github.com/dmaina5054/mithril/proxy
│   ├── internal/
│   │   ├── proxy/      # SOCKS5 handler, auth, session store, router
│   │   ├── iproyal/    # IPRoyal API client
│   │   ├── metrics/    # Prometheus exposition
│   │   └── health/     # /healthz endpoint
│   ├── config/         # Config loading + routing.yaml + profiles.yaml
│   └── main.go
├── ebpf/               # eBPF C programs + Go loaders (bpf2go)
├── observability/      # Docker Compose + all Prometheus/Grafana config
│   └── config/
│       ├── prometheus.yml
│       ├── alerts/
│       └── grafana/provisioning/
├── deploy/             # systemd units + install.sh
├── docs/
│   ├── mithril-infra-spec.docx   # full spec — read this for architecture
│   └── diagrams/                 # Mermaid diagrams — produced during build
│       ├── proxy-request-flow.md
│       ├── ebpf-enforcement-flow.md
│       ├── subuser-routing.md
│       ├── observability-data-flow.md
│       ├── iproyal-api-integration.md
│       ├── ebpf-kernel-userspace.md
│       ├── docker-compose-network.md
│       └── git-workflow.md
├── CLAUDE.md           # this file
└── README.md
```

---

## Naming — Hard Rules

These are enforced by Gandalf. Violations block the phase.

| Wrong | Correct |
|---|---|
| kf_image_service | shire-forge |
| go-socks5-proxy | mithril/proxy |
| palantir | mithril |
| ~/observability | /home/dm/Projects/learn/golang/mithril/observability |
| Prometheus on 0.0.0.0 | 127.0.0.1 only |

---

## Port Registry

| Port | Bind | Service |
|---|---|---|
| 3000 | 0.0.0.0 | Hermes WhatsApp bridge — **not** Mithril, do not reuse |
| 3001 | 0.0.0.0 | Grafana (Tailscale) — moved from 3000, Hermes conflict, gated Session A Phase 4 |
| 9090 | 127.0.0.1 | Prometheus |
| 9100 | 0.0.0.0 | node_exporter — opened beyond localhost so the Prometheus container can reach it via host-gateway, gated Session A Phase 4 |
| 1080 | 127.0.0.1 | socks5-proxy default |
| 1081 | 127.0.0.1 | socks5-proxy shire-forge |
| 9435 | 127.0.0.1 | ebpf-exporter |
| 9998 | 127.0.0.1 | socks5-proxy /metrics |
| 9999 | 127.0.0.1 | socks5-proxy /healthz |

Any port not in this table requires Gandalf's approval before opening.

---

## Reference Documents

Full architecture, gate criteria, naming registry, and feature specs are in:

```
docs/mithril-infra-spec.docx
```

Read this when you need:
- Architecture detail on any component
- Gate criteria for the current phase
- IPRoyal API endpoint specifications
- eBPF program designs and resource costs
- Docker Compose configuration patterns
- Kubernetes migration notes (for future Gondor work)

---

## Diagrams — Required Build Deliverables

Diagrams are **not optional**. Each is a named phase deliverable.
All diagrams are Mermaid, saved as `.md` files in `docs/diagrams/`.
They render on GitHub without any tooling.

Produce each diagram in the phase where the component is built —
not at the end of the build.

| Diagram file | Produced in phase | What it shows |
|---|---|---|
| `proxy-request-flow.md` | Session B Phase 2 | App → proxy → session router → IPRoyal → exit node → target. Include auth, geo prefix, session ID in the flow. |
| `subuser-routing.md` | Session B Phase 3 | Inbound port → profile lookup → credential construction → upstream. Show both shire-forge (:1081) and default (:1080) paths. |
| `iproyal-api-integration.md` | Session B Phase 1 | Proxy ↔ resi-api.iproyal.com. Show all 4 endpoints used (/me, /entry-nodes, /residential-subusers, /access/countries), what data flows in each direction, and polling intervals. |
| `ebpf-enforcement-flow.md` | Session B Phase 7 | Outbound packet → tc hook → BPF map check (is PID proxy-required?) → redirect to :1080 or pass. Include the proxy process exclusion path. |
| `ebpf-kernel-userspace.md` | Session B Phase 5 | All five eBPF programs → their BPF maps → Go readers → Prometheus metrics. Show perf ring buffers separately from hash maps. |
| `observability-data-flow.md` | Session A Phase 1 | All exporters (node_exporter, socks5-proxy /metrics, ebpf-exporter) → Prometheus scrape → Grafana datasource → dashboards → alert rules → Grafana alerting. |
| `docker-compose-network.md` | Session A Phase 1 | Docker Compose internal network topology. Prometheus container → host.docker.internal exporters. Grafana → Prometheus on internal network. Volume mounts. |
| `git-workflow.md` | Session A Phase 1 | Dev machine → git push → github.com/Dmaina5054/mithril → git pull → Minas Tirith. Show where .env lives (never in git), where CLAUDE.md travels (in git), where systemd units land. |

### Diagram Format

Every diagram file follows this structure:

```markdown
# [Diagram Title]

> Generated during: Session [A|B], Phase [N] — [phase name]  
> Last updated: [date]

[brief one-paragraph description of what this diagram shows and why it exists]

---

\`\`\`mermaid
[diagram code]
\`\`\`

## Notes

[Any caveats, simplifications, or things the diagram doesn't show]
```

---

## Build Sessions

Two ACP sessions. Session A first.

**Session A — Observability Stack**
Phases 1-4: Docker Compose, alert rules, dashboard JSON, smoke test.

**Session B — Proxy + eBPF**
Phases 0-10: Scaffold, IPRoyal client, SOCKS5 core, router, SNI peek,
eBPF bandwidth, eBPF SNI filter, tc enforcement, ZFS correlation,
Prometheus metrics wiring, systemd unit.

Full phase detail and gate criteria are in `docs/mithril-infra-spec.docx`.

---

## Resume Instructions

If this session is resuming mid-build:
1. Gandalf will provide a handoff block with the current ledger state
2. Do not redo completed phases
3. Start exactly from the phase Gandalf names
4. Read the handoff block fully before writing any code
