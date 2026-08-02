# mithril

Personal infrastructure layer — Go SOCKS5 proxy, eBPF observability,
and a Prometheus + Grafana monitoring stack.

Built on a Lord of the Rings naming theme. Lightweight, invisible,
stronger than it looks.

---

## Nodes

| Name | Role |
|---|---|
| Dev machine | Where this code is written — `/home/dm/Projects/learn/golang/mithril/` |
| Minas Tirith | Deployment target — clone and run here after local dev |
| Gondor | Future Kubernetes cluster — observability stack migrates here |

---

## What's In Here

### proxy/

Go SOCKS5 consumer proxy. Apps on localhost point at `:1080` (default)
or `:1081` (shire-forge workload). The proxy handles the upstream
connection to IPRoyal, including:

- Credential construction with geo-targeting and session mode per route
- Sub-user isolation — each workload profile has its own IPRoyal
  sub-user and bandwidth allocation
- Sticky vs rotating session management per destination pattern
- Entry node benchmarking — picks the lowest-latency IPRoyal node
  on startup and re-benchmarks every 6 hours
- Bandwidth monitoring via the IPRoyal API, exposed as Prometheus metrics

Runs as a systemd service on the host. Not in Docker — needs direct
access to the network interface for eBPF programs.

### ebpf/

Five eBPF programs loaded by the proxy on startup:

- **tc tproxy** — enforces proxy routing for configured workloads.
  Direct connections from proxy-required processes are redirected
  to `:1080` at the kernel level.
- **socket SNI filter** — extracts TLS SNI from ClientHello packets
  and classifies flows (image upload, API call, telemetry, unknown).
  Results enrich connection log entries.
- **sock_ops bandwidth** — tracks bytes sent/received per process.
  Exposes `iproyal_process_bytes_*` metrics so you can see which
  process consumed your IPRoyal bandwidth.
- **ZFS kprobe** — snapshots concurrent ZFS I/O at connection close.
  Correlates network and disk activity in the same log entry.
- **Go SNI peek** — pure Go fallback SNI extraction from TLS
  ClientHello bytes. No kernel involvement.

Requires Debian kernel 6.12+ with BTF and CO-RE. Uses `cilium/ebpf`
as the Go userspace library.

### observability/

Prometheus and Grafana in Docker Compose. Volume-mounted so data
survives container recreation and translates directly to Kubernetes
PVCs when this stack moves to Gondor.

```
docker compose up -d
```

Prometheus is localhost-only (no auth — never expose it externally).
Grafana is accessible on your Tailscale network at port 3000.

All scrape targets carry `node=` and `workload=` labels. Adding a
new node or workload is one scrape config block — no new Grafana
instance, no new dashboards from scratch. Template variables handle
the filtering.

### deploy/

systemd unit and install script for the proxy binary. Run on the
target node after cloning:

```bash
sudo ./deploy/install.sh
# fill /etc/socks5-proxy/env and profiles.yaml
sudo systemctl start socks5-proxy
```

### docs/

Full architecture specification and Mermaid process/data flow diagrams.
Diagrams are produced during the build alongside the code they describe —
not retrofitted afterward.

---

## Getting Started

### Local Development

```bash
# Clone
git clone https://github.com/Dmaina5054/mithril
cd mithril

# Build the proxy
cd proxy && make build

# Start the observability stack
cd ../observability
cp .env.example .env   # fill in passwords
docker compose up -d

# Verify
curl http://localhost:9090/-/healthy
# Grafana at http://<tailscale-hostname>:3000
```

### Deploying to Minas Tirith

```bash
# On Minas Tirith
git clone https://github.com/Dmaina5054/mithril
cd mithril

# Build
cd proxy && make build

# Install node_exporter with ZFS collector
apt install prometheus-node-exporter
echo 'ARGS="--collector.zfs"' >> /etc/default/prometheus-node-exporter
systemctl restart prometheus-node-exporter

# Start observability stack
cd ../observability
cp .env.example .env   # fill in passwords + Tailscale hostname
docker compose up -d

# Install and start proxy
cd ../deploy
sudo ./install.sh
# fill /etc/socks5-proxy/env and profiles.yaml
sudo systemctl start socks5-proxy
```

---

## Naming

| Thing | Name |
|---|---|
| Project | mithril |
| Git repo | github.com/Dmaina5054/mithril |
| Go module | github.com/dmaina5054/mithril/proxy |
| Image pipeline workload | shire-forge |
| Deploy server | Minas Tirith |
| Future K8s cluster | Gondor |
| Local LLM agent | Hermes (Gandalf persona) |

---

## Observability Stack Migration Path

The Docker Compose setup maps directly to Kubernetes:

| Compose concept | Kubernetes equivalent |
|---|---|
| Named volume | PersistentVolumeClaim |
| Config file mount | ConfigMap |
| .env file | Secret |
| depends_on | readinessProbe |
| ports: 127.0.0.1:9090 | ClusterIP Service |
| ports: 0.0.0.0:3000 | NodePort or Ingress |

When Gondor is ready, migrate the stack there as a CKA learning exercise.
The data in the volumes comes with it.

---

## Architecture

Process flow and data flow diagrams are in `docs/diagrams/`.
Full specification is in `docs/mithril-infra-spec.docx`.
