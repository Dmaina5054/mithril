# Docker Compose Network

> Generated during: Session A, Phase 1 — Compose + Config Files
> Last updated: 2026-08-02

Shows the internal Docker Compose network topology for the observability
stack: how the two containers reach each other, how Prometheus reaches
host-level exporters that are not in Docker, and which volumes and
config files are mounted where.

---

```mermaid
flowchart TB
    subgraph host["Minas Tirith host"]
        NE["node_exporter :9100"]
        SP["socks5-proxy :9998\n(systemd, not Docker)"]
        EB["ebpf-exporter :9435"]

        subgraph compose["docker compose — network: observability"]
            PROM["prometheus\n0.0.0.0:9090 in container\npublished 127.0.0.1:9090"]
            GRAF["grafana\n0.0.0.0:3000 in container\npublished 0.0.0.0:3000"]

            PROM -- "extra_hosts:\nhost.docker.internal → host-gateway" --> NE
            PROM --> SP
            PROM --> EB
            GRAF -- "http://prometheus:9090\n(internal DNS)" --> PROM
        end

        VOLP[("volume: prometheus_data")]
        VOLG[("volume: grafana_data")]
        CFGP["./config/prometheus.yml :ro"]
        CFGA["./config/alerts/ :ro"]
        CFGG["./config/grafana/provisioning :ro"]

        PROM --- VOLP
        PROM --- CFGP
        PROM --- CFGA
        GRAF --- VOLG
        GRAF --- CFGG
    end

    TS["Tailscale network"] -- ":3000 only" --> GRAF
```

## Notes

- Prometheus is published as `127.0.0.1:9090` — reachable from the host
  for local `curl`/debugging, never from Tailscale or the LAN.
- Grafana is published as `0.0.0.0:3000` and is the only container
  exposed beyond localhost; Tailscale ACLs (not shown) are what actually
  restrict who on the tailnet can reach it.
- `host.docker.internal` requires the explicit `extra_hosts:
  host.docker.internal:host-gateway` entry on the `prometheus` service
  because this is Linux Docker Engine, not Docker Desktop — without it
  the three host-level exporter scrapes would fail DNS resolution.
- `socks5-proxy` runs as a systemd unit directly on the host (it needs
  raw network/eBPF map access), not as a Compose service — it is only
  reachable *from* the compose network, never a member of it.
