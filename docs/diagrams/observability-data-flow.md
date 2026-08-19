# Observability Data Flow

> Generated during: Session A, Phase 1 — Compose + Config Files
> Last updated: 2026-08-02

Shows how metrics move from exporters on Minas Tirith through Prometheus
scraping, into Grafana as a datasource, out to provisioned dashboards,
and how alert rule evaluation feeds Grafana alerting. This is the shape
that every future workload (Gondor, Hermes) plugs into without any new
Prometheus or Grafana instance.

---

```mermaid
flowchart LR
    subgraph exporters["Exporters — host.docker.internal"]
        NE["node_exporter :9100\nworkload=infra"]
        SP["socks5-proxy /metrics :9998\nworkload=kioo-labs"]
        EB["ebpf-exporter :9435\nworkload=infra"]
    end

    subgraph prom["Prometheus :9090 — 127.0.0.1 only"]
        SC["Scrape jobs\n(node, socks5-proxy, ebpf-exporter)"]
        RULES["Alert rules\nconfig/alerts/*.yml"]
        TSDB[("TSDB\n90d retention")]
    end

    subgraph graf["Grafana :3001 — Tailscale-accessible"]
        DS["Prometheus datasource\n(provisioned as-code)"]
        DASH["Dashboards\nKioo Labs / Proxy Network /\nMinas Tirith Infra / eBPF"]
        ALERT["Grafana alerting\n(notifications)"]
    end

    NE -- "15s scrape" --> SC
    SP -- "15s scrape" --> SC
    EB -- "15s scrape" --> SC
    SC --> TSDB
    TSDB --> RULES
    RULES -- "firing alerts" --> ALERT
    TSDB -- "PromQL queries" --> DS
    DS --> DASH
    DS --> ALERT
```

## Notes

- Every scrape target and dashboard panel carries `node=` and
  `workload=` labels — that's the entire separation mechanism for
  multi-tenant data in one Prometheus/Grafana pair.
- Alert rule *evaluation* happens inside Prometheus (`rule_files` in
  `prometheus.yml`); Grafana alerting here refers to how firing alerts
  surface to a human — Grafana reads Prometheus's `ALERTS` series via
  the datasource, it does not duplicate rule evaluation.
- Future nodes (Gondor, Hermes) add a new scrape job under `exporters`
  and, if needed, a new dashboard folder — no new boxes in the
  Prometheus/Grafana tier of this diagram.
