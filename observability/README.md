# mithril-observability

Prometheus + Grafana for Minas Tirith personal infrastructure, run as
Docker Compose services with named volumes. This Compose file is the
single source of truth for the stack. Volumes survive container
recreation and are the migration artifact when this moves to Kubernetes
on Gondor.

One Prometheus, one Grafana. All current and future personal workloads
scrape into this same instance — separation is via `node=` / `workload=`
labels and Grafana folders, not separate deployments.

## First-time setup

```bash
cd /home/dm/Projects/learn/golang/mithril/observability
cp .env.example .env && nano .env   # fill in GRAFANA_PASSWORD, GRAFANA_SECRET_KEY, IPROYAL_API_TOKEN
docker compose up -d
```

Grafana's `GF_SERVER_ROOT_URL` is set to this node's real Tailscale
hostname, `debian.tail0a4eef.ts.net` (the Tailscale device name is
`debian`, not `minas-tirith` — check with `tailscale status` if it
ever changes, e.g. after a reinstall).

## Verify

```bash
docker compose ps
curl http://localhost:9090/-/healthy          # Prometheus
# Grafana: http://debian.tail0a4eef.ts.net:3001
```

## Operations

```bash
# Reload Prometheus config after editing (no restart needed)
curl -X POST http://localhost:9090/-/reload

# View logs
docker compose logs -f prometheus
docker compose logs -f grafana

# Stop without losing data (volumes persist)
docker compose down

# Full wipe including data (destructive — only for reset)
docker compose down -v
```

## Adding a new node's exporter

1. On the new node, install and start `node_exporter` (with `--collector.zfs`
   if the node has a ZFS pool).
2. Add a scrape block to `config/prometheus.yml`, following the commented
   template at the bottom of the file:

   ```yaml
   - job_name: <node>-node
     static_configs:
       - targets: [<node>.tail-xxxx.ts.net:9100]
         labels:
           node: <node>
           workload: <workload>
   ```
3. Reload Prometheus — no restart required:

   ```bash
   curl -X POST http://localhost:9090/-/reload
   ```
4. Add a dashboard under `config/grafana/provisioning/dashboards/Minas Tirith Infra/`
   (copy `node-overview.json`, change the `node=` template filter).

No new Compose file, no new Grafana instance, no new dashboards from
scratch — see `docs/mithril-infra-spec.docx` section 7 for the Gondor
and Hermes examples.

## Layout

```
observability/
├── docker-compose.yml
├── .env.example            # copy to .env, never commit .env
├── config/
│   ├── prometheus.yml
│   ├── alerts/              # *.yml alert rule groups
│   └── grafana/provisioning/
│       ├── datasources/prometheus.yml
│       └── dashboards/
│           ├── dashboards.yml
│           ├── Kioo Labs/
│           ├── Proxy Network/
│           ├── Minas Tirith Infra/
│           └── eBPF/
```

## Notes

- Prometheus binds `127.0.0.1:9090` only — it has no auth by default, so
  it is never exposed on Tailscale. Grafana (`0.0.0.0:3001`, full auth)
  is the only human entry point and reaches Prometheus over the internal
  Docker network.
- `host.docker.internal` does not resolve by default on Linux Docker
  Engine (only Docker Desktop does this natively) — the Prometheus
  service carries an explicit `extra_hosts: host.docker.internal:host-gateway`
  entry so the scrape targets in `config/prometheus.yml` resolve.
