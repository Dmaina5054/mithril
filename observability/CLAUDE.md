Project: mithril-observability

Stack: Prometheus + Grafana via Docker Compose

Prometheus: localhost-only (:9090), 90d retention

Grafana: Tailscale-accessible (:3000), provisioned as-code

Auth: GF_SECURITY_ADMIN_USER=daniel, password from .env

Scrape targets: node_exporter :9100, socks5-proxy :9998, ebpf-exporter :9435

Label taxonomy: node=minas-tirith, workload=(infra|kioo-labs|hermes|cka-lab)

Volumes: prometheus_data, grafana_data (named, explicit)
