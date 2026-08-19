# Proxy Request Flow — System Overview

> Originally planned as: Session B, Phase 2 deliverable per `CLAUDE.md`'s
> diagram table ("App → proxy → session router → IPRoyal → exit node →
> target"). Never actually produced at the time — of the 8 diagrams
> `CLAUDE.md` requires, this was the one missing. Filled in now,
> scoped to how the codebase actually works today rather than Phase
> 2's snapshot: the direct IPRoyal coupling that phase described was
> replaced by the `internal/vpnprovider` plugin layer (see
> `provider-plugin-architecture.md`) before this diagram was written.
> Last updated: 2026-08-19.

Shows how every major part of this codebase actually connects, in one
place: config loading, the SOCKS5 core, the pluggable provider layer,
the eBPF subsystems (bandwidth, SNI, redirect-enforcement, ZFS
correlation), and where observability plugs in. Each subsystem here
has its own more detailed diagram already — this one is the map that
shows how they fit together, not a replacement for any of them; see
the Notes section for where to go for depth on any one box.

---

```mermaid
flowchart TD
    subgraph clients["Clients"]
        APPDEFAULT["App using the\ndefault profile"]
        APPWORKLOAD["App using the\nkioo-labs / other profile"]
        REDIRECTPROC["Any other local process\n(no SOCKS5 awareness —\nonly if profiles.yaml lists\nits PID under enforce_pids)"]
    end

    subgraph config["Config — /etc/socks5-proxy/"]
        PROFILES["profiles.yaml\nprovider, provider_config,\nlisten_port, enforce_pids"]
        ROUTING["routing.yaml\npattern -> country/session rules"]
        ENVFILE["env\nMITHRIL_UPSTREAM_ADDR,\nconfig file paths"]
    end

    subgraph startup["main.go — startup, once per process"]
        LOADCFG["Load routing.yaml + profiles.yaml"]
        BUILDPROV["buildProvider(profile)\nfor every profile"]
        STARTEBPF["startEBPF / startSNIFilter /\nstartZFSKprobe /\nstartRedirectEnforcement\n(each non-fatal on failure)"]
        STARTOBS["startHealthz / startProxyMetrics"]
    end

    subgraph registry["internal/vpnprovider — plugin registry"]
        BLANKIMPORT["main.go blank-imports:\niproyal, socks5, brightdata\n(each Register()s at init())"]
        PROVIF["Provider interface\nName() / Dial(ctx, host, port, RouteOptions)"]
    end

    subgraph listeners["Per-profile SOCKS5 listeners (127.0.0.1)"]
        L1080[":1080 default"]
        L1081[":1081 kioo-labs"]
        LDOTS[":108N ... one per profile"]
    end

    subgraph socks5core["internal/proxy — SOCKS5 core (provider-agnostic)"]
        HANDLE["Handle()\nRFC1928 server handshake"]
        ROUTERDIAL["Router.Dial()\nmatch routing.yaml -> RouteOptions\n(+ sticky session store)"]
        SNIPEEK["PeekSNI\n(pure-Go fallback, Feature 5)"]
        RELAY["Relay()\nbidirectional copy until close"]
    end

    subgraph transparentpath["Transparent path (eBPF Feature 1)"]
        TLISTEN["127.0.0.1:19001\ntransparent listener"]
        HANDLETRANS["HandleTransparent()\nno SOCKS5 handshake —\ntarget already recovered"]
    end

    subgraph ebpf["eBPF programs (root/CAP_BPF — non-fatal if unavailable)"]
        SOCKOPS["sock_ops\nper-process bandwidth"]
        SNIFILTER["socket_filter\nSNI extraction +\nflow classification"]
        REDIRECT["connect4 + sockops bridge\ntraffic-redirect enforcement"]
        ZFSKPROBE["zfs_read/write kprobes\nI/O correlation"]
    end

    subgraph providers["Provider implementations"]
        IPROYALP["iproyal\ntargeting in the PASSWORD suffix"]
        BRIGHTP["brightdata\ntargeting in the USERNAME suffix,\nfixed host, port>1024 rule"]
        SOCKSP["socks5\nno targeting at all"]
    end

    subgraph upstreams["Upstream vendors"]
        IPROYALU["IPRoyal entry node\n(SOCKS5, host:port from config)"]
        BRIGHTU["brd.superproxy.io:22228\n(SOCKS5, fixed)"]
        OTHERU["Any other SOCKS5 upstream\n(Tor, self-hosted, ...)"]
    end

    DEST["Real destination\n(e.g. api.example.com:443)"]

    subgraph obs["Observability endpoints"]
        HEALTHZ[":9999 /healthz"]
        PMETRICS[":9998 /metrics\nproxy_connection_errors_total"]
        EMETRICS[":9435 /metrics\niproyal_process_bytes_*"]
    end

    PROMSTACK["Prometheus :9090 -> Grafana :3001\n(see observability-data-flow.md)"]

    %% --- startup wiring ---
    PROFILES --> LOADCFG
    ROUTING --> LOADCFG
    ENVFILE --> LOADCFG
    LOADCFG --> BUILDPROV
    BLANKIMPORT -.registers at init, before main runs.-> PROVIF
    BUILDPROV -->|vpnprovider.New(name, config)| PROVIF
    BUILDPROV --> L1080
    BUILDPROV --> L1081
    BUILDPROV --> LDOTS
    LOADCFG --> STARTEBPF
    LOADCFG --> STARTOBS
    STARTEBPF --> SOCKOPS
    STARTEBPF --> SNIFILTER
    STARTEBPF --> REDIRECT
    STARTEBPF --> ZFSKPROBE
    STARTOBS --> HEALTHZ
    STARTOBS --> PMETRICS

    %% --- SOCKS5 request path ---
    APPDEFAULT --> L1080
    APPWORKLOAD --> L1081
    L1080 --> HANDLE
    L1081 --> HANDLE
    LDOTS --> HANDLE
    HANDLE --> ROUTERDIAL
    ROUTERDIAL -->|RouteOptions| PROVIF
    PROVIF -.implemented by.-> IPROYALP
    PROVIF -.implemented by.-> BRIGHTP
    PROVIF -.implemented by.-> SOCKSP
    IPROYALP --> IPROYALU
    BRIGHTP --> BRIGHTU
    SOCKSP --> OTHERU
    IPROYALU --> DEST
    BRIGHTU --> DEST
    OTHERU --> DEST
    HANDLE --> SNIPEEK
    HANDLE -->|attach eBPF filter to conn| SNIFILTER
    HANDLE -->|read snapshot at close| ZFSKPROBE
    HANDLE --> RELAY
    RELAY -->|bidirectional copy| DEST
    HANDLE -.on handshake/dial/reply failure.-> PMETRICS

    %% --- transparent path ---
    REDIRECTPROC -->|connect() intercepted\nby connect4 hook| REDIRECT
    REDIRECT -->|rewrite dest to| TLISTEN
    TLISTEN --> HANDLETRANS
    HANDLETRANS --> ROUTERDIAL

    %% --- observability ---
    SOCKOPS --> EMETRICS
    PMETRICS -->|scraped| PROMSTACK
    EMETRICS -->|scraped| PROMSTACK
```

## Notes

- **This is the map, not the territory.** Every subgraph here has its
  own dedicated diagram with the actual detail:
  - `provider-plugin-architecture.md` — the `Provider` interface,
    registry, and what each provider implementation actually does
    differently (`iproyal`'s password suffix vs. `brightdata`'s
    username suffix vs. `socks5`'s "ignore everything").
  - `subuser-routing.md` — the inbound-port → profile → credential
    path in more depth (predates the plugin layer's `Provider`
    abstraction; still accurate for the shape of the routing decision
    itself, just written before `Router` delegated the actual dial).
  - `iproyal-api-integration.md` — `internal/iproyal.Client`'s REST
    calls (`/me`, `/access/entry-nodes`, `/residential-subusers`,
    `/access/countries`). Notably **not** part of this flow diagram at
    all: that client isn't wired into the hot path for any provider,
    `iproyal` included — it's only ever invoked manually via
    `cmd/apismoke`.
  - `ebpf-enforcement-flow.md` and `ebpf-kernel-userspace.md` — the
    eBPF subgraph's internals: BPF maps, the connect4/sockops bridge,
    ring buffers vs. hash maps.
  - `observability-data-flow.md` and `docker-compose-network.md` —
    what's behind the single `PROMSTACK` box here.
- **Two independent entry paths converge on the same `Router.Dial`.**
  A normal SOCKS5 client (`Handle`) and an eBPF-redirected process
  that never spoke SOCKS5 at all (`HandleTransparent`) both end up
  calling the exact same `Router`/`Provider` pipeline — this is
  deliberate (see `internal/proxy/handler.go`'s doc comments): nothing
  about credential construction or provider selection duplicates
  between the two paths.
- **Nothing in the eBPF subgraph is fatal if it fails to load.** Every
  arrow out of `startEBPF`'s four functions degrades gracefully — no
  root/CAP_BPF, wrong kernel, ZFS not loaded, all just mean that one
  feature's box in this diagram doesn't light up; the SOCKS5 core
  keeps running regardless. None of these four have been run with real
  privileges in any session that's touched this repo, including the
  one that added the provider plugin layer — "compiles clean, logic
  unit-tested, kernel behavior asserted but NOT LIVE-VERIFIED" per
  their own source comments, with one exception:
  `docs/diagrams/ebpf-enforcement-flow.md`'s own notes describe a live
  run against real traffic for the redirect-enforcement feature
  specifically.
- **`proxy_connection_errors_total` is the newest addition to this
  picture** (wired up alongside `/healthz` and `/metrics` in a recent
  session) — before that, `Handle`/`HandleTransparent` failures were
  only ever logged, never counted, and nothing listened on `:9998` or
  `:9999` at all despite both being documented in `CLAUDE.md`'s port
  registry since early on.
- **`/healthz` (:9999) is not scraped by Prometheus** —
  `observability/config/prometheus.yml` has scrape jobs for `node`,
  `socks5-proxy` (`:9998`), and `ebpf-exporter` (`:9435`) only; `/metrics`
  is checked by Prometheus scraping, `/healthz` isn't wired into
  anything today (it exists as a plain liveness endpoint, e.g. for a
  future load balancer or manual `curl` check).
- This diagram deliberately omits `deploy/` (systemd unit + install
  script) and `docs/diagrams/git-workflow.md`'s dev-machine → Minas
  Tirith path — those are about getting this process running on a
  host, not about what happens once it's running.
