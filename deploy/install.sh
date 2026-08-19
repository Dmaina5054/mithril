#!/usr/bin/env bash
# deploy/install.sh
# Installs the mithril-proxy binary + systemd unit on Minas Tirith.
#
# Run from the repo root or from deploy/, after `cd proxy && make build`:
#   sudo ./deploy/install.sh
#
# Idempotent: safe to re-run after a rebuild to pick up a new binary —
# existing config under /etc/socks5-proxy is never overwritten.
#
# Does NOT start the service: profiles.yaml and the env file need real
# provider credentials filled in first. See README.md's "Deploying to
# Minas Tirith" section for the full sequence this fits into.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "deploy/install.sh: must run as root (sudo ./install.sh) — installs a systemd unit and a binary under /usr/local/bin" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

BINARY_SRC="$REPO_ROOT/proxy/bin/mithril-proxy"
BINARY_DST="/usr/local/bin/mithril-proxy"
CONFIG_DIR="/etc/socks5-proxy"
UNIT_SRC="$SCRIPT_DIR/socks5-proxy.service"
UNIT_DST="/etc/systemd/system/socks5-proxy.service"

if [ ! -x "$BINARY_SRC" ]; then
    echo "deploy/install.sh: $BINARY_SRC not found or not executable — run 'cd proxy && make build' first" >&2
    exit 1
fi

echo "→ Installing binary to $BINARY_DST"
install -m 0755 "$BINARY_SRC" "$BINARY_DST"

echo "→ Creating $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"

# Seed config templates only if not already present — a re-run (e.g.
# after `make build` picks up a new binary) must never clobber an
# operator's real routing.yaml/profiles.yaml/env.
if [ ! -f "$CONFIG_DIR/routing.yaml" ]; then
    echo "→ Seeding $CONFIG_DIR/routing.yaml from proxy/config/routing.yaml"
    install -m 0644 "$REPO_ROOT/proxy/config/routing.yaml" "$CONFIG_DIR/routing.yaml"
else
    echo "→ $CONFIG_DIR/routing.yaml already exists, leaving it alone"
fi

if [ ! -f "$CONFIG_DIR/profiles.yaml" ]; then
    echo "→ Seeding $CONFIG_DIR/profiles.yaml from proxy/config/profiles.yaml.example"
    echo "  *** fill in real provider credentials before starting the service ***"
    install -m 0600 "$REPO_ROOT/proxy/config/profiles.yaml.example" "$CONFIG_DIR/profiles.yaml"
else
    echo "→ $CONFIG_DIR/profiles.yaml already exists, leaving it alone"
fi

if [ ! -f "$CONFIG_DIR/env" ]; then
    echo "→ Writing $CONFIG_DIR/env template"
    cat > "$CONFIG_DIR/env" <<'ENVEOF'
# /etc/socks5-proxy/env — loaded by the socks5-proxy systemd unit via
# EnvironmentFile=. Fill in real values; this file is not tracked in git.

# A fixed upstream host:port (e.g. an IPRoyal entry node) — required
# unless every profile in profiles.yaml sets its own provider_config's
# upstream_addr. See proxy/internal/vpnprovider/iproyal's Config doc
# comment and proxy/config/profiles.yaml.example.
MITHRIL_UPSTREAM_ADDR=

MITHRIL_ROUTING_CONFIG=/etc/socks5-proxy/routing.yaml
MITHRIL_PROFILES_CONFIG=/etc/socks5-proxy/profiles.yaml
ENVEOF
    chmod 0600 "$CONFIG_DIR/env"
else
    echo "→ $CONFIG_DIR/env already exists, leaving it alone"
fi

echo "→ Installing systemd unit to $UNIT_DST"
install -m 0644 "$UNIT_SRC" "$UNIT_DST"

echo "→ systemctl daemon-reload"
systemctl daemon-reload

echo "→ Enabling socks5-proxy (not starting — fill in config first)"
systemctl enable socks5-proxy

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ mithril-proxy installed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Next steps:"
echo "  1. Edit $CONFIG_DIR/env             (set MITHRIL_UPSTREAM_ADDR, if needed)"
echo "  2. Edit $CONFIG_DIR/profiles.yaml   (real provider credentials)"
echo "  3. sudo systemctl start socks5-proxy"
echo "  4. systemctl status socks5-proxy"
echo "  5. journalctl -u socks5-proxy -f"
