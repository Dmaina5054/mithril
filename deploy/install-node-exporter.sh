#!/usr/bin/env bash
# deploy/install-node-exporter.sh
# Installs node_exporter v1.12.1 with ZFS collector on Debian/Ubuntu.
# Run on Minas Tirith: bash deploy/install-node-exporter.sh
#
# Uses ~/.local/bin if no sudo. Creates a user systemd service.

set -euo pipefail

VERSION="1.12.1"
ARCH="linux-amd64"
BASE="node_exporter-${VERSION}.${ARCH}"
TARBALL="${BASE}.tar.gz"
URL="https://github.com/prometheus/node_exporter/releases/download/v${VERSION}/${TARBALL}"
EXPECTED_SHA256="b51d8a76aa2a9156a55d501aca6276fae09e262259a5e4e831d2c2222f084e63"

# ── Check for existing install ─────────────────────────────────────
if command -v node_exporter &>/dev/null; then
    echo "node_exporter already installed: $(node_exporter --version 2>&1 | head -1)"
    read -p "Reinstall? [y/N] " yn
    case $yn in
        [Yy]*) ;;
        *) echo "Aborted."; exit 0 ;;
    esac
fi

# ── Determine install path ─────────────────────────────────────────
if command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
    INSTALL_DIR="/usr/local/bin"
    USE_SUDO=1
else
    INSTALL_DIR="$HOME/.local/bin"
    USE_SUDO=0
    mkdir -p "$INSTALL_DIR"
fi

echo "→ Installing to $INSTALL_DIR"

# ── Download and verify ────────────────────────────────────────────
cd /tmp
echo "→ Downloading node_exporter v${VERSION}..."
curl -sLO "$URL"

echo "→ Verifying SHA256..."
echo "${EXPECTED_SHA256}  ${TARBALL}" | sha256sum -c --quiet

# ── Extract and install ────────────────────────────────────────────
echo "→ Extracting..."
tar xzf "$TARBALL"

if [ "$USE_SUDO" -eq 1 ]; then
    sudo mv "${BASE}/node_exporter" "$INSTALL_DIR/"
    sudo chmod 755 "${INSTALL_DIR}/node_exporter"
else
    mv "${BASE}/node_exporter" "$INSTALL_DIR/"
    chmod 755 "${INSTALL_DIR}/node_exporter"
fi

rm -rf "$BASE" "$TARBALL"

echo "→ Installed: $($INSTALL_DIR/node_exporter --version 2>&1 | head -1)"

# ── systemd user service ───────────────────────────────────────────
SYSTEMD_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
mkdir -p "$SYSTEMD_DIR"

cat > "$SYSTEMD_DIR/node-exporter.service" <<UNIT
[Unit]
Description=Prometheus Node Exporter (ZFS)
Documentation=https://github.com/prometheus/node_exporter
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/node_exporter \\
    --collector.zfs \\
    --web.listen-address=127.0.0.1:9100 \\
    --collector.systemd \\
    --collector.processes
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
UNIT

echo "→ systemd unit written to $SYSTEMD_DIR/node-exporter.service"

# ── Enable and start ───────────────────────────────────────────────
systemctl --user daemon-reload
systemctl --user enable node-exporter
systemctl --user start node-exporter

# Enable lingering so the user service survives logout
if command -v loginctl &>/dev/null; then
    loginctl enable-linger "$USER" 2>/dev/null || true
fi

sleep 2
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ node_exporter v${VERSION} installed and running"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Status:   systemctl --user status node-exporter"
echo "Metrics:  curl http://127.0.0.1:9100/metrics"
echo "ZFS:      curl -s http://127.0.0.1:9100/metrics | grep node_zfs"

# ── Verify ─────────────────────────────────────────────────────────
echo ""
echo "Verifying..."
sleep 1
if curl -sf http://127.0.0.1:9100/metrics > /dev/null; then
    METRIC_COUNT=$(curl -s http://127.0.0.1:9100/metrics | grep -c '^node_' || echo 0)
    ZFS_COUNT=$(curl -s http://127.0.0.1:9100/metrics | grep -c '^node_zfs' || echo 0)
    echo "  node_ metrics: $METRIC_COUNT"
    echo "  node_zfs metrics: $ZFS_COUNT"
    echo "  ✅ node_exporter is serving metrics"
else
    echo "  ⚠️  node_exporter is not responding on :9100"
fi
