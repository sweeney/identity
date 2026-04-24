#!/usr/bin/env bash
#
# Install the Identity (+ optional config) service on a Linux host.
# Run as root or with sudo from the directory containing the deploy files.
#
# Prerequisites: copy these files to the target host first:
#   /tmp/identity-server       — the binary
#   /tmp/identity.service      — identity systemd unit
#   /tmp/env.example           — identity env file template
#   /tmp/config.service        — config systemd unit (optional)
#   /tmp/config-env.example    — config env file template (optional)
#
# Usage:
#   sudo bash /tmp/install.sh            # install both services
#   INSTALL_CONFIG=0 sudo bash install.sh  # identity only
#
set -euo pipefail

INSTALL_CONFIG="${INSTALL_CONFIG:-1}"

echo "══════════════════════════════════════════"
echo "  Identity + Config Services — Install"
echo "══════════════════════════════════════════"
echo ""

# ── Binary ────────────────────────────────────
echo "=== Installing binary ==="
mkdir -p /opt/identity/bin
# Deploy user owns bin/ so deploy.sh can scp without sudo
chown "${SUDO_USER:-root}:${SUDO_USER:-root}" /opt/identity/bin
systemctl stop identity 2>/dev/null || true
systemctl stop config 2>/dev/null || true
VERSION=$(date +%Y%m%d-%H%M%S)
cp /tmp/identity-server "/opt/identity/bin/identity-server-${VERSION}"
chmod 755 "/opt/identity/bin/identity-server-${VERSION}"
ln -sfn "identity-server-${VERSION}" /opt/identity/bin/identity-server
echo "  /opt/identity/bin/identity-server -> identity-server-${VERSION}"

# ── System user ───────────────────────────────
echo ""
echo "=== System user ==="
if ! id identity &>/dev/null; then
    useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/identity identity
    echo "  Created user: identity"
else
    echo "  User 'identity' already exists"
fi

# ── Directories ───────────────────────────────
echo ""
echo "=== Directories ==="
mkdir -p /var/lib/identity
chown identity:identity /var/lib/identity
chmod 700 /var/lib/identity
echo "  /var/lib/identity (700, identity:identity) — shared by identity + config"

mkdir -p /etc/identity
chmod 700 /etc/identity
echo "  /etc/identity (700, root:root)"

# ── Identity env ──────────────────────────────
echo ""
echo "=== Identity environment file ==="
if [ ! -f /etc/identity/env ]; then
    cp /tmp/env.example /etc/identity/env
    chown root:root /etc/identity/env
    chmod 600 /etc/identity/env
    echo "  Installed /etc/identity/env from template"
    echo "  *** Edit this file with your settings ***"
else
    echo "  /etc/identity/env already exists — not overwriting"
fi

# ── Identity systemd ─────────────────────────
echo ""
echo "=== Identity systemd unit ==="
cp /tmp/identity.service /etc/systemd/system/identity.service
echo "  Installed /etc/systemd/system/identity.service"

# ── Config service (optional) ────────────────
if [ "$INSTALL_CONFIG" = "1" ] && [ -f /tmp/config.service ]; then
    echo ""
    echo "=== Config service ==="
    if [ ! -f /etc/identity/config.env ]; then
        if [ -f /tmp/config-env.example ]; then
            cp /tmp/config-env.example /etc/identity/config.env
            chown root:root /etc/identity/config.env
            chmod 600 /etc/identity/config.env
            echo "  Installed /etc/identity/config.env from template"
            echo "  *** Edit this file with your settings ***"
        else
            echo "  WARNING: /tmp/config-env.example missing — skipping env file install"
        fi
    else
        echo "  /etc/identity/config.env already exists — not overwriting"
    fi
    cp /tmp/config.service /etc/systemd/system/config.service
    echo "  Installed /etc/systemd/system/config.service"
fi

# ── Reload + enable + start ──────────────────
echo ""
echo "=== Enabling services ==="
systemctl daemon-reload
systemctl enable identity
systemctl restart identity
sleep 2

if systemctl is-active --quiet identity; then
    echo "  identity: running"
else
    echo "  WARNING: identity failed to start. Check logs:"
    echo "    journalctl -u identity -n 30"
fi

if [ "$INSTALL_CONFIG" = "1" ] && [ -f /etc/systemd/system/config.service ]; then
    systemctl enable config
    systemctl restart config
    sleep 2
    if systemctl is-active --quiet config; then
        echo "  config:   running"
    else
        echo "  WARNING: config failed to start. Check logs:"
        echo "    journalctl -u config -n 30"
    fi
fi

# ── Summary ───────────────────────────────────
echo ""
echo "══════════════════════════════════════════"
echo "  Install complete"
echo ""
echo "  Identity:"
echo "    Config:   sudo nano /etc/identity/env"
echo "    Status:   sudo systemctl status identity"
echo "    Logs:     sudo journalctl -u identity -f"
echo "    Password: sudo cat /var/lib/identity/initial-password.txt"
echo "               (delete after reading)"
if [ "$INSTALL_CONFIG" = "1" ] && [ -f /etc/systemd/system/config.service ]; then
    echo ""
    echo "  Config:"
    echo "    Config:   sudo nano /etc/identity/config.env"
    echo "    Status:   sudo systemctl status config"
    echo "    Logs:     sudo journalctl -u config -f"
fi
echo "══════════════════════════════════════════"
