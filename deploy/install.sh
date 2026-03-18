#!/usr/bin/env bash
#
# Install the Identity service on a Linux host.
# Run as root or with sudo from the directory containing the deploy files.
#
# Prerequisites: copy these files to the target host first:
#   /tmp/identity-server    — the binary
#   /tmp/identity.service   — systemd unit
#   /tmp/env.example        — env file template
#
# Usage:
#   sudo bash /tmp/install.sh
#
set -euo pipefail

echo "══════════════════════════════════════════"
echo "  Identity Service — Install"
echo "══════════════════════════════════════════"
echo ""

# ── Binary ────────────────────────────────────
echo "=== Installing binary ==="
mkdir -p /opt/identity/bin
# Deploy user owns bin/ so deploy.sh can scp without sudo
chown "${SUDO_USER:-root}:${SUDO_USER:-root}" /opt/identity/bin
systemctl stop identity 2>/dev/null || true
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
echo "  /var/lib/identity (700, identity:identity)"

mkdir -p /etc/identity
chmod 700 /etc/identity
echo "  /etc/identity (700, root:root)"

# ── Env file ──────────────────────────────────
echo ""
echo "=== Environment file ==="
if [ ! -f /etc/identity/env ]; then
    cp /tmp/env.example /etc/identity/env
    chown root:root /etc/identity/env
    chmod 600 /etc/identity/env
    echo "  Installed /etc/identity/env from template"
    echo "  *** Edit this file with your settings ***"
else
    echo "  /etc/identity/env already exists — not overwriting"
fi

# ── Systemd ───────────────────────────────────
echo ""
echo "=== Systemd service ==="
cp /tmp/identity.service /etc/systemd/system/identity.service
systemctl daemon-reload
echo "  Installed and reloaded"

# ── Start ─────────────────────────────────────
echo ""
echo "=== Starting service ==="
systemctl enable identity
systemctl restart identity
sleep 2

if systemctl is-active --quiet identity; then
    echo "  Service is running"
else
    echo "  WARNING: Service failed to start. Check logs:"
    echo "    journalctl -u identity -n 30"
fi

# ── Summary ───────────────────────────────────
echo ""
echo "══════════════════════════════════════════"
echo "  Install complete"
echo ""
echo "  Config:   sudo nano /etc/identity/env"
echo "  Status:   sudo systemctl status identity"
echo "  Logs:     sudo journalctl -u identity -f"
echo "  Password: sudo journalctl -u identity | grep Password"
echo "══════════════════════════════════════════"
