#!/usr/bin/env bash
#
# One-time setup for the Identity (+ optional config) service on a fresh
# Linux host. Run as root or with sudo.
#
# Usage:
#   sudo ./deploy/setup.sh
#   INSTALL_CONFIG=0 sudo ./deploy/setup.sh   # skip config service
#
set -euo pipefail

INSTALL_CONFIG="${INSTALL_CONFIG:-1}"

echo "=== Creating identity user ==="
if ! id identity &>/dev/null; then
    useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/identity identity
    echo "  Created user: identity"
else
    echo "  User already exists"
fi

echo "=== Creating directories ==="
mkdir -p /opt/identity/bin
# Deploy user (caller of deploy.sh) needs write access; identity user only needs read+exec
chown "${SUDO_USER:-root}:${SUDO_USER:-root}" /opt/identity/bin

mkdir -p /var/lib/identity
chown identity:identity /var/lib/identity
chmod 700 /var/lib/identity

mkdir -p /etc/identity
chmod 700 /etc/identity

echo "=== Installing identity env file ==="
if [ ! -f /etc/identity/env ]; then
    cp deploy/env.example /etc/identity/env
    chown root:root /etc/identity/env
    chmod 600 /etc/identity/env
    echo "  Installed /etc/identity/env — edit this file with your secrets"
else
    echo "  /etc/identity/env already exists, skipping"
fi

echo "=== Installing identity systemd unit ==="
cp deploy/identity.service /etc/systemd/system/identity.service

if [ "$INSTALL_CONFIG" = "1" ] && [ -f deploy/config.service ]; then
    echo "=== Installing config env file ==="
    if [ ! -f /etc/identity/config.env ]; then
        cp deploy/config-env.example /etc/identity/config.env
        chown root:root /etc/identity/config.env
        chmod 600 /etc/identity/config.env
        echo "  Installed /etc/identity/config.env — edit this file with your secrets"
    else
        echo "  /etc/identity/config.env already exists, skipping"
    fi

    echo "=== Installing config systemd unit ==="
    cp deploy/config.service /etc/systemd/system/config.service
    echo "  Installed config.service"
fi

systemctl daemon-reload
echo "  systemctl daemon-reload done"

echo ""
echo "=== Next steps ==="
echo "  1. Edit identity secrets:  sudo nano /etc/identity/env"
echo "  2. Enable identity:        sudo systemctl enable identity"
if [ "$INSTALL_CONFIG" = "1" ] && [ -f deploy/config.service ]; then
    echo "  3. Edit config secrets:    sudo nano /etc/identity/config.env"
    echo "  4. Enable config:          sudo systemctl enable config"
fi
echo "  5. Deploy:                 ./deploy/deploy.sh user@this-host"
echo "  6. Check status:           sudo systemctl status identity"
if [ "$INSTALL_CONFIG" = "1" ] && [ -f deploy/config.service ]; then
    echo "                             sudo systemctl status config"
fi
echo "  7. View logs:              sudo journalctl -u identity -f"
