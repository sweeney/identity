#!/usr/bin/env bash
#
# One-time setup for the Identity service on a fresh Linux host.
# Run as root or with sudo.
#
# Usage:
#   sudo ./deploy/setup.sh
#
set -euo pipefail

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

echo "=== Installing env file ==="
if [ ! -f /etc/identity/env ]; then
    cp deploy/env.example /etc/identity/env
    chown root:root /etc/identity/env
    chmod 600 /etc/identity/env
    echo "  Installed /etc/identity/env — edit this file with your secrets"
else
    echo "  /etc/identity/env already exists, skipping"
fi

echo "=== Installing systemd unit ==="
cp deploy/identity.service /etc/systemd/system/identity.service
systemctl daemon-reload
echo "  Installed identity.service"

echo ""
echo "=== Next steps ==="
echo "  1. Edit secrets:     sudo nano /etc/identity/env"
echo "  2. Enable service:   sudo systemctl enable identity"
echo "  3. Deploy:           ./deploy/deploy.sh user@this-host"
echo "  4. Check status:     sudo systemctl status identity"
echo "  5. View logs:        sudo journalctl -u identity -f"
