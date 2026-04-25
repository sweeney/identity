#!/usr/bin/env bash
#
# Build and deploy the Identity + Config services to a remote host.
#
# Usage:
#   ./deploy/deploy.sh sweeney@garibaldi
#
# Keeps the last 3 versioned binaries in /opt/identity/bin/ and symlinks
# the active one. Restarts BOTH identity and (if installed) config
# services after upload. Requires passwordless sudo for systemctl on
# the remote.
#
# First-time setup: run deploy/install.sh on the target host with sudo.
#
# Environment overrides:
#   DEPLOY_CONFIG=0       skip restarting the config service even if present
#   CONFIG_HEALTH_URL     config /healthz URL (optional; skipped if unset)
#
set -euo pipefail

REMOTE="${1:?Usage: $0 user@host}"
BINARY="identity-server"
BUILD_DIR="bin"
DEPLOY_DIR="/opt/identity/bin"
HEALTH_URL="${HEALTH_URL:-https://id.swee.net/health}"
CONFIG_HEALTH_URL="${CONFIG_HEALTH_URL:-}"
KEEP_VERSIONS=3
DEPLOY_CONFIG="${DEPLOY_CONFIG:-1}"

VERSION=$(date +%Y%m%d-%H%M%S)
COMMIT=$(git rev-parse --short HEAD)
REMOTE_BIN="${BINARY}-${VERSION}"

echo "=== Building $BINARY (linux/amd64) ==="
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X main.version=${COMMIT}" -o "$BUILD_DIR/$BINARY" ./cmd/server/
echo "  Built: $BUILD_DIR/$BINARY"

echo "=== Uploading to $REMOTE ==="
scp "$BUILD_DIR/$BINARY" "$REMOTE:$DEPLOY_DIR/$REMOTE_BIN"
ssh "$REMOTE" "chmod 755 $DEPLOY_DIR/$REMOTE_BIN"

echo "=== Activating $REMOTE_BIN ==="
ssh "$REMOTE" "ln -sfn $REMOTE_BIN $DEPLOY_DIR/$BINARY"

echo "=== Restarting identity ==="
ssh "$REMOTE" "sudo systemctl restart identity"

# Config service is optional — only restart if the unit file is present.
CONFIG_PRESENT="$(ssh "$REMOTE" 'test -f /etc/systemd/system/config.service && echo yes || echo no')"
if [ "$DEPLOY_CONFIG" = "1" ] && [ "$CONFIG_PRESENT" = "yes" ]; then
    echo "=== Restarting config ==="
    ssh "$REMOTE" "sudo systemctl restart config"
fi

echo "=== Verifying ==="
sleep 2

if ssh "$REMOTE" "sudo systemctl is-active --quiet identity"; then
    echo "  ✓ identity is running"
else
    echo "  ✗ identity failed to start"
    ssh "$REMOTE" "sudo journalctl -u identity -n 20 --no-pager"
    exit 1
fi

if [ "$DEPLOY_CONFIG" = "1" ] && [ "$CONFIG_PRESENT" = "yes" ]; then
    if ssh "$REMOTE" "sudo systemctl is-active --quiet config"; then
        echo "  ✓ config is running"
    else
        echo "  ✗ config failed to start"
        ssh "$REMOTE" "sudo journalctl -u config -n 20 --no-pager"
        exit 1
    fi
fi

ADVERTISED=$(curl -sf "$HEALTH_URL" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
if [ "$ADVERTISED" = "$COMMIT" ]; then
    echo "  ✓ identity version $COMMIT confirmed at $HEALTH_URL"
else
    echo "  ✗ identity version mismatch: deployed $COMMIT but $HEALTH_URL reports '${ADVERTISED:-<no response>}'"
    exit 1
fi

if [ -n "$CONFIG_HEALTH_URL" ]; then
    CFG_ADVERTISED=$(curl -sf "$CONFIG_HEALTH_URL" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
    if [ "$CFG_ADVERTISED" = "$COMMIT" ]; then
        echo "  ✓ config version $COMMIT confirmed at $CONFIG_HEALTH_URL"
    else
        echo "  ✗ config version mismatch: deployed $COMMIT but $CONFIG_HEALTH_URL reports '${CFG_ADVERTISED:-<no response>}'"
        exit 1
    fi
fi

echo "=== Cleaning old versions (keeping $KEEP_VERSIONS) ==="
ssh "$REMOTE" "\
  cd $DEPLOY_DIR && \
  ls -t ${BINARY}-* \
    | tail -n +$((KEEP_VERSIONS + 1)) \
    | xargs -r rm --"

echo ""
echo "=== Deployed $VERSION ==="
ssh "$REMOTE" "sudo journalctl -u identity -n 5 --no-pager"
if [ "$DEPLOY_CONFIG" = "1" ] && [ "$CONFIG_PRESENT" = "yes" ]; then
    echo ""
    ssh "$REMOTE" "sudo journalctl -u config -n 5 --no-pager"
fi
