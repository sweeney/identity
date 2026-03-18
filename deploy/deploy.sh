#!/usr/bin/env bash
#
# Build and deploy the Identity service to a remote host.
#
# Usage:
#   ./deploy/deploy.sh sweeney@garibaldi
#
# Keeps the last 3 versioned binaries in /opt/identity/bin/ and symlinks
# the active one. Requires passwordless sudo for systemctl on the remote.
#
# First-time setup:
#   sudo mkdir -p /opt/identity/bin
#   sudo chown sweeney:sweeney /opt/identity/bin
#   sudo ln -sf /opt/identity/bin/identity-server /usr/local/bin/identity-server
#   # then update identity.service ExecStart to /usr/local/bin/identity-server (the symlink)
#
set -euo pipefail

REMOTE="${1:?Usage: $0 user@host}"
BINARY="identity-server"
BUILD_DIR="bin"
DEPLOY_DIR="/opt/identity/bin"
KEEP_VERSIONS=3

VERSION=$(date +%Y%m%d-%H%M%S)
REMOTE_BIN="${BINARY}-${VERSION}"

echo "=== Building $BINARY (linux/amd64) ==="
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$BUILD_DIR/$BINARY" ./cmd/server/
echo "  Built: $BUILD_DIR/$BINARY"

echo "=== Uploading to $REMOTE ==="
ssh "$REMOTE" "mkdir -p $DEPLOY_DIR"
scp "$BUILD_DIR/$BINARY" "$REMOTE:$DEPLOY_DIR/$REMOTE_BIN"
ssh "$REMOTE" "chmod 755 $DEPLOY_DIR/$REMOTE_BIN"

echo "=== Linking $REMOTE_BIN ==="
ssh "$REMOTE" "ln -sfn $REMOTE_BIN $DEPLOY_DIR/$BINARY"

echo "=== Restarting service ==="
ssh "$REMOTE" "sudo systemctl restart identity"
sleep 2

echo "=== Cleaning old versions (keeping $KEEP_VERSIONS) ==="
ssh "$REMOTE" "\
  cd $DEPLOY_DIR && \
  ls -t ${BINARY}-* \
    | tail -n +$((KEEP_VERSIONS + 1)) \
    | xargs -r rm --"

echo ""
echo "=== Deployed $VERSION ==="
ssh "$REMOTE" "sudo journalctl -u identity -n 5 --no-pager"
