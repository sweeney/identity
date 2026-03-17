#!/usr/bin/env bash
#
# Build and deploy the Identity service.
# Run from the repo root. Builds for Linux amd64 by default.
#
# Usage:
#   ./deploy/deploy.sh              # build + deploy locally
#   ./deploy/deploy.sh user@host    # build + deploy to remote host via ssh
#
set -euo pipefail

REMOTE="${1:-}"
BINARY="identity-server"
BUILD_DIR="bin"
INSTALL_PATH="/usr/local/bin/$BINARY"

echo "=== Building $BINARY (linux/amd64) ==="
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$BUILD_DIR/$BINARY" ./cmd/server/
echo "  Built: $BUILD_DIR/$BINARY"

if [ -n "$REMOTE" ]; then
    echo "=== Deploying to $REMOTE ==="
    scp "$BUILD_DIR/$BINARY" "$REMOTE:/tmp/$BINARY"
    ssh "$REMOTE" "sudo mv /tmp/$BINARY $INSTALL_PATH && sudo chmod 755 $INSTALL_PATH && sudo systemctl restart identity"
    echo "  Deployed and restarted"
else
    echo "=== Installing locally ==="
    sudo cp "$BUILD_DIR/$BINARY" "$INSTALL_PATH"
    sudo chmod 755 "$INSTALL_PATH"
    sudo systemctl restart identity
    echo "  Installed and restarted"
fi

echo ""
echo "=== Status ==="
if [ -n "$REMOTE" ]; then
    ssh "$REMOTE" "sudo systemctl status identity --no-pager -l"
else
    sudo systemctl status identity --no-pager -l
fi
