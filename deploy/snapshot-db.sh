#!/usr/bin/env bash
#
# Take a consistent snapshot of the live identity database on a remote host,
# keep it on the host, and optionally copy it here.
#
# Usage:
#   ./deploy/snapshot-db.sh [--check] [--yes] [--fetch DEST] [--label NAME] user@host
#
#   --check        read-only: report what would happen and verify what can be
#                  verified without sudo, then exit. Nothing is created.
#   --fetch DEST   also copy the snapshot to the local file DEST (mode 0600).
#   --label NAME   suffix for the snapshot's filename (default: snapshot).
#   --yes          do not ask for confirmation.
#
# Run it before a deploy: the snapshot is the way back if a new binary leaves
# the database in a state the old one cannot use.
#
# The snapshot is taken with SQLite's online backup API (`.backup`), which is
# consistent while identity is running in WAL mode; copying the file is not. It
# runs as the service user, is made a single file (journal_mode=delete), is
# checked with `pragma integrity_check`, and lands
# in SNAPSHOT_DIR on the host, mode 0600, owned by the service user. --fetch
# stages a copy readable by the SSH user in a private temp dir, copies it, and
# removes the staged copy whether or not the copy succeeded.
#
# The snapshot holds password hashes, refresh token hashes and the JWT signing
# key. Treat a fetched copy as secret and delete it when finished.
#
# Needs sudo on the host (one password prompt). Safe to re-run: each run writes
# a new timestamped file and never touches the live database except to read it.
#
set -euo pipefail

# Overridable for tests; the defaults describe the production layout
# (deploy/identity.service, deploy/install.sh).
SSH=${IDENTITY_SSH:-ssh}
SCP=${IDENTITY_SCP:-scp}
SUDO=${IDENTITY_SUDO-sudo}
SERVICE_USER=${IDENTITY_SERVICE_USER-identity}
ENV_FILE=${IDENTITY_ENV_FILE:-/etc/identity/env}
WORKDIR=${IDENTITY_WORKDIR:-/var/lib/identity}
SNAPSHOT_DIR=${IDENTITY_SNAPSHOT_DIR:-/var/lib/identity/snapshots}

CHECK=0 YES=0 FETCH="" LABEL=snapshot REMOTE=""
usage() { sed -n '5,13p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
while [ $# -gt 0 ]; do
	case $1 in
	--check) CHECK=1 ;;
	--yes) YES=1 ;;
	--fetch) FETCH=${2:?--fetch needs a destination}; shift ;;
	--label) LABEL=${2:?--label needs a name}; shift ;;
	-h | --help) usage ;;
	-*) echo "unknown option: $1" >&2; usage ;;
	*) [ -z "$REMOTE" ] || usage; REMOTE=$1 ;;
	esac
	shift
done
[ -n "$REMOTE" ] || usage
case $LABEL in *[!A-Za-z0-9._-]*) echo "error: --label may only contain letters, digits, . _ -" >&2; exit 2 ;; esac

die() { echo "error: $*" >&2; exit 1; }

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
NAME="identity-$STAMP-$LABEL.db"

# --- Preconditions (no sudo, nothing written) ---------------------------------
echo "=== Checking $REMOTE ==="
$SSH -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE" true 2>/dev/null ||
	die "cannot ssh to $REMOTE without a password prompt"
$SSH "$REMOTE" "command -v sqlite3 >/dev/null" || die "sqlite3 is not installed on $REMOTE"
$SSH "$REMOTE" "test -d $WORKDIR" || die "$WORKDIR does not exist on $REMOTE"
echo "  ✓ ssh, sqlite3, $WORKDIR"
if [ -n "$FETCH" ]; then
	[ ! -e "$FETCH" ] || die "$FETCH already exists; refusing to overwrite it"
	[ -d "$(dirname "$FETCH")" ] || die "directory for $FETCH does not exist"
	echo "  ✓ local destination $FETCH is free"
fi

echo ""
echo "Plan:"
echo "  1. read DB_PATH from $ENV_FILE (default identity.db in $WORKDIR)"
echo "  2. as $SERVICE_USER: sqlite3 <db> \".backup $SNAPSHOT_DIR/$NAME\""
echo "  3. integrity_check the snapshot; it stays on the host, mode 0600"
[ -z "$FETCH" ] || echo "  4. copy it to $FETCH (mode 0600) and remove the staged copy on the host"

if [ "$CHECK" = 1 ]; then
	echo ""
	echo "--check: nothing was created."
	exit 0
fi
if [ -n "$SUDO" ] && [ ! -t 0 ]; then
	die "sudo needs a terminal to ask for your password; run this in a terminal"
fi
if [ "$YES" != 1 ]; then
	printf 'Proceed? sudo will prompt for your password on %s. [y/N] ' "$REMOTE"
	read -r answer
	case $answer in y | Y | yes) ;; *) echo "aborted"; exit 1 ;; esac
fi

# --- Snapshot on the host (one sudo session) ----------------------------------
# Runs remotely under bash. Prints the staged path (for --fetch) on its last
# line as "STAGED <path>".
REMOTE_SCRIPT='
set -euo pipefail
SUDO=$1 SERVICE_USER=$2 ENV_FILE=$3 WORKDIR=$4 SNAPSHOT_DIR=$5 NAME=$6 FETCH=$7
as_service() { if [ -n "$SERVICE_USER" ]; then $SUDO -u "$SERVICE_USER" "$@"; else "$@"; fi; }
DB=$($SUDO sed -n "s/^DB_PATH=//p" "$ENV_FILE" | tail -n 1 | tr -d "\"'"'"'")
DB=${DB:-identity.db}
case $DB in /*) ;; *) DB=$WORKDIR/$DB ;; esac
$SUDO test -f "$DB" || { echo "error: database $DB not found" >&2; exit 1; }
as_service mkdir -p "$SNAPSHOT_DIR"
as_service chmod 700 "$SNAPSHOT_DIR"
OUT=$SNAPSHOT_DIR/$NAME
as_service sh -c "umask 077 && sqlite3 \"$DB\" \".backup \\\"$OUT\\\"\""
# A backup keeps WAL mode, so every later open would leave -wal/-shm files
# beside it. Make it one self-contained file.
as_service sqlite3 "$OUT" "pragma journal_mode=delete" >/dev/null
# Switching mode leaves the -shm that opening it in WAL mode created; nothing
# else has this file open, so the leftovers can go.
as_service rm -f "$OUT-wal" "$OUT-shm"
[ "$(as_service sqlite3 "$OUT" "pragma integrity_check")" = ok ] || { echo "error: integrity_check failed on $OUT" >&2; exit 1; }
echo "  ✓ $DB -> $OUT ($($SUDO stat -c %s "$OUT" 2>/dev/null || $SUDO stat -f %z "$OUT") bytes, integrity ok)"
if [ "$FETCH" = 1 ]; then
	STAGE=$(mktemp -d)
	$SUDO cat "$OUT" >"$STAGE/$NAME"
	chmod 600 "$STAGE/$NAME"
	echo "STAGED $STAGE/$NAME"
fi
'
echo ""
echo "=== Snapshotting on $REMOTE ==="
OUTPUT=$($SSH -t "$REMOTE" "bash -c $(printf %q "$REMOTE_SCRIPT") _ $(printf %q "$SUDO") $(printf %q "$SERVICE_USER") \
	$(printf %q "$ENV_FILE") $(printf %q "$WORKDIR") $(printf %q "$SNAPSHOT_DIR") $(printf %q "$NAME") $([ -n "$FETCH" ] && echo 1 || echo 0)" |
	tee /dev/stderr | tr -d '\r') || die "snapshot failed on $REMOTE; nothing was fetched"

if [ -n "$FETCH" ]; then
	STAGED=$(sed -n 's/^STAGED //p' <<<"$OUTPUT" | tail -n 1)
	[ -n "$STAGED" ] || die "snapshot taken but no staged copy was reported"
	cleanup() { $SSH "$REMOTE" "rm -rf $(printf %q "$(dirname "$STAGED")")" || echo "warning: could not remove $STAGED on $REMOTE; delete it by hand" >&2; }
	trap cleanup EXIT
	(umask 077 && $SCP -q "$REMOTE:$STAGED" "$FETCH") || die "copy to $FETCH failed"
	chmod 600 "$FETCH"
	[ "$(sqlite3 "$FETCH" "pragma integrity_check")" = ok ] || die "local copy $FETCH failed integrity_check"
	echo "  ✓ fetched to $FETCH (integrity ok). It is secret: delete it when finished."
fi

echo ""
echo "=== Done: $SNAPSHOT_DIR/$NAME on $REMOTE ==="
