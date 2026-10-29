#!/usr/bin/env bash
#
# Before a deploy: snapshot the live identity database and rehearse the
# upgrade from what production runs now to this checkout's HEAD against it.
#
# Usage:
#   ./deploy/rehearse-deploy.sh [--check] [--yes] user@host
#
#   --check  no sudo, nothing written on the host: verify the host can be
#            snapshotted, build both versions, and rehearse on a database the
#            production version builds itself. Run this first.
#   --yes    do not ask for confirmation.
#
# Without --check it:
#   1. reads the version production runs from /health ($HEALTH_URL);
#   2. builds that commit and HEAD, each from a clean worktree;
#   3. snapshots the live database on the host (deploy/snapshot-db.sh; sudo
#      asks for your password once). The snapshot stays on the host as the
#      pre-deploy backup;
#   4. copies it to a private temp dir here and rehearses the upgrade, a
#      rollback and a roll-forward on that copy (deploy/rehearse-upgrade.sh);
#   5. deletes the local copy, pass or fail.
#
# Run it in a terminal: sudo needs one to ask for the password.
#
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
HEALTH_URL=${HEALTH_URL:-https://id.swee.net/health}

CHECK=0 YES=0 REMOTE=""
usage() { sed -n '6,12p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
while [ $# -gt 0 ]; do
	case $1 in
	--check) CHECK=1 ;;
	--yes) YES=1 ;;
	-h | --help) usage ;;
	-*) echo "unknown option: $1" >&2; usage ;;
	*) [ -z "$REMOTE" ] || usage; REMOTE=$1 ;;
	esac
	shift
done
[ -n "$REMOTE" ] || usage

die() { echo "error: $*" >&2; exit 1; }

# --- Preconditions ------------------------------------------------------------
echo "=== Preconditions ==="
for tool in git go curl sqlite3 python3; do
	command -v "$tool" >/dev/null || die "$tool is not installed"
done
git -C "$ROOT" diff --quiet HEAD -- || die "tracked files in $ROOT have uncommitted changes; the rehearsal builds HEAD, so commit or stash them first"
NEW_VER=$(git -C "$ROOT" rev-parse --short HEAD)
HEALTH=$(curl -sf --max-time 10 "$HEALTH_URL") || die "cannot reach $HEALTH_URL"
OLD_VER=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["version"])' "$HEALTH") ||
	die "no version in $HEALTH_URL: $HEALTH"
git -C "$ROOT" cat-file -e "$OLD_VER^{commit}" 2>/dev/null ||
	die "production runs $OLD_VER, which is not in this repository; git fetch first"
[ "$(git -C "$ROOT" rev-parse "$OLD_VER")" != "$(git -C "$ROOT" rev-parse HEAD)" ] ||
	die "production already runs HEAD ($NEW_VER); there is no upgrade to rehearse"
MIGRATIONS=$(git -C "$ROOT" ls-tree --name-only HEAD internal/db/migrations/ | grep -c '\.sql$')
echo "  production: $OLD_VER    this checkout: $NEW_VER    migrations at HEAD: $MIGRATIONS"

TMP=$(mktemp -d)
chmod 700 "$TMP"
cleanup() {
	for wt in "$TMP/src-old" "$TMP/src-new"; do
		[ ! -d "$wt" ] || git -C "$ROOT" worktree remove --force "$wt" 2>/dev/null || true
	done
	rm -rf "$TMP"
}
trap cleanup EXIT

if [ "$CHECK" = 1 ]; then
	"$HERE/snapshot-db.sh" --check "$REMOTE"
else
	echo ""
	echo "This will:"
	echo "  - snapshot the live database on $REMOTE (sudo prompts once; nothing else changes there),"
	echo "  - copy the snapshot to a private temp dir here, rehearse $OLD_VER -> $NEW_VER on it,"
	echo "  - delete the local copy afterwards, whatever the result."
	if [ "$YES" != 1 ]; then
		printf 'Proceed? [y/N] '
		read -r answer
		case $answer in y | Y | yes) ;; *) echo "aborted"; exit 1 ;; esac
	fi
fi

# --- Build both versions ------------------------------------------------------
echo ""
echo "=== Building $OLD_VER and $NEW_VER ==="
for pair in "old:$OLD_VER" "new:$NEW_VER"; do
	side=${pair%%:*} ver=${pair#*:}
	git -C "$ROOT" worktree add -q --detach "$TMP/src-$side" "$ver"
	go -C "$TMP/src-$side" build -ldflags "-X main.version=$ver" -o "$TMP/identity-$side" ./cmd/server/
	git -C "$ROOT" worktree remove --force "$TMP/src-$side"
	echo "  ✓ $ver"
done

# --- Rehearse -----------------------------------------------------------------
REHEARSE=("$HERE/rehearse-upgrade.sh" --old-bin "$TMP/identity-old" --old-ver "$OLD_VER"
	--new-bin "$TMP/identity-new" --new-ver "$NEW_VER" --migrations "$MIGRATIONS" --workdir "$TMP/work")
echo ""
if [ "$CHECK" = 1 ]; then
	echo "=== Rehearsing on a synthetic database (--check) ==="
	"${REHEARSE[@]}"
	echo ""
	echo "--check passed. Run without --check to snapshot $REMOTE and rehearse on real data."
	exit 0
fi

echo "=== Snapshotting $REMOTE ==="
"$HERE/snapshot-db.sh" --yes --label "pre-$NEW_VER" --fetch "$TMP/prod.db" "$REMOTE"
echo ""
echo "=== Rehearsing on the production snapshot ==="
"${REHEARSE[@]}" --db "$TMP/prod.db"
echo ""
echo "Rehearsal passed on production data; the local copy is being deleted."
echo "The pre-deploy snapshot stays on $REMOTE (see its path above)."
