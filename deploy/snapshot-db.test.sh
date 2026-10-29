#!/usr/bin/env bash
#
# Tests for deploy/snapshot-db.sh, run against a local fixture: ssh and scp are
# replaced by shims that run on this machine, sudo and the service user are
# disabled, and the "host" is a temp directory holding a live WAL database
# whose newest rows exist only in the -wal file, held open by a writer.
#
# Usage: ./deploy/snapshot-db.test.sh
#
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SCRIPT=$HERE/snapshot-db.sh
T=$(mktemp -d)
WRITER_PID=""
trap '[ -z "$WRITER_PID" ] || kill $WRITER_PID 2>/dev/null; [ -n "${KEEP_T:-}" ] || rm -rf "$T"' EXIT

PASS=0 FAIL=0
ok() { echo "  ✓ $1"; PASS=$((PASS + 1)); }
bad() { echo "  ✗ $1"; FAIL=$((FAIL + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# --- Shims --------------------------------------------------------------------
mkdir -p "$T/shims"
cat >"$T/shims/ssh" <<'EOF'
#!/usr/bin/env bash
# Drop ssh options and the host, run the command locally.
while [ $# -gt 0 ]; do
	case $1 in
	-t | -tt) shift ;;
	-o) shift 2 ;;
	*) break ;;
	esac
done
[ "${SHIM_SSH_FAIL:-0}" = 1 ] && exit 255
shift # host
exec bash -c "$*"
EOF
cat >"$T/shims/scp" <<'EOF'
#!/usr/bin/env bash
[ "$1" = -q ] && shift
exec cp "${1#*:}" "$2"
EOF
chmod +x "$T/shims/ssh" "$T/shims/scp"

# --- Fixture host -------------------------------------------------------------
HOST=$T/host
mkdir -p "$HOST/var/lib/identity" "$HOST/etc/identity"
DB=$HOST/var/lib/identity/live.db
echo 'DB_PATH=live.db' >"$HOST/etc/identity/env"
python3 - "$DB" "$T/writer.ready" <<'EOF' &
import sqlite3, sys, time, pathlib
db = sqlite3.connect(sys.argv[1], isolation_level=None)
db.execute("pragma journal_mode=wal")
db.execute("pragma wal_autocheckpoint=0")
db.execute("create table users (id integer primary key, name text)")
db.executemany("insert into users(name) values (?)", [(f"u{i}",) for i in range(100)])
pathlib.Path(sys.argv[2]).touch()
time.sleep(120)  # hold the connection: rows stay in the WAL, uncheckpointed
EOF
WRITER_PID=$!
for _ in $(seq 1 50); do [ -f "$T/writer.ready" ] && break; sleep 0.1; done
[ -f "$T/writer.ready" ] || { echo "fixture writer never became ready"; exit 1; }

export IDENTITY_SSH=$T/shims/ssh IDENTITY_SCP=$T/shims/scp IDENTITY_SUDO="" IDENTITY_SERVICE_USER=""
export IDENTITY_ENV_FILE=$HOST/etc/identity/env IDENTITY_WORKDIR=$HOST/var/lib/identity
export IDENTITY_SNAPSHOT_DIR=$HOST/var/lib/identity/snapshots

echo "== fixture"
check "rows live only in the WAL (main file has no users table yet)" \
	'[ -s "$DB-wal" ] && ! sqlite3 "file:$DB?immutable=1" "select 1 from users" >/dev/null 2>&1'

echo "== --check"
OUT=$("$SCRIPT" --check --fetch "$T/local.db" host 2>&1)
check "--check exits 0" true
check "--check creates no snapshot dir" '[ ! -e "$IDENTITY_SNAPSHOT_DIR" ]'
check "--check fetches nothing" '[ ! -e "$T/local.db" ]'
check "--check prints the plan" 'grep -q "nothing was created" <<<"$OUT"'

echo "== snapshot + fetch"
"$SCRIPT" --yes --fetch "$T/local.db" --label pre-test host >"$T/run1.log" 2>&1 || { cat "$T/run1.log"; bad "run exited non-zero"; }
SNAP=$(ls "$IDENTITY_SNAPSHOT_DIR"/identity-*-pre-test.db 2>/dev/null | head -n 1)
check "snapshot written on the host" '[ -n "$SNAP" ] && [ -f "$SNAP" ]'
check "snapshot holds the WAL-only rows (100)" '[ "$(sqlite3 "$SNAP" "select count(*) from users")" = 100 ]'
check "snapshot passes integrity_check" '[ "$(sqlite3 "$SNAP" "pragma integrity_check")" = ok ]'
check "snapshot is mode 0600" '[ "$(stat -f %Lp "$SNAP" 2>/dev/null || stat -c %a "$SNAP")" = 600 ]'
check "snapshot is one self-contained file (no -wal/-shm beside it)" '[ ! -e "$SNAP-wal" ] && [ ! -e "$SNAP-shm" ]'
check "snapshot dir is mode 0700" '[ "$(stat -f %Lp "$IDENTITY_SNAPSHOT_DIR" 2>/dev/null || stat -c %a "$IDENTITY_SNAPSHOT_DIR")" = 700 ]'
check "local copy fetched with all rows" '[ "$(sqlite3 "$T/local.db" "select count(*) from users")" = 100 ]'
check "local copy is mode 0600" '[ "$(stat -f %Lp "$T/local.db" 2>/dev/null || stat -c %a "$T/local.db")" = 600 ]'
STAGED=$(sed -n 's/^STAGED //p' "$T/run1.log" | tr -d '\r' | tail -n 1)
check "staged copy removed from the host" '[ -n "$STAGED" ] && [ ! -e "$STAGED" ] && [ ! -e "$(dirname "$STAGED")" ]'
check "live database still has its rows" '[ "$(sqlite3 "$DB" "select count(*) from users")" = 100 ]'

echo "== re-run is safe"
sleep 1 # timestamps have one-second resolution
"$SCRIPT" --yes --label pre-test host >"$T/run2.log" 2>&1 || bad "second run exited non-zero"
check "second run adds a second snapshot, first untouched" \
	'[ "$(ls "$IDENTITY_SNAPSHOT_DIR"/identity-*-pre-test.db | wc -l | tr -d " ")" = 2 ] && [ -f "$SNAP" ]'

echo "== refusals"
check "refuses to overwrite an existing --fetch destination" \
	'! "$SCRIPT" --yes --fetch "$T/local.db" host >/dev/null 2>&1'
check "fails cleanly when ssh is unreachable" \
	'! SHIM_SSH_FAIL=1 "$SCRIPT" --yes host >/dev/null 2>&1'
check "rejects an unsafe --label" \
	'! "$SCRIPT" --yes --label "../x" host >/dev/null 2>&1'
check "confirmation defaults to no" \
	'! echo "" | "$SCRIPT" host >/dev/null 2>&1 && [ "$(ls "$IDENTITY_SNAPSHOT_DIR" | wc -l | tr -d " ")" = 2 ]'
echo 'DB_PATH=missing.db' >"$HOST/etc/identity/env"
check "fails when the database does not exist" \
	'! "$SCRIPT" --yes host >/dev/null 2>&1'

echo ""
echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
