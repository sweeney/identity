#!/usr/bin/env bash
#
# End-to-end tests for deploy/rehearse-deploy.sh (and through it
# snapshot-db.sh and rehearse-upgrade.sh), run entirely on this machine:
#
#   - ssh/scp are shims that run locally, and sudo is disabled;
#   - the "host" is a temp dir whose database was built by the pre-ledger
#     production binary (7dbfa77), as the real one was;
#   - /health is a local server claiming that version.
#
# It builds 7dbfa77 and HEAD, so it takes a minute or two.
#
# Usage: ./deploy/rehearse-deploy.test.sh
#
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
SCRIPT=$HERE/rehearse-deploy.sh
PRE_LEDGER=7dbfa77 # last production version before the migrations ledger
T=$(mktemp -d)
HEALTH_PID=""
trap '[ -z "$HEALTH_PID" ] || kill $HEALTH_PID 2>/dev/null; git -C "$ROOT" worktree remove --force "$T/src" 2>/dev/null || true; rm -rf "$T"' EXIT

PASS=0 FAIL=0
ok() { echo "  ✓ $1"; PASS=$((PASS + 1)); }
bad() { echo "  ✗ $1"; FAIL=$((FAIL + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
worktrees() { git -C "$ROOT" worktree list | wc -l | tr -d ' '; }

# --- Shims --------------------------------------------------------------------
mkdir -p "$T/shims"
cat >"$T/shims/ssh" <<'EOF'
#!/usr/bin/env bash
while [ $# -gt 0 ]; do
	case $1 in -t | -tt) shift ;; -o) shift 2 ;; *) break ;; esac
done
shift # host
exec bash -c "$*"
EOF
cat >"$T/shims/scp" <<'EOF'
#!/usr/bin/env bash
[ "$1" = -q ] && shift
exec cp "${1#*:}" "$2"
EOF
chmod +x "$T/shims/ssh" "$T/shims/scp"

# --- Fake /health -------------------------------------------------------------
HEALTH_PORT=18299
echo "{\"status\":\"ok\",\"version\":\"$PRE_LEDGER\"}" >"$T/health.json"
python3 - "$HEALTH_PORT" "$T/health.json" <<'EOF' &
import http.server, sys
port, path = int(sys.argv[1]), sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = open(path, "rb").read()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
EOF
HEALTH_PID=$!
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$HEALTH_PORT/" >/dev/null 2>&1 && break; sleep 0.1; done
export HEALTH_URL=http://127.0.0.1:$HEALTH_PORT/health

# --- Fixture host, its database built by the pre-ledger binary ----------------
HOST=$T/host
mkdir -p "$HOST/var/lib/identity" "$HOST/etc/identity"
echo 'DB_PATH=identity.db' >"$HOST/etc/identity/env"
export IDENTITY_SSH=$T/shims/ssh IDENTITY_SCP=$T/shims/scp IDENTITY_SUDO="" IDENTITY_SERVICE_USER=""
export IDENTITY_ENV_FILE=$HOST/etc/identity/env IDENTITY_WORKDIR=$HOST/var/lib/identity
export IDENTITY_SNAPSHOT_DIR=$HOST/var/lib/identity/snapshots

boot_once() { # boot_once <binary> <db>: start, wait for /health, stop
	(cd "$T" && DB_PATH="$2" PORT=18298 RATE_LIMIT_DISABLED=1 ADMIN_USERNAME=fixture \
		ADMIN_PASSWORD=fixture-pass-1 BACKUP_SCHEDULE=off exec "$1" >"$T/fixture-boot.log" 2>&1) &
	local pid=$!
	for _ in $(seq 1 100); do curl -sf http://127.0.0.1:18298/health >/dev/null 2>&1 && break; sleep 0.2; done
	kill $pid; wait $pid 2>/dev/null || true
}
echo "== building the fixture (a $PRE_LEDGER database)"
git -C "$ROOT" worktree add -q --detach "$T/src" "$PRE_LEDGER"
go -C "$T/src" build -o "$T/identity-pre" ./cmd/server/
git -C "$ROOT" worktree remove --force "$T/src"
boot_once "$T/identity-pre" "$HOST/var/lib/identity/identity.db"
boot_once "$T/identity-pre" "$HOST/var/lib/identity/identity.db"
check "fixture database exists, without a ledger" \
	'[ "$(sqlite3 "$HOST/var/lib/identity/identity.db" "select count(*) from sqlite_master where name=\"schema_migrations\"")" = 0 ]'
cp "$HOST/var/lib/identity/identity.db" "$T/fixture-pristine.db"
WT_BEFORE=$(worktrees)

echo "== --check"
"$SCRIPT" --check host >"$T/check.log" 2>&1 || { tail -20 "$T/check.log"; bad "--check exited non-zero"; }
check "--check rehearses and passes" 'grep -q "REHEARSAL PASS" "$T/check.log" && grep -q -- "--check passed" "$T/check.log"'
check "--check takes no snapshot on the host" '[ ! -e "$IDENTITY_SNAPSHOT_DIR" ]'
check "--check leaves no worktrees behind" '[ "$(worktrees)" = "$WT_BEFORE" ]'

echo "== full run"
"$SCRIPT" --yes host >"$T/run.log" 2>&1 || { tail -30 "$T/run.log"; bad "full run exited non-zero"; }
check "rehearses on the snapshot and passes" 'grep -q "on a copy of prod.db" "$T/run.log" && grep -q "REHEARSAL PASS" "$T/run.log"'
check "adoption ledgers every migration" 'grep -q "ledger: $(git -C "$ROOT" ls-tree --name-only HEAD internal/db/migrations/ | grep -c "\.sql$") rows" "$T/run.log"'
check "pre-deploy snapshot kept on the host, named for HEAD" \
	'ls "$IDENTITY_SNAPSHOT_DIR"/identity-*-pre-"$(git -C "$ROOT" rev-parse --short HEAD)".db >/dev/null 2>&1'
check "the host's live database is untouched (still no ledger)" \
	'[ "$(sqlite3 "$HOST/var/lib/identity/identity.db" "select count(*) from sqlite_master where name=\"schema_migrations\"")" = 0 ]'
check "no worktrees left behind" '[ "$(worktrees)" = "$WT_BEFORE" ]'
check "no local copy of the snapshot left behind" \
	'! find "${TMPDIR:-/tmp}" -maxdepth 2 -name prod.db -newer "$T/fixture-pristine.db" 2>/dev/null | grep -q .'

echo "== refusals"
echo "{\"status\":\"ok\",\"version\":\"0000000\"}" >"$T/health.json"
check "refuses when production runs a commit this repo does not have" \
	'! "$SCRIPT" --yes host >"$T/r1.log" 2>&1 && grep -q "not in this repository" "$T/r1.log"'
echo "{\"status\":\"ok\",\"version\":\"$(git -C "$ROOT" rev-parse --short HEAD)\"}" >"$T/health.json"
check "refuses when production already runs HEAD" \
	'! "$SCRIPT" --yes host >"$T/r2.log" 2>&1 && grep -q "no upgrade to rehearse" "$T/r2.log"'
echo "{\"status\":\"ok\",\"version\":\"$PRE_LEDGER\"}" >"$T/health.json"
check "confirmation defaults to no" '! echo "" | "$SCRIPT" host >/dev/null 2>&1'

echo "== a failing rehearsal fails the run and still cleans up"
go -C "$ROOT" build -o "$T/identity-head" ./cmd/server/
boot_once "$T/identity-head" "$HOST/var/lib/identity/identity.db" # now ledgered: nothing to adopt
check "fails when the database already has a ledger" \
	'! "$SCRIPT" --yes host >"$T/r3.log" 2>&1 && grep -q "already has a migrations ledger" "$T/r3.log"'
check "no worktrees left behind after a failure" '[ "$(worktrees)" = "$WT_BEFORE" ]'

echo ""
echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
