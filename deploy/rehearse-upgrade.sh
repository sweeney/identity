#!/usr/bin/env bash
#
# Rehearse an identity upgrade against a database: boot the new binary on it,
# then roll back to the old binary, then forward again, checking each step.
#
# Usage:
#   ./deploy/rehearse-upgrade.sh --old-bin PATH --old-ver SHA --new-bin PATH --new-ver SHA \
#       --migrations N --workdir DIR [--db SNAPSHOT]
#
#   --db SNAPSHOT  rehearse on a COPY of this database (e.g. a prod snapshot).
#                  The original is never opened for writing.
#   (no --db)      the old binary builds a database itself, booted twice as
#                  production replays its migrations, seeded with a login and
#                  a refresh, so token continuity can be checked too.
#
# Normally run by deploy/rehearse-deploy.sh rather than by hand.
#
# What it checks:
#   - the old binary boots on the database as it is;
#   - the new binary's first boot succeeds, logs no warnings or errors, and
#     leaves a migrations ledger of N rows;
#   - the schema is unchanged apart from the ledger, and so are the row counts
#     of the durable tables (users, OAuth clients, passkeys, claim codes,
#     metadata). Tables of short-lived rows are reported, not enforced: a boot
#     may sweep entries that expired in the meantime;
#   - a second boot of the new binary applies nothing;
#   - the old binary still boots on the upgraded database (rollback), and the
#     new one again after it, applying nothing;
#   - (synthetic database only) a token minted before the upgrade still
#     verifies after it and after the rollback, and a fresh login works.
#
# The binaries run with DB_PATH pointing into --workdir, on 127.0.0.1:$PORT,
# with no R2 credentials, so nothing leaves this machine.
#
set -euo pipefail

OLD="" OLD_VER="" NEW="" NEW_VER="" MIGRATIONS="" WD="" SRC=""
while [ $# -gt 0 ]; do
	case $1 in
	--old-bin) OLD=$2; shift ;;
	--old-ver) OLD_VER=$2; shift ;;
	--new-bin) NEW=$2; shift ;;
	--new-ver) NEW_VER=$2; shift ;;
	--migrations) MIGRATIONS=$2; shift ;;
	--workdir) WD=$2; shift ;;
	--db) SRC=$2; shift ;;
	*) echo "unknown argument: $1" >&2; sed -n '7,9p' "$0" >&2; exit 2 ;;
	esac
	shift
done
for v in OLD OLD_VER NEW NEW_VER MIGRATIONS WD; do
	[ -n "${!v}" ] || { echo "missing argument for $v" >&2; exit 2; }
done
for b in "$OLD" "$NEW"; do [ -x "$b" ] || { echo "not executable: $b" >&2; exit 2; }; done

PORT=${REHEARSAL_PORT:-18181}
DB=$WD/identity.db
LOG=$WD/logs
DURABLE="users oauth_clients webauthn_credentials oauth_claim_codes metadata"
mkdir -p "$LOG"
chmod 700 "$WD"
rm -f "$DB" "$DB"-wal "$DB"-shm

fail() { echo "REHEARSAL FAIL: $*" >&2; exit 1; }
healthy() { curl -sf "http://127.0.0.1:$PORT/health" 2>/dev/null; }

# Warnings and errors in a boot log, minus the one expected here: no R2
# credentials are given, so backups are disabled.
problems() { grep -v 'R2 backup not configured' "$LOG/$1.log" | grep -iE 'warn|error|fail' || true; }

boot() { # boot <binary> <label> [seed|login]: start, wait for /health, act, stop
	local bin=$1 label=$2 want pid
	if [ "$bin" = "$OLD" ]; then want=$OLD_VER; else want=$NEW_VER; fi
	healthy >/dev/null && fail "port $PORT is already in use before $label"
	(cd "$WD" && DB_PATH="$DB" PORT=$PORT RATE_LIMIT_DISABLED=1 \
		ADMIN_USERNAME=rehearsal ADMIN_PASSWORD=rehearsal-pass-1 BACKUP_SCHEDULE=off \
		exec "$bin" >"$LOG/$label.log" 2>&1) &
	pid=$!
	for _ in $(seq 1 100); do
		healthy >"$LOG/$label.health" && break
		kill -0 $pid 2>/dev/null || { sed 's/^/    /' "$LOG/$label.log"; fail "$label exited during boot"; }
		sleep 0.2
	done
	healthy >/dev/null || { kill $pid 2>/dev/null; fail "$label never became healthy"; }
	grep -q "\"version\":\"$want\"" "$LOG/$label.health" ||
		{ kill $pid 2>/dev/null; fail "$label: /health says $(cat "$LOG/$label.health"), want $want"; }
	case ${3:-} in
	seed) seed ;;
	login) login_check "$label" ;;
	esac
	kill $pid
	wait $pid 2>/dev/null || true
	for _ in $(seq 1 50); do healthy >/dev/null || break; sleep 0.1; done
	healthy >/dev/null && fail "$label still serving after it was stopped"
	echo "  $label ($want): booted and stopped cleanly"
}

seed() {
	local r rt
	r=$(curl -sf -X POST "http://127.0.0.1:$PORT/api/v1/auth/login" -H 'Content-Type: application/json' \
		-d '{"username":"rehearsal","password":"rehearsal-pass-1"}') || fail "seed login"
	rt=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["refresh_token"])' <<<"$r")
	curl -sf -X POST "http://127.0.0.1:$PORT/api/v1/auth/refresh" -H 'Content-Type: application/json' \
		-d "{\"refresh_token\":\"$rt\"}" >"$WD/seed-refresh.json" || fail "seed refresh"
}

login_check() { # a token minted by the old binary must still verify
	local at id code
	at=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["access_token"])' "$WD/seed-refresh.json")
	id=$(python3 -c 'import base64,json,sys; p=sys.argv[1].split(".")[1]; p+="="*(-len(p)%4); print(json.loads(base64.urlsafe_b64decode(p))["sub"])' "$at")
	code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $at" "http://127.0.0.1:$PORT/api/v1/users/$id")
	[ "$code" = 200 ] || fail "$1: a token minted before the upgrade got $code, want 200"
	curl -sf -X POST "http://127.0.0.1:$PORT/api/v1/auth/login" -H 'Content-Type: application/json' \
		-d '{"username":"rehearsal","password":"rehearsal-pass-1"}' >/dev/null || fail "$1: fresh login failed"
	echo "    pre-upgrade token still verifies; fresh login works"
}

record() { # record <label>: schema (ledger excluded) and per-table row counts
	sqlite3 "$DB" "select type||' '||name||': '||coalesce(sql,'') from sqlite_master
		where name not like 'schema_migrations%' and name not like 'sqlite_autoindex_schema_migrations%'
		order by type, name" >"$WD/$1.schema"
	local t
	for t in $(sqlite3 "$DB" "select name from sqlite_master where type='table'
		and name not in ('schema_migrations','sqlite_sequence','audit_events') order by 1"); do
		echo "$t $(sqlite3 "$DB" "select count(*) from \"$t\"")"
	done >"$WD/$1.counts"
}

compare() { # compare <before> <after>
	diff "$WD/$1.schema" "$WD/$2.schema" >"$WD/$2.schema.diff" ||
		{ sed 's/^/    /' "$WD/$2.schema.diff"; fail "schema changed between $1 and $2"; }
	local t a b
	while read -r t b; do
		a=$(awk -v t="$t" '$1==t {print $2}' "$WD/$2.counts")
		[ "$a" = "$b" ] && continue
		case " $DURABLE " in
		*" $t "*) fail "$t: $b rows before, ${a:-none} after" ;;
		*) echo "    note: $t $b -> ${a:-none} (short-lived rows; not enforced)" ;;
		esac
	done <"$WD/$1.counts"
}

skips_or_applies() { grep -E 'applied [1-9]|skipping' "$LOG/$1.log" || true; }

# --- Database under test ------------------------------------------------------
if [ -n "$SRC" ]; then
	[ -f "$SRC" ] || fail "no database at $SRC"
	(umask 077 && cp "$SRC" "$DB")
	[ "$(sqlite3 "$DB" 'pragma integrity_check')" = ok ] || fail "the copy fails integrity_check"
	echo "== on a copy of $(basename "$SRC")"
	boot "$OLD" old
else
	echo "== on a database built by the old binary (booted twice, as production replays)"
	boot "$OLD" old-1 seed
	boot "$OLD" old-2
fi
[ "$(sqlite3 "$DB" "select count(*) from sqlite_master where name='schema_migrations'")" = 0 ] ||
	fail "this database already has a migrations ledger, so there is no adoption to rehearse"
record before

# --- Upgrade ------------------------------------------------------------------
echo "== upgrade: first boot of $NEW_VER (adopts the database into the ledger)"
boot "$NEW" new-1
grep -E 'db: (applying|applied)' "$LOG/new-1.log" | sed 's/^/    /' || true
echo "    $(grep -c 'column already present, skipping' "$LOG/new-1.log" || true) 'column already present, skipping' lines (expected on adoption)"
P=$(problems new-1); [ -z "$P" ] || { sed 's/^/    /' <<<"$P"; fail "warnings or errors on the adoption boot"; }
ROWS=$(sqlite3 "$DB" 'select count(*) from schema_migrations')
[ "$ROWS" = "$MIGRATIONS" ] || fail "ledger has $ROWS rows, want $MIGRATIONS"
record after-upgrade
compare before after-upgrade
echo "    ledger: $ROWS rows; schema and durable row counts unchanged"

echo "== second boot of $NEW_VER: nothing should apply"
boot "$NEW" new-2 "$([ -z "$SRC" ] && echo login)"
S=$(skips_or_applies new-2); [ -z "$S" ] || { sed 's/^/    /' <<<"$S"; fail "the second boot applied migrations again"; }
P=$(problems new-2); [ -z "$P" ] || { sed 's/^/    /' <<<"$P"; fail "warnings or errors on the second boot"; }

# --- Rollback and forward again -----------------------------------------------
echo "== rollback: $OLD_VER on the upgraded database"
boot "$OLD" rollback "$([ -z "$SRC" ] && echo login)"
record after-rollback
compare before after-rollback

echo "== roll forward again: $NEW_VER"
boot "$NEW" new-3
S=$(skips_or_applies new-3); [ -z "$S" ] || { sed 's/^/    /' <<<"$S"; fail "rolling forward re-applied migrations"; }
P=$(problems new-3); [ -z "$P" ] || { sed 's/^/    /' <<<"$P"; fail "warnings or errors rolling forward"; }

echo "REHEARSAL PASS"
