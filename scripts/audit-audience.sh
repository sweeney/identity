#!/usr/bin/env bash
#
# Which registered OAuth clients would still be accepted by a service that
# starts requiring a given audience?
#
# Run this BEFORE setting REQUIRED_AUDIENCE on any resource server: a client
# whose audiences do not include that value will have its tokens rejected the
# moment the service restarts.
#
#   sudo -u identity ./audit-audience.sh config
#
# Reads the identity database. It cannot write to it:
#
#   * sqlite3 is opened with -readonly, so any write is refused by SQLite
#     itself rather than by our good intentions.
#   * The database file must already exist. Without this check sqlite3 would
#     silently CREATE an empty database at a mistyped path.
#   * The audience argument is validated against a strict character set and
#     passed as a bound parameter, so it cannot alter the query.
#   * The query is a single SELECT. There is no code path that writes.
#
# Exit codes: 0 ok, 1 usage/validation, 2 environment (no sqlite3, no database).
set -euo pipefail

usage() {
    echo "usage: $(basename "$0") <audience>" >&2
    echo "  e.g. $(basename "$0") config" >&2
    echo "  DB_PATH may override the default database location." >&2
}

AUD="${1-}"
if [ -z "$AUD" ]; then
    usage
    exit 1
fi
if [ "$AUD" = "-h" ] || [ "$AUD" = "--help" ]; then
    usage
    exit 0
fi

# Audience values name services: hostnames, URLs, bare identifiers. Anything
# outside this set is a mistake at best, so refuse rather than interpret it.
if ! printf '%s' "$AUD" | grep -Eq '^[A-Za-z0-9._:/-]{1,253}$'; then
    echo "error: audience $(printf '%q' "$AUD") contains characters that are not" >&2
    echo "       valid in a service name (allowed: letters, digits, . _ : / -)" >&2
    exit 1
fi

DB="${DB_PATH:-/var/lib/identity/identity.db}"

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "error: sqlite3 is not installed" >&2
    exit 2
fi
# Existence is checked before touching sqlite3: given a path that does not
# exist, sqlite3 creates an empty database there rather than complaining.
if [ ! -e "$DB" ]; then
    echo "error: no database at $DB" >&2
    echo "       (set DB_PATH if it lives elsewhere; this script will not create one)" >&2
    exit 2
fi
if [ ! -f "$DB" ]; then
    echo "error: $DB is not a regular file" >&2
    exit 2
fi
if [ ! -r "$DB" ]; then
    echo "error: cannot read $DB — run as the identity user:" >&2
    echo "       sudo -u identity $0 $AUD" >&2
    exit 2
fi

# Read-only from here on. -bail stops at the first error rather than pressing on.
run_sql() { sqlite3 -readonly -bail "$DB" "$@"; }

if ! run_sql "SELECT 1 FROM sqlite_master WHERE type='table' AND name='oauth_clients';" | grep -q 1; then
    echo "error: $DB has no oauth_clients table — is this the identity database?" >&2
    exit 2
fi
if ! run_sql "PRAGMA table_info(oauth_clients);" | cut -d'|' -f2 | grep -qx audiences; then
    echo "error: this database predates the multi-valued audience migration (011)." >&2
    echo "       Deploy the current identity build first; it migrates on startup." >&2
    exit 2
fi

TOTAL=$(run_sql "SELECT count(*) FROM oauth_clients;")
echo "Audience: $AUD"
echo "Database: $DB (read-only)"
echo "Clients:  $TOTAL"
echo

# The audience is a bound parameter, so it is data and can never be SQL.
printf '.parameter set :aud %s\n%s\n' \
    "'$AUD'" \
    "SELECT CASE WHEN EXISTS (SELECT 1 FROM json_each(audiences) WHERE value = :aud)
                 THEN '  ACCEPTED  ' ELSE '  REJECTED  ' END
            || id || '   (' || audiences || ')'
       FROM oauth_clients
      ORDER BY 1 DESC, id;" | run_sql

echo
echo "REJECTED clients lose access the moment that service sets REQUIRED_AUDIENCE=$AUD."
echo "Add the audience to each client that legitimately calls it first, then enforce."
