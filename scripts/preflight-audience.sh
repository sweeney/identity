#!/usr/bin/env bash
#
# Preflight for issue #39: what happens to live sessions when the client
# registration becomes authoritative on refresh?
#
#   sudo -u identity ./preflight-audience.sh
#   sudo -u identity ./preflight-audience.sh --strict     # exit 3 if any session loses an audience
#
# Also reports which live sessions belong to confidential clients (refused at
# /api/v1/auth/refresh from #40 onward), and which admin sessions carry a
# non-exclusive audience (refused on the management routes from #37 onward).
#
# WHY THIS EXISTS
#
# Before #39, a refresh token carried the aud set frozen when the grant was
# created, and rotation replayed it verbatim. After #39, every rotation re-reads
# the issuing client's registered Audiences. That makes the registration
# authoritative — which is the point — but it also means any registration that
# is wrong today silently rewrites every live session for that client on its
# next refresh, within one access-token lifetime.
#
# The direction that hurts is loss. A session that loses an audience starts
# failing against the resource servers enforcing it (config does; mqttauth
# does), and from outside, a registration and the tokens in flight are
# indistinguishable. That mismatch is exactly what took mqttproxy down for 12
# hours: audit-audience.sh reported ACCEPTED for a client whose live tokens did
# not carry the audience at all.
#
# audit-audience.sh answers "which clients COULD pass?" from the registration
# alone. This answers "what are live sessions carrying RIGHT NOW, and what will
# they carry after the deploy?" — the two halves that were previously impossible
# to compare.
#
# SAFETY
#
# This script cannot write to the database:
#
#   * sqlite3 is opened with -readonly, so SQLite itself refuses any write.
#   * The database file must already exist. Without that check sqlite3 would
#     silently CREATE an empty database at a mistyped path.
#   * Every statement is a SELECT. There is no code path that writes.
#   * No shell interpolation reaches SQL; the queries are literal text.
#
# Exit codes:
#   0  ran cleanly, no session loses an audience
#   1  usage error
#   2  environment problem (no sqlite3, no database, no JSON support)
#   3  --strict only: at least one live session would lose an audience
#
set -euo pipefail

readonly DEFAULT_DB=/var/lib/identity/identity.db
DB_PATH="${DB_PATH:-$DEFAULT_DB}"
STRICT=0
SELF="id.swee.net"

usage() {
    cat >&2 <<USAGE
usage: $(basename "$0") [--strict]

Compares each OAuth client's registered audiences against the audiences carried
by its live (unrevoked) refresh tokens, and reports what those sessions will
carry once the registration becomes authoritative on refresh (#39).

  --strict     exit 3 if any live session would lose an audience, or if an
               admin session would be refused on the management plane
  --self NAME  this server's audience name (default: id.swee.net). Both the
               bare host and https://HOST are treated as naming this server.
  -h, --help   this message

  DB_PATH      database location (default: $DEFAULT_DB)
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --strict) STRICT=1; shift ;;
        --self)
            [ $# -ge 2 ] || { echo "error: --self needs a value" >&2; exit 1; }
            SELF="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage; exit 1 ;;
    esac
done

# --- environment ---------------------------------------------------------

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "error: sqlite3 is not installed or not on PATH" >&2
    exit 2
fi

if [ ! -f "$DB_PATH" ]; then
    echo "error: no database at $DB_PATH" >&2
    echo "  set DB_PATH if the database lives elsewhere." >&2
    echo "  (not creating it: sqlite3 would happily make an empty one at a typo)" >&2
    exit 2
fi

if [ ! -r "$DB_PATH" ]; then
    echo "error: $DB_PATH is not readable by $(id -un)" >&2
    echo "  try: sudo -u identity $0" >&2
    exit 2
fi

# Field separator for query output. Deliberately not a tab: tab counts as IFS
# whitespace, so bash collapses runs of it and an empty column silently shifts
# every later field one to the left. Unit Separator cannot appear in an audience
# (the registration form rejects control characters) and is not IFS whitespace.
readonly SEP=$'\x1f'

# How the database gets opened. Resolved once, below.
DB_URI="file:${DB_PATH}?mode=ro"
QUIESCENT=0

# Read-only helper. Every caller passes a literal SELECT.
query() {
    sqlite3 -readonly -noheader -separator "$SEP" "$DB_URI" "$1"
}

if ! query "SELECT 1;" >/dev/null 2>&1; then
    # A WAL database needs a -shm file, and a read-only connection cannot
    # create one. While the service is running that file exists and mode=ro
    # works; with the service stopped it does not, and mode=ro fails with a
    # bare "unable to open database file" that reads like corruption.
    #
    # immutable=1 tells SQLite the file will not change, so it skips WAL
    # recovery and the -shm entirely. That is only safe when nothing is writing
    # — which is exactly the situation that got us here, since a live writer
    # would have left a -shm for mode=ro to use. Still worth announcing: if the
    # service starts mid-run the read could tear.
    if sqlite3 -readonly "file:${DB_PATH}?immutable=1" "SELECT 1;" >/dev/null 2>&1; then
        DB_URI="file:${DB_PATH}?immutable=1"
        QUIESCENT=1
    else
        echo "error: cannot read $DB_PATH — is it corrupt, or not a database?" >&2
        exit 2
    fi
fi

# Audience lists are stored as JSON arrays. Comparing them as raw text would
# report a false difference whenever two equal sets are stored in a different
# order, so they are normalised with the JSON1 extension.
if ! query "SELECT json_valid('[]');" >/dev/null 2>&1; then
    echo "error: this sqlite3 lacks JSON support (JSON1), which is needed to" >&2
    echo "  compare audience lists without being fooled by element order." >&2
    exit 2
fi

for table in oauth_clients refresh_tokens; do
    if [ -z "$(query "SELECT name FROM sqlite_master WHERE type='table' AND name='${table}';")" ]; then
        echo "error: $DB_PATH has no '${table}' table — wrong database?" >&2
        exit 2
    fi
done

# --- report --------------------------------------------------------------

# sorted_json_array(x) as a reusable SQL fragment: elements sorted and
# comma-joined, so two equal sets always render identically.
readonly NORMALISE="
    CASE
      WHEN __COL__ IS NULL OR __COL__ = '' THEN ''
      ELSE COALESCE((SELECT group_concat(value, ',')
                     FROM (SELECT value FROM json_each(__COL__) ORDER BY value)), '')
    END"

# normalise <column-expression> -> the SQL fragment with that column bound in.
normalise() { echo "${NORMALISE//__COL__/$1}"; }

echo "database: $DB_PATH"
echo "read as:  $(id -un)"
if [ "$QUIESCENT" -eq 1 ]; then
    echo "note:     no live writer detected; read in immutable mode."
    echo "          If the identity service is stopped this is expected. If it is"
    echo "          supposed to be running, that is worth knowing before you trust"
    echo "          these numbers."
fi
echo

echo "=== Registered clients ==="
printf '%-28s %s\n' "CLIENT" "REGISTERED AUDIENCES"
query "
    SELECT id, $(normalise audiences)
    FROM oauth_clients
    ORDER BY id;
" | while IFS="$SEP" read -r id auds; do
    printf '%-28s %s\n' "$id" "${auds:-<none>}"
done
echo

echo "=== Live sessions, and what refresh will do to them ==="
echo
printf '%-18s %5s  %-34s %-34s %s\n' "CLIENT" "SESS" "CARRIED NOW" "AFTER NEXT REFRESH" "VERDICT"

# One row per (client, distinct audience set currently carried). Splitting by
# carried set matters: two sessions of the same client can disagree, which is
# precisely the migration-011 damage this is meant to surface.
REPORT=$(query "
    SELECT
      COALESCE(NULLIF(t.client_id, ''), '<unbound>')            AS client,
      COUNT(*)                                                  AS sessions,
      $(normalise t.audiences)                             AS carried,
      CASE
        WHEN t.client_id IS NULL OR t.client_id = '' THEN $(normalise t.audiences)
        WHEN c.id IS NULL THEN ''
        ELSE $(normalise c.audiences)
      END                                                       AS after,
      CASE
        WHEN t.client_id IS NULL OR t.client_id = '' THEN 'unbound'
        WHEN c.id IS NULL THEN 'no-registration'
        ELSE 'bound'
      END                                                       AS kind
    FROM refresh_tokens t
    LEFT JOIN oauth_clients c ON c.id = t.client_id
    WHERE t.is_revoked = 0
      -- Both sides stripped of the trailing Z and compared as text. Using
      -- datetime() would be cleaner but returns NULL on older sqlite builds
      -- that reject the Z suffix, which would silently exclude every row.
      AND replace(t.expires_at, 'Z', '') > strftime('%Y-%m-%dT%H:%M:%f', 'now')
    GROUP BY client, carried, after, kind
    ORDER BY client, carried;
")

losers=0
gainers=0
orphans=0
rows=0

if [ -z "$REPORT" ]; then
    echo "  (no live refresh tokens)"
else
    while IFS="$SEP" read -r client sessions carried after kind; do
        rows=$((rows + 1))
        verdict=""
        case "$kind" in
            unbound)
                verdict="unchanged — direct login, no registration to consult"
                ;;
            no-registration)
                if [ -z "$carried" ]; then
                    # Orphaned, but carrying nothing, so nothing is lost. Worth
                    # showing — the client is gone and these sessions will never
                    # be repaired — but it is not an impact, and counting it as
                    # one fires the warning below on a false alarm.
                    verdict="unchanged — client '$client' is not registered, but carried nothing"
                else
                    orphans=$((orphans + 1))
                    verdict="LOSES ALL — client '$client' is not registered"
                fi
                ;;
            bound)
                if [ "$carried" = "$after" ]; then
                    verdict="unchanged"
                else
                    lost=""
                    gained=""
                    # Set difference both ways, on comma-separated sorted lists.
                    IFS=',' read -ra now_arr <<< "$carried"
                    IFS=',' read -ra new_arr <<< "$after"
                    for a in "${now_arr[@]}"; do
                        [ -z "$a" ] && continue
                        found=0
                        for b in "${new_arr[@]}"; do [ "$a" = "$b" ] && found=1 && break; done
                        [ "$found" -eq 0 ] && lost="${lost:+$lost,}$a"
                    done
                    for b in "${new_arr[@]}"; do
                        [ -z "$b" ] && continue
                        found=0
                        for a in "${now_arr[@]}"; do [ "$a" = "$b" ] && found=1 && break; done
                        [ "$found" -eq 0 ] && gained="${gained:+$gained,}$b"
                    done
                    [ -n "$lost" ] && { losers=$((losers + 1)); verdict="LOSES: $lost"; }
                    [ -n "$gained" ] && { gainers=$((gainers + 1)); verdict="${verdict:+$verdict; }gains: $gained"; }
                fi
                ;;
        esac
        printf '%-18s %5s  %-34s %-34s %s\n' \
            "$client" "$sessions" "${carried:-<none>}" "${after:-<none>}" "$verdict"
    done <<< "$REPORT"
fi

echo
echo "=== Client authentication on /api/v1/auth/refresh (#40) ==="
echo
echo "  That endpoint authenticates no client. From #40 onward a session"
echo "  belonging to a CONFIDENTIAL client (one with a registered secret) is"
echo "  refused there and must refresh at /oauth/token instead. Public and"
echo "  device-grant clients are unaffected — that is the endpoint firmware uses."
echo
printf '%-18s %-14s %5s  %s\n' "CLIENT" "KIND" "SESS" "EFFECT"

CONFIDENTIAL=$(query "
    SELECT
      c.id,
      CASE WHEN c.client_secret_hash IS NOT NULL AND c.client_secret_hash != ''
           THEN 'confidential' ELSE 'public' END,
      COUNT(t.id)
    FROM oauth_clients c
    LEFT JOIN refresh_tokens t
      ON t.client_id = c.id
     AND t.is_revoked = 0
     AND replace(t.expires_at, 'Z', '') > strftime('%Y-%m-%dT%H:%M:%f', 'now')
    GROUP BY c.id
    ORDER BY c.id;
")

affected=0
while IFS="$SEP" read -r cid kind sess; do
    [ -z "$cid" ] && continue
    effect="none"
    if [ "$kind" = "confidential" ] && [ "${sess:-0}" -gt 0 ]; then
        affected=$((affected + sess))
        effect="REFUSED at /api/v1/auth/refresh — must use /oauth/token"
    elif [ "$kind" = "confidential" ]; then
        effect="none (no live sessions)"
    fi
    printf '%-18s %-14s %5s  %s\n' "$cid" "$kind" "${sess:-0}" "$effect"
done <<< "$CONFIDENTIAL"

echo
if [ "$affected" -gt 0 ]; then
    echo "  $affected live session(s) belong to confidential clients."
    echo "  If any of them refresh at /api/v1/auth/refresh they will now get 401"
    echo "  client_authentication_required. The token is NOT consumed, so the fix"
    echo "  is to retry at /oauth/token with the client secret."
else
    echo "  No live session belongs to a confidential client — #40 changes nothing"
    echo "  observable for current traffic."
fi

echo
echo "=== Management plane exclusivity (#37) ==="
echo
echo "  From #37 onward the management routes — GET/POST /api/v1/users,"
echo "  PUT/DELETE /api/v1/users/{id}, and the admin passkey login bridge —"
echo "  require a token naming this server ($SELF) and nothing else. A token"
echo "  delegated to sibling services is a bearer credential at each of them,"
echo "  so it must not also administer identity."
echo
echo "  Only ADMIN accounts can reach those routes at all, so only their"
echo "  sessions can be affected. Ordinary routes are unchanged."
echo
printf '%-18s %-14s %5s  %-34s %s\n' "CLIENT" "USER" "SESS" "AUDIENCE AFTER REFRESH" "MANAGEMENT PLANE"

ADMIN_ROWS=$(query "
    SELECT
      COALESCE(NULLIF(t.client_id, ''), '<unbound>'),
      u.username,
      COUNT(*),
      CASE
        WHEN t.client_id IS NULL OR t.client_id = '' THEN $(normalise t.audiences)
        WHEN c.id IS NULL THEN ''
        ELSE $(normalise c.audiences)
      END
    FROM refresh_tokens t
    JOIN users u ON u.id = t.user_id AND u.role = 'admin'
    LEFT JOIN oauth_clients c ON c.id = t.client_id
    WHERE t.is_revoked = 0
      AND replace(t.expires_at, 'Z', '') > strftime('%Y-%m-%dT%H:%M:%f', 'now')
    GROUP BY 1, 2, 4
    ORDER BY 1, 2;
")

locked=0
if [ -z "$ADMIN_ROWS" ]; then
    echo "  (no live sessions belong to an admin account — nothing can be affected)"
else
    while IFS="$SEP" read -r cid uname sess auds; do
        [ -z "$cid" ] && continue
        verdict="allowed"
        if [ -n "$auds" ]; then
            IFS=',' read -ra list <<< "$auds"
            for a in "${list[@]}"; do
                [ -z "$a" ] && continue
                if [ "$a" != "$SELF" ] && [ "$a" != "https://$SELF" ]; then
                    locked=$((locked + sess))
                    verdict="REFUSED — delegated to '$a'"
                    break
                fi
            done
        fi
        printf '%-18s %-14s %5s  %-34s %s\n' "$cid" "$uname" "$sess" "${auds:-<none>}" "$verdict"
    done <<< "$ADMIN_ROWS"
fi

echo
if [ "$locked" -gt 0 ]; then
    echo "  $locked admin session(s) will be refused on the management routes."
    echo "  They keep working on the ordinary routes and in the admin UI via"
    echo "  password or passkey login. To administer via the API they need a"
    echo "  token from a direct /api/v1/auth/login (which carries no audience)"
    echo "  or from a client registered for this server alone."
else
    echo "  No admin session is affected by #37."
fi

echo
echo "=== Summary ==="
echo "  session groups examined: $rows"
echo "  groups gaining an audience: $gainers   (these repair themselves on refresh)"
echo "  groups losing an audience:  $losers"
echo "  groups whose client is unregistered: $orphans"
echo

if [ "$losers" -gt 0 ] || [ "$orphans" -gt 0 ]; then
    cat <<'WARN'
  Sessions that lose an audience will start failing against any resource server
  enforcing it, within one access-token lifetime of the deploy. Fix the client
  registration first — that is the authoritative source after #39 — and re-run.
WARN
else
    echo "  No live session loses an audience."
fi

if [ "$locked" -gt 0 ]; then
    echo "  $locked admin session(s) lose management-plane access — see #37 above."
fi

# One exit decision, so a new impact category cannot be added above without
# being reflected here.
if [ "$STRICT" -eq 1 ] && { [ "$losers" -gt 0 ] || [ "$orphans" -gt 0 ] || [ "$locked" -gt 0 ]; }; then
    exit 3
fi
