#!/usr/bin/env bash
# Which registered clients would still be accepted by a service that starts
# requiring AUD? Run on the identity host.
#
#   sudo -u identity ./audit-audience.sh config
AUD="${1:?usage: $0 <audience>}"
DB="${DB_PATH:-/var/lib/identity/identity.db}"
sqlite3 "$DB" "
  SELECT
    CASE WHEN EXISTS (SELECT 1 FROM json_each(audiences) WHERE value = '$AUD')
         THEN '  ACCEPTED  ' ELSE '  REJECTED  ' END
    || id || '   (' || audiences || ')'
  FROM oauth_clients
  ORDER BY 1 DESC, id;"
