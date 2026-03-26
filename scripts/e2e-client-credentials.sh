#!/usr/bin/env bash
#
# End-to-end test suite for the Client Credentials flow.
# Runs against a live server — start it first:
#
#   ADMIN_USERNAME=admin ADMIN_PASSWORD=adminpassword1 \
#     PORT=8181 ./bin/identity-server
#
# Then:
#   ./scripts/e2e-client-credentials.sh [base_url]
#
# Default base URL: http://localhost:8181
#
# Credentials (override for non-default environments):
#   ADMIN_USERNAME   default: admin
#   ADMIN_PASSWORD   default: adminpassword1

BASE="${1:-http://localhost:8181}"
ADMIN_USER="${ADMIN_USERNAME:-admin}"
ADMIN_PASS="${ADMIN_PASSWORD:-adminpassword1}"
# Pause between token endpoint requests to respect rate limiting.
# Set to 0 when RATE_LIMIT_DISABLED=1 (local dev), or ~13s for production
# (server allows 5 req/min = 1 per 12s).
RATE_WAIT="${RATE_WAIT:-0}"
PASS=0
FAIL=0

# Wrapper: sleep before hitting rate-limited endpoints (token, introspect).
rate_sleep() { [ "$RATE_WAIT" -gt 0 ] && sleep "$RATE_WAIT" || true; }

check() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "  ✓ $desc"
    PASS=$((PASS+1))
  else
    echo "  ✗ $desc (expected: $expected, got: $actual)"
    FAIL=$((FAIL+1))
  fi
}

check_contains() {
  local desc="$1" needle="$2" haystack="$3"
  if echo "$haystack" | grep -q "$needle"; then
    echo "  ✓ $desc"
    PASS=$((PASS+1))
  else
    echo "  ✗ $desc (expected to contain: $needle)"
    FAIL=$((FAIL+1))
  fi
}

check_not_contains() {
  local desc="$1" needle="$2" haystack="$3"
  if echo "$haystack" | grep -q "$needle"; then
    echo "  ✗ $desc (should NOT contain: $needle)"
    FAIL=$((FAIL+1))
  else
    echo "  ✓ $desc"
    PASS=$((PASS+1))
  fi
}

# ── 0. Login to admin UI ──────────────────────────────────────────────

echo "=== 0. Admin login ==="
RESP=$(curl -s -D- -o /dev/null -X POST "$BASE/admin/login" \
  -d "username=$ADMIN_USER&password=$ADMIN_PASS" -H "Content-Type: application/x-www-form-urlencoded")
COOKIE=$(echo "$RESP" | grep -i 'set-cookie' | head -1 | sed 's/.*admin_session=//;s/;.*//')
check_contains "Admin session cookie" "eyJ" "$COOKIE"

# Get CSRF token
FORM_HTML=$(curl -s -b "admin_session=$COOKIE" "$BASE/admin/oauth/new")
CSRF=$(echo "$FORM_HTML" | grep '_csrf' | head -1 | sed 's/.*value="//;s/".*//')
check "Got CSRF token (non-empty)" "1" "$([ -n "$CSRF" ] && echo 1 || echo 0)"

# ── 1. Create confidential OAuth client ────────────────────────────

echo ""
echo "=== 1. Create confidential OAuth client ==="

STATUS=$(curl -s -o /dev/null -w '%{http_code}' -b "admin_session=$COOKIE" \
  -X POST "$BASE/admin/oauth/new" \
  -d "_csrf=$CSRF&id=e2e-service&name=E2E+Service&grant_types=client_credentials&token_endpoint_auth_method=client_secret_basic&redirect_uris=&scopes=read:users%0Awrite:users&audience=https://api.test" \
  -H "Content-Type: application/x-www-form-urlencoded")
# 303 = created; 200 = client already exists (form re-rendered) — both are fine
check "Create client (303 or 200)" "ok" "$([ "$STATUS" = "303" ] || [ "$STATUS" = "200" ] && echo ok || echo "HTTP $STATUS")"

# Generate a client secret
FORM_HTML=$(curl -s -b "admin_session=$COOKIE" "$BASE/admin/oauth/e2e-service/edit")
CSRF=$(echo "$FORM_HTML" | grep '_csrf' | head -1 | sed 's/.*value="//;s/".*//')

SECRET_RESP=$(curl -s -b "admin_session=$COOKIE" \
  -X POST "$BASE/admin/oauth/e2e-service/generate-secret" \
  -d "_csrf=$CSRF&admin_password=$ADMIN_PASS" \
  -H "Content-Type: application/x-www-form-urlencoded")
CLIENT_SECRET=$(echo "$SECRET_RESP" | grep -o '<code>[^<]*</code>' | head -1 | sed 's/<[^>]*>//g')
check "Client secret non-empty" "1" "$([ -n "$CLIENT_SECRET" ] && echo 1 || echo 0)"
echo "  (secret: ${CLIENT_SECRET:0:8}...)"

# ── 2. Client credentials token request ────────────────────────────

echo ""
echo "=== 2. Client credentials token request ==="

BASIC_AUTH=$(echo -n "e2e-service:$CLIENT_SECRET" | base64 -w0)

rate_sleep
TOKEN_RESP=$(curl -s -X POST "$BASE/oauth/token" \
  -H "Authorization: Basic $BASIC_AUTH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=read:users")
check_contains "Response has access_token" "access_token" "$TOKEN_RESP"
check_not_contains "Response has no refresh_token" "refresh_token" "$TOKEN_RESP"
check_contains "Response has expires_in" "expires_in" "$TOKEN_RESP"
check_contains "Response has scope" '"scope"' "$TOKEN_RESP"

ACCESS_TOKEN=$(echo "$TOKEN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")

# ── 3. JWT claims validation ───────────────────────────────────────

echo ""
echo "=== 3. JWT claims validation ==="

if [ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ]; then
  # Decode JWT payload (base64url → base64 → json)
  PAYLOAD=$(echo "$ACCESS_TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null)
  check_contains "Token has iss claim" '"iss"' "$PAYLOAD"
  check_contains "Token has sub = client_id" '"sub":"e2e-service"' "$PAYLOAD"
  check_contains "Token has client_id claim" '"client_id":"e2e-service"' "$PAYLOAD"
  check_contains "Token has jti claim" '"jti"' "$PAYLOAD"
  check_contains "Token has aud claim" '"aud"' "$PAYLOAD"
  check_contains "Token has scope claim" '"scope"' "$PAYLOAD"
  check_not_contains "Token has no usr (username)" '"usr"' "$PAYLOAD"
  check_not_contains "Token has no rol (role)" '"rol"' "$PAYLOAD"
else
  echo "  ✗ Skipping JWT claims — no access token received"
  FAIL=$((FAIL+8))
fi

# ── 4. Client authentication methods ──────────────────────────────

echo ""
echo "=== 4. Client authentication methods ==="

# client_secret_basic
rate_sleep
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/oauth/token" \
  -H "Authorization: Basic $BASIC_AUTH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials")
check "client_secret_basic = 200" "200" "$STATUS"

# Wrong secret
WRONG_AUTH=$(echo -n "e2e-service:wrong-secret" | base64 -w0)
rate_sleep
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/oauth/token" \
  -H "Authorization: Basic $WRONG_AUTH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials")
check "Wrong secret = 401" "401" "$STATUS"

# No credentials
rate_sleep
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials")
check "No credentials = 401" "401" "$STATUS"

# Unknown client
BAD_AUTH=$(echo -n "nonexistent:secret" | base64 -w0)
rate_sleep
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/oauth/token" \
  -H "Authorization: Basic $BAD_AUTH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials")
check "Unknown client = 401" "401" "$STATUS"

# ── 5. Scope validation ───────────────────────────────────────────

echo ""
echo "=== 5. Scope validation ==="

# Request allowed scope
rate_sleep
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/oauth/token" \
  -H "Authorization: Basic $BASIC_AUTH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=read:users")
check "Allowed scope = 200" "200" "$STATUS"

# Request disallowed scope
rate_sleep
RESP=$(curl -s -X POST "$BASE/oauth/token" \
  -H "Authorization: Basic $BASIC_AUTH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=delete:everything")
STATUS=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',''))" 2>/dev/null || echo "")
check "Disallowed scope = invalid_scope" "invalid_scope" "$STATUS"

# Request subset of allowed scopes
rate_sleep
RESP=$(curl -s -X POST "$BASE/oauth/token" \
  -H "Authorization: Basic $BASIC_AUTH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=read:users")
SCOPE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scope',''))" 2>/dev/null || echo "")
check "Subset scope matches request" "read:users" "$SCOPE"

# ── 6. Discovery endpoint ─────────────────────────────────────────

echo ""
echo "=== 6. Discovery endpoint ==="

DISC_RESP=$(curl -s "$BASE/.well-known/oauth-authorization-server")
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/.well-known/oauth-authorization-server")
check "GET discovery = 200" "200" "$STATUS"
check_contains "Has token_endpoint" "token_endpoint" "$DISC_RESP"
check_contains "Has grant_types_supported with client_credentials" "client_credentials" "$DISC_RESP"
check_contains "Has jwks_uri" "jwks_uri" "$DISC_RESP"
check_contains "Has introspection_endpoint" "introspection_endpoint" "$DISC_RESP"

# ── 7. Introspection ──────────────────────────────────────────────

echo ""
echo "=== 7. Introspection ==="

if [ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ]; then
  # Valid token
  rate_sleep
  INTRO_RESP=$(curl -s -X POST "$BASE/oauth/introspect" \
    -H "Authorization: Basic $BASIC_AUTH" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "token=$ACCESS_TOKEN")
  check_contains "Introspect valid token: active=true" '"active":true' "$INTRO_RESP"
  check_contains "Introspect has client_id" '"client_id"' "$INTRO_RESP"

  # Garbage token
  rate_sleep
  INTRO_RESP=$(curl -s -X POST "$BASE/oauth/introspect" \
    -H "Authorization: Basic $BASIC_AUTH" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "token=this.is.garbage")
  check_contains "Introspect invalid token: active=false" '"active":false' "$INTRO_RESP"

  # No client auth
  rate_sleep
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/oauth/introspect" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "token=$ACCESS_TOKEN")
  check "Introspect without auth = 401" "401" "$STATUS"
else
  echo "  ✗ Skipping introspection — no access token"
  FAIL=$((FAIL+4))
fi

# ── 8. Secret rotation ────────────────────────────────────────────

echo ""
echo "=== 8. Secret rotation ==="

# Rotate the secret
FORM_HTML=$(curl -s -b "admin_session=$COOKIE" "$BASE/admin/oauth/e2e-service/edit")
CSRF=$(echo "$FORM_HTML" | grep '_csrf' | head -1 | sed 's/.*value="//;s/".*//')

ROTATE_RESP=$(curl -s -b "admin_session=$COOKIE" \
  -X POST "$BASE/admin/oauth/e2e-service/rotate-secret" \
  -d "_csrf=$CSRF&admin_password=$ADMIN_PASS" \
  -H "Content-Type: application/x-www-form-urlencoded")
NEW_SECRET=$(echo "$ROTATE_RESP" | grep -o '<code>[^<]*</code>' | head -1 | sed 's/<[^>]*>//g')
check "New secret non-empty" "1" "$([ -n "$NEW_SECRET" ] && echo 1 || echo 0)"
echo "  (new secret: ${NEW_SECRET:0:8}...)"

# New secret works
NEW_BASIC_AUTH=$(echo -n "e2e-service:$NEW_SECRET" | base64 -w0)
rate_sleep
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/oauth/token" \
  -H "Authorization: Basic $NEW_BASIC_AUTH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials")
check "New secret works = 200" "200" "$STATUS"

# Old secret still works (prev hash)
rate_sleep
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/oauth/token" \
  -H "Authorization: Basic $BASIC_AUTH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials")
check "Old secret still works = 200" "200" "$STATUS"

# Clear previous secret
FORM_HTML=$(curl -s -b "admin_session=$COOKIE" "$BASE/admin/oauth/e2e-service/edit")
CSRF=$(echo "$FORM_HTML" | grep '_csrf' | head -1 | sed 's/.*value="//;s/".*//')

curl -s -o /dev/null -b "admin_session=$COOKIE" \
  -X POST "$BASE/admin/oauth/e2e-service/clear-prev-secret" \
  -d "_csrf=$CSRF&admin_password=$ADMIN_PASS" \
  -H "Content-Type: application/x-www-form-urlencoded"

# Old secret now fails
rate_sleep
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/oauth/token" \
  -H "Authorization: Basic $BASIC_AUTH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials")
check "Old secret after clear = 401" "401" "$STATUS"

# ── Cleanup ───────────────────────────────────────────────────────

FORM_HTML=$(curl -s -b "admin_session=$COOKIE" "$BASE/admin/oauth/e2e-service/edit")
CSRF=$(echo "$FORM_HTML" | grep '_csrf' | head -1 | sed 's/.*value="//;s/".*//')
curl -s -o /dev/null -b "admin_session=$COOKIE" \
  -X POST "$BASE/admin/oauth/e2e-service/delete" \
  -d "_csrf=$CSRF&admin_password=$ADMIN_PASS" \
  -H "Content-Type: application/x-www-form-urlencoded"

# ── Summary ───────────────────────────────────────────────────────

echo ""
echo "════════════════════════════"
echo "  PASS: $PASS   FAIL: $FAIL"
echo "════════════════════════════"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
