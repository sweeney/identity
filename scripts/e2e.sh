#!/usr/bin/env bash
#
# End-to-end test suite for the Identity service.
# Runs against a live server — start it first:
#
#   JWT_SECRET="<32+ chars>" ADMIN_USERNAME=admin ADMIN_PASSWORD=adminpassword1 \
#     PORT=8181 ./bin/identity-server
#
# Then:
#   ./scripts/e2e.sh [base_url]
#
# Default base URL: http://localhost:8181
#
# Environment variables:
#   ADMIN_PASSWORD   default: adminpassword1
#   ADMIN_USERNAME   default: admin

BASE="${1:-http://localhost:8181}"
ADMIN_USER="${ADMIN_USERNAME:-admin}"
ADMIN_PASS="${ADMIN_PASSWORD:-adminpassword1}"
PASS=0
FAIL=0

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

# ── 1. Health + Security Headers ──────────────────────────────────────

echo "=== 1. Health + Security Headers ==="
HEADERS=$(curl -s -D- -o /dev/null "$BASE/health")
check "GET /health" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/health")"
check_contains "X-Frame-Options: DENY" "DENY" "$HEADERS"
check_contains "X-Content-Type-Options: nosniff" "nosniff" "$HEADERS"
check_contains "Strict-Transport-Security" "max-age=" "$HEADERS"
check_contains "Content-Security-Policy" "default-src" "$HEADERS"
check_contains "Referrer-Policy" "strict-origin" "$HEADERS"

# ── 2. Admin login ────────────────────────────────────────────────────

echo ""
echo "=== 2. Admin login ==="
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/admin/login" \
  -d "username=admin&password=wrong" -H "Content-Type: application/x-www-form-urlencoded")
check "Bad creds re-renders form" "200" "$STATUS"

RESP=$(curl -s -D- -o /dev/null -X POST "$BASE/admin/login" \
  -d "username=$ADMIN_USER&password=$ADMIN_PASS" -H "Content-Type: application/x-www-form-urlencoded")
check_contains "Login redirects" "303" "$RESP"
COOKIE=$(echo "$RESP" | grep -i 'set-cookie' | head -1 | sed 's/.*admin_session=//;s/;.*//')
check_contains "Session cookie set" "eyJ" "$COOKIE"
if [[ "$BASE" == https://* ]]; then
  check_contains "Cookie has Secure flag" "Secure" "$RESP"
fi

# ── 3. CSRF protection ───────────────────────────────────────────────

echo ""
echo "=== 3. CSRF protection ==="
FORM_HTML=$(curl -s -b "admin_session=$COOKIE" "$BASE/admin/users/new")
check_contains "Form has CSRF hidden field" "_csrf" "$FORM_HTML"
CSRF=$(echo "$FORM_HTML" | grep '_csrf' | head -1 | sed 's/.*value="//;s/".*//')

STATUS=$(curl -s -o /dev/null -w '%{http_code}' -b "admin_session=$COOKIE" \
  -X POST "$BASE/admin/oauth/new" \
  -d "id=bad&name=Bad&redirect_uris=http://x/cb" \
  -H "Content-Type: application/x-www-form-urlencoded")
check "POST without CSRF token = 403" "403" "$STATUS"

STATUS=$(curl -s -o /dev/null -w '%{http_code}' -b "admin_session=$COOKIE" \
  -X POST "$BASE/admin/oauth/new" \
  -d "_csrf=$CSRF&id=testapp&name=Test+App&redirect_uris=http://localhost:3000/callback" \
  -H "Content-Type: application/x-www-form-urlencoded")
check "POST with CSRF token = 303" "303" "$STATUS"

# ── 4. OAuth client management ────────────────────────────────────────

echo ""
echo "=== 4. OAuth client management ==="
BODY=$(curl -s -b "admin_session=$COOKIE" "$BASE/admin/oauth")
check_contains "Client list shows testapp" "testapp" "$BODY"

STATUS=$(curl -s -o /dev/null -w '%{http_code}' -b "admin_session=$COOKIE" \
  -X POST "$BASE/admin/oauth/testapp/edit" \
  -d "_csrf=$CSRF&name=Test+App+v2&redirect_uris=http://localhost:3000/callback&admin_password=$ADMIN_PASS" \
  -H "Content-Type: application/x-www-form-urlencoded")
check "Edit client = 303" "303" "$STATUS"
BODY=$(curl -s -b "admin_session=$COOKIE" "$BASE/admin/oauth")
check_contains "Updated name shows" "Test App v2" "$BODY"

# ── 4b. OAuth client registration security ───────────────────────────
#
# These tests verify that validation added to fix red-team findings is
# enforced at the HTTP layer, not just in unit tests.

echo ""
echo "=== 4b. OAuth client registration security ==="

# javascript: redirect URI rejected at registration (N3)
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -b "admin_session=$COOKIE" \
  -X POST "$BASE/admin/oauth/new" \
  -d "_csrf=$CSRF&id=sec-test&name=Sec+Test&redirect_uris=javascript:alert(document.cookie)" \
  -H "Content-Type: application/x-www-form-urlencoded")
check "javascript: redirect URI rejected (stays on form)" "200" "$STATUS"

# data: redirect URI rejected at registration (N3)
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -b "admin_session=$COOKIE" \
  -X POST "$BASE/admin/oauth/new" \
  -d "_csrf=$CSRF&id=sec-test&name=Sec+Test&redirect_uris=data:text/html,%3Cscript%3Ex%3C/script%3E" \
  -H "Content-Type: application/x-www-form-urlencoded")
check "data: redirect URI rejected (stays on form)" "200" "$STATUS"

# client_credentials without audience rejected (L2)
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -b "admin_session=$COOKIE" \
  -X POST "$BASE/admin/oauth/new" \
  -d "_csrf=$CSRF&id=sec-test&name=Sec+Test&grant_types=client_credentials&redirect_uris=&audience=" \
  -H "Content-Type: application/x-www-form-urlencoded")
check "client_credentials without audience rejected" "200" "$STATUS"

# Invalid client ID characters rejected (N6) — spaces and slashes not allowed
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -b "admin_session=$COOKIE" \
  -X POST "$BASE/admin/oauth/new" \
  -d "_csrf=$CSRF&id=bad+id%2Fhere&name=Bad+ID&redirect_uris=https://example.com/cb" \
  -H "Content-Type: application/x-www-form-urlencoded")
check "Invalid client ID (spaces/slashes) rejected" "200" "$STATUS"

# Discovery: issuer must not reflect forged Host header (M1)
DISC_HOST=$(curl -s -H "Host: evil.attacker.com" "$BASE/.well-known/oauth-authorization-server")
check_not_contains "Discovery ignores forged Host header" "evil.attacker.com" "$DISC_HOST"

# ── 5. API login ──────────────────────────────────────────────────────

echo ""
echo "=== 5. API login ==="
LOGIN=$(curl -s -X POST "$BASE/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"'$ADMIN_USER'","password":"'$ADMIN_PASS'","device_hint":"e2e-test"}')
ACCESS=$(echo "$LOGIN" | jq -r '.access_token')
REFRESH=$(echo "$LOGIN" | jq -r '.refresh_token')
check_contains "Returns access_token" "eyJ" "$ACCESS"
check "expires_in = 900" "900" "$(echo "$LOGIN" | jq -r '.expires_in')"

# ── 6. GET /auth/me ───────────────────────────────────────────────────

echo ""
echo "=== 6. GET /auth/me ==="
ME=$(curl -s "$BASE/api/v1/auth/me" -H "Authorization: Bearer $ACCESS")
check "me.username = admin" "admin" "$(echo "$ME" | jq -r '.username')"
check "me.role = admin" "admin" "$(echo "$ME" | jq -r '.role')"

# ── 7. User CRUD ──────────────────────────────────────────────────────

echo ""
echo "=== 7. User CRUD ==="
CREATE=$(curl -s -X POST "$BASE/api/v1/users" \
  -H "Content-Type: application/json" -H "Authorization: Bearer $ACCESS" \
  -d '{"username":"alice","display_name":"Alice Smith","password":"alicepassword123","role":"user"}')
ALICE_ID=$(echo "$CREATE" | jq -r '.id')
check "Created alice" "alice" "$(echo "$CREATE" | jq -r '.username')"

check "List users = 2" "2" "$(curl -s "$BASE/api/v1/users" -H "Authorization: Bearer $ACCESS" | jq -r '.total')"

UPDATED=$(curl -s -X PUT "$BASE/api/v1/users/$ALICE_ID" \
  -H "Content-Type: application/json" -H "Authorization: Bearer $ACCESS" \
  -d '{"display_name":"Alice J. Smith"}')
check "Updated display name" "Alice J. Smith" "$(echo "$UPDATED" | jq -r '.display_name')"

# ── 8. Non-admin access controls ──────────────────────────────────────

echo ""
echo "=== 8. Non-admin access controls ==="
ALICE_LOGIN=$(curl -s -X POST "$BASE/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"alicepassword123"}')
ALICE_TOKEN=$(echo "$ALICE_LOGIN" | jq -r '.access_token')

check "Alice GET own record = 200" "200" \
  "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/v1/users/$ALICE_ID" -H "Authorization: Bearer $ALICE_TOKEN")"
check "Alice GET /users = 403" "403" \
  "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/v1/users" -H "Authorization: Bearer $ALICE_TOKEN")"

# ── 8b. New admin can log into admin UI ───────────────────────────────

echo ""
echo "=== 8b. New admin logs into admin UI ==="
# Create a second admin user via API
CREATE_ADMIN=$(curl -s -X POST "$BASE/api/v1/users" \
  -H "Content-Type: application/json" -H "Authorization: Bearer $ACCESS" \
  -d '{"username":"newadmin","display_name":"New Admin","password":"newadminpass123","role":"admin"}')
check "Created newadmin" "admin" "$(echo "$CREATE_ADMIN" | jq -r '.role')"

# Log into admin UI with the new admin
ADMIN2_RESP=$(curl -s -D- -o /dev/null -X POST "$BASE/admin/login" \
  -d "username=newadmin&password=newadminpass123" \
  -H "Content-Type: application/x-www-form-urlencoded")
check_contains "New admin login redirects" "303" "$ADMIN2_RESP"
ADMIN2_COOKIE=$(echo "$ADMIN2_RESP" | grep -i 'set-cookie' | head -1 | sed 's/.*admin_session=//;s/;.*//')
check_contains "New admin gets session" "eyJ" "$ADMIN2_COOKIE"

# Verify new admin can access the dashboard
DASHBOARD=$(curl -s -b "admin_session=$ADMIN2_COOKIE" "$BASE/admin/")
check_contains "New admin sees dashboard" "Dashboard" "$DASHBOARD"

# Verify non-admin cannot log into admin UI
NONADMIN_RESP=$(curl -s -X POST "$BASE/admin/login" \
  -d "username=alice&password=alicepassword123" \
  -H "Content-Type: application/x-www-form-urlencoded")
check_contains "Non-admin rejected" "Admin access required" "$NONADMIN_RESP"

# Clean up: delete the new admin
NEWADMIN_ID=$(echo "$CREATE_ADMIN" | jq -r '.id')
curl -s -o /dev/null -X DELETE "$BASE/api/v1/users/$NEWADMIN_ID" -H "Authorization: Bearer $ACCESS"

# ── 9. Token refresh + theft detection ────────────────────────────────

echo ""
echo "=== 9. Token refresh + theft detection ==="
REFRESHED=$(curl -s -X POST "$BASE/api/v1/auth/refresh" \
  -H "Content-Type: application/json" -d "{\"refresh_token\":\"$REFRESH\"}")
check_contains "Refresh returns new token" "eyJ" "$(echo "$REFRESHED" | jq -r '.access_token')"

REPLAY=$(curl -s -X POST "$BASE/api/v1/auth/refresh" \
  -H "Content-Type: application/json" -d "{\"refresh_token\":\"$REFRESH\"}")
check "Replay = token_family_compromised" "token_family_compromised" "$(echo "$REPLAY" | jq -r '.error')"

# ── 10. OAuth PKCE flow ───────────────────────────────────────────────

echo ""
echo "=== 10. OAuth PKCE flow ==="
VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
STATE="state-$(openssl rand -hex 8)"

# GET authorize — renders login form
AUTH_PAGE=$(curl -s "$BASE/oauth/authorize?response_type=code&client_id=testapp&redirect_uri=http://localhost:3000/callback&code_challenge=$CHALLENGE&code_challenge_method=S256&state=$STATE")
check_contains "Authorize page shows app name" "Test App" "$AUTH_PAGE"
check_contains "Authorize page has login form" "username" "$AUTH_PAGE"

# POST authorize — bad creds
BAD=$(curl -s "$BASE/oauth/authorize" -X POST \
  -d "client_id=testapp&redirect_uri=http://localhost:3000/callback&code_challenge=$CHALLENGE&username=alice&password=wrong" \
  -H "Content-Type: application/x-www-form-urlencoded")
check_contains "Bad creds re-renders form" "Invalid username or password" "$BAD"

# POST authorize — success
# Server uses a JS redirect page (200 + HTML) rather than HTTP 302, to support
# custom URI schemes (myapp://) that CSP form-action would block.
AUTH_RESP=$(curl -s "$BASE/oauth/authorize" -X POST \
  -d "client_id=testapp&redirect_uri=http://localhost:3000/callback&state=$STATE&code_challenge=$CHALLENGE&username=alice&password=alicepassword123" \
  -H "Content-Type: application/x-www-form-urlencoded")
# Server returns a JS redirect page (200) to support custom URI schemes.
# Extract the callback URL from the redirect-link href, decoding HTML entities.
REDIRECT_HREF=$(echo "$AUTH_RESP" | grep -o 'href="http[^"]*"' | head -1 | sed 's/href="//;s/"$//' | sed 's/&amp;/\&/g')
check_contains "Authorize redirects to callback" "http://localhost:3000/callback" "$REDIRECT_HREF"
check_contains "Redirect has code" "code=" "$REDIRECT_HREF"
check_contains "Redirect has state" "state=$STATE" "$REDIRECT_HREF"
CODE=$(echo "$REDIRECT_HREF" | sed 's/.*[?&]code=//;s/&.*//')

# Token exchange
TOKEN_RESP=$(curl -s -X POST "$BASE/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&client_id=testapp&code=$CODE&redirect_uri=http://localhost:3000/callback&code_verifier=$VERIFIER")
OAUTH_ACCESS=$(echo "$TOKEN_RESP" | jq -r '.access_token')
OAUTH_REFRESH=$(echo "$TOKEN_RESP" | jq -r '.refresh_token')
check_contains "Token exchange returns access_token" "eyJ" "$OAUTH_ACCESS"

# Verify token works
check "OAuth token resolves to alice" "alice" \
  "$(curl -s "$BASE/api/v1/auth/me" -H "Authorization: Bearer $OAUTH_ACCESS" | jq -r '.username')"

# Code replay
REPLAY_T=$(curl -s -X POST "$BASE/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&client_id=testapp&code=$CODE&redirect_uri=http://localhost:3000/callback&code_verifier=$VERIFIER")
check "Code replay = invalid_grant" "invalid_grant" "$(echo "$REPLAY_T" | jq -r '.error')"

# OAuth refresh
OAUTH_R=$(curl -s -X POST "$BASE/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$OAUTH_REFRESH")
check_contains "OAuth refresh works" "eyJ" "$(echo "$OAUTH_R" | jq -r '.access_token')"

# ── 11. OAuth error pages ─────────────────────────────────────────────

echo ""
echo "=== 11. OAuth error pages ==="
ERR=$(curl -s "$BASE/oauth/authorize?response_type=code&client_id=nope&redirect_uri=http://x/cb&code_challenge=a&code_challenge_method=S256")
check_contains "Unknown client" "Unknown Client" "$ERR"

ERR=$(curl -s "$BASE/oauth/authorize?response_type=code&client_id=testapp&redirect_uri=http://evil/cb&code_challenge=a&code_challenge_method=S256")
check_contains "Bad redirect URI" "Invalid Redirect URI" "$ERR"

ERR=$(curl -s "$BASE/oauth/authorize?response_type=code&client_id=testapp&redirect_uri=http://localhost:3000/callback&code_challenge=a&code_challenge_method=plain")
check_contains "Rejects plain PKCE" "S256" "$ERR"

# ── 12. Logout ────────────────────────────────────────────────────────

echo ""
echo "=== 12. Logout ==="
ADMIN_L=$(curl -s -X POST "$BASE/api/v1/auth/login" \
  -H "Content-Type: application/json" -d '{"username":"'$ADMIN_USER'","password":"'$ADMIN_PASS'"}')
AT=$(echo "$ADMIN_L" | jq -r '.access_token')
RT=$(echo "$ADMIN_L" | jq -r '.refresh_token')
check "Logout = 204" "204" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/auth/logout" \
    -H "Authorization: Bearer $AT" -H "Content-Type: application/json" \
    -d "{\"refresh_token\":\"$RT\"}")"

# ── 13. Delete user + last admin guard ────────────────────────────────

echo ""
echo "=== 13. Delete user + last admin guard ==="
ADMIN_L2=$(curl -s -X POST "$BASE/api/v1/auth/login" \
  -H "Content-Type: application/json" -d '{"username":"'$ADMIN_USER'","password":"'$ADMIN_PASS'"}')
AT2=$(echo "$ADMIN_L2" | jq -r '.access_token')

check "Delete alice = 204" "204" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$BASE/api/v1/users/$ALICE_ID" -H "Authorization: Bearer $AT2")"

ADMIN_USERS=$(curl -s "$BASE/api/v1/users" -H "Authorization: Bearer $AT2")
ADMIN_ID=$(echo "$ADMIN_USERS" | jq -r '.users[0].id')
check "Cannot delete last admin = 409" "409" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$BASE/api/v1/users/$ADMIN_ID" -H "Authorization: Bearer $AT2")"

# ── 14. Audit log ─────────────────────────────────────────────────────

echo ""
echo "=== 14. Audit log ==="
AUDIT=$(curl -s -b "admin_session=$COOKIE" "$BASE/admin/audit")
check_contains "Shows login events" "login" "$AUDIT"
check_contains "Detail: admin created user alice" "admin created user alice" "$AUDIT"
check_contains "Detail: admin deleted user alice" "admin deleted user alice" "$AUDIT"
check_contains "Shows oauth events" "oauth" "$AUDIT"
check_contains "Shows token compromised" "token compromised" "$AUDIT"
check_contains "Shows IP as localhost" "localhost" "$AUDIT"

# ── 15. Delete OAuth client ───────────────────────────────────────────

echo ""
echo "=== 15. Delete OAuth client ==="
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -b "admin_session=$COOKIE" \
  -X POST "$BASE/admin/oauth/testapp/delete" \
  -d "_csrf=$CSRF&admin_password=$ADMIN_PASS" \
  -H "Content-Type: application/x-www-form-urlencoded")
check "Delete client = 303" "303" "$STATUS"
BODY=$(curl -s -b "admin_session=$COOKIE" "$BASE/admin/oauth")
check_contains "Client list empty" "No OAuth clients" "$BODY"

# ── 16. OpenAPI spec ──────────────────────────────────────────────────

echo ""
echo "=== 16. OpenAPI spec ==="
check "GET /openapi.json = 200" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/openapi.json")"
check "GET /openapi.yaml = 200" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/openapi.yaml")"

# ── 17. DB file permissions ───────────────────────────────────────────

echo ""
echo "=== 17. DB file permissions ==="
if [ -f identity.db ]; then
  PERMS=$(stat -f '%Lp' identity.db 2>/dev/null || stat -c '%a' identity.db 2>/dev/null)
  check "identity.db permissions = 600" "600" "$PERMS"
else
  echo "  - identity.db not in current dir, skipping permission check"
fi

# ── Summary ───────────────────────────────────────────────────────────

echo ""
echo "================================"
echo "  PASSED: $PASS"
echo "  FAILED: $FAIL"
echo "================================"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
