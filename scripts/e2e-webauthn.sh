#!/usr/bin/env bash
#
# End-to-end test suite for WebAuthn / Passkey API endpoints.
# Tests the server-side API contract — cannot test actual biometric
# ceremonies (those require a browser), but exercises every endpoint,
# challenge lifecycle, error path, and auth guard.
#
# Usage:
#   1. Start the identity server with passkeys enabled:
#
#      ADMIN_USERNAME=admin ADMIN_PASSWORD=adminpassword1 \
#        RATE_LIMIT_DISABLED=1 ./bin/identity-server
#
#   2. Run:
#      ./scripts/e2e-webauthn.sh [base_url]
#
# Default base URL: http://localhost:8181

set -euo pipefail

BASE="${1:-http://localhost:8181}"
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

check_not_empty() {
  local desc="$1" value="$2"
  if [ -n "$value" ] && [ "$value" != "null" ]; then
    echo "  ✓ $desc"
    PASS=$((PASS+1))
  else
    echo "  ✗ $desc (was empty or null)"
    FAIL=$((FAIL+1))
  fi
}

# ── Setup: get an admin access token ──────────────────────────────

echo "=== Setup ==="
LOGIN=$(curl -s -X POST "$BASE/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"adminpassword1"}')
ACCESS=$(echo "$LOGIN" | jq -r '.access_token')
if [ -z "$ACCESS" ] || [ "$ACCESS" = "null" ]; then
  echo "FATAL: could not log in as admin — is the server running?"
  echo "Response: $LOGIN"
  exit 1
fi
echo "  ✓ Admin login successful"
PASS=$((PASS+1))

# Create a test user for passkey tests
CREATE=$(curl -s -X POST "$BASE/api/v1/users" \
  -H "Content-Type: application/json" -H "Authorization: Bearer $ACCESS" \
  -d '{"username":"passkeyuser","display_name":"Passkey User","password":"passkey-test-pw1","role":"user"}')
PK_USER_ID=$(echo "$CREATE" | jq -r '.id')
if [ -z "$PK_USER_ID" ] || [ "$PK_USER_ID" = "null" ]; then
  echo "  - passkeyuser already exists, fetching..."
  PK_USER_ID=$(curl -s "$BASE/api/v1/users" -H "Authorization: Bearer $ACCESS" \
    | jq -r '.users[] | select(.username=="passkeyuser") | .id')
fi

# Log in as the test user
PK_LOGIN=$(curl -s -X POST "$BASE/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"passkeyuser","password":"passkey-test-pw1"}')
PK_TOKEN=$(echo "$PK_LOGIN" | jq -r '.access_token')
check_not_empty "Test user login" "$PK_TOKEN"

# ── 1. WebAuthn Login Begin — Discoverable Flow ──────────────────

echo ""
echo "=== 1. WebAuthn Login Begin (discoverable) ==="

RESP=$(curl -s -X POST "$BASE/api/v1/webauthn/login/begin" \
  -H "Content-Type: application/json" -d '{}')
CHALLENGE_ID=$(echo "$RESP" | jq -r '.challenge_id')
CHALLENGE=$(echo "$RESP" | jq -r '.publicKey.challenge')
RPID=$(echo "$RESP" | jq -r '.publicKey.rpId')

check_not_empty "Returns challenge_id" "$CHALLENGE_ID"
check_not_empty "Returns challenge" "$CHALLENGE"
check "rpId = localhost" "localhost" "$RPID"
# Discoverable flow should not have allowCredentials
ALLOW_CREDS=$(echo "$RESP" | jq -r '.publicKey.allowCredentials // empty')
check "No allowCredentials (discoverable)" "" "$ALLOW_CREDS"

# ── 2. WebAuthn Login Begin — With Username (no creds) ────────────

echo ""
echo "=== 2. WebAuthn Login Begin (username, no passkeys) ==="

# Should return 200 with a discoverable challenge (same as unknown user)
# to prevent username enumeration
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/webauthn/login/begin" \
  -H "Content-Type: application/json" -d '{"username":"passkeyuser"}')
check "User with no passkeys = 200" "200" "$STATUS"

RESP=$(curl -s -X POST "$BASE/api/v1/webauthn/login/begin" \
  -H "Content-Type: application/json" -d '{"username":"passkeyuser"}')
NO_CREDS_CH=$(echo "$RESP" | jq -r '.challenge_id')
check_not_empty "Returns challenge_id for user with no passkeys" "$NO_CREDS_CH"
# Verify no allowCredentials (indistinguishable from unknown user)
ALLOW_CREDS=$(echo "$RESP" | jq -r '.publicKey.allowCredentials // empty')
check "No allowCredentials (no passkeys)" "" "$ALLOW_CREDS"

# ── 3. WebAuthn Login Begin — Unknown User ────────────────────────

echo ""
echo "=== 3. WebAuthn Login Begin (unknown user) ==="

RESP=$(curl -s -X POST "$BASE/api/v1/webauthn/login/begin" \
  -H "Content-Type: application/json" -d '{"username":"nonexistent-user-xyz"}')
STATUS=$(echo "$RESP" | jq -r '.challenge_id')
# Should return a fake challenge to prevent user enumeration
check_not_empty "Fake challenge for unknown user" "$STATUS"

# ── 4. WebAuthn Login Finish — Missing challenge_id ───────────────

echo ""
echo "=== 4. WebAuthn Login Finish (missing challenge_id) ==="

STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/webauthn/login/finish" \
  -H "Content-Type: application/json" -d '{}')
check "Missing challenge_id = 400" "400" "$STATUS"

# ── 5. WebAuthn Login Finish — Invalid challenge_id ───────────────

echo ""
echo "=== 5. WebAuthn Login Finish (invalid challenge_id) ==="

STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "$BASE/api/v1/webauthn/login/finish?challenge_id=bogus-challenge-id" \
  -H "Content-Type: application/json" -d '{}')
check "Invalid challenge = 400" "400" "$STATUS"

RESP=$(curl -s -X POST "$BASE/api/v1/webauthn/login/finish?challenge_id=bogus-challenge-id" \
  -H "Content-Type: application/json" -d '{}')
check "Error = webauthn_invalid_challenge" "webauthn_invalid_challenge" "$(echo "$RESP" | jq -r '.error')"

# ── 6. WebAuthn Register Begin — Unauthenticated ─────────────────

echo ""
echo "=== 6. WebAuthn Register Begin (unauthenticated) ==="

STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/webauthn/register/begin")
check "No auth = 401" "401" "$STATUS"

# ── 7. WebAuthn Register Begin — Authenticated ───────────────────

echo ""
echo "=== 7. WebAuthn Register Begin (authenticated) ==="

RESP=$(curl -s -X POST "$BASE/api/v1/webauthn/register/begin" \
  -H "Authorization: Bearer $PK_TOKEN")
REG_CHALLENGE_ID=$(echo "$RESP" | jq -r '.challenge_id')
REG_CHALLENGE=$(echo "$RESP" | jq -r '.publicKey.challenge')
REG_RPID=$(echo "$RESP" | jq -r '.publicKey.rp.id')
REG_USER_NAME=$(echo "$RESP" | jq -r '.publicKey.user.name')

check_not_empty "Returns challenge_id" "$REG_CHALLENGE_ID"
check_not_empty "Returns challenge" "$REG_CHALLENGE"
check "rp.id = localhost" "localhost" "$REG_RPID"
check "user.name = passkeyuser" "passkeyuser" "$REG_USER_NAME"

# ── 8. WebAuthn Register Finish — Missing challenge_id ────────────

echo ""
echo "=== 8. WebAuthn Register Finish (missing challenge_id) ==="

STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/webauthn/register/finish" \
  -H "Authorization: Bearer $PK_TOKEN")
check "Missing challenge_id = 400" "400" "$STATUS"

# ── 9. WebAuthn Register Finish — Invalid challenge ───────────────

echo ""
echo "=== 9. WebAuthn Register Finish (invalid challenge) ==="

STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "$BASE/api/v1/webauthn/register/finish?challenge_id=bogus" \
  -H "Authorization: Bearer $PK_TOKEN" -H "Content-Type: application/json" -d '{}')
check "Invalid challenge = 400" "400" "$STATUS"

RESP=$(curl -s -X POST "$BASE/api/v1/webauthn/register/finish?challenge_id=bogus" \
  -H "Authorization: Bearer $PK_TOKEN" -H "Content-Type: application/json" -d '{}')
check "Error = webauthn_invalid_challenge" "webauthn_invalid_challenge" "$(echo "$RESP" | jq -r '.error')"

# ── 10. WebAuthn Credentials — List (empty) ──────────────────────

echo ""
echo "=== 10. WebAuthn Credentials List (empty) ==="

RESP=$(curl -s "$BASE/api/v1/webauthn/credentials" -H "Authorization: Bearer $PK_TOKEN")
TOTAL=$(echo "$RESP" | jq -r '.total')
check "No credentials initially" "0" "$TOTAL"

# ── 11. WebAuthn Credentials — List (unauthenticated) ────────────

echo ""
echo "=== 11. WebAuthn Credentials (unauthenticated) ==="

STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/v1/webauthn/credentials")
check "No auth = 401" "401" "$STATUS"

# ── 12. WebAuthn Credentials — Delete non-existent ───────────────

echo ""
echo "=== 12. WebAuthn Delete non-existent credential ==="

STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE \
  "$BASE/api/v1/webauthn/credentials/does-not-exist" \
  -H "Authorization: Bearer $PK_TOKEN")
check "Delete non-existent = 404" "404" "$STATUS"

# ── 13. WebAuthn Credentials — Rename non-existent ───────────────

echo ""
echo "=== 13. WebAuthn Rename non-existent credential ==="

STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X PATCH \
  "$BASE/api/v1/webauthn/credentials/does-not-exist" \
  -H "Authorization: Bearer $PK_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"test"}')
check "Rename non-existent = 404" "404" "$STATUS"

# ── 14. Challenge expiry / single-use ─────────────────────────────

echo ""
echo "=== 14. Challenge lifecycle ==="

# Begin a login, get challenge, then try to use it with garbage — it should be consumed
RESP=$(curl -s -X POST "$BASE/api/v1/webauthn/login/begin" \
  -H "Content-Type: application/json" -d '{}')
CH_ID=$(echo "$RESP" | jq -r '.challenge_id')
check_not_empty "Got challenge" "$CH_ID"

# Try to finish with garbage body — should fail with verification error, not challenge error
# (challenge is found but verification fails, then challenge is deleted)
FINISH_RESP=$(curl -s -X POST "$BASE/api/v1/webauthn/login/finish?challenge_id=$CH_ID" \
  -H "Content-Type: application/json" -d '{"id":"x","rawId":"eA","type":"public-key","response":{"authenticatorData":"eA","clientDataJSON":"eA","signature":"eA"}}')
FINISH_ERR=$(echo "$FINISH_RESP" | jq -r '.error')
# Either verification_failed or invalid_challenge is acceptable
check_contains "Challenge consumed on use" "webauthn_" "$FINISH_ERR"

# Try to reuse the same challenge — should be gone
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "$BASE/api/v1/webauthn/login/finish?challenge_id=$CH_ID" \
  -H "Content-Type: application/json" -d '{}')
check "Reused challenge = 400" "400" "$STATUS"

RESP=$(curl -s -X POST "$BASE/api/v1/webauthn/login/finish?challenge_id=$CH_ID" \
  -H "Content-Type: application/json" -d '{}')
check "Reused challenge error" "webauthn_invalid_challenge" "$(echo "$RESP" | jq -r '.error')"

# ── 15. Cross-user challenge isolation ────────────────────────────

echo ""
echo "=== 15. Cross-user challenge isolation ==="

# Begin registration as passkeyuser
RESP=$(curl -s -X POST "$BASE/api/v1/webauthn/register/begin" \
  -H "Authorization: Bearer $PK_TOKEN")
CROSS_CH=$(echo "$RESP" | jq -r '.challenge_id')

# Try to finish as admin — should fail (different user)
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "$BASE/api/v1/webauthn/register/finish?challenge_id=$CROSS_CH" \
  -H "Authorization: Bearer $ACCESS" -H "Content-Type: application/json" -d '{}')
check "Cross-user challenge = 400" "400" "$STATUS"

# ── 16. WebAuthn routes disabled when no service ──────────────────
# (Can't easily test this against a running server that has passkeys enabled,
#  but we verify the routes exist and respond correctly)

echo ""
echo "=== 16. Route availability ==="

STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/webauthn/login/begin" \
  -H "Content-Type: application/json" -d '{}')
check "login/begin route exists" "200" "$STATUS"

STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/webauthn/register/begin" \
  -H "Authorization: Bearer $PK_TOKEN")
check "register/begin route exists" "200" "$STATUS"

STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/v1/webauthn/credentials" \
  -H "Authorization: Bearer $PK_TOKEN")
check "credentials route exists" "200" "$STATUS"

# ── Cleanup ──────────────────────────────────────────────────────

echo ""
echo "=== Cleanup ==="
if [ -n "$PK_USER_ID" ] && [ "$PK_USER_ID" != "null" ]; then
  curl -s -o /dev/null -X DELETE "$BASE/api/v1/users/$PK_USER_ID" -H "Authorization: Bearer $ACCESS"
  echo "  ✓ Deleted test user passkeyuser"
fi

# ── Summary ──────────────────────────────────────────────────────

echo ""
echo "================================"
echo "  PASSED: $PASS"
echo "  FAILED: $FAIL"
echo "================================"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
