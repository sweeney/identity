#!/usr/bin/env bash
#
# End-to-end test suite for RFC 8628 device flow + claim-code variant.
# Runs against a live server — start it first:
#
#   RATE_LIMIT_DISABLED=1 ADMIN_USERNAME=admin ADMIN_PASSWORD=adminpassword1 \
#     PORT=8181 ./bin/identity-server
#
# Then:
#   ./scripts/e2e-device-flow.sh [base_url]
#
# Default base URL: http://localhost:8181
#
# Credentials (override for non-default environments):
#   ADMIN_USERNAME   default: admin
#   ADMIN_PASSWORD   default: adminpassword1

BASE="${1:-http://localhost:8181}"
ADMIN_USER="${ADMIN_USERNAME:-admin}"
ADMIN_PASS="${ADMIN_PASSWORD:-adminpassword1}"
RATE_WAIT="${RATE_WAIT:-0}"
PASS=0
FAIL=0

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

json_field() {
  # json_field <field> <json>
  python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('$1',''))" "$2" 2>/dev/null || echo ""
}

# ── 0. Admin login ─────────────────────────────────────────────────
echo "=== 0. Admin login ==="
RESP=$(curl -s -D- -o /dev/null -X POST "$BASE/admin/login" \
  -d "username=$ADMIN_USER&password=$ADMIN_PASS" -H "Content-Type: application/x-www-form-urlencoded")
COOKIE=$(echo "$RESP" | grep -i 'set-cookie' | head -1 | sed 's/.*admin_session=//;s/;.*//')
check_contains "Admin session cookie" "eyJ" "$COOKIE"

# ── 1. Register an OAuth client with device_code grant ──────────────
echo ""
echo "=== 1. Register device-flow OAuth client ==="

FORM_HTML=$(curl -s -b "admin_session=$COOKIE" "$BASE/admin/oauth/new")
CSRF=$(echo "$FORM_HTML" | grep '_csrf' | head -1 | sed 's/.*value="//;s/".*//')

STATUS=$(curl -s -o /dev/null -w '%{http_code}' -b "admin_session=$COOKIE" \
  -X POST "$BASE/admin/oauth/new" \
  -d "_csrf=$CSRF&id=e2e-device&name=E2E+Devices&grant_types=urn:ietf:params:oauth:grant-type:device_code&token_endpoint_auth_method=none&redirect_uris=&scopes=&audience=" \
  -H "Content-Type: application/x-www-form-urlencoded")
check "Create client (303 or 200)" "ok" "$([ "$STATUS" = "303" ] || [ "$STATUS" = "200" ] && echo ok || echo "HTTP $STATUS")"

# ── 2. Discovery metadata advertises device flow ────────────────────
echo ""
echo "=== 2. Discovery advertises device flow ==="
META=$(curl -s "$BASE/.well-known/oauth-authorization-server")
check_contains "device_authorization_endpoint present" "device_authorization_endpoint" "$META"
check_contains "device_code grant advertised" "device_code" "$META"

# ── 3. Device requests authorization ────────────────────────────────
echo ""
echo "=== 3. Standard device flow: /oauth/device_authorization ==="
rate_sleep
DA_RESP=$(curl -s -X POST "$BASE/oauth/device_authorization" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=e2e-device")
check_contains "Response has device_code" "device_code" "$DA_RESP"
check_contains "Response has user_code" "user_code" "$DA_RESP"
check_contains "Response has verification_uri" "verification_uri" "$DA_RESP"
check_contains "Response has interval" "interval" "$DA_RESP"

DEVICE_CODE=$(json_field "device_code" "$DA_RESP")
USER_CODE=$(json_field "user_code" "$DA_RESP")
echo "  (user_code: $USER_CODE)"

# ── 4. Poll /oauth/token → authorization_pending ────────────────────
echo ""
echo "=== 4. Poll before approval → authorization_pending ==="
rate_sleep
POLL=$(curl -s -X POST "$BASE/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  --data-urlencode "client_id=e2e-device" \
  --data-urlencode "device_code=$DEVICE_CODE")
check_contains "authorization_pending error" "authorization_pending" "$POLL"

# ── 5. User approves via /oauth/device ─────────────────────────────
echo ""
echo "=== 5. User approves user_code ==="
rate_sleep
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/oauth/device" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "user_code=$USER_CODE" \
  --data-urlencode "username=$ADMIN_USER" \
  --data-urlencode "password=$ADMIN_PASS" \
  --data-urlencode "action=approve")
check "Approval returns 200" "200" "$STATUS"

# ── 6. Poll → tokens ────────────────────────────────────────────────
# Sleep a bit more than interval so slow_down doesn't fire on replay poll.
sleep 6
echo ""
echo "=== 6. Poll after approval → tokens ==="
TOKEN_RESP=$(curl -s -X POST "$BASE/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  --data-urlencode "client_id=e2e-device" \
  --data-urlencode "device_code=$DEVICE_CODE")
check_contains "Response has access_token" "access_token" "$TOKEN_RESP"
check_contains "Response has refresh_token" "refresh_token" "$TOKEN_RESP"

# ── 7. Second exchange of same device_code fails ────────────────────
echo ""
echo "=== 7. Replay of consumed device_code fails ==="
sleep 6
REPLAY=$(curl -s -X POST "$BASE/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  --data-urlencode "client_id=e2e-device" \
  --data-urlencode "device_code=$DEVICE_CODE")
check_contains "invalid_grant on replay" "invalid_grant" "$REPLAY"

# ── 8. Unknown device_code returns invalid_grant ───────────────────
echo ""
echo "=== 8. Unknown device_code → invalid_grant ==="
rate_sleep
UNKNOWN=$(curl -s -X POST "$BASE/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  --data-urlencode "client_id=e2e-device" \
  --data-urlencode "device_code=nope-this-does-not-exist")
check_contains "invalid_grant on unknown" "invalid_grant" "$UNKNOWN"

# ── 9. Claim code generation + claim + poll ─────────────────────────
echo ""
echo "=== 9. Claim-code flow ==="

# Generate a claim code via admin
FORM_HTML=$(curl -s -b "admin_session=$COOKIE" "$BASE/admin/oauth/e2e-device/claim-codes/new")
CSRF=$(echo "$FORM_HTML" | grep '_csrf' | head -1 | sed 's/.*value="//;s/".*//')
check "Got CSRF for claim-code form" "1" "$([ -n "$CSRF" ] && echo 1 || echo 0)"

STICKERS=$(curl -s -b "admin_session=$COOKIE" \
  -X POST "$BASE/admin/oauth/e2e-device/claim-codes/new" \
  -d "_csrf=$CSRF&labels=Kitchen+sensor" \
  -H "Content-Type: application/x-www-form-urlencoded")
# Extract the raw claim code (shown in the stickers page inside <code>...</code>)
CLAIM_CODE=$(echo "$STICKERS" | grep -oE '[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}' | head -1)
check "Stickers page has a 12-char claim code" "1" "$([ -n "$CLAIM_CODE" ] && echo 1 || echo 0)"
echo "  (claim_code: $CLAIM_CODE)"
check_contains "Stickers page has a QR SVG" "<svg" "$STICKERS"

# Device exchanges claim code for a device_code
rate_sleep
CLAIM_RESP=$(curl -s -X POST "$BASE/oauth/device/claim" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=e2e-device" \
  --data-urlencode "claim_code=$CLAIM_CODE")
check_contains "claim response has device_code" "device_code" "$CLAIM_RESP"
DEVICE_CODE2=$(json_field "device_code" "$CLAIM_RESP")
USER_CODE2=$(json_field "user_code" "$CLAIM_RESP")

# First poll → pending (device not yet bound on sticker — user must scan + approve)
rate_sleep
PENDING=$(curl -s -X POST "$BASE/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  --data-urlencode "client_id=e2e-device" \
  --data-urlencode "device_code=$DEVICE_CODE2")
check_contains "claim session pending" "authorization_pending" "$PENDING"

# User "scans the QR" — approves using the claim_code
rate_sleep
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/oauth/device" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "user_code=$CLAIM_CODE" \
  --data-urlencode "username=$ADMIN_USER" \
  --data-urlencode "password=$ADMIN_PASS" \
  --data-urlencode "action=approve")
check "Claim approval returns 200" "200" "$STATUS"

# Device's next poll gets tokens
sleep 6
CLAIMED_TOKENS=$(curl -s -X POST "$BASE/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  --data-urlencode "client_id=e2e-device" \
  --data-urlencode "device_code=$DEVICE_CODE2")
check_contains "claimed poll returns access_token" "access_token" "$CLAIMED_TOKENS"

# ── 10. Second boot: claim again → auto-approved ───────────────────
echo ""
echo "=== 10. Re-boot (claim again using same claim_code) → auto-approve ==="
rate_sleep
CLAIM_RESP2=$(curl -s -X POST "$BASE/oauth/device/claim" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=e2e-device" \
  --data-urlencode "claim_code=$CLAIM_CODE")
DEVICE_CODE3=$(json_field "device_code" "$CLAIM_RESP2")
check "Second claim returned a device_code" "1" "$([ -n "$DEVICE_CODE3" ] && echo 1 || echo 0)"

sleep 2
AUTO_TOKENS=$(curl -s -X POST "$BASE/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  --data-urlencode "client_id=e2e-device" \
  --data-urlencode "device_code=$DEVICE_CODE3")
check_contains "Auto-approved poll returns access_token" "access_token" "$AUTO_TOKENS"

# ── 11. Revoke claim code → subsequent claim fails ─────────────────
echo ""
echo "=== 11. Revoke claim code ==="
CODES_HTML=$(curl -s -b "admin_session=$COOKIE" "$BASE/admin/oauth/e2e-device/claim-codes")
CLAIM_ID=$(echo "$CODES_HTML" | grep -oE '/claim-codes/[a-f0-9-]+/revoke' | head -1 | sed 's|/claim-codes/||;s|/revoke||')
FORM_HTML=$(curl -s -b "admin_session=$COOKIE" "$BASE/admin/oauth/e2e-device/claim-codes")
CSRF=$(echo "$FORM_HTML" | grep '_csrf' | head -1 | sed 's/.*value="//;s/".*//')

STATUS=$(curl -s -o /dev/null -w '%{http_code}' -b "admin_session=$COOKIE" \
  -X POST "$BASE/admin/oauth/e2e-device/claim-codes/$CLAIM_ID/revoke" \
  -d "_csrf=$CSRF" -H "Content-Type: application/x-www-form-urlencoded")
check "Revoke returns 303" "303" "$STATUS"

rate_sleep
REVOKED_RESP=$(curl -s -X POST "$BASE/oauth/device/claim" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=e2e-device" \
  --data-urlencode "claim_code=$CLAIM_CODE")
check_contains "Revoked claim fails with invalid_grant" "invalid_grant" "$REVOKED_RESP"

# ── Summary ────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════"
exit $FAIL
