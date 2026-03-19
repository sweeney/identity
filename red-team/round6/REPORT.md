# Red Team Report — Round 6

**id.swee.net — Identity & Auth Server — Round 5 Fix Verification**

| | |
|---|---|
| **Target** | https://id.swee.net/ |
| **Source** | github.com/sweeney/identity |
| **Date** | 2026-03-18 |
| **Stack** | Go / SQLite / OAuth 2.0+PKCE / JWT / WebAuthn / Cloudflare |

---

## Assessment: CONDITIONAL PASS

All MEDIUM+ findings from Round 5 verified fixed. 3 LOW residual findings remain from incomplete fixes. 2 INFO items. No new attack surface discovered.

---

## Executive Summary

Round 5 identified 10 findings across the new WebAuthn/passkey attack surface (1 MEDIUM-HIGH, 3 MEDIUM, 4 LOW, 2 INFO). The maintainer claimed all 8 actionable findings were fixed. Round 6 verifies those fixes through both source code review and live testing against the production server.

**Result:** 6 of 8 fixes are fully verified. 2 fixes are partially complete, producing 3 LOW residual findings. All MEDIUM and above findings are confirmed remediated. No new attack surface was discovered during verification.

### Verification Methodology

| Method | Scope | Findings Covered |
|--------|-------|------------------|
| Source code review | Latest main commit, full diff against R5 snapshot | All 8 actionable findings |
| Live testing | Production server (id.swee.net) | R5-01, R5-02, R5-04, R5-06, R5-08 |

---

## Round 5 Fix Verification

| # | R5 Finding | R5 Severity | Source | Live | Verdict |
|---|-----------|-------------|--------|------|---------|
| R5-01 | Username enumeration via WebAuthn 3-way oracle | **MEDIUM-HIGH** | Partial | Verified | **FIXED** |
| R5-02 | TOCTOU race on challenge consumption | **MEDIUM** | Verified | Verified | **FIXED** |
| R5-03 | Hardcoded UserPresent/UserVerified flags | **MEDIUM** | Verified | N/A | **FIXED** |
| R5-04 | No credential registration limit | **MEDIUM** | Verified | Verified | **FIXED** |
| R5-05 | CORS origins auto-merged into WebAuthn origins | **LOW** | Verified | N/A | **FIXED** |
| R5-06 | Query params on POST (challenge_id, name) | **LOW** | Partial | Verified | **PARTIAL** |
| R5-07 | Passkey name unsanitized | **LOW** | Verified | N/A | **FIXED** |
| R5-08 | Admin passkey login missing CSRF | **LOW** | Partial | Verified | **PARTIAL** |

> **Source = Partial, Live = Verified** means the source review found theoretical gaps, but live testing confirmed the fix is effective in practice.

---

## Verification Details

### R5-01: Username Enumeration via WebAuthn Login/Begin — FIXED (was MEDIUM-HIGH)

**What changed:** `BeginLogin` now calls `BeginDiscoverableLogin()` for all cases — known user, unknown user, empty username, no body. The response is always HTTP 200 with an identical discoverable-credential challenge. No `allowCredentials` field is ever returned.

**Source evidence:**
- `internal/service/webauthn_service.go:243-267` — both branches use `BeginDiscoverableLogin()`

**Live evidence:**
- 10 requests across 4 payload types — all return identical 194-byte responses
- Timing delta is sub-millisecond (100-115ms range), not practically exploitable over network
- Rate limiting active on endpoint (429 after ~4 rapid requests)

**Residual notes:** Source review identified (1) a timing side channel from user DB lookup on line 255, and (2) dead code at `webauthn.go:96-97`. Live testing confirmed timing is not observable. Dead code tracked as R6-04 (INFO).

---

### R5-02: TOCTOU Race on Challenge Consumption — FIXED (was MEDIUM)

**What changed:** Challenge store implements `Consume()` using `DELETE ... RETURNING` — a single atomic SQL statement. No transaction wrapper needed; no race window exists. SQLite single-connection mode provides additional serialization.

**Source evidence:**
- `internal/store/webauthn_challenge_store.go:65-89` — atomic Consume method
- `internal/service/webauthn_service.go:153` (FinishRegistration) and `:298` (FinishLogin) — both use Consume
- `internal/domain/webauthn.go:55-58` — interface documents atomicity requirement

**Live evidence:**
- Two concurrent requests with same `challenge_id`:
  - Request 1: HTTP 401 "passkey authentication failed" (reached crypto verification)
  - Request 2: HTTP 400 "challenge expired or not found" (challenge already consumed)
- Confirms atomic single-use behavior

---

### R5-03: Hardcoded UserPresent/UserVerified Flags — FIXED (was MEDIUM)

**What changed:** `user_present` and `user_verified` columns added to DB schema with CHECK constraints. Flags read from `credential.Flags.UserPresent` and `credential.Flags.UserVerified` at registration time. `DomainCredentialToWebAuthn` maps stored values instead of hardcoding `true`.

**Source evidence:**
- `internal/service/webauthn_service.go:216-217` — reads from `credential.Flags`
- `internal/db/migrations/003_webauthn.sql:27-28` — schema columns with constraints
- `internal/store/webauthn_credential_store.go:31,42-43` — persists fields
- `internal/store/webauthn_credential_store.go:156,175-176` — reads fields back
- `internal/auth/webauthn.go:34-36` — maps to `webauthn.CredentialFlags`

**Live:** Not testable without real passkey enrollment.

---

### R5-04: No Credential Registration Limit — FIXED (was MEDIUM)

**What changed:** `maxCredentials: 25` set in `NewWebAuthnService`. `BeginRegistration` checks `len(existingCreds) >= s.maxCredentials` before allowing ceremony. Exceeding limit returns `ErrWebAuthnCredentialLimitReached` (HTTP 409).

**Source evidence:**
- `internal/service/webauthn_service.go:89` — `maxCredentials: 25`
- `internal/service/webauthn_service.go:110-111` — check before ceremony
- `internal/handler/api/webauthn.go:30-31` — HTTP 409 response mapping

**Live evidence:**
- Registration endpoint returns 401 without auth token — auth gate intact
- Full credential count testing requires authenticated session (out of scope)

---

### R5-05: CORS Auto-Merge with WebAuthn Origins — FIXED (was LOW)

**What changed:** `CORS_ORIGINS` and `WEBAUTHN_RP_ORIGINS` parsed from separate environment variables. No merge logic. Warning log fires if they diverge (advisory only). Regression test enforces separation.

**Source evidence:**
- `internal/config/config.go:134-142` — CORS parsing
- `internal/config/config.go:155-162` — WebAuthn parsing
- `internal/config/config.go:176-186` — warning, no merge
- `internal/config/config_test.go:154` — `TestLoad_WebAuthnDoesNotMergeCORSOrigins`

---

### R5-06: Query Parameters on POST Endpoints — PARTIAL (was LOW)

**What changed:** `headerOrQuery` helper checks `X-Challenge-ID` header first, falls back to query. Registration JS (`passkey-register.js`, `passkey-prompt.js`) uses header method.

**What remains:**
- `internal/ui/static/webauthn.js:73` — login JS still uses query parameter: `'/api/v1/webauthn/login/finish?challenge_id=' + challengeId`
- `internal/handler/oauth/handler.go:491-492` — OAuth prompt reads exclusively from `r.URL.Query().Get()`, not `headerOrQuery`

Login ceremony challenge IDs still appear in access logs, proxy logs, and browser history. Registration ceremonies are clean.

**Live evidence:** Both header and query delivery methods work — header method correctly reaches crypto verification.

---

### R5-07: Passkey Name Unsanitized — FIXED (was LOW)

**What changed:** `sanitizePasskeyName` strips control characters (<=0x1F or ==0x7F, except space 0x20) and truncates to 100 runes. Applied in both `FinishRegistration` and `RenameCredential`.

**Source evidence:**
- `internal/service/webauthn_service.go:20` — `const maxPasskeyNameLength = 100`
- `internal/service/webauthn_service.go:23-37` — sanitizer implementation
- `internal/service/webauthn_service.go:196` — called during registration
- `internal/service/webauthn_service.go:408` — called during rename

---

### R5-08: Admin Passkey Login Missing CSRF — PARTIAL (was LOW)

**What changed:** Admin passkey login endpoint validates `Origin` header. Cross-origin requests rejected with HTTP 403 before auth logic.

**What remains:**
1. **Origin check allows absent header** — `handler/admin/handler.go:260` uses `if origin != ""`, skipping check when Origin is missing
2. **OAuth authorizePasskey has no Origin check** — `handler/oauth/handler.go:216-271` accepts POST with `access_token`, no Origin validation

**Live evidence:**

| Test | Origin Header | HTTP Code | Response |
|------|--------------|-----------|----------|
| Evil origin | `Origin: https://evil.com` | **403** | `forbidden: origin mismatch` |
| No origin | (omitted) | 200 | Proceeds to auth check |
| Correct origin | `Origin: https://id.swee.net` | 200 | Proceeds to auth check |

---

## New / Residual Findings

### R6-01: Login JS Still Sends challenge_id in Query Params — LOW

**Origin:** R5-06 residual

The `headerOrQuery` helper and registration JS were updated to use `X-Challenge-ID` header, but the shared login JS was missed. `webauthn.js:73` still constructs the URL as `'/api/v1/webauthn/login/finish?challenge_id=' + challengeId`. The OAuth prompt handler (`handler/oauth/handler.go:491-492`) also reads exclusively from query params.

Login ceremony challenge IDs appear in server access logs, Cloudflare edge logs, and browser history. Registration ceremonies are clean.

**Recommended fix:** Update `webauthn.js` to send `X-Challenge-ID` via header, matching the pattern in `passkey-register.js`. Update OAuth handler to use `headerOrQuery`.

---

### R6-02: Origin Check Allows Absent Origin Header — LOW

**Origin:** R5-08 residual

The admin passkey login Origin check at `handler/admin/handler.go:260` uses `if origin != ""`, meaning requests without an `Origin` header bypass the check entirely. While modern browsers send `Origin` on cross-origin POST requests, some configurations (certain proxies, non-browser clients, older browsers) may omit it.

Practical risk is low: `SameSite=Strict` on admin session cookie blocks cross-site submissions in modern browsers, and the endpoint requires a valid JWT.

**Recommended fix:** For POST requests, require `Origin` to be present. If absent, fall back to `Referer`. Only skip for GET/HEAD.

---

### R6-03: OAuth authorizePasskey Has No Origin Check — LOW

**Origin:** R5-08 residual

The `authorizePasskey` handler (`handler/oauth/handler.go:216-271`) accepts a POST with `access_token` and issues an OAuth authorization code, but performs no Origin validation. The admin endpoint received a fix; this one was not updated.

Practical risk is low: requires valid JWT (15-min TTL) plus cross-origin attack vector. But adding Origin validation is straightforward defense-in-depth.

**Recommended fix:** Apply the same Origin validation. Ideally extract to shared middleware so all passkey POST endpoints are covered uniformly.

---

### R6-04: Dead Code Branch for ErrWebAuthnNoCredentials — INFO

**Origin:** R5-01 residual

At `handler/api/webauthn.go:96-97`, the `loginBegin` handler has a case for `service.ErrWebAuthnNoCredentials`. The service no longer returns this error from `BeginLogin` (eliminated in the R5-01 fix). Dead code — not exploitable, cleanup only.

---

### R6-05: HSTS Max-Age Still 30 Days — INFO

**Origin:** Persistent (R5-09)

Live server returns `Strict-Transport-Security: max-age=2592000` (30 days). Application code sets 2 years — likely Cloudflare override. Does not affect core security posture but falls short of the commonly recommended 1-year minimum.

---

## Trajectory Across All Rounds

| Round | Findings | Highest Severity | Assessment |
|-------|----------|-----------------|------------|
| Round 1 | 13 | 1 HIGH | — |
| Round 2 | 15 | 1 HIGH | — |
| Round 3 | 6 | 1 HIGH | — |
| Round 4 | 3 | 0 HIGH | PASS |
| Round 5 | 10 | 1 MEDIUM-HIGH, 3 MEDIUM | CONDITIONAL PASS (new WebAuthn surface) |
| **Round 6** | **5** | **0 HIGH, 3 LOW** | **CONDITIONAL PASS** |

Round 6 count reflects only new/residual findings. All 4 MEDIUM+ findings from Round 5 are verified fixed. The 3 LOW residuals are incomplete portions of already-LOW R5 findings.

---

## What's Solid

- **No SQL injection** — parameterized queries throughout, including all WebAuthn stores
- **No XSS** — Go template auto-escaping, strong CSP, no unsafe template functions
- **No CORS abuse** — proper allowlist, WebAuthn origins decoupled from CORS
- **PKCE enforced** — S256 required, no downgrade
- **Token rotation** — atomic TOCTOU-safe transaction, concurrent test coverage
- **Theft detection** — family-based revocation working correctly
- **Rate limiting** — per-IP, strict on all credential endpoints, proxy-header-resistant, bounded map
- **Admin re-auth** — password required for destructive operations
- **CSRF** — HMAC tokens on state-changing admin endpoints + Origin check on passkey login
- **Session security** — HttpOnly, Secure, SameSite=Strict, 2-hour TTL
- **WebAuthn challenge binding** — challenges bound to user, type-checked, expiry-checked
- **WebAuthn crypto verification** — go-webauthn library handles assertion/attestation correctly
- **WebAuthn challenge single-use** — atomic `DELETE RETURNING` eliminates TOCTOU race
- **WebAuthn discoverable login privacy** — identical responses for all user states, no enumeration oracle
- **WebAuthn authenticator flags** — UP/UV persisted from actual authenticator, not hardcoded
- **WebAuthn credential cap** — 25-passkey limit prevents stolen-JWT backdoor flooding
- **Passkey name sanitization** — 100-char limit, control chars stripped

---

## Conclusion

The WebAuthn/passkey implementation has been substantially hardened since Round 5. All four MEDIUM+ findings — username enumeration oracle, challenge TOCTOU race, hardcoded authenticator flags, and unlimited credential registration — are confirmed fixed with solid implementations (atomic SQL, proper flag persistence, service-layer caps).

The three remaining LOW findings are residual gaps from incomplete application of fixes that were correctly implemented in their primary locations but missed in secondary code paths (login JS, OAuth handler). These are straightforward to close.

### Remaining Remediation

| Priority | Finding | Effort |
|----------|---------|--------|
| 1 | R6-01 (login JS query params) | ~5 min — update `webauthn.js` to use header, update OAuth handler to use `headerOrQuery` |
| 2 | R6-02 + R6-03 (Origin gaps) | ~15 min — extract Origin check to shared middleware, require Origin on POST, add to OAuth handler |
| 3 | R6-04 (dead code) | ~2 min — delete unreachable branch |
| — | R6-05 (HSTS) | Cloudflare config change |

---

*Generated by Red Team -- Round 6 -- 2026-03-18*
