# Red Team Report: id.swee.net — Round 5

**Target:** https://id.swee.net/
**Source:** https://github.com/sweeney/identity/
**Date:** 2026-03-18
**Stack:** Go, SQLite (WAL), OAuth 2.0 + PKCE, JWT (HS256), bcrypt, WebAuthn/Passkeys, Cloudflare Tunnel
**Previous rounds:** `archive/round1/`, `archive/round2/`, `archive/round3/`, `archive/round4/`

---

## Assessment: CONDITIONAL PASS

1 MEDIUM-HIGH, 3 MEDIUM, 4 LOW, 2 INFO — new WebAuthn attack surface requires remediation before passkey feature is production-hardened.

---

## Executive Summary

Round 4 achieved a clean PASS with zero HIGH/MEDIUM findings on the core auth server. Round 5 assesses the newly added **WebAuthn/passkey** functionality, which introduces new credential types, cryptographic ceremonies, and admin UI surfaces. The existing auth infrastructure remains solid. However, the WebAuthn implementation has several issues that need attention.

Two proof-of-concept exploits were developed and tested:

| PoC | File | Status |
|-----|------|--------|
| Username enumeration oracle | `poc-username-enum.py` | Working — tested live against id.swee.net |
| Challenge race condition | `poc-challenge-race.py` | Demonstrates race window |

---

## Round 1–4 Remediation Status

| # | Original Finding | Original Severity | Status |
|---|-----------------|-------------------|--------|
| 1 | CORS wildcard origin reflection | HIGH | **REMEDIATED** — explicit allowlist, verified live |
| 2 | No rate limiting on auth endpoints | MEDIUM | **REMEDIATED** — strict 5/min on all credential endpoints including new WebAuthn login |
| 3 | Timing-based username enumeration | MEDIUM | **REMEDIATED** — dummy bcrypt on both Login and AuthorizeUser paths |
| 4 | Admin session not validated against user state | MEDIUM | **REMEDIATED** — per-request DB check for existence, active status, admin role |
| 5 | No CSRF on OAuth authorize POST | LOW-MED | **PARTIALLY REMEDIATED** — CSP form-action + PKCE + client re-validation, but no explicit CSRF token |

---

## New Findings Summary

| # | Finding | Severity |
|---|---------|----------|
| R5-01 | Username enumeration via WebAuthn login/begin — 3-way oracle + credential ID harvesting | **MEDIUM-HIGH** |
| R5-02 | TOCTOU race on challenge consumption — `defer Delete` allows concurrent reuse | **MEDIUM** |
| R5-03 | Hardcoded UserPresent/UserVerified flags — authenticator state never persisted | **MEDIUM** |
| R5-04 | No credential registration limit — stolen JWT registers ~225 persistent backdoor passkeys | **MEDIUM** |
| R5-05 | CORS origins auto-merged into WebAuthn origins — different trust decisions coupled | **LOW** |
| R5-06 | Query params on POST (challenge_id, name) — proxy/Referer leakage risk | **LOW** |
| R5-07 | Passkey name unsanitized (no length/char limit) — XSS blocked by html/template | **LOW** |
| R5-08 | Admin passkey login no CSRF — mitigated by SameSite=Strict | **LOW** |
| R5-09 | HSTS 30-day max-age, no preload | **INFO** |
| R5-10 | RP ID scoped to swee.net | **INFO** (by design) |

---

## Detailed Findings

### R5-01: Username Enumeration via WebAuthn Login/Begin [MEDIUM-HIGH]

**Description:** The `POST /api/v1/webauthn/login/begin` endpoint produces three distinguishable responses that reveal user state:

1. **Nonexistent user** — returns a fake discoverable challenge (HTTP 200, empty `allowCredentials`)
2. **Existing user, no passkeys** — returns HTTP 400 `webauthn_no_credentials` error
3. **Existing user, has passkeys** — returns HTTP 200 with populated `allowCredentials` containing credential IDs

This is a 3-way oracle that leaks both user existence and passkey enrollment status. The credential IDs in case (3) are also leaked, which can be used for targeted attacks.

**Attack Scenario:**
1. Attacker sends `POST /api/v1/webauthn/login/begin` with a target username.
2. Response code and body structure reveal whether the user exists and whether they have passkeys.
3. This oracle is not mitigated by the dummy-bcrypt timing fix applied to password login.
4. Rate limit is 5/min but supports slow enumeration over time.

**Evidence:**
- **Source:** `internal/service/webauthn_service.go` lines 222–228 (fake challenge for nonexistent user), lines 238–239 (`ErrWebAuthnNoCredentials` for exists-but-no-passkeys)
- **Live test:** `poc-username-enum.py` — confirmed working against production

**Recommended Fix:** Unify the response for all three cases. Always return a discoverable-style challenge (HTTP 200), regardless of user existence or passkey status. The `FinishLogin` callback will reject the assertion for nonexistent users. This matches the dummy-bcrypt pattern used for password login.

---

### R5-02: TOCTOU Race on Challenge Consumption [MEDIUM]

**Description:** Both `FinishRegistration` and `FinishLogin` use `defer s.challenges.Delete(challengeID)` to clean up challenges. The challenge is fetched, validated, and the entire cryptographic ceremony completes before the deferred delete executes. Two concurrent requests with the same `challenge_id` can both read the challenge before either deletes it.

**Attack Scenario:**
1. User initiates a WebAuthn login, receiving a `challenge_id`.
2. Attacker intercepts or shares the challenge_id (e.g., via XSS or shared network).
3. Attacker and legitimate user both send `FinishLogin` simultaneously.
4. Both requests call `GetByID` — both succeed because the deferred delete has not fired.
5. Both proceed through cryptographic verification. If both have valid assertions, both receive tokens.
6. SQLite single-connection serialization narrows but does not fully close this window, since the Go HTTP server handles requests concurrently and the CPU-bound crypto step releases the DB connection.

**Evidence:**
- **Source:** `internal/service/webauthn_service.go` line 135 (`defer` in FinishRegistration), line 290 (`defer` in FinishLogin)
- **PoC:** `poc-challenge-race.py` demonstrates the race window

**Recommended Fix:** Delete the challenge atomically *before* performing cryptographic verification. Use a transaction: SELECT + DELETE + commit in one step, then proceed with validation using the fetched data. This ensures the challenge is consumed exactly once.

---

### R5-03: Hardcoded UserPresent/UserVerified Flags [MEDIUM]

**Description:** The `DomainCredentialToWebAuthn` function hardcodes `UserPresent: true` and `UserVerified: true` for every credential. The actual authenticator flags from registration are never persisted — the domain model and database schema lack columns for UP and UV. This permanently destroys the security assurance metadata for every credential.

**Attack Scenario:**
1. User registers a basic security key that supports UP but not UV (no biometric capability).
2. The authenticator correctly reports UV=false during registration.
3. The server discards this flag and stores the credential as if UV=true.
4. If step-up authentication or risk-based access control is implemented based on UV status, this credential is indistinguishable from a biometric-verified one.
5. A stolen non-biometric key gains the same trust level as a biometric-protected credential.
6. If the RP tightens policy from `"preferred"` to `"required"`, it cannot identify which existing credentials actually had UV.

**Evidence:**
- **Source:** `internal/auth/webauthn.go` lines 34–39 (hardcoded flags in `DomainCredentialToWebAuthn`)
- `internal/domain/webauthn.go` lines 8–22 (missing UserPresent/UserVerified fields)
- `internal/service/webauthn_service.go` lines 178–192 (flags not extracted at registration)
- `internal/store/webauthn_credential_store.go` lines 24–54 (not stored in DB)

**Recommended Fix:**
1. Add `user_present` and `user_verified` columns to the `webauthn_credentials` table.
2. Add corresponding fields to the `domain.WebAuthnCredential` struct.
3. Persist the actual flags from `credential.Flags` at registration time.
4. Restore the actual flags in `DomainCredentialToWebAuthn` instead of hardcoding.
5. Migrate existing credentials conservatively: `user_present=true, user_verified=false`.

---

### R5-04: No Credential Registration Limit [MEDIUM]

**Description:** There is no cap on the number of passkeys a user can register. An attacker with a stolen JWT can register unlimited rogue passkeys as persistent backdoors. Registration endpoints are behind the general rate limiter (30 req/min) but NOT the strict auth limiter (5/min). At 2 requests per registration (begin + finish), an attacker can register ~15 passkeys/minute, yielding ~225 passkeys within a single 15-minute access token lifetime.

**Attack Scenario:**
1. Attacker obtains a valid JWT (via XSS, token theft, or compromised session).
2. Attacker scripts rapid `register/begin` + `register/finish` calls, each with a different authenticator.
3. ~225 rogue passkeys are registered within the JWT lifetime.
4. Victim rotates password and revokes refresh tokens — rogue passkeys survive.
5. Attacker retains persistent login access via any of the 225 passkeys.
6. Victim must manually discover and delete every rogue credential to fully recover.

**Evidence:**
- **Source:** `internal/service/webauthn_service.go` line 72 (`BeginRegistration` does not check credential count)
- `internal/db/migrations/003_webauthn.sql` — no CHECK constraint or per-user limit
- `cmd/server/main.go` lines 289–319 — registration endpoints only behind `generalRateLimiter` (30/min), not `strictAuthLimiter` (5/min)

**Recommended Fix:**
1. Cap credentials per user (e.g., 25). Check `len(existingCreds)` in `BeginRegistration` before starting the ceremony.
2. Apply the strict auth rate limiter to registration endpoints.
3. Require re-authentication (password or existing passkey) before registering a new passkey, instead of accepting any valid JWT.

---

### R5-05: CORS Origins Auto-Merged into WebAuthn Origins [LOW]

**Description:** Lines 173–187 of `internal/config/config.go` automatically merge all `CORS_ORIGINS` into `WebAuthnRPOrigins`. This couples two distinct trust decisions: "this origin may read API responses" (CORS/data-level) and "this origin may use passkeys bound to our RP ID" (WebAuthn/authentication-level). Adding a sibling subdomain to CORS silently grants it WebAuthn ceremony rights.

**Attack Scenario:**
1. Developer adds `https://app.swee.net` to `CORS_ORIGINS` for a new SPA.
2. Auto-merge silently adds it to `WebAuthnRPOrigins`.
3. XSS or compromise on `app.swee.net` allows attacker to initiate WebAuthn ceremonies using passkeys bound to RP ID `swee.net`.
4. The browser permits this because the RP ID matches. The server permits it because the origin is now in the allowed list.

**Evidence:**
- **Source:** `internal/config/config.go` lines 173–187 (merge logic with explicit comment stating intent)
- **Current risk:** Low — `CORS_ORIGINS` appears to be empty or `id.swee.net` only. Risk increases if sibling subdomains are added.

**Recommended Fix:** Remove the auto-merge logic. Configure `WEBAUTHN_RP_ORIGINS` and `CORS_ORIGINS` independently. Add a startup warning if they diverge, to surface the trust boundary difference.

---

### R5-06: Query Parameters on POST Endpoints [LOW]

**Description:** The WebAuthn finish endpoints accept `challenge_id` and `name` as URL query parameters on POST requests rather than in the request body. Query parameters on POST requests are an anti-pattern: they appear in `Referer` headers on subsequent navigation, may be logged by reverse proxies (Cloudflare edge logs), and are visible in browser developer tools. The `name` parameter could contain PII if users name passkeys after devices (e.g., "John's MacBook Pro").

**Evidence:**
- **Source:** `internal/handler/api/webauthn.go` lines 45–46 (`r.URL.Query().Get("challenge_id")`, `r.URL.Query().Get("name")`)
- `internal/handler/admin/handler.go` lines 407–408 (same pattern in admin handler)
- The `challenge_id` is an ephemeral UUID with 120s TTL, so replay risk is minimal. The concern is logging/leakage.

**Recommended Fix:** Move `challenge_id` and `name` to the POST request body. These endpoints already receive a JSON body (the WebAuthn attestation/assertion), so adding fields is trivial.

---

### R5-07: Passkey Name Unsanitized [LOW]

**Description:** The passkey `name` parameter has no length limit, no character filtering, and no input validation. An attacker with a valid session can register a passkey with arbitrary names including HTML tags, multi-megabyte strings, RTL override characters, or zero-width Unicode abuse. XSS is blocked by Go's `html/template` auto-escaping — no `template.HTML()` or unsafe template functions are used. The risk is limited to UI disruption.

**Evidence:**
- **Source:** `internal/handler/api/webauthn.go` line 46 (no validation on `name`)
- `internal/ui/templates/passkeys.html` line 14 (`{{.Name}}` — auto-escaped)
- `internal/ui/templates/user_form.html` line 58 (`{{.Name}}` — auto-escaped)
- Template FuncMap in `internal/handler/admin/router.go` is empty — no bypass functions

**Recommended Fix:** Add input validation: limit passkey names to 100 characters, allow only alphanumeric + spaces + basic punctuation, strip control characters.

---

### R5-08: Admin Passkey Login Missing CSRF Token [LOW]

**Description:** `POST /admin/login/passkey` accepts an `access_token` via form body and sets an admin session cookie, but has no CSRF token validation. Unlike all other admin POST routes, this one is not wrapped in `requireCSRF()`. The same pattern exists on `POST /oauth/authorize/passkey`.

**Mitigation:** The `admin_session` cookie uses `SameSite=Strict`, which blocks cross-site form submissions in all modern browsers. The attack also requires a pre-obtained valid JWT access token (15-min TTL, HS256-signed). A cross-site form submission would set the cookie, but `SameSite=Strict` prevents the cookie from being sent on the subsequent redirect, so the attack fails. The combination makes exploitation unrealistic.

**Evidence:**
- **Source:** `internal/handler/admin/router.go` line 48 (no `requireCSRF` middleware)
- `internal/handler/admin/handler.go` lines 258–296 (`loginPasskey` handler)
- `internal/handler/admin/handler.go` lines 134–143 (`SameSite=Strict` on session cookie)
- `internal/handler/oauth/handler.go` line 216 (same pattern on OAuth passkey endpoint)

**Recommended Fix:** Add an `Origin`/`Referer` header check as defense-in-depth. Verify the request origin matches `https://id.swee.net`. A full CSRF token is difficult since no session exists yet, but origin checking is lightweight and appropriate for login endpoints.

---

### R5-09: HSTS 30-Day Max-Age, No Preload [INFO]

**Description:** Live server returns `max-age=2592000` (30 days). Code shows `max-age=63072000` (2 years) — likely Cloudflare override or deployment lag. Missing `includeSubDomains` and `preload` directives. Carried forward from Round 4.

---

### R5-10: RP ID Scoped to swee.net [INFO — By Design]

**Description:** The WebAuthn RP ID is `swee.net` rather than `id.swee.net`. Passkeys are cryptographically bound to the parent domain and can be exercised by any origin under `*.swee.net`, subject to the `RPOrigins` server-side allowlist check. This broadens the trust boundary permanently — changing the RP ID would invalidate all existing passkeys.

**Current mitigation:** The `RPOrigins` allowlist restricts which origins can complete ceremonies. As long as only `https://id.swee.net` is listed, sibling subdomains are rejected.

**Evidence:**
- **Source:** `internal/auth/webauthn.go` — `RPID: "swee.net"`
- `internal/config/config.go` lines 148–187 (RP ID and origins configuration)

---

## Assessment Across All Rounds

| Round | Findings | HIGH | MEDIUM+ | LOW+ |
|-------|----------|------|---------|------|
| 1 | 13 | 1 | 3 | 9 |
| 2 | 15 | 1 | 5 | 9 |
| 3 | 6 | 1 | 2 | 3 |
| 4 | 3 | 0 | 0 | 3 |
| **5** | **10** | **0** | **4** | **6** |

Round 5 finding count reflects the new WebAuthn attack surface. Core auth findings from Rounds 1–4 remain resolved (4/5 fully remediated, 1 partially).

---

### What's Still Solid

- **No SQL injection** — parameterized queries throughout, including all new WebAuthn stores
- **No XSS** — Go template auto-escaping, strong CSP, no unsafe template functions
- **No CORS abuse** — proper allowlist, no origin reflection
- **PKCE enforced** — S256 required, no plain downgrade
- **Token rotation** — atomic TOCTOU-safe transaction, concurrent test coverage
- **Refresh token theft detection** — family-based revocation working
- **Rate limiting** — per-IP, strict on all credential endpoints, proxy-header-resistant
- **Admin re-auth** — password required for all destructive operations
- **CSRF** — HMAC tokens on all state-changing admin endpoints (except passkey login)
- **Session security** — HttpOnly, Secure, SameSite=Strict, 2-hour TTL
- **WebAuthn challenge binding** — challenges bound to user, type-checked, expiry-checked
- **WebAuthn crypto verification** — go-webauthn library handles assertion/attestation correctly
- **Challenge single-use on failure** — consumed even on failed verification attempts

---

### Priority Remediation Order

| Priority | Finding | Rationale |
|----------|---------|-----------|
| 1 | R5-01 (username enum) | Actively exploitable, PoC working live |
| 2 | R5-04 (no cred limit) | Enables persistent backdoors from stolen JWT |
| 3 | R5-02 (challenge TOCTOU) | Concurrency bug, straightforward fix |
| 4 | R5-03 (UV flags) | Data loss is permanent, harder to fix retroactively |
| 5 | R5-05–08 (LOW) | Defense-in-depth improvements |

### Conclusion

The core identity server remains well-hardened after four rounds of testing. The WebAuthn/passkey implementation is functional and the cryptographic ceremony handling is correct, but the surrounding infrastructure has gaps in credential lifecycle management (R5-03, R5-04), information leakage (R5-01), and concurrency safety (R5-02). These are typical first-implementation issues and are straightforward to remediate.

**Red team assessment: CONDITIONAL PASS** — resolve MEDIUM+ findings before considering passkey feature production-ready.
