# Round 6 — Source Code Verification of Round 5 Fixes

**Date:** 2026-03-18
**Target:** https://id.swee.net/ (source: github.com/sweeney/identity)
**Commit reviewed:** latest main as of 2026-03-18 (cloned to /tmp/identity-r6)

---

## R5-01: Username Enumeration via WebAuthn 3-Way Oracle

**Claimed fix:** "Always use discoverable flow — responses are now identical"
**Verdict: PARTIALLY FIXED**

### What changed
The `BeginLogin` method (`internal/service/webauthn_service.go:233-290`) now calls `s.wa.BeginDiscoverableLogin()` in both the empty-username and non-empty-username branches (lines 245 and 263). This means the response payload (`assertion`) is identical regardless of whether the user exists, has credentials, or is unknown. The handler (`internal/handler/api/webauthn.go:87-108`) no longer returns `ErrWebAuthnNoCredentials` from `loginBegin`.

### Remaining issue
**The handler still has a dead error branch that reveals intent but not data.** At `webauthn.go:96-97`, there is still a case for `service.ErrWebAuthnNoCredentials`, but the service never returns this error from `BeginLogin` anymore. This is dead code, not a vulnerability, but it should be cleaned up to avoid confusion.

**More importantly, the service still performs a user lookup** (line 255: `s.users.GetByUsername(username)`) when a username is provided, and stores the `userID` in the challenge record (line 277). While this does NOT leak to the client (the HTTP response is identical either way), it introduces a **subtle timing side channel**: requests for valid usernames will execute a successful DB query, while invalid usernames will hit `domain.ErrNotFound`. The time difference is small (single DB lookup) but measurable under controlled conditions.

**References:**
- `internal/service/webauthn_service.go:243-267` (both branches use BeginDiscoverableLogin)
- `internal/service/webauthn_service.go:255` (user lookup still performed)
- `internal/handler/api/webauthn.go:93-100` (dead ErrWebAuthnNoCredentials branch)

---

## R5-02: Challenge TOCTOU Race Condition

**Claimed fix:** "Atomic Consume method (SELECT+DELETE in transaction)"
**Verdict: VERIFIED**

### What changed
The `WebAuthnChallengeStore` (`internal/store/webauthn_challenge_store.go:65-89`) implements a `Consume` method that uses `DELETE ... RETURNING` — a single atomic SQL statement that deletes the row and returns its data in one operation. This is even better than a SELECT+DELETE in a transaction because it is a single statement, so there is no window for a race condition at all.

Both `FinishRegistration` (`internal/service/webauthn_service.go:153`) and `FinishLogin` (`internal/service/webauthn_service.go:298`) call `s.challenges.Consume(challengeID)` instead of separate Get+Delete.

The interface definition (`internal/domain/webauthn.go:55-58`) documents the atomicity requirement.

**Note on isolation:** SQLite with `SetMaxOpenConns(1)` (`internal/db/db.go:39`) serializes all queries through a single connection, which provides an additional layer of protection. The `DELETE ... RETURNING` approach is atomic regardless of connection pooling.

**References:**
- `internal/store/webauthn_challenge_store.go:65-89` (Consume with DELETE RETURNING)
- `internal/service/webauthn_service.go:153` (FinishRegistration uses Consume)
- `internal/service/webauthn_service.go:298` (FinishLogin uses Consume)
- `internal/domain/webauthn.go:55-58` (interface documents atomicity)

---

## R5-03: Hardcoded UserPresent/UserVerified Flags

**Claimed fix:** "Persist actual authenticator flags from registration"
**Verdict: VERIFIED**

### What changed
In `FinishRegistration` (`internal/service/webauthn_service.go:205-221`), the `UserPresent` and `UserVerified` fields are read from `credential.Flags.UserPresent` and `credential.Flags.UserVerified` (lines 216-217), not hardcoded.

The DB schema (`internal/db/migrations/003_webauthn.sql:27-28`) has `user_present` and `user_verified` columns with proper CHECK constraints.

The credential store (`internal/store/webauthn_credential_store.go:31,42-43`) persists these fields, and the scan functions (`webauthn_credential_store.go:156,175-176`) read them back.

The `DomainCredentialToWebAuthn` function (`internal/auth/webauthn.go:34-36`) maps these stored values into the `webauthn.CredentialFlags` struct, which the go-webauthn library uses during assertion validation.

**References:**
- `internal/service/webauthn_service.go:216-217` (reads from credential.Flags)
- `internal/db/migrations/003_webauthn.sql:27-28` (schema columns)
- `internal/auth/webauthn.go:34-36` (flags used in assertion validation)

---

## R5-04: No Credential Registration Limit

**Claimed fix:** "Cap at 25 passkeys per user"
**Verdict: VERIFIED**

### What changed
`NewWebAuthnService` (`internal/service/webauthn_service.go:79-91`) sets `maxCredentials: 25` (line 89).

`BeginRegistration` (`internal/service/webauthn_service.go:105-111`) checks `len(existingCreds) >= s.maxCredentials` before allowing the ceremony to begin. If exceeded, it returns `ErrWebAuthnCredentialLimitReached`.

The handler (`internal/handler/api/webauthn.go:30-31`) maps this to HTTP 409 Conflict with error code `webauthn_credential_limit`.

**Note:** The limit is enforced only at the service level, not at the DB/repository level (no trigger or constraint). This is acceptable because the service is the only path to credential creation. A DB-level constraint would be defense-in-depth but is not strictly necessary.

**References:**
- `internal/service/webauthn_service.go:89` (maxCredentials: 25)
- `internal/service/webauthn_service.go:110-111` (check + error)
- `internal/handler/api/webauthn.go:30-31` (HTTP 409 response)

---

## R5-05: CORS Auto-Merge with WebAuthn Origins

**Claimed fix:** "Removed — configure independently"
**Verdict: VERIFIED**

### What changed
`config.go` (`internal/config/config.go:134-186`) reads `CORS_ORIGINS` and `WEBAUTHN_RP_ORIGINS` from separate environment variables. They are never merged into each other.

Lines 176-186 add a helpful warning log if CORS origins contain entries not in WebAuthn origins, but this is advisory only — it does not modify either list.

The test `TestLoad_WebAuthnDoesNotMergeCORSOrigins` (`internal/config/config_test.go:154`) explicitly verifies that CORS origins do not leak into WebAuthn origins.

**References:**
- `internal/config/config.go:134-142` (CORS_ORIGINS parsing)
- `internal/config/config.go:155-162` (WEBAUTHN_RP_ORIGINS parsing)
- `internal/config/config.go:176-186` (warning, no merge)

---

## R5-06: Challenge ID Query Parameter Leakage

**Claimed fix:** "Headers first (X-Challenge-ID), query fallback"
**Verdict: PARTIALLY FIXED**

### What changed
The `headerOrQuery` helper (`internal/handler/api/webauthn.go:45-50`) checks `X-Challenge-ID` header first, falling back to query parameter. Both `registerFinish` (line 55) and `loginFinish` (line 111) use this helper.

The **registration JS** (`internal/ui/static/passkey-register.js:61-64` and `internal/ui/static/passkey-prompt.js:62-65`) sends `X-Challenge-ID` via header for registration finish.

### Remaining issue
**The login JS still uses query parameters.** In `internal/ui/static/webauthn.js:73`, the login finish request sends `challenge_id` as a query parameter:
```
'/api/v1/webauthn/login/finish?challenge_id=' + challengeId
```
This means challenge IDs for **login ceremonies** still appear in server access logs, proxy logs, and browser history. The fix was applied inconsistently — registration JS was updated but the shared login JS (`webauthn.js`) was not.

Additionally, the OAuth passkey prompt register finish handler (`internal/handler/oauth/handler.go:491-492`) still reads `challenge_id` and `name` exclusively from query parameters with `r.URL.Query().Get()`, not using `headerOrQuery`.

**References:**
- `internal/handler/api/webauthn.go:45-50` (headerOrQuery helper)
- `internal/ui/static/webauthn.js:73` (login still uses query param)
- `internal/ui/static/passkey-register.js:61-64` (registration uses header)
- `internal/handler/oauth/handler.go:491-492` (OAuth prompt uses query only)

---

## R5-07: Unsanitized Passkey Name

**Claimed fix:** "Max 100 chars, strip control characters"
**Verdict: VERIFIED**

### What changed
`sanitizePasskeyName` (`internal/service/webauthn_service.go:23-37`) strips control characters (anything <= 0x1F or == 0x7F, except space 0x20) and truncates to 100 runes (`maxPasskeyNameLength` constant at line 20).

The function is called in both `FinishRegistration` (line 196) and `RenameCredential` (line 408).

**References:**
- `internal/service/webauthn_service.go:20` (const maxPasskeyNameLength = 100)
- `internal/service/webauthn_service.go:23-37` (sanitizePasskeyName implementation)
- `internal/service/webauthn_service.go:196` (called during registration)
- `internal/service/webauthn_service.go:408` (called during rename)

---

## R5-08: Missing CSRF on Passkey Login

**Claimed fix:** "Origin header check on passkey login"
**Verdict: PARTIALLY FIXED**

### What changed
The **admin** passkey login endpoint (`internal/handler/admin/handler.go:258-267`) validates the Origin header:
```go
if origin := r.Header.Get("Origin"); origin != "" {
    host := r.Host
    if !strings.HasSuffix(origin, "://"+host) {
        http.Error(w, "forbidden: origin mismatch", http.StatusForbidden)
        return
    }
}
```

### Remaining issues

1. **Origin header is optional.** If the `Origin` header is missing (empty string), the check is skipped entirely (line 260: `if origin != "" {`). An attacker can craft a request without an Origin header (e.g., from a `<form>` submission in some browser configurations, or via certain proxies) to bypass this check. The fix should reject requests where Origin is absent for non-GET/HEAD methods, or at minimum require it when processing sensitive POST actions.

2. **The OAuth passkey endpoint has no Origin check at all.** The `authorizePasskey` handler (`internal/handler/oauth/handler.go:216-271`) accepts a `POST` with `access_token` and issues an OAuth authorization code, but performs no Origin validation whatsoever.

3. **The API login/finish endpoint has no Origin check.** The `loginFinish` handler (`internal/handler/api/webauthn.go:110-142`) issues JWT tokens but has no Origin header validation. While this endpoint is stateless (no cookies), a CSRF-style attack could be used if an attacker can steal the challenge_id.

**References:**
- `internal/handler/admin/handler.go:258-267` (admin Origin check — bypassable)
- `internal/handler/oauth/handler.go:216-271` (OAuth passkey — no Origin check)
- `internal/handler/api/webauthn.go:110-142` (API login/finish — no Origin check)

---

## Summary

| Finding | Verdict | Notes |
|---------|---------|-------|
| R5-01 Username enumeration | **PARTIALLY FIXED** | Response is identical but timing side channel remains via user DB lookup |
| R5-02 Challenge TOCTOU race | **VERIFIED** | DELETE RETURNING is atomic; single-connection SQLite adds further safety |
| R5-03 Hardcoded UV flags | **VERIFIED** | Flags read from authenticator response and persisted correctly |
| R5-04 No credential limit | **VERIFIED** | Capped at 25 in service layer |
| R5-05 CORS auto-merge | **VERIFIED** | Separate env vars, no merge, warning log only |
| R5-06 Query param leakage | **PARTIALLY FIXED** | Registration JS uses headers; login JS and OAuth prompt still use query params |
| R5-07 Unsanitized name | **VERIFIED** | 100 char limit + control char stripping in both registration and rename |
| R5-08 Missing CSRF | **PARTIALLY FIXED** | Admin checks Origin but allows absent header; OAuth and API endpoints unprotected |

**Overall: 4 VERIFIED, 4 PARTIALLY FIXED**

### Recommended actions for partially fixed items

1. **R5-01:** Add constant-time padding or always perform a dummy user lookup to eliminate the timing delta. Remove the dead `ErrWebAuthnNoCredentials` branch from the handler.

2. **R5-06:** Update `webauthn.js` to send `X-Challenge-ID` via header instead of query parameter. Update the OAuth prompt handler (`handler.go:491-492`) to use `headerOrQuery` or read from headers.

3. **R5-08:** Reject POST requests where the Origin header is absent (not just mismatched). Add Origin validation to the OAuth `authorizePasskey` handler. Consider adding Origin validation to the API `loginFinish` handler as defense-in-depth.
