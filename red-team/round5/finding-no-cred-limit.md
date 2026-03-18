# Finding: No Credential Registration Limit per User

**Severity:** Medium
**Category:** Resource exhaustion / Account takeover persistence
**Affected endpoints:**
- `POST /api/v1/webauthn/register/begin` (requires JWT)
- `POST /api/v1/webauthn/register/finish` (requires JWT)

## Summary

There is no limit on the number of passkey credentials a user can register. An attacker who obtains a valid JWT (e.g., via XSS, token theft, or a compromised session) can register an unlimited number of rogue passkeys on the victim's account.

## Evidence from source

**No application-level limit:** `BeginRegistration()` in `webauthn_service.go` (line 72) fetches all existing credentials via `ListByUserID` but never checks the count. `FinishRegistration()` (line 121) stores the new credential unconditionally.

**No DB-level constraint:** The `webauthn_credentials` table (`003_webauthn.sql`) has a UNIQUE constraint on `credential_id` (the raw WebAuthn ID from the authenticator) but no limit on the number of rows per `user_id`. There is no CHECK constraint or trigger capping credentials per user.

**`excludeCredentials` grows unbounded:** In `BeginRegistration()`, all existing credentials are loaded into a `WebAuthnUser` and passed to the go-webauthn library's `BeginRegistration()`. The library converts these into the `excludeCredentials` list in the `PublicKeyCredentialCreationOptions` JSON sent to the client. Each entry contains `id` (credential ID, typically 32-64 bytes, base64url-encoded), `type`, and `transports`. With thousands of credentials, this response payload grows to megabytes.

**Rate limiting is weak for this path:** The registration endpoints (`/api/v1/webauthn/register/*`) are behind `auth.RequireAuth` (JWT required) but are NOT behind the strict auth rate limiter (5 req/min). They only hit the general rate limiter: 30 req/min with burst of 10 (`main.go` lines 289-319). The strict limiter is applied only to login/token endpoints:
```
mux.Handle("POST /api/v1/auth/login", wrapAuth(apiRouter))
mux.Handle("POST /api/v1/webauthn/login/begin", wrapAuth(apiRouter))
mux.Handle("POST /api/v1/webauthn/login/finish", wrapAuth(apiRouter))
```
Registration endpoints fall through to `/api/v1/` which gets only `generalRateLimiter`.

## Attack scenarios

### 1. Persistent backdoor access (primary concern)

An attacker with a stolen JWT registers their own passkeys on the victim's account. Even after the victim rotates their password and revokes all refresh tokens, the attacker retains passkey-based login access. The victim would need to manually discover and delete every rogue credential.

**Practical throughput:** At 30 req/min general rate limit, registration requires two requests (begin + finish), so ~15 passkeys/minute. In the 15-minute lifetime of a single access token, an attacker could register ~225 passkeys. With refresh token rotation, this is unlimited over time.

### 2. Degraded registration ceremony

With thousands of `excludeCredentials` entries, the `BeginRegistration` response grows very large. At ~100 bytes per entry base64-encoded, 10,000 credentials produces a ~1MB JSON response. The browser's `navigator.credentials.create()` must process this entire list. While this likely won't crash modern browsers, it degrades UX and increases server memory/bandwidth usage on every subsequent registration attempt.

### 3. SQLite storage pressure

Each credential row is ~300-500 bytes in SQLite. 100,000 rogue credentials per account would consume ~30-50MB -- annoying but not fatal for a single-user server. However, the `ListByUserID` query (used on every login and registration ceremony) would become slow, and the full credential set is loaded into memory each time.

## Recommended fixes

1. **Cap credentials per user** (e.g., 25). Check `len(existingCreds)` in `BeginRegistration()` before starting the ceremony. The WebAuthn spec suggests most users need 3-5 passkeys.
2. **Apply the strict auth rate limiter** to registration endpoints, not just login endpoints.
3. **Consider requiring re-authentication** (password or existing passkey) before registering a new passkey, rather than accepting any valid JWT. This mitigates the stolen-JWT scenario.
