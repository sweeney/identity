# Round 1 Finding Verification Report

**Date:** 2026-03-18
**Target:** https://id.swee.net/
**Source:** `/round2/identity-src/` (current deployed version)
**Methodology:** Source code review + live endpoint testing (non-destructive)

---

## 1. CORS Wildcard Origin Reflection (was HIGH)

**Status: REMEDIATED**

### Source Code Evidence

The CORS middleware in `cmd/server/main.go` (lines 397-458) now uses an explicit allowlist approach:

- A `map[string]bool` called `allowed` is built once at startup from `cfg.CORSOrigins`.
- The `isAllowedOrigin()` function (line 450) only returns `true` if the origin is in the allowlist, or if in dev mode with an empty allowlist and the origin starts with `http://localhost`.
- CORS headers are only set for `/api/` and `/oauth/token` paths -- not for `/oauth/authorize`, `/admin/`, or other paths.
- The `Access-Control-Allow-Origin` header is set to the specific matched origin, never `*`.

### Live Verification

Tested all relevant endpoint categories with `Origin: https://evil.com`:

| Endpoint | ACAO Header Present? |
|---|---|
| `GET /api/v1/auth/me` | No |
| `OPTIONS /api/v1/auth/login` | No |
| `POST /api/v1/webauthn/login/begin` | No |
| `POST /oauth/token` | No |
| `OPTIONS /oauth/authorize` | No (not a CORS-enabled path) |
| `POST /oauth/authorize/passkey` | No (not a CORS-enabled path) |

No `Access-Control-Allow-Origin` header was reflected for the attacker-controlled origin on any endpoint. The `Vary: Origin` header is correctly set on API paths.

---

## 2. Rate Limiting on Auth Endpoints (was MEDIUM)

**Status: REMEDIATED**

### Source Code Evidence

In `cmd/server/main.go` (lines 289-334), two rate limiters are configured:

- **Strict (auth):** 5 req/min (0.083/s), burst 5 -- applied via `wrapAuth()` to:
  - `POST /api/v1/auth/login` (line 318)
  - `POST /api/v1/webauthn/login/begin` (line 319)
  - `POST /api/v1/webauthn/login/finish` (line 320)
  - `POST /oauth/token` (line 325)
  - `POST /oauth/authorize` (line 326)
  - `POST /admin/login` (line 334)
- **General:** 30 req/min (0.5/s), burst 10 -- applied as outer middleware wrapping all routes (line 364).

Production safety: rate limiting cannot be disabled in production (lines 291-294: if `RateLimitDisabled` is true and `IsProduction()`, it's forced back to `false`).

The rate limiter implementation (`internal/ratelimit/ratelimit.go`) uses per-IP token bucket rate limiting with proper cleanup of stale entries and a max visitor cap of 100,000 to prevent memory exhaustion.

All new WebAuthn login endpoints are covered by the strict rate limiter. The `POST /oauth/authorize/passkey` endpoint is NOT individually wrapped with `wrapAuth`, but it IS covered by the general rate limiter (30/min). This is a minor gap -- see note below.

**Note:** `POST /oauth/authorize/passkey` accepts an `access_token` (already issued by WebAuthn login) rather than raw credentials, so the strict rate limiter is less critical here. The general rate limiter still applies.

---

## 3. Timing-Based Username Enumeration on Password Login (was MEDIUM)

**Status: REMEDIATED**

### Source Code Evidence

In `internal/service/auth_service.go`:

- A `dummyHash` variable (lines 18-21) is pre-computed at startup: a bcrypt cost-12 hash of `"dummy-never-matches"`.
- In `Login()` (line 70-72): when `GetByUsername` returns `ErrNotFound`, the code calls `auth.CheckPassword(password, dummyHash)` before returning `ErrInvalidCredentials`. This ensures the response time for a non-existent user matches a real user (both do a bcrypt comparison).
- In `AuthorizeUser()` (line 117-118): same pattern -- when user is not found, `auth.CheckPassword(password, dummyHash)` is called before returning.

Both the direct API login path and the OAuth authorize path are protected. The bcrypt cost matches the production hashing cost (12), so timing is consistent.

---

## 4. Admin Session Validation Against User State (was MEDIUM)

**Status: REMEDIATED**

### Source Code Evidence

In `internal/handler/admin/handler.go`, the `requireSession()` middleware (lines 103-127):

```go
// Verify the user still exists, is active, and has admin role.
user, err := h.userSvc.GetByUsername(claims.Subject)
if err != nil || !user.IsActive || user.Role != domain.RoleAdmin {
    h.clearSession(w)
    http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
    return
}
```

On every protected admin request, the middleware:
1. Parses the JWT session cookie and checks expiration.
2. Looks up the user by username from the database.
3. Verifies the user still exists (`err != nil` check).
4. Verifies the user is still active (`!user.IsActive` check).
5. Verifies the user still has the admin role (`user.Role != domain.RoleAdmin` check).

If any check fails, the session cookie is cleared and the user is redirected to login.

Additionally, the JWT API middleware (`internal/auth/middleware.go`, lines 50-52) checks `claims.IsActive` and returns 403 if the account is disabled. Note: the JWT middleware relies on the `IsActive` claim embedded at token-issue time, so there is a window (up to 15 min, the access token TTL) where a disabled user's existing access token would still work for API calls. This is a known trade-off of JWT-based auth and is mitigated by the short TTL and refresh token validation (which checks user state from the database).

---

## 5. CSRF on OAuth Authorize POST (was LOW-MED)

**Status: PARTIALLY REMEDIATED**

### Source Code Evidence

The OAuth authorize POST (`POST /oauth/authorize`) does NOT have an explicit CSRF token mechanism. There is no `requireCSRF` middleware wrapping it (compare to the admin routes which all use `h.requireCSRF()`).

However, the following mitigations are in place:

1. **SameSite cookie policy:** Not directly applicable -- the OAuth authorize form uses username/password in the POST body, not session cookies.
2. **Re-validation of client_id + redirect_uri:** The `authorizePost` handler (line 133) re-validates the client and redirect URI on POST, preventing an attacker from redirecting the auth code to an arbitrary URI.
3. **CSP `form-action 'self'`:** The Content-Security-Policy header restricts form submissions to same-origin, which blocks cross-origin form POSTs in supporting browsers.
4. **Rate limiting:** The strict rate limiter (5/min) is applied to this endpoint.
5. **PKCE requirement:** The flow requires `code_challenge` (S256), and the code can only be exchanged with the matching `code_verifier`, which the attacker would not have.

The `POST /oauth/authorize/passkey` endpoint similarly lacks an explicit CSRF token but has similar mitigations (requires a valid access_token, re-validates client, CSP form-action).

**Why "partially":** While the combination of PKCE + client re-validation + CSP form-action provides strong defense-in-depth, there is no explicit anti-CSRF token on the form itself. CSP `form-action` is not universally enforced by all browsers/configurations, and the OAuth authorize form is a credential-submission endpoint. Best practice (per OAuth 2.0 Security BCP) would be to include an anti-CSRF token tied to the browser session. The admin UI correctly implements CSRF tokens via HMAC-derived tokens -- the same pattern could be applied to the OAuth authorize form.

---

## Summary

| # | Finding | Original Severity | Status | Notes |
|---|---------|------------------|--------|-------|
| 1 | CORS wildcard origin reflection | HIGH | **REMEDIATED** | Explicit allowlist, verified live |
| 2 | No rate limiting on auth endpoints | MEDIUM | **REMEDIATED** | Strict 5/min on all credential endpoints including new WebAuthn |
| 3 | Timing-based username enumeration | MEDIUM | **REMEDIATED** | Dummy bcrypt on both Login and AuthorizeUser paths |
| 4 | Admin session not validated against user state | MEDIUM | **REMEDIATED** | Per-request DB lookup for existence, active, and admin role |
| 5 | No CSRF on OAuth authorize POST | LOW-MED | **PARTIALLY REMEDIATED** | CSP form-action + PKCE + client re-validation, but no explicit CSRF token |
