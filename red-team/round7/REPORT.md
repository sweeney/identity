# Round 7 Red Team Report — id.swee.net

**Target:** `https://id.swee.net/`
**Date:** 2026-03-26
**Code:** Fresh clone of `https://github.com/sweeney/identity` (commit `7fd9ccc`)
**Focus:** New functionality — JWT HS256→ES256 migration, OAuth client credentials flow, JWKS endpoint, RFC 9068 service tokens, `RequireScope`/`RequireAudience` middleware

---

## Executive Summary

Round 7 focused on the new machine-to-machine (client credentials) infrastructure and the ES256 migration. Two prior vulnerabilities were confirmed fixed. Three new findings were identified: a medium-severity Host header injection in the OAuth discovery endpoint (code acknowledges but doesn't fix), a medium-severity architectural gap where audience/scope middleware exists but is unwired, and a low-severity service token type-confusion in the passkey OAuth bridge. No critical auth bypasses were found.

---

## Fixed from Previous Rounds

| Finding | Status |
|---|---|
| CORS `isAllowedOrigin` prefix match bypass (R5/R6) | **FIXED** — now exact `map[string]bool` lookup (`main.go:466-474`) |
| Admin session secret shared with JWT key (R6) | **FIXED** — `session_secret` is now a separate 64-byte random value in the metadata table (`secrets.go`) |

---

## Findings

### MEDIUM — M1: Host Header Injection in OAuth Discovery Endpoint

**File:** `src/internal/handler/oauth/handler.go:494-514`

The `GET /.well-known/oauth-authorization-server` endpoint constructs the entire discovery document — including `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri` — by trusting `r.Host` directly:

```go
// Use the configured issuer from the token issuer when available,
// rather than trusting the Host header which can be spoofed.
scheme := "https"
if r.TLS == nil && (strings.HasPrefix(r.Host, "localhost") || ...) {
    scheme = "http"
}
issuer := scheme + "://" + r.Host  // ← r.Host still used despite comment
```

The comment even acknowledges the problem but the fix was never implemented.

**Impact:** An attacker who can control the Host header in a GET request to `/.well-known/oauth-authorization-server` receives a response pointing all OAuth endpoints to their controlled domain. OAuth clients using discovery for endpoint configuration (RFC 8414 auto-discovery) could be directed to a fake authorization server.

**Exploitability in production:** Mitigated by Cloudflare Tunnel — Cloudflare normalizes the Host header before forwarding to the origin, making it difficult to inject an arbitrary Host from the internet. However:
- Exploitable on dev/staging/local instances where no reverse proxy normalizes Host
- Exploitable if the origin is ever directly reachable (Cloudflare bypass, CF outage, staging)
- Exploitable in CI/test environments

**PoC:**
```bash
curl -H "Host: evil.attacker.com" https://id.swee.net/.well-known/oauth-authorization-server
# Response: {"issuer":"https://evil.attacker.com","authorization_endpoint":"https://evil.attacker.com/oauth/authorize",...}
```
(In production behind Cloudflare, this PoC will return the real Host. On a local/staging instance it works.)

**Fix:** Use the configured issuer from `TokenIssuer` (which is set at server startup from env config) instead of `r.Host`. The `TokenIssuer.issuer` field already holds the correct value — expose it via a method and use it here.

---

### MEDIUM — M2: `RequireScope` and `RequireAudience` Middleware Not Applied to Any Routes

**Files:** `src/internal/auth/middleware.go:97-154`, `src/internal/handler/api/router.go`

`RequireScope` and `RequireAudience` middleware are implemented but not wired to any routes in the identity server itself, nor documented as a requirement for consuming services.

```go
// RequireAudience exists but is never called in router.go:
mux.Handle("GET /api/v1/users/{id}", auth.RequireAuth(issuer, http.HandlerFunc(uh.get)))
// Should be:
mux.Handle("GET /api/v1/users/{id}", auth.RequireAuth(issuer, auth.RequireAudience("id.swee.net", http.HandlerFunc(uh.get))))
```

**Audience gap:** A service token issued to any client with any audience is accepted as valid by `RequireAuth`. The `RequireAudience` middleware exists to prevent cross-service token replay (a token issued for `aud: "my-api"` should not work against `aud: "id.swee.net"`), but it is never applied.

In practice, the identity server's own API routes reject service tokens anyway (all handlers either check `if claims == nil` or are behind `RequireAdmin`), so this doesn't lead to a direct exploit on the identity service itself. The risk is:

1. **Consuming services** that protect their own endpoints using this identity server's JWTs. They need to apply `RequireAudience` themselves to prevent token replay across services. If they don't know they need to, they won't. The middleware exists but its necessity is invisible.

2. **Scope enforcement is absent.** A service token with `scope: "read:users"` has the same access as one with `scope: "write:admin"` from the identity server's perspective, because no route checks scope. This makes the scope field decorative rather than enforced.

**Fix:** Apply `RequireAudience("id.swee.net")` (or whatever the configured issuer hostname is) to all identity server API routes. Apply `RequireScope` to routes where scope differentiation matters. Document clearly that consuming services must apply both middleware.

---

### LOW — L1: Service Token Type-Confusion in `authorizePasskey` (No Auth Bypass)

**File:** `src/internal/handler/oauth/handler.go:258`, `src/internal/auth/jwt.go:236-268`

The `POST /oauth/authorize` endpoint has a passkey sub-flow (`authorizePasskey`) that accepts an `access_token` from a WebAuthn ceremony and issues an OAuth code for it. It calls `h.tokenIssuer.Parse()` directly — not through `RequireAuth` middleware:

```go
claims, err := h.tokenIssuer.Parse(accessToken)
```

`Parse` delegates to `parseWithKey`, which has no `typ` header check:

```go
func (ti *TokenIssuer) parseWithKey(tokenStr string, key *ecdsa.PrivateKey) (*domain.TokenClaims, error) {
    token, err := jwt.ParseWithClaims(tokenStr, &identityClaims{}, func(t *jwt.Token) (any, error) {
        if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok { ... }
        return &key.PublicKey, nil  // ← no typ: "at+jwt" rejection
    }, ...)
```

A service token (which has `typ: "at+jwt"`, `sub: <clientID>`) passes through `parseWithKey` successfully, returning `TokenClaims{UserID: clientID, IsActive: false, Role: ""}`. The `authorizePasskey` handler does **not** check `IsActive`, and then calls:

```go
h.svc.AuthorizeByUserID(clientID_from_form, redirectURI, claims.UserID /* = serviceClientID */, ...)
```

`AuthorizeByUserID` does **not** validate that `userID` corresponds to a real user — it blindly creates an auth code with `UserID = serviceClientID`. The auth code is stored in the DB. When the attacker subsequently calls `ExchangeCode`, it calls `IssueTokensForUser(serviceClientID)` → `users.GetByID(serviceClientID)` → `ErrNotFound` → failure.

**Impact:**
- No auth bypass — the token exchange fails
- But: a garbage auth code is inserted into the DB with `UserID = clientID`
- A fabricated audit event is emitted (`oauth_authorize_success` with `UserID = clientID`)
- An attacker with a valid service token can pollute the audit log and create DB noise

**PoC (conceptual):**
```bash
# 1. Get a client_credentials token for any registered client
TOKEN=$(curl -s -X POST https://id.swee.net/oauth/token \
  -u "my-service:client-secret" \
  -d "grant_type=client_credentials" | jq -r .access_token)

# 2. Use it in the passkey authorize endpoint as if it were a user token
curl -X POST https://id.swee.net/oauth/authorize \
  -d "access_token=$TOKEN&client_id=my-service&redirect_uri=https://app.example.com/callback&code_challenge=..." \
  -H "Accept: application/json"
# → Returns a code, but ExchangeCode will fail with invalid_credentials
```

**Fix:** Add a `typ` check in `parseWithKey` to reject service tokens, mirroring `ParseServiceToken`'s existing check. Alternatively, have `authorizePasskey` call a stricter parse function that requires user token type.

---

### LOW — L2: Empty Audience Allowed for `client_credentials` Clients (Silent Failure)

**Files:** `src/internal/handler/admin/handler.go:683-715`, `src/internal/auth/jwt.go:114`

When creating an OAuth client, the admin UI accepts an empty `audience` field without validation. However, `MintServiceToken` returns an error if `Audience == ""`:

```go
func (ti *TokenIssuer) MintServiceToken(claims domain.ServiceTokenClaims, ttl time.Duration) (string, error) {
    if claims.Audience == "" {
        return "", errors.New("audience is required for service tokens")
    }
```

If an admin creates a `client_credentials` client with no audience, any subsequent `POST /oauth/token` with `grant_type=client_credentials` returns a 500 Internal Server Error. The client has no indication of why — the error appears as a server fault rather than a configuration issue.

**Fix:** Validate that `audience` is non-empty when `grant_types` includes `client_credentials` in the admin UI creation/edit handlers.

---

### LOW — L3: `verifyAdminPassword` Endpoints Under General Rate Limiter (30/min), Not Strict (5/min)

**Files:** `src/cmd/server/main.go:336-337`, `src/internal/handler/admin/router.go:61-74`

Only `POST /admin/login` is wrapped with `wrapAuth` (5/min strict limiter). All other admin routes fall under the `/admin/` catch-all, which gets only the general 30/min rate limiter:

```go
mux.Handle("POST /admin/login", wrapAuth(adminRouter))  // 5/min strict
mux.Handle("/admin/", adminRouter)                       // 30/min general only
```

These admin endpoints accept and verify an `admin_password` field (re-confirmation for destructive operations) but are rate-limited at 30/min:
- `POST /admin/users/{id}/edit`
- `POST /admin/users/{id}/delete`
- `POST /admin/oauth/{id}/edit`
- `POST /admin/oauth/{id}/delete`
- `POST /admin/oauth/{id}/generate-secret`

**Precondition:** Requires an authenticated admin session cookie AND valid CSRF token. An attacker who has obtained both (e.g., via XSS or session hijacking) can attempt 30 password guesses per minute rather than 5, against the `verifyAdminPassword` re-confirmation flow.

**Severity context:** Lower than it first appears because it requires a pre-existing session. The comment at line 323-324 even explicitly lists `POST /admin/login` as an endpoint that must use strict rate limiting — the same comment does not cover the re-confirmation endpoints, suggesting this was overlooked.

**Fix:** Apply `wrapAuth` to all admin form POST endpoints that call `verifyAdminPassword`. Alternatively, implement a per-session lockout counter for failed re-confirmation attempts.

---

### INFO — I1: EC Private Key Stored Plaintext in SQLite

**File:** `src/cmd/server/secrets.go`

The ES256 private key is stored as PEM in the `metadata` table of the SQLite database, unencrypted. This is unchanged from the prior HS256 secret storage design. A database backup or file system access grants full token forgery capability. This is an accepted architectural trade-off (key material must live somewhere) but worth noting as the consequence of a DB compromise.

---

### INFO — I2: JWKS `kid` Not Used to Select Parse Key

**File:** `src/internal/auth/jwt.go:194-201`

The JWKS endpoint serves keys with stable `kid` values derived from the key's DER-encoded public key hash. However, `Parse` and `ParseServiceToken` ignore `kid` when selecting which key to try — they always try the current key first, then the previous key on failure. This means round-trip key hint is unused. Not a security issue, but a missed optimization and a deviation from the JWKS specification's intent.

---

## Summary Table

| ID | Title | Severity | Direct Exploit |
|---|---|---|---|
| M1 | Host header injection in discovery endpoint | Medium | Yes (dev/staging); mitigated in prod |
| M2 | RequireScope/RequireAudience not wired to any route | Medium | No (identity server routes self-protect; risk to consumers) |
| L1 | Service token type-confusion in authorizePasskey | Low | No (fails at exchange, audit log pollution) |
| L2 | Empty audience on client_credentials client → 500 | Low | No (operational failure only) |
| L3 | verifyAdminPassword under 30/min limiter, not 5/min | Low | Requires admin session + CSRF |
| I1 | EC private key plaintext in SQLite | Info | Requires DB access |
| I2 | JWKS kid not used for key selection | Info | No |

---

## Recommended Fix Priority

1. **M1 (Host header injection):** Fix immediately — use the configured issuer string from `TokenIssuer` in the discovery handler instead of `r.Host`. The comment already says this is the right approach.
2. **M2 (Unwired middleware):** Wire `RequireAudience` to the identity server's own routes; document that downstream services must add it for their own routes. Apply `RequireScope` to any routes where scope differentiation is desired.
3. **L1 (Service token type-confusion):** Add `typ` check to `parseWithKey` consistent with `ParseServiceToken`.
4. **L2 (Empty audience):** Add admin UI validation requiring non-empty audience for `client_credentials` clients.
