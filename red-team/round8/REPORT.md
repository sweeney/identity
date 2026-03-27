# Round 8 Red Team Report — id.swee.net

**Target:** `https://id.swee.net/`
**Source:** Fresh clone of `https://github.com/sweeney/identity` (latest commit: `0b05671 Fix Round 7 red team findings`)
**Date:** 2026-03-26

---

## Executive Summary

Round 8 opened by verifying all five Round 7 fixes — all confirmed correct and complete. Six new findings were identified: two MEDIUM, two LOW, and two INFO. The most impactful are a regression in the discovery endpoint (N1) and a cross-client token disclosure in the introspection endpoint (N4). No auth bypasses or privilege escalation paths were found.

---

## R7 Fixes Verified

| R7 ID | Finding | Fix status |
|---|---|---|
| M1 | Host header injection in discovery endpoint | **FIXED** — `discovery()` now calls `h.tokenIssuer.Issuer()` instead of `r.Host` |
| M2 | `RequireScope`/`RequireAudience` not wired | **FIXED** — `requireUserAuth` closure in `api/router.go:24` chains `RequireAuth` + `RequireAudience(issuer.Issuer())` for all protected routes |
| L1 | Service token type-confusion in `parseWithKey` | **FIXED** — `parseWithKey` now rejects `typ: "at+jwt"` tokens explicitly (`jwt.go:250`) |
| L2 | Empty audience on `client_credentials` client → 500 | **FIXED** — audience validated non-empty in both `oauthNewPost` and `oauthEditPost` when `client_credentials` grant is selected (`handler.go:705`, `handler.go:803`) |
| L3 | `verifyAdminPassword` endpoints under 30/min limiter | **FIXED** — all re-auth POST routes individually wrapped with `wrapAuth` in `main.go:339-345` (also covers `rotate-secret` and `clear-prev-secret` not in original finding) |

---

## New Findings

### MEDIUM — N1: M1 Fix Regression — Discovery Document Serves Invalid Non-URL Strings

**File:** `internal/config/config.go:118-120`, `internal/handler/oauth/handler.go:494-514`

The M1 fix correctly stopped using `r.Host` to build the issuer URL. Instead it uses `Issuer()`, which returns the configured `JWT_ISSUER` env var (falling back to `SITE_NAME`, falling back to `"Identity"`). In production, this is set to `"id.swee.net"` — a bare hostname with no scheme.

The discovery document served live at `https://id.swee.net/.well-known/oauth-authorization-server` now returns:

```json
{
  "issuer": "id.swee.net",
  "authorization_endpoint": "id.swee.net/oauth/authorize",
  "token_endpoint": "id.swee.net/oauth/token",
  "jwks_uri": "id.swee.net/.well-known/jwks.json",
  ...
}
```

These are not absolute URLs — they have no scheme. RFC 8414 §2 explicitly requires the issuer to be a URL that uses the `https` scheme, and all endpoint values must be absolute URIs prefixed with the issuer. `new URL("id.swee.net/oauth/authorize")` in a browser or Node.js returns a relative URL with `pathname: "id.swee.net/oauth/authorize"`, not an absolute one.

**Impact:** Any OAuth client library that uses auto-discovery (RFC 8414) to configure its endpoints will either throw an error when parsing the discovery document, or silently construct incorrect endpoint URLs (relative paths instead of absolute). The JWTs themselves still work — both sides agree on `iss: "id.swee.net"` — but the discovery document is unusable for standard-compliant clients.

**Fix:** Set `JWT_ISSUER=https://id.swee.net` in the production environment. Optionally add a startup validation check that the configured issuer matches `^https://`.

---

### LOW — N2: `script-src 'self'` CSP Blocks Inline Redirect Script in `oauth_redirect.html`

**File:** `internal/ui/templates/oauth_redirect.html`, `cmd/server/main.go:426`

The server sends `Content-Security-Policy: ... script-src 'self'; ...` (no `'unsafe-inline'`) on all responses. The `oauth_redirect.html` template contains an inline script:

```html
<script>window.location.replace(document.getElementById('redirect-link').href);</script>
```

This script is blocked by `script-src 'self'` in every modern browser. When a user completes the password-based OAuth login flow, they see the "Redirecting to app…" page but are not automatically redirected — they must click the fallback "Click here" link manually.

The passkey-based flow is unaffected (the JS redirect happens inside `passkey-login.js`, an external file).

**Impact:** Functional degradation of the password-based OAuth flow. No security vulnerability — but the authorization code and state are visible in the URL of the fallback link for the duration the user is on the page, slightly increasing the window for shoulder-surfing.

**Fix:** Either (a) move the redirect logic to a static `.js` file served from `/static/`, or (b) add a `nonce` to the CSP and inject it into the script tag, or (c) remove the inline script entirely since the `Accept: application/json` passkey path and the `<a>` fallback already cover the redirect needs.

---

### INFO — N3: `javascript:` Redirect URIs Executable via Client-Side JS Redirect

**File:** `internal/ui/static/passkey-login.js:53`, `internal/ui/templates/oauth_redirect.html:5`

`passkey-login.js` performs the final redirect using:
```javascript
window.location.href = data.redirect_uri;
```

`oauth_redirect.html` renders the redirect link as:
```html
<a id="redirect-link" href="{{.RedirectURL}}">...</a>
```
where `RedirectURL` is passed as `template.URL(...)`.

Both accept the redirect URI as-is from the server. If an admin registers an OAuth client with `javascript:alert(document.cookie)` as a redirect URI:
1. The `containsURI` exact-match check passes (it's registered)
2. The passkey JS redirect does `window.location.href = "javascript:alert(document.cookie)?code=abc"` → XSS executes
3. The fallback link in `oauth_redirect.html` is an `href="javascript:..."` that a user clicks → XSS executes (CSP doesn't prevent `href` navigation)

**Precondition:** Requires admin access to register the malicious client. An admin who does this can already do anything (read all users, tokens, audit logs, rotate secrets). This is purely a defense-in-depth gap.

**Fix:** In `passkey-login.js`, validate that `data.redirect_uri` has an `https:` or `http:` scheme before navigating: `if (!/^https?:\/\//i.test(data.redirect_uri)) throw new Error('Invalid redirect');`. The server could also reject `javascript:` and `data:` scheme redirect URIs at registration time.

---

### MEDIUM — N4: Introspect Endpoint Discloses Any Token to Any Authenticated Client

**File:** `internal/handler/oauth/handler.go:426-491`

RFC 7662 §2.1 states the authorization server "SHOULD determine whether the token is valid and whether it belongs to the requesting client." The `/oauth/introspect` endpoint authenticates the requesting client correctly (lines 434-446) but performs no ownership check before returning full token claims.

After verifying client credentials, the handler parses any presented token and returns its full contents. For a service token belonging to client A, a completely unrelated client B can introspect it and receive:

```json
{
  "active": true,
  "sub": "client-a",
  "client_id": "client-a",
  "scope": "read:users write:data",
  "token_type": "Bearer",
  "jti": "...",
  "exp": 1234567890,
  "iat": 1234567800
}
```

For user tokens, any authenticated client learns the `sub` (user UUID) and `username` of any user who has an active token.

**Affected code path:**
```go
// line 456 — no check that sc.ClientID == creds.ClientID
if sc, err := h.tokenIssuer.ParseServiceToken(token); err == nil {
    resp := map[string]any{
        "active":    true,
        "sub":       sc.ClientID,    // reveals owning client
        "client_id": sc.ClientID,
        "scope":     sc.Scope,       // reveals granted scopes
        ...
    }
    jsonOK(w, resp)
    return
}
// line 478 — same for user tokens
if uc, err := h.tokenIssuer.Parse(token); err == nil {
    jsonOK(w, map[string]any{
        "active":   true,
        "sub":      uc.UserID,
        "username": uc.Username,  // reveals username
    })
    return
}
```

**Impact:** Any OAuth client (including low-privilege ones) can enumerate: which service clients are active, what scopes they hold, and the identity of any user with a valid session token — provided the attacker can obtain or guess the opaque JTI. JTIs are UUIDs; guessing is not feasible, but a compromised low-privilege client can introspect tokens it legitimately received (e.g., via token passing) to pivot to user identity information. More practically, this violates the principle of least privilege between tenants of the same authorization server.

**Fix:** Add ownership validation before returning claims. For service tokens: `if sc.ClientID != creds.ClientID { jsonOK(w, map[string]any{"active": false}); return }`. For user tokens, check that the token's audience matches the requesting client's registered audience.

---

### LOW — N5: Introspect Response Missing `aud` Claim for Service Tokens

**File:** `internal/handler/oauth/handler.go:457-472`

RFC 7662 §2.2 specifies the introspect response SHOULD include `aud` if the token contains an audience. Service tokens (client credentials flow) are issued with an `aud` claim (set to the client's configured `audience` field). The introspect response for service tokens omits `aud`:

```go
resp := map[string]any{
    "active":     true,
    "sub":        sc.ClientID,
    "client_id":  sc.ClientID,
    "scope":      sc.Scope,
    "token_type": "Bearer",
    "jti":        sc.JTI,
    // "aud" missing — present in the token but not reflected in response
}
```

**Impact:** Resource servers that rely on introspection to validate the token audience cannot do so — they receive `active: true` with no audience information, and must either trust the token without audience verification or re-parse the JWT themselves, defeating the purpose of introspection.

**Fix:** Include `"aud": sc.Audience` in the introspect response for service tokens (requires `ServiceClaims` to expose the `Audience` field, or retrieve it from the registered client).

---

### INFO — N6: OAuth Client ID Accepts Arbitrary Characters

**File:** `internal/handler/admin/handler.go:677`

The admin `oauthNewPost` handler validates that the client ID is non-empty but applies no format constraints:

```go
id := strings.TrimSpace(r.FormValue("id"))
if id == "" || name == "" {
    // error
}
```

Spaces, slashes, null bytes, and other special characters are accepted. While client IDs are admin-controlled and this is not exploitable without existing admin access, a malformed client ID (e.g. containing `/` or `\x00`) could cause unexpected behavior in URL construction, logging, or future code paths that embed the client ID in structured output.

**Fix:** Validate client IDs against a safe character set at registration time: `^[a-zA-Z0-9._-]+$` (or similar).

---

## Summary

| Status | Count | IDs |
|---|---|---|
| R7 findings fixed | 5 | M1, M2, L1, L2, L3 |
| New MEDIUM | 2 | N1, N4 |
| New LOW | 2 | N2, N5 |
| New INFO | 2 | N3, N6 |
| Auth bypasses | 0 | — |

### Fix Priority

1. **N1** — Set `JWT_ISSUER=https://id.swee.net` in production env immediately. The discovery document is currently unusable for RFC-compliant OAuth clients.
2. **N4** — Add ownership validation in the introspect handler: reject service tokens not owned by the requesting client; reject user tokens whose audience doesn't match the requester.
3. **N2** — Extract inline redirect script to a static file to fix broken auto-redirect in password OAuth flow.
4. **N5** — Include `aud` in service token introspect responses so resource servers can validate audience via introspection.
5. **N3** — Add scheme validation in `passkey-login.js` before navigating; optionally reject non-https redirect URIs at client registration time.
6. **N6** — Restrict OAuth client IDs to a safe alphanumeric character set at registration time.
