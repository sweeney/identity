# Finding: Admin Passkey Login Endpoint Lacks CSRF Protection

**Date:** 2026-03-18
**Severity:** Low (requires pre-obtained access token; mitigated by SameSite=Strict)
**Target:** https://id.swee.net/
**CWE:** CWE-352 (Cross-Site Request Forgery)

## Summary

The `POST /admin/login/passkey` endpoint accepts an `access_token` via form body and sets an admin session cookie, but has **no CSRF token validation**. Unlike all other POST endpoints in the admin panel, this route is not wrapped in `requireCSRF()`. However, the admin session cookie uses `SameSite=Strict`, which provides robust browser-level CSRF protection in modern browsers.

## Technical Detail

### Route Registration (Missing CSRF)

From `internal/handler/admin/router.go`, line 48:

```go
// Public (no session, no CSRF)
mux.HandleFunc("GET /admin/login", h.loginGet)
mux.HandleFunc("POST /admin/login", h.loginPost)
mux.HandleFunc("POST /admin/login/passkey", h.loginPasskey)  // <-- no requireCSRF
```

Compare with every other POST route in the admin panel:

```go
mux.Handle("POST /admin/logout", h.requireSession(h.requireCSRF(http.HandlerFunc(h.logout))))
mux.Handle("POST /admin/users/new", h.requireSession(h.requireCSRF(http.HandlerFunc(h.usersNewPost))))
// ... all other POST routes use requireCSRF
```

The `POST /admin/login` (password login) also lacks `requireCSRF`, but that is expected -- there is no session yet from which to derive a CSRF token, and the password itself serves as a secret.

### The loginPasskey Handler

From `internal/handler/admin/handler.go`, lines 258-296:

```go
func (h *adminHandler) loginPasskey(w http.ResponseWriter, r *http.Request) {
    accessToken := r.FormValue("access_token")
    if accessToken == "" {
        // ... render error
        return
    }

    claims, err := h.tokenIssuer.Parse(accessToken)
    if err != nil {
        // ... render error
        return
    }

    user, err := h.userSvc.GetByID(claims.UserID)
    if err != nil || user.Role != domain.RoleAdmin {
        // ... render error
        return
    }

    // Sets admin_session cookie
    if err := h.setSession(w, user.Username); err != nil {
        // ...
        return
    }
    http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}
```

The handler:
1. Reads `access_token` from the form body
2. Validates it as a JWT
3. Checks the user has admin role
4. Sets the `admin_session` cookie
5. Redirects to `/admin/`

There is no Origin/Referer check, no CSRF token, and no other cross-origin protection beyond what the browser enforces via SameSite.

### Session Cookie Settings

From `internal/handler/admin/handler.go`, lines 134-143:

```go
http.SetCookie(w, &http.Cookie{
    Name:     "admin_session",
    Value:    tokenStr,
    Path:     "/admin",
    MaxAge:   int(sessionTTL.Seconds()),
    HttpOnly: true,
    Secure:   h.cfg.Production,       // true in production
    SameSite: http.SameSiteStrictMode, // SameSite=Strict
})
```

Key properties:
- **SameSite=Strict**: The browser will NOT send this cookie on any cross-site request (including top-level navigations from another site). This is the strongest SameSite setting.
- **HttpOnly**: Not readable by JavaScript.
- **Secure**: Set in production (HTTPS only).
- **Path=/admin**: Scoped to admin paths only.

## Attack Analysis

### Theoretical CSRF Attack

An attacker who has somehow obtained a valid JWT access token for an admin user could attempt:

```html
<!-- On https://evil.com -->
<form method="POST" action="https://id.swee.net/admin/login/passkey">
  <input type="hidden" name="access_token" value="eyJhbG...stolen_token">
</form>
<script>document.forms[0].submit();</script>
```

This would POST the access token to the login endpoint. If the cookie were set, the victim's browser would then have an admin session.

### Why This Does NOT Work in Practice

1. **SameSite=Strict blocks the attack.** When `evil.com` submits the form, the browser will NOT include the `admin_session` cookie in the request to `id.swee.net`. More importantly, the response's `Set-Cookie` with `SameSite=Strict` **will be accepted** by the browser (it is a response cookie, not a request cookie). However, this is actually the login endpoint -- there is no existing session cookie needed. The attack would:
   - POST the form (cross-site) -- the server processes it and sets the `admin_session` cookie
   - Redirect to `/admin/` -- but this redirect from the cross-site POST is treated as a cross-site navigation, and `SameSite=Strict` means the cookie is NOT sent on the redirect
   - The user lands on `/admin/login` (kicked out by `requireSession`)

   So the attack fails because the newly-set SameSite=Strict cookie is not sent on the subsequent navigation triggered by the cross-site form submission.

2. **The attacker needs a valid access token.** The JWT access token has a 15-minute TTL, is HS256-signed with the server's secret, and requires the user to have admin role. Obtaining one requires either:
   - Compromising the JWT secret
   - Intercepting a token in transit (mitigated by HTTPS + HSTS)
   - XSS on `id.swee.net` itself (at which point CSRF is irrelevant)

3. **Login CSRF has limited value.** Even if the attack succeeded, the result is that the victim's browser has an admin session for the *attacker's chosen admin account*. This is a "login CSRF" -- the victim is logged in as someone else. The attacker gains nothing unless they can trick the victim into performing sensitive actions while logged in as the wrong admin.

### Edge Cases

- **Older browsers** without SameSite support would be vulnerable. However, SameSite=Strict has been supported since Chrome 51 (2016), Firefox 60 (2018), Safari 13 (2019), and Edge 16 (2017). The remaining population of non-supporting browsers is negligible.
- **Same-site attacks**: If the attacker controls `evil.swee.net`, the form submission is same-site (same eTLD+1). `SameSite=Strict` still blocks this because it applies to cross-*origin* navigations that are not same-site top-level navigations initiated by the user. However, a form auto-submitted by JavaScript from `evil.swee.net` may be treated differently by some browsers. This edge case is browser-specific but generally `SameSite=Strict` blocks auto-submitted forms from sibling subdomains.

## Protections In Place

| Protection | Status |
|---|---|
| CSRF token on `/admin/login/passkey` | **MISSING** |
| SameSite=Strict on session cookie | Present (strong mitigation) |
| HttpOnly on session cookie | Present |
| Secure flag on session cookie | Present (production) |
| Access token required (HS256, 15min TTL) | Present (strong prerequisite) |
| X-Frame-Options: DENY | Present (prevents framing) |
| CSP frame-ancestors 'none' | Present (prevents framing) |

## Risk Assessment

**Effective risk: Low.** The SameSite=Strict cookie attribute provides robust CSRF protection at the browser level. The access token requirement makes the attack impractical even without SameSite. The combination of both mitigations makes exploitation unrealistic in any modern browser.

However, defense-in-depth principles suggest that application-level CSRF protection should not rely solely on browser-enforced SameSite cookies.

## Recommendations

1. **Add explicit CSRF protection to `/admin/login/passkey`.** Since this is a login endpoint (no session exists yet), the session-derived CSRF token approach used elsewhere cannot be applied. Options:
   - **Origin header check**: Verify `Origin` or `Referer` header matches `https://id.swee.net`. This is lightweight and appropriate for login endpoints.
   - **Double-submit cookie**: Set a random value in a cookie during the login page render, require it back in the form. This works without a session.

2. **Also consider adding Origin/Referer checking to `POST /admin/login`** (password login) for the same defense-in-depth reason, even though the password itself serves as a CSRF-like secret.

3. **The same pattern exists in `/oauth/authorize/passkey`** (`internal/handler/oauth/handler.go`, line 216). This endpoint also accepts `access_token` via form POST with no CSRF protection. The same analysis applies -- SameSite mitigates it, but Origin checking would add depth.

## References

- `internal/handler/admin/router.go` -- route registration, line 48 (no CSRF middleware)
- `internal/handler/admin/handler.go` -- `loginPasskey()` lines 258-296, `setSession()` lines 129-144, `requireCSRF()` lines 173-185
- `internal/handler/oauth/handler.go` -- `authorizePasskey()` lines 216-271 (same pattern)
- `cmd/server/main.go` -- security headers including X-Frame-Options and CSP (lines 397-446)
