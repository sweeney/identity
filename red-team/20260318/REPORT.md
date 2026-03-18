# Red Team Report: id.swee.net

**Target:** https://id.swee.net/
**Source:** https://github.com/sweeney/identity/
**Date:** 2026-03-18
**Stack:** Go, SQLite, OAuth 2.0 + PKCE, JWT (HS256), bcrypt, Cloudflare

---

## Vulnerability Summary

| # | Severity | Vulnerability | Confirmed | PoC |
|---|----------|--------------|-----------|-----|
| 1 | **HIGH** | Wildcard CORS - reflects any Origin | Live | `exploits/cors-exploit.html` |
| 2 | **MEDIUM** | No rate limiting on any auth endpoint | Live | `exploits/brute-force.py` |
| 3 | **MEDIUM** | Timing-based username enumeration | Live | `exploits/username-enum.py` |
| 4 | **MEDIUM** | Admin session not validated against current user state | Code | - |
| 5 | **LOW-MED** | No CSRF on OAuth authorize POST | Code | - |
| 6 | **LOW-MED** | State parameter not URL-encoded in OAuth redirect | Code | - |
| 7 | **LOW** | Admin login CSRF | Live | `exploits/admin-csrf-login.html` |
| 8 | **LOW** | Backup trigger via GET (should be POST+CSRF) | Code | - |
| 9 | **LOW** | Minimal password policy (8 chars, no complexity) | Code | - |
| 10 | **LOW** | CSP allows `unsafe-inline` for scripts | Live | - |
| 11 | **INFO** | Full API spec publicly exposed | Live | - |
| 12 | **INFO** | HSTS max-age only 30 days, no preload | Live | - |
| 13 | **INFO** | Admin panel publicly accessible (no IP restriction) | Live | - |

---

## Detailed Findings

### 1. HIGH: Wildcard CORS Origin Reflection

**Location:** `cmd/server/main.go:337-345`

The CORS middleware reflects any `Origin` header verbatim in `Access-Control-Allow-Origin`. This was **confirmed live**:

```
$ curl -H "Origin: https://evil.com" https://id.swee.net/api/v1/auth/me
→ access-control-allow-origin: https://evil.com
→ access-control-allow-headers: Authorization, Content-Type
→ access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
```

**Impact:** Any attacker-controlled website can make authenticated cross-origin API calls and read responses. This enables:
- Stealing user profile data via `/api/v1/auth/me`
- Cross-origin login to capture tokens
- Token refresh from attacker pages for persistent access

**Fix:** Replace origin reflection with an explicit allowlist.

---

### 2. MEDIUM: No Rate Limiting

**Location:** All routers — no rate limiting middleware exists anywhere.

**Confirmed live:** 5 rapid login attempts all returned 401 with no blocking, no 429, no delay escalation.

**Impact:** Enables brute-force password attacks and credential stuffing at full speed.

**Fix:** Add per-IP rate limiting, especially on `/api/v1/auth/login`, `/admin/login`, `/oauth/authorize`, and `/oauth/token`.

---

### 3. MEDIUM: Timing-Based Username Enumeration

**Location:** `internal/service/auth_service.go:62-63`

Despite having a dummy bcrypt hash for unknown users, **live testing revealed a clear timing side-channel**:

| User | Avg Response Time |
|------|------------------|
| `admin` (exists) | ~400-640ms |
| `nonexistent_xyz` | ~130-320ms |

The ~300ms delta is consistent and easily exploitable. The dummy hash appears to not be working as intended, or bcrypt cost differences between the dummy and real hash create measurable timing variance.

**Impact:** Attacker can enumerate valid usernames before attempting password brute-force.

**Fix:** Ensure the dummy hash uses identical bcrypt cost. Consider adding random jitter to auth response times.

---

### 4. MEDIUM: Admin Session Not Validated Against User State

**Location:** `internal/handler/admin/handler.go:58-69`

The admin session JWT only checks signature and expiry. It does **not** re-validate that:
- The user still exists
- The user is still active
- The user still has admin role

**Impact:** A deactivated or demoted admin retains access for up to 8 hours.

**Fix:** Re-check user state from DB on every admin request.

---

### 5. LOW-MED: No CSRF on OAuth Authorize POST

**Location:** `internal/handler/oauth/handler.go:104-150`

The POST handler has no CSRF token. Comment says "re-validate client on POST to prevent CSRF-style attacks" but client re-validation is not CSRF protection.

**Impact:** Limited — user must type their password, so exploitation requires social engineering.

---

### 6. LOW-MED: State Parameter Not URL-Encoded

**Location:** `internal/handler/oauth/handler.go:144-149`

```go
redirectURL += "&state=" + state  // no url.QueryEscape()
```

Special characters in `state` (`&`, `#`) can break the redirect URL structure.

---

### 7-10. LOW Findings

- **Admin login CSRF** (`/admin/login` POST has no CSRF token) — enables login CSRF
- **Backup on GET** (`/admin/backup` is GET, should be POST+CSRF) — can be triggered by img tags
- **Weak password policy** (only ≥8 chars, no complexity) — combined with no rate limiting, increases brute-force risk
- **CSP unsafe-inline** (`script-src 'self' 'unsafe-inline'`) — weakens XSS protection

---

## What's Done Well

The codebase has solid fundamentals that prevented several common attack classes:

- **No SQL injection** — all queries use parameterized statements
- **No hardcoded secrets** — JWT secrets auto-generated or from env vars
- **Refresh token rotation with theft detection** — family-based revocation
- **Tokens stored as SHA-256 hashes** — raw tokens never persisted
- **bcrypt at cost 12** — reasonable password hashing
- **PKCE S256 required** — no downgrade to `plain`
- **Auth code single-use** — atomic check-and-mark
- **IDOR protection** — non-admins limited to own records
- **Strong security headers** — X-Frame-Options DENY, nosniff, HSTS, strict referrer
- **HttpOnly SameSite=Strict cookies** — session cookies well-configured
- **OAuth client_id validated before redirect** — prevents open redirects to unregistered URIs

---

## Exploit Files

```
exploits/
├── cors-exploit.html       # Interactive CORS PoC (3 attack scenarios)
├── username-enum.py        # Async timing-based username enumeration
├── brute-force.py          # Async password brute-forcer
└── admin-csrf-login.html   # Login CSRF auto-submit
```

---

## Recommended Priority

1. **Fix CORS** (high impact, easy fix — allowlist origins)
2. **Add rate limiting** (medium impact, moderate effort)
3. **Fix timing side-channel** (investigate why dummy hash isn't working)
4. **Validate admin sessions against DB** (medium impact, easy fix)
5. **CSRF on OAuth authorize** (add token to form)
6. **URL-encode state parameter** (one-line fix)
