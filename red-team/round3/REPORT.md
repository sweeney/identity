# Red Team Report: id.swee.net — Round 3

**Target:** https://id.swee.net/
**Source:** https://github.com/sweeney/identity/
**Date:** 2026-03-18
**Stack:** Go, SQLite (WAL), OAuth 2.0 + PKCE, JWT (HS256), bcrypt, Cloudflare Tunnel
**Previous rounds:** `archive/round1/`, `archive/round2/`

---

## Round 2 Remediation Verification

| # | R2 Finding | Claimed Fix | Verified |
|---|-----------|-------------|----------|
| 1 | Token rotation race (TOCTOU) | Atomic RotateToken() with write-lock promotion | **FIXED** — read+validate+rotate in single tx; `SetMaxOpenConns(1)` serializes all DB access |
| 2 | No rate limiting | Per-IP middleware, strict on auth endpoints | **PARTIAL** — rate limiter exists but bypassable (see #1 below) |
| 3 | CF-Connecting-IP trusted unconditionally | TRUST_PROXY=cloudflare config flag | **PARTIAL** — `httputil.ExtractClientIP` fixed, but rate limiter uses its own unfixed copy (see #1) |
| 4 | Auth code error oracle | Single unified error message | **FIXED** — confirmed in code and live |
| 5 | Admin password logged to journal | Writes to initial-password.txt (0600) | **FIXED** — confirmed in code |
| 6 | No re-auth for destructive ops | Password confirmation for delete/role/deactivation | **FIXED** — with caveats (see #3 below) |
| 7 | OAuth client deletion not audit-logged | All 3 OAuth CRUD ops audit-logged | **FIXED** — confirmed in code |
| 8 | BEGIN IMMEDIATE mismatch | Write-lock promotion in RotateToken() | **FIXED** — moot because `SetMaxOpenConns(1)` serializes transactions |
| 9 | DB file permissions race | umask(0077) before sql.Open() | **FIXED** — confirmed in code |
| 10 | HSTS weak | 63072000 + includeSubDomains + preload | **FIXED** — confirmed in code |
| 11 | 8-hour admin session | Reduced to 2 hours | **FIXED** — confirmed in code |
| 12 | No form-action in CSP | Added form-action 'self' | **FIXED** — confirmed in code and live |
| 13 | Deterministic CSRF | Accepted risk | **ACCEPTED** |
| 14 | Access tokens valid after logout | Accepted risk | **ACCEPTED** |
| 15 | Auth code TOCTOU (mitigated) | Already mitigated | **CONFIRMED** |

**Summary:** 12 of 13 actionable findings fixed. 2 accepted risks are reasonable. But the rate limiting fix introduced a new critical vulnerability.

---

## New Vulnerability Summary

| # | Severity | Vulnerability | Source | PoC |
|---|----------|--------------|--------|-----|
| 1 | **HIGH** | Rate limiter bypassed via dual ExtractClientIP implementations | Code | `exploits/ratelimit-bypass.sh` |
| 2 | **MEDIUM** | POST /oauth/authorize missing strict rate limit | Code | `exploits/oauth-authorize-bruteforce.sh` |
| 3 | **MEDIUM** | OAuth client edit not covered by re-auth | Code | — |
| 4 | **LOW** | Rate limiter visitor map unbounded (memory DoS) | Code | — |
| 5 | **LOW** | RATE_LIMIT_DISABLED env var has no production guard | Code | — |
| 6 | **INFO** | Concurrent integration test for RotateToken is sequential, not truly concurrent | Code | — |

---

## Detailed Findings

### 1. HIGH: Rate Limiter Bypass via Dual ExtractClientIP

**Location:** `internal/ratelimit/ratelimit.go:110-121` vs `internal/httputil/clientip.go:11-22`

The rate limiter package contains its own `ExtractClientIP()` function that **always trusts** `CF-Connecting-IP`, regardless of the `TRUST_PROXY` configuration. Meanwhile, the shared `httputil.ExtractClientIP()` correctly respects the config:

```go
// ratelimit.go:112 — ALWAYS trusts CF-Connecting-IP
func ExtractClientIP(r *http.Request) string {
    if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
        return cf  // ← unconditional trust
    }
    // fallback to RemoteAddr
}

// httputil/clientip.go:11 — respects config
func ExtractClientIP(r *http.Request, trustProxy string) string {
    if trustProxy == "cloudflare" {  // ← config check
        if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
            return cf
        }
    }
    // fallback to RemoteAddr
}
```

**Impact:** An attacker can rotate the `CF-Connecting-IP` header to get a fresh rate limit bucket per request, completely bypassing all rate limiting. This undermines the entire rate limiting remediation from Round 2.

**Attack:**
```bash
# Each request uses a different spoofed IP → fresh rate limit bucket
for i in $(seq 1 1000); do
  curl -H "CF-Connecting-IP: 192.0.2.$i" \
    -X POST https://id.swee.net/api/v1/auth/login \
    -d '{"username":"admin","password":"attempt'$i'"}'
done
```

**Fix:** Remove the local `ExtractClientIP` from `ratelimit.go`. Have `Limiter` accept a `trustProxy` config parameter and call `httputil.ExtractClientIP(r, trustProxy)`.

---

### 2. MEDIUM: POST /oauth/authorize Missing Strict Rate Limit

**Location:** `cmd/server/main.go:287-290`

The strict auth rate limiter (5 req/min) is applied to:
- `POST /api/v1/auth/login` (line 287)
- `POST /oauth/token` (line 289)
- `POST /admin/login` (line 296)

But `POST /oauth/authorize` is handled by the catch-all `/oauth/` route (line 290) which only gets the general rate limiter (30 req/min). Since `/oauth/authorize` accepts username+password for authentication, it's a brute-force vector at **6x the rate** of the login endpoint.

Combined with finding #1 (CF-Connecting-IP bypass), this endpoint has effectively **no rate limiting at all**.

**Fix:** Apply `wrapAuth()` to `POST /oauth/authorize`, or add a separate strict-limited route for it.

---

### 3. MEDIUM: OAuth Client Edit Not Covered by Re-auth

**Location:** `internal/handler/admin/handler.go`

The new re-auth feature requires password confirmation for:
- User deletion
- User role changes
- User deactivation
- OAuth client deletion

But **OAuth client editing** (modifying `redirect_uri`, `name`, etc.) does NOT require re-auth. An attacker with a stolen admin session could modify an OAuth client's redirect URI to point to an attacker-controlled domain, hijacking the entire OAuth flow for that client's users.

This is arguably more dangerous than deleting a client (which causes a visible outage), since a redirect URI change enables silent token theft.

**Fix:** Require password re-auth for OAuth client updates, especially `redirect_uri` changes.

---

### 4. LOW: Rate Limiter Visitor Map Unbounded

**Location:** `internal/ratelimit/ratelimit.go:22-26, 44-57`

The visitor map has no size limit. An attacker (especially combined with finding #1) can create unlimited entries by using unique IPs. Each entry allocates a `rate.Limiter` and stays in memory for 3 minutes.

At scale (thousands of unique IPs/second), this could exhaust server memory.

**Fix:** Add a maximum visitor count (e.g., 100,000) with LRU eviction, or use a probabilistic data structure.

---

### 5. LOW: RATE_LIMIT_DISABLED Has No Production Guard

**Location:** `internal/config/config.go`, `cmd/server/main.go:265-271`

Setting `RATE_LIMIT_DISABLED=1` completely disables all rate limiting with only a log message. There is no check preventing this in production (`IDENTITY_ENV=production`). If this env var leaks from dev/staging to production, all rate limiting is silently disabled.

**Fix:** Refuse to start (or log a warning and ignore the flag) when `IDENTITY_ENV=production` and `RATE_LIMIT_DISABLED=1`.

---

### 6. INFO: RotateToken Integration Test Not Truly Concurrent

**Location:** `internal/store/token_store_integration_test.go`

The `TestTokenStore_RotateToken_PreventsConcurrentDoubleRotation` test calls `RotateToken` twice *sequentially*, not concurrently. This doesn't test the actual race condition scenario. A proper test would use goroutines with a `sync.WaitGroup` barrier.

Note: The fix is still correct (due to `SetMaxOpenConns(1)` serializing all connections), but the test doesn't prove it.

---

## What's Fixed Well

The maintainer did excellent work on the majority of findings:

- **Token rotation race** — correctly moved read+validate+rotate into a single transaction. The `SetMaxOpenConns(1)` setting ensures complete serialization of all database operations, making the TOCTOU impossible.
- **Auth code error oracle** — unified error messages, eliminating the information leak.
- **Admin password** — no longer logged to journal; written to a 0600 file that's documented for deletion.
- **Re-auth for destructive ops** — properly implemented with server-side password verification via `AuthorizeUser()`. Cannot be bypassed by omitting the field (returns error). CSRF protected.
- **DB permissions** — umask set before database creation.
- **HSTS** — strong configuration with includeSubDomains and preload.
- **CSP** — form-action 'self' added.
- **Admin session** — reduced from 8 hours to 2 hours.
- **Audit logging** — OAuth client CRUD operations all audit-logged.

---

## Live Server Verification

| Check | Result |
|-------|--------|
| Rate limiting on `/api/v1/auth/login` | **Working** — 429 after ~7 attempts, `Retry-After: 12` |
| Auth code error oracle | **Fixed** — unified message: `"The authorization code is invalid or has expired."` |
| CSP form-action | **Fixed** — `form-action 'self'` present |
| HSTS | **Partially deployed** — still showing `max-age=2592000` (30 days) live, code shows 63072000 |
| CF-Connecting-IP spoofing | **Blocked by Cloudflare** — returns 403 (error 1000) |
| Security headers | **All present** — nosniff, DENY, strict-origin-when-cross-origin |
| PKCE enforcement | **Confirmed** — `/oauth/authorize` requires `code_challenge_method=S256` |

Note: Through Cloudflare, the `CF-Connecting-IP` spoofing for rate limit bypass (finding #1) is mitigated at the CDN layer — Cloudflare returns 403 when clients send this header. However, the code-level vulnerability remains: if Cloudflare is ever removed or bypassed, the rate limiter is trivially circumvented.

---

## Exploit Files

```
exploits/
├── ratelimit-bypass.sh           # CF-Connecting-IP rotation to bypass rate limiting
└── oauth-authorize-bruteforce.sh # Brute-force via unprotected OAuth authorize
```

---

## Recommended Priority

1. **Fix dual ExtractClientIP** (HIGH — completely undermines rate limiting)
   - Remove `ratelimit.ExtractClientIP()`, use `httputil.ExtractClientIP()` with config
2. **Add strict rate limit to POST /oauth/authorize** (MEDIUM — brute-force vector)
3. **Require re-auth for OAuth client edits** (MEDIUM — redirect URI hijacking)
4. **Bound the visitor map** (LOW — memory DoS prevention)
5. **Guard RATE_LIMIT_DISABLED in production** (LOW — operational safety)

---

## Overall Assessment

The project has improved significantly across three rounds. The original 13 findings from Round 1 and 15 from Round 2 have been methodically addressed. The remaining issues are concentrated in the newly-introduced rate limiting code, which contains a critical consistency bug (dual IP extraction) but is otherwise well-structured.

The core authentication, session management, token handling, and CSRF protections are now solid. The codebase demonstrates a mature security posture with proper parameterized queries, bcrypt hashing, constant-time comparisons, PKCE enforcement, and comprehensive security headers.

**One fix (removing the duplicate ExtractClientIP and routing POST /oauth/authorize through the strict limiter) would close all HIGH and MEDIUM findings.**
