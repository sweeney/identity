# Red Team Report: id.swee.net — Round 2

**Target:** https://id.swee.net/
**Source:** https://github.com/sweeney/identity/
**Date:** 2026-03-18
**Stack:** Go, SQLite (WAL), OAuth 2.0 + PKCE, JWT (HS256), bcrypt, Cloudflare Tunnel
**Round 1 archive:** `archive/2026-03-18-round1/`

---

## Round 1 Remediation Verification

| Round 1 Finding | Status |
|----------------|--------|
| Wildcard CORS origin reflection | **FIXED** — no origin reflection observed |
| No rate limiting on auth endpoints | **NOT FIXED** — confirmed still absent (see #2) |
| Timing-based username enumeration | **FIXED** — dummy bcrypt hash at cost 12 |
| Admin session not validated against user state | **FIXED** — re-checks user/role/active on every request |
| No CSRF on OAuth authorize POST | **FIXED** — CSRF middleware now applied |
| State parameter not URL-encoded | **FIXED** — `url.QueryEscape()` used |
| CSP allows unsafe-inline | **FIXED** — strong CSP without unsafe-inline |

---

## Vulnerability Summary

| # | Severity | Vulnerability | Source | PoC |
|---|----------|--------------|--------|-----|
| 1 | **HIGH** | Refresh token rotation race condition (TOCTOU) | Code+Logic | `exploits/token-rotation-race.py` |
| 2 | **MEDIUM** | No rate limiting — still present | Live | (Round 1 PoC still works) |
| 3 | **MEDIUM** | CF-Connecting-IP trusted unconditionally | Code | `exploits/ip-spoof.sh` |
| 4 | **MEDIUM** | Auth code error oracle leaks code state | Code+Live | `exploits/error-oracle.sh` |
| 5 | **MEDIUM** | Admin password logged to systemd journal | Code | — |
| 6 | **MEDIUM** | No re-authentication for destructive admin ops | Code | — |
| 7 | **MEDIUM** | OAuth client deletion not audit-logged | Code | — |
| 8 | **LOW-MED** | Rotate() comment says BEGIN IMMEDIATE but code uses plain Begin() | Code | — |
| 9 | **LOW-MED** | DB file permissions race on first startup | Code | — |
| 10 | **LOW-MED** | HSTS max-age still 30 days, no includeSubDomains/preload | Live | — |
| 11 | **LOW** | 8-hour admin session TTL (excessive) | Code | — |
| 12 | **LOW** | No `form-action` directive in CSP | Live | — |
| 13 | **LOW** | Deterministic CSRF token (HMAC of session cookie) | Code | — |
| 14 | **LOW** | Access tokens remain valid after logout (15 min window) | Code | — |
| 15 | **INFO** | Auth code exchange TOCTOU (mitigated by MarkUsed WHERE clause) | Code | `exploits/authcode-race.py` |

---

## Detailed Findings

### 1. HIGH: Refresh Token Rotation Race Condition

**Location:** `internal/service/auth_service.go:150-192`, `internal/store/token_store.go:57-91`

The `Refresh()` function reads the token via `GetByHash()` (line 153) and checks `tok.IsRevoked` (line 162) **outside** of any transaction. It then calls `issueTokens()` → `Rotate()` which starts its own transaction. Between the read and the write, a concurrent request can also read the same token as not-revoked.

```
Timeline:
  Goroutine A: GetByHash(hash) → tok.IsRevoked == false  [releases DB conn]
  Goroutine B: GetByHash(hash) → tok.IsRevoked == false  [releases DB conn]
  Goroutine A: Rotate(old, newA) → UPDATE is_revoked=1, INSERT newA → commit
  Goroutine B: Rotate(old, newB) → UPDATE is_revoked=1 (no-op), INSERT newB → commit
  Result: TWO valid refresh tokens from the same parent
```

Despite `SetMaxOpenConns(1)` serializing SQL, Go goroutines interleave between SQL calls. The `Rotate()` transaction only protects the revoke+insert pair, not the preceding read+validate.

**Impact:** Attacker who intercepts a refresh token can race the legitimate user's refresh, obtaining their own valid token pair without triggering theft detection. Both tokens work independently going forward.

**Compounding factor:** The comment on line 56 of `token_store.go` claims "BEGIN IMMEDIATE transaction" but the code uses plain `Begin()` which is DEFERRED in SQLite. This is a documentation/implementation mismatch.

**Fix:** Move GetByHash + IsRevoked check into the Rotate transaction, or use a SELECT ... FOR UPDATE pattern. The entire read-validate-rotate sequence must be atomic.

---

### 2. MEDIUM: No Rate Limiting (Still Present)

**Location:** All routers — no rate limiting middleware

**Confirmed live:** 8 rapid sequential POST requests to `/api/v1/auth/login` all returned HTTP 401 with no 429, no `Retry-After`, no `X-RateLimit-*` headers, no delay escalation.

This was the #2 finding in Round 1. It remains unfixed.

---

### 3. MEDIUM: CF-Connecting-IP Trusted Unconditionally

**Locations:**
- `internal/handler/api/auth.go:142-145`
- `internal/handler/oauth/handler.go:264-267`
- `internal/handler/admin/handler.go:213-220`

All three `extractClientIP` functions blindly trust `CF-Connecting-IP`:

```go
func extractClientIP(r *http.Request) string {
    if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
        return cf
    }
    // fallback to RemoteAddr
}
```

**Impact:**
- If the server is ever reachable directly (bypassing Cloudflare), all audit log IPs are forgeable
- Attacker can poison audit logs with arbitrary IPs during incident response
- Future IP-based rate limiting would be bypassable

Note: Through Cloudflare Tunnel, Cloudflare overwrites this header, so the current deployment is partially protected. But the code has no validation that the request actually came through Cloudflare.

**Fix:** Only trust the header when behind a verified proxy. Validate against Cloudflare's published IP ranges, or use a config flag like `TRUST_PROXY=cloudflare`.

---

### 4. MEDIUM: Auth Code Error Oracle

**Location:** `internal/handler/oauth/handler.go:186-193`

The token endpoint returns distinct error messages for different auth code failure modes:

| Code State | error_description |
|-----------|-------------------|
| Never existed | "The authorization code is invalid." |
| Already used | "The authorization code has already been used." |
| Expired | "The authorization code has expired." |

**Impact:** Attacker can determine whether a code was ever valid, whether someone else already exchanged it (race detection), and infer timing of code issuance.

**Fix:** Return a single generic message: `"The authorization code is invalid or has expired."`

---

### 5. MEDIUM: Admin Password Logged to Journal

**Location:** `cmd/server/seed.go:48-56`, `deploy/install.sh:97`

On first run without explicit credentials, the generated admin password is logged in plaintext:

```go
log.Println("════════════════════════════════════════════════════")
log.Printf("  Password: %s", password)
```

And install.sh tells users to retrieve it via `sudo journalctl -u identity | grep Password`. The password persists in systemd journal with default retention, accessible to users with journal access.

**Fix:** Write the initial password to a file with 0600 permissions and delete it after first admin login, or require setting it via environment variable.

---

### 6. MEDIUM: No Re-authentication for Destructive Admin Operations

**Location:** `internal/handler/admin/handler.go`

An admin session (8-hour JWT cookie) grants full access to:
- Delete any user (line 412-430)
- Delete any OAuth client (line 560-568)
- Modify user roles and active status (line 373-407)
- Trigger backups (line 434-439)

None of these require password re-entry. A stolen admin session cookie grants 8 hours of unrestricted destructive access.

**Fix:** Require password confirmation for user deletion, role changes, and OAuth client deletion.

---

### 7. MEDIUM: OAuth Client Deletion Not Audit-Logged

**Location:** `internal/handler/admin/handler.go:560-568`

```go
func (h *adminHandler) oauthDeletePost(w http.ResponseWriter, r *http.Request) {
    id := r.PathValue("id")
    if err := h.oauthClients.Delete(id); err != nil {
        // ...
    }
    http.Redirect(w, r, "/admin/oauth", http.StatusSeeOther)
}
```

No audit event is recorded. Compare to user deletion which records an audit event via `h.userSvc.Delete(id, h.auditMeta(r))`. A compromised admin could delete OAuth clients without leaving a trace in the audit log.

**Fix:** Add `h.recordEvent(domain.EventOAuthClientDeleted, ...)` before the redirect.

---

### 8. LOW-MED: Rotate() Comment/Code Mismatch

**Location:** `internal/store/token_store.go:56-58`

```go
// Rotate atomically revokes oldTokenID and inserts newToken within a single
// BEGIN IMMEDIATE transaction to prevent concurrent refresh races.
func (s *TokenStore) Rotate(oldTokenID string, newToken *domain.RefreshToken) error {
    tx, err := s.db.DB().Begin()  // ← plain Begin(), not BEGIN IMMEDIATE
```

The comment claims `BEGIN IMMEDIATE` but the code uses Go's default `Begin()` which produces a `DEFERRED` transaction in SQLite. While `SetMaxOpenConns(1)` serializes connections, this is still a gap — `BEGIN IMMEDIATE` would acquire the reserved lock immediately, preventing even the possibility of a concurrent writer.

---

### 9. LOW-MED: Database File Permissions Race

**Location:** `internal/db/db.go:23-49`

The database file is created by `sql.Open()` with default umask (typically 0644), then migrations run, then `os.Chmod(path, 0600)` is called. Between creation and chmod, the file containing all user password hashes and tokens is world-readable.

```go
sqlDB, err := sql.Open("sqlite", path)    // created with 0644
// ... configure, migrate (writes secrets) ...
os.Chmod(path, 0600)                       // fixed after the fact
```

**Fix:** Set umask before Open, or use `os.OpenFile` with explicit permissions to create the file first.

---

### 10. LOW-MED: HSTS Still Weak

**Live confirmed:** `Strict-Transport-Security: max-age=2592000` (30 days)

Missing `includeSubDomains` and `preload`. Industry standard is `max-age=31536000; includeSubDomains; preload`.

---

### 11-14. LOW Findings

| # | Finding | Location |
|---|---------|----------|
| 11 | **8-hour admin session** — excessive for security-critical admin UI | `handler.go:44` |
| 12 | **No form-action in CSP** — forms could submit to external origins | `main.go:334` |
| 13 | **Deterministic CSRF tokens** — HMAC(session_cookie) means leaked session = leaked CSRF | `handler.go:159-166` |
| 14 | **Access tokens valid after logout** — 15-min JWT remains valid, no revocation list | `auth.go:108-121` |

---

### 15. INFO: Auth Code Exchange TOCTOU (Mitigated)

**Location:** `internal/service/oauth_service.go:104-139`, `internal/store/oauth_code_store.go:51-64`

Same TOCTOU pattern as the refresh token race: `GetByHash` + `UsedAt == nil` check outside transaction, then `MarkUsed` separately. However, `MarkUsed` uses `WHERE used_at IS NULL` and checks `RowsAffected`, so the second concurrent request fails at the DB level.

This is a defence-in-depth success — the DB-level check catches the race. But the error returned is a generic wrapping of `ErrNotFound` rather than `ErrAuthCodeAlreadyUsed`, and the pattern is fragile (removing the `RowsAffected` check would reopen the vulnerability).

---

## What's Improved Since Round 1

The remediations demonstrate solid security response:

- **CORS:** Proper allowlist replacing wildcard reflection
- **CSP:** Removed `unsafe-inline`, added `frame-ancestors 'none'`
- **Admin sessions:** Now re-validate user existence, active status, and admin role on every request
- **CSRF:** Added to OAuth authorize and admin state-changing endpoints
- **URL encoding:** State parameter properly escaped
- **Timing:** Dummy bcrypt hash appears to be working (could not reproduce timing differential)
- **New tests:** Added security_headers_test.go, admin_test.go, oauth handler_test.go

---

## Exploit Files

```
exploits/
├── token-rotation-race.py   # Async refresh token race condition PoC
├── authcode-race.py          # Auth code exchange race attempt (mitigated)
├── ip-spoof.sh               # CF-Connecting-IP audit log spoofing
└── error-oracle.sh           # OAuth error message information leak
```

---

## Recommended Priority

1. **Fix token rotation race** (HIGH — move read+validate into Rotate transaction)
2. **Add rate limiting** (MEDIUM — still unfixed from Round 1)
3. **Fix CF-Connecting-IP trust** (MEDIUM — validate proxy source)
4. **Unify auth code error messages** (MEDIUM — easy one-line fix)
5. **Stop logging admin password** (MEDIUM — use secure delivery mechanism)
6. **Require re-auth for destructive admin ops** (MEDIUM)
7. **Audit-log OAuth client deletion** (MEDIUM — one-line fix)
8. **Fix Rotate() to use BEGIN IMMEDIATE** (LOW-MED — match comment to code)
9. **Fix DB permissions race** (LOW-MED — set umask before Open)
10. **Increase HSTS max-age** (LOW-MED — config change)
