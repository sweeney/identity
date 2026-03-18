# Red Team Report: id.swee.net — Round 4 (Final)

**Target:** https://id.swee.net/
**Source:** https://github.com/sweeney/identity/
**Date:** 2026-03-18
**Stack:** Go, SQLite (WAL), OAuth 2.0 + PKCE, JWT (HS256), bcrypt, Cloudflare Tunnel
**Previous rounds:** `archive/round1/`, `archive/round2/`, `archive/round3/`

---

## Round 3 Remediation Verification

| # | R3 Finding | Status |
|---|-----------|--------|
| 1 | Rate limiter bypass (dual ExtractClientIP) | **FIXED** — duplicate removed; uses `httputil.ExtractClientIP(r, trustProxy)` with config; tests verify CF header ignored when `trustProxy` is empty |
| 2 | POST /oauth/authorize missing strict rate limit | **FIXED** — `wrapAuth()` applied; confirmed live at ~5 req/window (same as login) |
| 3 | OAuth client edit not covered by re-auth | **FIXED** — `verifyAdminPassword()` call added; form includes password field for edits |
| 4 | Visitor map unbounded | **FIXED** — capped at 100,000 with emergency cleanup; deny-all limiter for overflow IPs (not stored) |
| 5 | RATE_LIMIT_DISABLED no production guard | **FIXED** — flag overridden to `false` when `IDENTITY_ENV=production`, with warning logged |
| 6 | RotateToken test sequential | **FIXED** — 10-goroutine concurrent test with `sync.WaitGroup` barrier; asserts exactly 1 success |

**All 6 Round 3 findings are confirmed fixed.**

---

## Live Server Verification

| Check | Result |
|-------|--------|
| Rate limiting on `/api/v1/auth/login` | **Working** — 429 after 5 requests, `Retry-After` header present |
| Rate limiting on `POST /oauth/authorize` | **Working** — same ~5 req/window as login (was 30/min) |
| Rate limiting on `POST /admin/login` | **Working** — unified rate limit bucket |
| Proxy header bypass (X-Forwarded-For, X-Real-IP, True-Client-IP) | **Not exploitable** — all correctly ignored for rate limit keying |
| CF-Connecting-IP spoofing | **Blocked** — Cloudflare returns 403 |
| CORS | **Correct** — no origin reflection |
| Error messages | **Generic** — no user enumeration |
| CSP | **Strong** — includes form-action 'self' |
| Security headers | **All present** — nosniff, DENY, strict-origin-when-cross-origin |

---

## Remaining Observations

| # | Severity | Finding | Notes |
|---|----------|---------|-------|
| 1 | **LOW** | HSTS max-age still 30 days live | Code shows 63072000 — likely deployment lag or Cloudflare override. Not a code bug. |
| 2 | **INFO** | No `Permissions-Policy` header | Defense-in-depth; not exploitable |
| 3 | **INFO** | No `Cache-Control: no-store` on auth pages | Browser could cache login forms |

No HIGH or MEDIUM findings remain.

---

## Assessment Across All Rounds

| Round | Findings | HIGH | MEDIUM | LOW+ |
|-------|----------|------|--------|------|
| 1 | 13 | 1 | 3 | 9 |
| 2 | 15 | 1 | 5 | 9 |
| 3 | 6 | 1 | 2 | 3 |
| **4** | **3** | **0** | **0** | **3** |

### What's Solid

- **No SQL injection** — parameterized queries throughout
- **No XSS** — Go template auto-escaping, strong CSP
- **No CORS abuse** — proper allowlist
- **PKCE enforced** — S256 required, no plain downgrade
- **Token rotation** — atomic TOCTOU-safe transaction, concurrent test coverage
- **Refresh token theft detection** — family-based revocation working
- **Rate limiting** — per-IP, strict on all credential endpoints, proxy-header-resistant
- **Admin re-auth** — password required for all destructive and sensitive operations
- **CSRF** — HMAC-based tokens on all state-changing POST endpoints
- **Session security** — HttpOnly, Secure, SameSite=Strict, 2-hour TTL
- **Audit logging** — comprehensive coverage including OAuth client CRUD
- **DB permissions** — umask(0077) before creation
- **Secret management** — no journal logging, auto-generated, rotation supported

### Conclusion

The identity server has reached a strong security posture. All HIGH and MEDIUM findings from four rounds of testing have been addressed. The remaining items are informational hardening suggestions, not exploitable vulnerabilities.

**Red team assessment: PASS**
