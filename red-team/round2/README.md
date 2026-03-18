# Red Team Assessment: id.swee.net

**Target:** https://id.swee.net/
**Source:** https://github.com/sweeney/identity/
**Date:** 2026-03-18
**Stack:** Go, SQLite, OAuth 2.0 + PKCE, JWT (HS256), bcrypt, Cloudflare Tunnel

---

## Contents

```
red-team-20260318/
├── README.md                          ← this file
├── round1/
│   ├── REPORT.md                      ← Round 1 findings (markdown)
│   ├── report.html                    ← Round 1 findings (styled HTML)
│   └── exploits/
│       ├── cors-exploit.html          ← Wildcard CORS PoC (3 attack scenarios)
│       ├── brute-force.py             ← Async password brute-forcer
│       ├── username-enum.py           ← Timing-based username enumeration
│       └── admin-csrf-login.html      ← Admin login CSRF auto-submit
└── round2/
    ├── REPORT.md                      ← Round 2 findings (markdown)
    ├── report.html                    ← Round 2 findings (styled HTML)
    └── exploits/
        ├── token-rotation-race.py     ← Refresh token TOCTOU race condition
        ├── authcode-race.py           ← Auth code exchange race (mitigated)
        ├── ip-spoof.sh                ← CF-Connecting-IP audit log spoofing
        └── error-oracle.sh            ← OAuth error message information leak
```

## Summary

### Round 1 (13 findings, 6 remediations applied)

| Severity | Count | Key Findings |
|----------|-------|-------------|
| HIGH     | 1     | Wildcard CORS origin reflection |
| MEDIUM   | 3     | No rate limiting, timing username enum, admin session validation |
| LOW-MED  | 2     | Missing CSRF, state param encoding |
| LOW      | 4     | Admin CSRF, backup via GET, weak password policy, CSP |
| INFO     | 3     | Public API spec, weak HSTS, public admin panel |

### Round 2 (15 findings — post-remediation)

| Severity | Count | Key Findings |
|----------|-------|-------------|
| HIGH     | 1     | Refresh token rotation race condition (TOCTOU) |
| MEDIUM   | 5     | Rate limiting still absent, CF-IP spoofing, error oracle, admin password in journal, no re-auth for destructive ops |
| LOW-MED  | 3     | BEGIN IMMEDIATE mismatch, DB permissions race, weak HSTS |
| LOW      | 4     | Admin session TTL, CSP form-action, deterministic CSRF, post-logout token validity |
| INFO     | 1     | Auth code TOCTOU (mitigated by DB check) |

## How to View Reports

Open the HTML reports in a browser for the best experience:

```bash
open round1/report.html
open round2/report.html
```

## Running the PoCs

**Round 2 exploits require Python 3.8+ with aiohttp:**

```bash
pip install aiohttp

# Token rotation race (requires a valid refresh token)
python3 round2/exploits/token-rotation-race.py --token <refresh_token>

# Auth code race (requires valid auth code + PKCE params)
python3 round2/exploits/authcode-race.py --code <code> --client-id <id> \
    --redirect-uri <uri> --code-verifier <verifier>

# IP spoofing demo
bash round2/exploits/ip-spoof.sh

# Error oracle demo
bash round2/exploits/error-oracle.sh
```

## Top Priority Fixes

1. **Fix token rotation race** — make read+validate+rotate atomic (HIGH)
2. **Add rate limiting** — unfixed since Round 1 (MEDIUM)
3. **Validate CF-Connecting-IP source** — don't trust blindly (MEDIUM)
4. **Unify auth code error messages** — single generic error (MEDIUM)
5. **Stop logging admin password** — use secure delivery (MEDIUM)
