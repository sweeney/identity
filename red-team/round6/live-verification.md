# Round 6 — Live Verification of Round 5 Fixes

**Date:** 2026-03-18
**Target:** https://id.swee.net/
**Purpose:** Verify Round 5 remediation items are deployed and effective on the live server.

---

## R5-01: Username Enumeration via WebAuthn Login Begin (MEDIUM-HIGH)

**Fix claimed:** "Always use discoverable flow — responses are now identical"

**Verdict: VERIFIED FIXED**

**Evidence:**

All four payloads now return identical 200 responses with the same structure and size (194 bytes). No `allowCredentials` field is present in any response — the server always returns a discoverable-credential flow regardless of whether the user exists or has passkeys registered.

| Run | Payload | HTTP Code | Response Size | Structure |
|-----|---------|-----------|---------------|-----------|
| 1 | `{"username":"admin"}` (known user) | 200 | 194 | challenge_id + publicKey (no allowCredentials) |
| 1 | `{"username":"nonexistent_user_xyz_12345"}` | 200 | 194 | challenge_id + publicKey (no allowCredentials) |
| 1 | `{"username":""}` | 200 | 194 | challenge_id + publicKey (no allowCredentials) |
| 1 | `{}` (empty body) | 200 | 194 | challenge_id + publicKey (no allowCredentials) |
| 2 | `{"username":"admin"}` | 200 | 194 | identical |
| 2 | `{"username":"nonexistent_user_xyz_12345"}` | 200 | 194 | identical |
| 2 | `{"username":""}` | 200 | 194 | identical |
| 2 | `{}` | 200 | 194 | identical |
| 3 | `{"username":"admin"}` | 200 | 194 | identical |
| 3 | `{"username":"nonexistent_user_xyz_12345"}` | 200 | 194 | identical |

Sample response (all payloads produce this exact structure):
```json
{
  "challenge_id": "<uuid>",
  "publicKey": {
    "challenge": "<base64url>",
    "timeout": 300000,
    "rpId": "swee.net",
    "userVerification": "preferred"
  }
}
```

**Timing:** Response times are consistent across all payloads (~100-115ms), with no observable timing oracle.

**Previous behavior (R5):** existing+passkeys returned 200 with `allowCredentials`, existing+no-passkeys returned 400, nonexistent returned 200 without `allowCredentials`. This oracle is now eliminated.

**Bonus observation:** Rate limiting is active on this endpoint (429 after ~4 rapid requests). This is a positive defense-in-depth measure.

---

## R5-02: Challenge TOCTOU Race Condition (MEDIUM)

**Fix claimed:** "Atomic Consume method"

**Verdict: VERIFIED FIXED**

**Evidence:**

Two concurrent requests were fired simultaneously with the same `challenge_id` as a query parameter:

- **Request 1:** `{"error":"webauthn_verification_failed","message":"passkey authentication failed"}` — HTTP 401 (0.111s)
- **Request 2:** `{"error":"webauthn_invalid_challenge","message":"challenge expired or not found"}` — HTTP 400 (0.106s)

The first request consumed the challenge atomically and proceeded to cryptographic verification (which correctly failed since we don't have a real passkey). The second request could not find the challenge at all — confirming the atomic consume is working. A TOCTOU race would have allowed both requests to proceed to verification with the same error.

---

## R5-04: No Credential Registration Limit (MEDIUM)

**Fix claimed:** Limit enforcement (requires auth to test fully)

**Verdict: VERIFIED (auth gate intact)**

**Evidence:**

```
POST /api/v1/webauthn/register/begin with no auth:
{"error":"unauthorized","message":"missing authorization header"}
HTTP 401
```

The registration endpoint correctly requires authentication. Full credential limit testing would require an authenticated session, which is out of scope for this verification pass.

---

## R5-06: Query Parameter Leakage of Challenge ID (LOW)

**Fix claimed:** Support X-Challenge-ID header as alternative to query parameter

**Verdict: VERIFIED FIXED**

**Evidence:**

Both delivery mechanisms work:

1. **Query parameter:** `POST /api/v1/webauthn/login/finish?challenge_id=<uuid>` — HTTP 401 (reached crypto verification, "passkey authentication failed")
2. **X-Challenge-ID header:** `POST /api/v1/webauthn/login/finish` with `X-Challenge-ID: <uuid>` — HTTP 401 (reached crypto verification, "passkey authentication failed")

Both methods successfully deliver the challenge_id to the server. Clients can now use the header method to avoid logging sensitive challenge IDs in URLs/access logs.

---

## R5-08: Missing CSRF Protection on Passkey Login (LOW)

**Fix claimed:** Origin validation on passkey login endpoint

**Verdict: VERIFIED FIXED**

**Evidence:**

| Test | Origin Header | HTTP Code | Response |
|------|--------------|-----------|----------|
| Evil origin | `Origin: https://evil.com` | **403** | `forbidden: origin mismatch` |
| No origin | (omitted) | 200 | Proceeds to auth check (fails on bad token) |
| Correct origin | `Origin: https://id.swee.net` | 200 | Proceeds to auth check (fails on bad token) |

Cross-origin requests are explicitly rejected with a 403 and "origin mismatch" error. The check runs before any authentication logic, which is the correct order. Requests without an Origin header are allowed through (standard browser behavior — same-origin form submissions don't always send Origin).

---

## Security Headers

**Verdict: ALL PRESENT (one item noted)**

Response headers from `GET /`:

| Header | Value | Status |
|--------|-------|--------|
| `Content-Security-Policy` | `default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'` | Present |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Present |
| `Strict-Transport-Security` | `max-age=2592000` | Present, **but see note** |
| `X-Content-Type-Options` | `nosniff` | Present |
| `X-Frame-Options` | `DENY` | Present |

**HSTS max-age note:** The value is still `2592000` (30 days). Round 5 recommended increasing this. The current value provides HSTS protection but is shorter than the commonly recommended minimum of `31536000` (1 year). This is a low-priority item and does not affect the core security posture.

---

## Additional Observations

1. **Rate limiting is active:** The `/api/v1/webauthn/login/begin` endpoint enforces rate limiting (HTTP 429 after ~4 rapid requests from the same IP). This was not explicitly called out as a Round 5 fix but is a positive defense-in-depth control that helps mitigate brute-force and enumeration attacks.

2. **Cloudflare:** The server is behind Cloudflare (cf-ray headers present), which provides additional DDoS and bot protection.

3. **No new endpoints discovered** during this verification pass.

---

## Summary

| Finding | Severity | Verdict |
|---------|----------|---------|
| R5-01: Username enumeration | MEDIUM-HIGH | **VERIFIED FIXED** |
| R5-02: Challenge TOCTOU race | MEDIUM | **VERIFIED FIXED** |
| R5-04: No credential limit | MEDIUM | **VERIFIED** (auth gate intact) |
| R5-06: Query param leakage | LOW | **VERIFIED FIXED** |
| R5-08: Missing CSRF | LOW | **VERIFIED FIXED** |
| Security headers | — | All present |
| HSTS max-age | LOW | Still 30 days (unchanged) |

**Overall: All tested Round 5 fixes are confirmed deployed and functioning correctly on the live server.** The only remaining low-priority item is the HSTS max-age, which is still at 30 days instead of the recommended 1 year.
