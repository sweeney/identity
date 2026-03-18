# WebAuthn Challenge Validation Flow - Deep Dive

**Date:** 2026-03-18
**Target:** id.swee.net identity server
**Scope:** WebAuthn challenge creation, storage, validation, and deletion logic
**Files reviewed:**
- `internal/service/webauthn_service.go` (full, all functions)
- `internal/store/webauthn_challenge_store.go` (full)
- `internal/handler/api/webauthn.go` (full)
- `internal/domain/webauthn.go` (full)
- `internal/auth/webauthn.go` (full)
- `internal/db/migrations/003_webauthn.sql`
- `internal/service/webauthn_service_test.go` (full)
- `internal/handler/api/router.go`
- `cmd/server/main.go` (cleanup goroutine)

---

## Finding 1: Challenge Reuse via Race Condition (TOCTOU)

**Severity: Low-Medium (theoretical)**

The challenge is deleted via `defer s.challenges.Delete(challengeID)` in both `FinishRegistration` (line 135) and `FinishLogin` (line 290). This means the challenge is fetched first, validated, and only deleted when the function returns.

The window between `GetByID` and the deferred `Delete` includes the entire cryptographic verification, user lookup, credential storage, and token issuance. If two concurrent requests hit `FinishLogin` with the same `challenge_id`, both could call `GetByID` before either's `defer Delete` executes.

**Mitigating factors:**
- SQLite is configured with `SetMaxOpenConns(1)`, which serializes all DB operations through a single connection. This effectively prevents concurrent reads from overlapping with writes at the DB level.
- However, the service layer does not hold any lock across the get-validate-delete span. The `GetByID` calls from two goroutines would be serialized by the SQLite connection pool, but both could succeed before either defer fires. The Go HTTP server handles requests concurrently even with a single DB connection -- the goroutines interleave at each DB call boundary.
- The actual cryptographic verification (`s.wa.FinishLogin` / `s.wa.FinishRegistration`) is CPU-bound and does not hold the DB connection, so a second request can read the challenge from the DB while the first is in the crypto verification step.

**Recommendation:** Delete the challenge BEFORE performing the cryptographic verification, not after. Or use an atomic "SELECT ... DELETE" (SQLite does not have `DELETE ... RETURNING` in all versions, but a transaction with SELECT + DELETE + commit would close the window). The pattern should be: fetch and delete in one transaction, then validate.

---

## Finding 2: Challenge Type Confusion - Properly Mitigated

**Severity: None (mitigated)**

Both `FinishRegistration` and `FinishLogin` explicitly check the challenge `Type` field:
- `FinishRegistration` checks `ch.Type != "registration"` (line 137)
- `FinishLogin` checks `ch.Type != "authentication"` (line 292)

The DB schema also enforces `CHECK(type IN ('registration', 'authentication'))` at the SQL level.

A registration challenge cannot be used for authentication and vice versa. Tests confirm this (`TestWebAuthnService_FinishRegistration_WrongType`, `TestWebAuthnService_FinishLogin_WrongType`).

**Result:** No issue found.

---

## Finding 3: Challenge User Binding

**Severity: None (mitigated for registration, partially for login)**

**Registration:** `FinishRegistration` checks `ch.UserID != userID` (line 137). The `userID` comes from the JWT claims of the authenticated user (`auth.ClaimsFromContext`), not from any user-supplied parameter. User A cannot finish User B's registration challenge.

**Login (known user flow):** When `BeginLogin` is called with a username, the challenge stores `userID = user.ID`. In `FinishLogin`, the `authenticatedUserID` is set from `ch.UserID` (line 332). The challenge is bound to a specific user, and the WebAuthn library verifies the assertion against that user's credentials.

**Login (discoverable flow):** When `BeginLogin` is called without a username (or with a nonexistent user), `UserID` is empty in the challenge. In `FinishLogin`, the discoverable flow resolves the user from the credential's `userHandle` via the callback (line 311-326). The WebAuthn library itself validates that the credential belongs to the resolved user. No user-binding issue here -- the authenticator itself asserts user identity.

**Login (fake challenge for nonexistent user):** When a nonexistent username is provided, `BeginLogin` creates a discoverable-flow challenge with empty `UserID` (line 267). At `FinishLogin` time, this enters the discoverable code path. An attacker cannot exploit this because the WebAuthn library validates the assertion against actual stored credentials via the callback. If the user doesn't exist, the callback returns an error.

**Result:** No issue found.

---

## Finding 4: Timing Attacks on Error Paths

**Severity: Informational**

Error paths in `FinishLogin` and `FinishRegistration` return early at different points:
1. Challenge not found -> immediate return (no DB delete)
2. Wrong type / wrong user / expired -> return after setting up defer delete (fast)
3. Unmarshal failure -> return after setting up defer delete (fast)
4. Crypto verification failure -> return after the full WebAuthn verification (slower)
5. Success -> return after credential storage + token issuance (slowest)

An attacker could potentially distinguish "valid challenge ID but wrong assertion" from "invalid challenge ID" based on response timing, since path (4) involves actual cryptographic verification while path (1) does not. However:
- The challenge ID is a UUID4, so guessing valid ones is infeasible.
- The error messages already distinguish these cases (`webauthn_invalid_challenge` vs `webauthn_verification_failed`), so timing adds no new information beyond what the error codes already reveal.

**Result:** No exploitable timing issue.

---

## Finding 5: challenge_id Parameter - Input Validation

**Severity: None (safe)**

The `challenge_id` is received as a query parameter (`r.URL.Query().Get("challenge_id")`) in the handler. It is passed as a string to `GetByID`, which uses a parameterized SQL query: `WHERE id = ?`. This is safe against SQL injection.

The `challenge_id` is generated server-side as `uuid.New().String()` (UUIDv4). The store does not perform any filesystem operations with this value, so path traversal is not applicable.

There is no validation that the `challenge_id` conforms to UUID format before the DB query, but since it's used as a parameterized query value and the table uses `TEXT PRIMARY KEY`, a malformed ID simply won't match any row and returns `domain.ErrNotFound`.

**Result:** No issue found.

---

## Finding 6: session_data JSON Deserialization

**Severity: None (safe)**

The `SessionData` field is:
1. Marshaled from `webauthn.SessionData` struct via `json.Marshal` at creation time (server-controlled)
2. Stored as a TEXT column in SQLite
3. Unmarshaled back into `webauthn.SessionData` via `json.Unmarshal` at validation time

The data is never sourced from user input. It's created by the `go-webauthn` library on the server side, serialized to JSON, stored in the DB, then deserialized. An attacker would need write access to the database to inject malicious session data, and if they have that, they have larger problems.

The `go-webauthn` library's `SessionData` struct uses strongly-typed fields (string, []byte, etc.), so there's no polyglot deserialization risk.

**Result:** No issue found.

---

## Finding 7: Expired Challenge Reuse Window

**Severity: None (mitigated)**

Expired challenges are cleaned up by a background goroutine every 24 hours (`cmd/server/main.go`). However, the service layer checks expiry at validation time:
- `FinishRegistration`: `time.Now().After(ch.ExpiresAt)` (line 141)
- `FinishLogin`: `time.Now().After(ch.ExpiresAt)` (line 296)

An expired challenge that hasn't been cleaned up yet cannot be used because the expiry check happens before any crypto verification. The 24h cleanup is purely a housekeeping measure to avoid unbounded table growth.

**Result:** No issue found.

---

## Finding 8: Fabricated Assertion Data Against Valid Challenge

**Severity: None (handled correctly)**

If an attacker calls `POST /api/v1/webauthn/login/finish?challenge_id=<valid_id>` with a completely fabricated assertion body, the flow is:

1. Challenge is fetched from DB (success, it's valid)
2. Defer delete is set up
3. Type check passes (`"authentication"`)
4. Expiry check passes (challenge is fresh)
5. SessionData is deserialized (success)
6. If known-user flow: `s.wa.FinishLogin(waUser, sessionData, r)` is called
   - The `go-webauthn` library parses the assertion from `r.Body`
   - It validates the challenge nonce in the assertion matches `sessionData.Challenge`
   - It verifies the signature against the stored public key
   - A fabricated assertion will fail cryptographic verification
7. Error path: returns `ErrWebAuthnVerificationFailed` -> HTTP 401 `webauthn_verification_failed`
8. Challenge is deleted via defer (consumed even on failure)

The challenge is single-use: even a failed attempt consumes it. This is correct behavior. An attacker cannot retry with different assertion data against the same challenge.

**Result:** No issue found. Defense in depth is solid here.

---

## Finding 9: User Enumeration via WebAuthn Errors

**Severity: Informational (already mitigated)**

`BeginLogin` with a nonexistent username returns a fake discoverable challenge rather than an error (lines 222-228). This matches the bcrypt dummy-hash pattern used in password login. The response is indistinguishable from a real discoverable challenge.

However, `BeginLogin` with a valid username but NO registered passkeys returns `ErrWebAuthnNoCredentials` (line 238-239), which the handler maps to HTTP 400 `webauthn_no_credentials`. This reveals that the user exists but has no passkeys.

This is a minor user enumeration vector, but it's arguably acceptable since:
- An attacker could already enumerate users via the password login endpoint's timing (despite the dummy hash, there may be detectable differences)
- The information "user exists but has no passkeys" is low value

**Result:** Minor informational finding.

---

## Summary

| # | Issue | Severity | Status |
|---|-------|----------|--------|
| 1 | Challenge reuse via TOCTOU race | Low-Medium | Theoretical; mitigated by SQLite single-connection but not fully closed |
| 2 | Challenge type confusion | None | Properly checked |
| 3 | Challenge user binding | None | Properly checked |
| 4 | Timing attacks | Informational | No new info beyond error codes |
| 5 | challenge_id injection | None | Parameterized queries |
| 6 | session_data deserialization | None | Server-controlled data |
| 7 | Expired challenge reuse | None | Expiry checked at validation time |
| 8 | Fabricated assertion data | None | Crypto verification + single-use challenge |
| 9 | User enumeration via no-credentials error | Informational | Minor, arguably acceptable |

**Most notable finding:** Finding 1 (TOCTOU on challenge consumption). While SQLite's single-connection constraint and the short challenge TTL make exploitation difficult in practice, the pattern of "read then defer delete" is not atomic. In a higher-concurrency database (e.g., if SQLite were swapped for PostgreSQL, or if `MaxOpenConns` were increased), this would become a real challenge replay vulnerability. The fix is straightforward: delete the challenge before proceeding with validation, or use a transactional delete-and-return pattern.
