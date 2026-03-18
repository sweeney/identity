# Finding: WebAuthn UserPresent and UserVerified Flags Hardcoded to True

**Severity:** HIGH
**Category:** Authentication Bypass / Credential Flag Forgery
**Date:** 2026-03-18
**Status:** Open

## Summary

The `DomainCredentialToWebAuthn` function in `internal/auth/webauthn.go` hardcodes the `UserPresent` and `UserVerified` flags to `true` when reconstructing stored credentials for the go-webauthn library. The actual flag values from the authenticator response at registration time are never persisted (the domain model has no fields for them), so the true security posture of every credential is lost.

## Root Cause

Two compounding defects:

1. **Missing persistence:** When `FinishRegistration` stores a new credential (webauthn_service.go:178-192), it extracts `BackupEligible` and `BackupState` from `credential.Flags` but silently drops `UserPresent` and `UserVerified`. The `domain.WebAuthnCredential` struct and the `webauthn_credentials` database table have no columns for these flags.

2. **Hardcoded reconstruction:** Since the flags are not stored, `DomainCredentialToWebAuthn` (webauthn.go:34-39) fabricates them:

```go
Flags: webauthn.CredentialFlags{
    UserPresent:    true,  // hardcoded
    UserVerified:   true,  // hardcoded
    BackupEligible: c.BackupEligible,
    BackupState:    c.BackupState,
},
```

## Affected Code Paths

| File | Lines | Role |
|---|---|---|
| `internal/auth/webauthn.go` | 24-46 | `DomainCredentialToWebAuthn` -- hardcodes UP=true, UV=true |
| `internal/domain/webauthn.go` | 8-22 | `WebAuthnCredential` struct -- missing UserPresent/UserVerified fields |
| `internal/store/webauthn_credential_store.go` | 24-54 | `Create` -- does not store UP/UV flags |
| `internal/service/webauthn_service.go` | 178-192 | `FinishRegistration` -- does not extract UP/UV from credential |
| `internal/service/webauthn_service.go` | 308-346 | `FinishLogin` -- loads credentials with fabricated flags |

### Data Flow

1. **Registration:** User registers a passkey. The authenticator returns flags indicating whether user presence was tested (UP) and whether user verification (biometric/PIN) was performed (UV). The go-webauthn library validates these against the RP config and returns them in `credential.Flags`. The service stores the credential but **discards UP and UV**.

2. **Login:** User authenticates. The service loads stored credentials via `DomainCredentialsToWebAuthn`, which sets UP=true and UV=true on every credential. These reconstructed credentials are passed to `s.wa.FinishLogin()` (or `FinishDiscoverableLogin`). The go-webauthn library compares the assertion's flags against the stored credential's flags as part of its validation logic.

3. **Impact:** The library sees that the credential was supposedly registered with UV=true, so it may enforce UV on the assertion. However, the more critical issue is the **inverse**: a credential that was registered *without* user verification (UV=false) -- for example, on an authenticator that does not support biometrics -- is presented to the library as if it *does* have UV=true. This misrepresents the credential's security properties.

## Attack Scenarios

### Scenario 1: Stolen Security Key Without Biometric

An attacker obtains a user's non-biometric security key (e.g., a basic FIDO2 key that supports UP but not UV). The credential was registered with UV=false because the key has no biometric capability. However, the server stores the credential as if UV=true. During login, the go-webauthn library's assertion validation sees UV=true on the stored credential and the authenticator may or may not enforce UV on the assertion side. The server cannot distinguish between a credential that was verified with biometrics and one that was not -- they all look identical.

If the application later implements step-up authentication or tiered trust levels based on UV status (e.g., "this credential was verified with biometrics, so allow high-value operations"), the data to make that determination does not exist. Every credential appears to have the highest assurance level regardless of actual authenticator capability.

### Scenario 2: Credential Cloning / Export

If a credential is backed up or synced (as indicated by BackupEligible/BackupState, which *are* tracked), the clone may operate on a device without the original's biometric capability. The server cannot detect this degradation because it never recorded the original UV state and always claims UV=true.

### Scenario 3: Downgrade of RP Verification Policy

The WebAuthn config requests `UserVerification: "preferred"` (webauthn.go:66). This means authenticators *may* skip UV if they don't support it, and the library will accept the registration. But because UV is then hardcoded to true in storage, the server loses the ability to know that a particular credential was registered without verification. If the RP later tightens policy to `"required"`, it cannot retroactively identify which credentials actually had UV and which did not.

## Actual vs Expected Behavior

**Actual:** Every stored credential is reported to the go-webauthn library as having UserPresent=true and UserVerified=true, regardless of the actual authenticator response at registration time. The true flag values are permanently lost.

**Expected:** The `UserPresent` and `UserVerified` flags from `credential.Flags` should be persisted at registration time (alongside BackupEligible and BackupState) and faithfully restored when constructing `webauthn.Credential` objects for login validation. This allows:

- The go-webauthn library to perform correct flag-based validation during login
- The application to make security decisions based on the actual assurance level of each credential
- Future policy changes (e.g., requiring UV for admin operations) to work against accurate data

## Severity Justification

Rated **HIGH** for the following reasons:

1. **Universal scope:** Affects every WebAuthn credential in the system. There are no code paths where the actual UP/UV values are preserved.

2. **Silent data loss:** The flags are silently discarded at registration and silently fabricated at login. There are no log entries, errors, or warnings. The test suite (`webauthn_test.go`) does not assert on the flag values.

3. **Security property misrepresentation:** The server fundamentally cannot distinguish between credentials registered with biometric verification and those registered without. This is a core WebAuthn security invariant that is violated.

4. **Blocks future security features:** Any step-up authentication, risk-based access control, or credential assurance tiering that depends on UV status is impossible to implement correctly without first fixing this bug and migrating existing data.

5. **Library contract violation:** The go-webauthn library expects the stored credential to reflect reality. Passing fabricated flags may cause the library to make incorrect validation decisions (e.g., not rejecting an assertion that lacks UV when the stored credential claims UV was present at registration).

Not rated CRITICAL because: the current application does not appear to make explicit security decisions based on UV status beyond what the go-webauthn library does internally, and the library's `UserVerification: "preferred"` policy is somewhat forgiving. Exploitation requires either a stolen authenticator or a future feature that relies on the corrupted flag data.

## Remediation

### 1. Add UserPresent and UserVerified to the domain model and database

```go
// domain/webauthn.go
type WebAuthnCredential struct {
    // ... existing fields ...
    UserPresent    bool
    UserVerified   bool
    BackupEligible bool
    BackupState    bool
    // ...
}
```

Add a migration:
```sql
ALTER TABLE webauthn_credentials ADD COLUMN user_present INTEGER NOT NULL DEFAULT 0;
ALTER TABLE webauthn_credentials ADD COLUMN user_verified INTEGER NOT NULL DEFAULT 0;
```

### 2. Persist the actual flags at registration

In `FinishRegistration` (webauthn_service.go), extract and store the flags:

```go
domainCred := &domain.WebAuthnCredential{
    // ... existing fields ...
    UserPresent:    credential.Flags.UserPresent,
    UserVerified:   credential.Flags.UserVerified,
    BackupEligible: credential.Flags.BackupEligible,
    BackupState:    credential.Flags.BackupState,
}
```

### 3. Restore the actual flags in DomainCredentialToWebAuthn

```go
Flags: webauthn.CredentialFlags{
    UserPresent:    c.UserPresent,
    UserVerified:   c.UserVerified,
    BackupEligible: c.BackupEligible,
    BackupState:    c.BackupState,
},
```

### 4. Update the credential store

Add `user_present` and `user_verified` to the INSERT, SELECT, and scan functions in `webauthn_credential_store.go`.

### 5. Handle existing data

Existing credentials were stored without UP/UV. After migration, they will default to `false`. Consider:
- Prompting users to re-register credentials to capture accurate flags
- Or defaulting existing credentials to `user_present=true, user_verified=false` as a conservative assumption (presence was almost certainly tested; verification status is unknown)

### 6. Add tests

Add assertions in `webauthn_test.go` that verify `DomainCredentialToWebAuthn` faithfully round-trips the UP and UV flags rather than hardcoding them.

## References

- [W3C WebAuthn Spec - Authenticator Data Flags](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data)
- [go-webauthn/webauthn CredentialFlags](https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#CredentialFlags)
- FIDO2 CTAP2 specification sections on UP and UV flag semantics
