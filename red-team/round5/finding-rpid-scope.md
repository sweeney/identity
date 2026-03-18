# Finding: WebAuthn RP ID Scoped to Parent Domain (`swee.net`)

**Date:** 2026-03-18
**Severity:** Medium (requires compromise of a sibling subdomain)
**Target:** https://id.swee.net/
**CWE:** CWE-346 (Origin Validation Error)

## Summary

The WebAuthn Relying Party ID is configured as `swee.net` rather than `id.swee.net`. This means passkeys registered on `id.swee.net` are cryptographically bound to the parent domain `swee.net` and can be exercised by **any origin under `*.swee.net`**, provided that origin appears in the `WebAuthnRPOrigins` allowlist. Additionally, CORS origins are automatically merged into the WebAuthn origins list, which widens the attack surface if CORS is configured for sibling subdomains.

## Technical Detail

### RP ID and Origin Configuration

From `internal/config/config.go`:

```go
// Environment variables:
//   WEBAUTHN_RP_ID         = "swee.net"         (parent domain)
//   WEBAUTHN_RP_ORIGINS    = "https://id.swee.net"  (expected production value)
```

The RP ID is passed directly to the `go-webauthn` library in `internal/auth/webauthn.go`:

```go
func NewWebAuthn(rpID, rpDisplayName string, rpOrigins []string) (*webauthn.WebAuthn, error) {
    return webauthn.New(&webauthn.Config{
        RPID:      rpID,          // "swee.net"
        RPOrigins: rpOrigins,     // ["https://id.swee.net", + any CORS origins]
    })
}
```

### CORS-to-WebAuthn Origin Merging

Lines 173-187 of `internal/config/config.go` merge all `CORS_ORIGINS` into `WebAuthnRPOrigins`:

```go
// Merge CORS origins into WebAuthn origins -- if you trust an origin for
// CORS, it should also be allowed to perform WebAuthn ceremonies.
if cfg.WebAuthnRPID != "" && len(cfg.CORSOrigins) > 0 {
    existing := make(map[string]bool, len(cfg.WebAuthnRPOrigins))
    for _, o := range cfg.WebAuthnRPOrigins {
        existing[o] = true
    }
    for _, o := range cfg.CORSOrigins {
        if !existing[o] {
            cfg.WebAuthnRPOrigins = append(cfg.WebAuthnRPOrigins, o)
        }
    }
}
```

This means any origin added to `CORS_ORIGINS` (e.g., `https://app.swee.net`) is automatically trusted for WebAuthn ceremonies. The comment in the code explicitly states this is intentional, but it conflates two distinct trust decisions:

- **CORS trust**: "this origin may read API responses" (data-level)
- **WebAuthn origin trust**: "this origin may use passkeys bound to our RP ID" (authentication-level)

### How the WebAuthn Spec Interacts with RP ID

Per the WebAuthn specification (Section 5.1.4.2, step 9):
- The RP ID (`swee.net`) defines which domain the credential is bound to
- The browser verifies that the calling origin's effective domain is the RP ID or a subdomain of it
- The server then checks that the origin in `clientDataJSON` matches one of `RPOrigins`

So the browser will happily let `https://evil.swee.net` initiate a WebAuthn ceremony using credentials bound to RP ID `swee.net`. The server-side origin check in `RPOrigins` is the only gate.

## Attack Scenarios

### Scenario 1: Subdomain Takeover + Passkey Theft

**Prerequisite:** Attacker compromises or takes over any `*.swee.net` subdomain (e.g., `staging.swee.net`, `blog.swee.net`).

1. Attacker sets up a phishing page on `https://evil.swee.net`
2. Victim visits `https://evil.swee.net`
3. The attacker's JavaScript calls `navigator.credentials.get()` with `rpId: "swee.net"`
4. The browser shows the passkey prompt -- it is valid because the RP ID matches
5. If victim approves, the attacker receives a signed WebAuthn assertion

**Current mitigation:** The server checks `RPOrigins` and would reject `https://evil.swee.net` unless it appears in the list. This is effective **as long as the origin list stays tight**.

**Risk:** If `CORS_ORIGINS` is ever expanded to include a sibling subdomain (e.g., for an SPA at `https://app.swee.net`), that origin automatically becomes a valid WebAuthn origin. A compromise of that SPA could then be leveraged to steal passkey assertions.

### Scenario 2: Future Configuration Drift

If a developer adds `https://app.swee.net` to `CORS_ORIGINS` (a reasonable thing to do for an SPA), the auto-merge logic silently makes it a valid WebAuthn origin. No explicit review of WebAuthn security implications occurs.

### Scenario 3: Rogue Passkey Registration on Victim Account

If an attacker has a valid session (via XSS on a trusted sibling subdomain) and the sibling origin is in the WebAuthn origins list, they could:
1. Call `POST /api/v1/webauthn/register/begin` using the victim's access token
2. Complete the ceremony from the sibling origin (browser allows it because RP ID is `swee.net`)
3. Register a rogue passkey on the victim's account
4. Later authenticate as the victim using the rogue passkey

This requires the attacker to have the victim's access token, which limits practical exploitability.

## What Actually Protects Against This Today

1. **`RPOrigins` server-side check**: The `go-webauthn` library validates that `clientDataJSON.origin` is in the configured `RPOrigins` list. If only `https://id.swee.net` is listed, sibling subdomains are rejected.
2. **CORS policy**: CORS headers are only set on `/api/` and `/oauth/token` paths. Admin paths and HTML pages do not get CORS headers. However, the WebAuthn API endpoints are under `/api/v1/webauthn/` and would get CORS headers if the origin is allowed.
3. **SameSite=Strict on admin cookie**: The admin session cookie uses `SameSite=Strict`, preventing cross-site session riding.

## Risk Assessment

- **Current risk (CORS_ORIGINS empty or id.swee.net only):** Low. The origin check blocks sibling subdomains.
- **Risk if CORS_ORIGINS expands to sibling subdomains:** Medium-High. The auto-merge makes that sibling a valid WebAuthn origin, and compromise of the sibling enables passkey abuse.
- **Design risk:** The RP ID being `swee.net` rather than `id.swee.net` permanently broadens the cryptographic trust boundary. This cannot be changed without re-registering all passkeys.

## Recommendations

1. **Separate WebAuthn origins from CORS origins.** Remove the auto-merge logic (lines 173-187 of config.go). These are different trust decisions and should be configured independently.
2. **Consider using `id.swee.net` as the RP ID** if there is no need for passkeys to work across multiple subdomains. This narrows the trust boundary to exactly the auth server.
3. **If `swee.net` RP ID is intentional**, document the security implications and ensure operational procedures include WebAuthn impact assessment when modifying `CORS_ORIGINS`.
4. **Add a startup warning** if `CORS_ORIGINS` contains origins that differ from `WEBAUTHN_RP_ORIGINS`, to surface the trust expansion.

## References

- `internal/config/config.go` -- RP ID, origins, and CORS-merge logic (lines 148-187)
- `internal/auth/webauthn.go` -- `NewWebAuthn()` passes config to go-webauthn library
- `cmd/server/main.go` -- WebAuthn initialization (lines 232-243), security headers / CORS (lines 397-458)
- WebAuthn spec Section 5.1.4.2 (RP ID validation)
