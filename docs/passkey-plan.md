# Passkey / WebAuthn Implementation Plan

## Overview

Add passkey support to the Identity Service so users can authenticate via biometrics (Face ID, Touch ID, Windows Hello, Android biometrics) across all device types: desktop browsers, mobile browsers, and native mobile apps.

Passkeys are built on the WebAuthn standard (W3C Web Authentication API). They use public-key cryptography — the server stores a public key, the private key never leaves the user's device (or their iCloud Keychain / Google Password Manager / Windows Hello vault, which syncs it across devices).

---

## How Passkeys Work

### Registration (Attestation Ceremony)

```
┌──────────┐          ┌──────────────┐          ┌─────────────┐
│  Browser  │          │   Identity   │          │ Authenticator│
│  / App    │          │   Server     │          │ (Touch ID,  │
│           │          │              │          │  Face ID…)  │
└─────┬─────┘          └──────┬───────┘          └──────┬──────┘
      │                       │                         │
      │  1. POST /webauthn/   │                         │
      │     register/begin    │                         │
      │ ─────────────────────>│                         │
      │                       │                         │
      │  2. Challenge +       │                         │
      │     RP info + user    │                         │
      │ <─────────────────────│                         │
      │                       │                         │
      │  3. navigator.credentials.create(options)       │
      │ ───────────────────────────────────────────────>│
      │                       │                         │
      │  4. User touches      │                         │
      │     biometric sensor  │                         │
      │ <──────────── credential (public key, attestation)
      │                       │                         │
      │  5. POST /webauthn/   │                         │
      │     register/finish   │                         │
      │ ─────────────────────>│                         │
      │                       │                         │
      │  6. Verify + store    │                         │
      │     public key        │                         │
      │ <───── 200 OK ────────│                         │
```

### Authentication (Assertion Ceremony)

```
┌──────────┐          ┌──────────────┐          ┌─────────────┐
│  Browser  │          │   Identity   │          │ Authenticator│
│  / App    │          │   Server     │          │             │
└─────┬─────┘          └──────┬───────┘          └──────┬──────┘
      │                       │                         │
      │  1. POST /webauthn/   │                         │
      │     login/begin       │                         │
      │ ─────────────────────>│                         │
      │                       │                         │
      │  2. Challenge +       │                         │
      │     allowed creds     │                         │
      │ <─────────────────────│                         │
      │                       │                         │
      │  3. navigator.credentials.get(options)          │
      │ ───────────────────────────────────────────────>│
      │                       │                         │
      │  4. User biometric    │                         │
      │ <──────── signed assertion ─────────────────────│
      │                       │                         │
      │  5. POST /webauthn/   │                         │
      │     login/finish      │                         │
      │ ─────────────────────>│                         │
      │                       │                         │
      │  6. Verify signature  │                         │
      │     → issue JWT +     │                         │
      │       refresh token   │                         │
      │ <── tokens ───────────│                         │
```

### Key Concepts

| Term | Meaning |
|------|---------|
| **Relying Party (RP)** | Our Identity server. Identified by RP ID (the domain, e.g. `id.example.com`) |
| **Discoverable credential** | Passkey stored on-device (resident key). Enables username-less login |
| **User verification** | Biometric or PIN check on the device itself |
| **Attestation** | Proof of authenticator type (we'll use `"none"` — we don't need hardware attestation) |
| **Challenge** | Random bytes from server, prevents replay attacks. Short-lived (60–120s) |
| **Credential ID** | Opaque handle identifying a specific passkey |
| **COSE public key** | The public key in CBOR Object Signing format |
| **Sign count** | Monotonic counter to detect credential cloning |

---

## Cross-Device and Cross-Platform Flows

### Flow 1: Desktop Browser

The simplest case. User visits the Identity server directly in Chrome/Safari/Firefox/Edge.

**Registration:** User logs in with password → navigates to account settings → clicks "Add passkey" → browser calls `navigator.credentials.create()` → OS prompts for biometric → credential stored in platform authenticator (Windows Hello, macOS Touch ID, iCloud Keychain, Google Password Manager).

**Login:** User visits login page → clicks "Sign in with passkey" → browser calls `navigator.credentials.get()` → OS prompts for biometric → server verifies → JWT issued.

**Passwordless option:** If user has discoverable credentials, the `allowCredentials` list can be empty, enabling fully username-less login. The browser autofills the username field and prompts for biometric directly.

### Flow 2: Mobile Browser (Safari / Chrome)

Identical to desktop from the protocol perspective. The WebAuthn API is the same in mobile browsers.

**Registration:** Same as desktop. On iOS, credentials go to iCloud Keychain. On Android, they go to Google Password Manager.

**Login:** Same as desktop. On iOS 16+/Android 14+, passkeys auto-sync across devices via the platform's cloud sync.

**Cross-device (hybrid transport):** If a user registered on desktop and wants to log in on mobile (or vice versa), the passkey syncs automatically via iCloud/Google. No extra server work needed — the same credential works on both devices because the private key is synced by the OS.

If using a *different ecosystem* (registered on iPhone, logging in on Windows), the user can use **hybrid transport**: the desktop browser shows a QR code, the user scans it with their phone, authenticates with biometrics on the phone, and the assertion is relayed over BLE. This is handled entirely by the browser/OS — **no server changes needed**.

### Flow 3: Native Mobile App → WebView Handoff

For native iOS/Android apps that authenticate via OAuth:

```
┌────────────┐      ┌───────────────────┐      ┌──────────────┐
│  Native App │      │ ASWebAuth Session │      │   Identity   │
│  (iOS)      │      │ / Custom Tab      │      │   Server     │
│             │      │ (Android)         │      │              │
└──────┬──────┘      └────────┬──────────┘      └──────┬───────┘
       │                      │                        │
       │  1. Start OAuth      │                        │
       │     flow (PKCE)      │                        │
       │ ────────────────────>│                        │
       │                      │                        │
       │                      │  2. GET /oauth/        │
       │                      │     authorize?...      │
       │                      │ ──────────────────────>│
       │                      │                        │
       │                      │  3. Login page with    │
       │                      │     passkey option     │
       │                      │ <──────────────────────│
       │                      │                        │
       │                      │  4. User taps passkey  │
       │                      │     → WebAuthn in      │
       │                      │     system browser     │
       │                      │                        │
       │                      │  5. POST /webauthn/    │
       │                      │     login/finish       │
       │                      │ ──────────────────────>│
       │                      │                        │
       │                      │  6. Set session cookie  │
       │                      │     → redirect with    │
       │                      │     auth code          │
       │                      │ <──────────────────────│
       │                      │                        │
       │  7. Receive callback │                        │
       │     with auth code   │                        │
       │ <────────────────────│                        │
       │                      │                        │
       │  8. Exchange code    │                        │
       │     for tokens       │                        │
       │ ─────────────────────────────────────────────>│
       │                      │                        │
       │  9. JWT + refresh    │                        │
       │ <─────────────────────────────────────────────│
```

**How it works:**

- **iOS:** `ASWebAuthenticationSession` opens Safari in-app. Safari has full access to the device's passkeys (iCloud Keychain). WebAuthn works natively inside this session. After auth, Safari redirects back to the app via the registered URI scheme.

- **Android:** Chrome Custom Tabs (or the system browser via `androidx.browser`). Chrome has access to Google Password Manager passkeys. Same flow — WebAuthn works, redirect back to app.

**Key insight:** The native app never directly calls WebAuthn APIs. It delegates authentication to the system browser via OAuth, and the browser handles the passkey ceremony. This means our server's OAuth login page just needs to support passkeys alongside passwords — no special native-app endpoints needed.

**Alternative — native passkey APIs (iOS 16+ / Android 14+):**
- iOS: `ASAuthorizationPlatformPublicKeyCredentialProvider` can perform WebAuthn directly in-app without a web view
- Android: `CredentialManager` API with FIDO2 credentials

These would call our `/webauthn/login/begin` and `/webauthn/login/finish` API endpoints directly from native code, bypassing OAuth entirely. The app would receive JWT tokens directly. This is the smoothest UX but requires each native app to implement the WebAuthn client-side logic.

---

## Architecture Decision: Two Options

### Option A: Passkeys as an Additional Auth Method (Recommended)

Passkeys complement passwords. Users can have both. Login page shows both options.

```
Password login:  POST /api/v1/auth/login         → JWT + refresh
Passkey login:   POST /api/v1/webauthn/login/*    → JWT + refresh
OAuth login:     GET /oauth/authorize             → login page (password OR passkey)
                                                     → auth code → JWT + refresh
```

**Pros:**
- No migration needed — existing users keep working
- Gradual adoption — users add passkeys when ready
- Fallback if passkey fails (lost device, new device without synced passkeys)
- Admin accounts can require password as a policy safeguard

**Cons:**
- Passwords remain a phishing target for users who don't adopt passkeys
- Slightly more UI complexity (two login options)

### Option B: Passkeys Replace Passwords

After registering a passkey, the user's password is removed. Login is passkey-only.

**Pros:**
- Stronger security posture
- Simpler mental model once migrated

**Cons:**
- Recovery is hard if all devices are lost (need recovery codes or admin reset)
- Can't easily support CLIs or headless environments
- Risky for admin accounts
- Requires building a recovery code system

### Recommendation: Option A

Start with Option A. Optionally add a per-user flag (`passkey_only`) later that disables password login for that user. Admins always keep password access.

---

## Implementation Plan

### Phase 1: Database Schema

New migration `003_webauthn.sql`:

```sql
-- WebAuthn challenges (ephemeral, 120-second TTL)
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id          TEXT PRIMARY KEY,
    user_id     TEXT,            -- NULL for login (discoverable credential flow)
    challenge   BLOB NOT NULL,   -- raw random bytes
    type        TEXT NOT NULL CHECK(type IN ('registration', 'authentication')),
    session_data TEXT NOT NULL,   -- JSON: go-webauthn SessionData blob
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires
    ON webauthn_challenges(expires_at);

-- Stored passkey credentials (one user can have many)
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id              TEXT PRIMARY KEY,           -- UUID (our internal ID)
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   BLOB NOT NULL UNIQUE,       -- WebAuthn credential.rawId
    public_key      BLOB NOT NULL,              -- COSE-encoded public key
    attestation_type TEXT NOT NULL DEFAULT 'none',
    aaguid          BLOB,                       -- Authenticator attestation GUID
    sign_count      INTEGER NOT NULL DEFAULT 0, -- Monotonic counter
    transports      TEXT,                       -- JSON array: ["internal","hybrid","usb","ble","nfc"]
    name            TEXT NOT NULL DEFAULT '',    -- User-provided label ("MacBook Pro Touch ID")
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id
    ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id
    ON webauthn_credentials(credential_id);
```

### Phase 2: Domain Layer

New file `internal/domain/webauthn.go`:

```go
type WebAuthnCredential struct {
    ID              string    // Internal UUID
    UserID          string    // FK to users
    CredentialID    []byte    // WebAuthn credential raw ID
    PublicKey       []byte    // COSE public key
    AttestationType string
    AAGUID          []byte
    SignCount       uint32
    Transports      []string  // ["internal", "hybrid", ...]
    Name            string    // User-provided label
    CreatedAt       time.Time
    LastUsedAt      time.Time
}

type WebAuthnCredentialRepository interface {
    Create(cred *WebAuthnCredential) error
    GetByCredentialID(credentialID []byte) (*WebAuthnCredential, error)
    ListByUserID(userID string) ([]*WebAuthnCredential, error)
    UpdateSignCount(id string, signCount uint32) error
    UpdateLastUsed(id string) error
    Delete(id string) error
    DeleteAllForUser(userID string) error
}

// WebAuthnChallenge stores ephemeral challenge data for in-flight ceremonies.
type WebAuthnChallenge struct {
    ID          string
    UserID      string // empty for discoverable-credential login
    Challenge   []byte
    Type        string // "registration" or "authentication"
    SessionData string // JSON blob from go-webauthn library
    CreatedAt   time.Time
    ExpiresAt   time.Time
}

type WebAuthnChallengeRepository interface {
    Create(ch *WebAuthnChallenge) error
    GetByID(id string) (*WebAuthnChallenge, error)
    Delete(id string) error
    DeleteExpired() error
}
```

### Phase 3: Go Library Integration

Use `github.com/go-webauthn/webauthn` — the most mature Go WebAuthn library (actively maintained, used in Gitea, Kanidm, etc.).

New file `internal/auth/webauthn.go`:

```go
// Adapter: make our domain.User satisfy the webauthn.User interface
type WebAuthnUser struct {
    user        *domain.User
    credentials []webauthn.Credential
}

func (u *WebAuthnUser) WebAuthnID() []byte                         { return []byte(u.user.ID) }
func (u *WebAuthnUser) WebAuthnName() string                       { return u.user.Username }
func (u *WebAuthnUser) WebAuthnDisplayName() string                { return u.user.DisplayName }
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }
```

Configuration:

```go
webAuthn, _ := webauthn.New(&webauthn.Config{
    RPDisplayName: "Identity Service",       // Human-readable
    RPID:          "id.example.com",         // Domain name (from env/config)
    RPOrigins:     []string{"https://id.example.com"}, // Allowed origins
    // For native apps using direct API:
    // RPOrigins: []string{"https://id.example.com", "ios:bundle:com.example.app"}
    AttestationPreference: protocol.PreferNoAttestation,
    AuthenticatorSelection: protocol.AuthenticatorSelection{
        ResidentKey:      protocol.ResidentKeyRequirementPreferred,
        UserVerification: protocol.VerificationPreferred,
    },
})
```

Config via environment:
- `WEBAUTHN_RP_ID` — the domain name (required for passkeys to work)
- `WEBAUTHN_RP_DISPLAY_NAME` — shown in browser prompts (default: "Identity Service")
- `WEBAUTHN_RP_ORIGINS` — comma-separated allowed origins

### Phase 4: Service Layer

Extend `AuthServicer` interface:

```go
type AuthServicer interface {
    // ... existing methods ...

    // WebAuthn registration (user must be authenticated)
    BeginPasskeyRegistration(userID string) (*protocol.CredentialCreation, string, error)
    FinishPasskeyRegistration(userID, challengeID string, response *protocol.ParsedCredentialCreationData) error

    // WebAuthn authentication (user is NOT authenticated)
    BeginPasskeyLogin(username string) (*protocol.CredentialAssertion, string, error)
    FinishPasskeyLogin(challengeID string, response *protocol.ParsedCredentialAssertionData, deviceHint, clientIP string) (*LoginResult, error)

    // Credential management
    ListPasskeys(userID string) ([]*domain.WebAuthnCredential, error)
    RenamePasskey(userID, credentialID, name string) error
    DeletePasskey(userID, credentialID string) error
}
```

Key flows:

**Registration:**
1. `BeginPasskeyRegistration` — load user + existing credentials, generate challenge via `webauthn.BeginRegistration()`, store challenge in DB, return options JSON + challenge ID
2. `FinishPasskeyRegistration` — load challenge from DB, call `webauthn.FinishRegistration()`, store new credential in DB, delete challenge, audit log

**Login:**
1. `BeginPasskeyLogin` — if username provided, load user's credentials for `allowCredentials` list; if empty, use discoverable credential flow (empty `allowCredentials`); generate challenge, store in DB
2. `FinishPasskeyLogin` — load challenge, call `webauthn.FinishLogin()`, verify signature, update sign count, look up user from credential, check `is_active`, issue JWT + refresh token via existing `issueTokens()`, audit log

### Phase 5: API Endpoints

New routes under `/api/v1/webauthn/`:

```
# Registration (requires valid JWT — user must be logged in)
POST /api/v1/webauthn/register/begin     → { publicKey: { ... }, challenge_id: "..." }
POST /api/v1/webauthn/register/finish    → 201 Created

# Authentication (no auth required — this IS the login)
POST /api/v1/webauthn/login/begin        → { publicKey: { ... }, challenge_id: "..." }
POST /api/v1/webauthn/login/finish       → { access_token, refresh_token, ... }

# Credential management (requires valid JWT)
GET    /api/v1/webauthn/credentials      → [{ id, name, created_at, last_used_at }]
PATCH  /api/v1/webauthn/credentials/{id} → rename
DELETE /api/v1/webauthn/credentials/{id} → delete
```

New file `internal/handler/api/webauthn.go`.

### Phase 6: OAuth Integration

The OAuth authorize page (`oauth_login.html`) currently shows username + password fields. We add a "Sign in with passkey" button.

**Flow within OAuth authorize:**

1. User hits `GET /oauth/authorize?client_id=...&redirect_uri=...&...` → login page renders
2. Login page includes JavaScript that:
   - On "Sign in with passkey" click, calls `POST /api/v1/webauthn/login/begin`
   - Calls `navigator.credentials.get()` with the returned options
   - Sends assertion to `POST /api/v1/webauthn/login/finish`
   - On success, receives a short-lived one-time session token
   - Posts that session token back to `POST /oauth/authorize` (new parameter: `session_token` instead of `username`/`password`)
3. Server validates session token, issues auth code, redirects

Alternative (simpler): The WebAuthn login/finish endpoint sets a short-lived HTTP-only cookie (e.g., `webauthn_session`), and the OAuth authorize POST checks for this cookie in addition to username/password. This avoids token passing in JavaScript.

**Recommended approach:** Add a new `AuthorizeUserByPasskey(credentialUserID, clientIP string) (string, error)` method to `AuthServicer` that works like `AuthorizeUser` but skips the password check (since WebAuthn already verified the user). The OAuth handler calls this after WebAuthn verification.

### Phase 7: Admin UI

Add passkey management to the admin panel:

- `/admin/users/{id}` — show registered passkeys, allow delete
- `/admin/` dashboard — passkey adoption stats (users with passkeys vs. without)

### Phase 8: Frontend JavaScript

New file `internal/ui/static/js/webauthn.js`:

```javascript
// Helper functions for WebAuthn ceremonies
async function beginPasskeyRegistration() {
    const resp = await fetch('/api/v1/webauthn/register/begin', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    const { publicKey, challenge_id } = await resp.json();

    // Base64URL decode challenge and user.id
    publicKey.challenge = base64URLToBuffer(publicKey.challenge);
    publicKey.user.id = base64URLToBuffer(publicKey.user.id);
    // Decode excludeCredentials
    if (publicKey.excludeCredentials) {
        publicKey.excludeCredentials = publicKey.excludeCredentials.map(c => ({
            ...c, id: base64URLToBuffer(c.id)
        }));
    }

    const credential = await navigator.credentials.create({ publicKey });

    // Send attestation back
    await fetch('/api/v1/webauthn/register/finish', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            challenge_id,
            credential: credentialToJSON(credential)
        })
    });
}

async function beginPasskeyLogin(username) {
    const resp = await fetch('/api/v1/webauthn/login/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }) // empty for discoverable credential
    });
    const { publicKey, challenge_id } = await resp.json();

    publicKey.challenge = base64URLToBuffer(publicKey.challenge);
    if (publicKey.allowCredentials) {
        publicKey.allowCredentials = publicKey.allowCredentials.map(c => ({
            ...c, id: base64URLToBuffer(c.id)
        }));
    }

    const assertion = await navigator.credentials.get({ publicKey });

    const result = await fetch('/api/v1/webauthn/login/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            challenge_id,
            credential: credentialToJSON(assertion)
        })
    });
    return result.json(); // { access_token, refresh_token, ... }
}
```

### Phase 9: Conditional UI / WebAuthn Feature Detection

The login pages (both direct and OAuth) should detect WebAuthn support:

```javascript
if (window.PublicKeyCredential) {
    // Show "Sign in with passkey" button
    // Optionally check for conditional mediation support:
    const available = await PublicKeyCredential.isConditionalMediationAvailable();
    if (available) {
        // Enable autofill-assisted passkey login (input autocomplete="webauthn")
    }
}
```

**Conditional UI (autofill-assisted):** On supporting browsers (Chrome 108+, Safari 16+), passkey login can be triggered from the username field's autofill dropdown. The user doesn't even need to click a button — they just tap their passkey suggestion in autofill. This requires `mediation: "conditional"` in the `navigator.credentials.get()` call and `autocomplete="username webauthn"` on the username input.

---

## How Each Client Type Works (Summary)

| Client | Registration | Login | Notes |
|--------|-------------|-------|-------|
| **Desktop browser** | Direct: `/webauthn/register/*` | Direct: `/webauthn/login/*` | Full WebAuthn API available |
| **Mobile Safari** | Direct: same endpoints | Direct: same endpoints | iCloud Keychain syncs passkeys |
| **Mobile Chrome** | Direct: same endpoints | Direct: same endpoints | Google Password Manager syncs |
| **Cross-device** (phone for desktop) | N/A | Hybrid transport (QR + BLE) | Handled by browser — no server changes |
| **Native iOS app (OAuth)** | Via `ASWebAuthenticationSession` | Via `ASWebAuthenticationSession` | System browser handles WebAuthn |
| **Native iOS app (direct)** | `ASAuthorizationPlatformPublicKeyCredentialProvider` → our API | Same | Best UX, more client-side code |
| **Native Android app (OAuth)** | Via Chrome Custom Tab | Via Chrome Custom Tab | System browser handles WebAuthn |
| **Native Android app (direct)** | `CredentialManager` API → our API | Same | Best UX, more client-side code |

---

## New Error Codes

| Code | HTTP | When |
|------|------|------|
| `webauthn_not_enabled` | 400 | RP not configured (missing `WEBAUTHN_RP_ID`) |
| `webauthn_invalid_challenge` | 400 | Challenge expired or not found |
| `webauthn_verification_failed` | 400 | Attestation or assertion verification failed |
| `webauthn_credential_exists` | 409 | Credential already registered |
| `webauthn_no_credentials` | 400 | User has no registered passkeys |
| `webauthn_credential_not_found` | 404 | Credential ID not found for user |

---

## Audit Events

New event types for the existing `auth_events` table:

| Event | Description |
|-------|-------------|
| `passkey_register_success` | User registered a new passkey |
| `passkey_register_failure` | Registration ceremony failed |
| `passkey_login_success` | User authenticated via passkey |
| `passkey_login_failure` | Assertion verification failed |
| `passkey_deleted` | Passkey removed (by user or admin) |

---

## Configuration

New environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBAUTHN_RP_ID` | *(none — feature disabled if unset)* | Domain for the RP (e.g., `id.example.com`) |
| `WEBAUTHN_RP_DISPLAY_NAME` | `"Identity Service"` | Human-readable name shown in browser prompts |
| `WEBAUTHN_RP_ORIGINS` | `https://{WEBAUTHN_RP_ID}` | Comma-separated allowed origins |

When `WEBAUTHN_RP_ID` is not set, all `/webauthn/*` endpoints return `webauthn_not_enabled`. This keeps the feature opt-in and backward compatible.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/go-webauthn/webauthn` | Server-side WebAuthn ceremonies |

This is the only new dependency. It's well-maintained (2.5k+ GitHub stars, used by Gitea, Woodpecker CI, and others), has no CGo requirements, and its API maps cleanly to our architecture.

---

## Files to Create / Modify

### New files

| File | Purpose |
|------|---------|
| `internal/db/migrations/003_webauthn.sql` | Schema for credentials + challenges |
| `internal/domain/webauthn.go` | Domain types + repository interfaces |
| `internal/store/webauthn_credential_store.go` | Credential CRUD |
| `internal/store/webauthn_challenge_store.go` | Challenge CRUD (ephemeral) |
| `internal/auth/webauthn.go` | `webauthn.User` adapter, config setup |
| `internal/handler/api/webauthn.go` | HTTP handlers for all `/webauthn/*` endpoints |
| `internal/ui/static/js/webauthn.js` | Client-side WebAuthn ceremony helpers |

### Modified files

| File | Change |
|------|--------|
| `internal/config/config.go` | Add `WebAuthnRPID`, `WebAuthnRPDisplayName`, `WebAuthnRPOrigins` |
| `internal/service/interfaces.go` | Extend `AuthServicer` with WebAuthn methods |
| `internal/service/auth_service.go` | Implement WebAuthn registration + login flows |
| `internal/handler/api/router.go` | Register `/webauthn/*` routes |
| `internal/handler/oauth/handler.go` | Support passkey login in OAuth authorize flow |
| `internal/domain/oauth.go` | Add new audit event constants |
| `internal/spec/openapi.yaml` | Document new endpoints |
| `cmd/server/main.go` | Initialize `go-webauthn`, pass to services |
| `internal/ui/templates/oauth_login.html` | Add passkey login button + JS |
| `internal/ui/templates/login.html` | Add passkey login button + JS (admin login) |
| `go.mod` / `go.sum` | Add `go-webauthn/webauthn` dependency |
| `scripts/e2e.sh` | Add passkey flow tests (may need headless browser or mock) |

---

## Implementation Order

1. **Schema + domain types** — migration, domain models, repository interfaces
2. **Store layer** — SQLite implementations for credential + challenge repos
3. **go-webauthn integration** — library setup, user adapter, config
4. **Service layer** — registration + login + credential management logic
5. **API handlers** — HTTP endpoints, request/response types
6. **Frontend JS** — `webauthn.js` helper, login page integration
7. **OAuth integration** — passkey option on OAuth login page
8. **Admin UI** — credential management in admin panel
9. **OpenAPI spec** — document all new endpoints
10. **Testing** — unit tests, e2e script additions

Each phase is independently testable. Phase 1–5 can be built and tested via `curl` + a WebAuthn testing tool. Phase 6–7 add the browser UX. Phase 8–10 are polish.

---

## Security Considerations

- **Challenge TTL:** 120 seconds, single-use, deleted after verification
- **Sign count verification:** Detect credential cloning (increment must be > stored value)
- **Origin validation:** Enforced by `go-webauthn` library via `RPOrigins` config
- **RP ID binding:** Credentials are cryptographically bound to the RP ID domain — they cannot be used on a different domain
- **No attestation requirement:** We use `"none"` — we trust any authenticator. This maximizes compatibility (all passkey providers work). If you later want to restrict to specific authenticators (e.g., hardware keys only), you can change this.
- **Rate limiting:** `/webauthn/login/*` endpoints should be covered by the existing auth rate limiter (5 req/min per IP)
- **User enumeration:** `login/begin` with a specific username reveals whether that user exists. Mitigation: support discoverable credential flow (no username needed) as the primary UX, or return a fake challenge for non-existent users (like the current bcrypt dummy hash strategy)
