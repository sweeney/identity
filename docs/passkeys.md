# Passkeys / WebAuthn

Passkeys let users sign in with biometrics (Touch ID, Face ID, Windows Hello) instead of typing a password. They're built on the WebAuthn standard and are phishing-resistant — the credential is cryptographically bound to your domain and can't be used on a fake site.

## How it works

1. User registers a passkey while logged in (via password or existing passkey)
2. The browser creates a public/private key pair — the private key stays on the device (or syncs via iCloud Keychain / Google Password Manager)
3. The server stores the public key
4. On next login, the server sends a challenge, the device signs it with the private key, the server verifies the signature

After a successful passkey login, the server issues the same JWT access token + refresh token pair as a password login. All existing token refresh, rotation, and theft detection works unchanged.

## Configuration

### Development (automatic)

In development mode (`IDENTITY_ENV=development` or unset), passkeys are automatically enabled with `localhost` as the Relying Party ID. No configuration needed.

If your client apps run on different ports (e.g. a demo on `:9091`), add them to `CORS_ORIGINS` — they're automatically included as allowed WebAuthn origins:

```bash
CORS_ORIGINS=http://localhost:9091,http://localhost:9093 ./bin/identity-server
```

### Production

Set the Relying Party ID to your domain. Use the parent domain (not the subdomain) so passkeys work across subdomains and native apps:

```bash
WEBAUTHN_RP_ID=swee.net
WEBAUTHN_RP_ORIGINS=https://id.swee.net
```

The RP ID is permanent — it's baked into every passkey at registration time. If you change it, all existing passkeys are invalidated.

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBAUTHN_RP_ID` | `localhost` (dev) / none (prod) | Domain for the Relying Party |
| `WEBAUTHN_RP_ORIGINS` | derived from RP ID | Comma-separated allowed origins |
| `WEBAUTHN_RP_DISPLAY_NAME` | `Identity Service` | Shown in browser passkey prompts |
| `SITE_NAME` | `Identity` | Shown in admin nav, OAuth login, page titles |

## Admin UI

### Managing your own passkeys

After logging in to the admin UI, click **Passkeys** in the navigation bar. From there you can:

- Register a new passkey (your browser will prompt for biometrics)
- Name your passkeys (e.g. "MacBook Pro", "iPhone")
- Delete passkeys

### Managing other users' passkeys

When editing a user at `/admin/users/{id}/edit`, a **Passkeys** section at the bottom shows their registered passkeys. Admins can delete a user's passkeys from there.

### Passkey registration prompt

After a password login, users who don't have a passkey are prompted to register one. This appears on both the admin login flow and the OAuth login flow. The prompt can be skipped — it appears again on the next password login until a passkey is registered.

## API reference

All endpoints are under `/api/v1/webauthn/`. Registration endpoints require a valid JWT (the user must be logged in). Login endpoints are unauthenticated (they *are* the login).

### Registration

**Begin registration** (requires JWT):

```
POST /api/v1/webauthn/register/begin
Authorization: Bearer <access_token>
```

Response:
```json
{
  "publicKey": { "challenge": "...", "rp": { "id": "swee.net" }, "user": { ... }, ... },
  "challenge_id": "uuid"
}
```

**Finish registration** (requires JWT):

```
POST /api/v1/webauthn/register/finish?challenge_id=<id>&name=<optional-name>
Authorization: Bearer <access_token>
Content-Type: application/json

{ "id": "...", "rawId": "...", "type": "public-key", "response": { ... } }
```

Response: `201 Created` with the credential details.

### Authentication

**Begin login** (no auth required):

```
POST /api/v1/webauthn/login/begin
Content-Type: application/json

{ "username": "alice" }
```

Omit `username` for discoverable credential flow (username-less login). If the username doesn't exist, a fake challenge is returned to prevent user enumeration.

Response:
```json
{
  "publicKey": { "challenge": "...", "allowCredentials": [...], ... },
  "challenge_id": "uuid"
}
```

**Finish login** (no auth required):

```
POST /api/v1/webauthn/login/finish?challenge_id=<id>
Content-Type: application/json

{ "id": "...", "rawId": "...", "type": "public-key", "response": { ... } }
```

Response (same as password login):
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "..."
}
```

### Credential management

**List credentials** (requires JWT):
```
GET /api/v1/webauthn/credentials
Authorization: Bearer <access_token>
```

**Rename credential** (requires JWT):
```
PATCH /api/v1/webauthn/credentials/{id}
Authorization: Bearer <access_token>
Content-Type: application/json

{ "name": "MacBook Pro" }
```

**Delete credential** (requires JWT):
```
DELETE /api/v1/webauthn/credentials/{id}
Authorization: Bearer <access_token>
```

## Error codes

| Code | HTTP | When |
|------|------|------|
| `webauthn_not_enabled` | 400 | RP not configured (`WEBAUTHN_RP_ID` not set) |
| `webauthn_invalid_challenge` | 400 | Challenge expired, not found, or already used |
| `webauthn_verification_failed` | 400/401 | Attestation or assertion verification failed |
| `webauthn_no_credentials` | 400 | User has no registered passkeys |
| `webauthn_credential_not_found` | 404 | Credential ID not found for this user |

## Integration guide

### JavaScript (browser)

The WebAuthn API requires binary buffers. You need helpers to convert between base64url (used in JSON) and ArrayBuffer (used by the browser API):

```javascript
function base64urlToBuffer(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufferToBase64url(buf) {
  const bytes = new Uint8Array(buf);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
```

**Login flow:**

```javascript
// 1. Begin
const beginResp = await fetch('/api/v1/webauthn/login/begin', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'alice' }), // or {} for discoverable
});
const { publicKey, challenge_id } = await beginResp.json();

// 2. Decode challenge
publicKey.challenge = base64urlToBuffer(publicKey.challenge);
if (publicKey.allowCredentials) {
  publicKey.allowCredentials = publicKey.allowCredentials.map(c => ({
    ...c, id: base64urlToBuffer(c.id),
  }));
}

// 3. Browser ceremony
const assertion = await navigator.credentials.get({ publicKey });

// 4. Finish
const finishResp = await fetch(`/api/v1/webauthn/login/finish?challenge_id=${challenge_id}`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    id: assertion.id,
    rawId: bufferToBase64url(assertion.rawId),
    type: assertion.type,
    response: {
      authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
      clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
      signature: bufferToBase64url(assertion.response.signature),
      userHandle: assertion.response.userHandle
        ? bufferToBase64url(assertion.response.userHandle) : undefined,
    },
  }),
});
const { access_token, refresh_token } = await finishResp.json();
```

### OAuth flow

For OAuth clients (SPAs, server-side apps, BFF), passkey login happens on the Identity server's login page — no client-side WebAuthn code needed. The OAuth authorize page includes a "Sign in with passkey" button automatically when the browser supports WebAuthn.

### Native apps (iOS / Android)

Native apps using OAuth (`ASWebAuthenticationSession` on iOS, Chrome Custom Tabs on Android) get passkey support for free — the system browser handles the WebAuthn ceremony on the Identity server's login page.

For direct passkey APIs (without OAuth), use:
- **iOS**: `ASAuthorizationPlatformPublicKeyCredentialProvider` calling the `/api/v1/webauthn/*` endpoints
- **Android**: `CredentialManager` API calling the same endpoints

Both require an association file on your domain:
- iOS: `https://swee.net/.well-known/apple-app-site-association`
- Android: `https://swee.net/.well-known/assetlinks.json`

## Cross-device login

When a user needs to log in on a device that doesn't have their passkey (e.g. a new computer), they can use their phone as an authenticator. The browser shows a QR code, the user scans it with their phone, authenticates with biometrics, and the assertion is relayed via Bluetooth. This is handled entirely by the browser/OS — no server changes needed.

## Demo app

A standalone passkey demo is included at `examples/passkey-demo/`:

```bash
# Terminal 1: start the identity server
ADMIN_USERNAME=admin ADMIN_PASSWORD=mypassword \
  CORS_ORIGINS=http://localhost:9093 \
  go run ./cmd/server

# Terminal 2: start the demo
go run ./examples/passkey-demo

# Open http://localhost:9093
```

The demo lets you: password login, register a passkey, sign out, sign back in with the passkey, list/delete passkeys.

## Testing

```bash
# Unit tests
go test ./...

# WebAuthn e2e tests (requires running server)
./scripts/e2e-webauthn.sh
```

The e2e script tests all API endpoints, error paths, challenge lifecycle, cross-user isolation, and route availability (32 checks). It can't test the actual biometric ceremony (that requires a browser), but verifies the full server-side contract.
