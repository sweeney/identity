# Identity API — Integration Guide

This document covers everything a client developer needs to integrate with the Identity service, including the direct API login flow, the OAuth 2.0 authorization code flow with PKCE, and the device authorization flow for embedded and headless hardware.

---

## Overview

The Identity service is a self-hosted JWT authentication and identity management service. Single Go binary, SQLite database. In production, traffic goes through a Cloudflare Tunnel, so the endpoint is always **HTTPS**.

- **Base URL**: `https://<your-domain>`
- **API endpoints**: `/api/v1/*` — JSON request/response
- **OAuth endpoints**: `/oauth/*` — form-encoded requests, JSON token responses
- **Admin UI**: `/admin/*` — browser-based management
- **Machine-readable spec**: `GET /openapi.json` or `GET /openapi.yaml` (OpenAPI 3.0)

---

## Four Ways to Authenticate

### Option A: Direct API Login

Best for first-party apps that collect credentials directly.

1. `POST /api/v1/auth/login` with username + password → receive tokens
2. Use `Authorization: Bearer <access_token>` on every request
3. Refresh proactively with `POST /api/v1/auth/refresh`

### Option B: OAuth 2.0 Authorization Code + PKCE

Best for third-party apps, multiple domains, or native mobile apps that should redirect to the Identity server for login.

1. App generates a PKCE `code_verifier` and `code_challenge`
2. App redirects user to `GET /oauth/authorize` with client_id, redirect_uri, code_challenge
3. User logs in on the Identity server
4. Identity server redirects back with an authorization code
5. App exchanges the code at `POST /oauth/token` with the code_verifier → receive tokens

OAuth clients must be registered via the admin UI at `/admin/oauth` before use.

### Option C: Client Credentials (service-to-service)

Best for backend services, cron jobs, and microservices that need to call APIs without user involvement.

1. Register an OAuth client with `client_credentials` grant type and generate a secret
2. `POST /oauth/token` with `grant_type=client_credentials` + client authentication → receive access token
3. Use `Authorization: Bearer <access_token>` on every request
4. When the token expires (15 min), re-authenticate with the same credentials (no refresh token)

See [Client Credentials Flow](#client-credentials-flow) below for details.

### Option D: Device Authorization Grant (RFC 8628)

Best for embedded hardware, IoT sensors, and any device that cannot open a browser — ESP32s, Raspberry Pis, headless servers, smart appliances.

Two variants depending on whether the device has a screen:

- **Standard flow** — device displays an 8-char code (`ABCD-EFGH`) and a URL; user visits the URL, types the code, logs in. Device polls until approved.
- **Claim-code flow** — device ships with a 12-char code pre-baked in firmware and printed as a QR sticker. User scans the sticker once to pair. On every subsequent boot the device authenticates automatically without any user interaction.

See [Device Authorization Flow](#device-authorization-flow-rfc-8628) below for details.

---

## Direct API Flow

### Step 1 — Login

```
POST /api/v1/auth/login
Content-Type: application/json
```

| Field | Type | Required | Description |
|---|---|---|---|
| `username` | string | Yes | User's username |
| `password` | string | Yes | User's password |
| `device_hint` | string | No | Informational label, e.g. `"iPhone 15 / iOS 18"` |

**Response 200**:

```json
{
  "access_token":  "eyJhbGc...",
  "token_type":    "Bearer",
  "expires_in":    900,
  "refresh_token": "dGhpcyBpcyBhIHJhbmRvbSB0b2tlbg"
}
```

| Field | Description |
|---|---|
| `access_token` | Short-lived JWT (15 min) — use in `Authorization` headers |
| `token_type` | Always `"Bearer"` |
| `expires_in` | Seconds until access token expires (always 900) |
| `refresh_token` | Long-lived opaque token (30-day sliding) — store securely |

### Step 2 — Make Authenticated Requests

```
Authorization: Bearer eyJhbGc...
```

### Step 3 — Refresh Before Expiry

Access tokens expire after 15 minutes. Refresh proactively when the token has less than 60 seconds remaining.

> **Important**: Every call to `/auth/refresh` invalidates the old refresh token and returns a new one. **Store the new refresh token immediately.**

```
POST /api/v1/auth/refresh
Content-Type: application/json
```

```json
{ "refresh_token": "dGhpcyBpcyBhIHJhbmRvbSB0b2tlbg" }
```

**Response 200**: Same shape as login — new `access_token` and new `refresh_token`.

**Refresh token lifetime**: 30 days, **sliding**. Each successful refresh resets the 30-day window.

### Step 4 — Logout

**Revoke current session only** (pass the refresh token):

```
POST /api/v1/auth/logout
Authorization: Bearer <access_token>
Content-Type: application/json
```

```json
{ "refresh_token": "dGhpcyBpcyBhIHJhbmRvbSB0b2tlbg" }
```

**Revoke all sessions** (omit the body entirely):

```
POST /api/v1/auth/logout
Authorization: Bearer <access_token>
```

If a body is present it **must be `Content-Type: application/json`**. Sending any other encoding (e.g. form data) returns `400 invalid_request_body`. An empty body with no `Content-Type` is valid and triggers the sign-out-everywhere path.

**Response**: `204 No Content`

**Error responses**:

| Status | Error code | Cause |
|---|---|---|
| `400` | `invalid_request_body` | Non-empty body is not valid JSON |
| `401` | — | Missing or invalid access token |

---

## OAuth 2.0 Authorization Code Flow + PKCE

### Registering a Client

Before an app can use OAuth, register it via the admin UI at `/admin/oauth/new`. You'll need:

- **Client ID** — a short identifier like `myapp` (lowercase, hyphens, underscores)
- **Application Name** — displayed to users during login
- **Redirect URIs** — allowlist of URIs the server will redirect to (one per line)

Native apps can use custom schemes (e.g. `myapp://callback`).

### Step 1 — Generate PKCE Pair

The client generates a random `code_verifier` (43-128 characters, unreserved URI characters) and computes the challenge:

```
code_challenge = base64url(sha256(code_verifier))
```

### Step 2 — Redirect to Authorize

Open in the user's browser:

```
GET /oauth/authorize
  ?response_type=code
  &client_id=myapp
  &redirect_uri=https://myapp.example.com/callback
  &code_challenge=<base64url-encoded-challenge>
  &code_challenge_method=S256
  &state=<random-csrf-token>
```

| Parameter | Required | Description |
|---|---|---|
| `response_type` | Yes | Must be `code` |
| `client_id` | Yes | Registered client ID |
| `redirect_uri` | Yes | Must match one of the client's registered URIs |
| `code_challenge` | Yes | S256 PKCE challenge |
| `code_challenge_method` | Yes | Must be `S256` (plain is rejected) |
| `state` | Recommended | Opaque value for CSRF protection — returned unchanged |

The Identity server renders a login form showing the application name. After the user submits valid credentials, the server redirects to:

```
https://myapp.example.com/callback?code=<authorization-code>&state=<state>
```

### Step 3 — Exchange Code for Tokens

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&client_id=myapp
&code=<authorization-code>
&redirect_uri=https://myapp.example.com/callback
&code_verifier=<original-verifier>
```

| Parameter | Required | Description |
|---|---|---|
| `grant_type` | Yes | `authorization_code` |
| `client_id` | Yes | Must match the authorize request |
| `code` | Yes | The authorization code from the redirect |
| `redirect_uri` | Yes | Must match the authorize request |
| `code_verifier` | Yes | The original PKCE verifier |

**Response 200**:

```json
{
  "access_token":  "eyJhbGc...",
  "token_type":    "Bearer",
  "expires_in":    900,
  "refresh_token": "dGhpcyBpcyBhIHJhbmRvbSB0b2tlbg"
}
```

Authorization codes are single-use and expire after 60 seconds.

### Step 4 — Refresh via OAuth Token Endpoint

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=<refresh-token>
```

**Response 200**: Same token response shape.

### OAuth Error Format

The `/oauth/token` endpoint uses RFC 6749 error format, which differs from the rest of the API:

```json
{
  "error": "invalid_grant",
  "error_description": "The authorization code has expired."
}
```

| `error` code | When |
|---|---|
| `invalid_request` | Missing required parameters |
| `invalid_grant` | Bad/expired/replayed code, PKCE failure, bad refresh token |
| `unsupported_grant_type` | Grant type not recognized |
| `unauthorized_client` | Client not authorized for this grant type |
| `invalid_client` | Bad client credentials or auth method mismatch |
| `invalid_scope` | Requested scope exceeds client's allowed scopes |
| `access_denied` | Account disabled |
| `server_error` | Unexpected internal error |

---

## Client Credentials Flow

For backend services that need to call APIs without user involvement.

### Prerequisites

1. Register an OAuth client at `/admin/oauth` with:
   - **Grant Types**: `client_credentials` checked
   - **Token Endpoint Auth Method**: `client_secret_basic` (recommended) or `client_secret_post`
   - **Scopes**: the scopes this service is allowed to request (e.g. `read:users`)
   - **Audience**: the identifier of the target service (e.g. `https://api.example.com`)
2. Generate a client secret on the client's edit page

### Step 1 — Obtain an access token

```
POST /oauth/token
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded
```

| Field | Type | Required | Description |
|---|---|---|---|
| `grant_type` | string | Yes | Must be `client_credentials` |
| `scope` | string | No | Space-delimited scopes. Defaults to all client scopes if omitted. |

**Response 200**:

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read:users"
}
```

No `refresh_token` is returned. When the token expires, repeat this request.

**Go example**:

```go
func authenticate(clientID, clientSecret, scope string) (*TokenResponse, error) {
    form := url.Values{
        "grant_type": {"client_credentials"},
        "scope":      {scope},
    }
    req, _ := http.NewRequest("POST", identityURL+"/oauth/token",
        strings.NewReader(form.Encode()))
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    req.SetBasicAuth(clientID, clientSecret)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
    }

    var tok TokenResponse
    json.NewDecoder(resp.Body).Decode(&tok)
    return &tok, nil
}
```

**Swift example**:

```swift
func authenticate(clientID: String, clientSecret: String, scope: String) async throws -> TokenResponse {
    var request = URLRequest(url: URL(string: "\(identityURL)/oauth/token")!)
    request.httpMethod = "POST"
    request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

    let credentials = Data("\(clientID):\(clientSecret)".utf8).base64EncodedString()
    request.setValue("Basic \(credentials)", forHTTPHeaderField: "Authorization")

    request.httpBody = "grant_type=client_credentials&scope=\(scope)".data(using: .utf8)

    let (data, response) = try await URLSession.shared.data(for: request)
    guard (response as? HTTPURLResponse)?.statusCode == 200 else {
        throw AuthError.authenticationFailed
    }
    return try JSONDecoder().decode(TokenResponse.self, from: data)
}
```

### Step 2 — Use the token

Same as all other flows: send `Authorization: Bearer <access_token>` on every request.

### Step 3 — Re-authenticate on expiry

There is no refresh token. When the access token expires (check `expires_in`), call the token endpoint again with the same credentials.

**Recommended pattern**: cache the token in memory with its expiry time. Re-authenticate with a 60-second buffer before `expires_in` to avoid clock-skew 401s.

### JWT claims (RFC 9068)

Service tokens use a different claim structure from user tokens:

```json
{
  "iss": "https://id.example.com",
  "sub": "my-service",
  "client_id": "my-service",
  "aud": "https://api.example.com",
  "scope": "read:users",
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "iat": 1711393200,
  "exp": 1711394100
}
```

- `sub` = `client_id` (no user identity)
- `client_id` is a top-level claim (use this to distinguish service tokens from user tokens)
- `aud` identifies the target service — resource servers should reject tokens not intended for them
- `scope` is space-delimited
- `jti` is a unique token ID (enables revocation lists)
- No `usr` (username), `rol` (role), or `act` (active) claims

### Token introspection (RFC 7662)

Resource servers can validate a token in real-time by calling the introspection endpoint:

```
POST /oauth/introspect
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

token=eyJhbGciOiJFUzI1NiIs...
```

**Response** (valid token):
```json
{
  "active": true,
  "sub": "my-service",
  "client_id": "my-service",
  "scope": "read:users",
  "token_type": "Bearer",
  "jti": "550e8400-...",
  "exp": 1711394100,
  "iat": 1711393200
}
```

**Response** (expired/invalid token):
```json
{ "active": false }
```

### Discovery (RFC 8414)

```
GET /.well-known/oauth-authorization-server
```

Returns the token endpoint URL, JWKS URI, supported grant types, and other metadata. Useful for clients that want to self-configure rather than hard-code URLs.

### Secret rotation

1. Admin clicks "Rotate Secret" on the client's edit page
2. A new secret is generated; both old and new are accepted
3. Update the service's configuration with the new secret
4. Admin clicks "Clear Previous Secret" to complete rotation

Zero-downtime — the service continues authenticating throughout.

### Error codes

| `error` code | When |
|---|---|
| `invalid_client` | Unknown client, bad secret, or auth method mismatch |
| `unauthorized_client` | Client not configured for `client_credentials` grant |
| `invalid_scope` | Requested scope exceeds allowed scopes |

---

## Device Authorization Flow (RFC 8628) — Firmware Guide

For embedded devices and headless hardware that cannot open a browser. The device asks the server to start a session, then polls until a human approves it from any browser. Two modes are supported: **standard** (device has a screen) and **claim-code** (device has no screen, ships with a pre-baked code).

> **If you are a firmware developer or AI coding agent building a device:** read this entire section top to bottom. The HTTP contract is below; the gotchas that will actually bite you on a constrained device (clock, TLS roots, atomic NVS writes, refresh rotation ordering, polling jitter) are in [Firmware Implementation Notes](#firmware-implementation-notes) near the bottom. Don't skip them.

### Choose a flow

```
Does the device have a display that can render ≥ 20 characters?
│
├─ Yes ──► Standard flow. User types the code at your verification URL.
│         Each boot is a fresh pairing unless you persist the refresh token.
│
└─ No ───► Claim-code flow. Bake a 12-char code into firmware, print it on a sticker.
          User scans the sticker once to pair. Re-boots auto-pair forever
          unless an admin revokes the code.
```

### What you need from the admin before you can build

1. A **client_id** (a short string like `my-sensor`) — bake this into firmware as a compile-time constant.
2. For claim-code devices: **one raw claim code per unit** — generated at `/admin/oauth/{client_id}/claim-codes`. The admin sees them exactly once; they get flashed into each device and printed on its sticker.
3. The **verification URL base** — usually `https://<your-identity-host>/oauth/device`. Hard-code this or fetch it from `verification_uri` at runtime.

### Prerequisites

1. In the admin UI at `/admin/oauth/new`, register an OAuth client with:
   - **Grant Types**: `urn:ietf:params:oauth:grant-type:device_code` checked
   - **Client ID**: a short identifier such as `my-sensor` (no secret required)
   - **Scopes** and **Audience**: configure as needed for your API
2. Note the **Client ID** — it is baked into device firmware.
3. For the claim-code flow only: go to `/admin/oauth/{client_id}/claim-codes`, generate one claim code per physical device, and attach the printed sticker (or flash the code into firmware) before shipping.

---

### Standard Device Flow (device has a screen)

Use this when the device can display at least a short alphanumeric string and a URL.

#### Step 1 — Request a device session

```
POST /oauth/device_authorization
Content-Type: application/x-www-form-urlencoded

client_id=my-sensor
&scope=read:data          (optional)
```

| Field | Required | Description |
|---|---|---|
| `client_id` | Yes | Registered client ID |
| `scope` | No | Space-delimited scopes; defaults to all client scopes |

**Response 200**:

```json
{
  "device_code":              "Tz9Kw…",
  "user_code":                "ABCD-EFGH",
  "verification_uri":         "https://id.example.com/oauth/device",
  "verification_uri_complete": "https://id.example.com/oauth/device?user_code=ABCD-EFGH",
  "expires_in":               600,
  "interval":                 5
}
```

| Field | Description |
|---|---|
| `device_code` | Opaque polling secret — keep in RAM only, never log |
| `user_code` | 8-char code to show to the user (`XXXX-XXXX` format) |
| `verification_uri` | URL to display alongside the code |
| `verification_uri_complete` | URL with the code pre-filled — embed in a QR if the device has a display |
| `expires_in` | Seconds until both codes expire (600 s / 10 min) |
| `interval` | Minimum seconds between polls — start here, increase on `slow_down` |

#### Step 2 — Show the code to the user

Display `user_code` and `verification_uri` on the device screen (or print them to a serial console for development). If the device can render a QR code, use `verification_uri_complete` so the user does not have to type the code manually.

The user opens the URL in any browser, logs in, and clicks Approve. The device does not need to know when this happens — it finds out by polling.

#### Step 3 — Poll for tokens

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:device_code
&client_id=my-sensor
&device_code=Tz9Kw…
```

| Field | Required | Description |
|---|---|---|
| `grant_type` | Yes | Must be `urn:ietf:params:oauth:grant-type:device_code` |
| `client_id` | Yes | Same client ID as Step 1 |
| `device_code` | Yes | The `device_code` from Step 1 |

**On approval — Response 200**:

```json
{
  "access_token":  "eyJhbGc…",
  "token_type":    "Bearer",
  "expires_in":    900,
  "refresh_token": "dGhpcyBpcyBhIHJhbmRvbSB0b2tlbg"
}
```

Tokens are identical to those from direct login — the same refresh rotation and theft detection apply. Store the refresh token in non-volatile storage; see [Token Storage on Embedded Devices](#token-storage-on-embedded-devices).

**While waiting — error responses**:

| `error` | Action |
|---|---|
| `authorization_pending` | Not approved yet — wait `interval` seconds and poll again |
| `slow_down` | Polling too fast — add 5 seconds to your interval permanently, then retry |
| `access_denied` | User clicked Deny — stop polling, show an error, restart the flow if needed |
| `expired_token` | The 10-minute window closed — restart from Step 1 |
| `invalid_grant` | `device_code` unknown or mismatched `client_id` — restart from Step 1 |

> **Do not poll faster than `interval` seconds.** The server returns `slow_down` if you do, which increases the required interval. Every `slow_down` response must permanently increase your interval by 5 seconds for the remainder of that session.

---

### Claim-Code Flow (screenless device)

Use this when the device has no display and cannot show a code to the user. The claim code is a 12-char string (`XXXX-XXXX-XXXX`) generated by the admin, printed on a QR sticker attached to the device or flashed into firmware. The user scans the sticker once to pair. From then on the device authenticates on its own.

#### Boot sequence

```
Boot
 │
 ├─ POST /oauth/device/claim  (claim_code from firmware)
 │      │
 │      └─► device_code  (valid for 10 min)
 │
 ├─ Poll POST /oauth/token with device_code
 │      │
 │      ├─ authorization_pending  →  (first boot, unbound) wait for user to scan sticker
 │      │                            user visits verification_uri, logs in, approves
 │      │                            polling resumes → tokens issued
 │      │
 │      └─ access_token + refresh_token  →  (bound) store in NVS, proceed
 │
 └─ Use access_token, refresh before expiry
```

#### Step 1 — Exchange claim code for a device session

```
POST /oauth/device/claim
Content-Type: application/x-www-form-urlencoded

client_id=my-sensor
&claim_code=DQLC-V379-9RAQ
&scope=read:data          (optional)
```

| Field | Required | Description |
|---|---|---|
| `client_id` | Yes | Registered client ID (baked in firmware) |
| `claim_code` | Yes | 12-char claim code (baked in firmware or NVS) |
| `scope` | No | Space-delimited scopes |

**Response 200**:

```json
{
  "device_code":              "Hz4Rm…",
  "user_code":                "QHLP-5B2W",
  "claim_code":               "DQLC-V379-9RAQ",
  "verification_uri":         "https://id.example.com/oauth/device",
  "verification_uri_complete": "https://id.example.com/oauth/device?code=DQLC-V379-9RAQ",
  "expires_in":               600,
  "interval":                 5
}
```

Note that `verification_uri_complete` uses the claim code (`?code=…`), not the session user code, so the sticker QR remains valid across reboots.

**Error responses**:

| `error` | Cause |
|---|---|
| `invalid_grant` | Claim code not found or already revoked — contact admin |
| `invalid_client` | Unknown `client_id` |
| `unauthorized_client` | Client not configured for device flow |

#### Step 2 — Poll for tokens (same as standard flow)

Poll `POST /oauth/token` with the `device_code` from Step 1 using the same request format and error-handling rules as the standard flow above.

**First boot (unbound claim code):** The server returns `authorization_pending` until the user scans the QR sticker on the device and approves. After approval, the claim code is permanently bound to that user — no further user interaction is ever needed for this device.

**Subsequent boots (bound claim code):** The session is auto-approved the moment it is created. Your first poll (or second at most) returns tokens immediately.

#### Re-authentication on every boot

Because the claim code is permanent, the device can always get fresh tokens by repeating Steps 1–2 — even if its NVS is wiped or the refresh token is corrupted. This is the intended recovery path for factory resets.

#### Revocation

If a device is decommissioned or stolen, an admin revokes its claim code at `/admin/oauth/{client_id}/claim-codes`. After revocation:
- Any ongoing poll returns `access_denied`
- Future calls to `POST /oauth/device/claim` return `invalid_grant`
- Existing refresh tokens derived from the claim code continue to work until they expire or are explicitly invalidated — call `POST /api/v1/auth/logout` (all sessions) to clear them immediately if needed

---

### Firmware Implementation Notes

Constrained devices have a handful of failure modes that a server-side OAuth client never has to think about. Get these right up front.

#### Quick DO / DON'T checklist

| Do | Don't |
|---|---|
| Sync the system clock via NTP **before** making any HTTPS call | Assume the MCU clock is correct on first boot |
| Ship a pinned CA bundle or the server's fingerprint | Trust the platform default CA pool on an ESP32 — there isn't one |
| Persist the new refresh token **before** returning success from your refresh function | Keep the old refresh token around "just in case" — rotation is instantaneous |
| Add random jitter (±20%) to every poll interval | Poll at the exact same second as every other device on your network |
| Treat `slow_down` as a one-way ratchet — add 5 s to your interval for the rest of the session | Reset the interval back to 5 s after any successful poll |
| Retry transient network errors (DNS, TCP RST, TLS handshake fail) with exponential backoff | Treat a network error the same as `access_denied` |
| Keep `device_code` in RAM only; zero it after exchange | Store `device_code` in NVS |
| Treat the claim code as the device's permanent identity | Regenerate the claim code at runtime |

#### Clock and NTP

Access tokens are JWTs with an `exp` claim. The server validates `exp` against **its own** clock, so your device clock only matters if your firmware inspects the JWT locally.

- If you treat the access token as opaque and just use the server-provided `expires_in` to schedule the next refresh, you can skip NTP entirely. This is the recommended approach.
- If you do parse the JWT (to check `exp` before sending a request, for example), sync via NTP first — SNTP is fine, pool.ntp.org works, ±10 s is plenty.
- TLS itself is tolerant: Go's `crypto/tls` on the server side doesn't care about the client's clock, and `modernc/sqlite`'s cert chain only cares about the server-presented certificate.

#### TLS root certificates

In production the identity server is fronted by Cloudflare Tunnel, so the cert chain terminates at a well-known public CA. On an MCU with no preinstalled CA pool you have two choices:

- **Bundle a CA**: flash Cloudflare's root (and one backup) as a PEM string into your firmware. Smaller, easier to audit, but you must re-flash devices if the root rotates (Cloudflare re-issues every few years).
- **Pin the SPKI fingerprint**: compute SHA-256 of the server cert's SubjectPublicKeyInfo and compare on every handshake. No re-flash needed when the cert is re-issued as long as the same key pair is reused. Most IoT deployments do this.

Arduino's `WiFiClientSecure.setCACert(pem)` and ESP-IDF's `esp_tls_cfg_t.cacert_pem_buf` both work. Don't use `setInsecure()` in production.

#### Atomic NVS writes

Flash loses state if power is cut between an erase and a program. If your platform exposes atomic NVS (ESP-IDF's `nvs_flash` is durable per-key but **not** across keys; Zephyr NVS is per-entry atomic), prefer the native API. Otherwise:

1. Write the new refresh token to a **shadow key** (`refresh_token.new`).
2. Commit/flush.
3. Rename atomically to the canonical key.

A half-written refresh token bricks the device — it doesn't match server state and every future refresh returns `token_family_compromised`, which forces you back through the claim-code flow. That's survivable but embarrassing.

#### Refresh rotation ordering (critical)

Every `POST /api/v1/auth/refresh` invalidates the old refresh token **the moment the server processes it**. Your firmware sees the response window, but the server has already moved on. Therefore:

```
1. Hold a local copy of the current refresh token in RAM.
2. POST /api/v1/auth/refresh with it.
3. On 200 OK: write the *new* refresh token to NVS.  ← this step must not fail.
4. Update the in-RAM access token.
```

If step 3 fails (NVS write error, power loss) you have lost access to this device's refresh chain. Recovery is the claim-code flow (auto-approves; no human interaction). This is why claim-code is a nicer answer than standard device flow for unattended hardware — recovery is graceful.

Never retry a failed `/auth/refresh` with the same refresh token. The second call will fail with `token_family_compromised` and revoke every session for that user.

#### Polling etiquette: jitter and rate limiting

The server rate-limits `POST /oauth/token` at 5 requests per minute per IP. Two or three devices behind the same NAT polling in lockstep can starve each other.

- **Add jitter**: `sleep(interval * (1 + random(-0.2, +0.2)))`.
- **Increase interval on `slow_down`**: permanently add 5 seconds. Never decrease it within a session.
- **Transient network errors get exponential backoff**: 1 s, 2 s, 4 s, up to `interval`. Don't treat network errors as auth errors.
- **After 15 minutes of `authorization_pending`**: the `device_code` will expire. Start over from Step 1 rather than polling forever.

#### Token and claim-code storage

Embedded devices cannot use a hardware keychain. Store tokens in non-volatile storage (NVS, EEPROM, or a dedicated flash partition) and treat the storage as the security boundary.

```
NVS key              Value                                     Write frequency
──────────────────── ───────────────────────────────────────── ────────────────
"refresh_token"      opaque string, 30-day sliding lifetime    every refresh (~15 min)
"access_token"       JWT, 15-min lifetime (optional)           every refresh
"access_expiry"      Unix timestamp of access token expiry     every refresh
"claim_code"         12-char code (claim-code flow only)       once, at factory
```

**Flash wear**: a refresh every 15 minutes is ~100 writes/day, ~35 K writes/year. ESP32 internal NVS is rated for ~100 K erase cycles per sector, which the NVS library spreads across sectors, so 10+ years of life is realistic. If you need more, persist access tokens in RAM only and only write `refresh_token` on change (it changes every refresh, so the saving is small).

**Recommended boot strategy**:

1. Read `refresh_token` from NVS.
2. If present, try `POST /api/v1/auth/refresh` → new access + refresh tokens. Persist both.
3. If refresh fails (`invalid_refresh_token` / `token_family_compromised`) or NVS is empty, fall through to the claim-code flow.
4. Never store the `device_code` — it is single-use per boot and expires in 10 minutes.

**Claim code storage**: The claim code never changes. Flash it at the factory or include it in signed firmware. If you store it in NVS for flexibility, write it once and treat it as read-only. Losing the claim code is recoverable (admin can look it up by label); leaking it is not (an attacker could impersonate the device until the admin revokes it).

#### Handling revocation

If an admin revokes a device's claim code or an attacker triggers family-compromise detection:

- Ongoing polls return `access_denied` (claim) or `token_family_compromised` (refresh).
- Stop network traffic, clear `refresh_token` from NVS, and either enter an "unpaired" state or hard-reboot into the claim-code flow.
- **Do not retry automatically** on `access_denied` — doing so flares rate limits and audit logs.

#### Testing without hardware

Every step is reachable over plain `curl`. If you're wiring up firmware in an LLM-driven loop, validate the server contract with curl first, then port to your MCU SDK. See `scripts/e2e-device-flow.sh` at the repo root for a working end-to-end script you can crib from — it exercises both flows and the error paths in 25 checks.

```bash
# Standard flow, start a session:
curl -X POST https://id.example.com/oauth/device_authorization \
  -d "client_id=my-sensor"

# Claim-code flow:
curl -X POST https://id.example.com/oauth/device/claim \
  -d "client_id=my-sensor&claim_code=DQLC-V379-9RAQ"

# Poll:
curl -X POST https://id.example.com/oauth/token \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  --data-urlencode "client_id=my-sensor" \
  --data-urlencode "device_code=Tz9Kw…"
```

---

### C Example (ESP32 / Arduino)

```c
// Pseudocode — adapt HTTPClient calls to your WiFi library.
// Assumes wifi_post(url, body, response_buf, buf_len) returns HTTP status.

#define IDENTITY_URL   "https://id.example.com"
#define CLIENT_ID      "my-sensor"
#define CLAIM_CODE_KEY "claim_code"    // NVS key
#define REFRESH_KEY    "refresh_token" // NVS key

// Claim-code boot sequence. Returns 0 on success, -1 on error.
int device_authenticate(char *access_token_out) {
    char claim_code[20];
    nvs_get_str(CLAIM_CODE_KEY, claim_code, sizeof(claim_code));

    // Step 1: exchange claim code for a device session
    char body[256], resp[1024];
    snprintf(body, sizeof(body),
        "client_id=" CLIENT_ID "&claim_code=%s", claim_code);
    if (wifi_post(IDENTITY_URL "/oauth/device/claim", body, resp, sizeof(resp)) != 200)
        return -1; // invalid/revoked claim code — contact admin

    char device_code[128];
    int interval = 5; // seconds
    json_get_str(resp, "device_code", device_code, sizeof(device_code));
    json_get_int(resp, "interval", &interval);

    // Step 2: poll until approved
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(interval * 1000));

        snprintf(body, sizeof(body),
            "grant_type=urn:ietf:params:oauth:grant-type:device_code"
            "&client_id=" CLIENT_ID
            "&device_code=%s", device_code);
        int status = wifi_post(IDENTITY_URL "/oauth/token", body, resp, sizeof(resp));

        if (status == 200) {
            char refresh[256];
            json_get_str(resp, "access_token",  access_token_out, 512);
            json_get_str(resp, "refresh_token", refresh, sizeof(refresh));
            nvs_set_str(REFRESH_KEY, refresh); // persist for next boot
            return 0;
        }

        char err[64];
        json_get_str(resp, "error", err, sizeof(err));

        if (strcmp(err, "authorization_pending") == 0) {
            continue; // keep waiting
        } else if (strcmp(err, "slow_down") == 0) {
            interval += 5; // back off permanently for this session
        } else {
            // access_denied / expired_token / invalid_grant — give up
            return -1;
        }
    }
}

void app_main(void) {
    char access_token[512] = {0};

    // Try refresh first (fast path on subsequent boots)
    char saved_refresh[256];
    if (nvs_get_str(REFRESH_KEY, saved_refresh, sizeof(saved_refresh)) == OK) {
        char body[512], resp[1024];
        snprintf(body, sizeof(body),
            "{\"refresh_token\":\"%s\"}", saved_refresh);
        if (http_post_json(IDENTITY_URL "/api/v1/auth/refresh",
                           body, resp, sizeof(resp)) == 200) {
            json_get_str(resp, "access_token",  access_token,    sizeof(access_token));
            json_get_str(resp, "refresh_token", saved_refresh,   sizeof(saved_refresh));
            nvs_set_str(REFRESH_KEY, saved_refresh);
            goto authenticated;
        }
        // Refresh failed — fall through to claim-code flow
        nvs_erase_key(REFRESH_KEY);
    }

    // Claim-code flow (first boot or after refresh failure)
    if (device_authenticate(access_token) != 0) {
        ESP_LOGE("auth", "Authentication failed — check claim code or admin");
        esp_restart();
    }

authenticated:
    // access_token is valid; use it on every request
    // Repeat the refresh/claim flow when it expires (check expires_in or handle 401)
}
```

---

### Device Flow Error Reference

Errors from `POST /oauth/token` use RFC 6749 format:

```json
{ "error": "authorization_pending", "error_description": "The user has not yet approved this device." }
```

| `error` | Meaning | Action |
|---|---|---|
| `authorization_pending` | User has not approved yet | Wait `interval` seconds, poll again |
| `slow_down` | Polling interval too short | Add 5 s to interval permanently, then poll again |
| `access_denied` | User denied or account disabled | Stop polling; restart flow or surface error to user |
| `expired_token` | `device_code` expired (10 min window) | Restart from Step 1 |
| `invalid_grant` | Unknown `device_code` or claim code revoked | Restart from Step 1 (standard) or contact admin (claim-code) |
| `invalid_client` | Unknown `client_id` | Fix firmware — client ID is wrong |
| `unauthorized_client` | Client not enabled for device flow | Admin must enable the `device_code` grant on the client |

---



```
App Launch
    │
    ├─ Refresh token in secure storage? ─Yes─► POST /auth/refresh (or /oauth/token)
    │                                              │
    │                                         Success? ─Yes─► Store new tokens, proceed
    │                                              │
    │                                          No (401) ─────────────────────────┐
    │                                                                             │
    └─ No ────────────────────────────────────────────────────────────────────► Login Screen
                                                                                (direct or OAuth)
```

**Access token** (in-memory only):
- Valid for 900 seconds (15 minutes)
- Embed in `Authorization: Bearer` header
- Do NOT persist to disk

**Refresh token** (secure storage):
- Valid for 30 days sliding
- Rotated on every use — always save the newest one
- If lost, user must log in again

---

## Token Rotation and Theft Detection

Every refresh rotates the token: old token is revoked, new pair issued. If a **previously-used** refresh token is presented again, the server assumes theft. It revokes the **entire token family** (all tokens from that login session) and returns `token_family_compromised`.

**What to do**: Clear all stored tokens, show the login screen, and alert the user: *"Your session was ended for security reasons. Please log in again."*

**Implementation requirement**: Use a mutex around the refresh call. If multiple in-flight requests all get a 401 simultaneously, only one should refresh; the others should wait and reuse the result.

```
var accessToken: String?
var refreshMutex: Mutex

function callAPI(endpoint, body):
    response = http(endpoint, Authorization: "Bearer " + accessToken)

    if response.status == 401:
        refreshMutex.lock()
        defer refreshMutex.unlock()

        // Another thread may have already refreshed
        if accessToken has changed since we last read it:
            return http(endpoint, Authorization: "Bearer " + accessToken)

        result = POST /auth/refresh { refresh_token: loadRefreshToken() }

        if result.status != 200:
            clearAllTokens()
            navigateToLogin()
            return error

        accessToken = result.access_token
        saveRefreshToken(result.refresh_token)
        return http(endpoint, Authorization: "Bearer " + accessToken)

    return response
```

---

## Secure Token Storage

Never store tokens in plain text, logs, or crash reports.

### iOS (Swift)

```swift
import Security

func saveRefreshToken(_ token: String) {
    let data = token.data(using: .utf8)!
    let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrAccount: "refresh_token",
        kSecValueData: data,
        kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    SecItemDelete(query as CFDictionary)
    SecItemAdd(query as CFDictionary, nil)
}
```

### Android (Kotlin)

```kotlin
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val prefs = EncryptedSharedPreferences.create(
    context,
    "identity_secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

prefs.edit().putString("refresh_token", refreshToken).apply()
```

---

## Error Handling Reference

### API Errors (`/api/v1/*`)

All errors follow this envelope:

```json
{
  "error":   "snake_case_code",
  "message": "Human readable description"
}
```

| HTTP Status | `error` code | Action |
|---|---|---|
| `401` | `unauthorized` | Attempt token refresh, then show login |
| `401` | `invalid_credentials` | Show login form error |
| `401` | `invalid_refresh_token` | Clear all tokens, show login |
| `401` | `token_expired` | Attempt token refresh |
| `401` | `token_family_compromised` | Clear all tokens, alert user, show login |
| `403` | `account_disabled` | Show "account disabled" message |
| `403` | `forbidden` | Show permission error |
| `404` | `not_found` | Show not found UI |
| `409` | `username_taken` | Show inline field error |
| `409` | `cannot_delete_last_admin` | Show error message |
| `422` | `validation_error` | Show field errors |
| `422` | `weak_password` | Show password strength requirement |
| `500` | `internal_error` | Show generic error |

### OAuth Errors (`/oauth/token`)

Uses RFC 6749 format — see the OAuth section above.

---

## API Reference

### Auth Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/auth/login` | None | Authenticate, receive tokens |
| POST | `/api/v1/auth/refresh` | None | Rotate refresh token, receive new pair |
| POST | `/api/v1/auth/logout` | Bearer | Revoke session(s) |
| GET | `/api/v1/auth/me` | Bearer | Inspect current user from JWT claims |

### User Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/users` | Admin | List all users |
| POST | `/api/v1/users` | Admin | Create a user |
| GET | `/api/v1/users/{id}` | Bearer | Get user (non-admins: own record only) |
| PUT | `/api/v1/users/{id}` | Admin | Partial update |
| DELETE | `/api/v1/users/{id}` | Admin | Delete user (last admin protected) |

### OAuth Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/oauth/authorize` | None | Render login form for OAuth client |
| POST | `/oauth/authorize` | None | Submit credentials, receive redirect with code |
| POST | `/oauth/token` | None | Exchange code or refresh token for tokens |
| POST | `/oauth/device_authorization` | None | Begin standard device flow — returns `device_code` + `user_code` |
| POST | `/oauth/device/claim` | None | Begin claim-code flow — exchange pre-shared claim code for `device_code` |
| GET | `/oauth/device` | None | Browser-facing device verification page (user types/scans code here) |

### Admin UI

| Path | Description |
|---|---|
| `/admin/` | Dashboard |
| `/admin/users` | User management |
| `/admin/oauth` | OAuth client management (CRUD) |
| `/admin/audit` | Auth event timeline |

---

## JWT Token Structure

The access token payload contains:

```json
{
  "iss": "identity.home",
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "exp": 1700000900,
  "usr": "alice",
  "rol": "user",
  "act": true
}
```

| Claim | Description |
|---|---|
| `sub` | User UUID |
| `exp` | Expiry (Unix timestamp) |
| `usr` | Username |
| `rol` | `"user"` or `"admin"` |
| `act` | Account active status |

Use `GET /api/v1/auth/me` for user info rather than decoding the JWT client-side.

---

## Role Model

- **admin** — full access to all endpoints including user management
- **user** — can call `/auth/*` and `GET /users/{own-id}` only

---

## Audit Log

All authentication events are recorded to an immutable audit log, visible at `/admin/audit`. Events include:

| Event | When |
|---|---|
| `login_success` | Successful API login |
| `login_failure` | Failed login attempt (wrong password or unknown user) |
| `oauth_authorize_success` | Successful OAuth authorization |
| `oauth_authorize_failure` | Failed OAuth authorization attempt |
| `token_family_compromised` | Replayed refresh token detected |
| `logout` | Single-session logout |
| `logout_all` | All-sessions logout |
| `device_authorize_issued` | Device session started (`/oauth/device_authorization` or `/oauth/device/claim`) |
| `device_authorize_approved` | User approved a device session (or auto-approved via bound claim code) |
| `device_authorize_denied` | User denied a device session |
| `device_token_issued` | Tokens issued to a device after approval |
| `claim_code_created` | Admin generated a new claim code |
| `claim_code_bound` | Claim code bound to a user on first approval |
| `claim_code_revoked` | Admin revoked a claim code |

Each event captures: username, user ID, client ID (for OAuth), IP address, device hint, and timestamp.

---

## Machine-Readable Spec

```
GET /openapi.json   application/json
GET /openapi.yaml   application/yaml
```

The source is at `internal/spec/openapi.yaml`.

---

## Versioning

The current API version is **v1** (path prefix `/api/v1`). OAuth endpoints are unversioned at `/oauth/*`. Breaking changes will be introduced under a new version path.
