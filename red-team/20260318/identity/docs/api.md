# Identity API — Integration Guide

This document covers everything a client developer needs to integrate with the Identity service, including the direct API login flow and the OAuth 2.0 authorization code flow with PKCE.

---

## Overview

The Identity service is a self-hosted JWT authentication and identity management service. Single Go binary, SQLite database. In production, traffic goes through a Cloudflare Tunnel, so the endpoint is always **HTTPS**.

- **Base URL**: `https://<your-domain>`
- **API endpoints**: `/api/v1/*` — JSON request/response
- **OAuth endpoints**: `/oauth/*` — form-encoded requests, JSON token responses
- **Admin UI**: `/admin/*` — browser-based management
- **Machine-readable spec**: `GET /openapi.json` or `GET /openapi.yaml` (OpenAPI 3.0)

---

## Two Ways to Authenticate

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

```
POST /api/v1/auth/logout
Authorization: Bearer <access_token>
Content-Type: application/json
```

```json
{ "refresh_token": "dGhpcyBpcyBhIHJhbmRvbSB0b2tlbg" }
```

If `refresh_token` is provided, only that device's session is revoked. If omitted, **all** sessions for the user are revoked.

**Response**: `204 No Content`

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
| `unsupported_grant_type` | Grant type not `authorization_code` or `refresh_token` |
| `access_denied` | Account disabled |
| `server_error` | Unexpected internal error |

---

## Token Lifecycle

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
