# Identity API — Full Lifecycle Walkthrough

This walkthrough exercises every endpoint in a realistic lifecycle: direct API login, user management, token rotation, theft detection, OAuth authorization code flow with PKCE, and the audit log.

For the machine-readable contract see `GET /openapi.json`. For the integration guide see `docs/api.md`.

## Setup

Start the server:

```bash
./bin/identity-server
```

On first run, the server generates a JWT signing secret (stored in the DB) and an admin account with a random password printed to stdout. Alternatively, provide explicit credentials:

```bash
ADMIN_USERNAME="admin" ADMIN_PASSWORD="adminpassword1" ./bin/identity-server
```

Default port is 8181.

## Route map

### API routes (`/api/v1`)

```
POST   /api/v1/auth/login       — no auth
POST   /api/v1/auth/refresh     — no auth
POST   /api/v1/auth/logout      — Bearer token
GET    /api/v1/auth/me          — Bearer token
GET    /api/v1/users            — admin only
POST   /api/v1/users            — admin only
GET    /api/v1/users/{id}       — Bearer (non-admins: own record only)
PUT    /api/v1/users/{id}       — admin only
DELETE /api/v1/users/{id}       — admin only
```

### OAuth routes (`/oauth`)

```
GET    /oauth/authorize          — renders login form
POST   /oauth/authorize          — submits credentials, redirects with code
POST   /oauth/token              — exchanges code or refresh token for tokens
```

### Admin UI routes (`/admin`)

```
/admin/              — dashboard
/admin/users         — user management
/admin/oauth         — OAuth client management
/admin/audit         — auth event timeline
```

---

## Part 1: Direct API Flow

### Step 1 — Login

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"adminpassword1","device_hint":"walkthrough"}' | jq .
```

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "uZynErs28_VQ8ynAxdRno..."
}
```

Save both tokens. The access token is used in `Authorization` headers. The refresh token is used to get new tokens before expiry.

### Step 2 — Inspect current user

```bash
curl -s http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .
```

```json
{
  "id": "e5d68731-...",
  "username": "admin",
  "role": "admin",
  "is_active": true
}
```

### Step 3 — Create a user (admin only)

```bash
curl -s -X POST http://localhost:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{"username":"alice","display_name":"Alice Smith","password":"alicepass123","role":"user"}' | jq .
```

```json
{
  "id": "d06d19a0-...",
  "username": "alice",
  "display_name": "Alice Smith",
  "role": "user",
  "is_active": true,
  "created_at": "2026-03-17T12:00:00Z"
}
```

### Step 4 — List users (admin only)

```bash
curl -s http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .
```

```json
{
  "total": 2,
  "users": [
    { "id": "d06d19a0-...", "username": "alice", "role": "user", ... },
    { "id": "e5d68731-...", "username": "admin", "role": "admin", ... }
  ]
}
```

### Step 5 — Non-admin access controls

Alice can call `/auth/me` and fetch her own user record, but admin-only endpoints return 403:

```bash
ALICE_TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"alicepass123"}' | jq -r '.access_token')

# Own record — 200 OK
curl -s http://localhost:8080/api/v1/users/$ALICE_ID \
  -H "Authorization: Bearer $ALICE_TOKEN" | jq .

# Admin endpoint — 403 Forbidden
curl -s http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer $ALICE_TOKEN" | jq .
```

```json
{ "error": "forbidden", "message": "admin role required" }
```

### Step 6 — Token refresh

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}" | jq .
```

Returns a new access token and a **new** refresh token. The old refresh token is now invalid.

### Step 7 — Token theft detection

Replaying the old (rotated) refresh token triggers family-wide revocation:

```bash
# Replay the OLD refresh token
curl -s -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$OLD_REFRESH_TOKEN\"}" | jq .
```

```json
{
  "error": "token_family_compromised",
  "message": "token reuse detected — please log in again"
}
```

The entire token family is now revoked — even the new token from step 6.

### Step 8 — Logout

```bash
# Logout single device
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}"
# → 204

# Logout all devices (omit refresh_token)
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer $ACCESS_TOKEN"
# → 204
```

### Error cases

**Invalid credentials** — 401:
```json
{ "error": "invalid_credentials", "message": "invalid username or password" }
```

**Duplicate username** — 409:
```json
{ "error": "username_taken", "message": "a user with that username already exists" }
```

**Weak password** — 422:
```json
{ "error": "weak_password", "message": "password must be at least 12 characters" }
```

**Cannot delete last admin** — 409:
```json
{ "error": "cannot_delete_last_admin", "message": "cannot delete the last admin user" }
```

---

## Part 2: OAuth 2.0 Authorization Code Flow + PKCE

### Step 1 — Register an OAuth client

Open the admin UI at `http://localhost:8080/admin/oauth/new` and create a client:

- **Client ID**: `myapp`
- **Application Name**: `My Home Dashboard`
- **Redirect URIs**: `https://myapp.example.com/callback`

### Step 2 — Generate PKCE pair

```bash
CODE_VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
STATE=$(openssl rand -hex 16)
```

### Step 3 — Open the authorize URL

In a browser (or programmatically):

```
http://localhost:8080/oauth/authorize
  ?response_type=code
  &client_id=myapp
  &redirect_uri=https://myapp.example.com/callback
  &code_challenge=$CODE_CHALLENGE
  &code_challenge_method=S256
  &state=$STATE
```

The Identity server renders a branded login page showing "Sign in to My Home Dashboard".

### Step 4 — User submits credentials

After the user enters their username and password, the server:

1. Validates the credentials
2. Generates a single-use authorization code (60s TTL)
3. Records an audit event (`oauth_authorize_success` or `oauth_authorize_failure`)
4. Redirects to:

```
https://myapp.example.com/callback?code=<authorization-code>&state=$STATE
```

### Step 5 — Exchange code for tokens

```bash
curl -s -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&client_id=myapp&code=$CODE&redirect_uri=https://myapp.example.com/callback&code_verifier=$CODE_VERIFIER" | jq .
```

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "abc123..."
}
```

### Step 6 — Refresh via the OAuth token endpoint

```bash
curl -s -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN" | jq .
```

### OAuth error cases

**Invalid/expired code**:
```json
{ "error": "invalid_grant", "error_description": "The authorization code has expired." }
```

**PKCE mismatch**:
```json
{ "error": "invalid_grant", "error_description": "PKCE verification failed." }
```

**Code replay** (already used):
```json
{ "error": "invalid_grant", "error_description": "The authorization code has already been used." }
```

**Unknown client** (at GET /oauth/authorize): renders an error page with "The client_id is not registered."

**Bad redirect URI** (at GET /oauth/authorize): renders an error page with "The redirect_uri is not registered for this client."

---

## Part 3: Admin UI

### Dashboard

`GET /admin/` — shows user count and backup status.

### User Management

`GET /admin/users` — list, create, edit, delete users. Supports enabling/disabling accounts and changing roles.

### OAuth Client Management

`GET /admin/oauth` — list all registered OAuth clients with their redirect URIs.

- **Create**: `GET /admin/oauth/new` — form for client ID, name, and redirect URIs (one per line)
- **Edit**: `GET /admin/oauth/{id}/edit` — update name and redirect URIs
- **Delete**: `GET /admin/oauth/{id}/delete` — confirm and delete

### Audit Log

`GET /admin/audit` — timeline of all auth events, newest first.

Each event shows:
- **Timestamp** in UTC
- **Event type** with color-coded badge (green = success, red = failure/compromise)
- **Username** (captured even for failed logins)
- **Client ID** (for OAuth events)
- **IP address** (from `CF-Connecting-IP` or `RemoteAddr`)
- **Device hint** (from login requests)

Supports filtering by user ID or event type via query parameters.

---

## Summary

| # | What | Endpoint |
|---|---|---|
| 1 | Direct login | `POST /api/v1/auth/login` |
| 2 | Inspect token claims | `GET /api/v1/auth/me` |
| 3 | Refresh tokens | `POST /api/v1/auth/refresh` |
| 4 | Logout | `POST /api/v1/auth/logout` |
| 5 | User CRUD | `/api/v1/users` (admin) |
| 6 | Token theft detection | Automatic on refresh token replay |
| 7 | OAuth authorize | `GET/POST /oauth/authorize` |
| 8 | OAuth token exchange | `POST /oauth/token` |
| 9 | OAuth client management | `/admin/oauth` |
| 10 | Audit log | `/admin/audit` |
