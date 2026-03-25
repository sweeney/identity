# Authentication Flows

Visual walkthrough of how web apps, mobile apps, and backend services authenticate against the Identity server.

---

## Flow A: Direct API Login

For first-party apps that collect credentials directly (e.g. your own mobile app).

```
  Mobile App                                    Identity Server
  ──────────                                    ───────────────
      │
      │  POST /api/v1/auth/login
      │  { username, password, device_hint }
      │ ──────────────────────────────────────────►│
      │                                            │  Validate credentials
      │                                            │  Hash password (bcrypt)
      │                                            │  Mint JWT access token (15 min)
      │                                            │  Generate refresh token (30-day)
      │                                            │  Store refresh token hash in DB
      │                                            │  Record audit event
      │◄────────────────────────────────────────── │
      │  { access_token, refresh_token,
      │    token_type: "Bearer", expires_in: 900 }
      │
      │  ┌─────────────────────────────────┐
      │  │ Store refresh token in Keychain │
      │  │ Keep access token in memory     │
      │  └─────────────────────────────────┘
      │
      │  GET /api/v1/auth/me
      │  Authorization: Bearer <access_token>
      │ ──────────────────────────────────────────►│
      │                                            │  Parse JWT (no DB hit)
      │◄────────────────────────────────────────── │
      │  { id, username, role, is_active }
      │
      ▼
```

---

## Flow B: OAuth 2.0 Authorization Code + PKCE

For third-party apps, multi-domain web apps, or any app that redirects to
`identity.swee.net` for login. This is the "Sign in with Identity" flow.

### Phase 1: Authorization

```
  Web/Mobile App                   Browser                      Identity Server
  ──────────────                   ───────                      ───────────────
      │
      │  1. Generate PKCE pair:
      │     code_verifier  = random(32 bytes)
      │     code_challenge = base64url(sha256(code_verifier))
      │     state          = random(16 bytes)
      │
      │  2. Open browser / redirect
      │ ─────────────────────►│
      │                       │  GET /oauth/authorize
      │                       │  ?response_type=code
      │                       │  &client_id=myapp
      │                       │  &redirect_uri=https://myapp/cb
      │                       │  &code_challenge=ABC123
      │                       │  &code_challenge_method=S256
      │                       │  &state=XYZ
      │                       │ ──────────────────────────────►│
      │                       │                                │  Look up client in DB
      │                       │                                │  Validate redirect_uri
      │                       │                                │    against allowlist
      │                       │◄────────────────────────────── │
      │                       │  HTML login page:
      │                       │  "Sign in to My App"
      │                       │
      │                       │  ┌──────────────────────┐
      │                       │  │  Username: [alice   ] │
      │                       │  │  Password: [•••••••] │
      │                       │  │  [ Sign in ]         │
      │                       │  └──────────────────────┘
      │                       │
      │                       │  POST /oauth/authorize
      │                       │  { client_id, redirect_uri,
      │                       │    code_challenge, username,
      │                       │    password }
      │                       │ ──────────────────────────────►│
      │                       │                                │  Validate credentials
      │                       │                                │  Generate auth code
      │                       │                                │  Store code hash in DB
      │                       │                                │    (60s TTL, single-use)
      │                       │                                │  Record audit event
      │                       │◄────────────────────────────── │
      │                       │  302 Redirect
      │                       │  Location: https://myapp/cb
      │                       │    ?code=DEF456&state=XYZ
      │◄─────────────────────│
      │  App receives callback
      │  Verify state matches
      │
```

### Phase 2: Token Exchange

```
  Web/Mobile App                                    Identity Server
  ──────────────                                    ───────────────
      │
      │  3. Exchange code for tokens
      │
      │  POST /oauth/token
      │  Content-Type: application/x-www-form-urlencoded
      │
      │  grant_type=authorization_code
      │  &client_id=myapp
      │  &code=DEF456
      │  &redirect_uri=https://myapp/cb
      │  &code_verifier=<original verifier>
      │ ──────────────────────────────────────────►│
      │                                            │  Look up code hash in DB
      │                                            │  Verify: client matches
      │                                            │  Verify: redirect_uri matches
      │                                            │  Verify: not expired (<60s)
      │                                            │  Verify: not already used
      │                                            │  Verify PKCE:
      │                                            │    sha256(verifier) == challenge
      │                                            │  Mark code as used
      │                                            │  Mint JWT access token
      │                                            │  Generate refresh token
      │                                            │  Store refresh token hash
      │◄────────────────────────────────────────── │
      │  {
      │    "access_token":  "eyJhbGc...",
      │    "token_type":    "Bearer",
      │    "expires_in":    900,
      │    "refresh_token": "abc123..."
      │  }
      │
      │  ┌─────────────────────────────────┐
      │  │ Store refresh token securely    │
      │  │ Keep access token in memory     │
      │  └─────────────────────────────────┘
      │
      ▼  Now use access_token exactly like Flow A
```

---

## Token Refresh (both flows)

```
  App                                               Identity Server
  ───                                               ───────────────
      │
      │  Access token expires in <60s?
      │
      │  POST /api/v1/auth/refresh          (direct API)
      │  ── OR ──
      │  POST /oauth/token                  (OAuth)
      │    grant_type=refresh_token
      │    &refresh_token=<current token>
      │ ──────────────────────────────────────────►│
      │                                            │  Look up token by hash
      │                                            │  Verify: not revoked
      │                                            │  Verify: not expired
      │                                            │  Verify: user still active
      │                                            │
      │                                            │  ┌──────────────────────┐
      │                                            │  │ ROTATE:              │
      │                                            │  │  Revoke old token    │
      │                                            │  │  Issue new pair      │
      │                                            │  │  (atomic transaction)│
      │                                            │  └──────────────────────┘
      │                                            │
      │◄────────────────────────────────────────── │
      │  { new access_token, new refresh_token }
      │
      │  ┌──────────────────────────────────────┐
      │  │ CRITICAL: Save new refresh token     │
      │  │ IMMEDIATELY. The old one is dead.    │
      │  └──────────────────────────────────────┘
      │
      ▼
```

---

## Token Theft Detection

What happens when a stolen refresh token is replayed:

```
  Legitimate App          Attacker                  Identity Server
  ──────────────          ────────                  ───────────────
      │                       │
      │  Login ──────────────────────────────────►│
      │◄───────────────────── refresh_token_v1 ── │
      │                       │
      │  ··· attacker steals refresh_token_v1 ···
      │                       │
      │  Refresh (v1) ───────────────────────────►│
      │◄───────────────────── refresh_token_v2 ── │  v1 is now revoked
      │                       │
      │                       │  Replay (v1) ────►│
      │                       │                    │  v1 is revoked!
      │                       │                    │  ┌─────────────────────┐
      │                       │                    │  │ THEFT DETECTED      │
      │                       │                    │  │ Revoke ALL tokens   │
      │                       │                    │  │ in this family      │
      │                       │                    │  │ (v1, v2, and any    │
      │                       │                    │  │  future descendants)│
      │                       │                    │  │ Record audit event  │
      │                       │                    │  └─────────────────────┘
      │                       │◄────────────────── │
      │                       │  401 token_family_compromised
      │                       │
      │  Next request with v2 fails too ─────────►│
      │◄────────────────────── 401 ────────────── │  v2 was also revoked
      │                                            │
      │  ┌────────────────────────────────────┐
      │  │ Clear all tokens.                  │
      │  │ Show login screen.                 │
      │  │ Alert: "Session ended for          │
      │  │         security reasons"          │
      │  └────────────────────────────────────┘
      │
      ▼
```

---

## Concurrent Refresh Protection

Multiple in-flight requests hitting a 401 simultaneously must coordinate:

```
  Request A ────► 401 ──┐
  Request B ────► 401 ──┤
  Request C ────► 401 ──┤
                        ▼
                 ┌─── Mutex ───┐
                 │             │
                 │  Request A  │──► POST /auth/refresh ──► new tokens
                 │             │
                 │  Request B  │──► (mutex locked, wait...)
                 │  Request C  │──► (mutex locked, wait...)
                 │             │
                 │  A finishes │──► stores new access_token
                 │             │
                 │  Request B  │──► sees token changed, retries with new token
                 │  Request C  │──► sees token changed, retries with new token
                 │             │
                 └─────────────┘
```

Without this mutex, B and C would also call refresh, but only one refresh can
succeed — the others would get `invalid_refresh_token` because the token was
already rotated by A.

---

## App Startup Decision Tree

```
                        App Launch
                            │
                 ┌──────────┴──────────┐
                 │                     │
          Has refresh token?     No refresh token
                 │                     │
                 ▼                     ▼
          POST /auth/refresh     ┌──────────┐
                 │               │  Login    │
          ┌──────┴──────┐       │  Screen   │
          │             │       └──────────┘
       Success       Failed          │
          │          (401)           │
          ▼             │      Direct login?──── Yes ──► POST /api/v1/auth/login
    Store new tokens    │            │
    Proceed to app      │           No (OAuth)
                        │            │
                        ▼            ▼
                   ┌──────────┐   Redirect to
                   │  Login   │   /oauth/authorize
                   │  Screen  │   (PKCE flow)
                   └──────────┘
```

---

## Flow D: Client Credentials (service-to-service)

For backend services, cron jobs, and workers that need to call the Identity API (or other services that validate Identity JWTs) without any user involvement.

```
  Backend Service                               Identity Server
  ───────────────                               ───────────────
      │
      │  POST /oauth/token
      │  Authorization: Basic base64(client_id:client_secret)
      │  grant_type=client_credentials
      │  scope=read:users
      │ ──────────────────────────────────────────►│
      │                                            │  Verify client_id exists
      │                                            │  bcrypt-compare secret
      │                                            │  Check client has grant_type=client_credentials
      │                                            │  Validate scope ⊆ allowed scopes
      │                                            │  Mint JWT (15 min, RFC 9068 claims)
      │                                            │  Record audit event
      │◄────────────────────────────────────────── │
      │  { access_token, token_type: "Bearer",
      │    expires_in: 900, scope: "read:users" }
      │
      │  ┌──────────────────────────────────────┐
      │  │ Cache token in memory                │
      │  │ No refresh token — just re-auth      │
      │  └──────────────────────────────────────┘
      │
      │  GET /api/v1/users
      │  Authorization: Bearer <access_token>
      │ ──────────────────────────────────────────►│  Resource Server
      │                                            │  Verify JWT signature (via JWKS)
      │                                            │  Check exp
      │                                            │  Check aud matches this service
      │                                            │  Check scope includes required scope
      │◄────────────────────────────────────────── │
      │  200 OK
      │
      │  ⏰ Token expires after 15 minutes...
      │
      │  POST /oauth/token  (same request as above)
      │ ──────────────────────────────────────────►│
      │◄────────────────────────────────────────── │
      │  New access token
      ▼
```

**Key differences from user flows:**
- No browser, no redirect, no user interaction
- No refresh token — the client secret is the long-lived credential
- JWT claims use RFC 9068 format: `sub` = client_id, `client_id` (top-level), `aud`, `scope`, `jti`
- No `UserID`, `Username`, or `Role` in the JWT

**Token management in code:**
```go
// Simple pattern: authenticate, cache, re-authenticate on expiry
var (
    mu          sync.Mutex
    token       string
    tokenExpiry time.Time
)

func getToken(clientSecret string) (string, error) {
    mu.Lock()
    defer mu.Unlock()

    // Return cached token if still valid (with 60s buffer)
    if token != "" && time.Now().Before(tokenExpiry.Add(-60*time.Second)) {
        return token, nil
    }

    // Re-authenticate
    tok, err := authenticate(clientSecret, "read:users")
    if err != nil {
        return "", err
    }
    token = tok.AccessToken
    tokenExpiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
    return token, nil
}
```

**Discovery:** Clients can fetch `GET /.well-known/oauth-authorization-server` (RFC 8414) to find the token endpoint, JWKS URI, and supported grant types programmatically.

**Introspection:** Resource servers can call `POST /oauth/introspect` (RFC 7662) with client credentials to verify a token in real-time, useful for high-stakes operations where the 15-minute revocation window is too wide.

**Secret rotation:** Rotate the client secret via the admin UI at `/admin/oauth/{id}/edit`. During rotation, both old and new secrets are accepted. Clear the previous secret after all services have updated.

---

## Audit Trail

Every arrow labeled with an auth action above generates an audit event:

```
┌─────────────────────────────────────────────────────────────────────┐
│ TIME                EVENT                  USER    CLIENT    IP     │
├─────────────────────────────────────────────────────────────────────┤
│ 2026-03-17 14:00:01 ✓ login               alice   —         1.2.3.4│
│ 2026-03-17 14:15:02 ✓ oauth authorize     alice   myapp     1.2.3.4│
│ 2026-03-17 14:20:05 ✗ login failed        bob     —         5.6.7.8│
│ 2026-03-17 14:22:10 ⚠ token compromised   alice   —         9.0.1.2│
│ 2026-03-17 14:23:00 ✓ client_credentials  —       worker    3.4.5.6│
│ 2026-03-17 14:25:00   logout              alice   —         1.2.3.4│
└─────────────────────────────────────────────────────────────────────┘

Visible at /admin/audit. Filterable by user or event type.
```
