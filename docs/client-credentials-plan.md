# Client Credentials Flow — Implementation Plan

## Overview

Add OAuth 2.0 Client Credentials grant (RFC 6749 §4.4) for service-to-service authentication. A service authenticates with `client_id` + `client_secret`, receives a JWT access token, and uses it to call protected APIs. No user involvement, no refresh tokens.

## Standards

| RFC | What it covers | How we use it |
|-----|---------------|---------------|
| [RFC 6749 §4.4](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4) | Client Credentials grant | Core flow |
| [RFC 6749 §2.3](https://datatracker.ietf.org/doc/html/rfc6749#section-2.3) | Client authentication | `client_secret_basic` and `client_secret_post` |
| [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068) | JWT Profile for Access Tokens | JWT claim structure |
| [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) | Authorization Server Metadata | Discovery endpoint |
| [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) | Token Introspection | Real-time revocation checks |

## Flow

```
  Service                          Identity Server
    │                                     │
    │  POST /oauth/token                  │
    │  Authorization: Basic base64(id:secret)
    │  grant_type=client_credentials      │
    │  scope=read:users                   │
    │─────────────────────────────────────►│
    │                                     │ ── verify client_id exists
    │                                     │ ── verify secret against bcrypt hash
    │                                     │ ── check client has grant_type=client_credentials
    │                                     │ ── validate requested scopes ⊆ allowed scopes
    │                                     │ ── mint JWT
    │  {                                  │
    │    "access_token": "eyJ...",        │
    │    "token_type": "Bearer",          │
    │    "expires_in": 900,               │
    │    "scope": "read:users"            │
    │  }                                  │
    │◄─────────────────────────────────────│
    │                                     │
    │  GET /api/v1/users                  │
    │  Authorization: Bearer eyJ...       │
    │─────────────────────────────────────►│ Resource Server
    │                                     │ ── verify JWT signature
    │                                     │ ── check exp
    │                                     │ ── check aud matches this service
    │                                     │ ── check scope includes required scope
    │  200 OK                             │
    │◄─────────────────────────────────────│
```

No refresh tokens — when the access token expires (15 minutes), the service re-authenticates with the same credentials.

## JWT Claims (RFC 9068)

```json
{
  "iss": "https://id.example.com",
  "sub": "my-service",
  "client_id": "my-service",
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "aud": "https://api.example.com",
  "scope": "read:users write:users",
  "iat": 1711393200,
  "exp": 1711396800
}
```

- `sub` = `client_id` (no prefix convention, per RFC 9068 §4)
- `client_id` is a top-level claim (distinguishes service tokens from user tokens)
- `jti` is a UUID — enables revocation lists
- `aud` is required — resource servers MUST reject tokens where their identifier is not in `aud`
- `scope` is space-delimited (per RFC 6749 §3.3)
- No `UserID`, `Username`, or `Role` claims

## Implementation Steps

### Step 1: Database migration

New migration `00N_client_credentials.sql`:

```sql
ALTER TABLE oauth_clients ADD COLUMN client_secret_hash TEXT;
ALTER TABLE oauth_clients ADD COLUMN client_secret_hash_prev TEXT;
ALTER TABLE oauth_clients ADD COLUMN grant_types TEXT NOT NULL DEFAULT '["authorization_code"]';
ALTER TABLE oauth_clients ADD COLUMN scopes TEXT NOT NULL DEFAULT '[]';
ALTER TABLE oauth_clients ADD COLUMN token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none';
ALTER TABLE oauth_clients ADD COLUMN audience TEXT NOT NULL DEFAULT '';
```

- `client_secret_hash` — bcrypt, nullable (PKCE-only clients don't need one)
- `client_secret_hash_prev` — supports secret rotation (accept either, clear prev when ready)
- `grant_types` — JSON array: `["authorization_code"]`, `["client_credentials"]`, or both
- `scopes` — JSON array of scopes the client is allowed to request
- `token_endpoint_auth_method` — `none` (public/PKCE), `client_secret_basic`, `client_secret_post`
- `audience` — the `aud` value to embed in tokens issued for this client

### Step 2: Domain model

Extend `OAuthClient` in `internal/domain/oauth.go`:

```go
type OAuthClient struct {
    ID                      string
    Name                    string
    RedirectURIs            []string
    SecretHash              string   // bcrypt
    SecretHashPrev          string   // for rotation
    GrantTypes              []string // "authorization_code", "client_credentials"
    Scopes                  []string // allowed scopes
    TokenEndpointAuthMethod string   // "none", "client_secret_basic", "client_secret_post"
    Audience                string   // aud claim for issued tokens
    CreatedAt               time.Time
    UpdatedAt               time.Time
}
```

### Step 3: Client authentication

New file `internal/handler/oauth/client_auth.go`:

- Parse `Authorization: Basic base64(client_id:client_secret)` → `(id, secret, ok)`
- Fall back to form body `client_id` + `client_secret`
- Match against client's declared `token_endpoint_auth_method`
- Verify secret with `bcrypt.CompareHashAndPassword` (try current hash, then prev hash)

### Step 4: Token endpoint — `client_credentials` grant

Add `case "client_credentials"` to the switch in `handler.go`:

1. Authenticate client (step 3)
2. Verify `"client_credentials"` is in client's `grant_types`
3. Parse requested `scope`, verify it's a subset of client's allowed `scopes`
4. Mint JWT with RFC 9068 claims (new `MintServiceToken` method on `TokenIssuer`)
5. Return `{ access_token, token_type: "Bearer", expires_in, scope }` — no `refresh_token`
6. Log audit event `auth_event_client_credentials`

### Step 5: Service token JWT minting

New method in `internal/auth/jwt.go`:

```go
type ServiceTokenClaims struct {
    ClientID string
    Audience string
    Scope    string
    JTI      string  // uuid.New()
}

func (ti *TokenIssuer) MintServiceToken(claims ServiceTokenClaims, ttl time.Duration) (string, error)
```

Default TTL: 15 minutes (matches user access token TTL).

### Step 6: Middleware update

In `internal/auth/middleware.go`:

- `RequireAuth` — when parsing the JWT, check for `client_id` claim. If present and no user-associated `sub`, populate `ServiceClaims` in the request context instead of `UserClaims`.
- New `RequireScope(scope string)` middleware — checks that the token's `scope` claim includes the required scope. Works for both service and user tokens.
- Existing `RequireAdmin` continues to work for user tokens; service tokens with appropriate scopes bypass it via `RequireScope`.

### Step 7: Admin UI

Extend `/admin/oauth` client form:

- **Client type toggle**: "Public (PKCE)" vs "Confidential (with secret)"
- **Secret display**: Show secret once on creation, never again. "Regenerate" button.
- **Grant types**: Checkboxes for `authorization_code` and `client_credentials`
- **Scopes**: Text area (one per line)
- **Audience**: Text input
- Validation: `client_credentials` requires a secret; `authorization_code` without a secret requires redirect URIs (PKCE)

### Step 8: Secret rotation

- Admin clicks "Rotate secret" → current hash moves to `prev`, new secret generated
- Both are accepted during verification
- "Clear previous secret" button to complete rotation
- No downtime — services update their config, then admin clears prev

### Step 9: Discovery endpoint (RFC 8414)

New handler for `GET /.well-known/oauth-authorization-server`:

```json
{
  "issuer": "https://id.example.com",
  "token_endpoint": "https://id.example.com/oauth/token",
  "authorization_endpoint": "https://id.example.com/oauth/authorize",
  "jwks_uri": "https://id.example.com/.well-known/jwks.json",
  "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "response_types_supported": ["code"],
  "scopes_supported": ["read:users", "write:users"],
  "code_challenge_methods_supported": ["S256"]
}
```

### Step 10: Token introspection (RFC 7662)

New endpoint `POST /oauth/introspect`:

- Authenticated by client credentials (the resource server calling introspect is itself a client)
- Returns `{"active": true, "sub": "...", "client_id": "...", "scope": "...", "exp": ...}` or `{"active": false}`
- Optional — resource servers can use this for high-stakes operations instead of pure local JWT validation

## Testing

### Unit tests

**`internal/auth/jwt_test.go`** — Service token minting:
- Mint a service token → parse it → verify all RFC 9068 claims present (`iss`, `sub`, `client_id`, `jti`, `aud`, `scope`, `iat`, `exp`)
- Mint with empty scope → `scope` claim absent
- Mint with empty audience → error (aud is required)
- `jti` is unique across two mints
- Expired service token → parse fails
- Service token doesn't contain `UserID`, `Username`, or `Role`

**`internal/auth/middleware_test.go`** — Scope and service token middleware:
- `RequireAuth` with a valid service token → `ServiceClaims` in context (not `UserClaims`)
- `RequireAuth` with a valid user token → `UserClaims` in context (unchanged behavior)
- `RequireScope("read:users")` with token containing `"read:users write:users"` → pass
- `RequireScope("write:users")` with token containing `"read:users"` → 403
- `RequireScope` with user token that has no scope claim → 403
- `RequireAdmin` still works for user tokens (regression)

**`internal/handler/oauth/client_auth_test.go`** — Client authentication:
- Valid Basic auth header → extracts client_id and secret
- Malformed Basic header (bad base64, no colon, empty parts) → error
- Form body `client_id` + `client_secret` → extracts both
- Client declares `client_secret_basic` but credentials sent via form → reject
- Client declares `token_endpoint_auth_method=none` but secret sent → reject
- Secret matches current hash → ok
- Secret matches prev hash (rotation in progress) → ok
- Secret matches neither → error

**`internal/handler/oauth/handler_test.go`** — Token endpoint:
- `grant_type=client_credentials` with valid client + secret → 200, access token, no `refresh_token` in response
- `grant_type=client_credentials` with bad secret → 401 `invalid_client`
- `grant_type=client_credentials` with client that only has `["authorization_code"]` → 400 `unauthorized_client`
- `grant_type=client_credentials` requesting scope not in client's allowed list → 400 `invalid_scope`
- `grant_type=client_credentials` requesting subset of allowed scopes → 200, token's scope matches request
- `grant_type=client_credentials` with no scope param → 200, token gets client's full allowed scopes
- `grant_type=client_credentials` with `token_endpoint_auth_method=none` client → 401 (can't authenticate)
- Update existing `unsupported_grant_type` test (currently checks client_credentials is rejected — flip it)

**`internal/service/oauth_service_test.go`** — Service layer:
- `IssueClientCredentials` with valid client → returns access token
- `IssueClientCredentials` with disabled client → error (if we add client disable)
- Scope validation: requested ⊆ allowed → ok; requested ⊄ allowed → `ErrInvalidScope`
- Audit event emitted with type `auth_event_client_credentials`

**`internal/store/oauth_store_integration_test.go`** — Persistence:
- Create client with secret hash, grant types, scopes → read back → all fields match
- Update client secret (rotation) → prev hash set → both verifiable
- Clear prev hash → only current works
- Default grant_types for existing clients after migration → `["authorization_code"]`

### Integration tests (Go)

**`internal/integration/e2e_oauth_test.go`** — Full flow against real SQLite:
- Create confidential client → call `/oauth/token` with `grant_type=client_credentials` → receive JWT → decode and verify all claims
- Use the issued JWT to call a protected endpoint with `RequireScope` → 200
- Use the issued JWT against a different-audience endpoint → 403
- Use an expired JWT → 401
- Rotate client secret → old secret fails, new secret works, prev secret works until cleared

### E2E script

**`scripts/e2e-client-credentials.sh`** — curl-based, matches existing e2e.sh style:

```
=== 1. Create confidential OAuth client (admin UI) ===
  ✓ POST /admin/oauth/new with secret = 303
  ✓ Client secret returned in response

=== 2. Client credentials token request ===
  ✓ POST /oauth/token grant_type=client_credentials = 200
  ✓ Response has access_token
  ✓ Response has no refresh_token
  ✓ Response has expires_in
  ✓ Response has scope

=== 3. JWT claims validation ===
  ✓ Token has iss claim
  ✓ Token has sub = client_id
  ✓ Token has client_id claim
  ✓ Token has jti claim
  ✓ Token has aud claim
  ✓ Token has scope claim (space-delimited)
  ✓ Token does NOT have UserID/Username/Role

=== 4. Client authentication methods ===
  ✓ client_secret_basic (Authorization: Basic) = 200
  ✓ client_secret_post (form body) = 200
  ✓ Wrong secret = 401
  ✓ No secret = 401
  ✓ Unknown client_id = 401

=== 5. Scope validation ===
  ✓ Request allowed scope = 200
  ✓ Request disallowed scope = 400 invalid_scope
  ✓ Request subset of allowed scopes = 200

=== 6. Grant type enforcement ===
  ✓ Client without client_credentials grant type = 400 unauthorized_client

=== 7. Use token against protected endpoint ===
  ✓ Bearer token on scoped endpoint = 200
  ✓ Bearer token missing required scope = 403
  ✓ Expired token = 401

=== 8. Secret rotation ===
  ✓ Rotate secret via admin = 303
  ✓ New secret works = 200
  ✓ Old secret still works (prev hash) = 200
  ✓ Clear prev secret via admin = 303
  ✓ Old secret now fails = 401

=== 9. Discovery endpoint ===
  ✓ GET /.well-known/oauth-authorization-server = 200
  ✓ Response has token_endpoint
  ✓ Response has grant_types_supported containing client_credentials
  ✓ Response has jwks_uri

=== 10. Introspection ===
  ✓ POST /oauth/introspect with valid token = 200, active=true
  ✓ POST /oauth/introspect with expired token = 200, active=false
  ✓ POST /oauth/introspect without client auth = 401
```

### Negative / security tests (across all layers)

- Timing-safe comparison: secret verification uses bcrypt (inherently constant-time)
- Client secret never logged in audit events (only client_id)
- Client secret never returned from GET endpoints (only shown once on creation)
- Token with forged `client_id` claim but valid signature → `client_id` must match `sub`
- Token with `aud` not matching resource server → rejected by `RequireScope`/`RequireAudience`
- SQL injection in scope parameter → parameterized queries prevent it
- Extremely long scope string → bounded by client's allowed scopes

## File Changes Summary

| File | Change |
|------|--------|
| `internal/db/migrations/00N_client_credentials.sql` | New migration |
| `internal/domain/oauth.go` | Extend `OAuthClient`, add `ServiceTokenClaims` |
| `internal/store/oauth_client_store.go` | Persist new fields |
| `internal/auth/jwt.go` | Add `MintServiceToken` |
| `internal/auth/middleware.go` | Add `ServiceClaims` context, `RequireScope` |
| `internal/handler/oauth/client_auth.go` | New: client authentication |
| `internal/handler/oauth/handler.go` | Add `client_credentials` case, introspection |
| `internal/handler/oauth/router.go` | Add introspect route, discovery route |
| `internal/service/oauth_service.go` | Add `IssueClientCredentials` |
| `internal/service/interfaces.go` | Extend `OAuthServicer` |
| `internal/service/errors.go` | Add `ErrInvalidScope`, `ErrUnauthorizedClient` |
| `internal/handler/admin/handler.go` | Extend client form |
| `internal/ui/templates/oauth_client_form.html` | Secret, grant types, scopes UI |
| `internal/spec/openapi.yaml` | Document new endpoints and grant type |
| `scripts/e2e-client-credentials.sh` | New E2E test script |

## Decisions

1. **Scope naming** — `resource:action` (e.g., `read:users`, `write:orders`) to match existing colon patterns.
2. **Service token TTL** — 15 minutes default, same as user access tokens.
3. **Introspection access** — any authenticated client can introspect. Simple, sufficient at current scale. Can gate behind an `introspect` scope later if needed.
