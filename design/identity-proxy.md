# Identity Proxy — Design Document

A self-hosted, identity-aware reverse proxy that sits in front of web services, authenticating users against the Identity service before forwarding requests. Inspired by Google's Identity-Aware Proxy (BeyondCorp) but purpose-built for Cloudflare Tunnel deployments on swee.net.

## Background: How Google IAP Works

Google's Identity-Aware Proxy is a core component of their BeyondCorp zero-trust architecture. The key insight is simple: **move authentication out of individual applications and into the infrastructure layer**.

### Architecture

```
Internet → Google Front End → IAP (auth check) → Backend Service
```

IAP is not a separate process — it's a layer inside Google's load balancer (the "Google Front End"). When you enable IAP on a GCP resource, the load balancer itself starts enforcing authentication before any request reaches your service.

### How It Works

1. **Unauthenticated request arrives** — IAP checks for a session cookie (`GCP_IAP_AUTH_TOKEN`). If missing or expired, it redirects the browser to Google's OAuth 2.0 login flow.

2. **User authenticates** — Google login completes, IAP receives an OAuth token, creates a session, and sets the `GCP_IAP_AUTH_TOKEN` cookie (encrypted, httponly, secure).

3. **Subsequent requests** — The cookie is present. IAP validates it, and if valid, forwards the request to the backend with identity headers:
   - `X-Goog-IAP-JWT-Assertion` — A signed JWT containing the user's email and subject ID
   - `X-Goog-Authenticated-User-Email` — `accounts.google.com:<email>`
   - `X-Goog-Authenticated-User-Id` — `accounts.google.com:<subject-id>`

4. **Backend trusts the headers** — The backend never sees unauthenticated traffic. It can optionally verify the JWT signature (Google publishes the public keys) for defense-in-depth, but the proxy already enforced auth.

### Session Model

- The `GCP_IAP_AUTH_TOKEN` cookie is an encrypted, opaque blob managed by IAP
- Session lifetime is configurable (default ~1 hour, max 24 hours)
- IAP handles refresh transparently — the user never sees a re-login unless the session fully expires
- AJAX requests get a 401 instead of a redirect (IAP detects `X-Requested-With: XMLHttpRequest`)

### Key Design Principles

- **Zero application changes** — The backend app doesn't need auth code at all. It just reads headers.
- **Central policy** — Access control (who can reach which service) is configured in one place, not per-app.
- **Cookie-based sessions** — The proxy manages its own session state via cookies. The user's browser holds the cookie; the proxy validates it on every request.

## Open-Source Alternatives

| Project | Architecture | Complexity | Notes |
|---------|-------------|------------|-------|
| **oauth2-proxy** | Standalone reverse proxy or nginx `auth_request` subrequest | Low | Simple, battle-tested, focused on OAuth2/OIDC. Most popular. |
| **Pomerium** | Full proxy with authenticate/authorize/databroker components | High | Enterprise zero-trust. Overkill for simple setups. |
| **Authelia** | Auth server + nginx `auth_request` | Medium | Full SSO server with 2FA. More than just a proxy. |
| **Ory Oathkeeper** | API gateway / decision API | High | Microservices-oriented, policy engine. |

For our use case — simple services behind Cloudflare Tunnels on a single Linux box — **oauth2-proxy's approach is closest** but we can do better by integrating directly with our own Identity service's OAuth flow rather than going through a generic OIDC layer.

## Our Design: `identity-proxy`

### What It Is

A single Go binary that acts as a reverse proxy. It sits between Cloudflare Tunnel and your backend services. For each incoming request, it checks for a valid session cookie. If present, it forwards the request with identity headers. If not, it redirects to the Identity service's OAuth authorize endpoint.

### Deployment Model

```
                                   ┌─────────────────────────────────────────┐
                                   │            Linux box (garibaldi)        │
                                   │                                        │
Internet ──► Cloudflare Tunnel ──► │  identity-proxy (:8080)                │
                                   │    │                                   │
                                   │    ├──► app-a (localhost:3000)         │
                                   │    ├──► app-b (localhost:3001)         │
                                   │    └──► app-c (localhost:3002)         │
                                   │                                        │
                                   │  identity-server (:8181)  ◄── OAuth ──┘
                                   └─────────────────────────────────────────┘
```

Cloudflare Tunnel currently points directly at each service. With identity-proxy, the tunnel points at the proxy instead, and the proxy forwards to the backend after auth.

**Multiple tunnels approach** (one subdomain per service):
- `app-a.swee.net` tunnel → `identity-proxy:8080` → route config says app-a → `localhost:3000`
- `app-b.swee.net` tunnel → `identity-proxy:8080` → route config says app-b → `localhost:3001`

The proxy uses the `Host` header (provided by Cloudflare Tunnel) to determine which backend to route to.

### Auth Flow

```
Browser                    identity-proxy              Identity Service
   │                            │                            │
   │── GET app-a.swee.net ─────►│                            │
   │                            │ no session cookie          │
   │                            │                            │
   │◄── 302 to identity ───────│                            │
   │    /oauth/authorize?                                   │
   │    client_id=proxy&                                    │
   │    redirect_uri=app-a.swee.net/__proxy/callback&       │
   │    code_challenge=...&                                 │
   │    state=<original_url>                                │
   │                                                        │
   │── GET /oauth/authorize ──────────────────────────────►│
   │                            │                           │ (login page)
   │◄── login page HTML ───────────────────────────────────│
   │                                                        │
   │── POST username/password ─────────────────────────────►│
   │                                                        │
   │◄── 302 to redirect_uri ──────────────────────────────│
   │    ?code=...&state=...                                │
   │                                                        │
   │── GET /__proxy/callback?code=...&state=... ──────────►│
   │                            │                           │
   │                            │── POST /oauth/token ─────►│
   │                            │   code + code_verifier    │
   │                            │                           │
   │                            │◄── access_token + ────────│
   │                            │    refresh_token          │
   │                            │                           │
   │◄── 302 to original_url ──│                            │
   │    Set-Cookie: __proxy_session=<encrypted>             │
   │                                                        │
   │── GET original_url ───────►│                           │
   │    Cookie: __proxy_session │ valid session             │
   │                            │                           │
   │                            │── GET backend ───────────►│ (app-a)
   │                            │   X-Identity-User: alice  │
   │                            │   X-Identity-Role: user   │
   │                            │   X-Identity-Email: ...   │
   │                            │                           │
   │◄── response ──────────────│                            │
```

### Session Cookie Design

The proxy manages its own session. It does NOT pass the JWT to the browser.

**Cookie: `__proxy_session`**

Contents (encrypted with AES-256-GCM, using a server-side key):
```json
{
  "user_id": "uuid",
  "username": "alice",
  "role": "admin",
  "email": "alice@example.com",
  "access_token": "<jwt>",
  "refresh_token": "<opaque>",
  "access_token_exp": 1700000900,
  "issued_at": 1700000000
}
```

**Properties:**
- `HttpOnly`, `Secure`, `SameSite=Lax`
- `Path=/`
- `Domain` set per-route (e.g., `.swee.net` for shared sessions, or per-subdomain)
- Max session lifetime: configurable (e.g., 24 hours) — after this, user must re-login regardless of refresh token validity

**Why encrypt rather than just sign?** The cookie contains the access_token and refresh_token. These must not leak to client-side JavaScript or be visible in browser devtools. Encryption keeps them opaque.

### Token Lifecycle Within the Proxy

1. **On callback**: Exchange auth code for tokens. Store both in the encrypted session cookie.
2. **On each request**: Decrypt cookie, check `access_token_exp`.
   - If access token has >60s remaining: use it as-is.
   - If access token has <60s remaining or is expired: call `POST /oauth/token` with `grant_type=refresh_token` to get new tokens. Update the cookie with the new tokens. (Set-Cookie on the response.)
3. **On refresh failure** (`token_family_compromised`, `invalid_refresh_token`): Clear the cookie, redirect to login.
4. **On session expiry** (max lifetime exceeded): Clear the cookie, redirect to login.

The backend never deals with tokens. It just sees headers.

### Headers Passed to Backend

| Header | Value | Example |
|--------|-------|---------|
| `X-Identity-User-Id` | User UUID from JWT `sub` claim | `550e8400-e29b-41d4-a716-446655440000` |
| `X-Identity-Username` | Username from JWT `usr` claim | `alice` |
| `X-Identity-Role` | Role from JWT `rol` claim | `admin` |
| `X-Identity-Token` | The raw JWT (for backends that want to verify) | `eyJhbGci...` |

The proxy also strips these headers from incoming requests to prevent spoofing.

### Configuration

Single YAML file:

```yaml
# identity-proxy.yaml

# Identity service to authenticate against
identity_url: "http://localhost:8181"

# OAuth client (registered in Identity service)
oauth_client_id: "identity-proxy"

# Encryption key for session cookies (32 bytes, base64)
# Generate with: openssl rand -base64 32
session_secret: "base64-encoded-32-byte-key"

# Session lifetime (even if refresh token is still valid)
session_max_age: "24h"

# Cookie domain (optional, defaults to request host)
# cookie_domain: ".swee.net"

# Routes: Host header → backend
routes:
  "app-a.swee.net":
    upstream: "http://localhost:3000"
    # Optional: restrict to specific roles
    # allowed_roles: ["admin"]

  "app-b.swee.net":
    upstream: "http://localhost:3001"

  "app-c.swee.net":
    upstream: "http://localhost:3002"
    allowed_roles: ["admin", "user"]

  # Default route if no host matches (optional)
  # "*":
  #   upstream: "http://localhost:4000"

# Listen address
listen: ":8080"

# Optional: paths that skip auth (e.g., health checks)
public_paths:
  - "/__proxy/health"
  - "/favicon.ico"
```

### Callback Path

The proxy reserves `/__proxy/callback` on every route's domain for the OAuth callback. This path is handled internally by the proxy — it never reaches the backend.

When registering the OAuth client in the Identity service, you register all callback URIs:
```
https://app-a.swee.net/__proxy/callback
https://app-b.swee.net/__proxy/callback
https://app-c.swee.net/__proxy/callback
```

### Cloudflare Tunnel Integration

Each service currently has its own tunnel config pointing directly at the backend. With the proxy, you change the tunnel target:

**Before:**
```yaml
# cloudflared config
ingress:
  - hostname: app-a.swee.net
    service: http://localhost:3000
  - hostname: app-b.swee.net
    service: http://localhost:3001
```

**After:**
```yaml
ingress:
  - hostname: app-a.swee.net
    service: http://localhost:8080
  - hostname: app-b.swee.net
    service: http://localhost:8080
```

The proxy handles routing based on `Host` header. The Identity service itself (`identity.swee.net`) should NOT go through the proxy — it handles its own auth.

### Trust Model

Since Cloudflare Tunnel terminates TLS and forwards to localhost, the proxy runs on plain HTTP. This is fine because:
- All external traffic is HTTPS (Cloudflare handles TLS)
- The proxy ↔ backend communication is localhost-only
- The session cookie has `Secure` flag (Cloudflare sets the scheme header)

The proxy should trust `CF-Connecting-IP` for client IP (same as the Identity service with `TRUST_PROXY=cloudflare`).

## Implementation Plan

### Package Structure

```
identity-proxy/
├── cmd/
│   └── identity-proxy/
│       └── main.go              # Entry point, load config, start server
├── internal/
│   ├── config/
│   │   └── config.go            # YAML config parsing
│   ├── proxy/
│   │   ├── proxy.go             # Core reverse proxy + routing
│   │   ├── session.go           # Cookie encryption/decryption
│   │   ├── oauth.go             # OAuth flow (redirect, callback, PKCE)
│   │   └── refresh.go           # Token refresh logic
│   └── middleware/
│       └── middleware.go         # Auth check, header injection, header stripping
├── go.mod
├── go.sum
├── identity-proxy.example.yaml  # Example config
├── Makefile
└── README.md
```

### Dependencies

Minimal — Go stdlib where possible:
- `net/http/httputil.ReverseProxy` — the actual proxying
- `crypto/aes` + `crypto/cipher` — session cookie encryption (stdlib)
- `gopkg.in/yaml.v3` — config file parsing
- `github.com/golang-jwt/jwt/v5` — JWT parsing (to extract claims, NOT to verify — the Identity service already verified when it issued the token, and the proxy trusts the Identity service)

Actually, the proxy should **verify** the JWT signature to confirm the Identity service issued it. This requires knowing the JWT secret or having a JWKS endpoint. Two options:

1. **Shared secret** — The proxy knows the Identity service's JWT secret and verifies HS256 signatures directly. Simple but requires secret distribution.
2. **Trust the token exchange** — The proxy got the token from `/oauth/token` over localhost. It trusts that response. It only parses the JWT to extract claims (without signature verification). The session cookie's encryption is the trust boundary.

**Recommendation: Option 2.** The proxy received the token directly from the Identity service over a trusted localhost connection. Re-verifying the signature adds complexity for no security gain. The encrypted session cookie is the proxy's own trust boundary. If someone can tamper with localhost traffic between the proxy and the Identity service, you have bigger problems.

### Build & Deploy

```makefile
# Makefile
build:
	go build -o bin/identity-proxy ./cmd/identity-proxy

deploy:
	# Same pattern as identity-server: scp binary, symlink, restart
	./deploy/deploy.sh sweeney@garibaldi
```

### Systemd Unit

```ini
[Unit]
Description=Identity Proxy
After=network.target identity.service
Wants=identity.service

[Service]
Type=simple
ExecStart=/opt/identity-proxy/bin/identity-proxy --config /opt/identity-proxy/identity-proxy.yaml
Restart=always
RestartSec=5
User=sweeney

[Install]
WantedBy=multi-user.target
```

## Key Design Decisions

### 1. Separate binary, separate repo

The proxy is a distinct concern from the Identity service. It should be its own Go module in its own repo. It depends on the Identity service's HTTP API only — no shared Go packages.

### 2. Server-side sessions via encrypted cookies (no database)

Like Google IAP's `GCP_IAP_AUTH_TOKEN`, the session state lives entirely in the cookie. No session database, no Redis, no shared state. This means:
- Horizontally scalable (not relevant now, but free)
- No cleanup/GC of expired sessions
- Cookie size is the only limit (~500 bytes encrypted, well under the 4KB cookie limit)

### 3. PKCE for the OAuth flow

The Identity service requires PKCE (S256). The proxy generates a `code_verifier` per auth flow and stores it temporarily. Since the OAuth flow is synchronous (redirect → login → callback), the verifier can be stored in a short-lived cookie (`__proxy_pkce`, encrypted, 5-minute expiry) or in the `state` parameter (encrypted).

**Recommendation: Store in a separate cookie.** The `state` parameter should remain a simple HMAC'd value containing the original URL. Stuffing the PKCE verifier into state makes it unwieldy. A separate short-lived cookie is clean.

### 4. AJAX/API handling

For XHR/fetch requests (detected by `Accept: application/json` or `X-Requested-With: XMLHttpRequest`), return `401 {"error": "unauthenticated"}` instead of a 302 redirect. This lets SPAs handle re-auth gracefully.

### 5. WebSocket support

`httputil.ReverseProxy` handles WebSocket upgrades automatically (Go 1.12+). The auth check happens on the initial HTTP upgrade request, which carries the session cookie. Once upgraded, the connection is proxied directly.

### 6. No per-user access lists (yet)

Start simple: if a user has a valid account on the Identity service, they can access any proxied service (subject to `allowed_roles` in the route config). Per-user access lists can be added later if needed.

## What the Backend Services Need to Do

**Nothing.** That's the whole point.

But if they want to know who's making the request, they read the `X-Identity-*` headers. A simple Go middleware:

```go
func IdentityFromProxy(r *http.Request) (userID, username, role string) {
    return r.Header.Get("X-Identity-User-Id"),
           r.Header.Get("X-Identity-Username"),
           r.Header.Get("X-Identity-Role")
}
```

## Future Extensions

- **Per-user access control**: An `access` table in the Identity service mapping users to allowed services
- **Logout propagation**: A `/__proxy/logout` endpoint that clears the session cookie and redirects to the Identity service's logout
- **Session listing**: Admin can see active proxy sessions
- **Metrics**: Request counts, auth redirects, refresh counts per route
- **JWKS endpoint on Identity service**: For environments where shared secrets aren't viable
