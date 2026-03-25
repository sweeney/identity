# Example OAuth Clients

Four demo apps showing different ways to integrate with the Identity service.

The first three implement the Authorization Code + PKCE flow — the difference is where the tokens end up. The fourth demonstrates service-to-service auth using Client Credentials.

## Running the demos

Start the Identity server:

```bash
JWT_SECRET="<32+ chars>" ADMIN_USERNAME=admin ADMIN_PASSWORD=adminpassword1 \
  ./bin/identity-server
```

Register each demo as an OAuth client at `/admin/oauth/new`:

| Demo | Client ID | Grant Type | Redirect URI |
|------|-----------|------------|-------------|
| Server-side | `demo` | authorization_code | `http://localhost:9090/callback` |
| SPA | `spa-demo` | authorization_code | `http://localhost:9091/` |
| BFF | `bff-demo` | authorization_code | `http://localhost:9092/callback` |
| Client Credentials | `worker` | client_credentials | (none) |

For the Client Credentials demo, also generate a client secret on the edit page, set scopes to `read:users`, audience to `http://localhost:8181`, and auth method to `client_secret_basic`.

Then start whichever demo you want:

```bash
go run ./examples/server-side-demo                          # http://localhost:9090
go run ./examples/spa-demo                                  # http://localhost:9091
go run ./examples/bff-demo                                  # http://localhost:9092
CLIENT_SECRET=<secret> go run ./examples/client-credentials-demo  # runs once, prints output
```

---

## The four approaches

### 1. Server-side (single user)

**`examples/server-side-demo`** — Go backend renders HTML, holds tokens in a Go variable.

```
Browser ──GET /──► Go server ──Bearer token──► Identity API
                   (tokens in RAM)
```

**How it works**: The Go server performs the entire OAuth flow server-side. Tokens are stored in a Go variable. Pages are server-rendered — the browser never sees a token.

**Token storage**: Go variable (in-process memory).

**Good for**: Quick prototypes, CLI tools with a browser callback, single-user apps.

**Limitations**: Single user (one global variable), state lost on restart, no session management.

---

### 2. SPA (JavaScript + localStorage)

**`examples/spa-demo`** — Pure client-side JavaScript. No backend logic. Tokens in localStorage.

```
Browser ──fetch()──► Identity API
(tokens in localStorage)
```

**How it works**: A static HTML page with JavaScript handles the entire OAuth flow. PKCE verifier and state are generated in the browser using the Web Crypto API. After the redirect, JavaScript exchanges the code for tokens via `fetch()` and stores them in `localStorage`.

**Token storage**: `localStorage` (persists across tabs and page reloads).

**Good for**: Native mobile apps (using secure storage instead of localStorage), desktop apps (Electron/Tauri), internal tools with low threat models.

**Limitations**: `localStorage` is accessible to any JavaScript running on the page. A single XSS vulnerability means an attacker can steal tokens. There is no way to make a refresh token truly secret in the browser.

---

### 3. BFF — Backend-for-Frontend (recommended for web apps)

**`examples/bff-demo`** — Go backend holds tokens server-side. Browser gets an HttpOnly session cookie.

```
Browser ──cookie──► BFF server ──Bearer token──► Identity API
                    (tokens in session store)
```

**How it works**: The BFF performs the OAuth token exchange server-to-server — the browser never sees the authorization code response or the tokens. The browser receives an HttpOnly, Secure session cookie containing a random session ID. When the browser makes API calls, they go to the BFF, which looks up the session, attaches the access token, and proxies the request to the Identity server.

**Token storage**: Server-side session map (in-memory in the demo; use SQLite/Redis in production).

**Good for**: Any web application where security matters. This is the recommended approach.

**Why it's more secure**:
- Tokens are invisible to JavaScript (HttpOnly cookie)
- XSS cannot steal tokens — the worst an attacker can do is make requests within the user's session, which is still bad but far less damaging than exfiltrating a long-lived refresh token
- The BFF can add its own rate limiting, logging, and validation before proxying
- Token refresh happens transparently on the server

---

### 4. Client Credentials (service-to-service)

**`examples/client-credentials-demo`** — Go CLI that authenticates as a service, not a user.

```
Service ──POST /oauth/token──► Identity Server
          (client_id + secret)
          ◄── access_token (JWT, 15 min)
```

**How it works**: The service sends its `client_id` and `client_secret` to the token endpoint using HTTP Basic auth. It receives a short-lived JWT with `client_id`, `aud`, `scope`, and `jti` claims (RFC 9068). No user, no browser, no redirect.

**Token storage**: In-memory variable. Re-authenticate when expired.

**Good for**: Cron jobs, microservices, background workers, any server-side process that needs to call a protected API.

**Key differences from user flows**: No refresh token (the secret _is_ the long-lived credential). JWT claims identify the service, not a user. Resource servers check `scope` and `aud` instead of `role`.

---

## Other integration styles

These aren't demoed above but are worth knowing about:

### Native mobile apps

Use the SPA approach but with platform-secure storage instead of localStorage:

- **iOS**: Store refresh tokens in Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). Hold access tokens in memory only.
- **Android**: Store refresh tokens in `EncryptedSharedPreferences` via Jetpack Security. Hold access tokens in memory only.
- Use `ASWebAuthenticationSession` (iOS) or Chrome Custom Tabs (Android) for the OAuth redirect — never embed a WebView.

See `docs/api.md` for Swift and Kotlin code examples.

### Server-to-server (machine clients)

Use the **Client Credentials** flow (see `examples/client-credentials-demo`):

- Register an OAuth client with `client_credentials` grant type and generate a secret
- `POST /oauth/token` with `grant_type=client_credentials` + HTTP Basic auth
- Receive a short-lived JWT (15 min) — no refresh token, just re-authenticate
- Use `RequireScope` and `RequireAudience` middleware on receiving services to validate tokens

This is the OAuth 2.0 standard for machine-to-machine auth (RFC 6749 §4.4).

### Multi-page server-rendered apps (Rails, Django, etc.)

Use the BFF pattern. Your web framework is the BFF:

1. `/login` redirects to Identity's `/oauth/authorize`
2. `/callback` exchanges the code server-side
3. Store tokens in your framework's session (which is typically a signed cookie pointing to server-side storage)
4. Middleware attaches the access token when calling the Identity API
5. Middleware handles automatic refresh when tokens expire

### Reverse proxy with auth (Nginx, Caddy, Traefik)

If you don't want to modify your app at all:

1. Put a forward-auth middleware in front of your app
2. The middleware checks for a valid session cookie
3. If missing, redirect to Identity's OAuth flow
4. On callback, store tokens in the middleware's session
5. On each request, set `X-User-ID` and `X-User-Role` headers before proxying to your app

This is what projects like OAuth2-Proxy and Authelia do. It's the right choice if you have existing apps that can't be modified.

---

## Which should I use?

| Scenario | Approach |
|----------|----------|
| Web app (any framework) | **BFF** |
| React/Vue/Angular SPA | **BFF** (add a lightweight API proxy) |
| iOS / Android app | **SPA pattern** with Keychain / EncryptedSharedPreferences |
| Electron / Tauri desktop app | **SPA pattern** with OS keychain |
| CLI tool | **Server-side** (temporary localhost callback) |
| Quick prototype | **Server-side** |
| Existing app behind a reverse proxy | **Forward-auth middleware** |
| Server-to-server / microservices | **Client Credentials** |

When in doubt, use the BFF pattern. It's more code, but it's the only approach where a frontend vulnerability can't directly compromise user tokens.
