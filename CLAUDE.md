# Identity Service

A self-hosted JWT authentication and identity management service. Single Go binary, SQLite database, exposed via Cloudflare Tunnel (always HTTPS in production).

## What it does

Provides user accounts, JWT-based sessions, OAuth 2.0 authorization code flow with PKCE, and passkey/WebAuthn authentication for web and mobile apps. An admin manages users, OAuth clients, and passkeys via a web UI or API. Apps authenticate users (by password or passkey), receive tokens, and use those tokens to call the Identity API or other protected services.

## Getting the full API spec

```bash
GET /openapi.json   # OpenAPI 3.0 spec as JSON
GET /openapi.yaml   # OpenAPI 3.0 spec as YAML
```

Human-readable guides are in `docs/`:
- `docs/api.md` — integration guide with Swift/Kotlin examples and error reference
- `docs/api-walkthrough.md` — executable walkthrough showing every endpoint with real output
- `docs/auth-flows.md` — ASCII art diagrams of all auth flows
- `docs/passkeys.md` — passkey/WebAuthn setup, API reference, and integration guide
- `docs/r2-backup.md` — R2 backup setup and restore procedures

## Auth flow (direct API)

1. `POST /api/v1/auth/login` → receive `access_token` (JWT, 15 min) + `refresh_token` (opaque, 30-day sliding)
2. Send `Authorization: Bearer <access_token>` on every request
3. When access token has <60s remaining, call `POST /api/v1/auth/refresh` with the refresh token → receive a new pair
4. **Always persist the new refresh token immediately** — the old one is invalidated the moment refresh is called
5. On logout: `POST /api/v1/auth/logout` with the refresh token (or omit it to sign out all devices)

## OAuth 2.0 flow (PKCE)

1. Register an OAuth client at `/admin/oauth`
2. App redirects to `GET /oauth/authorize` with `client_id`, `redirect_uri`, `code_challenge` (S256), `state`
3. User logs in on the Identity server
4. Server redirects back with `?code=...&state=...`
5. App exchanges code at `POST /oauth/token` with `code_verifier` → receive tokens
6. Refresh via `POST /oauth/token` with `grant_type=refresh_token`

## Passkey / WebAuthn flow

Passkeys let users sign in with biometrics (Touch ID, Face ID, Windows Hello) instead of a password.

1. User logs in with password, registers a passkey at `/admin/passkeys` (or is prompted after login)
2. Next login: `POST /api/v1/webauthn/login/begin` → receive challenge
3. Browser calls `navigator.credentials.get()` → user touches biometric
4. `POST /api/v1/webauthn/login/finish?challenge_id=...` with the assertion → receive `access_token` + `refresh_token`
5. Tokens work identically to password-based login — same refresh, same rotation, same theft detection

Passkeys also work on the server-rendered login pages (admin UI and OAuth authorize). The login page shows a "Sign in with passkey" button when the browser supports WebAuthn. After a password login, users without passkeys are prompted to register one.

See `docs/passkeys.md` for full API reference and integration guide.

## Token rotation and theft detection

Every refresh rotates the token: old token is revoked, new pair issued. If a **previously-used** refresh token is ever presented again, the server assumes the token was stolen. It revokes the **entire token family** and returns `token_family_compromised`. The client must clear all tokens and show the login screen.

## Role model

- `admin` — full access to all endpoints including user management and admin UI
- `user` — can call `/auth/*` and `GET /users/{own-id}` only

## Error envelope

All API errors return the same shape (`/oauth/token` uses RFC 6749 format instead):

```json
{ "error": "snake_case_code", "message": "Human readable" }
```

Key error codes: `invalid_credentials`, `token_family_compromised`, `token_expired`, `invalid_refresh_token`, `account_disabled`, `forbidden`, `unknown_client`, `invalid_redirect_uri`, `invalid_auth_code`, `pkce_verification_failed`, `webauthn_not_enabled`, `webauthn_invalid_challenge`, `webauthn_verification_failed`, `webauthn_no_credentials`, `webauthn_credential_not_found`

## Running locally

```bash
# Zero config — generates JWT secret and admin password on first run
./bin/identity-server

# Or with explicit credentials for automation
ADMIN_USERNAME="admin" ADMIN_PASSWORD="<password>" ./bin/identity-server
```

Optional env vars: `IDENTITY_ENV` (`development`|`production`), `PORT` (default 8181), `DB_PATH` (default `identity.db`), `JWT_SECRET` (overrides DB-managed secret), `CORS_ORIGINS` (comma-separated allowed origins for API CORS and WebAuthn), `TRUST_PROXY` (`cloudflare` to trust `CF-Connecting-IP` header), `RATE_LIMIT_DISABLED` (`1` to disable rate limiting in dev/test), `SITE_NAME` (human-readable name shown in UI, default `Identity`), `WEBAUTHN_RP_ID` (passkey domain, e.g. `swee.net`; auto-configured as `localhost` in development), `WEBAUTHN_RP_ORIGINS` (comma-separated allowed WebAuthn origins; derived from RP ID if unset, merged with `CORS_ORIGINS`), `R2_*` for Cloudflare R2 backups.

On first run without `ADMIN_PASSWORD`, the generated password is written to `initial-password.txt` in the working directory (not logged to stdout). Delete the file after reading.

## Deploying

```bash
make deploy                              # Build + deploy to sweeney@garibaldi
./deploy/deploy.sh sweeney@garibaldi     # Same thing, explicit
```

Deploys versioned binaries to `/opt/identity/bin/` with a symlink, keeps last 3 versions. Fully non-interactive (uses passwordless `systemctl`).

## CLI commands

```
./identity-server --reset-admin             # Reset admin password (interactive)
./identity-server --rotate-jwt-secret       # Rotate JWT signing secret (zero-downtime)
./identity-server --clear-prev-jwt-secret   # Remove previous secret after rotation
./identity-server --list-backups            # List R2 backups
./identity-server --restore-backup [key]    # Restore from R2 backup
```

## Key implementation files

| Path | What it is |
|---|---|
| `internal/handler/api/` | HTTP handlers for all `/api/v1/*` routes |
| `internal/handler/oauth/` | OAuth `/oauth/authorize` and `/oauth/token` handlers |
| `internal/handler/admin/` | Server-rendered admin UI (`/admin/`) |
| `internal/service/auth_service.go` | Login, refresh, logout, authorize business logic |
| `internal/service/oauth_service.go` | OAuth PKCE flow orchestration |
| `internal/service/user_service.go` | User CRUD business logic |
| `internal/auth/jwt.go` | JWT mint/parse, supports previous-secret fallback |
| `internal/auth/middleware.go` | `RequireAuth` and `RequireAdmin` middleware |
| `internal/ratelimit/ratelimit.go` | Per-IP rate limiting middleware |
| `internal/httputil/clientip.go` | Shared client IP extraction with proxy trust |
| `internal/store/token_store.go` | Token rotation with atomic TOCTOU-safe transaction |
| `internal/store/audit_store.go` | Audit event recording (also emits to stdout) |
| `internal/domain/oauth.go` | OAuth types, auth event constants, repository interfaces |
| `internal/domain/webauthn.go` | WebAuthn credential/challenge types and repository interfaces |
| `internal/auth/webauthn.go` | WebAuthn user adapter and library configuration |
| `internal/service/webauthn_service.go` | Passkey registration, login, credential management |
| `internal/handler/api/webauthn.go` | WebAuthn API endpoints (`/api/v1/webauthn/*`) |
| `internal/store/webauthn_credential_store.go` | WebAuthn credential persistence |
| `internal/store/webauthn_challenge_store.go` | WebAuthn challenge persistence (ephemeral) |
| `internal/spec/openapi.yaml` | OpenAPI 3.0 spec (served at `/openapi.json`) |
| `cmd/server/secrets.go` | DB-managed JWT secret with rotation support |
| `cmd/server/backups.go` | `--list-backups` and `--restore-backup` CLI commands |
| `deploy/` | systemd unit, env template, install script |
| `examples/` | Four demo clients (server-side, SPA, BFF, passkey) |
| `scripts/e2e.sh` | End-to-end test suite (58 checks) |
| `scripts/e2e-webauthn.sh` | WebAuthn end-to-end test suite (32 checks) |
