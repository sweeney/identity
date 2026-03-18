# Identity Service

A self-hosted JWT authentication and identity management service. Single Go binary, SQLite database, exposed via Cloudflare Tunnel (always HTTPS in production).

## What it does

Provides user accounts, JWT-based sessions, and OAuth 2.0 authorization code flow with PKCE for web and mobile apps. An admin manages users and OAuth clients via a web UI or API. Apps authenticate users, receive tokens, and use those tokens to call the Identity API or other protected services.

## Getting the full API spec

```bash
GET /openapi.json   # OpenAPI 3.0 spec as JSON
GET /openapi.yaml   # OpenAPI 3.0 spec as YAML
```

Human-readable guides are in `docs/`:
- `docs/api.md` — integration guide with Swift/Kotlin examples and error reference
- `docs/api-walkthrough.md` — executable walkthrough showing every endpoint with real output
- `docs/auth-flows.md` — ASCII art diagrams of all auth flows
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

Key error codes: `invalid_credentials`, `token_family_compromised`, `token_expired`, `invalid_refresh_token`, `account_disabled`, `forbidden`, `unknown_client`, `invalid_redirect_uri`, `invalid_auth_code`, `pkce_verification_failed`

## Running locally

```bash
# Zero config — generates JWT secret and admin password on first run
./bin/identity-server

# Or with explicit credentials for automation
ADMIN_USERNAME="admin" ADMIN_PASSWORD="<password>" ./bin/identity-server
```

Optional env vars: `IDENTITY_ENV` (`development`|`production`), `PORT` (default 8181), `DB_PATH` (default `identity.db`), `JWT_SECRET` (overrides DB-managed secret), `CORS_ORIGINS` (comma-separated allowed origins for API CORS), `TRUST_PROXY` (`cloudflare` to trust `CF-Connecting-IP` header), `RATE_LIMIT_DISABLED` (`1` to disable rate limiting in dev/test), `R2_*` for Cloudflare R2 backups.

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
| `internal/spec/openapi.yaml` | OpenAPI 3.0 spec (served at `/openapi.json`) |
| `cmd/server/secrets.go` | DB-managed JWT secret with rotation support |
| `cmd/server/backups.go` | `--list-backups` and `--restore-backup` CLI commands |
| `deploy/` | systemd unit, env template, install script |
| `examples/` | Three OAuth demo clients (server-side, SPA, BFF) |
| `scripts/e2e.sh` | End-to-end test suite (58 checks) |
