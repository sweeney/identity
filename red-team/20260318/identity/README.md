# Identity

A self-hosted authentication and identity management service. Single Go binary, SQLite database, OAuth 2.0 with PKCE.

**Live at [id.swee.net](https://id.swee.net)**

## Features

- **JWT authentication** — short-lived access tokens (15 min) + rotating refresh tokens (30-day sliding)
- **OAuth 2.0 Authorization Code + PKCE** — "Sign in with Identity" for any app
- **Token theft detection** — replayed refresh tokens revoke the entire token family
- **Admin UI** — manage users, OAuth clients, and view the audit log
- **Audit log** — every login, logout, user change, and backup is recorded
- **R2 backups** — automatic SQLite backups to Cloudflare R2
- **Zero-config startup** — just run the binary; JWT secret and admin password auto-generated on first run
- **Security hardened** — CSRF protection, security headers, bcrypt, constant-time auth

## Quick start

```bash
# Build
go build -o bin/identity-server ./cmd/server/

# Run (zero config — generates admin password on first run)
./bin/identity-server

# Or with explicit admin credentials
ADMIN_USERNAME=admin ADMIN_PASSWORD=mypassword ./bin/identity-server
```

Open http://localhost:8181/admin/ and log in with the credentials from the console output.

## CLI commands

```
./identity-server                        # Start the server
./identity-server --reset-admin          # Reset admin password (interactive)
./identity-server --rotate-jwt-secret    # Rotate the JWT signing secret
./identity-server --clear-prev-jwt-secret # Remove previous secret after rotation
./identity-server --list-backups         # List R2 backups
./identity-server --restore-backup [key] # Restore from R2 backup
./identity-server --help                 # Show all commands
```

## Environment variables

All optional. The service runs with zero configuration.

| Variable | Default | Description |
|---|---|---|
| `IDENTITY_ENV` | `development` | `development` or `production` (affects cookie security, R2 paths) |
| `PORT` | `8181` | HTTP listen port |
| `DB_PATH` | `identity.db` | SQLite database path |
| `JWT_SECRET` | auto-generated | Override the DB-managed JWT signing secret |
| `ADMIN_USERNAME` | `admin` | Initial admin username (first run only) |
| `ADMIN_PASSWORD` | auto-generated | Initial admin password (first run only) |
| `R2_ACCOUNT_ID` | | Cloudflare account ID for R2 backups |
| `R2_ACCESS_KEY_ID` | | R2 API token access key |
| `R2_SECRET_ACCESS_KEY` | | R2 API token secret |
| `R2_BUCKET_NAME` | | R2 bucket name |

## API

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/auth/login` | None | Authenticate, receive tokens |
| POST | `/api/v1/auth/refresh` | None | Rotate refresh token |
| POST | `/api/v1/auth/logout` | Bearer | Revoke session(s) |
| GET | `/api/v1/auth/me` | Bearer | Current user from JWT claims |
| GET | `/api/v1/users` | Admin | List users |
| POST | `/api/v1/users` | Admin | Create user |
| GET | `/api/v1/users/{id}` | Bearer | Get user (non-admins: own record only) |
| PUT | `/api/v1/users/{id}` | Admin | Update user |
| DELETE | `/api/v1/users/{id}` | Admin | Delete user |
| GET | `/oauth/authorize` | None | OAuth login form |
| POST | `/oauth/authorize` | None | Submit credentials, redirect with code |
| POST | `/oauth/token` | None | Exchange code or refresh token |
| GET | `/openapi.json` | None | OpenAPI 3.0 spec (JSON) |
| GET | `/openapi.yaml` | None | OpenAPI 3.0 spec (YAML) |

## Production deployment

See [deploy/](deploy/) for systemd unit, env file template, and install script.

```bash
# On the target host:
sudo bash /tmp/install.sh
sudo nano /etc/identity/env    # set IDENTITY_ENV=production and R2 creds
sudo journalctl -u identity | grep Password  # get the generated admin password
```

## Documentation

- [docs/api.md](docs/api.md) — Integration guide with code examples
- [docs/api-walkthrough.md](docs/api-walkthrough.md) — Executable walkthrough of every endpoint
- [docs/auth-flows.md](docs/auth-flows.md) — ASCII art diagrams of all auth flows
- [docs/r2-backup.md](docs/r2-backup.md) — R2 backup setup and restore
- [examples/](examples/) — Demo OAuth clients (server-side, SPA, BFF)

## Testing

```bash
go test ./...                          # Unit tests
go test -tags=integration ./...        # Integration tests
./scripts/e2e.sh                       # End-to-end tests against running server
```
