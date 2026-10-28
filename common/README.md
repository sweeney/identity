# `common/`

The Go package sibling services use to verify Identity-issued tokens. This is a
**separate Go module** (`github.com/sweeney/identity/common`) so consumers can
depend on it without pulling in the server's `internal/` code.

```bash
go get github.com/sweeney/identity/common@v0.7.0
```

Consumers pin an exact version. Releasing a new version (tagging `common/vX.Y.Z`)
is documented in the repo root [`CLAUDE.md`](../CLAUDE.md#releasing-a-new-version-of-common)
— never make breaking changes without bumping the minor version.

## Packages

| Package | What it does |
|---|---|
| [`auth`](auth) | Verify Identity-issued ES256 JWTs against the published JWKS. `JWKSVerifier` (with optional `slog` logging and a pull-based `Metrics()` snapshot), the `TokenParser` interface, and `TokenClaims` / `ServiceTokenClaims` / `Role` types. |

`auth` stays beside the server because it changes in lockstep with Identity's
token issuer (`internal/auth/jwt.go`), and Identity's own tests check the tokens
it issues against this verifier.

## Moved to `github.com/sweeney/common`

As of v0.7.0 the generic service-infrastructure packages live in the
[`sweeney/common`](https://github.com/sweeney/common) repo, moved unchanged
apart from their import paths. v0.6.0 of this module still contains them.

| Was `identity/common/…` | Now | Module |
|---|---|---|
| `db` | `github.com/sweeney/common/db` | `db` |
| `backup`, `backup/mocks` | `github.com/sweeney/common/backup`, `…/backup/mocks` | `backup` |
| `cli` | `github.com/sweeney/common/backup/cli` | `backup` |
| `apierr` | `github.com/sweeney/common/web/apierr` | `web` |
| `httputil` | `github.com/sweeney/common/web/httputil` | `web` |
| `ratelimit` | `github.com/sweeney/common/web/ratelimit` | `web` |
| `spec` | `github.com/sweeney/common/web/spec` | `web` |

`secrets` had no users outside Identity and is now `internal/secrets`.

The guides that used to live here moved with their packages:

- [Writing a migration](https://github.com/sweeney/common/blob/main/db/README.md#writing-a-migration),
  including adopting a database that predates the `schema_migrations` ledger
- [Reporting backup health](https://github.com/sweeney/common/blob/main/backup/README.md#reporting-backup-health)
- [`web/README.md`](https://github.com/sweeney/common/blob/main/web/README.md) — `apierr`, `httputil`, `ratelimit`, `spec`

## Related docs

- [`docs/verifying-tokens.md`](../docs/verifying-tokens.md) — using `auth.JWKSVerifier` to verify tokens in a Go service
- [`docs/r2-backup.md`](../docs/r2-backup.md) — R2 backup setup and restore
- [`docs/deployment.md`](../docs/deployment.md) — deployment, env file, and secret/`TRUST_PROXY` config
- [`CLAUDE.md`](../CLAUDE.md) — architecture overview and the `common/` release flow
