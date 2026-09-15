# `common/`

Shared Go packages used by the Identity server **and** by sibling services that
integrate with it (e.g. the config service). This is a **separate Go module**
(`github.com/sweeney/identity/common`) so consumers can depend on it without
pulling in the server's `internal/` code.

```bash
go get github.com/sweeney/identity/common@v0.1.0
```

Consumers pin an exact version. Releasing a new version (tagging `common/vX.Y.Z`)
is documented in the repo root [`CLAUDE.md`](../CLAUDE.md#releasing-a-new-version-of-common)
— never make breaking changes without bumping the minor version.

## Packages

| Package | What it does |
|---|---|
| [`auth`](auth) | Verify Identity-issued ES256 JWTs against the published JWKS. `JWKSVerifier` (with optional `slog` logging and a pull-based `Metrics()` snapshot), the `TokenParser` interface, and `TokenClaims` / `ServiceTokenClaims` / `Role` types. |
| [`apierr`](apierr) | Shared sentinel errors (`ErrNotFound`, `ErrConflict`, `ErrUserLimitReached`, `ErrTokenAlreadyRevoked`) for consistent error mapping. |
| [`backup`](backup) | Database backup orchestration. `Manager` drives scheduled uploads via an `Uploader`; `R2Uploader` targets Cloudflare R2 (S3 API), `NoopManager` disables backups. |
| [`cli`](cli) | CLI helpers for backups — `ListBackups` and `RestoreBackup`. |
| [`db`](db) | SQLite open + embedded migrations via `OpenWithMigrations`. Applied migrations are recorded in `schema_migrations` and never re-run — see [Writing a migration](#writing-a-migration). |
| [`httputil`](httputil) | Proxy-aware HTTP helpers — `ExtractClientIP` (honours `TRUST_PROXY`) and `CheckOrigin`. |
| [`ratelimit`](ratelimit) | Per-IP token-bucket rate-limiting middleware (`Limiter`). |
| [`secrets`](secrets) | DB-managed JWT signing secret — `Resolve`, `RotateJWT`, `ClearPrevJWT` (supports zero-downtime rotation). |
| [`spec`](spec) | OpenAPI YAML→JSON `Converter` used to serve `/openapi.json` from embedded YAML. |

## Writing a migration

`OpenWithMigrations` applies every file in the embedded migrations directory in
filename order, each in a transaction of its own, and records it by filename in
a `schema_migrations` table. A recorded migration is never executed again, so:

- **Migrations need not be idempotent.** A one-shot `INSERT`, or a table rebuild
  that cannot be expressed as `IF NOT EXISTS`, is fine.
- **Never edit a migration that has shipped.** Deployed databases already record
  it and will not run it again; the change would only reach fresh databases.
  Add a new file instead.
- **Do not manage transactions.** The runner opens one per file, so a migration
  must not `BEGIN`/`COMMIT`, and must not contain a statement SQLite refuses to
  run inside a transaction (`VACUUM`, or a `foreign_keys` pragma).
- **`duplicate column name` is skipped, per statement.** SQLite has no
  `ADD COLUMN IF NOT EXISTS`, so a migration that backfills a column into the
  databases missing it adds it unconditionally; the rest of the file still runs.
  Any other error fails the boot, names the file, and rolls the whole file back,
  leaving it to be retried once it is fixed.

A database migrated before `schema_migrations` existed is adopted on its first
boot with the new runner: the outstanding migrations are applied, the
already-applied ones report `duplicate column name` and are skipped, and all of
them are recorded.

Statement splitting is comment-, string- and `BEGIN ... END`-aware, so prose
punctuation in a migration's comments is safe (this was [#44](https://github.com/sweeney/identity/issues/44)).

## Related docs

- [`docs/verifying-tokens.md`](../docs/verifying-tokens.md) — using `auth.JWKSVerifier` to verify tokens in a Go service
- [`docs/r2-backup.md`](../docs/r2-backup.md) — R2 backup setup and restore (`backup`, `cli`)
- [`docs/deployment.md`](../docs/deployment.md) — deployment, env file, and secret/`TRUST_PROXY` config
- [`CLAUDE.md`](../CLAUDE.md) — architecture overview and the `common/` release flow
