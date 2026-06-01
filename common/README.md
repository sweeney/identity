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
| [`db`](db) | SQLite open + embedded migrations via `OpenWithMigrations`. |
| [`httputil`](httputil) | Proxy-aware HTTP helpers — `ExtractClientIP` (honours `TRUST_PROXY`) and `CheckOrigin`. |
| [`ratelimit`](ratelimit) | Per-IP token-bucket rate-limiting middleware (`Limiter`). |
| [`secrets`](secrets) | DB-managed JWT signing secret — `Resolve`, `RotateJWT`, `ClearPrevJWT` (supports zero-downtime rotation). |
| [`spec`](spec) | OpenAPI YAML→JSON `Converter` used to serve `/openapi.json` from embedded YAML. |

## Related docs

- [`docs/verifying-tokens.md`](../docs/verifying-tokens.md) — using `auth.JWKSVerifier` to verify tokens in a Go service
- [`docs/r2-backup.md`](../docs/r2-backup.md) — R2 backup setup and restore (`backup`, `cli`)
- [`docs/deployment.md`](../docs/deployment.md) — deployment, env file, and secret/`TRUST_PROXY` config
- [`CLAUDE.md`](../CLAUDE.md) — architecture overview and the `common/` release flow
