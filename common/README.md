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
| [`backup`](backup) | Database backup orchestration. `Manager` drives scheduled uploads via an `Uploader` and reports what happened via `Status()`; `R2Uploader` targets Cloudflare R2 (S3 API), `NoopManager` disables backups. `RedactSecrets` scrubs credentials out of SDK errors before they are surfaced. |
| [`cli`](cli) | CLI helpers for backups — `ListBackups` and `RestoreBackup`. |
| [`db`](db) | SQLite open + embedded migrations via `OpenWithMigrations`. |
| [`httputil`](httputil) | Proxy-aware HTTP helpers — `ExtractClientIP` (honours `TRUST_PROXY`) and `CheckOrigin`. |
| [`ratelimit`](ratelimit) | Per-IP token-bucket rate-limiting middleware (`Limiter`). |
| [`secrets`](secrets) | DB-managed JWT signing secret — `Resolve`, `RotateJWT`, `ClearPrevJWT` (supports zero-downtime rotation). |
| [`spec`](spec) | OpenAPI YAML→JSON `Converter` used to serve `/openapi.json` from embedded YAML. |

## Reporting backup health

`Manager.Status()` returns a snapshot of the backup history, so a consumer does
not have to shadow the `Manager` with its own bookkeeping to answer "are
backups working?":

```go
func healthHandler(m *backup.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := m.Status()
		json.NewEncoder(w).Encode(map[string]any{
			"last_attempt": s.LastAttempt, // zero until the first attempt
			"last_success": s.LastSuccess, // never moved by a failure
			"last_key":     s.LastKey,     // newest *good* backup, kept across failures
			"last_error":   s.LastError,   // empty when the last attempt succeeded
			"next_run":     s.NextRun,     // zero when Schedule is "off"
			"successes":    s.Successes,
			"failures":     s.Failures,
		})
	}
}
```

`LastAttempt == LastSuccess` means the most recent backup succeeded; a
`LastSuccess` lagging behind `LastAttempt` means backups are failing now, and
the gap says for how long. How much lag is unhealthy is the consumer's call.

`LastError` has already been through `backup.RedactSecrets`, which removes
credential-shaped values (`Credential=`, `Signature=`, `SecretAccessKey`,
`x-amz-security-token`, bare access key IDs) from the AWS SDK's error text
while leaving the diagnosis readable. Errors *returned* from `RunNow` are not
redacted — pass one through `RedactSecrets` before putting it anywhere public.

`Config.Clock` replaces the `Manager`'s use of `time.Now`, which is what makes
`NextRun()` and the backup key assertable from a test without waiting for the
schedule to come round. The timers themselves are real: a clock that never
advances still waits real time, and defers every `MinInterval`-throttled
trigger, since by its own clock no time has passed.

## Related docs

- [`docs/verifying-tokens.md`](../docs/verifying-tokens.md) — using `auth.JWKSVerifier` to verify tokens in a Go service
- [`docs/r2-backup.md`](../docs/r2-backup.md) — R2 backup setup and restore (`backup`, `cli`)
- [`docs/deployment.md`](../docs/deployment.md) — deployment, env file, and secret/`TRUST_PROXY` config
- [`CLAUDE.md`](../CLAUDE.md) — architecture overview and the `common/` release flow
