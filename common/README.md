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
| [`db`](db) | SQLite open + embedded migrations via `OpenWithMigrations`. Applied migrations are recorded in `schema_migrations` and never re-run — see [Writing a migration](#writing-a-migration). |
| [`httputil`](httputil) | Proxy-aware HTTP helpers — `ExtractClientIP` (honours `TRUST_PROXY`) and `CheckOrigin`. |
| [`ratelimit`](ratelimit) | Per-IP token-bucket rate-limiting middleware (`Limiter`). |
| [`secrets`](secrets) | DB-managed JWT signing secret — `Resolve`, `RotateJWT`, `ClearPrevJWT` (supports zero-downtime rotation). |
| [`spec`](spec) | OpenAPI YAML→JSON `Converter` used to serve `/openapi.json` from embedded YAML. |

## Reporting backup health

`Manager.Status()` returns a snapshot of the backup history, so a consumer does
not have to shadow the `Manager` with its own bookkeeping to answer "are
backups working?".

**Put this behind the same auth as the rest of your admin surface, not on an
unauthenticated `/healthz`.** `last_key` names a live object in your bucket and
`last_error` is SDK text that `RedactSecrets` guards on a best-effort basis —
neither is something to hand to anyone who can reach the port. (This is why
Identity does not serve it from its own `/health`.)

```go
type backupHealth struct {
	Configured  bool       `json:"configured"`            // false: no destination — backups cannot happen
	Scheduled   bool       `json:"scheduled"`             // false: nothing is waiting to take one
	LastAttempt *time.Time `json:"last_attempt,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"` // never moved by a failure
	NextRun     *time.Time `json:"next_run,omitempty"`
	LastKey     string     `json:"last_key,omitempty"`    // newest *good* backup, kept across failures
	LastError   string     `json:"last_error,omitempty"`  // empty when the last attempt succeeded
	Successes   int        `json:"successes"`
	Failures    int        `json:"failures"`
}

// omitZero keeps a never-yet-happened timestamp out of the JSON. A zero
// time.Time marshals to "0001-01-01T00:00:00Z", which a dashboard reads as a
// date rather than as "no backup has run".
func omitZero(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func backupHealthHandler(m *backup.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := m.Status()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(backupHealth{
			Configured:  s.Configured,
			Scheduled:   s.Scheduled,
			LastAttempt: omitZero(s.LastAttempt),
			LastSuccess: omitZero(s.LastSuccess),
			NextRun:     omitZero(s.NextRun),
			LastKey:     s.LastKey,
			LastError:   s.LastError,
			Successes:   s.Successes,
			Failures:    s.Failures,
		}); err != nil {
			log.Printf("backup health: %v", err)
		}
	}
}
```

`LastAttempt == LastSuccess` means the most recent backup succeeded; a
`LastSuccess` lagging behind `LastAttempt` means backups are failing now, and
the gap says for how long. How much lag is unhealthy is the consumer's call.

Read `Configured` and `Scheduled` first. An all-zero `Status` means three
different things — no destination configured (`Configured` false, the
`NoopManager`), configured but nothing scheduling backups (`Scheduled` false:
`Schedule: "off"`, or `Start` never called), or simply nothing having run yet —
and only those two fields tell them apart. A domain interface that declares
only `TriggerAsync`/`RunNow` needs widening before `Status()` can be called
without a type assertion.

`LastError` has already been through `backup.RedactSecrets`, which removes
credential-shaped values (`Credential=`, `Signature=`, `SecretAccessKey`,
`x-amz-security-token`, bare access key IDs) from the AWS SDK's error text
while leaving the diagnosis readable — an error code and its message survive
whole, and so does the signing algorithm. Errors *returned* from `RunNow` are
not redacted; pass one through `RedactSecrets` before putting it anywhere
public.

`Config.Clock` replaces the `Manager`'s use of `time.Now`, which is what makes
`NextRun()` and the backup key assertable from a test without waiting for the
schedule to come round. It is never called while the `Manager` holds a lock, so
a clock may call back into it. The timers themselves are real: a clock that
never advances still waits real time, and defers every `MinInterval`-throttled
trigger indefinitely, re-arming once per interval without taking a backup.

## Writing a migration

`OpenWithMigrations` applies every file in the embedded migrations directory in
filename order, each in a transaction of its own, and records it by filename in
a `schema_migrations` table. A recorded migration is never executed again, so:

- **Migrations need not be idempotent.** A one-shot `INSERT` or `UPDATE` is
  fine.
- **Do not rebuild a table that anything references.** `Open` enables
  `foreign_keys` before migrating and the runner holds a transaction, where
  SQLite will not let the pragma be turned off — so the `CREATE new` /
  `INSERT SELECT` / `DROP old` / `RENAME` dance runs with foreign keys enforced
  and the `DROP` fires every `ON DELETE CASCADE` pointing at the table. It
  commits cleanly and is recorded as applied, having silently emptied the
  referencing tables. Widening a `CHECK` constraint, or anything else that needs
  a rebuild, has to happen outside the migration runner until the runner grows a
  way to opt a file out of the transaction.
- **Never edit or rename a migration that has shipped.** Deployed databases
  already record it under its filename and will not run it again, so the change
  reaches only databases created afterwards and the two drift apart. A rename is
  worse than an edit: the new name reads as a brand-new migration and re-runs on
  every deployed database, while the old name sits in the ledger forever. Add a
  new file instead. The ledger records each migration's checksum and warns on
  the next boot if the file has changed since — a warning, not a failure, since
  failing would turn a corrected typo in a comment into an outage.
- **Do not manage transactions.** The runner opens one per file, so a migration
  must not `BEGIN`/`COMMIT`, and must not contain a statement SQLite refuses to
  run inside a transaction (`VACUUM`, or a `foreign_keys` pragma).
- **`duplicate column name` from an `ALTER TABLE ... ADD COLUMN` is skipped, per
  statement.** SQLite has no `ADD COLUMN IF NOT EXISTS`, so a migration that
  backfills a column into the databases missing it adds it unconditionally; the
  rest of the file still runs, and the skip is logged. The tolerance is scoped
  to that one statement deliberately, because the same message means something
  else everywhere else: from a `CREATE TABLE` it is a repeated name in the
  column list, and from an `ALTER TABLE ... RENAME COLUMN x TO y` it is a rename
  onto a name already taken. Both are mistakes, and the ledger would record
  either as applied and never offer it again. Any other error fails the boot,
  names the file, and rolls the whole file back, leaving it to be retried once
  it is fixed.

### Adopting a database that predates the ledger

On its first boot with this runner, a database with no `schema_migrations` table
is offered every migration: the outstanding ones apply, the already-applied ones
are skipped, and all of them are recorded, so nothing is offered twice after
that.

That works **provided every already-applied migration is re-runnable**, because
the skipped `duplicate column name` is the only error tolerated. In practice
that means every `CREATE` carries `IF NOT EXISTS`, and nothing renames or drops
a column. What SQLite returns when a statement is executed a second time:

| Re-run statement | Error | Adoption |
|---|---|---|
| `ALTER TABLE a ADD COLUMN y INT` | `duplicate column name: y` | skipped |
| `CREATE TABLE a (x INT)` | `table a already exists` | **boot fails** |
| `CREATE INDEX ix ON a(x)` | `index ix already exists` | **boot fails** |
| `CREATE TRIGGER tr ...` | `trigger tr already exists` | **boot fails** |
| `CREATE VIEW v AS ...` | `view v already exists` | **boot fails** |
| `ALTER TABLE a RENAME COLUMN x TO z` | `no such column: "x"` | **boot fails** |
| `ALTER TABLE a DROP COLUMN y` | `no such column: "y"` | **boot fails** |

Identity's thirteen migrations all qualify, and so do the four in
`sweeney/config`; the adoption path is covered by
`TestMigrations_AdoptFullyMigratedDatabase` in `internal/db`. **Any other
consumer upgrading to a version of this module that has the ledger should check
its own migrations against that table first** — a bare `CREATE INDEX` or a
`RENAME COLUMN` among them turns the adoption boot into a startup outage.

Statement splitting is comment-, string- and `BEGIN ... END`-aware, so prose
punctuation in a migration's comments is safe (this was [#44](https://github.com/sweeney/identity/issues/44)).


## Related docs

- [`docs/verifying-tokens.md`](../docs/verifying-tokens.md) — using `auth.JWKSVerifier` to verify tokens in a Go service
- [`docs/r2-backup.md`](../docs/r2-backup.md) — R2 backup setup and restore (`backup`, `cli`)
- [`docs/deployment.md`](../docs/deployment.md) — deployment, env file, and secret/`TRUST_PROXY` config
- [`CLAUDE.md`](../CLAUDE.md) — architecture overview and the `common/` release flow
