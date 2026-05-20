# Handoff: Splitting the Config service into its own repo

This file briefs a fresh Claude session on an in-progress refactor. Read it
top-to-bottom before doing anything — it captures decisions, current state,
and what's next. It is **not** intended to be committed; delete it when the
project is done.

## TL;DR

The user is splitting the sibling **config service** (currently a subcommand
of the identity binary) into its own repository, `sweeney/config-service`.
We chose to share code via an in-tree Go **sub-module** at `./common/`,
which the new repo will import as `github.com/sweeney/identity/common`. Step
1 (move `httputil`, `ratelimit`, `backup` into `common/`) is **complete and
pushed**. Steps 2-6 remain.

- Branch: **`claude/extract-config-service-uoYre`** (the one task system
  prompt designated for this work — keep using it)
- Last commit on branch: **`40a8516`** "Extract httputil, ratelimit, backup
  into common/ sub-module"
- Base: `origin/master` at `87c4b9c` "Remove 'homelab' language throughout".
  Master has **not** moved since we started. As of the last check we were 0
  behind, 1 ahead. Re-check with `git fetch && git rev-list --left-right
  --count origin/master...HEAD` before starting.
- Build status: `go build ./...`, `go vet ./...`, `go test -race ./...`,
  `go test -race -tags integration ./...`, `make build` all pass on the
  current commit.

## Why this refactor

The repo today is one binary with two subcommands (`identity` and `config`),
sharing a single `internal/` tree. The user wants config to live in its own
repo so it can release independently. The runtime coupling is already
minimal — config validates identity-issued JWTs over JWKS-over-HTTP — so
the work is purely a build-time split.

We evaluated four options earlier in the conversation:
1. Same repo, separate binaries (doesn't actually decouple)
2. **New repo + shared library module** (chosen)
3. New repo, copy-and-own the small shared surface (drift risk)
4. Monorepo with `go.work` (good local DX, awkward CI/release)

Option 2 was picked because the shared surface is small but non-trivial
(JWKS verifier, R2 backup, sqlite open + migrations runner, ratelimit,
httputil, OpenAPI serving, DB-managed JWT secrets, backup CLI helper), and
bug fixes in those should propagate to both services rather than diverge.

We also explicitly considered putting the shared module in a **third** repo
(`sweeney/identity-common`) but settled on the in-tree sub-module variant
because:
- One fewer repo to version, tag, and PR against.
- During step 1-5 the shared code is in flux; keeping it co-located with
  identity makes local dev fast (the `replace` directive avoids `go get`
  churn).
- We can still promote it to its own repo later if it earns the right.

## Repo / module layout

```
sweeney/identity (this repo)
├── go.mod                        module github.com/sweeney/identity
│                                 (requires + replaces common -> ./common)
├── common/
│   ├── go.mod                    module github.com/sweeney/identity/common
│   ├── go.sum
│   ├── httputil/                 [moved in step 1]
│   ├── ratelimit/                [moved in step 1]
│   └── backup/                   [moved in step 1; decoupled from domain]
│       └── mocks/                MockUploader lives here now
├── cmd/server/                   identity + config subcommand dispatcher
├── internal/                     identity-specific (and config-specific
│                                 until extracted)
└── ...

sweeney/config-service (separate repo, created by user; we have NOT
touched it yet — it gets populated in step 4)
```

`common/go.mod` declares its own deps (aws-sdk, modernc/sqlite, mock,
golang.org/x/time, testify). identity's root `go.mod` had those direct deps
demoted to `// indirect` once `go mod tidy` ran.

The `replace` line in identity's root `go.mod`:
```go
replace github.com/sweeney/identity/common => ./common
```
This is intentional — identity always builds against the in-tree copy.
Released versions of common will be tagged as **`common/vX.Y.Z`** (path-
prefixed sub-module tags) and consumed by config-service via normal `go get
github.com/sweeney/identity/common@vX.Y.Z`. The `replace` directive does
NOT need to be removed for releases — it only affects identity's local
build.

## What step 1 did (already merged into the branch)

**Moved (via `git mv` so history is preserved):**
- `internal/httputil/` → `common/httputil/` (no code changes)
- `internal/ratelimit/` → `common/ratelimit/` (only import path updated)
- `internal/backup/{backup,noop,r2,backup_test}.go` → `common/backup/`
- `internal/mocks/mock_uploader.go` → `common/backup/mocks/mock_uploader.go`
  (the only mock used solely by backup itself; other mocks in
  `internal/mocks/` stayed put)

**Key refactor — backup decoupled from `internal/domain`:**

The old `backup.NewManager(cfg, uploader, audit domain.AuditRepository)`
took a full `domain.AuditRepository` just to record success/failure events.
That's a hard coupling from common to identity's domain types, which the
common module must not have.

The new signature is:
```go
type EventRecorder func(success bool, detail string)
func NewManager(cfg Config, uploader Uploader, record EventRecorder) *Manager
```

Callers adapt their own audit sinks into this callback:
- **Identity** (`cmd/server/identity.go`): a helper
  `backupAuditRecorder(audit domain.AuditRepository) backup.EventRecorder`
  closes over `auditStore` and constructs `domain.AuthEvent{…}` records.
  Defined at the bottom of `identity.go`.
- **Config** (`cmd/server/config.go`): the old `stdoutAudit` shim (a
  five-method type pretending to be a `domain.AuditRepository`) was
  deleted entirely and replaced with a single function
  `logBackupEvent(success bool, detail string)` that logs to stdout. The
  `domain` import in `config.go` is still there because that file uses
  `domain.BackupService` and `domain.EventBackup*` constants.

**Import sweep:**
- Every site that imported `github.com/sweeney/identity/internal/{httputil,ratelimit,backup}`
  now imports `github.com/sweeney/identity/common/{httputil,ratelimit,backup}`.
  Done via a single sed pass; ~13 files updated.

**Verification (passed at the tip):**
```bash
go build ./...
go vet ./...
go test -race -count=1 ./...                # unit
go test -race -count=1 -tags integration ./... # integration
make build
```

## Migration plan — the six steps

1. ✅ **Done**. Move `httputil`, `ratelimit`, `backup` into `common/`.
   Decouple backup from `internal/domain` via the EventRecorder callback.
   Wire up `replace` directive.
2. ⏭ **NEXT.** Move more shared infrastructure into `common/`:
   - `internal/db/db.go` (sqlite open + generic migration runner). Note:
     `internal/db/migrations/` (identity's migration SQL) and
     `internal/db/config_migrations/` (config's) STAY where they are for
     now — they'll move to their respective repos in step 4-5.
   - `internal/auth/jwks_verifier.go` + the JWKS-only middleware bits.
     Identity's richer middleware (with password/webauthn awareness)
     stays in `internal/auth/` and wraps common's `RequireAuth`.
     `jwt.go` (the mint side), `password.go`, `webauthn.go` are
     identity-only and stay put.
   - `internal/spec/spec.go` (the handler that serves an embedded YAML).
     The two YAMLs (`openapi.yaml`, `config-openapi.yaml`) stay — each
     repo will keep its own.
   - `cmd/server/secrets.go` → `common/secrets/jwt_secret.go` (DB-managed
     signing key, used by both services).
   - `cmd/server/backups.go` → `common/cli/backups.go`. Refactor to take
     service name + R2 prefix as arguments rather than branching on
     hardcoded names.
   - Also worth eyeing during step 2: `internal/domain/errors.go` is
     used by both services — either promote to `common/errors` or
     duplicate (it's tiny). A `grep` pass should turn up any other small
     shared symbols.
3. **Tag `common/v0.1.0`** once step 2 lands and tests pass. Push the tag:
   `git tag common/v0.1.0 && git push origin common/v0.1.0`. Confirm
   resolution: from any other repo, `go get github.com/sweeney/identity/common@v0.1.0`.
4. **Stand up `sweeney/config-service`.** Move:
   - `internal/domain/config.go`, `internal/store/config_store.go`,
     `internal/service/config_service.go`, `internal/handler/config/`,
     `internal/ui-config/`, `internal/db/config_migrations/`,
     `internal/config/configsvc.go`, `internal/spec/config-openapi.yaml`,
     `cmd/server/config.go`, `scripts/e2e-config.sh`, `docs/config*.md`.
   - Point its `go.mod` at `common@v0.1.0`.
   - **IMPORTANT CONSTRAINT:** my GitHub MCP tools are scoped to
     `sweeney/identity` only (see system prompt). I can prepare the file
     tree and commits locally, but I **cannot** push to or open PRs
     against `sweeney/config-service`. The user has created that repo at
     https://github.com/sweeney/config-service — when we get to step 4
     they need to either push themselves or rescope the MCP server.
     Confirm with the user before doing significant work on the
     config-service tree.
5. **Delete the moved files from identity.** Drop the `config` subcommand
   from `cmd/server/main.go`'s dispatcher; rename `cmd/server` →
   `cmd/identity` (or leave the path; not critical). The legacy
   `--list-backups`, `--restore-backup`, `--reset-admin`, `--rotate-jwt-key`,
   `--clear-prev-jwt-key` flags should continue to work on identity.
6. **Update deploy + docs.** `deploy/` currently installs both services
   from one binary — split into per-service units, each pulled from its
   own repo's CI. Update `CLAUDE.md` (currently says "one binary, two
   services" all over). Update `README.md`. Update `docs/deployment.md`,
   `docs/config*.md`, etc.

## Constraints and conventions

- **Branch policy** (from the task system prompt at session start):
  > All development on **`claude/extract-config-service-uoYre`**.
  > Push to that branch. Do NOT push to master.
  Keep using this branch for steps 2-3 (and arguably 5-6). For step 4
  the work happens in a different repo entirely, so this constraint is
  N/A there.
- **Do NOT open a PR** unless the user explicitly asks. Just commit and
  push.
- **GitHub MCP repo scope:** `sweeney/identity` only. Calls against
  `sweeney/config-service` will be denied.
- **Commit style** based on `git log --oneline`:
  - Short imperative subject line, no Conventional Commits prefix.
  - Optional descriptive body explaining the *why*.
  - Look at recent commits for tone: "Remove 'homelab' language throughout",
    "Suppress WebAuthn RP origins warning for wildcard CORS entries".
- **No git amend.** Always create new commits.
- **No new \*.md files unless asked** (per global instructions). This
  handoff doc was explicitly requested.

## Files of note to read first in a fresh session

- `CLAUDE.md` — project overview (one binary, two services; lists every
  shared package).
- `cmd/server/main.go` — subcommand dispatcher.
- `cmd/server/identity.go` — identity entrypoint; see
  `backupAuditRecorder` at the bottom for the step-1 adapter pattern.
- `cmd/server/config.go` — config entrypoint; see `logBackupEvent`.
- `cmd/server/secrets.go`, `cmd/server/backups.go` — destined for
  `common/` in step 2.
- `common/go.mod`, root `go.mod` — module wiring.
- `internal/auth/jwks_verifier.go`, `internal/auth/middleware.go` — the
  split surgery for step 2.

## Verification recipe (run after every step)

```bash
cd common && go build ./... && go test -race ./...
cd .. && go build ./... && go vet ./... \
  && go test -race -count=1 ./... \
  && go test -race -count=1 -tags integration ./... \
  && make build
```

## Quick context the user may not remind you of

- The user prefers tight communication. Short status updates, no narration
  of internal deliberation. Code: no comments unless explaining a
  non-obvious "why".
- The user said "you'll do step 2 on a fresh branch off this one" earlier —
  but the task system prompt designates one specific branch. **Ask before
  branching off**; they may have meant the same branch, or they may want a
  stacked branch.
- The user has confirmed they want option 1 (in-tree sub-module) and
  explicitly created `https://github.com/sweeney/config-service`. They
  said "go ahead in a new branch" when authorizing step 1.

## Outstanding questions to surface when resuming

1. "Are we proceeding with step 2 on `claude/extract-config-service-uoYre`,
   or do you want a fresh branch?"
2. "Should step 2 also include `internal/domain/errors.go` → `common/errors`,
   or duplicate it later?"
3. When approaching step 4: "My GitHub MCP is scoped to sweeney/identity
   only — I can prepare the config-service tree locally but you'll need
   to push it, or rescope my tools. Which?"
