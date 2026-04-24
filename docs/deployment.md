# Deployment guide

This repo produces a single Go binary, `identity-server`, that runs
multiple services selected via subcommand:

```
identity-server identity   # identity service on :8181 (default)
identity-server config     # config service on :8282
```

A typical production deploy runs **both** as separate systemd units,
sharing the binary, the R2 bucket, and the `/var/lib/identity/` state
directory, but holding separate SQLite files and separate env files.

## Binary install

The install script drops the binary to `/opt/identity/bin/` with a
versioned filename plus a `current` symlink, creates the `identity`
system user, and writes the systemd units.

```bash
sudo ./deploy/install.sh /path/to/built/identity-server
```

This installs and enables both `identity.service` and `config.service`.
If you only want one, disable the other afterwards:

```bash
sudo systemctl disable --now config.service
```

## Env files

| Path | Purpose | Owner |
|---|---|---|
| `/etc/identity/env` | Identity service env | `root:root` 0600 |
| `/etc/identity/config.env` | Config service env | `root:root` 0600 |

Both are loaded by their respective systemd unit via `EnvironmentFile=`.
See `deploy/env.example` and `deploy/config-env.example` for every
variable with defaults.

A minimal `/etc/identity/config.env`:

```
IDENTITY_ENV=production
PORT=8282
DB_PATH=/var/lib/identity/config.db
IDENTITY_ISSUER_URL=https://id.example.com
IDENTITY_ISSUER=https://id.example.com
R2_ACCOUNT_ID=xxx
R2_ACCESS_KEY_ID=xxx
R2_SECRET_ACCESS_KEY=xxx
R2_BUCKET_NAME=homelab-backups
```

`CORS_ORIGINS` is rarely needed for config unless you plan to call the
API from a browser app.

## State layout

Both services share `/var/lib/identity/`, owned by the `identity` user
with mode 0700. Each service owns a distinct SQLite file:

```
/var/lib/identity/
├── identity.db
├── identity.db-wal
├── identity.db-shm
├── config.db
├── config.db-wal
└── config.db-shm
```

R2 backups use disjoint prefixes:

```
{env}/backups/identity/{YYYY/MM/DD}/identity-{ts}.sqlite3
{env}/backups/config/{YYYY/MM/DD}/config-{ts}.sqlite3
```

Legacy identity backups (before the per-service layout) at
`{env}/backups/{YYYY/MM/DD}/identity-{ts}.sqlite3` remain discoverable
via `--list-backups`.

## Port layout

| Service | Default port |
|---|---|
| identity | 8181 |
| config | 8282 |

Override via `PORT` in the service's env file. Typical production fronts
both with Cloudflare Tunnel on separate hostnames:
`id.example.com → :8181`, `config.example.com → :8282`.

## Running as different unix users

The default install uses one `identity` unix user for both services.
This is fine for a homelab. If you want real isolation between services
(so a compromise of one can't read the other's SQLite file), create a
second user and override the `User=`/`Group=` in a systemd drop-in:

```ini
# /etc/systemd/system/config.service.d/user.conf
[Service]
User=config
Group=config
```

…and `chown` `config.db` accordingly. Note that both services must be
able to write to their own DB directory.

## Deploy flow

```bash
make deploy                              # build + deploy + restart both units
# or
./deploy/deploy.sh sweeney@garibaldi     # same, explicit
```

The deploy script uploads the new binary (versioned), atomically
swings the `current` symlink, and restarts **both** units in sequence.
It then curls each service's health endpoint and aborts the rollout
if either fails — the previous versioned binary stays in place for
rollback via symlink.

## Adding a third service

The pattern:

1. Subcommand entrypoint in `cmd/server/<name>.go` implementing
   `run<Name>(args []string) error`, wired into `dispatch()` in
   `cmd/server/main.go`.
2. A `domain.<Name>Repository` and matching `store.<Name>Store` pair in
   `internal/domain/<name>.go` and `internal/store/<name>_store.go`.
3. A separate embedded migration directory, e.g.
   `internal/db/<name>_migrations/`, surfaced as `db.Open<Name>(path)`.
4. Service and handler packages under `internal/service/` and
   `internal/handler/<name>/`.
5. A `deploy/<name>.service` systemd unit + `deploy/<name>-env.example`.
6. Update `deploy/install.sh` to install the new unit and create the
   env file stub.
7. Either reuse identity's JWT via JWKS (like config does) or generate
   your own issuer — don't share the identity DB for secrets.

The config service is the canonical reference for this pattern.
