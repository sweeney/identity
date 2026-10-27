# Deployment guide

This repo produces a single Go binary, `identity-server`, that runs the
identity service.

## Binary install

The install script drops the binary to `/opt/identity/bin/` with a
versioned filename plus a `current` symlink, creates the `identity`
system user, and writes the systemd unit.

```bash
sudo ./deploy/install.sh /path/to/built/identity-server
```

## Env files

| Path | Purpose | Owner |
|---|---|---|
| `/etc/identity/env` | Identity service env | `root:root` 0600 |

Loaded by the systemd unit via `EnvironmentFile=`.
See `deploy/env.example` for every variable with defaults.

## State layout

The service uses `/var/lib/identity/`, owned by the `identity` user
with mode 0700:

```
/var/lib/identity/
├── identity.db
├── identity.db-wal
└── identity.db-shm
```

R2 backups use the prefix:

```
{env}/backups/identity/{YYYY/MM/DD}/identity-{ts}.sqlite3
```

Legacy identity backups (before the per-service layout) at
`{env}/backups/{YYYY/MM/DD}/identity-{ts}.sqlite3` remain discoverable
via `--list-backups`.

## Port layout

| Service | Default port |
|---|---|
| identity | 8181 |

Override via `PORT` in the env file. Typical production fronts the
service with Cloudflare Tunnel: `id.example.com → :8181`.

## Deploy flow

```bash
./deploy/deploy.sh sweeney@garibaldi     # build + deploy + restart
```

The deploy script uploads the new binary (versioned), atomically
swings the `current` symlink, and restarts the unit. It then curls
the service's health endpoint and aborts the rollout if it fails —
the previous versioned binary stays in place for rollback via symlink.

### Before a risky deploy: snapshot and rehearse

```bash
./deploy/rehearse-deploy.sh --check sweeney@garibaldi   # no sudo, nothing written on the host
./deploy/rehearse-deploy.sh sweeney@garibaldi           # one sudo prompt
```

`rehearse-deploy.sh` reads the version production runs from `/health`, builds
it and this checkout's HEAD, and snapshots the live database on the host with
SQLite's online backup (`deploy/snapshot-db.sh`; safe while identity runs in
WAL mode). The snapshot stays on the host under
`/var/lib/identity/snapshots/`, mode 0600, as the pre-deploy backup. A copy is
fetched to a private temp dir, where `deploy/rehearse-upgrade.sh` boots the new
binary on it, boots it again, rolls back to the old binary and forward again,
checking the schema, the durable row counts and the migrations ledger at each
step. The local copy is deleted afterwards, pass or fail. `--check` does the
same against a database the production version builds itself.

Run it in a terminal (sudo needs one for the password). The scripts' tests are
`deploy/snapshot-db.test.sh` and `deploy/rehearse-deploy.test.sh`; both run
entirely on this machine.

To roll back, point the symlink at the previous versioned binary and restart:

```bash
ssh sweeney@garibaldi 'ln -sfn identity-server-<previous> /opt/identity/bin/identity-server && sudo systemctl restart identity'
```
