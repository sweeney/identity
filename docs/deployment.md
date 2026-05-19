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
