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

## Debugging from the journal

Every audit event is also written to the journal as one line:

```
audit: <event> user="…" [client="…"] [device="…"] [detail="…"] ip="…"
```

`device` is the caller's User-Agent on token-endpoint and refresh events, or
the declared device name on a login.

**A client says `/oauth/token` failed.** Every refusal logs the grant, the
client, how it authenticated and which required fields arrived. It logs
presence only, never values:

```bash
ssh sweeney@garibaldi 'journalctl -u identity --since "-1h" --no-pager | grep "oauth: token refused"'
# oauth: token refused status=400 error="invalid_request" grant_type="authorization_code"
#   client="muse" client_via=basic auth=client_secret_basic
#   fields=client_id:-,code:+,redirect_uri:+,code_verifier:+ ip="…" ua="…"
```

Device polling's `authorization_pending` and `slow_down` are not logged.

**Something keeps presenting a dead refresh token.**
`refresh_token_revoked_reuse` means the token was revoked on purpose and a
client has not noticed. The detail gives the reason; `client`, `device` and
`ip` say which client it is. `token_family_compromised` is kept for a replay of
a rotated token (or one revoked before migration 014), which is a real theft
signal. Both are throttled to one line per token family, then one summary per
10 minutes:

```bash
ssh sweeney@garibaldi 'journalctl -u identity --since today --no-pager | grep -E "revoked_reuse|token_family_compromised"'
# audit: refresh_token_revoked_reuse user="sweeney" client="thermostat" device="thermo-fw/2.1"
#   detail="reason=password_change repeated=23 since=2026-11-24T10:15:22Z" ip="…"
```

The `auth_events` table holds the same records with the client always set. It
is owned by the `identity` user, so querying it needs sudo on the host.
