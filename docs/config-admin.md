# Config service — administrator guide

Operational notes for running the config service: namespace design,
backups, restore, role changes, identity-coupling concerns. For the
integration surface, see [`config.md`](config.md).

## Creating namespaces

Only admin users can create namespaces. Each create call must supply
`name`, `read_role`, `write_role`, and an initial `document` (which may
be `{}`).

```bash
curl -s -X POST https://config.example.com/api/v1/config/namespaces \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name":       "mqtt_topics",
    "read_role":  "user",
    "write_role": "admin",
    "document":   { "temperature": "home/sensors/temp" }
  }'
```

Names must match `^[a-z0-9_-]{1,64}$`. Keep them descriptive but short:
`mqtt_topics`, `house_names`, `sensor_locations`, `prefs`.

## Choosing roles

Defaults that age well:

- **Admin-only for everything operational.** MQTT broker passwords (even
  if you shouldn't store those here), device serial numbers, network
  topology. `read_role: admin`, `write_role: admin`.
- **User-readable for discovery data.** MQTT topic names, friendly names,
  location coords. `read_role: user`, `write_role: admin`.
- **User-writable only when genuinely user data.** Per-user UI prefs,
  dashboard layouts. `read_role: user`, `write_role: user`.

Users cannot delete namespaces or change ACLs regardless of `write_role`
— both operations are admin-only.

### Changing roles later

Use `PATCH /api/v1/config/namespaces/{ns}` with the new `read_role` and
`write_role`. The document is untouched. Note that tightening
`read_role` from `user` to `admin` will immediately start returning 404
to in-flight user requests — there is no grace period.

```bash
curl -s -X PATCH \
  https://config.example.com/api/v1/config/namespaces/mqtt_topics \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"read_role":"admin","write_role":"admin"}'
```

## Document design patterns

### Flat keys for loose collections

```json
{
  "main": "Rivendell",
  "guest": "Hobbiton",
  "holiday": "Lothlorien"
}
```

Good for: friendly name lookups, topic-to-device mappings, mode flags.
Reads return the whole object; callers extract the one they need.

### Nested objects for structured records

```json
{
  "kitchen": {
    "topic": "home/kitchen/temp",
    "device_id": "esp32-kitchen",
    "calibration_offset": -0.4
  },
  "living_room": {
    "topic": "home/living_room/temp",
    "device_id": "esp32-living",
    "calibration_offset": 0.0
  }
}
```

Good for: when each entry has multiple attributes. Don't abuse this for
more than ~50 entries — consider splitting by category into multiple
namespaces (`sensors_indoor`, `sensors_outdoor`, …) if you cross that.

### Size hygiene

Documents are capped at **64KB** after JSON compaction. The cap exists
to protect the backup pipeline and to discourage using the config
service as a blob store. If you're bumping the cap, you probably want a
different data store (a tiny DB, a file, a proper CMS).

## Backups

### On-write triggers

Every successful `POST`/`PUT`/`PATCH`/`DELETE` triggers an async R2
upload. The backup manager coalesces triggers within a cooldown window
(`BACKUP_MIN_INTERVAL`, default **30s**): rapid bursts collapse into
one upload at the end of the window.

RPO implications:
- **Slow-trickle writes** (once-in-a-while admin edits) → each write
  has its own backup ≤ 30s after it returns.
- **Script storm** (100 writes in 10s) → one backup at T+30s, covering
  the whole burst. Data in between is not individually recoverable.

If your workload has critical write-every-N-seconds traffic, either set
`BACKUP_MIN_INTERVAL=0` (disable throttling; every write uploads) or
increase R2 pricing / capacity planning accordingly. For a homelab the
default is right.

### Scheduled backups

A daily snapshot runs at **03:00 UTC** regardless of write activity.
This is independent of the per-write trigger and cannot be disabled
short of removing R2 credentials from the env.

### Failure handling

Failed backups log to stdout and increment the audit trail but do **not**
fail the user's request. Rationale: a successful PUT has already been
committed to SQLite; surfacing the backup error to the caller would
imply an all-or-nothing guarantee we don't provide. Monitor the logs
or audit stream for sustained `backup: upload failed` entries.

### R2 key layout

```
{env}/backups/config/{YYYY/MM/DD}/config-{RFC3339-timestamp}.sqlite3
```

Example:

```
production/backups/config/2026/04/24/config-2026-04-24T15:30:45Z.sqlite3
```

This is distinct from identity's path (`…/backups/identity/…`) and from
any legacy identity path from before the per-service layout. See
[`r2-backup.md`](r2-backup.md) for the full key taxonomy and restore
procedure for both services.

## Restoring from backup

```bash
# List available config backups
./identity-server config --list-backups

# Restore the most recent (interactive picker)
./identity-server config --restore-backup

# Or restore a specific key
./identity-server config --restore-backup \
  production/backups/config/2026/04/24/config-2026-04-24T15:30:45Z.sqlite3
```

The restore writes to the path from `DB_PATH` (default `config.db`). Stop
the config service before restoring — the restore CLI overwrites the
file even if the service is running, which will corrupt the SQLite WAL.

```bash
sudo systemctl stop config
sudo -u identity ./identity-server config --restore-backup
sudo systemctl start config
```

## Identity coupling

The config service depends on identity at runtime for token verification
via JWKS. It does **not** depend on identity for:

- Startup (config boots standalone; tokens just all fail until identity
  is reachable again)
- Database (fully separate SQLite file)
- Backups (separate R2 prefix)

If identity is down, config continues to serve cached JWKS but new
tokens will eventually fail to verify when the cache expires
(`JWKS_CACHE_TTL`, default 5 minutes). For a homelab deployment where
both services run on the same host behind the same tunnel, this is
rarely a concern in practice.

### Rotating identity's JWT key

When you run `./identity-server --rotate-jwt-key`, the config service
will see unknown `kid` in incoming tokens and refetch JWKS automatically.
No restart needed. Throttling prevents a bad-token storm from stampeding
identity; observed fetch rate is bounded by `RefetchMinInterval`
(default 10s).

## Configuration reference

Environment variables for the config service (systemd env file typically
at `/etc/identity/config.env`):

| Variable | Default | Notes |
|---|---|---|
| `PORT` | `8282` | Listen port |
| `DB_PATH` | `config.db` | SQLite file |
| `IDENTITY_ENV` | `development` | `production` requires HTTPS for identity |
| `IDENTITY_ISSUER_URL` | `http://localhost:8181` (dev) | Required in production |
| `IDENTITY_ISSUER` | `IDENTITY_ISSUER_URL` | Expected JWT `iss` claim |
| `JWKS_CACHE_TTL` | `5m` | Duration string |
| `BACKUP_MIN_INTERVAL` | `30s` | Duration; 0 disables throttling |
| `TRUST_PROXY` | (unset) | `cloudflare` honours `CF-Connecting-IP` |
| `CORS_ORIGINS` | (unset) | Comma-separated allowed origins |
| `RATE_LIMIT_DISABLED` | `0` | `1` disables rate limiting (dev/test only) |
| `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET_NAME` | (unset) | Required together for backups |
