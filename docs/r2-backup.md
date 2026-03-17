# Cloudflare R2 Database Backup

The Identity service can automatically back up its SQLite database to Cloudflare R2 (S3-compatible object storage). Backups happen:

- **On every new login** (async, non-blocking)
- **Daily at 03:00 UTC**
- **On demand** via the admin UI at `/admin/backup`

If R2 is not configured, the service runs without backups and logs a warning on startup.

---

## Setup

### 1. Create an R2 bucket

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com) → **R2** → **Overview**
2. Click **Create bucket**
3. Name it (e.g. `identity-sqlite`)
4. Leave defaults (no public access needed)

### 2. Create an API token

1. In the R2 overview, click **Manage R2 API Tokens**
2. Click **Create API token**
3. Set permissions: **Object Read & Write**
4. Scope it to your bucket (`identity-sqlite`)
5. Click **Create API Token**
6. Save the **Access Key ID** and **Secret Access Key** — they're shown once

### 3. Find your Account ID

Your Cloudflare Account ID is in the dashboard URL:

```
https://dash.cloudflare.com/<account-id>/r2/overview
```

Or look in the right sidebar of any Cloudflare dashboard page under **Account ID**.

### 4. Configure the service

Set the four environment variables:

```bash
R2_ACCOUNT_ID=your-account-id
R2_ACCESS_KEY_ID=your-access-key-id
R2_SECRET_ACCESS_KEY=your-secret-access-key
R2_BUCKET_NAME=identity-sqlite
```

If using the systemd deployment, add these to `/etc/identity/env`:

```bash
sudo nano /etc/identity/env
```

Then restart:

```bash
sudo systemctl restart identity
```

---

## Verifying it works

### Check startup logs

```bash
sudo journalctl -u identity -n 20
```

If configured correctly, you will **not** see the "R2 backup not configured" warning. Backup success and failure are logged to stdout (visible via `journalctl`) and recorded as audit events.

### Trigger a manual backup

1. Log into the admin UI
2. Click **Dashboard** → **Run backup now**

Or create a user (any login triggers an async backup).

### List backups

```bash
./identity-server --list-backups
```

Output:
```
Listing backups for environment: production

#     Date                      Size  Key
────────────────────────────────────────────────────────────────────
1     2026-03-17 17:17:37      100KB  production/backups/2026/03/17/identity-...
2     2026-03-17 17:09:46        4KB  production/backups/2026/03/17/identity-...

2 backup(s) found.
```

---

## Backup format

Each backup is a complete copy of the SQLite database file. Backups are separated by environment:

```
<env>/backups/YYYY/MM/DD/identity-<RFC3339-timestamp>.sqlite3
```

For example:
```
production/backups/2026/03/17/identity-2026-03-17T14:30:00Z.sqlite3
development/backups/2026/03/17/identity-2026-03-17T10:00:00Z.sqlite3
```

The environment is set by `IDENTITY_ENV` (defaults to `development`).

---

## Restoring from a backup

### Using the built-in command (recommended)

```bash
# Stop the service
sudo systemctl stop identity

# Interactive — shows a list and lets you pick
sudo -u identity ./identity-server --restore-backup

# Or specify a key directly
sudo -u identity ./identity-server --restore-backup "production/backups/2026/03/17/identity-2026-03-17T14:30:00Z.sqlite3"

# Start the service
sudo systemctl start identity
```

The restore command prompts for confirmation before overwriting the database, downloads the file, and sets 600 permissions.

---

## Retention

The service does not delete old backups. R2 supports [lifecycle rules](https://developers.cloudflare.com/r2/buckets/object-lifecycles/) to auto-expire old objects. Recommended:

1. In the Cloudflare dashboard → R2 → your bucket → **Settings** → **Object lifecycle rules**
2. Add a rule: delete objects older than 30 days (or whatever suits your needs)

---

## Disabling backups

Simply don't set the `R2_*` environment variables. The service logs a warning and runs normally without backups.
