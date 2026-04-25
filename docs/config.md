# Config service — integration guide

The config service stores structured homelab configuration as named JSON
documents with per-namespace role ACLs. It runs as a separate process from
identity (default port 8282) and validates JWTs against identity's JWKS
endpoint, so you authenticate exactly the same way you authenticate against
identity itself.

Who this doc is for: application developers and scripts that need to
**read or write** config. For operational topics (creating namespaces,
backups, restore), see [`config-admin.md`](config-admin.md). For a
copy-paste walkthrough with real server output, see
[`config-walkthrough.md`](config-walkthrough.md).

## Concepts

- **Namespace** — a named bucket of config. The namespace *is* a JSON
  object; there are no per-key rows. Writes replace the whole document.
- **ACL** — each namespace has a `read_role` and a `write_role`, each
  one of `admin` or `user`. Admins always satisfy any role requirement;
  users only satisfy `user`.
- **404 vs 403** — callers who lack `read_role` receive **404**, not 403,
  so namespace existence is never leaked. Callers who can read but not
  write receive **403** on write attempts (since they already know the
  namespace exists). Callers who can neither read nor write receive 404
  on any request.

## Authentication

All endpoints except `/healthz` require a Bearer token issued by the
identity service. v1 accepts **user tokens only** — client-credentials
service tokens are rejected with 403. Obtain a token via identity's
`POST /api/v1/auth/login` (see `docs/api.md`).

```
Authorization: Bearer <access_token>
```

Tokens expire in 15 minutes; refresh them against identity as usual. The
config service does no token rotation on its own.

### Key rotation

If identity rotates its JWT signing key (`./identity-server --rotate-jwt-key`),
the config service's JWKS cache will refetch on the first token that carries
the new `kid`. Expect a single additional round-trip; no config restart
needed.

## Endpoints

| Method | Path | Purpose | Role |
|---|---|---|---|
| GET | `/healthz` | Unauth health probe | — |
| GET | `/api/v1/config` | List visible namespaces | read_role |
| GET | `/api/v1/config/{ns}` | Full JSON document | read_role |
| PUT | `/api/v1/config/{ns}` | Replace document | write_role |
| DELETE | `/api/v1/config/{ns}` | Delete namespace | admin |
| POST | `/api/v1/config/namespaces` | Create namespace | admin |
| PATCH | `/api/v1/config/namespaces/{ns}` | Update ACL | admin |

An OpenAPI 3.0 spec is served at `GET /openapi.json` and `GET /openapi.yaml`.

### Error envelope

Errors match the identity convention:

```json
{ "error": "snake_case_code", "message": "Human readable" }
```

Common codes:

| Code | Status | When |
|---|---|---|
| `unauthorized` | 401 | Missing or invalid Bearer token |
| `forbidden` | 403 | Valid token but insufficient role (caller can read) |
| `not_found` | 404 | Namespace missing **or** caller lacks read role |
| `conflict` | 409 | Duplicate `POST /namespaces` |
| `invalid_name` | 400 | Namespace name must match `^[a-z0-9_-]{1,64}$` |
| `invalid_role` | 400 | Role must be `admin` or `user` |
| `invalid_document` | 400 | Document must be a JSON object |
| `invalid_request` | 400 | Malformed JSON body |
| `document_too_large` | 413 | Stored document exceeds 64KB |
| `request_too_large` | 413 | Request body exceeds 128KB |
| `internal_error` | 500 | Server fault — retry, then file an issue |

## Typical flows

### Reading config from a service

```bash
TOKEN=$(curl -s -X POST https://id.example.com/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"svc-bot","password":"…"}' \
  | jq -r .access_token)

curl -s https://config.example.com/api/v1/config/mqtt_topics \
  -H "Authorization: Bearer $TOKEN"
# → {"temperature":"home/sensors/temp","humidity":"home/sensors/humidity"}
```

The returned body is the stored document verbatim — parse it with a plain
JSON decoder.

### Replacing a document

`PUT` is whole-document replacement. If you only want to change one field,
read-modify-write:

```bash
# GET, merge, PUT
DOC=$(curl -s -H "Authorization: Bearer $TOKEN" \
  https://config.example.com/api/v1/config/mqtt_topics)

MERGED=$(echo "$DOC" | jq '.pressure = "home/sensors/pressure"')

curl -s -X PUT https://config.example.com/api/v1/config/mqtt_topics \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$MERGED"
# → {"name":"mqtt_topics","changed":true}
```

A byte-identical (after JSON compaction) PUT returns `{"changed": false}`
and performs no write — safe to script in a loop without hammering R2.

### Listing everything visible to the caller

```bash
curl -s https://config.example.com/api/v1/config \
  -H "Authorization: Bearer $TOKEN"
# → [
#     {"name":"mqtt_topics","read_role":"user","write_role":"admin",
#      "updated_at":"2026-04-24T17:06:34.828Z","created_at":"2026-04-24T17:06:34.828Z"}
#   ]
```

Users see only namespaces whose `read_role` they satisfy; admins see all.

## Client guidance

- **Cache reads on the client side** when they're hot-path. The server does
  no HTTP caching headers; poll on your own TTL, and treat 404 as
  authoritative (no retry).
- **Don't embed secrets.** Config documents are intended for non-secret
  homelab data (topics, IP addresses, friendly names). Treat any writer
  as able to read back everything they wrote.
- **Concurrent edits are last-write-wins.** v1 has no ETag / `If-Match`.
  If you need multi-writer coordination, serialize at the caller.
- **Per-write backups** trigger the R2 upload pipeline. The manager
  coalesces bursts (default 30s window), so rapid successive PUTs result
  in roughly one backup per window. Don't rely on a backup existing the
  instant after a PUT returns.

## Language examples

### Go

```go
req, _ := http.NewRequest("GET",
    "https://config.example.com/api/v1/config/mqtt_topics", nil)
req.Header.Set("Authorization", "Bearer "+token)
resp, err := http.DefaultClient.Do(req)
if err != nil { return err }
defer resp.Body.Close()
if resp.StatusCode == 404 { return ErrNotFound }

var doc map[string]string
if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
    return err
}
```

### Python

```python
import requests
r = requests.get(
    "https://config.example.com/api/v1/config/mqtt_topics",
    headers={"Authorization": f"Bearer {token}"},
    timeout=5,
)
r.raise_for_status()
topics = r.json()
```

### Shell (read-modify-write)

```bash
curl -s -H "Authorization: Bearer $TOKEN" $CFG/api/v1/config/mqtt_topics \
  | jq '.pressure = "home/sensors/pressure"' \
  | curl -s -X PUT -H "Authorization: Bearer $TOKEN" \
         -H 'Content-Type: application/json' \
         --data-binary @- $CFG/api/v1/config/mqtt_topics
```
