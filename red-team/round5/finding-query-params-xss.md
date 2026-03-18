# Finding: Query Parameter Exposure & Passkey Name XSS Assessment

**Date:** 2026-03-18
**Target:** id.swee.net (identity-src)
**Severity:** Low (query param exposure) / Not Exploitable (XSS)

---

## 1. Query Parameter Usage Confirmed

Both WebAuthn finish endpoints accept sensitive parameters via query string rather than request body:

**API handler** (`internal/handler/api/webauthn.go`):
- `POST /api/v1/webauthn/register/finish?challenge_id=<uuid>&name=<label>` (lines 45-46)
- `POST /api/v1/webauthn/login/finish?challenge_id=<uuid>` (line 101)

**Admin handler** (`internal/handler/admin/handler.go`):
- `POST /admin/passkeys/register/finish?challenge_id=<uuid>&name=<label>` (lines 407-408)

In all cases, `r.URL.Query().Get()` is used to extract the values. The `challenge_id` is a server-generated UUID, and `name` is a user-supplied passkey label.

## 2. Log Exposure

### Server request logging

The server uses Go's standard `net/http` without explicit request logging middleware. There is no access log middleware that would log full request URLs. The `log.Printf` calls in `main.go` only log startup/shutdown messages.

### Audit log exposure

The audit store (`internal/store/audit_store.go`, line 26) emits structured log lines to stdout:

```
log.Printf("audit: %s user=%s detail=%s ip=%s", event.EventType, event.Username, event.Detail, event.IPAddress)
```

These audit events do **not** include the request URL or query parameters. The `challenge_id` and `name` values are not captured in audit events. The passkey registration success event records only the event type, user ID, and username -- not the passkey name or challenge ID.

### Risk assessment

The `challenge_id` is a UUID that maps to an ephemeral challenge with a 120-second TTL, deleted after use. Even if logged, replay is not possible. However, query parameters in POST requests are an anti-pattern because:

- They appear in `Referer` headers if the page navigates after the POST
- They may be logged by reverse proxies (nginx, Cloudflare) or WAFs
- They are visible in browser history (though these are API calls, not navigations)

Since the server sits behind a Cloudflare Tunnel (`TRUST_PROXY=cloudflare`), Cloudflare's edge logs could capture the full URL including query strings. The `name` parameter could contain PII if users name passkeys after devices (e.g., "John's MacBook Pro").

**Recommendation:** Move `challenge_id` and `name` to the POST request body (JSON). These are POST endpoints already receiving a request body (the WebAuthn attestation/assertion), so adding fields is trivial.

## 3. Passkey Name Sanitization

### No input validation on name

The `name` parameter flows through with zero sanitization:

1. **API handler** (`webauthn.go:46`): `name := r.URL.Query().Get("name")` -- raw from query string
2. **Service** (`webauthn_service.go:189`): `Name: name` -- stored directly into domain object
3. **Store**: Stored directly in SQLite via parameterized query (no SQL injection, but no content validation)

There is no length limit, no character filtering, no HTML entity encoding at the storage layer. The `RenameCredential` path (`webauthn.go:186`) also passes the name through without sanitization, though it reads from a JSON body field rather than a query parameter.

### What can be injected

An attacker with a valid session can register a passkey with any name, including:
- `<script>alert(1)</script>`
- `<img src=x onerror=alert(1)>`
- Very long strings (no length limit)
- Null bytes, control characters, unicode abuse

## 4. XSS via Passkey Name -- NOT EXPLOITABLE

### Template engine provides auto-escaping

The admin UI uses Go's `html/template` package (confirmed in `internal/handler/admin/router.go:1` and `handler.go:10`), which **automatically HTML-escapes all interpolated values**.

### Rendering locations

Passkey names are rendered in two templates:

**`passkeys.html` (line 14):**
```
<td>{{if .Name}}{{.Name}}{{else}}<em>unnamed</em>{{end}}</td>
```

**`user_form.html` (line 58):**
```
<td>{{if .Name}}{{.Name}}{{else}}<em>unnamed</em>{{end}}</td>
```

In both cases, `{{.Name}}` uses the default Go template action, which in `html/template` applies context-aware escaping. A name like `<script>alert(1)</script>` would be rendered as `&lt;script&gt;alert(1)&lt;/script&gt;` in the HTML output.

### No unsafe template functions

Neither template uses `template.HTML()`, `template.JS()`, or any other mechanism to bypass the auto-escaping. There are no `| safe` filters or equivalent. The `template.FuncMap` in `router.go:23` is empty.

### Audit log template

The audit log template (`audit_log.html`) does not display passkey names at all. It shows event types, usernames, detail strings, and IP addresses -- all auto-escaped by `html/template`.

### Verdict

**Stored XSS via passkey name is not exploitable.** Go's `html/template` auto-escaping effectively neutralizes any HTML/JS injection in the passkey name field.

## 5. Residual Risks

Despite XSS being blocked, the lack of name validation has minor consequences:

| Issue | Impact |
|-------|--------|
| No length limit on passkey name | UI disruption -- very long names could break table layout |
| No character filtering | Unicode abuse could cause rendering issues (RTL override, zero-width chars) |
| Query param exposure of `name` | PII in proxy/CDN logs; `Referer` header leakage |
| Query param exposure of `challenge_id` | Minimal -- ephemeral UUID with 120s TTL, single-use |

## 6. Recommendations

1. **Move `challenge_id` and `name` to POST body** -- These are POST endpoints; query params on POST is an anti-pattern. The WebAuthn attestation JSON body could be wrapped in an envelope, or sent as separate form fields.

2. **Add name validation** -- Limit passkey names to 100 characters, alphanumeric + spaces + basic punctuation. Reject or strip control characters.

3. **Add name sanitization at storage time** -- Even though the template engine escapes output, defense-in-depth suggests sanitizing at write time too.

---

## Files Examined

- `/internal/handler/api/webauthn.go` -- API WebAuthn handlers
- `/internal/handler/admin/handler.go` -- Admin UI handlers including passkey management
- `/internal/handler/admin/router.go` -- Router setup, template initialization
- `/internal/service/webauthn_service.go` -- WebAuthn business logic
- `/internal/store/audit_store.go` -- Audit event persistence and logging
- `/internal/ui/templates/passkeys.html` -- Passkey list template
- `/internal/ui/templates/user_form.html` -- User edit form with passkeys section
- `/internal/ui/templates/audit_log.html` -- Audit log display template
- `/cmd/server/main.go` -- Server setup, middleware chain
