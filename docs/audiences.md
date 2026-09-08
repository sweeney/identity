# Audiences: what `aud` is for, and what to put in it

This is the guide to the **Audience** field you are asked for when registering
an OAuth client at `/admin/oauth`. It exists because that field has no obvious
right answer, and getting it wrong fails in confusing ways — a token that works
against one service and is silently refused by another.

---

## What `aud` is for

The `aud` claim names the service a token is *for*. A recipient is supposed to
reject a token that does not name it (RFC 7519 §4.1.3).

The point is containment. Tokens leak — into logs, crash reports, proxies, error
trackers — and a service that holds your token can always present it somewhere
else. `aud` is what stops a token that reached service A from being usable
against service B.

The sharpest version of that concern, and the reason this is enforced at all:

> An admin signs in through an app registered for some downstream service. That
> app's token identifies an admin. If nothing checks `aud`, whoever holds it —
> the app, the service it talks to, anyone who compromises either — can present
> it to `POST /api/v1/users` and create themselves an admin account.

Two controls stand in the way of that: the **role** check, and the **audience**
check. The role check does not help here, because the subject really is an
admin. Audience is the one doing the work.

---

## How Identity uses it

**Minting.** A client's registered Audience becomes the `aud` claim on every
user token minted through it — authorization code, device grant and claim code
alike. A client with an empty Audience mints tokens with no `aud` at all. Tokens
from the direct API login (`POST /api/v1/auth/login`) never carry one, because
no client is involved.

**The registration is authoritative, on every rotation.** A refresh re-reads the
client's current Audience rather than replaying the set captured when the grant
was created. Editing a client's Audience therefore reaches live sessions within
one access-token lifetime (~15 minutes) instead of waiting for every user to
sign in again:

- **Removing** an audience withdraws it. This is what makes the Audience field
  usable as a revocation control — before, a client that kept refreshing held
  its original set indefinitely, because rotation grants a fresh refresh TTL and
  nothing caps the chain.
- **Adding** one reaches existing sessions on their next refresh, so a resource
  server can start requiring an audience without signing everyone out first.
- A client whose registration has been **deleted** mints no `aud` at all from
  its next rotation onward.

A token from the direct API login has no client, so there is no registration to
consult and its (absent) audience is carried forward unchanged.

The set still cannot be *widened by the client*: it comes from the registration,
which only an admin can edit, never from anything the client sends.

**Two planes.** Identity's own routes are split by what they do, not only by
who may call them:

| Plane | Routes | Rule |
|---|---|---|
| Ordinary | `/api/v1/auth/*`, `GET /api/v1/users/{id}` | `aud` is absent **or** names this server |
| Management | `GET`/`POST` `/api/v1/users`, `PUT`/`DELETE` `/api/v1/users/{id}`, `POST /admin/login/passkey` | `aud` is absent **or** names this server **and nothing else** |

The management rule is stricter because a multi-audience token is a live bearer
credential at every service it names. A client that calls `/api/v1/auth/me`
legitimately needs identity in its list, so the normal shape names identity
*alongside* several siblings — and any one of those siblings, compromised, would
otherwise hold something that can create and delete users here as soon as the
account behind it is an admin.

An absent `aud` passes both: a direct `/api/v1/auth/login` token was never
delegated anywhere, which is the strongest position a token can be in, not the
weakest. So an admin signing in directly keeps full access, and an admin using a
delegated client does not — they administer through the admin UI, or through a
client registered for this server alone.

`GET /api/v1/users/{id}` stays on the ordinary plane deliberately: it is how a
user reads their own record, a self-service read rather than administration.

**Checking.** `RequireAudience` guards every `/api/v1/*` route, and the three
public passkey bridges check the same rule directly. A token is accepted when:

| Token | Accepted when `aud` is |
|---|---|
| User token | absent, **or** names this server |
| Service token (`client_credentials`) | names this server — absent is a rejection |

"Names this server" means the configured issuer (`https://id.swee.net`) or that
URL's host (`id.swee.net`). Both spellings are the same service, and Identity is
the authority on which names mean itself. Anything else — including a different
host that merely looks similar — is a different service and is refused with
`403 invalid_audience`.

**Downstream.** Sibling services verify Identity's tokens with
`common/auth.JWKSVerifier`. Audience checking there is **opt-in**: set
`RequiredAudience` in `JWKSVerifierConfig` and the verifier rejects tokens that
do not name the service. Leave it unset and `aud` is ignored entirely.

---

## Choosing a value when you register a client

| The client is… | Audience | Why |
|---|---|---|
| A service talking to one other service (`client_credentials`) | that service's name, e.g. `statehouse` | Narrow by default. Costs nothing and contains a leak completely. |
| A service talking to the Identity API | `id.swee.net` | Names this server. |
| An app whose tokens are only ever used against Identity | `id.swee.net` | Same. |
| An app talking to several services | see below | One field cannot name several services. |
| Unsure, and it only calls Identity | leave empty | No `aud` is accepted by Identity. It is also accepted by every downstream service, so this is the widest option — prefer a real value once you know it. |

**A client may name several services.** RFC 7519 §4.1.3 defines `aud` as a list,
and that is the mechanism for "this token is for these recipients". A native app
that signs in once and talks to statehouse, countinghouse and Identity names all
three:

```json
{ "aud": ["statehouse", "countinghouse", "id.swee.net"] }
```

Select the services on the client form. The list offered is every audience
already in use, plus this server — deliberately *not* client ids, because a
client and a resource server are different things. A service that makes
outbound calls appears because it needs a `client_credentials` registration
(which requires an audience), but a service that only receives tokens never
registers at all, and a browser app like an admin SPA registers and should
never be named as an audience by anyone.

So a resource server that is not a client — the config service, say — is not
listed until something names it. Type it into the free-text box once and it is
offered from then on.

Each named service accepts the token; anything else refuses it. So the client
above can call statehouse and countinghouse and Identity, while a client naming
only `["statehouse"]` can call statehouse and nothing else — including not
Identity.

The remaining option, not implemented here, is **a token per service** (RFC 8707
resource indicators): the client asks for `resource=https://statehouse.swee.net`
and gets a token audienced to just that, requesting another for the next
service. That isolates further — a token leaked from statehouse names only
statehouse — at the cost of a token exchange per service.

---

## Current state of this deployment

Worth stating plainly, because it changes what `aud` is buying today.

**Sibling services are not enforcing audience.** A token minted with
`aud=id.swee.net` is accepted by statehouse, which would reject it if it set
`RequiredAudience`. So the boundary is currently enforced at Identity's own API
and nowhere else. Setting `RequiredAudience` on each service is what turns the
field from documentation into a control.

**`RequireScope` is wired to zero routes**, and it does not read a user token's
`scope` claim — it passes any admin and rejects any non-admin. The device grant
now issues genuinely scoped user tokens (`scope=read:sensors`), so that claim is
currently written and never read. If you want finer control than admin/user,
this is the thing to finish: a scope is a more precise statement than a role.

---

## If user tokens should be broad

A reasonable model is *service tokens narrow, user tokens broad*: once someone
has authenticated, their token works across the whole suite, and roles or scopes
provide the granularity.

The cost is specific, and multi-valued `aud` lets you avoid most of it: a
client that names the services it uses but *not* Identity gets tokens that work
across the suite and cannot administer Identity at all. The escalation at the
top of this document only returns if the client names Identity as well.

If it must — because the app calls `/auth/me` — then the audience check stops
distinguishing for that client, and the role check alone cannot tell a replayed
token from a legitimate one.

That is recoverable without giving up the model, because the distinction that
matters is not Identity-versus-others but **ordinary versus management**:

- `/api/v1/auth/*` — accept the ecosystem audience. Apps call `/auth/me` and
  `/auth/refresh` normally.
- `/api/v1/users/*` and the admin UI — require an audience naming Identity.

A token harvested from a resource service then still works everywhere it is
meant to, and still cannot create an admin. `RequireAudience` is already applied
per-route, so this is a routing change rather than an architectural one.

---

## Errors

| Code | Meaning |
|---|---|
| `403 invalid_audience` | The token names a different service. Check the client's registered Audience against the table above. |

A token rejected this way is not invalid — it is valid, and for somewhere else.
It will keep working against the service it was minted for.
