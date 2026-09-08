# Verifying Identity tokens in a Go service

This guide is for **resource servers** — Go services that *receive* Identity-issued
access tokens (in an `Authorization: Bearer <jwt>` header) and need to verify them
before trusting the request. This is the other side of the flows in
[`api.md`](api.md): those describe apps that *obtain* tokens; this describes
services that *validate* them.

> **Do not trust an unverified JWT.** A JWT payload is just base64url-encoded
> JSON — anyone can decode and forge one. The signature is the only thing that
> proves a token came from Identity. The `printJWTClaims` helper in
> `examples/client-credentials-demo` decodes *without* verifying; it is for
> displaying your own freshly-issued token, **not** for authorizing requests.

Identity signs tokens with **ES256** (ECDSA P-256) and publishes its public keys
at `GET /.well-known/jwks.json`. A consuming service verifies signatures against
that JWKS — it never needs the private key.

## Use the `common/auth` module

Don't copy Identity's internal signing code — it lives under `internal/` (not
importable from other modules) and holds the private key. Instead, depend on the
purpose-built, self-contained module:

```bash
go get github.com/sweeney/identity/common@v0.1.0
```

`common/auth.JWKSVerifier` fetches and caches Identity's public keys and verifies
both user and service tokens. It implements the same `TokenParser` interface
Identity uses internally, so middleware written against it is portable.

## Construct a verifier

```go
import commonauth "github.com/sweeney/identity/common/auth"

verifier, err := commonauth.NewJWKSVerifier(commonauth.JWKSVerifierConfig{
    IssuerURL: "https://id.swee.net", // JWKS fetched from {IssuerURL}/.well-known/jwks.json
    Issuer:    "https://id.swee.net", // expected `iss` claim; required

    // Optional:
    RequiredAudience: "https://my-service.example.com", // assert `aud` if set
    // HTTPClient, CacheTTL (default 5m), RefetchMinInterval (default 10s)
})
if err != nil {
    log.Fatal(err)
}
```

`NewJWKSVerifier` does no network I/O — keys are fetched lazily on the first
`Parse`. Construct it once at startup and share it (it is safe for concurrent
use). **Key rotation is handled for you:** keys are cached with a time-based TTL
and additionally refetched on a `kid` miss (throttled by `RefetchMinInterval`),
so a rotated signing key is picked up without a restart.

## Verify a user token

```go
claims, err := verifier.Parse(ctx, tokenStr)
switch {
case errors.Is(err, commonauth.ErrTokenExpired):
    // 401 — client should refresh and retry
case errors.Is(err, commonauth.ErrTokenInvalid):
    // 401 — bad signature, wrong issuer, malformed, etc.
case err != nil:
    // unexpected
default:
    // claims.UserID, claims.Username, claims.Role, claims.IsActive, claims.Audience
}
```

`Parse` rejects service (client-credentials) tokens, so a machine token can never
be mistaken for a user. Use `ParseServiceToken` for those.

## Verify a service (client-credentials) token

```go
sc, err := verifier.ParseServiceToken(ctx, tokenStr)
if err != nil {
    // ErrTokenExpired / ErrTokenInvalid as above
}
if !sc.HasScope("read:users") {
    // 403 insufficient_scope
}
// sc.ClientID, sc.Audience, sc.Scope, sc.JTI, sc.ExpiresAt, sc.IssuedAt
```

`ParseServiceToken` rejects user tokens (it requires the RFC 9068 `at+jwt` type
header), so the two token kinds can't be confused.

## Wire it into HTTP middleware

`JWKSVerifier` is a drop-in for any code expecting a `TokenParser`. A minimal
middleware:

```go
func RequireAuth(v *commonauth.JWKSVerifier, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        h := r.Header.Get("Authorization")
        parts := strings.SplitN(h, " ", 2)
        if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
            w.Header().Set("WWW-Authenticate", "Bearer")
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        claims, err := v.Parse(r.Context(), parts[1])
        if err != nil {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        if !claims.IsActive {
            http.Error(w, "forbidden", http.StatusForbidden)
            return
        }
        ctx := context.WithValue(r.Context(), claimsKey, claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

Identity's own `internal/auth.RequireAuth` follows this exact shape — it just
takes the `TokenParser` interface, so it accepts the in-process `*TokenIssuer`
or a `*JWKSVerifier` interchangeably.

## Observability

Pass an optional `*slog.Logger` to receive structured output for JWKS fetch
failures, key rotations, and stale-cache fallbacks:

```go
verifier, _ := commonauth.NewJWKSVerifier(commonauth.JWKSVerifierConfig{
    IssuerURL: "https://id.swee.net",
    Issuer:    "https://id.swee.net",
    Logger:    slog.Default(), // omit for no logging
})
```

For metrics, poll `Metrics()` — a lock-free snapshot of counters and cache
state — from your `/metrics` or `/healthz` handler and map it onto your backend:

```go
m := verifier.Metrics()
// m.Fetches, m.FetchErrors, m.KidMisses, m.Rotations, m.StaleServed,
// m.KeyCount, m.FetchedAt, m.LastFetchError
```

The verifier deliberately exposes a **pull snapshot** rather than firing
consumer callbacks: no foreign code runs inside its locked, latency-sensitive
verification path, so a slow or panicking metrics sink can't stall or crash
token verification.

> Don't treat `FetchedAt` as a liveness signal. It's zero until the first token
> is verified (lazy fetch), and an *old* `FetchedAt` is the normal steady state —
> keys are cached and only refetched on TTL expiry or a `kid` miss.

## Notes

- **Issuer vs. IssuerURL.** `IssuerURL` is where JWKS is fetched; `Issuer` is the
  expected `iss` claim. They're usually identical, but differ if Identity sits
  behind a reverse proxy that rewrites the host.
- **Audience.** Set `RequiredAudience` to reject tokens not minted for your
  service. Service tokens always carry an `aud`; user tokens carry one only when
  they were minted through the OAuth, device or claim-code grants, in which case
  it is the requesting client's configured audience. A token from a direct
  `/api/v1/auth/login` carries none.

  Both `TokenClaims.Audience` and `ServiceTokenClaims.Audience` are `[]string`,
  holding the `aud` claim verbatim, and both types have a `HasAudience(aud)`
  helper. Test membership with it rather than comparing or splitting strings: a
  space is legal inside a single `aud` value, so joining the list and
  re-splitting it is lossy in both directions. `Parse` and `ParseServiceToken`
  both populate the field.

  Setting `RequiredAudience` is the belt to `HasAudience`'s braces — it makes
  the JWT parser itself reject a non-matching `aud`, and (because it requires
  the claim to be present) also rejects tokens that carry no audience at all.

- **Turn enforcement on in warn-only mode first.** `RequiredAudienceWarnOnly`
  makes the check an observation rather than a gate: a token that fails is still
  accepted, and the mismatch is logged at warn level with the subject, the
  audience presented and the one expected.

  ```go
  RequiredAudience:         "my-service",
  RequiredAudienceWarnOnly: true,   // observe for a few days, then remove
  ```

  Without this, switching enforcement on is a guess. Identity's clients table
  tells you which registered clients *could* satisfy an audience; it cannot tell
  you which callers actually exist. A caller that is not a registered client at
  all — another resource server, a script, something nobody remembers — appears
  only when it breaks. Run warn-only, read the log, then enforce on evidence.

  Watch for `subject` values you do not recognise and for tokens with an empty
  `presented_audience`, which is the case enforcement breaks hardest.
- **Errors.** Three errors come back from the parse calls, and the distinction
  matters:

  | Error | Meaning | Map to |
  |---|---|---|
  | `ErrTokenExpired` | The token was valid and has aged out | `401` — the client should refresh |
  | `ErrTokenInvalid` | Bad signature, wrong issuer, malformed | `401` — the client should sign in again |
  | `ErrKeysUnavailable` | **We could not check it.** JWKS unreachable, erroring, or cached keys too stale to trust | `503` — the client should retry |

  Do not fold `ErrKeysUnavailable` into a `401`. It is a statement about
  identity's availability, not a verdict on the caller's token: treating it as
  "invalid" makes every service sign every user out simultaneously during an
  identity outage, over tokens that were never examined. A failed `HasScope`
  check is a `403`.

  Cached keys are served through a brief JWKS outage, but only up to
  `MaxStaleAge` (default 30 minutes) — past that the verifier reports
  `ErrKeysUnavailable` rather than continuing to honour keys it can no longer
  confirm are published, which would otherwise make key revocation ineffective
  for as long as the endpoint stayed down.
- **Versioning.** The `common` module is pinned to an exact version by consumers;
  see the release flow in the repo root `CLAUDE.md`. Bump with
  `go get github.com/sweeney/identity/common@vX.Y.Z`.

See [`api.md` → JWT Token Structure](api.md#jwt-token-structure) for the claim
fields, and [`api.md` → Discovery (RFC 8414)](api.md#discovery-rfc-8414) for the
JWKS and metadata endpoints.
