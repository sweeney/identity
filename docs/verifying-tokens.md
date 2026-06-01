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
    // claims.UserID, claims.Username, claims.Role, claims.IsActive
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

## Notes

- **Issuer vs. IssuerURL.** `IssuerURL` is where JWKS is fetched; `Issuer` is the
  expected `iss` claim. They're usually identical, but differ if Identity sits
  behind a reverse proxy that rewrites the host.
- **Audience.** Set `RequiredAudience` to reject tokens not minted for your
  service. Service tokens always carry an `aud`; user tokens carry one only when
  the login/authorize request specified it.
- **Errors.** Only `ErrTokenExpired` and `ErrTokenInvalid` are returned from the
  parse calls — map both to `401`, and map a failed `HasScope` check to `403`.
- **Versioning.** The `common` module is pinned to an exact version by consumers;
  see the release flow in the repo root `CLAUDE.md`. Bump with
  `go get github.com/sweeney/identity/common@vX.Y.Z`.

See [`api.md` → JWT Token Structure](api.md#jwt-token-structure) for the claim
fields, and [`api.md` → Discovery (RFC 8414)](api.md#discovery-rfc-8414) for the
JWKS and metadata endpoints.
