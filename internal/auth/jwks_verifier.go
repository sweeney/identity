package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"

	"github.com/sweeney/identity/internal/domain"
)

// TokenParser is the minimal interface that auth middleware needs to
// validate Bearer tokens. Both *TokenIssuer (identity, in-process) and
// *JWKSVerifier (consuming services, over HTTP) implement it.
//
// The ctx parameter bounds network I/O performed during verification
// (e.g. JWKS refetches). In-process implementations are free to ignore it.
type TokenParser interface {
	Parse(ctx context.Context, tokenStr string) (*domain.TokenClaims, error)
	ParseServiceToken(ctx context.Context, tokenStr string) (*domain.ServiceTokenClaims, error)
}

// Compile-time assertion that *TokenIssuer satisfies TokenParser.
var _ TokenParser = (*TokenIssuer)(nil)

// Defaults for JWKSVerifier.
const (
	defaultJWKSCacheTTL   = 5 * time.Minute
	defaultJWKSRefetchMin = 10 * time.Second
	defaultJWKSTimeout    = 10 * time.Second
)

// JWKSVerifierConfig configures a verifier that validates tokens issued by a
// remote identity service via its JWKS endpoint.
type JWKSVerifierConfig struct {
	// IssuerURL is the base URL of the identity service, e.g.
	// "http://localhost:8181". The verifier fetches JWKS from
	// {IssuerURL}/.well-known/jwks.json.
	IssuerURL string
	// Issuer is the expected JWT `iss` claim. Usually the same as
	// IssuerURL, but may differ if identity is behind a reverse proxy.
	// Required.
	Issuer string
	// HTTPClient is used for JWKS fetches. Defaults to a client with a
	// 10s timeout.
	HTTPClient *http.Client
	// CacheTTL is how long fetched JWKS remain valid before a refetch is
	// forced on the next Parse. Defaults to 5 minutes.
	CacheTTL time.Duration
	// RefetchMinInterval throttles refetches triggered by kid-miss to
	// avoid hammering the identity service if a bad token is replayed in
	// a tight loop. Defaults to 10s.
	RefetchMinInterval time.Duration
	// RequiredAudience, when non-empty, asserts that incoming tokens carry
	// a matching `aud` claim. Mitigates cross-service token replay where
	// an identity-issued user token could otherwise authenticate against
	// any sibling service that trusts the same JWKS. Defaults to unset for
	// backward compatibility — turning this on requires identity to stamp
	// a matching audience on issuance.
	RequiredAudience string
}

// JWKSVerifier validates ES256 JWTs against a JWKS served by the identity
// service. Keys are cached in memory with time-based invalidation and
// additionally refreshed on kid miss (so JWT key rotations propagate
// without a restart).
//
// Refetches are deduplicated via singleflight so a storm of concurrent
// cache misses results in a single outbound request, and a stale cache
// keeps serving its existing keys if the identity service is briefly
// unreachable — liveness is preferred over freshness during a blip.
type JWKSVerifier struct {
	issuerURL        string
	issuer           string
	requiredAudience string
	httpClient       *http.Client
	cacheTTL         time.Duration
	refetchMin       time.Duration

	sf singleflight.Group

	mu         sync.RWMutex
	keys       map[string]*ecdsa.PublicKey
	fetchedAt  time.Time
	lastMissAt time.Time
}

// NewJWKSVerifier constructs a JWKSVerifier. No network I/O occurs here —
// the JWKS is fetched lazily on the first Parse call.
func NewJWKSVerifier(cfg JWKSVerifierConfig) (*JWKSVerifier, error) {
	if cfg.IssuerURL == "" {
		return nil, errors.New("IssuerURL is required")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("Issuer is required")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultJWKSTimeout}
	}
	ttl := cfg.CacheTTL
	if ttl == 0 {
		ttl = defaultJWKSCacheTTL
	}
	refetch := cfg.RefetchMinInterval
	if refetch == 0 {
		refetch = defaultJWKSRefetchMin
	}
	return &JWKSVerifier{
		issuerURL:        strings.TrimSuffix(cfg.IssuerURL, "/"),
		issuer:           cfg.Issuer,
		requiredAudience: cfg.RequiredAudience,
		httpClient:       client,
		cacheTTL:         ttl,
		refetchMin:       refetch,
		keys:             map[string]*ecdsa.PublicKey{},
	}, nil
}

// Issuer returns the expected issuer string. Useful for callers that also
// need to configure audience middleware keyed on the issuer URL.
func (v *JWKSVerifier) Issuer() string { return v.issuer }

// Parse validates tokenStr as an identity user access token. Returns
// ErrTokenExpired when the token has expired and ErrTokenInvalid for all
// other validation failures. ctx bounds JWKS refetches.
func (v *JWKSVerifier) Parse(ctx context.Context, tokenStr string) (*domain.TokenClaims, error) {
	if tokenStr == "" {
		return nil, ErrTokenInvalid
	}

	claims := &identityClaims{}
	_, err := v.parseJWT(ctx, tokenStr, claims, func(typ string) error {
		// Service tokens carry typ=at+jwt per RFC 9068; reject them as user tokens.
		if typ == "at+jwt" {
			return errors.New("service token not accepted as user token")
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrTokenInvalid
	}
	return &domain.TokenClaims{
		UserID:   claims.Subject,
		Username: claims.Username,
		Role:     claims.Role,
		IsActive: claims.IsActive,
	}, nil
}

// ParseServiceToken validates tokenStr as an identity service (client_credentials)
// token. Returns ErrTokenInvalid if tokenStr is not a service token. ctx
// bounds JWKS refetches.
func (v *JWKSVerifier) ParseServiceToken(ctx context.Context, tokenStr string) (*domain.ServiceTokenClaims, error) {
	if tokenStr == "" {
		return nil, ErrTokenInvalid
	}

	claims := &serviceClaims{}
	_, err := v.parseJWT(ctx, tokenStr, claims, func(typ string) error {
		if typ != "at+jwt" {
			return errors.New("not a service token")
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrTokenInvalid
	}
	if claims.ClientID == "" {
		return nil, ErrTokenInvalid
	}
	var exp, iat int64
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Unix()
	}
	if claims.IssuedAt != nil {
		iat = claims.IssuedAt.Unix()
	}
	return &domain.ServiceTokenClaims{
		ClientID:  claims.ClientID,
		Audience:  strings.Join(claims.Audience, " "),
		Scope:     claims.Scope,
		JTI:       claims.ID,
		ExpiresAt: exp,
		IssuedAt:  iat,
	}, nil
}

// parseJWT is the shared JWT parsing core. typGuard is called with the token
// header's `typ` field so callers can distinguish user vs. service tokens.
func (v *JWKSVerifier) parseJWT(ctx context.Context, tokenStr string, claims jwt.Claims, typGuard func(string) error) (*jwt.Token, error) {
	return jwt.ParseWithClaims(
		tokenStr,
		claims,
		func(t *jwt.Token) (any, error) {
			// Defence-in-depth: WithValidMethods below already whitelists
			// ES256 by name, but keep the type assertion to rule out any
			// future library change that might widen acceptance.
			if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			typ, _ := t.Header["typ"].(string)
			if typGuard != nil {
				if err := typGuard(typ); err != nil {
					return nil, err
				}
			}
			kid, _ := t.Header["kid"].(string)
			if kid == "" {
				return nil, errors.New("missing kid in token header")
			}
			return v.keyForKid(ctx, kid)
		},
		// Whitelist the exact signing method we trust. *jwt.SigningMethodECDSA
		// matches ES256, ES384, and ES512 — accepting them all would be
		// alg-confusion-adjacent even if the P-256 keys we publish wouldn't
		// actually verify an ES384 signature.
		append(
			[]jwt.ParserOption{
				jwt.WithValidMethods([]string{"ES256"}),
				jwt.WithIssuer(v.issuer),
				jwt.WithExpirationRequired(),
			},
			v.optionalAudienceOption()...,
		)...,
	)
}

// optionalAudienceOption returns a ParserOption slice that asserts the
// required audience when configured, or an empty slice otherwise.
// Keeping the default off preserves backward compatibility — identity
// does not currently stamp audiences on user tokens.
func (v *JWKSVerifier) optionalAudienceOption() []jwt.ParserOption {
	if v.requiredAudience == "" {
		return nil
	}
	return []jwt.ParserOption{jwt.WithAudience(v.requiredAudience)}
}

// keyForKid returns the public key with the given kid. It refreshes the
// JWKS cache when the key is missing or the cache is stale.
//
// Availability properties:
//   - Refetches run under a singleflight group: N concurrent cache misses
//     result in one outbound HTTP request, not N.
//   - If a refetch fails AND the kid is still in the (stale) cache, the
//     cached key is returned with a warning log — we prefer serving a
//     stale-but-valid key over blocking all auth on a transient JWKS blip.
//   - Repeated kid misses are rate-limited via refetchMin to prevent a
//     bad-token storm from stampeding the identity service.
func (v *JWKSVerifier) keyForKid(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	v.mu.RLock()
	key, have := v.keys[kid]
	stale := time.Since(v.fetchedAt) > v.cacheTTL
	throttled := !have && !v.fetchedAt.IsZero() && time.Since(v.lastMissAt) < v.refetchMin
	v.mu.RUnlock()

	if have && !stale {
		return key, nil
	}
	if !have && throttled {
		return nil, fmt.Errorf("unknown kid %q (refetch throttled)", kid)
	}

	// Deduplicate concurrent refetches. All callers share a single outbound
	// request; the singleflight key is constant because JWKS is a single
	// resource shared across all kids.
	_, err, _ := v.sf.Do("jwks", func() (any, error) {
		// Re-check after singleflight ownership — another caller may have
		// completed the refetch while we were waiting on Do.
		v.mu.RLock()
		_, reHave := v.keys[kid]
		reStale := time.Since(v.fetchedAt) > v.cacheTTL
		v.mu.RUnlock()
		if reHave && !reStale {
			return nil, nil
		}
		return nil, v.refetch(ctx)
	})

	// Re-read cache after the refetch attempt (successful or not).
	v.mu.RLock()
	key, have = v.keys[kid]
	v.mu.RUnlock()

	if err != nil {
		// Refetch failed. If we already have a cached key for this kid,
		// serve it — a transient identity-service blip should not cascade
		// into a full auth outage here.
		if have {
			log.Printf("jwks refetch failed, serving cached key for kid %q: %v", kid, err)
			return key, nil
		}
		v.mu.Lock()
		v.lastMissAt = time.Now()
		v.mu.Unlock()
		return nil, err
	}

	if !have {
		v.mu.Lock()
		v.lastMissAt = time.Now()
		v.mu.Unlock()
		return nil, fmt.Errorf("unknown kid %q after refetch", kid)
	}
	return key, nil
}

// refetch fetches JWKS from the identity service and, on success, atomically
// replaces the in-memory cache. The HTTP I/O happens without v.mu held so
// other goroutines can keep hitting the RLock-guarded read path. Only the
// final map swap takes the write lock.
func (v *JWKSVerifier) refetch(ctx context.Context) error {
	url := v.issuerURL + "/.well-known/jwks.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build jwks request: %w", err)
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks status %d", resp.StatusCode)
	}

	var set JWKSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}

	keys := make(map[string]*ecdsa.PublicKey, len(set.Keys))
	for _, j := range set.Keys {
		if j.Kty != "EC" || j.Crv != "P-256" || j.Kid == "" {
			continue
		}
		pub, err := jwkToECDSAPublic(j)
		if err != nil {
			continue
		}
		keys[j.Kid] = pub
	}
	if len(keys) == 0 {
		return errors.New("jwks contained no usable keys")
	}

	v.mu.Lock()
	v.keys = keys
	v.fetchedAt = time.Now()
	v.mu.Unlock()
	return nil
}

// jwkToECDSAPublic converts an EC P-256 JWK to a usable ecdsa.PublicKey.
func jwkToECDSAPublic(j JWK) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("decode jwk.x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("decode jwk.y: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
