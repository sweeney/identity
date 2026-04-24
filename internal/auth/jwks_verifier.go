package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sweeney/identity/internal/domain"
)

// TokenParser is the minimal interface that auth middleware needs to
// validate Bearer tokens. Both *TokenIssuer (identity, in-process) and
// *JWKSVerifier (consuming services, over HTTP) implement it.
type TokenParser interface {
	Parse(tokenStr string) (*domain.TokenClaims, error)
	ParseServiceToken(tokenStr string) (*domain.ServiceTokenClaims, error)
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
}

// JWKSVerifier validates ES256 JWTs against a JWKS served by the identity
// service. Keys are cached in memory with time-based invalidation and
// additionally refreshed on kid miss (so JWT key rotations propagate
// without a restart).
type JWKSVerifier struct {
	issuerURL   string
	issuer      string
	httpClient  *http.Client
	cacheTTL    time.Duration
	refetchMin  time.Duration

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
		issuerURL:  strings.TrimSuffix(cfg.IssuerURL, "/"),
		issuer:     cfg.Issuer,
		httpClient: client,
		cacheTTL:   ttl,
		refetchMin: refetch,
		keys:       map[string]*ecdsa.PublicKey{},
	}, nil
}

// Issuer returns the expected issuer string. Useful for callers that also
// need to configure audience middleware keyed on the issuer URL.
func (v *JWKSVerifier) Issuer() string { return v.issuer }

// Parse validates tokenStr as an identity user access token. Returns
// ErrTokenExpired when the token has expired and ErrTokenInvalid for all
// other validation failures.
func (v *JWKSVerifier) Parse(tokenStr string) (*domain.TokenClaims, error) {
	if tokenStr == "" {
		return nil, ErrTokenInvalid
	}

	claims := &identityClaims{}
	_, err := v.parseJWT(tokenStr, claims, func(typ string) error {
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
// token. Returns ErrTokenInvalid if tokenStr is not a service token.
func (v *JWKSVerifier) ParseServiceToken(tokenStr string) (*domain.ServiceTokenClaims, error) {
	if tokenStr == "" {
		return nil, ErrTokenInvalid
	}

	claims := &serviceClaims{}
	_, err := v.parseJWT(tokenStr, claims, func(typ string) error {
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
func (v *JWKSVerifier) parseJWT(tokenStr string, claims jwt.Claims, typGuard func(string) error) (*jwt.Token, error) {
	return jwt.ParseWithClaims(
		tokenStr,
		claims,
		func(t *jwt.Token) (any, error) {
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
			return v.keyForKid(kid)
		},
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
	)
}

// keyForKid returns the public key with the given kid, refreshing the JWKS
// cache if the key is missing or the cache is stale. A failed refetch is
// throttled so a storm of bad tokens cannot stampede the identity service.
func (v *JWKSVerifier) keyForKid(kid string) (*ecdsa.PublicKey, error) {
	v.mu.RLock()
	key, have := v.keys[kid]
	stale := time.Since(v.fetchedAt) > v.cacheTTL
	v.mu.RUnlock()

	if have && !stale {
		return key, nil
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// Re-check under the write lock in case another goroutine refetched.
	key, have = v.keys[kid]
	stale = time.Since(v.fetchedAt) > v.cacheTTL
	if have && !stale {
		return key, nil
	}

	// Throttle refetches on repeated misses.
	if !have && time.Since(v.lastMissAt) < v.refetchMin && !v.fetchedAt.IsZero() {
		return nil, fmt.Errorf("unknown kid %q (refetch throttled)", kid)
	}

	if err := v.refetchLocked(); err != nil {
		v.lastMissAt = time.Now()
		return nil, err
	}

	key, have = v.keys[kid]
	if !have {
		v.lastMissAt = time.Now()
		return nil, fmt.Errorf("unknown kid %q after refetch", kid)
	}
	return key, nil
}

// refetchLocked fetches JWKS from the identity service and replaces the
// in-memory cache. Must be called with v.mu held.
func (v *JWKSVerifier) refetchLocked() error {
	url := v.issuerURL + "/.well-known/jwks.json"
	req, err := http.NewRequest(http.MethodGet, url, nil)
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
	v.keys = keys
	v.fetchedAt = time.Now()
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
