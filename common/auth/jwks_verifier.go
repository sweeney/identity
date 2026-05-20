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
)

// TokenParser is the minimal interface that auth middleware needs to
// validate Bearer tokens. Both *TokenIssuer (identity, in-process) and
// *JWKSVerifier (consuming services, over HTTP) implement it.
type TokenParser interface {
	Parse(ctx context.Context, tokenStr string) (*TokenClaims, error)
	ParseServiceToken(ctx context.Context, tokenStr string) (*ServiceTokenClaims, error)
}

// Private JWT claim structs for parsing — mirrors the shapes identity stamps
// on its tokens. Not exported; callers receive the typed *TokenClaims result.
type identityClaims struct {
	jwt.RegisteredClaims
	Username string `json:"usr"`
	Role     Role   `json:"rol"`
	IsActive bool   `json:"act"`
}

type serviceClaims struct {
	jwt.RegisteredClaims
	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
}

// Private JWK types for JSON deserialization of JWKS responses.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

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
	// a matching `aud` claim.
	RequiredAudience string
}

// JWKSVerifier validates ES256 JWTs against a JWKS served by the identity
// service. Keys are cached in memory with time-based invalidation and
// additionally refreshed on kid miss.
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

// Issuer returns the expected issuer string.
func (v *JWKSVerifier) Issuer() string { return v.issuer }

// Parse validates tokenStr as an identity user access token.
func (v *JWKSVerifier) Parse(ctx context.Context, tokenStr string) (*TokenClaims, error) {
	if tokenStr == "" {
		return nil, ErrTokenInvalid
	}

	claims := &identityClaims{}
	_, err := v.parseJWT(ctx, tokenStr, claims, func(typ string) error {
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
	return &TokenClaims{
		UserID:   claims.Subject,
		Username: claims.Username,
		Role:     claims.Role,
		IsActive: claims.IsActive,
	}, nil
}

// ParseServiceToken validates tokenStr as an identity service (client_credentials) token.
func (v *JWKSVerifier) ParseServiceToken(ctx context.Context, tokenStr string) (*ServiceTokenClaims, error) {
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
	return &ServiceTokenClaims{
		ClientID:  claims.ClientID,
		Audience:  strings.Join(claims.Audience, " "),
		Scope:     claims.Scope,
		JTI:       claims.ID,
		ExpiresAt: exp,
		IssuedAt:  iat,
	}, nil
}

func (v *JWKSVerifier) parseJWT(ctx context.Context, tokenStr string, claims jwt.Claims, typGuard func(string) error) (*jwt.Token, error) {
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
			return v.keyForKid(ctx, kid)
		},
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

func (v *JWKSVerifier) optionalAudienceOption() []jwt.ParserOption {
	if v.requiredAudience == "" {
		return nil
	}
	return []jwt.ParserOption{jwt.WithAudience(v.requiredAudience)}
}

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

	_, err, _ := v.sf.Do("jwks", func() (any, error) {
		v.mu.RLock()
		_, reHave := v.keys[kid]
		reStale := time.Since(v.fetchedAt) > v.cacheTTL
		v.mu.RUnlock()
		if reHave && !reStale {
			return nil, nil
		}
		return nil, v.refetch(ctx)
	})

	v.mu.RLock()
	key, have = v.keys[kid]
	v.mu.RUnlock()

	if err != nil {
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

	var set jwkSet
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

func jwkToECDSAPublic(j jwk) (*ecdsa.PublicKey, error) {
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
