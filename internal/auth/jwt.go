package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/sweeney/identity/internal/domain"
)

// identityClaims extends the standard JWT registered claims with our custom fields.
type identityClaims struct {
	jwt.RegisteredClaims
	Username string      `json:"usr"`
	Role     domain.Role `json:"rol"`
	IsActive bool        `json:"act"`
}

// serviceClaims is the JWT claim set for client_credentials tokens (RFC 9068).
type serviceClaims struct {
	jwt.RegisteredClaims
	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
}

// JWK represents a single JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JWKSet is a JSON Web Key Set served at /.well-known/jwks.json.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// TokenIssuer mints and validates JWT access tokens using ES256 (ECDSA P-256).
type TokenIssuer struct {
	key       *ecdsa.PrivateKey
	keyID     string
	prevKey   *ecdsa.PrivateKey // optional: accepted during key rotation
	prevKeyID string
	issuer    string
	ttl       time.Duration
}

// GenerateKey generates a new EC P-256 private key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// NewTokenIssuer creates a TokenIssuer.
// prevKey may be nil — it is only used as a fallback during key rotation.
func NewTokenIssuer(key, prevKey *ecdsa.PrivateKey, issuer string, ttl time.Duration) (*TokenIssuer, error) {
	if key == nil {
		return nil, errors.New("jwt key must not be nil")
	}
	ti := &TokenIssuer{
		key:    key,
		keyID:  publicKeyID(&key.PublicKey),
		issuer: issuer,
		ttl:    ttl,
	}
	if prevKey != nil {
		ti.prevKey = prevKey
		ti.prevKeyID = publicKeyID(&prevKey.PublicKey)
	}
	return ti, nil
}

// Mint creates a signed JWT access token for the given claims.
func (ti *TokenIssuer) Mint(claims domain.TokenClaims) (string, error) {
	now := time.Now()
	registered := jwt.RegisteredClaims{
		Issuer:    ti.issuer,
		Subject:   claims.UserID,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ti.ttl)),
		ID:        uuid.New().String(),
	}
	if claims.Audience != "" {
		registered.Audience = jwt.ClaimStrings{claims.Audience}
	}
	jwtClaims := identityClaims{
		RegisteredClaims: registered,
		Username:         claims.Username,
		Role:             claims.Role,
		IsActive:         claims.IsActive,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwtClaims)
	token.Header["kid"] = ti.keyID
	signed, err := token.SignedString(ti.key)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

// MintServiceToken creates a signed JWT for a client_credentials grant (RFC 9068).
func (ti *TokenIssuer) MintServiceToken(claims domain.ServiceTokenClaims, ttl time.Duration) (string, error) {
	if claims.Audience == "" {
		return "", errors.New("audience is required for service tokens")
	}
	now := time.Now()
	jwtClaims := serviceClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ti.issuer,
			Subject:   claims.ClientID,
			Audience:  jwt.ClaimStrings{claims.Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuid.New().String(),
		},
		ClientID: claims.ClientID,
		Scope:    claims.Scope,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwtClaims)
	token.Header["kid"] = ti.keyID
	token.Header["typ"] = "at+jwt" // RFC 9068 §2.1
	signed, err := token.SignedString(ti.key)
	if err != nil {
		return "", fmt.Errorf("sign service token: %w", err)
	}
	return signed, nil
}

// ParseServiceToken validates a JWT and returns ServiceTokenClaims if the token
// contains a client_id claim. Returns ErrTokenInvalid if it's not a service token.
func (ti *TokenIssuer) ParseServiceToken(tokenStr string) (*domain.ServiceTokenClaims, error) {
	if tokenStr == "" {
		return nil, ErrTokenInvalid
	}

	parse := func(key *ecdsa.PrivateKey) (*domain.ServiceTokenClaims, error) {
		token, err := jwt.ParseWithClaims(
			tokenStr,
			&serviceClaims{},
			func(t *jwt.Token) (any, error) {
				if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				// Reject tokens without the at+jwt type header (RFC 9068 §2.1).
				// This prevents user tokens from being accepted as service tokens.
				if typ, _ := t.Header["typ"].(string); typ != "at+jwt" {
					return nil, fmt.Errorf("not a service token")
				}
				return &key.PublicKey, nil
			},
			jwt.WithIssuer(ti.issuer),
			jwt.WithExpirationRequired(),
		)
		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
				return nil, ErrTokenExpired
			}
			return nil, ErrTokenInvalid
		}
		c, ok := token.Claims.(*serviceClaims)
		if !ok || !token.Valid || c.ClientID == "" {
			return nil, ErrTokenInvalid
		}
		var exp, iat int64
		if c.ExpiresAt != nil {
			exp = c.ExpiresAt.Unix()
		}
		if c.IssuedAt != nil {
			iat = c.IssuedAt.Unix()
		}
		return &domain.ServiceTokenClaims{
			ClientID:  c.ClientID,
			Audience:  strings.Join(c.Audience, " "),
			Scope:     c.Scope,
			JTI:       c.ID,
			ExpiresAt: exp,
			IssuedAt:  iat,
		}, nil
	}

	result, err := parse(ti.key)
	if err != nil && ti.prevKey != nil && !errors.Is(err, ErrTokenExpired) {
		if result, fallbackErr := parse(ti.prevKey); fallbackErr == nil {
			return result, nil
		}
	}
	return result, err
}

// Parse validates a JWT and returns the embedded TokenClaims.
// Returns ErrTokenExpired if the token has expired, ErrTokenInvalid for all
// other validation failures.
func (ti *TokenIssuer) Parse(tokenStr string) (*domain.TokenClaims, error) {
	if tokenStr == "" {
		return nil, ErrTokenInvalid
	}

	claims, err := ti.parseWithKey(tokenStr, ti.key)
	if err != nil {
		// If we have a previous key and the primary failed (but not due to expiry),
		// try the fallback. This handles zero-downtime key rotation.
		if ti.prevKey != nil && !errors.Is(err, ErrTokenExpired) {
			if claims, fallbackErr := ti.parseWithKey(tokenStr, ti.prevKey); fallbackErr == nil {
				return claims, nil
			}
		}
		return nil, err
	}
	return claims, nil
}

// Issuer returns the configured issuer string for this TokenIssuer.
func (ti *TokenIssuer) Issuer() string {
	return ti.issuer
}

// JWKS returns the public key set for this issuer in JWK Set format.
// Serve this at /.well-known/jwks.json so consuming services can verify tokens
// without holding the private key.
func (ti *TokenIssuer) JWKS() JWKSet {
	keys := []JWK{publicKeyToJWK(ti.keyID, &ti.key.PublicKey)}
	if ti.prevKey != nil {
		keys = append(keys, publicKeyToJWK(ti.prevKeyID, &ti.prevKey.PublicKey))
	}
	return JWKSet{Keys: keys}
}

func (ti *TokenIssuer) parseWithKey(tokenStr string, key *ecdsa.PrivateKey) (*domain.TokenClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&identityClaims{},
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			// Reject service tokens (RFC 9068 at+jwt type) — they must use ParseServiceToken.
			if typ, _ := t.Header["typ"].(string); typ == "at+jwt" {
				return nil, fmt.Errorf("service token not accepted as user token")
			}
			return &key.PublicKey, nil
		},
		jwt.WithIssuer(ti.issuer),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrTokenInvalid
	}

	c, ok := token.Claims.(*identityClaims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}

	return &domain.TokenClaims{
		UserID:   c.Subject,
		Username: c.Username,
		Role:     c.Role,
		IsActive: c.IsActive,
	}, nil
}

// publicKeyID derives a stable key ID from an EC public key by hashing its
// DER encoding. The first 8 bytes of the SHA-256 hash are base64url-encoded.
func publicKeyID(pub *ecdsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// publicKeyToJWK converts an EC public key to JWK representation.
func publicKeyToJWK(kid string, pub *ecdsa.PublicKey) JWK {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	xPadded := make([]byte, byteLen)
	yPadded := make([]byte, byteLen)
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	copy(xPadded[byteLen-len(xBytes):], xBytes)
	copy(yPadded[byteLen-len(yBytes):], yBytes)
	return JWK{
		Kty: "EC",
		Use: "sig",
		Alg: "ES256",
		Kid: kid,
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(xPadded),
		Y:   base64.RawURLEncoding.EncodeToString(yPadded),
	}
}
