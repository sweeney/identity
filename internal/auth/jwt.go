package auth

import (
	"errors"
	"fmt"
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

// TokenIssuer mints and validates JWT access tokens.
type TokenIssuer struct {
	secret    []byte
	prevSecret []byte // optional: accepted during key rotation
	issuer    string
	ttl       time.Duration
}

// NewTokenIssuer creates a TokenIssuer.
// prevSecret may be empty — it is only used as a fallback during key rotation.
func NewTokenIssuer(secret, prevSecret, issuer string, ttl time.Duration) (*TokenIssuer, error) {
	if secret == "" {
		return nil, errors.New("jwt secret must not be empty")
	}
	ti := &TokenIssuer{
		secret:  []byte(secret),
		issuer:  issuer,
		ttl:     ttl,
	}
	if prevSecret != "" {
		ti.prevSecret = []byte(prevSecret)
	}
	return ti, nil
}

// Mint creates a signed JWT access token for the given claims.
func (ti *TokenIssuer) Mint(claims domain.TokenClaims) (string, error) {
	now := time.Now()
	jwtClaims := identityClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ti.issuer,
			Subject:   claims.UserID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ti.ttl)),
			ID:        uuid.New().String(),
		},
		Username: claims.Username,
		Role:     claims.Role,
		IsActive: claims.IsActive,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	signed, err := token.SignedString(ti.secret)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

// Parse validates a JWT and returns the embedded TokenClaims.
// Returns ErrTokenExpired if the token has expired, ErrTokenInvalid for all
// other validation failures.
func (ti *TokenIssuer) Parse(tokenStr string) (*domain.TokenClaims, error) {
	if tokenStr == "" {
		return nil, ErrTokenInvalid
	}

	claims, err := ti.parseWithSecret(tokenStr, ti.secret)
	if err != nil {
		// If we have a previous secret and the primary failed (but not due to expiry),
		// try the fallback. This handles zero-downtime key rotation.
		if ti.prevSecret != nil && !errors.Is(err, ErrTokenExpired) {
			claims, fallbackErr := ti.parseWithSecret(tokenStr, ti.prevSecret)
			if fallbackErr == nil {
				return claims, nil
			}
		}
		return nil, err
	}
	return claims, nil
}

func (ti *TokenIssuer) parseWithSecret(tokenStr string, secret []byte) (*domain.TokenClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&identityClaims{},
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return secret, nil
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
