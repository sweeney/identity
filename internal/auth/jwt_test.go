package auth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
)

func newTestIssuer(t *testing.T) *auth.TokenIssuer {
	t.Helper()
	key, err := auth.GenerateKey()
	require.NoError(t, err)
	issuer, err := auth.NewTokenIssuer(key, nil, "identity.home", 15*time.Minute)
	require.NoError(t, err)
	return issuer
}

func TestTokenIssuer_MintAndParse(t *testing.T) {
	issuer := newTestIssuer(t)

	claims := domain.TokenClaims{
		UserID:   "user-123",
		Username: "alice",
		Role:     domain.RoleUser,
		IsActive: true,
	}

	token, err := issuer.Mint(claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	parsed, err := issuer.Parse(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "user-123", parsed.UserID)
	assert.Equal(t, "alice", parsed.Username)
	assert.Equal(t, domain.RoleUser, parsed.Role)
	assert.True(t, parsed.IsActive)
}

func TestTokenIssuer_ExpiredToken(t *testing.T) {
	key, err := auth.GenerateKey()
	require.NoError(t, err)
	issuer, err := auth.NewTokenIssuer(key, nil, "identity.home", time.Millisecond)
	require.NoError(t, err)

	token, err := issuer.Mint(domain.TokenClaims{UserID: "u1", Username: "bob", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	time.Sleep(5 * time.Millisecond)

	_, err = issuer.Parse(context.Background(), token)
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrTokenExpired)
}

func TestTokenIssuer_InvalidSignature(t *testing.T) {
	key1, err := auth.GenerateKey()
	require.NoError(t, err)
	key2, err := auth.GenerateKey()
	require.NoError(t, err)

	issuer1, err := auth.NewTokenIssuer(key1, nil, "identity.home", 15*time.Minute)
	require.NoError(t, err)
	issuer2, err := auth.NewTokenIssuer(key2, nil, "identity.home", 15*time.Minute)
	require.NoError(t, err)

	token, err := issuer1.Mint(domain.TokenClaims{UserID: "u1", Username: "alice", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	_, err = issuer2.Parse(context.Background(), token)
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrTokenInvalid)
}

func TestTokenIssuer_WrongIssuer(t *testing.T) {
	key, err := auth.GenerateKey()
	require.NoError(t, err)

	issuer1, err := auth.NewTokenIssuer(key, nil, "identity.home", 15*time.Minute)
	require.NoError(t, err)
	issuer2, err := auth.NewTokenIssuer(key, nil, "different.issuer", 15*time.Minute)
	require.NoError(t, err)

	token, err := issuer1.Mint(domain.TokenClaims{UserID: "u1", Username: "alice", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	_, err = issuer2.Parse(context.Background(), token)
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrTokenInvalid)
}

func TestTokenIssuer_PreviousKeyFallback(t *testing.T) {
	// Scenario: key is being rotated. Old tokens signed with prevKey
	// should still be accepted by an issuer configured with prevKey.
	oldKey, err := auth.GenerateKey()
	require.NoError(t, err)
	newKey, err := auth.GenerateKey()
	require.NoError(t, err)

	oldIssuer, err := auth.NewTokenIssuer(oldKey, nil, "identity.home", 15*time.Minute)
	require.NoError(t, err)

	token, err := oldIssuer.Mint(domain.TokenClaims{UserID: "u1", Username: "alice", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	// New issuer: new primary key + old key as fallback
	newIssuer, err := auth.NewTokenIssuer(newKey, oldKey, "identity.home", 15*time.Minute)
	require.NoError(t, err)

	parsed, err := newIssuer.Parse(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "u1", parsed.UserID)
}

func TestTokenIssuer_MalformedToken(t *testing.T) {
	issuer := newTestIssuer(t)

	_, err := issuer.Parse(context.Background(), "this.is.not.a.jwt")
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrTokenInvalid)
}

func TestTokenIssuer_EmptyToken(t *testing.T) {
	issuer := newTestIssuer(t)

	_, err := issuer.Parse(context.Background(), "")
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrTokenInvalid)
}

func TestTokenIssuer_KidConsistency(t *testing.T) {
	// The kid in a minted token's header must match a kid in the JWKS.
	// This is the link a consuming service uses to select the right public key.
	key, err := auth.GenerateKey()
	require.NoError(t, err)
	issuer, err := auth.NewTokenIssuer(key, nil, "identity.home", 15*time.Minute)
	require.NoError(t, err)

	token, err := issuer.Mint(domain.TokenClaims{UserID: "u1", Username: "alice", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	// Decode the JWT header (first segment) to extract kid.
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]any
	require.NoError(t, json.Unmarshal(headerJSON, &header))
	tokenKid, ok := header["kid"].(string)
	require.True(t, ok, "kid should be present in JWT header")
	assert.NotEmpty(t, tokenKid)

	// The kid must appear in the JWKS.
	jwks := issuer.JWKS()
	var found bool
	for _, k := range jwks.Keys {
		if k.Kid == tokenKid {
			found = true
			break
		}
	}
	assert.True(t, found, "token kid %q not found in JWKS", tokenKid)
}

func TestTokenIssuer_JWKS(t *testing.T) {
	key, err := auth.GenerateKey()
	require.NoError(t, err)
	issuer, err := auth.NewTokenIssuer(key, nil, "identity.home", 15*time.Minute)
	require.NoError(t, err)

	jwks := issuer.JWKS()
	require.Len(t, jwks.Keys, 1)

	k := jwks.Keys[0]
	assert.Equal(t, "EC", k.Kty)
	assert.Equal(t, "sig", k.Use)
	assert.Equal(t, "ES256", k.Alg)
	assert.Equal(t, "P-256", k.Crv)
	assert.NotEmpty(t, k.Kid)
	assert.NotEmpty(t, k.X)
	assert.NotEmpty(t, k.Y)
}

func decodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "expected 3-part JWT")
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(payloadJSON, &payload))
	return payload
}

func TestTokenIssuer_Mint_WithAudience(t *testing.T) {
	issuer := newTestIssuer(t)
	claims := domain.TokenClaims{
		UserID:   "user-1",
		Username: "alice",
		Role:     domain.RoleUser,
		IsActive: true,
		Audience: "mqttproxy",
	}

	token, err := issuer.Mint(claims)
	require.NoError(t, err)

	payload := decodeJWTPayload(t, token)
	aud, ok := payload["aud"]
	require.True(t, ok, "aud claim should be present in token payload")
	// JWT spec: aud is always an array when set via ClaimStrings
	audSlice, ok := aud.([]any)
	require.True(t, ok, "aud should be an array")
	require.Len(t, audSlice, 1)
	assert.Equal(t, "mqttproxy", audSlice[0])
}

func TestTokenIssuer_Mint_WithoutAudience(t *testing.T) {
	issuer := newTestIssuer(t)
	claims := domain.TokenClaims{
		UserID:   "user-1",
		Username: "alice",
		Role:     domain.RoleUser,
		IsActive: true,
		// Audience intentionally empty
	}

	token, err := issuer.Mint(claims)
	require.NoError(t, err)

	payload := decodeJWTPayload(t, token)
	_, hasAud := payload["aud"]
	assert.False(t, hasAud, "aud claim should be absent when no audience is set")
}

func TestTokenIssuer_JWKS_WithPrevKey(t *testing.T) {
	oldKey, err := auth.GenerateKey()
	require.NoError(t, err)
	newKey, err := auth.GenerateKey()
	require.NoError(t, err)

	issuer, err := auth.NewTokenIssuer(newKey, oldKey, "identity.home", 15*time.Minute)
	require.NoError(t, err)

	jwks := issuer.JWKS()
	require.Len(t, jwks.Keys, 2)
	assert.NotEqual(t, jwks.Keys[0].Kid, jwks.Keys[1].Kid)
}
