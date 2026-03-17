package auth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
)

const testSecret = "test-secret-key-that-is-long-enough-for-hmac"

func newTestIssuer(t *testing.T) *auth.TokenIssuer {
	t.Helper()
	issuer, err := auth.NewTokenIssuer(testSecret, "", "identity.home", 15*time.Minute)
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

	parsed, err := issuer.Parse(token)
	require.NoError(t, err)
	assert.Equal(t, "user-123", parsed.UserID)
	assert.Equal(t, "alice", parsed.Username)
	assert.Equal(t, domain.RoleUser, parsed.Role)
	assert.True(t, parsed.IsActive)
}

func TestTokenIssuer_ExpiredToken(t *testing.T) {
	// Create issuer with a very short TTL, then advance time past it
	issuer, err := auth.NewTokenIssuer(testSecret, "", "identity.home", time.Millisecond)
	require.NoError(t, err)

	token, err := issuer.Mint(domain.TokenClaims{UserID: "u1", Username: "bob", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	time.Sleep(5 * time.Millisecond)

	_, err = issuer.Parse(token)
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrTokenExpired)
}

func TestTokenIssuer_InvalidSignature(t *testing.T) {
	issuer := newTestIssuer(t)

	token, err := issuer.Mint(domain.TokenClaims{UserID: "u1", Username: "alice", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	// Create a second issuer with a different secret
	wrongIssuer, err := auth.NewTokenIssuer("completely-different-secret-key-here", "", "identity.home", 15*time.Minute)
	require.NoError(t, err)

	_, err = wrongIssuer.Parse(token)
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrTokenInvalid)
}

func TestTokenIssuer_WrongIssuer(t *testing.T) {
	issuer := newTestIssuer(t)

	token, err := issuer.Mint(domain.TokenClaims{UserID: "u1", Username: "alice", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	wrongIssuer, err := auth.NewTokenIssuer(testSecret, "", "different.issuer", 15*time.Minute)
	require.NoError(t, err)

	_, err = wrongIssuer.Parse(token)
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrTokenInvalid)
}

func TestTokenIssuer_PreviousSecretFallback(t *testing.T) {
	// Scenario: secret is being rotated. Old tokens signed with prevSecret
	// should still be accepted by an issuer configured with prevSecret.
	oldIssuer, err := auth.NewTokenIssuer("old-secret-key-long-enough-for-hmac-algo", "", "identity.home", 15*time.Minute)
	require.NoError(t, err)

	token, err := oldIssuer.Mint(domain.TokenClaims{UserID: "u1", Username: "alice", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	// New issuer: new primary secret + old secret as fallback
	newIssuer, err := auth.NewTokenIssuer(
		"new-secret-key-long-enough-for-hmac-algo",
		"old-secret-key-long-enough-for-hmac-algo",
		"identity.home",
		15*time.Minute,
	)
	require.NoError(t, err)

	parsed, err := newIssuer.Parse(token)
	require.NoError(t, err)
	assert.Equal(t, "u1", parsed.UserID)
}

func TestTokenIssuer_MalformedToken(t *testing.T) {
	issuer := newTestIssuer(t)

	_, err := issuer.Parse("this.is.not.a.jwt")
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrTokenInvalid)
}

func TestTokenIssuer_EmptyToken(t *testing.T) {
	issuer := newTestIssuer(t)

	_, err := issuer.Parse("")
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrTokenInvalid)
}
