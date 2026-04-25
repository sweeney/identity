package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
)

func TestMintServiceToken_AllClaims(t *testing.T) {
	issuer := newTestIssuer(t)
	claims := domain.ServiceTokenClaims{
		ClientID: "my-service",
		Audience: "https://api.example.com",
		Scope:    "read:users write:users",
	}

	token, err := issuer.MintServiceToken(claims, 15*time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	parsed, err := issuer.ParseServiceToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "my-service", parsed.ClientID)
	assert.Equal(t, "https://api.example.com", parsed.Audience)
	assert.Equal(t, "read:users write:users", parsed.Scope)
	assert.NotEmpty(t, parsed.JTI)
}

func TestMintServiceToken_EmptyAudience_Error(t *testing.T) {
	issuer := newTestIssuer(t)
	claims := domain.ServiceTokenClaims{
		ClientID: "my-service",
		Audience: "",
		Scope:    "read:users",
	}

	_, err := issuer.MintServiceToken(claims, 15*time.Minute)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "audience")
}

func TestMintServiceToken_EmptyScope(t *testing.T) {
	issuer := newTestIssuer(t)
	claims := domain.ServiceTokenClaims{
		ClientID: "my-service",
		Audience: "https://api.example.com",
		Scope:    "",
	}

	token, err := issuer.MintServiceToken(claims, 15*time.Minute)
	require.NoError(t, err)

	parsed, err := issuer.ParseServiceToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "", parsed.Scope)
}

func TestMintServiceToken_UniqueJTI(t *testing.T) {
	issuer := newTestIssuer(t)
	claims := domain.ServiceTokenClaims{
		ClientID: "my-service",
		Audience: "https://api.example.com",
		Scope:    "read:users",
	}

	token1, err := issuer.MintServiceToken(claims, 15*time.Minute)
	require.NoError(t, err)
	token2, err := issuer.MintServiceToken(claims, 15*time.Minute)
	require.NoError(t, err)

	parsed1, _ := issuer.ParseServiceToken(context.Background(), token1)
	parsed2, _ := issuer.ParseServiceToken(context.Background(), token2)
	assert.NotEqual(t, parsed1.JTI, parsed2.JTI)
}

func TestMintServiceToken_Expired(t *testing.T) {
	issuer := newTestIssuer(t)
	claims := domain.ServiceTokenClaims{
		ClientID: "my-service",
		Audience: "https://api.example.com",
		Scope:    "read:users",
	}

	// Mint with a TTL of 0 (expires immediately)
	token, err := issuer.MintServiceToken(claims, -1*time.Second)
	require.NoError(t, err)

	_, err = issuer.ParseServiceToken(context.Background(), token)
	assert.Error(t, err)
}

func TestParseServiceToken_UserTokenFails(t *testing.T) {
	issuer := newTestIssuer(t)
	// Mint a user token
	userToken, err := issuer.Mint(domain.TokenClaims{
		UserID:   "user-123",
		Username: "alice",
		Role:     domain.RoleUser,
		IsActive: true,
	})
	require.NoError(t, err)

	// Parsing as service token should fail (no client_id claim)
	_, err = issuer.ParseServiceToken(context.Background(), userToken)
	assert.Error(t, err)
}

func TestParseServiceToken_InvalidToken(t *testing.T) {
	issuer := newTestIssuer(t)
	_, err := issuer.ParseServiceToken(context.Background(), "not-a-valid-token")
	assert.Error(t, err)

	_, err = issuer.ParseServiceToken(context.Background(), "")
	assert.Error(t, err)
}

// TestParse_RejectsServiceToken verifies that a service token (typ: at+jwt) is
// rejected by Parse to prevent type-confusion attacks in the authorizePasskey flow.
func TestParse_RejectsServiceToken(t *testing.T) {
	issuer := newTestIssuer(t)
	serviceToken, err := issuer.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "my-service",
		Audience: "https://api.example.com",
		Scope:    "read:users",
	}, 15*time.Minute)
	require.NoError(t, err)

	_, err = issuer.Parse(context.Background(), serviceToken)
	assert.Error(t, err, "Parse must reject service tokens (typ: at+jwt)")
}

func TestMintServiceToken_KeyRotation(t *testing.T) {
	key1, err := auth.GenerateKey()
	require.NoError(t, err)
	key2, err := auth.GenerateKey()
	require.NoError(t, err)

	// Mint with key1
	issuer1, err := auth.NewTokenIssuer(key1, nil, "test-issuer", 15*time.Minute)
	require.NoError(t, err)
	token, err := issuer1.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "svc", Audience: "https://api", Scope: "read:x",
	}, 15*time.Minute)
	require.NoError(t, err)

	// Parse with key2 as primary, key1 as previous — should work
	issuer2, err := auth.NewTokenIssuer(key2, key1, "test-issuer", 15*time.Minute)
	require.NoError(t, err)
	parsed, err := issuer2.ParseServiceToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "svc", parsed.ClientID)
}
