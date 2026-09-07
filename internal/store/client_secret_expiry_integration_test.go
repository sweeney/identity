//go:build integration

package store_test

// client_secret_expiry_integration_test.go covers the WP13 (#27) finding that
// the rotated-out client secret never expired: it was accepted forever, so a
// secret an operator deliberately rotated away from stayed valid indefinitely.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/store"
)

func TestOAuthClientStore_PreviousSecretExpiry_RoundTrips(t *testing.T) {
	database := openTestDB(t)
	clients := store.NewOAuthClientStore(database)

	expires := time.Now().UTC().Add(domain.ClientSecretRotationWindow).Truncate(time.Millisecond)
	require.NoError(t, clients.Create(&domain.OAuthClient{
		ID:                  "rotating",
		Name:                "Rotating",
		GrantTypes:          []string{domain.GrantTypeClientCredentials},
		SecretHash:          "new-hash",
		SecretHashPrev:      "old-hash",
		SecretPrevExpiresAt: &expires,
	}))

	got, err := clients.GetByID("rotating")
	require.NoError(t, err)
	require.NotNil(t, got.SecretPrevExpiresAt)
	assert.WithinDuration(t, expires, *got.SecretPrevExpiresAt, time.Second)
	assert.True(t, got.PreviousSecretUsable(time.Now().UTC()),
		"inside the rotation window the old secret still works")
	assert.False(t, got.PreviousSecretUsable(expires.Add(time.Second)),
		"past the window it must not")
}

// A client with no previous secret, and one with no expiry recorded (a row
// predating the migration), both behave as before.
func TestOAuthClientStore_PreviousSecretExpiry_Absent(t *testing.T) {
	database := openTestDB(t)
	clients := store.NewOAuthClientStore(database)

	require.NoError(t, clients.Create(&domain.OAuthClient{
		ID: "plain", Name: "Plain",
		GrantTypes: []string{domain.GrantTypeClientCredentials},
		SecretHash: "hash",
	}))

	got, err := clients.GetByID("plain")
	require.NoError(t, err)
	assert.Nil(t, got.SecretPrevExpiresAt)
	assert.False(t, got.PreviousSecretUsable(time.Now().UTC()),
		"no previous secret means nothing to accept")

	require.NoError(t, clients.Create(&domain.OAuthClient{
		ID: "legacy", Name: "Legacy",
		GrantTypes:     []string{domain.GrantTypeClientCredentials},
		SecretHash:     "new",
		SecretHashPrev: "old",
	}))
	legacy, err := clients.GetByID("legacy")
	require.NoError(t, err)
	assert.True(t, legacy.PreviousSecretUsable(time.Now().UTC()),
		"a row predating the migration keeps working until its next rotation")
}
