//go:build integration

package store_test

// claim_code_bind_integration_test.go covers WP5 (GHSA-fj5g-j4mv-7m5g):
// ClaimCodeStore.Bind was not compare-and-swap. It updated on
// `WHERE id = ? AND revoked_at IS NULL` without requiring the code to still be
// unbound, so a second Bind overwrote the first. A claim code is a credential
// printed on a device sticker and is meant to tie to exactly one owner on first
// use; two racing approvals could hand the device to whoever wrote last.
//
// OAuthCodeStore.MarkUsed already gets this right with `AND used_at IS NULL`.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/store"
)

func TestClaimCodeStore_Bind_IsCompareAndSwap(t *testing.T) {
	database := openTestDB(t)
	clientStore := store.NewOAuthClientStore(database)
	userStore := store.NewUserStore(database)
	claimCodes := store.NewClaimCodeStore(database)

	require.NoError(t, clientStore.Create(&domain.OAuthClient{
		ID:         "device-client",
		Name:       "Device",
		GrantTypes: []string{domain.GrantTypeDeviceCode},
	}))
	first := &domain.User{ID: "user-first", Username: "first", PasswordHash: "x", Role: domain.RoleUser, IsActive: true}
	second := &domain.User{ID: "user-second", Username: "second", PasswordHash: "x", Role: domain.RoleUser, IsActive: true}
	require.NoError(t, userStore.Create(first))
	require.NoError(t, userStore.Create(second))

	now := time.Now().UTC()
	cc := &domain.ClaimCode{
		ID:        "claim-1",
		CodeHash:  "hash-1",
		ClientID:  "device-client",
		Label:     "Kitchen sensor",
		CreatedAt: now,
	}
	require.NoError(t, claimCodes.Create(cc))

	require.NoError(t, claimCodes.Bind(cc.ID, first.ID, now),
		"the first bind claims the code")

	err := claimCodes.Bind(cc.ID, second.ID, now.Add(time.Second))
	require.Error(t, err,
		"a second bind must not silently reassign a claim code to another user")

	got, err := claimCodes.GetByID(cc.ID)
	require.NoError(t, err)
	assert.Equal(t, first.ID, got.BoundUserID,
		"the original owner must keep the device")
}
