//go:build integration

package store_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/store"
)

// --- helpers ---

func newDeviceAuthorization(id, deviceHash, userCode, clientID string) *domain.DeviceAuthorization {
	now := time.Now().UTC()
	return &domain.DeviceAuthorization{
		ID:             id,
		DeviceCodeHash: deviceHash,
		UserCode:       userCode,
		ClientID:       clientID,
		Scope:          "",
		Status:         domain.DeviceStatusPending,
		IssuedAt:       now,
		ExpiresAt:      now.Add(10 * time.Minute),
		PollInterval:   5,
	}
}

func newClaimCode(id, hash, clientID, label string) *domain.ClaimCode {
	return &domain.ClaimCode{
		ID:        id,
		CodeHash:  hash,
		ClientID:  clientID,
		Label:     label,
		CreatedAt: time.Now().UTC(),
	}
}

// --- DeviceAuthorizationStore ---

func TestDeviceAuthorizationStore_CreateAndGetByDeviceHash(t *testing.T) {
	database := openTestDB(t)
	cs := store.NewOAuthClientStore(database)
	das := store.NewDeviceAuthorizationStore(database)

	client := newTestClient(t, cs, "device-client")
	da := newDeviceAuthorization("dev-1", sha256hex("raw-device-1"), "ABCD-EFGH", client.ID)

	require.NoError(t, das.Create(da))

	got, err := das.GetByDeviceHash(sha256hex("raw-device-1"))
	require.NoError(t, err)
	assert.Equal(t, "dev-1", got.ID)
	assert.Equal(t, "ABCD-EFGH", got.UserCode)
	assert.Equal(t, domain.DeviceStatusPending, got.Status)
	assert.Empty(t, got.UserID)
	assert.Nil(t, got.ConsumedAt)
}

func TestDeviceAuthorizationStore_GetByDeviceHash_NotFound(t *testing.T) {
	das := store.NewDeviceAuthorizationStore(openTestDB(t))
	_, err := das.GetByDeviceHash("nope")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestDeviceAuthorizationStore_GetByUserCode(t *testing.T) {
	database := openTestDB(t)
	cs := store.NewOAuthClientStore(database)
	das := store.NewDeviceAuthorizationStore(database)

	client := newTestClient(t, cs, "device-client-uc")
	da := newDeviceAuthorization("dev-uc", sha256hex("raw-uc"), "WDJB-MJHT", client.ID)
	require.NoError(t, das.Create(da))

	got, err := das.GetByUserCode("WDJB-MJHT")
	require.NoError(t, err)
	assert.Equal(t, "dev-uc", got.ID)

	_, err = das.GetByUserCode("NOSUCH-CD")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestDeviceAuthorizationStore_Approve(t *testing.T) {
	database := openTestDB(t)
	cs := store.NewOAuthClientStore(database)
	us := store.NewUserStore(database)
	das := store.NewDeviceAuthorizationStore(database)

	u := seedUser(t, us, "approver")
	client := newTestClient(t, cs, "device-client-approve")
	da := newDeviceAuthorization("dev-appr", sha256hex("raw-appr"), "WXYZ-1234", client.ID)
	require.NoError(t, das.Create(da))

	require.NoError(t, das.Approve("dev-appr", u.ID, time.Now().UTC()))

	got, err := das.GetByDeviceHash(sha256hex("raw-appr"))
	require.NoError(t, err)
	assert.Equal(t, domain.DeviceStatusApproved, got.Status)
	assert.Equal(t, u.ID, got.UserID)
}

func TestDeviceAuthorizationStore_Deny(t *testing.T) {
	database := openTestDB(t)
	cs := store.NewOAuthClientStore(database)
	das := store.NewDeviceAuthorizationStore(database)

	client := newTestClient(t, cs, "device-client-deny")
	da := newDeviceAuthorization("dev-deny", sha256hex("raw-deny"), "DENY-CODE", client.ID)
	require.NoError(t, das.Create(da))

	require.NoError(t, das.Deny("dev-deny", time.Now().UTC()))

	got, err := das.GetByDeviceHash(sha256hex("raw-deny"))
	require.NoError(t, err)
	assert.Equal(t, domain.DeviceStatusDenied, got.Status)
}

func TestDeviceAuthorizationStore_MarkPolled(t *testing.T) {
	database := openTestDB(t)
	cs := store.NewOAuthClientStore(database)
	das := store.NewDeviceAuthorizationStore(database)

	client := newTestClient(t, cs, "device-client-poll")
	da := newDeviceAuthorization("dev-poll", sha256hex("raw-poll"), "POLL-CODE", client.ID)
	require.NoError(t, das.Create(da))

	polledAt := time.Now().UTC()
	require.NoError(t, das.MarkPolled("dev-poll", polledAt))

	got, err := das.GetByDeviceHash(sha256hex("raw-poll"))
	require.NoError(t, err)
	require.NotNil(t, got.LastPolledAt)
	assert.WithinDuration(t, polledAt, *got.LastPolledAt, time.Second)
}

func TestDeviceAuthorizationStore_MarkConsumed(t *testing.T) {
	database := openTestDB(t)
	cs := store.NewOAuthClientStore(database)
	us := store.NewUserStore(database)
	das := store.NewDeviceAuthorizationStore(database)

	u := seedUser(t, us, "consumer")
	client := newTestClient(t, cs, "device-client-consume")
	da := newDeviceAuthorization("dev-cons", sha256hex("raw-cons"), "CONS-CODE", client.ID)
	require.NoError(t, das.Create(da))
	require.NoError(t, das.Approve("dev-cons", u.ID, time.Now().UTC()))

	require.NoError(t, das.MarkConsumed("dev-cons", time.Now().UTC()))

	// Second consume must fail — idempotency guard prevents a stolen approved code
	// from being exchanged twice.
	err := das.MarkConsumed("dev-cons", time.Now().UTC())
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestDeviceAuthorizationStore_DeleteExpired(t *testing.T) {
	database := openTestDB(t)
	cs := store.NewOAuthClientStore(database)
	das := store.NewDeviceAuthorizationStore(database)

	client := newTestClient(t, cs, "device-client-exp")
	now := time.Now().UTC()

	expired := newDeviceAuthorization("dev-exp", sha256hex("raw-exp"), "EXP1-CODE", client.ID)
	expired.IssuedAt = now.Add(-15 * time.Minute)
	expired.ExpiresAt = now.Add(-5 * time.Minute)
	require.NoError(t, das.Create(expired))

	live := newDeviceAuthorization("dev-live", sha256hex("raw-live"), "LIV1-CODE", client.ID)
	require.NoError(t, das.Create(live))

	require.NoError(t, das.DeleteExpired())

	_, err := das.GetByDeviceHash(sha256hex("raw-exp"))
	assert.ErrorIs(t, err, domain.ErrNotFound)

	_, err = das.GetByDeviceHash(sha256hex("raw-live"))
	assert.NoError(t, err)
}

// --- ClaimCodeStore ---

func TestClaimCodeStore_CreateAndGetByHash(t *testing.T) {
	database := openTestDB(t)
	cs := store.NewOAuthClientStore(database)
	ccs := store.NewClaimCodeStore(database)

	client := newTestClient(t, cs, "claim-client")
	c := newClaimCode("cc-1", sha256hex("raw-claim-1"), client.ID, "Kitchen sensor")
	require.NoError(t, ccs.Create(c))

	got, err := ccs.GetByHash(sha256hex("raw-claim-1"))
	require.NoError(t, err)
	assert.Equal(t, "cc-1", got.ID)
	assert.Equal(t, "Kitchen sensor", got.Label)
	assert.False(t, got.IsBound())
	assert.False(t, got.IsRevoked())
}

func TestClaimCodeStore_GetByID(t *testing.T) {
	database := openTestDB(t)
	cs := store.NewOAuthClientStore(database)
	ccs := store.NewClaimCodeStore(database)

	client := newTestClient(t, cs, "claim-client-id")
	c := newClaimCode("cc-id", sha256hex("raw-id"), client.ID, "Living room")
	require.NoError(t, ccs.Create(c))

	got, err := ccs.GetByID("cc-id")
	require.NoError(t, err)
	assert.Equal(t, "Living room", got.Label)

	_, err = ccs.GetByID("does-not-exist")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestClaimCodeStore_ListByClient(t *testing.T) {
	database := openTestDB(t)
	cs := store.NewOAuthClientStore(database)
	ccs := store.NewClaimCodeStore(database)

	clientA := newTestClient(t, cs, "claim-client-a")
	clientB := newTestClient(t, cs, "claim-client-b")

	for i, label := range []string{"A1", "A2", "A3"} {
		require.NoError(t, ccs.Create(newClaimCode(
			"cc-a-"+string(rune('a'+i)),
			sha256hex("raw-a-"+label),
			clientA.ID, label,
		)))
	}
	require.NoError(t, ccs.Create(newClaimCode("cc-b-1", sha256hex("raw-b-1"), clientB.ID, "B1")))

	listA, err := ccs.ListByClient(clientA.ID)
	require.NoError(t, err)
	assert.Len(t, listA, 3)

	listB, err := ccs.ListByClient(clientB.ID)
	require.NoError(t, err)
	assert.Len(t, listB, 1)
}

func TestClaimCodeStore_Bind(t *testing.T) {
	database := openTestDB(t)
	cs := store.NewOAuthClientStore(database)
	us := store.NewUserStore(database)
	ccs := store.NewClaimCodeStore(database)

	u := seedUser(t, us, "binder")
	client := newTestClient(t, cs, "claim-client-bind")
	c := newClaimCode("cc-bind", sha256hex("raw-bind"), client.ID, "Hall")
	require.NoError(t, ccs.Create(c))

	require.NoError(t, ccs.Bind("cc-bind", u.ID, time.Now().UTC()))

	got, err := ccs.GetByID("cc-bind")
	require.NoError(t, err)
	assert.True(t, got.IsBound())
	assert.Equal(t, u.ID, got.BoundUserID)
}

func TestClaimCodeStore_Revoke(t *testing.T) {
	database := openTestDB(t)
	cs := store.NewOAuthClientStore(database)
	ccs := store.NewClaimCodeStore(database)

	client := newTestClient(t, cs, "claim-client-revoke")
	c := newClaimCode("cc-rev", sha256hex("raw-rev"), client.ID, "Outdoor")
	require.NoError(t, ccs.Create(c))

	require.NoError(t, ccs.Revoke("cc-rev", time.Now().UTC()))

	got, err := ccs.GetByID("cc-rev")
	require.NoError(t, err)
	assert.True(t, got.IsRevoked())
}

func TestClaimCodeStore_GetByHash_NotFound(t *testing.T) {
	ccs := store.NewClaimCodeStore(openTestDB(t))
	_, err := ccs.GetByHash("nope")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}
