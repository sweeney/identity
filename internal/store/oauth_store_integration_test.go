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

// --- OAuthClientStore ---

func TestOAuthClientStore_CreateAndGetByID(t *testing.T) {
	cs := store.NewOAuthClientStore(openTestDB(t))

	client := &domain.OAuthClient{
		ID:           "client-1",
		Name:         "My App",
		RedirectURIs: []string{"https://myapp.example.com/callback", "myapp://callback"},
		CreatedAt:    time.Now().UTC().Truncate(time.Millisecond),
		UpdatedAt:    time.Now().UTC().Truncate(time.Millisecond),
	}
	require.NoError(t, cs.Create(client))

	got, err := cs.GetByID("client-1")
	require.NoError(t, err)
	assert.Equal(t, "client-1", got.ID)
	assert.Equal(t, "My App", got.Name)
	assert.Equal(t, []string{"https://myapp.example.com/callback", "myapp://callback"}, got.RedirectURIs)
}

func TestOAuthClientStore_GetByID_NotFound(t *testing.T) {
	cs := store.NewOAuthClientStore(openTestDB(t))
	_, err := cs.GetByID("nonexistent")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestOAuthClientStore_List(t *testing.T) {
	cs := store.NewOAuthClientStore(openTestDB(t))

	for i, name := range []string{"App A", "App B", "App C"} {
		require.NoError(t, cs.Create(&domain.OAuthClient{
			ID:           "client-" + string(rune('a'+i)),
			Name:         name,
			RedirectURIs: []string{"https://example.com/cb"},
			CreatedAt:    time.Now().UTC(),
			UpdatedAt:    time.Now().UTC(),
		}))
	}

	clients, err := cs.List()
	require.NoError(t, err)
	assert.Len(t, clients, 3)
}

func TestOAuthClientStore_Update(t *testing.T) {
	cs := store.NewOAuthClientStore(openTestDB(t))

	client := &domain.OAuthClient{
		ID:           "client-upd",
		Name:         "Original",
		RedirectURIs: []string{"https://original.example.com/cb"},
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	require.NoError(t, cs.Create(client))

	client.Name = "Updated"
	client.RedirectURIs = []string{"https://updated.example.com/cb", "myapp://cb"}
	require.NoError(t, cs.Update(client))

	got, err := cs.GetByID("client-upd")
	require.NoError(t, err)
	assert.Equal(t, "Updated", got.Name)
	assert.Equal(t, []string{"https://updated.example.com/cb", "myapp://cb"}, got.RedirectURIs)
}

func TestOAuthClientStore_Delete(t *testing.T) {
	cs := store.NewOAuthClientStore(openTestDB(t))
	require.NoError(t, cs.Create(&domain.OAuthClient{
		ID:           "client-del",
		Name:         "To Delete",
		RedirectURIs: []string{"https://example.com/cb"},
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))

	require.NoError(t, cs.Delete("client-del"))

	_, err := cs.GetByID("client-del")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

// --- OAuthCodeStore ---

func newTestClient(t *testing.T, cs *store.OAuthClientStore, id string) *domain.OAuthClient {
	t.Helper()
	client := &domain.OAuthClient{
		ID:           id,
		Name:         "Test Client",
		RedirectURIs: []string{"https://app.example.com/callback"},
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	require.NoError(t, cs.Create(client))
	return client
}

func TestOAuthCodeStore_CreateAndGetByHash(t *testing.T) {
	database := openTestDB(t)
	us := store.NewUserStore(database)
	cs := store.NewOAuthClientStore(database)
	codes := store.NewOAuthCodeStore(database)

	u := seedUser(t, us, "oauth-user")
	client := newTestClient(t, cs, "test-client-1")

	now := time.Now().UTC()
	code := &domain.AuthCode{
		ID:            "code-1",
		CodeHash:      sha256hex("rawcode1"),
		ClientID:      client.ID,
		UserID:        u.ID,
		RedirectURI:   "https://app.example.com/callback",
		CodeChallenge: "challenge-abc",
		IssuedAt:      now,
		ExpiresAt:     now.Add(60 * time.Second),
	}
	require.NoError(t, codes.Create(code))

	got, err := codes.GetByHash(sha256hex("rawcode1"))
	require.NoError(t, err)
	assert.Equal(t, "code-1", got.ID)
	assert.Equal(t, client.ID, got.ClientID)
	assert.Equal(t, u.ID, got.UserID)
	assert.Nil(t, got.UsedAt)
}

func TestOAuthCodeStore_GetByHash_NotFound(t *testing.T) {
	codes := store.NewOAuthCodeStore(openTestDB(t))
	_, err := codes.GetByHash("nonexistent")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestOAuthCodeStore_MarkUsed(t *testing.T) {
	database := openTestDB(t)
	us := store.NewUserStore(database)
	cs := store.NewOAuthClientStore(database)
	codes := store.NewOAuthCodeStore(database)

	u := seedUser(t, us, "oauth-user2")
	client := newTestClient(t, cs, "test-client-2")

	now := time.Now().UTC()
	code := &domain.AuthCode{
		ID:            "code-used",
		CodeHash:      sha256hex("rawcode-used"),
		ClientID:      client.ID,
		UserID:        u.ID,
		RedirectURI:   "https://app.example.com/callback",
		CodeChallenge: "challenge-xyz",
		IssuedAt:      now,
		ExpiresAt:     now.Add(60 * time.Second),
	}
	require.NoError(t, codes.Create(code))

	usedAt := time.Now().UTC()
	require.NoError(t, codes.MarkUsed("code-used", usedAt))

	got, err := codes.GetByHash(sha256hex("rawcode-used"))
	require.NoError(t, err)
	assert.NotNil(t, got.UsedAt)
}

func TestOAuthCodeStore_MarkUsed_AlreadyUsed(t *testing.T) {
	database := openTestDB(t)
	us := store.NewUserStore(database)
	cs := store.NewOAuthClientStore(database)
	codes := store.NewOAuthCodeStore(database)

	u := seedUser(t, us, "oauth-user3")
	client := newTestClient(t, cs, "test-client-3")

	now := time.Now().UTC()
	code := &domain.AuthCode{
		ID:            "code-double",
		CodeHash:      sha256hex("rawcode-double"),
		ClientID:      client.ID,
		UserID:        u.ID,
		RedirectURI:   "https://app.example.com/callback",
		CodeChallenge: "challenge-dbl",
		IssuedAt:      now,
		ExpiresAt:     now.Add(60 * time.Second),
	}
	require.NoError(t, codes.Create(code))
	require.NoError(t, codes.MarkUsed("code-double", time.Now().UTC()))

	// Second MarkUsed should fail (already used)
	err := codes.MarkUsed("code-double", time.Now().UTC())
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestOAuthCodeStore_DeleteExpiredAndUsed(t *testing.T) {
	database := openTestDB(t)
	us := store.NewUserStore(database)
	cs := store.NewOAuthClientStore(database)
	codes := store.NewOAuthCodeStore(database)

	u := seedUser(t, us, "oauth-user4")
	client := newTestClient(t, cs, "test-client-4")

	now := time.Now().UTC()

	// Expired code
	expiredCode := &domain.AuthCode{
		ID:            "code-expired",
		CodeHash:      sha256hex("raw-expired"),
		ClientID:      client.ID,
		UserID:        u.ID,
		RedirectURI:   "https://app.example.com/callback",
		CodeChallenge: "ch1",
		IssuedAt:      now.Add(-2 * time.Minute),
		ExpiresAt:     now.Add(-1 * time.Minute), // expired
	}
	require.NoError(t, codes.Create(expiredCode))

	// Valid code
	validCode := &domain.AuthCode{
		ID:            "code-valid",
		CodeHash:      sha256hex("raw-valid"),
		ClientID:      client.ID,
		UserID:        u.ID,
		RedirectURI:   "https://app.example.com/callback",
		CodeChallenge: "ch2",
		IssuedAt:      now,
		ExpiresAt:     now.Add(60 * time.Second),
	}
	require.NoError(t, codes.Create(validCode))

	require.NoError(t, codes.DeleteExpiredAndUsed())

	_, err := codes.GetByHash(sha256hex("raw-expired"))
	assert.ErrorIs(t, err, domain.ErrNotFound)

	_, err = codes.GetByHash(sha256hex("raw-valid"))
	assert.NoError(t, err)
}

// --- AuditStore ---

func TestAuditStore_RecordAndList(t *testing.T) {
	as := store.NewAuditStore(openTestDB(t))

	events := []*domain.AuthEvent{
		{
			ID:         "evt-1",
			EventType:  domain.EventLoginSuccess,
			UserID:     "user-1",
			Username:   "alice",
			OccurredAt: time.Now().UTC().Add(-2 * time.Minute),
		},
		{
			ID:         "evt-2",
			EventType:  domain.EventLoginFailure,
			Username:   "ghost",
			OccurredAt: time.Now().UTC().Add(-1 * time.Minute),
		},
	}
	for _, e := range events {
		require.NoError(t, as.Record(e))
	}

	got, err := as.List(10)
	require.NoError(t, err)
	assert.Len(t, got, 2)
	// Newest first
	assert.Equal(t, "evt-2", got[0].ID)
}

func TestAuditStore_ListForUser(t *testing.T) {
	as := store.NewAuditStore(openTestDB(t))

	require.NoError(t, as.Record(&domain.AuthEvent{
		ID: "e1", EventType: domain.EventLoginSuccess,
		UserID: "user-a", Username: "alice", OccurredAt: time.Now().UTC(),
	}))
	require.NoError(t, as.Record(&domain.AuthEvent{
		ID: "e2", EventType: domain.EventLoginSuccess,
		UserID: "user-b", Username: "bob", OccurredAt: time.Now().UTC(),
	}))
	require.NoError(t, as.Record(&domain.AuthEvent{
		ID: "e3", EventType: domain.EventLogout,
		UserID: "user-a", Username: "alice", OccurredAt: time.Now().UTC(),
	}))

	got, err := as.ListForUser("user-a", 10)
	require.NoError(t, err)
	assert.Len(t, got, 2)
	for _, e := range got {
		assert.Equal(t, "user-a", e.UserID)
	}
}

func TestAuditStore_List_Limit(t *testing.T) {
	as := store.NewAuditStore(openTestDB(t))

	for i := 0; i < 5; i++ {
		require.NoError(t, as.Record(&domain.AuthEvent{
			ID:         "evt-" + string(rune('a'+i)),
			EventType:  domain.EventLoginSuccess,
			Username:   "alice",
			OccurredAt: time.Now().UTC(),
		}))
	}

	got, err := as.List(3)
	require.NoError(t, err)
	assert.Len(t, got, 3)
}
