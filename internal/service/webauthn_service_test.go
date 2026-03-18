package service_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

func newTestWebAuthn(t *testing.T) *webauthn.WebAuthn {
	t.Helper()
	wa, err := auth.NewWebAuthn("localhost", "Test", []string{"http://localhost:8181"})
	require.NoError(t, err)
	return wa
}

func newTestWebAuthnService(t *testing.T, ctrl *gomock.Controller) (
	*service.WebAuthnService,
	*mocks.MockUserRepository,
	*mocks.MockWebAuthnCredentialRepository,
	*mocks.MockWebAuthnChallengeRepository,
) {
	t.Helper()

	userRepo := mocks.NewMockUserRepository(ctrl)
	credRepo := mocks.NewMockWebAuthnCredentialRepository(ctrl)
	challengeRepo := mocks.NewMockWebAuthnChallengeRepository(ctrl)
	auditRepo := mocks.NewMockAuditRepository(ctrl)
	auditRepo.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()

	wa := newTestWebAuthn(t)
	issuer := newTestIssuer(t)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)
	backupSvc.EXPECT().TriggerAsync().AnyTimes()
	tokenRepo.EXPECT().Create(gomock.Any()).Return(nil).AnyTimes()
	authSvc := service.NewAuthService(issuer, userRepo, tokenRepo, backupSvc, auditRepo, 30*24*time.Hour)

	svc := service.NewWebAuthnService(wa, authSvc, userRepo, credRepo, challengeRepo, auditRepo, backupSvc)
	return svc, userRepo, credRepo, challengeRepo
}

// --- BeginRegistration ---

func TestWebAuthnService_BeginRegistration_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, userRepo, credRepo, challengeRepo := newTestWebAuthnService(t, ctrl)

	user := activeUser()
	userRepo.EXPECT().GetByID("user-123").Return(user, nil)
	credRepo.EXPECT().ListByUserID("user-123").Return(nil, nil)
	challengeRepo.EXPECT().Create(gomock.Any()).Return(nil)

	creation, challengeID, err := svc.BeginRegistration("user-123")
	require.NoError(t, err)
	assert.NotNil(t, creation)
	assert.NotEmpty(t, challengeID)
	assert.NotEmpty(t, creation.Response.Challenge)
}

func TestWebAuthnService_BeginRegistration_UserNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, userRepo, _, _ := newTestWebAuthnService(t, ctrl)

	userRepo.EXPECT().GetByID("ghost").Return(nil, domain.ErrNotFound)

	_, _, err := svc.BeginRegistration("ghost")
	assert.Error(t, err)
}

func TestWebAuthnService_BeginRegistration_WithExistingCredentials(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, userRepo, credRepo, challengeRepo := newTestWebAuthnService(t, ctrl)

	user := activeUser()
	userRepo.EXPECT().GetByID("user-123").Return(user, nil)
	existing := []*domain.WebAuthnCredential{
		{ID: "c1", CredentialID: []byte("existing-cred"), PublicKey: []byte("key"), AttestationType: "none", AAGUID: make([]byte, 16)},
	}
	credRepo.EXPECT().ListByUserID("user-123").Return(existing, nil)
	challengeRepo.EXPECT().Create(gomock.Any()).Return(nil)

	creation, challengeID, err := svc.BeginRegistration("user-123")
	require.NoError(t, err)
	assert.NotNil(t, creation)
	assert.NotEmpty(t, challengeID)
	// Existing credentials are passed to the library which may or may not
	// include them in CredentialExcludeList depending on configuration.
	// The key behavior is that BeginRegistration succeeds with existing creds.
}

// --- FinishRegistration ---

func TestWebAuthnService_FinishRegistration_ChallengeNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, challengeRepo := newTestWebAuthnService(t, ctrl)

	challengeRepo.EXPECT().GetByID("bad-id").Return(nil, domain.ErrNotFound)

	_, err := svc.FinishRegistration("user-123", "bad-id", "", nil)
	assert.ErrorIs(t, err, service.ErrWebAuthnInvalidChallenge)
}

func TestWebAuthnService_FinishRegistration_WrongUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, challengeRepo := newTestWebAuthnService(t, ctrl)

	ch := &domain.WebAuthnChallenge{
		ID: "ch-1", UserID: "other-user", Type: "registration",
		SessionData: "{}", ExpiresAt: time.Now().Add(time.Minute),
	}
	challengeRepo.EXPECT().GetByID("ch-1").Return(ch, nil)
	challengeRepo.EXPECT().Delete("ch-1").Return(nil)

	_, err := svc.FinishRegistration("user-123", "ch-1", "", nil)
	assert.ErrorIs(t, err, service.ErrWebAuthnInvalidChallenge)
}

func TestWebAuthnService_FinishRegistration_Expired(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, challengeRepo := newTestWebAuthnService(t, ctrl)

	ch := &domain.WebAuthnChallenge{
		ID: "ch-1", UserID: "user-123", Type: "registration",
		SessionData: "{}", ExpiresAt: time.Now().Add(-time.Minute),
	}
	challengeRepo.EXPECT().GetByID("ch-1").Return(ch, nil)
	challengeRepo.EXPECT().Delete("ch-1").Return(nil)

	_, err := svc.FinishRegistration("user-123", "ch-1", "", nil)
	assert.ErrorIs(t, err, service.ErrWebAuthnInvalidChallenge)
}

func TestWebAuthnService_FinishRegistration_WrongType(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, challengeRepo := newTestWebAuthnService(t, ctrl)

	ch := &domain.WebAuthnChallenge{
		ID: "ch-1", UserID: "user-123", Type: "authentication",
		SessionData: "{}", ExpiresAt: time.Now().Add(time.Minute),
	}
	challengeRepo.EXPECT().GetByID("ch-1").Return(ch, nil)
	challengeRepo.EXPECT().Delete("ch-1").Return(nil)

	_, err := svc.FinishRegistration("user-123", "ch-1", "", nil)
	assert.ErrorIs(t, err, service.ErrWebAuthnInvalidChallenge)
}

// --- BeginLogin ---

func TestWebAuthnService_BeginLogin_DiscoverableFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, challengeRepo := newTestWebAuthnService(t, ctrl)

	challengeRepo.EXPECT().Create(gomock.Any()).Return(nil)

	assertion, challengeID, err := svc.BeginLogin("")
	require.NoError(t, err)
	assert.NotNil(t, assertion)
	assert.NotEmpty(t, challengeID)
	// Discoverable flow has no allowCredentials
	assert.Empty(t, assertion.Response.AllowedCredentials)
}

func TestWebAuthnService_BeginLogin_WithUsername(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, userRepo, credRepo, challengeRepo := newTestWebAuthnService(t, ctrl)

	user := activeUser()
	userRepo.EXPECT().GetByUsername("alice").Return(user, nil)
	creds := []*domain.WebAuthnCredential{
		{ID: "c1", UserID: user.ID, CredentialID: []byte("cid-1"), PublicKey: []byte("key"), AttestationType: "none"},
	}
	credRepo.EXPECT().ListByUserID(user.ID).Return(creds, nil)
	challengeRepo.EXPECT().Create(gomock.Any()).Return(nil)

	assertion, _, err := svc.BeginLogin("alice")
	require.NoError(t, err)
	assert.NotEmpty(t, assertion.Response.AllowedCredentials)
}

func TestWebAuthnService_BeginLogin_NoCredentials(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, userRepo, credRepo, _ := newTestWebAuthnService(t, ctrl)

	user := activeUser()
	userRepo.EXPECT().GetByUsername("alice").Return(user, nil)
	credRepo.EXPECT().ListByUserID(user.ID).Return(nil, nil)

	_, _, err := svc.BeginLogin("alice")
	assert.ErrorIs(t, err, service.ErrWebAuthnNoCredentials)
}

func TestWebAuthnService_BeginLogin_UnknownUser_FakeChallenge(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, userRepo, _, challengeRepo := newTestWebAuthnService(t, ctrl)

	userRepo.EXPECT().GetByUsername("ghost").Return(nil, domain.ErrNotFound)
	challengeRepo.EXPECT().Create(gomock.Any()).Return(nil)

	// Should not error — returns a fake challenge to prevent user enumeration
	assertion, challengeID, err := svc.BeginLogin("ghost")
	require.NoError(t, err)
	assert.NotNil(t, assertion)
	assert.NotEmpty(t, challengeID)
}

// --- FinishLogin ---

func TestWebAuthnService_FinishLogin_ChallengeNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, challengeRepo := newTestWebAuthnService(t, ctrl)

	challengeRepo.EXPECT().GetByID("bad").Return(nil, domain.ErrNotFound)

	_, err := svc.FinishLogin("bad", nil, "", "")
	assert.ErrorIs(t, err, service.ErrWebAuthnInvalidChallenge)
}

func TestWebAuthnService_FinishLogin_Expired(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, challengeRepo := newTestWebAuthnService(t, ctrl)

	ch := &domain.WebAuthnChallenge{
		ID: "ch-1", Type: "authentication",
		SessionData: "{}", ExpiresAt: time.Now().Add(-time.Minute),
	}
	challengeRepo.EXPECT().GetByID("ch-1").Return(ch, nil)
	challengeRepo.EXPECT().Delete("ch-1").Return(nil)

	_, err := svc.FinishLogin("ch-1", nil, "", "")
	assert.ErrorIs(t, err, service.ErrWebAuthnInvalidChallenge)
}

func TestWebAuthnService_FinishLogin_WrongType(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, challengeRepo := newTestWebAuthnService(t, ctrl)

	ch := &domain.WebAuthnChallenge{
		ID: "ch-1", Type: "registration",
		SessionData: "{}", ExpiresAt: time.Now().Add(time.Minute),
	}
	challengeRepo.EXPECT().GetByID("ch-1").Return(ch, nil)
	challengeRepo.EXPECT().Delete("ch-1").Return(nil)

	_, err := svc.FinishLogin("ch-1", nil, "", "")
	assert.ErrorIs(t, err, service.ErrWebAuthnInvalidChallenge)
}

func TestWebAuthnService_FinishLogin_InvalidSessionData(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, challengeRepo := newTestWebAuthnService(t, ctrl)

	ch := &domain.WebAuthnChallenge{
		ID: "ch-1", Type: "authentication",
		SessionData: "not-json", ExpiresAt: time.Now().Add(time.Minute),
	}
	challengeRepo.EXPECT().GetByID("ch-1").Return(ch, nil)
	challengeRepo.EXPECT().Delete("ch-1").Return(nil)

	_, err := svc.FinishLogin("ch-1", nil, "", "")
	assert.Error(t, err)
}

// --- ListCredentials ---

func TestWebAuthnService_ListCredentials(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, credRepo, _ := newTestWebAuthnService(t, ctrl)

	now := time.Now().UTC()
	creds := []*domain.WebAuthnCredential{
		{ID: "c1", Name: "Mac", CreatedAt: now, LastUsedAt: now},
	}
	credRepo.EXPECT().ListByUserID("user-123").Return(creds, nil)

	result, err := svc.ListCredentials("user-123")
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "Mac", result[0].Name)
}

// --- RenameCredential ---

func TestWebAuthnService_RenameCredential_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, credRepo, _ := newTestWebAuthnService(t, ctrl)

	creds := []*domain.WebAuthnCredential{{ID: "cred-1", UserID: "user-123"}}
	credRepo.EXPECT().ListByUserID("user-123").Return(creds, nil)
	credRepo.EXPECT().Rename("cred-1", "New Name").Return(nil)

	err := svc.RenameCredential("user-123", "cred-1", "New Name")
	assert.NoError(t, err)
}

func TestWebAuthnService_RenameCredential_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, credRepo, _ := newTestWebAuthnService(t, ctrl)

	credRepo.EXPECT().ListByUserID("user-123").Return(nil, nil)

	err := svc.RenameCredential("user-123", "ghost", "Name")
	assert.ErrorIs(t, err, service.ErrWebAuthnCredentialNotFound)
}

func TestWebAuthnService_RenameCredential_WrongUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, credRepo, _ := newTestWebAuthnService(t, ctrl)

	// User has no credentials — the target cred belongs to someone else
	credRepo.EXPECT().ListByUserID("user-123").Return(nil, nil)

	err := svc.RenameCredential("user-123", "other-users-cred", "Name")
	assert.ErrorIs(t, err, service.ErrWebAuthnCredentialNotFound)
}

// --- DeleteCredential ---

func TestWebAuthnService_DeleteCredential_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, userRepo, credRepo, _ := newTestWebAuthnService(t, ctrl)

	creds := []*domain.WebAuthnCredential{{ID: "cred-1", UserID: "user-123"}}
	credRepo.EXPECT().ListByUserID("user-123").Return(creds, nil)
	credRepo.EXPECT().Delete("cred-1").Return(nil)
	userRepo.EXPECT().GetByID("user-123").Return(activeUser(), nil)

	err := svc.DeleteCredential("user-123", "cred-1")
	assert.NoError(t, err)
}

func TestWebAuthnService_DeleteCredential_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, credRepo, _ := newTestWebAuthnService(t, ctrl)

	credRepo.EXPECT().ListByUserID("user-123").Return(nil, nil)

	err := svc.DeleteCredential("user-123", "ghost")
	assert.ErrorIs(t, err, service.ErrWebAuthnCredentialNotFound)
}

func TestWebAuthnService_DeleteCredential_WrongUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, credRepo, _ := newTestWebAuthnService(t, ctrl)

	credRepo.EXPECT().ListByUserID("user-123").Return(nil, nil)

	err := svc.DeleteCredential("user-123", "other-users-cred")
	assert.ErrorIs(t, err, service.ErrWebAuthnCredentialNotFound)
}

// --- SessionData JSON round-trip ---

func TestWebAuthnSessionData_JSONRoundTrip(t *testing.T) {
	sd := webauthn.SessionData{
		Challenge:            "test-challenge-base64url",
		UserID:               []byte("user-123"),
		UserVerification:     "preferred",
		AllowedCredentialIDs: [][]byte{[]byte("cred-1"), []byte("cred-2")},
	}

	data, err := json.Marshal(sd)
	require.NoError(t, err)

	var restored webauthn.SessionData
	require.NoError(t, json.Unmarshal(data, &restored))

	assert.Equal(t, sd.Challenge, restored.Challenge)
	assert.Equal(t, sd.UserID, restored.UserID)
	assert.Equal(t, sd.UserVerification, restored.UserVerification)
	assert.Len(t, restored.AllowedCredentialIDs, 2)
}
