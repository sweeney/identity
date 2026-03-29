package service_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

// jwtAudience decodes the JWT payload and returns the aud claim values.
// Returns nil if no aud claim is present.
func jwtAudience(t *testing.T, token string) []string {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "expected 3-part JWT")
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(payloadJSON, &payload))
	raw, ok := payload["aud"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []any:
		out := make([]string, len(v))
		for i, s := range v {
			out[i] = s.(string)
		}
		return out
	case string:
		return []string{v}
	default:
		t.Fatalf("unexpected aud type %T", raw)
		return nil
	}
}

func newTestIssuer(t *testing.T) *auth.TokenIssuer {
	t.Helper()
	key, err := auth.GenerateKey()
	require.NoError(t, err)
	issuer, err := auth.NewTokenIssuer(key, nil, "identity.home", 15*time.Minute)
	require.NoError(t, err)
	return issuer
}

func activeUser() *domain.User {
	return &domain.User{
		ID:           "user-123",
		Username:     "alice",
		DisplayName:  "Alice",
		PasswordHash: mustHash("correctpassword"),
		Role:         domain.RoleUser,
		IsActive:     true,
	}
}

func mustHash(password string) string {
	h, err := auth.HashPassword(password, 4)
	if err != nil {
		panic(err)
	}
	return h
}

func newTestAuthService(t *testing.T, ctrl *gomock.Controller, userRepo *mocks.MockUserRepository, tokenRepo *mocks.MockTokenRepository, backupSvc *mocks.MockBackupService) (*service.AuthService, *mocks.MockAuditRepository) {
	t.Helper()
	auditRepo := mocks.NewMockAuditRepository(ctrl)
	auditRepo.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()
	svc := service.NewAuthService(newTestIssuer(t), userRepo, tokenRepo, backupSvc, auditRepo, 30*24*time.Hour)
	return svc, auditRepo
}

// --- Login ---

func TestAuthService_Login_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	user := activeUser()
	userRepo.EXPECT().GetByUsername("alice").Return(user, nil)
	tokenRepo.EXPECT().Create(gomock.Any()).Return(nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	result, err := svc.Login("alice", "correctpassword", "iPhone 15", "1.2.3.4")
	require.NoError(t, err)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.Equal(t, 900, result.ExpiresIn)
}

func TestAuthService_Login_WrongPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	user := activeUser()
	userRepo.EXPECT().GetByUsername("alice").Return(user, nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	_, err := svc.Login("alice", "wrongpassword", "", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrInvalidCredentials)
}

func TestAuthService_Login_UnknownUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	userRepo.EXPECT().GetByUsername("ghost").Return(nil, domain.ErrNotFound)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	_, err := svc.Login("ghost", "password", "", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrInvalidCredentials)
}

func TestAuthService_Login_DisabledUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	user := activeUser()
	user.IsActive = false
	userRepo.EXPECT().GetByUsername("alice").Return(user, nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	_, err := svc.Login("alice", "correctpassword", "", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrAccountDisabled)
}

// --- AuthorizeUser ---

func TestAuthService_AuthorizeUser_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	user := activeUser()
	userRepo.EXPECT().GetByUsername("alice").Return(user, nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	userID, err := svc.AuthorizeUser("alice", "correctpassword", "1.2.3.4")
	require.NoError(t, err)
	assert.Equal(t, "user-123", userID)
}

func TestAuthService_AuthorizeUser_WrongPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	user := activeUser()
	userRepo.EXPECT().GetByUsername("alice").Return(user, nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	_, err := svc.AuthorizeUser("alice", "wrongpassword", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrInvalidCredentials)
}

// --- IssueTokensForUser ---

func TestAuthService_IssueTokensForUser_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	user := activeUser()
	userRepo.EXPECT().GetByID("user-123").Return(user, nil)
	tokenRepo.EXPECT().Create(gomock.Any()).Return(nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	result, err := svc.IssueTokensForUser("user-123", "")
	require.NoError(t, err)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
}

func TestAuthService_IssueTokensForUser_DisabledUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	user := activeUser()
	user.IsActive = false
	userRepo.EXPECT().GetByID("user-123").Return(user, nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	_, err := svc.IssueTokensForUser("user-123", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrAccountDisabled)
}

func TestAuthService_IssueTokensForUser_WithAudience(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	userRepo.EXPECT().GetByID("user-123").Return(activeUser(), nil)
	tokenRepo.EXPECT().Create(gomock.Any()).Return(nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	result, err := svc.IssueTokensForUser("user-123", "mqttproxy")
	require.NoError(t, err)

	aud := jwtAudience(t, result.AccessToken)
	require.NotNil(t, aud, "access token should contain aud claim")
	assert.Equal(t, []string{"mqttproxy"}, aud)
}

func TestAuthService_IssueTokensForUser_NoAudience(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	userRepo.EXPECT().GetByID("user-123").Return(activeUser(), nil)
	tokenRepo.EXPECT().Create(gomock.Any()).Return(nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	result, err := svc.IssueTokensForUser("user-123", "")
	require.NoError(t, err)

	aud := jwtAudience(t, result.AccessToken)
	assert.Nil(t, aud, "access token should not contain aud claim when audience is empty")
}

// --- Refresh ---

func TestAuthService_Refresh_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	rawToken := "some-raw-refresh-token-value-long-enough"
	tokenHash := service.HashToken(rawToken)

	existingToken := &domain.RefreshToken{
		ID:        "tok-1",
		UserID:    "user-123",
		TokenHash: tokenHash,
		FamilyID:  "family-1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IsRevoked: false,
	}

	user := activeUser()
	tokenRepo.EXPECT().RotateToken(tokenHash, gomock.Any()).Return(existingToken, nil)
	userRepo.EXPECT().GetByID("user-123").Return(user, nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	result, err := svc.Refresh(rawToken)
	require.NoError(t, err)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
}

func TestAuthService_Refresh_TokenNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	rawToken := "nonexistent-token-value-long-enough-here"
	tokenRepo.EXPECT().RotateToken(service.HashToken(rawToken), gomock.Any()).Return(nil, domain.ErrNotFound)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	_, err := svc.Refresh(rawToken)
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrInvalidRefreshToken)
}

func TestAuthService_Refresh_AlreadyRevoked_TriggersTheftDetection(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	rawToken := "revoked-token-value-long-enough-here-ok"
	tokenHash := service.HashToken(rawToken)

	revokedToken := &domain.RefreshToken{
		ID:        "tok-revoked",
		UserID:    "user-123",
		TokenHash: tokenHash,
		FamilyID:  "family-1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IsRevoked: true, // already revoked — theft signal
	}

	// RotateToken returns the old token + ErrTokenAlreadyRevoked
	tokenRepo.EXPECT().RotateToken(tokenHash, gomock.Any()).Return(revokedToken, domain.ErrTokenAlreadyRevoked)
	// lookupUsername for audit
	userRepo.EXPECT().GetByID("user-123").Return(activeUser(), nil).AnyTimes()
	// Whole family must be invalidated
	tokenRepo.EXPECT().RevokeFamilyByHash(tokenHash).Return(nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	_, err := svc.Refresh(rawToken)
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrTokenFamilyCompromised)
}

func TestAuthService_Refresh_Expired(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	rawToken := "expired-token-value-long-enough-here-yes"
	tokenHash := service.HashToken(rawToken)

	expiredToken := &domain.RefreshToken{
		ID:        "tok-exp",
		UserID:    "user-123",
		TokenHash: tokenHash,
		FamilyID:  "family-1",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // already expired
		IsRevoked: false,
	}

	// RotateToken succeeds (token was valid), but caller checks expiry after
	tokenRepo.EXPECT().RotateToken(tokenHash, gomock.Any()).Return(expiredToken, nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	_, err := svc.Refresh(rawToken)
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrRefreshTokenExpired)
}

func TestAuthService_Refresh_DisabledUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	rawToken := "valid-token-but-user-disabled-here-okay"
	tokenHash := service.HashToken(rawToken)

	tok := &domain.RefreshToken{
		ID:        "tok-1",
		UserID:    "user-123",
		TokenHash: tokenHash,
		FamilyID:  "family-1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IsRevoked: false,
	}

	disabledUser := activeUser()
	disabledUser.IsActive = false

	tokenRepo.EXPECT().RotateToken(tokenHash, gomock.Any()).Return(tok, nil)
	userRepo.EXPECT().GetByID("user-123").Return(disabledUser, nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	_, err := svc.Refresh(rawToken)
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrAccountDisabled)
}

func TestAuthService_Refresh_PreservesAudience(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	rawToken := "audience-bearing-refresh-token-long-ok"
	tokenHash := service.HashToken(rawToken)

	// Old token carries the audience stored at initial code exchange.
	oldTok := &domain.RefreshToken{
		ID:        "tok-aud",
		UserID:    "user-123",
		TokenHash: tokenHash,
		FamilyID:  "family-aud",
		Audience:  "mqttproxy",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IsRevoked: false,
	}

	tokenRepo.EXPECT().RotateToken(tokenHash, gomock.Any()).Return(oldTok, nil)
	userRepo.EXPECT().GetByID("user-123").Return(activeUser(), nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	result, err := svc.Refresh(rawToken)
	require.NoError(t, err)

	aud := jwtAudience(t, result.AccessToken)
	require.NotNil(t, aud, "refreshed access token should carry aud claim")
	assert.Equal(t, []string{"mqttproxy"}, aud)
}

func TestAuthService_Refresh_NoAudienceWhenTokenHasNone(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	rawToken := "no-audience-refresh-token-value-long-ok"
	tokenHash := service.HashToken(rawToken)

	oldTok := &domain.RefreshToken{
		ID:        "tok-noaud",
		UserID:    "user-123",
		TokenHash: tokenHash,
		FamilyID:  "family-noaud",
		// Audience intentionally empty (direct login, not OAuth PKCE)
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IsRevoked: false,
	}

	tokenRepo.EXPECT().RotateToken(tokenHash, gomock.Any()).Return(oldTok, nil)
	userRepo.EXPECT().GetByID("user-123").Return(activeUser(), nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	result, err := svc.Refresh(rawToken)
	require.NoError(t, err)

	aud := jwtAudience(t, result.AccessToken)
	assert.Nil(t, aud, "refreshed access token should not contain aud when token has no audience")
}

// --- Logout ---

func TestAuthService_Logout_SpecificToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	rawToken := "logout-specific-token-value-long-enough"
	tokenHash := service.HashToken(rawToken)
	tok := &domain.RefreshToken{ID: "tok-logout", UserID: "user-123", TokenHash: tokenHash}

	userRepo.EXPECT().GetByID("user-123").Return(activeUser(), nil).AnyTimes()
	tokenRepo.EXPECT().GetByHash(tokenHash).Return(tok, nil)
	tokenRepo.EXPECT().RevokeByID("tok-logout").Return(nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	err := svc.Logout("user-123", rawToken)
	require.NoError(t, err)
}

func TestAuthService_Logout_AllTokens(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	userRepo.EXPECT().GetByID("user-123").Return(activeUser(), nil).AnyTimes()
	tokenRepo.EXPECT().RevokeAllForUser("user-123").Return(nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	// Empty refresh token string means revoke all
	err := svc.Logout("user-123", "")
	require.NoError(t, err)
}
