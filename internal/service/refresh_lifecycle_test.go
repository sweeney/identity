package service_test

// refresh_lifecycle_test.go covers WP4 (GHSA-vrh2-jqhp-4m44).
//
// Refresh tokens live for 30 days on a sliding window, so anything that should
// end a session has to actually end it. Two did not: changing a password left
// every existing refresh token usable, and logout revoked whatever token it was
// handed without checking it belonged to the caller.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

// Changing a password is how a user responds to a compromise. If the sessions
// opened with the old password survive it, the response does nothing: the
// attacker keeps a working refresh token for up to 30 days.
func TestUserService_Update_PasswordChange_RevokesRefreshTokens(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	user := &domain.User{ID: "u-1", Username: "alice", Role: domain.RoleUser, IsActive: true}
	userRepo.EXPECT().GetByID("u-1").Return(user, nil)
	userRepo.EXPECT().Update(gomock.Any()).Return(nil)
	backupSvc.EXPECT().TriggerAsync().AnyTimes()

	tokenRepo.EXPECT().RevokeAllForUser("u-1").Return(nil).
		Times(1)

	svc := service.NewUserService(userRepo, tokenRepo, backupSvc, nil, maxUsers).WithBcryptCost(4)
	newPassword := "a-brand-new-password"
	_, err := svc.Update("u-1", service.UpdateUserInput{Password: &newPassword})
	require.NoError(t, err)
}

// An edit that does not touch the password must not sign the user out.
func TestUserService_Update_NonPasswordChange_KeepsSessions(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	user := &domain.User{ID: "u-1", Username: "alice", Role: domain.RoleUser, IsActive: true}
	userRepo.EXPECT().GetByID("u-1").Return(user, nil)
	userRepo.EXPECT().Update(gomock.Any()).Return(nil)
	backupSvc.EXPECT().TriggerAsync().AnyTimes()
	// No RevokeAllForUser expectation: calling it here would sign the user out
	// for a display-name edit.

	svc := service.NewUserService(userRepo, tokenRepo, backupSvc, nil, maxUsers).WithBcryptCost(4)
	name := "Alice A."
	_, err := svc.Update("u-1", service.UpdateUserInput{DisplayName: &name})
	require.NoError(t, err)
}

// Logout revoked the token it was handed after looking it up by hash, without
// checking whose it was. Any authenticated user holding someone else's refresh
// token could end their session with it.
func TestAuthService_Logout_RefusesAnotherUsersToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	users := mocks.NewMockUserRepository(ctrl)
	tokens := mocks.NewMockTokenRepository(ctrl)
	backup := mocks.NewMockBackupService(ctrl)
	audit := mocks.NewMockAuditRepository(ctrl)
	audit.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()
	users.EXPECT().GetByID(gomock.Any()).Return(activeUser(), nil).AnyTimes()

	victimToken := &domain.RefreshToken{
		ID:        "tok-victim",
		UserID:    "victim-1",
		TokenHash: service.HashToken("victims-raw-token"),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	tokens.EXPECT().GetByHash(victimToken.TokenHash).Return(victimToken, nil)
	// No RevokeByID expectation: revoking here is the defect.

	svc := service.NewAuthService(newTestIssuer(t), users, tokens, backup, audit, time.Hour)
	err := svc.Logout("attacker-1", "victims-raw-token")

	assert.Error(t, err, "logging out somebody else's session must not succeed")
}

// The owner logging out their own token still works.
func TestAuthService_Logout_OwnTokenSucceeds(t *testing.T) {
	ctrl := gomock.NewController(t)
	users := mocks.NewMockUserRepository(ctrl)
	tokens := mocks.NewMockTokenRepository(ctrl)
	backup := mocks.NewMockBackupService(ctrl)
	audit := mocks.NewMockAuditRepository(ctrl)
	audit.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()
	users.EXPECT().GetByID(gomock.Any()).Return(activeUser(), nil).AnyTimes()

	own := &domain.RefreshToken{
		ID:        "tok-own",
		UserID:    "user-1",
		TokenHash: service.HashToken("my-raw-token"),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	tokens.EXPECT().GetByHash(own.TokenHash).Return(own, nil)
	tokens.EXPECT().RevokeByID("tok-own").Return(nil)

	svc := service.NewAuthService(newTestIssuer(t), users, tokens, backup, audit, time.Hour)
	require.NoError(t, svc.Logout("user-1", "my-raw-token"))
}

// A refresh token issued before the client-binding migration has no recorded
// client. A correct RFC 6749 client still sends its client_id on refresh, so
// comparing the two rejected every pre-existing session on its first refresh —
// signing out every OAuth user the moment the fix deployed.
//
// An unbound token predates the binding and cannot be attributed to a client;
// refusing it buys nothing (that is the pre-migration posture either way) and
// costs every live session. It is accepted and adopted: the rotated token comes
// back bound to the presenting client, so the window closes after one refresh.
func TestAuthService_RefreshForClient_AdoptsLegacyUnboundToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	users := mocks.NewMockUserRepository(ctrl)
	tokens := mocks.NewMockTokenRepository(ctrl)
	backup := mocks.NewMockBackupService(ctrl)
	audit := mocks.NewMockAuditRepository(ctrl)
	audit.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()

	legacy := &domain.RefreshToken{
		ID: "tok-legacy", UserID: "user-123", FamilyID: "fam-1",
		TokenHash: service.HashToken("legacy-raw"),
		ClientID:  "", // issued before migration 009
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	tokens.EXPECT().GetByHash(legacy.TokenHash).Return(legacy, nil).AnyTimes()
	users.EXPECT().GetByID("user-123").Return(activeUser(), nil).AnyTimes()

	var rotated *domain.RefreshToken
	tokens.EXPECT().RotateToken(legacy.TokenHash, gomock.Any()).
		DoAndReturn(func(_ string, newTok *domain.RefreshToken) (*domain.RefreshToken, error) {
			rotated = newTok
			return legacy, nil
		})

	result, err := svcForRefresh(t, users, tokens, backup, audit).
		RefreshForClient("legacy-raw", "claude")

	require.NoError(t, err, "a pre-migration session must survive the upgrade")
	require.NotNil(t, result)
	require.NotNil(t, rotated)
	assert.Equal(t, "claude", rotated.ClientID,
		"the rotated token must be adopted by the presenting client, so the "+
			"binding applies from here on")
}

// A token that *is* bound still refuses a different client.
func TestAuthService_RefreshForClient_BoundTokenRefusesOtherClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	users := mocks.NewMockUserRepository(ctrl)
	tokens := mocks.NewMockTokenRepository(ctrl)
	backup := mocks.NewMockBackupService(ctrl)
	audit := mocks.NewMockAuditRepository(ctrl)
	audit.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()

	bound := &domain.RefreshToken{
		ID: "tok-bound", UserID: "user-123", FamilyID: "fam-1",
		TokenHash: service.HashToken("bound-raw"),
		ClientID:  "photo-app",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	tokens.EXPECT().GetByHash(bound.TokenHash).Return(bound, nil)
	// No RotateToken expectation: the wrong client must not get a rotation.

	_, err := svcForRefresh(t, users, tokens, backup, audit).
		RefreshForClient("bound-raw", "attacker-app")
	assert.ErrorIs(t, err, service.ErrRefreshTokenClientMismatch)
}

func svcForRefresh(
	t *testing.T,
	users *mocks.MockUserRepository,
	tokens *mocks.MockTokenRepository,
	backup *mocks.MockBackupService,
	audit *mocks.MockAuditRepository,
) *service.AuthService {
	t.Helper()
	return service.NewAuthService(newTestIssuer(t), users, tokens, backup, audit, 30*24*time.Hour)
}
