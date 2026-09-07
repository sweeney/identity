package service_test

// audit_trail_test.go covers WP11 (GHSA-38rv-3m75-4gqr): AuthorizeUser
// recorded nothing on failure.
//
// Login records a login.failure event for every bad attempt. AuthorizeUser is
// the same password check behind /oauth/authorize and the device verification
// page, and it recorded nothing at all — so credential stuffing through either
// of those, at any volume, left the audit log completely clean. The admin
// dashboard, which is where an operator would notice an attack, showed nothing.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

func TestAuthService_AuthorizeUser_RecordsFailures(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*mocks.MockUserRepository)
	}{
		{
			name: "unknown username",
			setup: func(users *mocks.MockUserRepository) {
				users.EXPECT().GetByUsername("ghost").Return(nil, domain.ErrNotFound)
			},
		},
		{
			name: "wrong password",
			setup: func(users *mocks.MockUserRepository) {
				users.EXPECT().GetByUsername("ghost").Return(activeUser(), nil)
			},
		},
		{
			name: "disabled account",
			setup: func(users *mocks.MockUserRepository) {
				u := activeUser()
				u.IsActive = false
				users.EXPECT().GetByUsername("ghost").Return(u, nil)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			users := mocks.NewMockUserRepository(ctrl)
			tokens := mocks.NewMockTokenRepository(ctrl)
			backup := mocks.NewMockBackupService(ctrl)
			audit := mocks.NewMockAuditRepository(ctrl)
			tc.setup(users)

			var recorded []*domain.AuthEvent
			audit.EXPECT().Record(gomock.Any()).DoAndReturn(func(e *domain.AuthEvent) error {
				recorded = append(recorded, e)
				return nil
			}).AnyTimes()

			svc := service.NewAuthService(newTestIssuer(t), users, tokens, backup, audit, 0)
			_, err := svc.AuthorizeUser("ghost", "wrong-password", "203.0.113.7")
			require.Error(t, err)

			require.Len(t, recorded, 1,
				"a failed authorize must leave an audit trail, as a failed login does")
			assert.Equal(t, domain.EventLoginFailure, recorded[0].EventType)
			assert.Equal(t, "ghost", recorded[0].Username)
			assert.Equal(t, "203.0.113.7", recorded[0].IPAddress,
				"the client IP is the whole point of the record")
		})
	}
}

// A successful authorize is already covered by the caller's own events; this
// just pins that the failure path does not fire on success.
func TestAuthService_AuthorizeUser_SuccessRecordsNoFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	users := mocks.NewMockUserRepository(ctrl)
	tokens := mocks.NewMockTokenRepository(ctrl)
	backup := mocks.NewMockBackupService(ctrl)
	audit := mocks.NewMockAuditRepository(ctrl)

	users.EXPECT().GetByUsername("alice").Return(activeUser(), nil)

	var recorded []*domain.AuthEvent
	audit.EXPECT().Record(gomock.Any()).DoAndReturn(func(e *domain.AuthEvent) error {
		recorded = append(recorded, e)
		return nil
	}).AnyTimes()

	svc := service.NewAuthService(newTestIssuer(t), users, tokens, backup, audit, 0)
	id, err := svc.AuthorizeUser("alice", "correctpassword", "203.0.113.7")
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	for _, e := range recorded {
		assert.NotEqual(t, domain.EventLoginFailure, e.EventType)
	}
}

// Passkey login events used to carry no IP and no device hint, so the one
// class of login the dashboard could not attribute was the passwordless one.
func TestWebAuthnService_FinishLogin_AuditCarriesIPAndDevice(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, userRepo, credRepo, challengeRepo := newTestWebAuthnService(t, ctrl)

	user := &domain.User{ID: "user-alice", Username: "alice", Role: domain.RoleUser, IsActive: true}
	authr := newSoftAuthenticator(t, user.ID)
	cred := authr.credential()

	userRepo.EXPECT().GetByID(user.ID).Return(user, nil).AnyTimes()
	credRepo.EXPECT().ListByUserID(user.ID).Return([]*domain.WebAuthnCredential{cred}, nil).AnyTimes()
	credRepo.EXPECT().GetByCredentialID(gomock.Any()).Return(cred, nil).AnyTimes()
	credRepo.EXPECT().UpdateSignCount(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	credRepo.EXPECT().UpdateLastUsed(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	var stored *domain.WebAuthnChallenge
	challengeRepo.EXPECT().Create(gomock.Any()).DoAndReturn(func(ch *domain.WebAuthnChallenge) error {
		stored = ch
		return nil
	})
	challengeRepo.EXPECT().Consume(gomock.Any()).DoAndReturn(func(string) (*domain.WebAuthnChallenge, error) {
		return stored, nil
	})

	assertion, challengeID, err := svc.BeginLogin("")
	require.NoError(t, err)

	req := authr.assertionRequest(t, assertion.Response.Challenge.String(), testRPID, testOrigin)
	_, err = svc.FinishLogin(challengeID, req, "iPhone 15 / iOS 18", "203.0.113.7")
	require.NoError(t, err)

	var success *domain.AuthEvent
	for _, e := range webauthnRecordedEvents {
		if e.EventType == domain.EventPasskeyLoginSuccess {
			success = e
		}
	}
	require.NotNil(t, success, "a passkey login must be audited")
	assert.Equal(t, "203.0.113.7", success.IPAddress, "the client IP must be recorded")
	assert.Equal(t, "iPhone 15 / iOS 18", success.DeviceHint, "the device hint must be recorded")
}
