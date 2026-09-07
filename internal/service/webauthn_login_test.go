package service_test

// webauthn_login_test.go covers WP12 (GHSA-9795-969v-64m8).
//
// BeginLogin always runs the *discoverable* ceremony — deliberately, so that
// existing users, users without passkeys and unknown users are indistinguishable
// at login/begin. But when the submitted username resolved to a real account it
// still recorded that user's ID on the challenge, and FinishLogin branched on
// that field into the known-user validation path. go-webauthn's ValidateLogin
// opens with bytes.Equal(user.WebAuthnID(), session.UserID), and a discoverable
// session carries a nil UserID, so the comparison could never succeed.
//
// Two consequences:
//
//  1. Passkey login was permanently broken whenever a username was supplied.
//     The shipped login page does exactly that, so typing your username and
//     clicking "Sign in with passkey" always failed while leaving the field
//     blank worked.
//
//  2. The branch itself was a username oracle: with any valid passkey of their
//     own, an attacker got 200 for a username that does not exist and 401 for
//     one that does — undoing the hardening at login/begin one step later.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/domain"
)

const (
	testRPID   = "localhost"
	testOrigin = "http://localhost:8181"
)

func TestWebAuthnService_FinishLogin_KnownUsername_Succeeds(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, userRepo, credRepo, challengeRepo := newTestWebAuthnService(t, ctrl)

	user := &domain.User{ID: "user-alice", Username: "alice", Role: domain.RoleUser, IsActive: true}
	authr := newSoftAuthenticator(t, user.ID)
	cred := authr.credential()

	userRepo.EXPECT().GetByUsername("alice").Return(user, nil).AnyTimes()
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

	// The user types their username on the login page, as the shipped UI does.
	assertion, challengeID, err := svc.BeginLogin("alice")
	require.NoError(t, err)
	require.NotEmpty(t, challengeID)

	req := authr.assertionRequest(t, assertion.Response.Challenge.String(), testRPID, testOrigin)
	result, err := svc.FinishLogin(challengeID, req, "test-device", "127.0.0.1")

	require.NoError(t, err, "a valid passkey assertion must complete the login")
	require.NotNil(t, result)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
}

// The response to login/finish must not depend on whether the username handed
// to login/begin existed. An attacker holding any valid passkey could otherwise
// read existence off the status code.
func TestWebAuthnService_FinishLogin_UsernameIsNotAnExistenceOracle(t *testing.T) {
	// The attacker owns this account and its passkey.
	attacker := &domain.User{ID: "user-mallory", Username: "mallory", Role: domain.RoleUser, IsActive: true}

	run := func(t *testing.T, probedUsername string, probedExists bool) error {
		t.Helper()
		ctrl := gomock.NewController(t)
		svc, userRepo, credRepo, challengeRepo := newTestWebAuthnService(t, ctrl)

		authr := newSoftAuthenticator(t, attacker.ID)
		cred := authr.credential()

		if probedExists {
			victim := &domain.User{ID: "user-victim", Username: probedUsername, Role: domain.RoleUser, IsActive: true}
			userRepo.EXPECT().GetByUsername(probedUsername).Return(victim, nil).AnyTimes()
			userRepo.EXPECT().GetByID("user-victim").Return(victim, nil).AnyTimes()
			credRepo.EXPECT().ListByUserID("user-victim").Return(nil, nil).AnyTimes()
		} else {
			userRepo.EXPECT().GetByUsername(probedUsername).Return(nil, domain.ErrNotFound).AnyTimes()
		}
		userRepo.EXPECT().GetByID(attacker.ID).Return(attacker, nil).AnyTimes()
		credRepo.EXPECT().ListByUserID(attacker.ID).Return([]*domain.WebAuthnCredential{cred}, nil).AnyTimes()
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

		assertion, challengeID, err := svc.BeginLogin(probedUsername)
		require.NoError(t, err)

		req := authr.assertionRequest(t, assertion.Response.Challenge.String(), testRPID, testOrigin)
		_, err = svc.FinishLogin(challengeID, req, "", "127.0.0.1")
		return err
	}

	var errExisting, errUnknown error
	t.Run("probing an existing username", func(t *testing.T) {
		errExisting = run(t, "alice", true)
	})
	t.Run("probing an unknown username", func(t *testing.T) {
		errUnknown = run(t, "no-such-user", false)
	})

	assert.Equal(t, errUnknown, errExisting,
		"finishing with the attacker's own valid passkey must give the same result "+
			"whether or not the probed username exists")
}
