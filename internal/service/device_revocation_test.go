package service_test

// device_revocation_test.go covers WP5 (GHSA-fj5g-j4mv-7m5g): revoking a claim
// code did not stop the device paired with it.
//
// The admin UI says "The device will stop working", and an operator revoking a
// sticker code for a lost or compromised device is entitled to believe it. But
// PollForToken never looked at the claim code the session came from, so a
// device that had already exchanged its sticker for a device_code kept polling
// successfully and kept being handed fresh tokens.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/service"
)

func revokedClaimCode(id string) *domain.ClaimCode {
	revoked := time.Now().UTC().Add(-time.Minute)
	bound := time.Now().UTC().Add(-time.Hour)
	return &domain.ClaimCode{
		ID:          id,
		ClientID:    "device-client",
		Label:       "Kitchen sensor",
		BoundUserID: "user-99",
		BoundAt:     &bound,
		RevokedAt:   &revoked,
	}
}

func TestDeviceFlowService_PollForToken_RevokedClaimCode_StopsTheDevice(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, claimCodes := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("appr-2", "device-client", 5*time.Minute)
	da.Status = domain.DeviceStatusApproved
	da.UserID = "user-99"
	da.ClaimCodeID = "claim-1"

	devices.EXPECT().GetByDeviceHash(da.DeviceCodeHash).Return(da, nil)
	devices.EXPECT().MarkPolled("appr-2", gomock.Any()).Return(nil)
	claimCodes.EXPECT().GetByID("claim-1").Return(revokedClaimCode("claim-1"), nil).AnyTimes()

	// No MarkConsumed and no IssueTokensForUser expectation: reaching either
	// means the revoked device was served.
	_, err := svc.PollForToken("device-client", "raw-appr-2", "1.2.3.4")

	require.Error(t, err, "a device whose claim code was revoked must stop working")
	assert.ErrorIs(t, err, service.ErrClaimCodeRevoked)
}

func TestDeviceFlowService_PollForToken_LiveClaimCode_StillWorks(t *testing.T) {
	// Control: an unrevoked claim code keeps issuing tokens as before.
	ctrl := gomock.NewController(t)
	svc, auth, clients, devices, claimCodes := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("appr-3", "device-client", 5*time.Minute)
	da.Status = domain.DeviceStatusApproved
	da.UserID = "user-99"
	da.ClaimCodeID = "claim-2"

	bound := time.Now().UTC().Add(-time.Hour)
	live := &domain.ClaimCode{ID: "claim-2", ClientID: "device-client", BoundUserID: "user-99", BoundAt: &bound}

	devices.EXPECT().GetByDeviceHash(da.DeviceCodeHash).Return(da, nil)
	devices.EXPECT().MarkPolled("appr-3", gomock.Any()).Return(nil)
	devices.EXPECT().MarkConsumed("appr-3", gomock.Any()).Return(nil)
	claimCodes.EXPECT().GetByID("claim-2").Return(live, nil).AnyTimes()
	clients.EXPECT().GetByID("device-client").Return(deviceClient(), nil)
	auth.EXPECT().IssueTokensForUser("user-99", "https://api.example.com").
		Return(&service.LoginResult{AccessToken: "a", RefreshToken: "r"}, nil)

	got, err := svc.PollForToken("device-client", "raw-appr-3", "1.2.3.4")
	require.NoError(t, err)
	assert.Equal(t, "a", got.AccessToken)
}
