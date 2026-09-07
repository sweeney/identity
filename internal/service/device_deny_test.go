package service_test

// device_deny_test.go covers the WP5 (GHSA-fj5g-j4mv-7m5g) findings on denial.
//
// Deny took only a user_code and an IP — no identity at all — so anyone who
// could read the code off a screen could deny the session and stop the
// legitimate owner from signing their device in. Approve requires
// authentication; denial is the same decision with the opposite sign and
// needs the same proof.
//
// Deny also resolved the code only via GetByUserCode. The sticker flow has the
// user type a *claim* code, which Approve handles with a claim-code fallback
// and Deny did not — so "Deny this device" on that page could only ever fail.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/service"
)

func TestDeviceFlowService_Deny_StandardFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, _ := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("deny-1", "device-client", 5*time.Minute)
	devices.EXPECT().GetByUserCode(da.UserCode).Return(da, nil)
	devices.EXPECT().Deny("deny-1", gomock.Any()).Return(nil)

	require.NoError(t, svc.Deny(da.UserCode, "user-99", "alice", "1.2.3.4"))
}

// The sticker flow: the user types the claim code printed on the device, not a
// per-session user_code. Approve resolves that; Deny must too.
func TestDeviceFlowService_Deny_ClaimCodeFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, claimCodes := newDeviceFlowService(t, ctrl)

	bound := time.Now().UTC().Add(-time.Hour)
	cc := &domain.ClaimCode{ID: "claim-9", ClientID: "device-client", BoundUserID: "user-99", BoundAt: &bound}
	pending := pendingAuthorization("deny-2", "device-client", 5*time.Minute)
	pending.ClaimCodeID = "claim-9"

	devices.EXPECT().GetByUserCode(gomock.Any()).Return(nil, domain.ErrNotFound)
	claimCodes.EXPECT().GetByHash(gomock.Any()).Return(cc, nil)
	devices.EXPECT().ListPendingByClaimID("claim-9").Return([]*domain.DeviceAuthorization{pending}, nil)
	devices.EXPECT().Deny("deny-2", gomock.Any()).Return(nil)

	require.NoError(t, svc.Deny("ABCD-1234-EFGH", "user-99", "alice", "1.2.3.4"),
		`"Deny this device" must work in the sticker flow, not only the standard flow`)
}

// A claim code already bound to someone else must not be deniable by a
// different user — the same rule Approve applies.
func TestDeviceFlowService_Deny_ClaimCodeBoundToAnotherUser_Refused(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, claimCodes := newDeviceFlowService(t, ctrl)

	bound := time.Now().UTC().Add(-time.Hour)
	cc := &domain.ClaimCode{ID: "claim-9", ClientID: "device-client", BoundUserID: "someone-else", BoundAt: &bound}

	devices.EXPECT().GetByUserCode(gomock.Any()).Return(nil, domain.ErrNotFound)
	claimCodes.EXPECT().GetByHash(gomock.Any()).Return(cc, nil)

	err := svc.Deny("ABCD-1234-EFGH", "user-99", "alice", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrInvalidUserCode)
}
