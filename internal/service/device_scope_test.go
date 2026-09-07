package service_test

// device_scope_test.go covers the remaining WP5 (GHSA-fj5g-j4mv-7m5g) findings.
//
// Scope in the device grant was consent theatre: IssueDeviceAuthorization
// validated the requested scope against the client's allowed scopes, the store
// persisted it, and the approval page showed it to the user — and then issuance
// threw it away. Every device, whatever it asked for, received a token with the
// user's full privileges.
//
// And revoking a claim code did not revoke the tokens it had already produced,
// so a retired device kept working for the refresh token's 30-day window.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/service"
)

func TestDeviceFlowService_PollForToken_IssuesTokenWithConsentedScope(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, auth, clients, devices, _ := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("scoped-1", "device-client", 5*time.Minute)
	da.Status = domain.DeviceStatusApproved
	da.UserID = "user-99"
	da.Scope = "read:sensors"

	devices.EXPECT().GetByDeviceHash(da.DeviceCodeHash).Return(da, nil)
	devices.EXPECT().MarkPolled("scoped-1", gomock.Any()).Return(nil)
	devices.EXPECT().MarkConsumed("scoped-1", gomock.Any()).Return(nil)
	clients.EXPECT().GetByID("device-client").Return(deviceClient(), nil)

	auth.EXPECT().
		IssueTokensForGrant("user-99", gomock.Any()).
		DoAndReturn(func(_ string, grant service.GrantContext) (*service.LoginResult, error) {
			assert.Equal(t, "read:sensors", grant.Scope,
				"the device must receive exactly the scope the user consented to")
			assert.Equal(t, "https://api.example.com", grant.Audience)
			return &service.LoginResult{AccessToken: "a", RefreshToken: "r"}, nil
		})

	_, err := svc.PollForToken("device-client", "raw-scoped-1", "1.2.3.4")
	require.NoError(t, err)
}

func TestDeviceFlowService_PollForToken_BindsTokenToClaimCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, auth, clients, devices, claimCodes := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("scoped-2", "device-client", 5*time.Minute)
	da.Status = domain.DeviceStatusApproved
	da.UserID = "user-99"
	da.ClaimCodeID = "claim-7"

	bound := time.Now().UTC().Add(-time.Hour)
	claimCodes.EXPECT().GetByID("claim-7").
		Return(&domain.ClaimCode{ID: "claim-7", ClientID: "device-client", BoundUserID: "user-99", BoundAt: &bound}, nil).
		AnyTimes()
	devices.EXPECT().GetByDeviceHash(da.DeviceCodeHash).Return(da, nil)
	devices.EXPECT().MarkPolled("scoped-2", gomock.Any()).Return(nil)
	devices.EXPECT().MarkConsumed("scoped-2", gomock.Any()).Return(nil)
	clients.EXPECT().GetByID("device-client").Return(deviceClient(), nil)

	auth.EXPECT().
		IssueTokensForGrant("user-99", gomock.Any()).
		DoAndReturn(func(_ string, grant service.GrantContext) (*service.LoginResult, error) {
			assert.Equal(t, "claim-7", grant.ClaimCodeID,
				"the token family must record the claim code so revoking it reaches these tokens")
			return &service.LoginResult{AccessToken: "a", RefreshToken: "r"}, nil
		})

	_, err := svc.PollForToken("device-client", "raw-scoped-2", "1.2.3.4")
	require.NoError(t, err)
}

func TestDeviceFlowService_RevokeClaimCode_RevokesIssuedTokens(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, _, claimCodes, tokens := newDeviceFlowServiceWithTokens(t, ctrl)

	bound := time.Now().UTC().Add(-time.Hour)
	claimCodes.EXPECT().GetByID("claim-7").
		Return(&domain.ClaimCode{ID: "claim-7", ClientID: "device-client", BoundUserID: "user-99", BoundAt: &bound}, nil)
	claimCodes.EXPECT().Revoke("claim-7", gomock.Any()).Return(nil)

	// The admin UI promises the device stops working. That has to include the
	// tokens it is already holding, not just its next poll.
	tokens.EXPECT().RevokeByClaimCodeID("claim-7").Return(nil)

	require.NoError(t, svc.RevokeClaimCode("claim-7", "1.2.3.4"))
}

// The device grant issues refresh tokens like any other flow, so they must
// carry the client they were issued to. ExchangeCode set this on the PKCE path
// and PollForToken did not, leaving device tokens unbound: a leaked device
// refresh token could be redeemed by any other registered client, which is the
// exact hole WP4 closed everywhere else.
func TestDeviceFlowService_PollForToken_BindsTokenToClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, auth, clients, devices, _ := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("bind-1", "device-client", 5*time.Minute)
	da.Status = domain.DeviceStatusApproved
	da.UserID = "user-99"

	devices.EXPECT().GetByDeviceHash(da.DeviceCodeHash).Return(da, nil)
	devices.EXPECT().MarkPolled("bind-1", gomock.Any()).Return(nil)
	devices.EXPECT().MarkConsumed("bind-1", gomock.Any()).Return(nil)
	clients.EXPECT().GetByID("device-client").Return(deviceClient(), nil)

	auth.EXPECT().
		IssueTokensForGrant("user-99", gomock.Any()).
		DoAndReturn(func(_ string, grant service.GrantContext) (*service.LoginResult, error) {
			assert.Equal(t, "device-client", grant.ClientID,
				"a device-grant token must be bound to the client that polled for it")
			return &service.LoginResult{AccessToken: "a", RefreshToken: "r"}, nil
		})

	_, err := svc.PollForToken("device-client", "raw-bind-1", "1.2.3.4")
	require.NoError(t, err)
}
