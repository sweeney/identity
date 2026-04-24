package service_test

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

func newDeviceFlowService(t *testing.T, ctrl *gomock.Controller) (
	*service.DeviceFlowService,
	*mocks.MockAuthServicer,
	*mocks.MockOAuthClientRepository,
	*mocks.MockDeviceAuthorizationRepository,
	*mocks.MockClaimCodeRepository,
) {
	t.Helper()
	auth := mocks.NewMockAuthServicer(ctrl)
	clients := mocks.NewMockOAuthClientRepository(ctrl)
	devices := mocks.NewMockDeviceAuthorizationRepository(ctrl)
	claimCodes := mocks.NewMockClaimCodeRepository(ctrl)
	audit := mocks.NewMockAuditRepository(ctrl)
	audit.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()

	svc := service.NewDeviceFlowService(auth, clients, devices, claimCodes, audit, service.DeviceFlowConfig{
		DeviceCodeTTL:   10 * time.Minute,
		PollInterval:    5,
		VerificationURI: "https://id.example.com/device",
	})
	return svc, auth, clients, devices, claimCodes
}

func deviceClient() *domain.OAuthClient {
	return &domain.OAuthClient{
		ID:         "device-client",
		Name:       "Home IoT",
		GrantTypes: []string{domain.GrantTypeDeviceCode},
		Scopes:     []string{"read:sensors", "write:sensors"},
		Audience:   "https://api.example.com",
	}
}

// --- IssueDeviceAuthorization ---

func TestDeviceFlowService_IssueDeviceAuthorization_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, devices, _ := newDeviceFlowService(t, ctrl)

	clients.EXPECT().GetByID("device-client").Return(deviceClient(), nil)
	devices.EXPECT().Create(gomock.Any()).DoAndReturn(func(da *domain.DeviceAuthorization) error {
		assert.Equal(t, "device-client", da.ClientID)
		assert.Equal(t, domain.DeviceStatusPending, da.Status)
		assert.NotEmpty(t, da.DeviceCodeHash)
		assert.Regexp(t, `^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}$`, da.UserCode)
		assert.Equal(t, 5, da.PollInterval)
		return nil
	})

	res, err := svc.IssueDeviceAuthorization("device-client", "read:sensors", "1.2.3.4")
	require.NoError(t, err)
	assert.NotEmpty(t, res.DeviceCode)
	assert.NotEmpty(t, res.UserCode)
	assert.Equal(t, "https://id.example.com/device", res.VerificationURI)
	assert.Contains(t, res.VerificationURIComplete, "user_code=")
	assert.Equal(t, 600, res.ExpiresIn)
	assert.Equal(t, 5, res.Interval)
}

func TestDeviceFlowService_IssueDeviceAuthorization_UnknownClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, _, _ := newDeviceFlowService(t, ctrl)

	clients.EXPECT().GetByID("unknown").Return(nil, domain.ErrNotFound)

	_, err := svc.IssueDeviceAuthorization("unknown", "", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrUnknownClient)
}

func TestDeviceFlowService_IssueDeviceAuthorization_ClientMissingGrant(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, _, _ := newDeviceFlowService(t, ctrl)

	c := deviceClient()
	c.GrantTypes = []string{"authorization_code"}
	clients.EXPECT().GetByID("device-client").Return(c, nil)

	_, err := svc.IssueDeviceAuthorization("device-client", "", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrUnauthorizedClient)
}

func TestDeviceFlowService_IssueDeviceAuthorization_InvalidScope(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, _, _ := newDeviceFlowService(t, ctrl)

	clients.EXPECT().GetByID("device-client").Return(deviceClient(), nil)

	_, err := svc.IssueDeviceAuthorization("device-client", "admin:everything", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrInvalidScope)
}

// --- ClaimDevice ---

func TestDeviceFlowService_ClaimDevice_UnboundCodePending(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, devices, claimCodes := newDeviceFlowService(t, ctrl)

	clients.EXPECT().GetByID("device-client").Return(deviceClient(), nil)
	cc := &domain.ClaimCode{
		ID:        "cc-1",
		CodeHash:  service.HashToken("KITCHEN-0001-ABCD"),
		ClientID:  "device-client",
		Label:     "Kitchen",
		CreatedAt: time.Now().UTC(),
	}
	claimCodes.EXPECT().GetByHash(service.HashToken("KITCHEN-0001-ABCD")).Return(cc, nil)
	devices.EXPECT().Create(gomock.Any()).DoAndReturn(func(da *domain.DeviceAuthorization) error {
		assert.Equal(t, "cc-1", da.ClaimCodeID)
		assert.Equal(t, domain.DeviceStatusPending, da.Status)
		return nil
	})

	res, err := svc.ClaimDevice("device-client", "KITCHEN-0001-ABCD", "", "1.2.3.4")
	require.NoError(t, err)
	assert.Equal(t, "KITCHEN-0001-ABCD", res.ClaimCode)
	assert.NotEmpty(t, res.DeviceCode)
}

func TestDeviceFlowService_ClaimDevice_BoundCodeAutoApproves(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, devices, claimCodes := newDeviceFlowService(t, ctrl)

	clients.EXPECT().GetByID("device-client").Return(deviceClient(), nil)
	boundAt := time.Now().UTC().Add(-24 * time.Hour)
	cc := &domain.ClaimCode{
		ID:          "cc-bound",
		CodeHash:    service.HashToken("BOUND-CODE-FOO0"),
		ClientID:    "device-client",
		BoundUserID: "user-42",
		BoundAt:     &boundAt,
		CreatedAt:   boundAt,
	}
	claimCodes.EXPECT().GetByHash(service.HashToken("BOUND-CODE-FOO0")).Return(cc, nil)

	var capturedID string
	devices.EXPECT().Create(gomock.Any()).DoAndReturn(func(da *domain.DeviceAuthorization) error {
		capturedID = da.ID
		return nil
	})
	devices.EXPECT().Approve(gomock.Any(), "user-42", gomock.Any()).DoAndReturn(func(id, userID string, _ time.Time) error {
		assert.Equal(t, capturedID, id)
		return nil
	})

	_, err := svc.ClaimDevice("device-client", "BOUND-CODE-FOO0", "", "1.2.3.4")
	require.NoError(t, err)
}

func TestDeviceFlowService_ClaimDevice_UnknownCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, _, claimCodes := newDeviceFlowService(t, ctrl)

	clients.EXPECT().GetByID("device-client").Return(deviceClient(), nil)
	claimCodes.EXPECT().GetByHash(gomock.Any()).Return(nil, domain.ErrNotFound)

	_, err := svc.ClaimDevice("device-client", "DEAD-BEEF-CAFE", "", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrInvalidClaimCode)
}

func TestDeviceFlowService_ClaimDevice_RevokedCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, _, claimCodes := newDeviceFlowService(t, ctrl)

	clients.EXPECT().GetByID("device-client").Return(deviceClient(), nil)
	revoked := time.Now().UTC().Add(-1 * time.Hour)
	cc := &domain.ClaimCode{
		ID:        "cc-rev",
		CodeHash:  service.HashToken("REV-OKED-CODE"),
		ClientID:  "device-client",
		RevokedAt: &revoked,
	}
	claimCodes.EXPECT().GetByHash(gomock.Any()).Return(cc, nil)

	_, err := svc.ClaimDevice("device-client", "REV-OKED-CODE", "", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrClaimCodeRevoked)
}

func TestDeviceFlowService_ClaimDevice_WrongClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, _, claimCodes := newDeviceFlowService(t, ctrl)

	clients.EXPECT().GetByID("device-client").Return(deviceClient(), nil)
	cc := &domain.ClaimCode{
		ID:       "cc-mismatch",
		CodeHash: service.HashToken("MISM-ATCH-CODE"),
		ClientID: "other-client",
	}
	claimCodes.EXPECT().GetByHash(gomock.Any()).Return(cc, nil)

	_, err := svc.ClaimDevice("device-client", "MISM-ATCH-CODE", "", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrInvalidClaimCode)
}

// --- PollForToken ---

func pendingAuthorization(id, clientID string, ttl time.Duration) *domain.DeviceAuthorization {
	now := time.Now().UTC()
	return &domain.DeviceAuthorization{
		ID:             id,
		DeviceCodeHash: service.HashToken("raw-" + id),
		UserCode:       "USR-CODE",
		ClientID:       clientID,
		Status:         domain.DeviceStatusPending,
		IssuedAt:       now,
		ExpiresAt:      now.Add(ttl),
		PollInterval:   5,
	}
}

func TestDeviceFlowService_PollForToken_Pending(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, _ := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("pend-1", "device-client", 5*time.Minute)
	devices.EXPECT().GetByDeviceHash(da.DeviceCodeHash).Return(da, nil)
	devices.EXPECT().MarkPolled("pend-1", gomock.Any()).Return(nil)

	_, err := svc.PollForToken("device-client", "raw-pend-1", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrDeviceAuthorizationPending)
}

func TestDeviceFlowService_PollForToken_Denied(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, _ := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("deny-1", "device-client", 5*time.Minute)
	da.Status = domain.DeviceStatusDenied
	devices.EXPECT().GetByDeviceHash(da.DeviceCodeHash).Return(da, nil)
	devices.EXPECT().MarkPolled("deny-1", gomock.Any()).Return(nil)

	_, err := svc.PollForToken("device-client", "raw-deny-1", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrDeviceAuthorizationDenied)
}

func TestDeviceFlowService_PollForToken_Expired(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, _ := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("exp-1", "device-client", -1*time.Minute)
	devices.EXPECT().GetByDeviceHash(da.DeviceCodeHash).Return(da, nil)

	_, err := svc.PollForToken("device-client", "raw-exp-1", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrDeviceCodeExpired)
}

func TestDeviceFlowService_PollForToken_SlowDown(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, _ := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("sd-1", "device-client", 5*time.Minute)
	justPolled := time.Now().UTC().Add(-1 * time.Second) // 1s ago, interval is 5s
	da.LastPolledAt = &justPolled
	devices.EXPECT().GetByDeviceHash(da.DeviceCodeHash).Return(da, nil)
	devices.EXPECT().MarkPolled("sd-1", gomock.Any()).Return(nil)

	_, err := svc.PollForToken("device-client", "raw-sd-1", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrDeviceSlowDown)
}

func TestDeviceFlowService_PollForToken_ClientMismatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, _ := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("mis-1", "device-client", 5*time.Minute)
	devices.EXPECT().GetByDeviceHash(da.DeviceCodeHash).Return(da, nil)

	_, err := svc.PollForToken("other-client", "raw-mis-1", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrInvalidDeviceCode)
}

func TestDeviceFlowService_PollForToken_UnknownCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, _ := newDeviceFlowService(t, ctrl)

	devices.EXPECT().GetByDeviceHash(gomock.Any()).Return(nil, domain.ErrNotFound)

	_, err := svc.PollForToken("device-client", "nonexistent", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrInvalidDeviceCode)
}

func TestDeviceFlowService_PollForToken_Approved_IssuesTokens(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, auth, clients, devices, _ := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("appr-1", "device-client", 5*time.Minute)
	da.Status = domain.DeviceStatusApproved
	da.UserID = "user-99"
	devices.EXPECT().GetByDeviceHash(da.DeviceCodeHash).Return(da, nil)
	devices.EXPECT().MarkPolled("appr-1", gomock.Any()).Return(nil)
	devices.EXPECT().MarkConsumed("appr-1", gomock.Any()).Return(nil)
	clients.EXPECT().GetByID("device-client").Return(deviceClient(), nil)

	tokens := &service.LoginResult{
		AccessToken:  "access.token.value",
		TokenType:    "Bearer",
		ExpiresIn:    900,
		RefreshToken: "refresh.xyz",
	}
	auth.EXPECT().IssueTokensForUser("user-99", "https://api.example.com").Return(tokens, nil)

	got, err := svc.PollForToken("device-client", "raw-appr-1", "1.2.3.4")
	require.NoError(t, err)
	assert.Equal(t, "access.token.value", got.AccessToken)
	assert.Equal(t, "refresh.xyz", got.RefreshToken)
}

func TestDeviceFlowService_PollForToken_ApprovedButAlreadyConsumed(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, _ := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("cons-1", "device-client", 5*time.Minute)
	da.Status = domain.DeviceStatusApproved
	da.UserID = "user-99"
	devices.EXPECT().GetByDeviceHash(da.DeviceCodeHash).Return(da, nil)
	devices.EXPECT().MarkPolled("cons-1", gomock.Any()).Return(nil)
	devices.EXPECT().MarkConsumed("cons-1", gomock.Any()).Return(domain.ErrNotFound)

	_, err := svc.PollForToken("device-client", "raw-cons-1", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrInvalidDeviceCode)
}

// --- Approve (user_code flow) ---

func TestDeviceFlowService_Approve_UserCodeFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, _ := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("ap-uc", "device-client", 5*time.Minute)
	da.UserCode = "WXYZ-1234"
	devices.EXPECT().GetByUserCode("WXYZ-1234").Return(da, nil)
	devices.EXPECT().Approve("ap-uc", "user-1", gomock.Any()).Return(nil)

	err := svc.Approve("wxyz-1234", "user-1", "alice", "1.2.3.4")
	require.NoError(t, err)
}

func TestDeviceFlowService_Approve_UserCodeFlow_Expired(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, _ := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("ap-exp", "device-client", -1*time.Minute)
	da.UserCode = "WXYZ-EXPD"
	devices.EXPECT().GetByUserCode("WXYZ-EXPD").Return(da, nil)

	err := svc.Approve("WXYZ-EXPD", "user-1", "alice", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrDeviceCodeExpired)
}

func TestDeviceFlowService_Approve_UserCodeFlow_AlreadyApproved(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, _ := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("ap-twice", "device-client", 5*time.Minute)
	da.Status = domain.DeviceStatusApproved
	da.UserCode = "TWIC-EONE"
	devices.EXPECT().GetByUserCode("TWIC-EONE").Return(da, nil)

	err := svc.Approve("TWIC-EONE", "user-1", "alice", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrInvalidUserCode)
}

// --- Approve (claim_code flow) ---

func TestDeviceFlowService_Approve_ClaimCode_UnboundBindsAndApprovesPending(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, claimCodes := newDeviceFlowService(t, ctrl)

	devices.EXPECT().GetByUserCode(gomock.Any()).Return(nil, domain.ErrNotFound)

	raw := "KTCHN-0001-ABCD"
	cc := &domain.ClaimCode{
		ID:        "cc-k1",
		CodeHash:  service.HashToken(raw),
		ClientID:  "device-client",
		CreatedAt: time.Now().UTC().Add(-1 * time.Hour),
	}
	claimCodes.EXPECT().GetByHash(service.HashToken(raw)).Return(cc, nil)
	claimCodes.EXPECT().Bind("cc-k1", "user-7", gomock.Any()).Return(nil)

	// One pending session tied to this claim → service approves it.
	pending := []*domain.DeviceAuthorization{
		{ID: "sess-1", ClientID: "device-client", ClaimCodeID: "cc-k1", Status: domain.DeviceStatusPending},
	}
	devices.EXPECT().ListPendingByClaimID("cc-k1").Return(pending, nil)
	devices.EXPECT().Approve("sess-1", "user-7", gomock.Any()).Return(nil)

	err := svc.Approve(raw, "user-7", "alice", "1.2.3.4")
	require.NoError(t, err)
}

func TestDeviceFlowService_Approve_ClaimCode_BoundToOtherUserRejected(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, claimCodes := newDeviceFlowService(t, ctrl)

	devices.EXPECT().GetByUserCode(gomock.Any()).Return(nil, domain.ErrNotFound)

	raw := "OTHR-USER-CODE"
	bound := time.Now().UTC().Add(-24 * time.Hour)
	cc := &domain.ClaimCode{
		ID:          "cc-other",
		CodeHash:    service.HashToken(raw),
		ClientID:    "device-client",
		BoundUserID: "user-other",
		BoundAt:     &bound,
	}
	claimCodes.EXPECT().GetByHash(service.HashToken(raw)).Return(cc, nil)

	err := svc.Approve(raw, "user-me", "me", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrInvalidUserCode)
}

func TestDeviceFlowService_Approve_ClaimCode_Revoked(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, claimCodes := newDeviceFlowService(t, ctrl)

	devices.EXPECT().GetByUserCode(gomock.Any()).Return(nil, domain.ErrNotFound)

	raw := "REVO-KED0-CLAIM"
	revoked := time.Now().UTC().Add(-1 * time.Hour)
	cc := &domain.ClaimCode{
		ID:        "cc-rev",
		CodeHash:  service.HashToken(raw),
		ClientID:  "device-client",
		RevokedAt: &revoked,
	}
	claimCodes.EXPECT().GetByHash(service.HashToken(raw)).Return(cc, nil)

	err := svc.Approve(raw, "user-7", "alice", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrClaimCodeRevoked)
}

// --- Deny ---

func TestDeviceFlowService_Deny(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, _ := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("deny-me", "device-client", 5*time.Minute)
	da.UserCode = "DENY-MEEE"
	devices.EXPECT().GetByUserCode("DENY-MEEE").Return(da, nil)
	devices.EXPECT().Deny("deny-me", gomock.Any()).Return(nil)

	err := svc.Deny("DENY-MEEE", "1.2.3.4")
	require.NoError(t, err)
}

// --- CreateClaimCodes ---

func TestDeviceFlowService_CreateClaimCodes_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, _, claimCodes := newDeviceFlowService(t, ctrl)

	clients.EXPECT().GetByID("device-client").Return(deviceClient(), nil)
	claimCodes.EXPECT().Create(gomock.Any()).Return(nil).Times(3)

	results, err := svc.CreateClaimCodes("device-client", []string{"Kitchen", "Hall", "Garage"}, "1.2.3.4")
	require.NoError(t, err)
	require.Len(t, results, 3)

	seen := map[string]bool{}
	for _, r := range results {
		assert.NotEmpty(t, r.RawCode)
		assert.Regexp(t, `^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}$`, r.RawCode)
		assert.False(t, seen[r.RawCode], "claim codes must be unique")
		seen[r.RawCode] = true
	}
	assert.Equal(t, "Kitchen", results[0].Label)
	assert.Equal(t, "Garage", results[2].Label)
}

func TestDeviceFlowService_CreateClaimCodes_ClientMissingGrant(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, _, _ := newDeviceFlowService(t, ctrl)

	c := deviceClient()
	c.GrantTypes = []string{"authorization_code"}
	clients.EXPECT().GetByID("device-client").Return(c, nil)

	_, err := svc.CreateClaimCodes("device-client", []string{"Kitchen"}, "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrUnauthorizedClient)
}

// --- RevokeClaimCode ---

func TestDeviceFlowService_RevokeClaimCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, _, claimCodes := newDeviceFlowService(t, ctrl)

	cc := &domain.ClaimCode{ID: "cc-rev", ClientID: "device-client"}
	claimCodes.EXPECT().GetByID("cc-rev").Return(cc, nil)
	claimCodes.EXPECT().Revoke("cc-rev", gomock.Any()).Return(nil)

	require.NoError(t, svc.RevokeClaimCode("cc-rev", "1.2.3.4"))
}

func TestDeviceFlowService_RevokeClaimCode_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, _, claimCodes := newDeviceFlowService(t, ctrl)

	claimCodes.EXPECT().GetByID("missing").Return(nil, domain.ErrNotFound)

	err := svc.RevokeClaimCode("missing", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrInvalidClaimCode)
}

// --- DeleteClaimCode ---

func TestDeviceFlowService_DeleteClaimCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, _, claimCodes := newDeviceFlowService(t, ctrl)

	now := time.Now().UTC()
	cc := &domain.ClaimCode{ID: "cc-del", ClientID: "device-client", RevokedAt: &now}
	claimCodes.EXPECT().GetByID("cc-del").Return(cc, nil)
	claimCodes.EXPECT().Delete("cc-del").Return(nil)

	require.NoError(t, svc.DeleteClaimCode("cc-del", "1.2.3.4"))
}

func TestDeviceFlowService_DeleteClaimCode_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, _, claimCodes := newDeviceFlowService(t, ctrl)

	claimCodes.EXPECT().GetByID("missing").Return(nil, domain.ErrNotFound)

	err := svc.DeleteClaimCode("missing", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrInvalidClaimCode)
}

func TestDeviceFlowService_DeleteClaimCode_NotRevoked(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, _, claimCodes := newDeviceFlowService(t, ctrl)

	cc := &domain.ClaimCode{ID: "cc-active", ClientID: "device-client"}
	claimCodes.EXPECT().GetByID("cc-active").Return(cc, nil)

	err := svc.DeleteClaimCode("cc-active", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrInvalidClaimCode)
}

// --- LookupForVerification ---

func TestDeviceFlowService_LookupForVerification_UserCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, devices, _ := newDeviceFlowService(t, ctrl)

	da := pendingAuthorization("lv-1", "device-client", 5*time.Minute)
	da.UserCode = "LOOK-CODE"
	devices.EXPECT().GetByUserCode("LOOK-CODE").Return(da, nil)
	clients.EXPECT().GetByID("device-client").Return(deviceClient(), nil)

	view, err := svc.LookupForVerification("look-code")
	require.NoError(t, err)
	require.NotNil(t, view.Authorization)
	assert.Equal(t, "lv-1", view.Authorization.ID)
	assert.Equal(t, "Home IoT", view.Client.Name)
	assert.Nil(t, view.ClaimCode)
}

func TestDeviceFlowService_LookupForVerification_ClaimCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, devices, claimCodes := newDeviceFlowService(t, ctrl)

	devices.EXPECT().GetByUserCode(gomock.Any()).Return(nil, domain.ErrNotFound)

	raw := "CLAIM-CODE-STIK"
	cc := &domain.ClaimCode{
		ID: "cc-lv", CodeHash: service.HashToken(raw), ClientID: "device-client", Label: "Kitchen",
	}
	claimCodes.EXPECT().GetByHash(service.HashToken(raw)).Return(cc, nil)
	clients.EXPECT().GetByID("device-client").Return(deviceClient(), nil)

	view, err := svc.LookupForVerification(raw)
	require.NoError(t, err)
	require.NotNil(t, view.ClaimCode)
	assert.Equal(t, "Kitchen", view.ClaimCode.Label)
	assert.Equal(t, "Home IoT", view.Client.Name)
}

func TestDeviceFlowService_LookupForVerification_Unknown(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, devices, claimCodes := newDeviceFlowService(t, ctrl)

	devices.EXPECT().GetByUserCode(gomock.Any()).Return(nil, domain.ErrNotFound)
	claimCodes.EXPECT().GetByHash(gomock.Any()).Return(nil, domain.ErrNotFound)

	_, err := svc.LookupForVerification("NEVE-RCODE")
	assert.ErrorIs(t, err, service.ErrInvalidUserCode)
}
