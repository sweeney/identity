package oauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/handler/oauth"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

func newDeviceRouter(svc service.OAuthServicer, deviceSvc service.DeviceFlowServicer, authSvc service.AuthServicer) http.Handler {
	return oauth.NewRouter(svc, "", nil, authSvc, nil, deviceSvc, "", "Test")
}

// --- POST /oauth/device_authorization ---

func TestDeviceAuthorization_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)

	result := &service.DeviceAuthorizationResult{
		DeviceCode:              "raw-device",
		UserCode:                "ABCD-EFGH",
		VerificationURI:         "https://id.example.com/device",
		VerificationURIComplete: "https://id.example.com/device?user_code=ABCD-EFGH",
		ExpiresIn:               600,
		Interval:                5,
	}
	deviceSvc.EXPECT().IssueDeviceAuthorization("device-client", "read:sensors", gomock.Any()).Return(result, nil)

	h := newDeviceRouter(svc, deviceSvc, nil)
	rr := postForm(t, h, "/oauth/device_authorization", url.Values{
		"client_id": {"device-client"},
		"scope":     {"read:sensors"},
	})
	require.Equal(t, http.StatusOK, rr.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "raw-device", body["device_code"])
	assert.Equal(t, "ABCD-EFGH", body["user_code"])
	assert.Equal(t, float64(5), body["interval"])
}

func TestDeviceAuthorization_MissingClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)

	h := newDeviceRouter(svc, deviceSvc, nil)
	rr := postForm(t, h, "/oauth/device_authorization", url.Values{})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_request")
}

func TestDeviceAuthorization_UnauthorizedClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	deviceSvc.EXPECT().IssueDeviceAuthorization("bad", "", gomock.Any()).Return(nil, service.ErrUnauthorizedClient)

	h := newDeviceRouter(svc, deviceSvc, nil)
	rr := postForm(t, h, "/oauth/device_authorization", url.Values{
		"client_id": {"bad"},
	})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "unauthorized_client")
}

func TestDeviceAuthorization_UnknownClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	deviceSvc.EXPECT().IssueDeviceAuthorization("nope", "", gomock.Any()).Return(nil, service.ErrUnknownClient)

	h := newDeviceRouter(svc, deviceSvc, nil)
	rr := postForm(t, h, "/oauth/device_authorization", url.Values{"client_id": {"nope"}})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_client")
}

func TestDeviceAuthorization_DisabledWhenServiceNil(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	h := oauth.NewRouter(svc, "", nil, nil, nil, nil, "", "")
	rr := postForm(t, h, "/oauth/device_authorization", url.Values{"client_id": {"any"}})
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --- POST /oauth/device/claim ---

func TestDeviceClaim_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)

	result := &service.DeviceAuthorizationResult{
		DeviceCode:      "raw-dev",
		UserCode:        "UCUC-1234",
		ClaimCode:       "KTCH-0001-ABCD",
		VerificationURI: "https://id.example.com/device",
		ExpiresIn:       600,
		Interval:        5,
	}
	deviceSvc.EXPECT().ClaimDevice("device-client", "KTCH-0001-ABCD", "", gomock.Any()).Return(result, nil)

	h := newDeviceRouter(svc, deviceSvc, nil)
	rr := postForm(t, h, "/oauth/device/claim", url.Values{
		"client_id":  {"device-client"},
		"claim_code": {"KTCH-0001-ABCD"},
	})
	require.Equal(t, http.StatusOK, rr.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "raw-dev", body["device_code"])
	assert.Equal(t, "KTCH-0001-ABCD", body["claim_code"])
}

func TestDeviceClaim_MissingFields(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)

	h := newDeviceRouter(svc, deviceSvc, nil)
	rr := postForm(t, h, "/oauth/device/claim", url.Values{"client_id": {"device-client"}})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_request")
}

func TestDeviceClaim_InvalidClaim(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	deviceSvc.EXPECT().ClaimDevice("device-client", "DEAD-CODE-ZZZZ", "", gomock.Any()).Return(nil, service.ErrInvalidClaimCode)

	h := newDeviceRouter(svc, deviceSvc, nil)
	rr := postForm(t, h, "/oauth/device/claim", url.Values{
		"client_id":  {"device-client"},
		"claim_code": {"DEAD-CODE-ZZZZ"},
	})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")
}

func TestDeviceClaim_Revoked(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	deviceSvc.EXPECT().ClaimDevice(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, service.ErrClaimCodeRevoked)

	h := newDeviceRouter(svc, deviceSvc, nil)
	rr := postForm(t, h, "/oauth/device/claim", url.Values{
		"client_id":  {"device-client"},
		"claim_code": {"ANY-CODE-XYZ0"},
	})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")
}

// --- POST /oauth/token (device_code grant) ---

func TestTokenDeviceCode_AuthorizationPending(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	deviceSvc.EXPECT().PollForToken("device-client", "raw-device", gomock.Any()).Return(nil, service.ErrDeviceAuthorizationPending)

	h := newDeviceRouter(svc, deviceSvc, nil)
	rr := postForm(t, h, "/oauth/token", url.Values{
		"grant_type":  {domain.GrantTypeDeviceCode},
		"client_id":   {"device-client"},
		"device_code": {"raw-device"},
	})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "authorization_pending")
}

func TestTokenDeviceCode_SlowDown(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	deviceSvc.EXPECT().PollForToken(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, service.ErrDeviceSlowDown)

	h := newDeviceRouter(svc, deviceSvc, nil)
	rr := postForm(t, h, "/oauth/token", url.Values{
		"grant_type":  {domain.GrantTypeDeviceCode},
		"client_id":   {"device-client"},
		"device_code": {"raw-device"},
	})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "slow_down")
}

func TestTokenDeviceCode_Expired(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	deviceSvc.EXPECT().PollForToken(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, service.ErrDeviceCodeExpired)

	h := newDeviceRouter(svc, deviceSvc, nil)
	rr := postForm(t, h, "/oauth/token", url.Values{
		"grant_type":  {domain.GrantTypeDeviceCode},
		"client_id":   {"device-client"},
		"device_code": {"raw-device"},
	})
	assert.Contains(t, rr.Body.String(), "expired_token")
}

func TestTokenDeviceCode_Denied(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	deviceSvc.EXPECT().PollForToken(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, service.ErrDeviceAuthorizationDenied)

	h := newDeviceRouter(svc, deviceSvc, nil)
	rr := postForm(t, h, "/oauth/token", url.Values{
		"grant_type":  {domain.GrantTypeDeviceCode},
		"client_id":   {"device-client"},
		"device_code": {"raw-device"},
	})
	assert.Contains(t, rr.Body.String(), "access_denied")
}

func TestTokenDeviceCode_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	result := &service.LoginResult{
		AccessToken:  "a.b.c",
		TokenType:    "Bearer",
		ExpiresIn:    900,
		RefreshToken: "refresh.xyz",
	}
	deviceSvc.EXPECT().PollForToken(gomock.Any(), gomock.Any(), gomock.Any()).Return(result, nil)

	h := newDeviceRouter(svc, deviceSvc, nil)
	rr := postForm(t, h, "/oauth/token", url.Values{
		"grant_type":  {domain.GrantTypeDeviceCode},
		"client_id":   {"device-client"},
		"device_code": {"raw-device"},
	})
	require.Equal(t, http.StatusOK, rr.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "a.b.c", body["access_token"])
	assert.Equal(t, "refresh.xyz", body["refresh_token"])
}

// --- GET /oauth/device ---

func TestDeviceVerifyGet_NoCodePromptsForOne(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)

	h := newDeviceRouter(svc, deviceSvc, nil)
	req := httptest.NewRequest(http.MethodGet, "/oauth/device", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Device code")
}

func TestDeviceVerifyGet_WithUserCodeShowsApprovalPrompt(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)

	view := &service.DeviceApprovalView{
		Authorization: &domain.DeviceAuthorization{ID: "s-1", UserCode: "ABCD-1234", Scope: "read:sensors"},
		Client:        &domain.OAuthClient{ID: "device-client", Name: "Home IoT"},
	}
	deviceSvc.EXPECT().LookupForVerification("ABCD-1234").Return(view, nil)

	h := newDeviceRouter(svc, deviceSvc, nil)
	req := httptest.NewRequest(http.MethodGet, "/oauth/device?user_code=ABCD-1234", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Home IoT")
	assert.Contains(t, rr.Body.String(), "read:sensors")
}

func TestDeviceVerifyGet_ClaimCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)

	view := &service.DeviceApprovalView{
		Client:    &domain.OAuthClient{ID: "device-client", Name: "Home IoT"},
		ClaimCode: &domain.ClaimCode{ID: "cc-1", Label: "Kitchen sensor"},
	}
	deviceSvc.EXPECT().LookupForVerification("KTCH-0001-ABCD").Return(view, nil)

	h := newDeviceRouter(svc, deviceSvc, nil)
	req := httptest.NewRequest(http.MethodGet, "/oauth/device?code=KTCH-0001-ABCD", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Kitchen sensor")
}

func TestDeviceVerifyGet_UnknownCodeShowsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	deviceSvc.EXPECT().LookupForVerification("UNKN-OWN0").Return(nil, service.ErrInvalidUserCode)

	h := newDeviceRouter(svc, deviceSvc, nil)
	req := httptest.NewRequest(http.MethodGet, "/oauth/device?user_code=UNKN-OWN0", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "not recognised")
}

// --- POST /oauth/device ---

func TestDeviceVerifyPost_ApproveSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	authSvc := mocks.NewMockAuthServicer(ctrl)

	authSvc.EXPECT().AuthorizeUser("alice", "password", gomock.Any()).Return("user-alice", nil)
	deviceSvc.EXPECT().Approve("ABCD-1234", "user-alice", "alice", gomock.Any()).Return(nil)

	h := newDeviceRouter(svc, deviceSvc, authSvc)
	rr := postForm(t, h, "/oauth/device", url.Values{
		"user_code": {"ABCD-1234"},
		"username":  {"alice"},
		"password":  {"password"},
		"action":    {"approve"},
	})
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Device approved")
}

func TestDeviceVerifyPost_ApproveBadPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	authSvc := mocks.NewMockAuthServicer(ctrl)

	authSvc.EXPECT().AuthorizeUser("alice", "wrong", gomock.Any()).Return("", service.ErrInvalidCredentials)

	h := newDeviceRouter(svc, deviceSvc, authSvc)
	rr := postForm(t, h, "/oauth/device", url.Values{
		"user_code": {"ABCD-1234"},
		"username":  {"alice"},
		"password":  {"wrong"},
		"action":    {"approve"},
	})
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid username or password")
}

func TestDeviceVerifyPost_Deny(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	deviceSvc.EXPECT().Deny("ABCD-1234", gomock.Any()).Return(nil)

	h := newDeviceRouter(svc, deviceSvc, authSvc)
	rr := postForm(t, h, "/oauth/device", url.Values{
		"user_code": {"ABCD-1234"},
		"action":    {"deny"},
	})
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Device denied")
}

// --- discovery metadata ---

func TestDiscovery_AdvertisesDeviceGrant(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)

	issuer := newSecurityTestIssuer(t, "https://id.example.com")
	h := oauth.NewRouter(svc, "", issuer, nil, nil, deviceSvc, "", "")
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Contains(t, body["device_authorization_endpoint"], "/oauth/device_authorization")
	grants, _ := body["grant_types_supported"].([]any)
	var found bool
	for _, g := range grants {
		if s, ok := g.(string); ok && s == domain.GrantTypeDeviceCode {
			found = true
			break
		}
	}
	assert.True(t, found, "device_code grant should be advertised")
}

func TestDiscovery_OmitsDeviceGrantWhenDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	issuer := newSecurityTestIssuer(t, "https://id.example.com")
	h := oauth.NewRouter(svc, "", issuer, nil, nil, nil, "", "")
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.NotContains(t, rr.Body.String(), "device_authorization_endpoint")
}
