package oauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/auth"
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
	// Passkey approval is offered alongside username/password.
	assert.Contains(t, rr.Body.String(), `id="passkey-btn"`)
	assert.Contains(t, rr.Body.String(), "passkey-device.js")
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

// --- Post-approval passkey registration prompt ---
//
// After a password approval, if the user has no passkeys and the browser
// supports WebAuthn, the device page offers to register one (mirrors the OAuth
// login flow). The continue/skip target is GET /oauth/device/done.

// newDeviceRouterWithPasskey builds a device-flow router with a WebAuthn service
// and a non-empty session key, so the post-approval passkey prompt is active.
func newDeviceRouterWithPasskey(svc service.OAuthServicer, deviceSvc service.DeviceFlowServicer, authSvc service.AuthServicer, webauthnSvc service.WebAuthnServicer) http.Handler {
	return oauth.NewRouter(svc, "", nil, authSvc, webauthnSvc, deviceSvc, "test-session-key", "Test")
}

func TestDeviceVerifyPost_ApprovePromptsForPasskeyWhenNone(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)

	authSvc.EXPECT().AuthorizeUser("alice", "password", gomock.Any()).Return("user-alice", nil)
	deviceSvc.EXPECT().Approve("ABCD-1234", "user-alice", "alice", gomock.Any()).Return(nil)
	webauthnSvc.EXPECT().ListCredentials("user-alice").Return([]*domain.WebAuthnCredential{}, nil)

	h := newDeviceRouterWithPasskey(svc, deviceSvc, authSvc, webauthnSvc)
	rr := postForm(t, h, "/oauth/device", url.Values{
		"user_code":          {"ABCD-1234"},
		"username":           {"alice"},
		"password":           {"password"},
		"action":             {"approve"},
		"webauthn_supported": {"1"},
	})
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Sign in faster next time")
	assert.Contains(t, rr.Body.String(), "/oauth/device/done")
	assert.NotContains(t, rr.Body.String(), "Device approved")
}

func TestDeviceVerifyPost_ApproveNoPromptWhenHasPasskey(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)

	authSvc.EXPECT().AuthorizeUser("alice", "password", gomock.Any()).Return("user-alice", nil)
	deviceSvc.EXPECT().Approve("ABCD-1234", "user-alice", "alice", gomock.Any()).Return(nil)
	webauthnSvc.EXPECT().ListCredentials("user-alice").Return([]*domain.WebAuthnCredential{{ID: "cred-1"}}, nil)

	h := newDeviceRouterWithPasskey(svc, deviceSvc, authSvc, webauthnSvc)
	rr := postForm(t, h, "/oauth/device", url.Values{
		"user_code":          {"ABCD-1234"},
		"username":           {"alice"},
		"password":           {"password"},
		"action":             {"approve"},
		"webauthn_supported": {"1"},
	})
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Device approved")
	assert.NotContains(t, rr.Body.String(), "Sign in faster next time")
}

func TestDeviceVerifyPost_ApproveNoPromptWithoutWebauthnSupport(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)

	authSvc.EXPECT().AuthorizeUser("alice", "password", gomock.Any()).Return("user-alice", nil)
	deviceSvc.EXPECT().Approve("ABCD-1234", "user-alice", "alice", gomock.Any()).Return(nil)
	// No webauthn_supported flag → the prompt check short-circuits before any
	// credential lookup, so ListCredentials must not be called.

	h := newDeviceRouterWithPasskey(svc, deviceSvc, authSvc, webauthnSvc)
	rr := postForm(t, h, "/oauth/device", url.Values{
		"user_code": {"ABCD-1234"},
		"username":  {"alice"},
		"password":  {"password"},
		"action":    {"approve"},
	})
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Device approved")
}

func TestDeviceVerifyDone_ShowsApprovedConfirmation(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	authSvc := mocks.NewMockAuthServicer(ctrl)

	h := newDeviceRouter(svc, deviceSvc, authSvc)
	req := httptest.NewRequest(http.MethodGet, "/oauth/device/done", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "Device approved")
	assert.Contains(t, body, `href="/oauth/device"`)
	assert.Contains(t, body, "Authorize another device")
}

// --- POST /oauth/device/passkey ---
//
// Bridges a WebAuthn (passkey) login ceremony into device approval: the browser
// completes the passkey ceremony in JavaScript, obtains a user access token, and
// posts it here together with the user_code to approve the device.

// deviceRouterWithIssuer builds a device-flow router that also has a token issuer
// wired (required for the passkey bridge to parse access tokens).
func deviceRouterWithIssuer(svc service.OAuthServicer, deviceSvc service.DeviceFlowServicer, issuer *auth.TokenIssuer) http.Handler {
	return oauth.NewRouter(svc, "", issuer, nil, nil, deviceSvc, "", "Test")
}

// postDevicePasskey posts to /oauth/device/passkey with an Origin matching Host
// (so CheckOrigin passes) and Accept: application/json (XHR caller).
func postDevicePasskey(t *testing.T, h http.Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/device/passkey", nil)
	req.Host = "id.example.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", "https://id.example.com")
	req.Body = http.NoBody
	req.Form = form
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func mintUserToken(t *testing.T, issuer *auth.TokenIssuer, userID, username string) string {
	t.Helper()
	tok, err := issuer.Mint(domain.TokenClaims{
		UserID:   userID,
		Username: username,
		Role:     "user",
		IsActive: true,
		Audience: "https://id.example.com",
	})
	require.NoError(t, err)
	return tok
}

func TestDeviceVerifyPasskey_ApproveSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	issuer := newSecurityTestIssuer(t, "https://id.example.com")

	token := mintUserToken(t, issuer, "user-alice", "alice")
	deviceSvc.EXPECT().Approve("ABCD-1234", "user-alice", "alice", gomock.Any()).Return(nil)

	h := deviceRouterWithIssuer(svc, deviceSvc, issuer)
	rr := postDevicePasskey(t, h, url.Values{
		"access_token": {token},
		"user_code":    {"ABCD-1234"},
	})
	require.Equal(t, http.StatusOK, rr.Code)

	var body map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "approved", body["status"])
}

func TestDeviceVerifyPasskey_MissingParams(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	issuer := newSecurityTestIssuer(t, "https://id.example.com")

	h := deviceRouterWithIssuer(svc, deviceSvc, issuer)
	rr := postDevicePasskey(t, h, url.Values{"user_code": {"ABCD-1234"}})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestDeviceVerifyPasskey_InvalidToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	issuer := newSecurityTestIssuer(t, "https://id.example.com")

	h := deviceRouterWithIssuer(svc, deviceSvc, issuer)
	rr := postDevicePasskey(t, h, url.Values{
		"access_token": {"not-a-real-token"},
		"user_code":    {"ABCD-1234"},
	})
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "invalid_token", body["error"])
}

// A client_credentials service token (typ: at+jwt) must never be accepted as a
// user identity for device approval — same guard as authorizePasskey.
func TestDeviceVerifyPasskey_ServiceTokenRejected(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	issuer := newSecurityTestIssuer(t, "https://id.example.com")

	serviceToken, err := issuer.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "some-service",
		Audience: "https://id.example.com",
		Scope:    "read:users",
	}, 15*time.Minute)
	require.NoError(t, err)

	h := deviceRouterWithIssuer(svc, deviceSvc, issuer)
	rr := postDevicePasskey(t, h, url.Values{
		"access_token": {serviceToken},
		"user_code":    {"ABCD-1234"},
	})
	assert.Equal(t, http.StatusUnauthorized, rr.Code,
		"service token must be rejected by device passkey approval")
}

func TestDeviceVerifyPasskey_ExpiredCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	issuer := newSecurityTestIssuer(t, "https://id.example.com")

	token := mintUserToken(t, issuer, "user-alice", "alice")
	deviceSvc.EXPECT().Approve("EXPD-0000", "user-alice", "alice", gomock.Any()).Return(service.ErrDeviceCodeExpired)

	h := deviceRouterWithIssuer(svc, deviceSvc, issuer)
	rr := postDevicePasskey(t, h, url.Values{
		"access_token": {token},
		"user_code":    {"EXPD-0000"},
	})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "expired_token", body["error"])
}

func TestDeviceVerifyPasskey_CrossOriginRejected(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	issuer := newSecurityTestIssuer(t, "https://id.example.com")
	token := mintUserToken(t, issuer, "user-alice", "alice")

	h := deviceRouterWithIssuer(svc, deviceSvc, issuer)
	req := httptest.NewRequest(http.MethodPost, "/oauth/device/passkey", nil)
	req.Host = "id.example.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", "https://evil.example.com")
	req.Body = http.NoBody
	req.Form = url.Values{"access_token": {token}, "user_code": {"ABCD-1234"}}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestDeviceVerifyPasskey_DisabledWhenServiceNil(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	issuer := newSecurityTestIssuer(t, "https://id.example.com")

	h := oauth.NewRouter(svc, "", issuer, nil, nil, nil, "", "")
	rr := postDevicePasskey(t, h, url.Values{
		"access_token": {"x"},
		"user_code":    {"ABCD-1234"},
	})
	assert.Equal(t, http.StatusNotFound, rr.Code)
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
