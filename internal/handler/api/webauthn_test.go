package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/handler/api"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

// --- POST /api/v1/webauthn/register/begin ---

func TestWebAuthnRegisterBegin_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)
	issuer := newTestIssuer(t)

	creation := &protocol.CredentialCreation{
		Response: protocol.PublicKeyCredentialCreationOptions{
			Challenge: []byte("test-challenge"),
		},
	}
	webauthnSvc.EXPECT().BeginRegistration("user-123").Return(creation, "challenge-id-1", nil)

	h := api.NewRouter(issuer, nil, nil, webauthnSvc, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/register/begin", nil)
	req.Header.Set("Authorization", "Bearer "+userToken(t, issuer, "user-123"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]any
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "challenge-id-1", resp["challenge_id"])
	assert.NotNil(t, resp["publicKey"])
}

func TestWebAuthnRegisterBegin_Unauthenticated(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)

	h := api.NewRouter(newTestIssuer(t), nil, nil, webauthnSvc, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/register/begin", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestWebAuthnRegisterBegin_NotEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)
	issuer := newTestIssuer(t)

	webauthnSvc.EXPECT().BeginRegistration("user-123").Return(nil, "", service.ErrWebAuthnNotEnabled)

	h := api.NewRouter(issuer, nil, nil, webauthnSvc, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/register/begin", nil)
	req.Header.Set("Authorization", "Bearer "+userToken(t, issuer, "user-123"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "webauthn_not_enabled", resp["error"])
}

// --- POST /api/v1/webauthn/register/finish ---

func TestWebAuthnRegisterFinish_MissingChallengeID(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)
	issuer := newTestIssuer(t)

	h := api.NewRouter(issuer, nil, nil, webauthnSvc, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/register/finish", nil)
	req.Header.Set("Authorization", "Bearer "+userToken(t, issuer, "user-123"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "validation_error", resp["error"])
}

func TestWebAuthnRegisterFinish_InvalidChallenge(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)
	issuer := newTestIssuer(t)

	webauthnSvc.EXPECT().FinishRegistration("user-123", "bad-id", "", gomock.Any()).Return(nil, service.ErrWebAuthnInvalidChallenge)

	h := api.NewRouter(issuer, nil, nil, webauthnSvc, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/register/finish?challenge_id=bad-id", nil)
	req.Header.Set("Authorization", "Bearer "+userToken(t, issuer, "user-123"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "webauthn_invalid_challenge", resp["error"])
}

func TestWebAuthnRegisterFinish_VerificationFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)
	issuer := newTestIssuer(t)

	webauthnSvc.EXPECT().FinishRegistration("user-123", "ch-1", "", gomock.Any()).Return(nil, service.ErrWebAuthnVerificationFailed)

	h := api.NewRouter(issuer, nil, nil, webauthnSvc, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/register/finish?challenge_id=ch-1", nil)
	req.Header.Set("Authorization", "Bearer "+userToken(t, issuer, "user-123"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "webauthn_verification_failed", resp["error"])
}

func TestWebAuthnRegisterFinish_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)
	issuer := newTestIssuer(t)

	cred := &domain.WebAuthnCredential{ID: "new-cred", Name: "Test Key", CreatedAt: time.Now(), LastUsedAt: time.Now()}
	webauthnSvc.EXPECT().FinishRegistration("user-123", "ch-1", "", gomock.Any()).Return(cred, nil)

	h := api.NewRouter(issuer, nil, nil, webauthnSvc, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/register/finish?challenge_id=ch-1", nil)
	req.Header.Set("Authorization", "Bearer "+userToken(t, issuer, "user-123"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)
}

// --- POST /api/v1/webauthn/login/begin ---

func TestWebAuthnLoginBegin_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)

	assertion := &protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge: []byte("login-challenge"),
		},
	}
	webauthnSvc.EXPECT().BeginLogin("alice").Return(assertion, "login-ch-1", nil)

	h := api.NewRouter(newTestIssuer(t), nil, nil, webauthnSvc, "")
	rr := postJSON(t, h, "/api/v1/webauthn/login/begin", map[string]string{"username": "alice"})

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]any
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "login-ch-1", resp["challenge_id"])
	assert.NotNil(t, resp["publicKey"])
}

func TestWebAuthnLoginBegin_DiscoverableFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)

	assertion := &protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge: []byte("disc-challenge"),
		},
	}
	webauthnSvc.EXPECT().BeginLogin("").Return(assertion, "disc-ch-1", nil)

	h := api.NewRouter(newTestIssuer(t), nil, nil, webauthnSvc, "")
	rr := postJSON(t, h, "/api/v1/webauthn/login/begin", map[string]string{})

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestWebAuthnLoginBegin_NoCredentials(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)

	// User with no passkeys now gets a discoverable challenge (not an error)
	// to prevent username enumeration
	assertion := &protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge: []byte("disc-challenge"),
		},
	}
	webauthnSvc.EXPECT().BeginLogin("bob").Return(assertion, "disc-ch-1", nil)

	h := api.NewRouter(newTestIssuer(t), nil, nil, webauthnSvc, "")
	rr := postJSON(t, h, "/api/v1/webauthn/login/begin", map[string]string{"username": "bob"})

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]any
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "disc-ch-1", resp["challenge_id"])
}

func TestWebAuthnLoginBegin_MalformedJSON_Returns400(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl) // no expectations — must not be called
	h := api.NewRouter(newTestIssuer(t), nil, nil, webauthnSvc, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/login/begin", strings.NewReader("{not valid json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp) //nolint:errcheck
	assert.Equal(t, "invalid_request_body", resp["error"])
}

func TestWebAuthnLoginBegin_FormEncodedBody_Returns400(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl) // no expectations — must not be called
	h := api.NewRouter(newTestIssuer(t), nil, nil, webauthnSvc, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/login/begin", strings.NewReader("username=alice"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp) //nolint:errcheck
	assert.Equal(t, "invalid_request_body", resp["error"])
}

// --- POST /api/v1/webauthn/login/finish ---

func TestWebAuthnLoginFinish_MissingChallengeID(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)

	h := api.NewRouter(newTestIssuer(t), nil, nil, webauthnSvc, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/login/finish", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestWebAuthnLoginFinish_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)

	result := &service.LoginResult{
		AccessToken:  "wa-access-token",
		TokenType:    "Bearer",
		ExpiresIn:    900,
		RefreshToken: "wa-refresh-token",
	}
	webauthnSvc.EXPECT().FinishLogin("login-ch-1", gomock.Any(), "", gomock.Any()).Return(result, nil)

	h := api.NewRouter(newTestIssuer(t), nil, nil, webauthnSvc, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/login/finish?challenge_id=login-ch-1", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]any
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "wa-access-token", resp["access_token"])
	assert.Equal(t, "wa-refresh-token", resp["refresh_token"])
}

func TestWebAuthnLoginFinish_VerificationFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)

	webauthnSvc.EXPECT().FinishLogin("ch-1", gomock.Any(), "", gomock.Any()).Return(nil, service.ErrWebAuthnVerificationFailed)

	h := api.NewRouter(newTestIssuer(t), nil, nil, webauthnSvc, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/login/finish?challenge_id=ch-1", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var resp map[string]string
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "webauthn_verification_failed", resp["error"])
}

func TestWebAuthnLoginFinish_AccountDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)

	webauthnSvc.EXPECT().FinishLogin("ch-1", gomock.Any(), "", gomock.Any()).Return(nil, service.ErrAccountDisabled)

	h := api.NewRouter(newTestIssuer(t), nil, nil, webauthnSvc, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/login/finish?challenge_id=ch-1", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// --- GET /api/v1/webauthn/credentials ---

func TestWebAuthnListCredentials_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)
	issuer := newTestIssuer(t)

	now := time.Now().UTC()
	creds := []*domain.WebAuthnCredential{
		{ID: "cred-1", Name: "MacBook Pro", CreatedAt: now, LastUsedAt: now},
		{ID: "cred-2", Name: "iPhone 15", CreatedAt: now, LastUsedAt: now},
	}
	webauthnSvc.EXPECT().ListCredentials("user-123").Return(creds, nil)

	h := api.NewRouter(issuer, nil, nil, webauthnSvc, "")
	rr := authGet(t, h, "/api/v1/webauthn/credentials", userToken(t, issuer, "user-123"))

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]any
	decodeJSON(t, rr, &resp)
	assert.Equal(t, float64(2), resp["total"])
}

func TestWebAuthnListCredentials_Unauthenticated(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)

	h := api.NewRouter(newTestIssuer(t), nil, nil, webauthnSvc, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/webauthn/credentials", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// --- PATCH /api/v1/webauthn/credentials/{id} ---

func TestWebAuthnRenameCredential_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)
	issuer := newTestIssuer(t)

	webauthnSvc.EXPECT().RenameCredential("user-123", "cred-1", "My Laptop").Return(nil)

	h := api.NewRouter(issuer, nil, nil, webauthnSvc, "")
	rr := patchJSONAuth(t, h, "/api/v1/webauthn/credentials/cred-1", map[string]string{"name": "My Laptop"}, userToken(t, issuer, "user-123"))

	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestWebAuthnRenameCredential_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)
	issuer := newTestIssuer(t)

	webauthnSvc.EXPECT().RenameCredential("user-123", "ghost", gomock.Any()).Return(service.ErrWebAuthnCredentialNotFound)

	h := api.NewRouter(issuer, nil, nil, webauthnSvc, "")
	rr := patchJSONAuth(t, h, "/api/v1/webauthn/credentials/ghost", map[string]string{"name": "X"}, userToken(t, issuer, "user-123"))

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --- DELETE /api/v1/webauthn/credentials/{id} ---

func TestWebAuthnDeleteCredential_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)
	issuer := newTestIssuer(t)

	webauthnSvc.EXPECT().DeleteCredential("user-123", "cred-1").Return(nil)

	h := api.NewRouter(issuer, nil, nil, webauthnSvc, "")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/webauthn/credentials/cred-1", nil)
	req.Header.Set("Authorization", "Bearer "+userToken(t, issuer, "user-123"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestWebAuthnDeleteCredential_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)
	issuer := newTestIssuer(t)

	webauthnSvc.EXPECT().DeleteCredential("user-123", "ghost").Return(service.ErrWebAuthnCredentialNotFound)

	h := api.NewRouter(issuer, nil, nil, webauthnSvc, "")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/webauthn/credentials/ghost", nil)
	req.Header.Set("Authorization", "Bearer "+userToken(t, issuer, "user-123"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --- WebAuthn routes not registered when service is nil ---

func TestWebAuthnRoutes_NilService(t *testing.T) {
	h := api.NewRouter(newTestIssuer(t), nil, nil, nil, "")
	rr := postJSON(t, h, "/api/v1/webauthn/login/begin", map[string]string{})
	// When webauthnSvc is nil, routes are not registered — expect 405 Method Not Allowed or 404
	assert.True(t, rr.Code == http.StatusNotFound || rr.Code == http.StatusMethodNotAllowed,
		"expected 404 or 405 when webauthn is disabled, got %d", rr.Code)
}

// patchJSONAuth sends a PATCH request with JSON body and auth header.
func patchJSONAuth(t *testing.T, handler http.Handler, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}
