package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/handler/api"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

const testSecret = "test-secret-key-that-is-long-enough-for-hmac"

func newTestIssuer(t *testing.T) *auth.TokenIssuer {
	t.Helper()
	issuer, err := auth.NewTokenIssuer(testSecret, "", "identity.home", 15*time.Minute)
	require.NoError(t, err)
	return issuer
}

func postJSON(t *testing.T, handler http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder, v any) {
	t.Helper()
	require.NoError(t, json.NewDecoder(rr.Body).Decode(v))
}

// --- POST /api/v1/auth/login ---

func TestLoginHandler_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	authSvc := mocks.NewMockAuthServicer(ctrl)

	loginResult := &service.LoginResult{
		AccessToken:  "access.token.here",
		TokenType:    "Bearer",
		ExpiresIn:    900,
		RefreshToken: "refresh-token-here",
	}
	authSvc.EXPECT().Login("alice", "correctpassword", "iPhone 15", gomock.Any()).Return(loginResult, nil)

	h := api.NewRouter(newTestIssuer(t), authSvc, nil)
	rr := postJSON(t, h, "/api/v1/auth/login", map[string]string{
		"username":    "alice",
		"password":    "correctpassword",
		"device_hint": "iPhone 15",
	})

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var resp map[string]any
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "access.token.here", resp["access_token"])
	assert.Equal(t, "refresh-token-here", resp["refresh_token"])
	assert.Equal(t, "Bearer", resp["token_type"])
	assert.Equal(t, float64(900), resp["expires_in"])
}

func TestLoginHandler_InvalidCredentials(t *testing.T) {
	ctrl := gomock.NewController(t)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	authSvc.EXPECT().Login("alice", "wrong", "", gomock.Any()).Return(nil, service.ErrInvalidCredentials)

	h := api.NewRouter(newTestIssuer(t), authSvc, nil)
	rr := postJSON(t, h, "/api/v1/auth/login", map[string]string{
		"username": "alice",
		"password": "wrong",
	})

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var resp map[string]string
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "invalid_credentials", resp["error"])
}

func TestLoginHandler_AccountDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	authSvc.EXPECT().Login("alice", "correctpassword", "", gomock.Any()).Return(nil, service.ErrAccountDisabled)

	h := api.NewRouter(newTestIssuer(t), authSvc, nil)
	rr := postJSON(t, h, "/api/v1/auth/login", map[string]string{
		"username": "alice",
		"password": "correctpassword",
	})

	assert.Equal(t, http.StatusForbidden, rr.Code)
	var resp map[string]string
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "account_disabled", resp["error"])
}

func TestLoginHandler_MalformedJSON(t *testing.T) {
	h := api.NewRouter(newTestIssuer(t), nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString("{bad json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestLoginHandler_MissingFields(t *testing.T) {
	h := api.NewRouter(newTestIssuer(t), nil, nil)
	rr := postJSON(t, h, "/api/v1/auth/login", map[string]string{"username": "alice"})
	assert.Equal(t, http.StatusUnprocessableEntity, rr.Code)
}

// --- POST /api/v1/auth/refresh ---

func TestRefreshHandler_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	authSvc := mocks.NewMockAuthServicer(ctrl)

	result := &service.LoginResult{
		AccessToken:  "new.access.token",
		TokenType:    "Bearer",
		ExpiresIn:    900,
		RefreshToken: "new-refresh-token",
	}
	authSvc.EXPECT().Refresh("old-refresh-token").Return(result, nil)

	h := api.NewRouter(newTestIssuer(t), authSvc, nil)
	rr := postJSON(t, h, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": "old-refresh-token",
	})

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]any
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "new.access.token", resp["access_token"])
}

func TestRefreshHandler_InvalidToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	authSvc.EXPECT().Refresh("bad-token").Return(nil, service.ErrInvalidRefreshToken)

	h := api.NewRouter(newTestIssuer(t), authSvc, nil)
	rr := postJSON(t, h, "/api/v1/auth/refresh", map[string]string{"refresh_token": "bad-token"})

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var resp map[string]string
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "invalid_refresh_token", resp["error"])
}

func TestRefreshHandler_FamilyCompromised(t *testing.T) {
	ctrl := gomock.NewController(t)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	authSvc.EXPECT().Refresh("stolen-token").Return(nil, service.ErrTokenFamilyCompromised)

	h := api.NewRouter(newTestIssuer(t), authSvc, nil)
	rr := postJSON(t, h, "/api/v1/auth/refresh", map[string]string{"refresh_token": "stolen-token"})

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var resp map[string]string
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "token_family_compromised", resp["error"])
}

// --- POST /api/v1/auth/logout ---

func TestLogoutHandler_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	authSvc.EXPECT().Logout("user-123", "my-refresh-token").Return(nil)

	issuer := newTestIssuer(t)
	token, err := issuer.Mint(domain.TokenClaims{UserID: "user-123", Username: "alice", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	h := api.NewRouter(issuer, authSvc, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", mustJSON(map[string]string{"refresh_token": "my-refresh-token"}))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestLogoutHandler_Unauthenticated(t *testing.T) {
	h := api.NewRouter(newTestIssuer(t), nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", mustJSON(map[string]string{}))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// --- GET /api/v1/auth/me ---

func TestMeHandler_Success(t *testing.T) {
	issuer := newTestIssuer(t)
	token, err := issuer.Mint(domain.TokenClaims{
		UserID:   "user-123",
		Username: "alice",
		Role:     domain.RoleUser,
		IsActive: true,
	})
	require.NoError(t, err)

	h := api.NewRouter(issuer, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]any
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "user-123", resp["id"])
	assert.Equal(t, "alice", resp["username"])
}

func mustJSON(v any) *bytes.Reader {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}
