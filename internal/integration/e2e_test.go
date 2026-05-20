//go:build integration

// Package integration contains end-to-end tests that wire up the full server
// stack (real SQLite, real services, httptest server) and exercise complete
// user flows without any mocks.
package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/common/backup"
	"github.com/sweeney/identity/internal/db"
	apihandler "github.com/sweeney/identity/internal/handler/api"
	"github.com/sweeney/identity/internal/service"
	"github.com/sweeney/identity/internal/store"
)

// testServer builds a full in-process server with a real SQLite DB.
type testServer struct {
	srv     *httptest.Server
	authSvc *service.AuthService
	userSvc *service.UserService
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()

	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })

	userStore := store.NewUserStore(database)
	tokenStore := store.NewTokenStore(database)

	key, err := auth.GenerateKey()
	require.NoError(t, err)
	issuer, err := auth.NewTokenIssuer(key, nil, "identity.home", 15*time.Minute)
	require.NoError(t, err)

	noopBackup := &backup.NoopManager{}
	auditStore := store.NewAuditStore(database)

	authSvc := service.NewAuthService(issuer, userStore, tokenStore, noopBackup, auditStore, 30*24*time.Hour)
	userSvc := service.NewUserService(userStore, tokenStore, noopBackup, auditStore, 10).WithBcryptCost(4)

	handler := apihandler.NewRouter(issuer, authSvc, userSvc, nil, "")
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return &testServer{srv: srv, authSvc: authSvc, userSvc: userSvc}
}

func (ts *testServer) post(t *testing.T, path string, body any, token string) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, ts.srv.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func (ts *testServer) get(t *testing.T, path, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.srv.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func decodeBody(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	require.NoError(t, json.NewDecoder(resp.Body).Decode(v))
}

// seedAdmin creates the first admin user directly via the service layer.
func (ts *testServer) seedAdmin(t *testing.T) {
	t.Helper()
	_, err := ts.userSvc.Create("admin", "Admin User", "adminpassword1", "admin")
	require.NoError(t, err)
}

// --- E2E: Full login → use token → refresh → logout flow ---

func TestE2E_LoginRefreshLogout(t *testing.T) {
	ts := newTestServer(t)
	ts.seedAdmin(t)

	// 1. Login
	loginResp := ts.post(t, "/api/v1/auth/login", map[string]string{
		"username":    "admin",
		"password":    "adminpassword1",
		"device_hint": "Test Client",
	}, "")
	require.Equal(t, http.StatusOK, loginResp.StatusCode)

	var loginBody map[string]any
	decodeBody(t, loginResp, &loginBody)
	accessToken := loginBody["access_token"].(string)
	refreshToken := loginBody["refresh_token"].(string)
	assert.NotEmpty(t, accessToken)
	assert.NotEmpty(t, refreshToken)
	assert.Equal(t, float64(900), loginBody["expires_in"])

	// 2. Use access token — GET /api/v1/auth/me
	meResp := ts.get(t, "/api/v1/auth/me", accessToken)
	require.Equal(t, http.StatusOK, meResp.StatusCode)
	var meBody map[string]any
	decodeBody(t, meResp, &meBody)
	assert.Equal(t, "admin", meBody["username"])

	// 3. Refresh tokens
	refreshResp := ts.post(t, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": refreshToken,
	}, "")
	require.Equal(t, http.StatusOK, refreshResp.StatusCode)

	var refreshBody map[string]any
	decodeBody(t, refreshResp, &refreshBody)
	newAccessToken := refreshBody["access_token"].(string)
	newRefreshToken := refreshBody["refresh_token"].(string)
	assert.NotEmpty(t, newAccessToken)
	assert.NotEmpty(t, newRefreshToken)
	assert.NotEqual(t, accessToken, newAccessToken)
	assert.NotEqual(t, refreshToken, newRefreshToken)

	// 4. Old refresh token is now invalid (already rotated)
	replayResp := ts.post(t, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": refreshToken,
	}, "")
	require.Equal(t, http.StatusUnauthorized, replayResp.StatusCode)

	var replayBody map[string]string
	decodeBody(t, replayResp, &replayBody)
	// Should be "token_family_compromised" because replaying a rotated token
	// triggers the theft detection logic
	assert.Equal(t, "token_family_compromised", replayBody["error"])

	// 5. Logout (new refresh token should also be invalidated since family was compromised)
	logoutResp := ts.post(t, "/api/v1/auth/logout", map[string]string{
		"refresh_token": newRefreshToken,
	}, newAccessToken)
	require.Equal(t, http.StatusNoContent, logoutResp.StatusCode)
	logoutResp.Body.Close()
}

// --- E2E: Token theft detection ---

func TestE2E_TokenTheftDetection(t *testing.T) {
	ts := newTestServer(t)
	ts.seedAdmin(t)

	// Login to get initial tokens
	loginResp := ts.post(t, "/api/v1/auth/login", map[string]string{
		"username": "admin",
		"password": "adminpassword1",
	}, "")
	require.Equal(t, http.StatusOK, loginResp.StatusCode)

	var tokens map[string]any
	decodeBody(t, loginResp, &tokens)
	originalRefresh := tokens["refresh_token"].(string)

	// Legitimate client refreshes
	refreshResp := ts.post(t, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": originalRefresh,
	}, "")
	require.Equal(t, http.StatusOK, refreshResp.StatusCode)

	var newTokens map[string]any
	decodeBody(t, refreshResp, &newTokens)
	_ = newTokens["refresh_token"].(string)

	// Attacker attempts to use the OLD (now-rotated) token — should trigger family compromise
	attackResp := ts.post(t, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": originalRefresh,
	}, "")
	require.Equal(t, http.StatusUnauthorized, attackResp.StatusCode)

	var attackBody map[string]string
	decodeBody(t, attackResp, &attackBody)
	assert.Equal(t, "token_family_compromised", attackBody["error"])
}

// --- E2E: User management by admin ---

func TestE2E_UserManagement(t *testing.T) {
	ts := newTestServer(t)
	ts.seedAdmin(t)

	// Login as admin
	loginResp := ts.post(t, "/api/v1/auth/login", map[string]string{
		"username": "admin",
		"password": "adminpassword1",
	}, "")
	require.Equal(t, http.StatusOK, loginResp.StatusCode)

	var loginTokens map[string]any
	decodeBody(t, loginResp, &loginTokens)
	adminToken := loginTokens["access_token"].(string)

	// Create a new user
	createResp := ts.post(t, "/api/v1/users", map[string]string{
		"username":     "newuser",
		"display_name": "New User",
		"password":     "strongpassword1",
		"role":         "user",
	}, adminToken)
	require.Equal(t, http.StatusCreated, createResp.StatusCode)

	var created map[string]any
	decodeBody(t, createResp, &created)
	userID := created["id"].(string)
	assert.NotEmpty(t, userID)

	// List users — should have 2 (admin + new)
	listResp := ts.get(t, "/api/v1/users", adminToken)
	require.Equal(t, http.StatusOK, listResp.StatusCode)

	var listBody map[string]any
	decodeBody(t, listResp, &listBody)
	assert.Equal(t, float64(2), listBody["total"])

	// New user logs in
	userLoginResp := ts.post(t, "/api/v1/auth/login", map[string]string{
		"username": "newuser",
		"password": "strongpassword1",
	}, "")
	require.Equal(t, http.StatusOK, userLoginResp.StatusCode)

	var userTokens map[string]any
	decodeBody(t, userLoginResp, &userTokens)
	userAccessToken := userTokens["access_token"].(string)

	// New user can get their own record
	selfResp := ts.get(t, fmt.Sprintf("/api/v1/users/%s", userID), userAccessToken)
	require.Equal(t, http.StatusOK, selfResp.StatusCode)
	selfResp.Body.Close()

	// New user cannot get admin's record
	adminGetResp := ts.get(t, "/api/v1/users/admin-id", userAccessToken)
	assert.Equal(t, http.StatusForbidden, adminGetResp.StatusCode)
	adminGetResp.Body.Close()

	// Delete the new user
	delReq, _ := http.NewRequest(http.MethodDelete, ts.srv.URL+"/api/v1/users/"+userID, nil)
	delReq.Header.Set("Authorization", "Bearer "+adminToken)
	delResp, err := http.DefaultClient.Do(delReq)
	require.NoError(t, err)
	delResp.Body.Close()
	assert.Equal(t, http.StatusNoContent, delResp.StatusCode)
}

// --- E2E: Account disabled cannot authenticate ---

func TestE2E_DisabledUserCannotLogin(t *testing.T) {
	ts := newTestServer(t)
	ts.seedAdmin(t)

	// Create a user
	_, err := ts.userSvc.Create("victim", "Victim", "strongpassword1", "user")
	require.NoError(t, err)

	// Disable the user via service
	users, _ := ts.userSvc.List()
	var victimID string
	for _, u := range users {
		if u.Username == "victim" {
			victimID = u.ID
		}
	}
	require.NotEmpty(t, victimID)

	isActive := false
	_, err = ts.userSvc.Update(victimID, service.UpdateUserInput{IsActive: &isActive})
	require.NoError(t, err)

	// Attempt login — should be forbidden
	resp := ts.post(t, "/api/v1/auth/login", map[string]string{
		"username": "victim",
		"password": "strongpassword1",
	}, "")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	resp.Body.Close()
}
