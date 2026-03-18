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

	authpkg "github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/handler/api"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

func adminToken(t *testing.T, issuer *authpkg.TokenIssuer) string {
	t.Helper()
	tok, err := issuer.Mint(domain.TokenClaims{
		UserID: "admin-1", Username: "admin", Role: domain.RoleAdmin, IsActive: true,
	})
	require.NoError(t, err)
	return tok
}

func userToken(t *testing.T, issuer *authpkg.TokenIssuer, userID string) string {
	t.Helper()
	tok, err := issuer.Mint(domain.TokenClaims{
		UserID: userID, Username: "alice", Role: domain.RoleUser, IsActive: true,
	})
	require.NoError(t, err)
	return tok
}

var _ = authpkg.NewTokenIssuer // ensure import is used

func authGet(t *testing.T, handler http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func postJSONAuth(t *testing.T, handler http.Handler, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func putJSONAuth(t *testing.T, handler http.Handler, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func sampleUser(id string) *domain.User {
	return &domain.User{
		ID:          id,
		Username:    "user-" + id,
		DisplayName: "User " + id,
		Role:        domain.RoleUser,
		IsActive:    true,
		CreatedAt:   time.Now(),
	}
}

// --- GET /api/v1/users ---

func TestListUsers_AdminSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	issuer := newTestIssuer(t)

	users := []*domain.User{sampleUser("1"), sampleUser("2")}
	userSvc.EXPECT().List().Return(users, nil)

	h := api.NewRouter(issuer, nil, userSvc, "")
	rr := authGet(t, h, "/api/v1/users", adminToken(t, issuer))

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]any
	decodeJSON(t, rr, &resp)
	assert.Equal(t, float64(2), resp["total"])
}

func TestListUsers_NonAdminForbidden(t *testing.T) {
	issuer := newTestIssuer(t)
	h := api.NewRouter(issuer, nil, nil, "")
	rr := authGet(t, h, "/api/v1/users", userToken(t, issuer, "u1"))
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestListUsers_Unauthenticated(t *testing.T) {
	h := api.NewRouter(newTestIssuer(t), nil, nil, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// --- POST /api/v1/users ---

func TestCreateUser_AdminSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	issuer := newTestIssuer(t)

	created := sampleUser("new-1")
	userSvc.EXPECT().Create("newuser", "New User", "strongpassword1", domain.RoleUser, gomock.Any()).Return(created, nil)

	h := api.NewRouter(issuer, nil, userSvc, "")
	rr := postJSONAuth(t, h, "/api/v1/users", map[string]string{
		"username":     "newuser",
		"display_name": "New User",
		"password":     "strongpassword1",
		"role":         "user",
	}, adminToken(t, issuer))

	assert.Equal(t, http.StatusCreated, rr.Code)
}

func TestCreateUser_DuplicateUsername(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	issuer := newTestIssuer(t)

	userSvc.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, domain.ErrConflict)

	h := api.NewRouter(issuer, nil, userSvc, "")
	rr := postJSONAuth(t, h, "/api/v1/users", map[string]string{
		"username": "existing", "display_name": "Existing", "password": "strongpassword1", "role": "user",
	}, adminToken(t, issuer))

	assert.Equal(t, http.StatusConflict, rr.Code)
	var resp map[string]string
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "username_taken", resp["error"])
}

func TestCreateUser_UserLimitReached(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	issuer := newTestIssuer(t)

	userSvc.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, domain.ErrUserLimitReached)

	h := api.NewRouter(issuer, nil, userSvc, "")
	rr := postJSONAuth(t, h, "/api/v1/users", map[string]string{
		"username": "u", "display_name": "U", "password": "strongpassword1", "role": "user",
	}, adminToken(t, issuer))

	assert.Equal(t, http.StatusUnprocessableEntity, rr.Code)
	var resp map[string]string
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "user_limit_reached", resp["error"])
}

// --- GET /api/v1/users/{id} ---

func TestGetUser_AdminCanGetAnyUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	issuer := newTestIssuer(t)

	userSvc.EXPECT().GetByID("u-999").Return(sampleUser("u-999"), nil)

	h := api.NewRouter(issuer, nil, userSvc, "")
	rr := authGet(t, h, "/api/v1/users/u-999", adminToken(t, issuer))
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestGetUser_UserCanGetSelf(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	issuer := newTestIssuer(t)

	userSvc.EXPECT().GetByID("user-123").Return(sampleUser("user-123"), nil)

	h := api.NewRouter(issuer, nil, userSvc, "")
	rr := authGet(t, h, "/api/v1/users/user-123", userToken(t, issuer, "user-123"))
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestGetUser_UserCannotGetOther(t *testing.T) {
	issuer := newTestIssuer(t)
	h := api.NewRouter(issuer, nil, nil, "")
	// user-123 tries to get user-456
	rr := authGet(t, h, "/api/v1/users/user-456", userToken(t, issuer, "user-123"))
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestGetUser_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	issuer := newTestIssuer(t)

	userSvc.EXPECT().GetByID("ghost").Return(nil, domain.ErrNotFound)

	h := api.NewRouter(issuer, nil, userSvc, "")
	rr := authGet(t, h, "/api/v1/users/ghost", adminToken(t, issuer))
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --- PUT /api/v1/users/{id} ---

func TestUpdateUser_AdminSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	issuer := newTestIssuer(t)

	updated := sampleUser("u-1")
	updated.DisplayName = "Updated Name"
	userSvc.EXPECT().Update("u-1", gomock.Any(), gomock.Any()).Return(updated, nil)

	h := api.NewRouter(issuer, nil, userSvc, "")
	rr := putJSONAuth(t, h, "/api/v1/users/u-1", map[string]string{
		"display_name": "Updated Name",
	}, adminToken(t, issuer))

	assert.Equal(t, http.StatusOK, rr.Code)
}

// --- DELETE /api/v1/users/{id} ---

func TestDeleteUser_AdminSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	issuer := newTestIssuer(t)

	userSvc.EXPECT().Delete("u-del", gomock.Any()).Return(nil)

	h := api.NewRouter(issuer, nil, userSvc, "")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/u-del", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken(t, issuer))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestDeleteUser_LastAdmin(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	issuer := newTestIssuer(t)

	userSvc.EXPECT().Delete("admin-1", gomock.Any()).Return(service.ErrCannotDeleteLastAdmin)

	h := api.NewRouter(issuer, nil, userSvc, "")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/admin-1", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken(t, issuer))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusConflict, rr.Code)
	var resp map[string]string
	decodeJSON(t, rr, &resp)
	assert.Equal(t, "cannot_delete_last_admin", resp["error"])
}
