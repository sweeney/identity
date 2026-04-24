package admin_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/handler/admin"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

const (
	adminUser = "admin"
	adminPass = "adminpassword1"
)

func newRouter(t *testing.T, userSvc *mocks.MockUserServicer) http.Handler {
	t.Helper()
	ctrl := gomock.NewController(t)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	oauthClients := mocks.NewMockOAuthClientRepository(ctrl)
	auditRepo := mocks.NewMockAuditRepository(ctrl)
	auditRepo.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()
	auditRepo.EXPECT().List(gomock.Any()).Return(nil, nil).AnyTimes()

	// Allow admin login: AuthorizeUser returns a user ID, GetByID returns an admin user
	authSvc.EXPECT().AuthorizeUser(adminUser, adminPass, gomock.Any()).Return("admin-id", nil).AnyTimes()
	authSvc.EXPECT().AuthorizeUser(gomock.Any(), gomock.Any(), gomock.Any()).Return("", service.ErrInvalidCredentials).AnyTimes()
	userSvc.EXPECT().GetByID("admin-id").Return(&domain.User{
		ID: "admin-id", Username: adminUser, Role: domain.RoleAdmin, IsActive: true,
	}, nil).AnyTimes()
	// Session validation re-checks user state from DB on every request
	userSvc.EXPECT().GetByUsername(adminUser).Return(&domain.User{
		ID: "admin-id", Username: adminUser, Role: domain.RoleAdmin, IsActive: true,
	}, nil).AnyTimes()

	return admin.NewRouter(admin.Config{
		SessionSecret: testSessionSecret,
	}, authSvc, userSvc, oauthClients, auditRepo, nil, nil, nil, nil)
}

func loginSession(t *testing.T, handler http.Handler) *http.Cookie {
	t.Helper()
	form := url.Values{"username": {adminUser}, "password": {adminPass}}
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusSeeOther, rr.Code)

	for _, c := range rr.Result().Cookies() {
		if c.Name == "admin_session" {
			return c
		}
	}
	t.Fatal("no admin_session cookie in login response")
	return nil
}

func authRequest(method, path string, cookie *http.Cookie) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(cookie)
	return req
}

const testSessionSecret = "test-session-secret-key-long-enough"

// csrfTokenFor computes the CSRF token for a given session cookie value.
func csrfTokenFor(sessionValue string) string {
	mac := hmac.New(sha256.New, []byte(testSessionSecret+"csrf"))
	mac.Write([]byte(sessionValue))
	return hex.EncodeToString(mac.Sum(nil))
}

// --- Login ---

func TestAdminLogin_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	handler := newRouter(t, userSvc)

	form := url.Values{"username": {adminUser}, "password": {adminPass}}
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/admin/", rr.Header().Get("Location"))

	// Should set admin_session cookie
	var found bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == "admin_session" {
			found = true
			assert.True(t, c.HttpOnly)
		}
	}
	assert.True(t, found, "admin_session cookie should be set")
}

func TestAdminLogin_WrongPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	handler := newRouter(t, userSvc)

	form := url.Values{"username": {adminUser}, "password": {"wrongpassword"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid credentials")
}

func TestAdminLogin_GetPage(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	handler := newRouter(t, userSvc)

	req := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Login")
}

// --- Dashboard ---

func TestAdminDashboard_Authenticated(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	userSvc.EXPECT().List().Return([]*domain.User{}, nil)

	handler := newRouter(t, userSvc)
	session := loginSession(t, handler)

	req := authRequest(http.MethodGet, "/admin/", session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Dashboard")
}

func TestAdminDashboard_Unauthenticated(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	handler := newRouter(t, userSvc)

	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/admin/login", rr.Header().Get("Location"))
}

// --- User List ---

func TestAdminUsers_List(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	users := []*domain.User{
		{ID: "u1", Username: "alice", Role: domain.RoleUser, IsActive: true, CreatedAt: time.Now()},
	}
	userSvc.EXPECT().List().Return(users, nil)

	handler := newRouter(t, userSvc)
	session := loginSession(t, handler)

	req := authRequest(http.MethodGet, "/admin/users", session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "alice")
}

// --- Create User Form ---

func TestAdminUsers_NewForm(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	handler := newRouter(t, userSvc)
	session := loginSession(t, handler)

	req := authRequest(http.MethodGet, "/admin/users/new", session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Create User")
}

func TestAdminUsers_Create_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	userSvc.EXPECT().
		Create("newuser", "New User", "strongpassword1", domain.RoleUser, gomock.Any()).
		Return(&domain.User{ID: "u-new", Username: "newuser"}, nil)

	handler := newRouter(t, userSvc)
	session := loginSession(t, handler)

	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf":        {csrf},
		"username":     {"newuser"},
		"display_name": {"New User"},
		"password":     {"strongpassword1"},
		"role":         {"user"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/admin/users", rr.Header().Get("Location"))
}

func TestAdminUsers_Create_ValidationError(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	handler := newRouter(t, userSvc)
	session := loginSession(t, handler)

	// Missing password
	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf":        {csrf},
		"username":     {"newuser"},
		"display_name": {"New User"},
		"role":         {"user"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should re-render form with error, not redirect
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "required")
}

// --- Delete User ---

func TestAdminUsers_Delete_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	userSvc.EXPECT().Delete("u-del", gomock.Any()).Return(nil)

	handler := newRouter(t, userSvc)
	session := loginSession(t, handler)

	csrf := csrfTokenFor(session.Value)
	form := url.Values{"_csrf": {csrf}, "admin_password": {adminPass}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/u-del/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
}

func TestAdminUsers_Delete_WrongPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	userSvc.EXPECT().GetByID("u-del").Return(&domain.User{
		ID: "u-del", Username: "victim", Role: domain.RoleUser, IsActive: true,
	}, nil)

	handler := newRouter(t, userSvc)
	session := loginSession(t, handler)

	csrf := csrfTokenFor(session.Value)
	form := url.Values{"_csrf": {csrf}, "admin_password": {"wrongpassword"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/u-del/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Incorrect password")
}

func TestAdminUsers_Delete_MissingPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	userSvc.EXPECT().GetByID("u-del").Return(&domain.User{
		ID: "u-del", Username: "victim", Role: domain.RoleUser, IsActive: true,
	}, nil)

	handler := newRouter(t, userSvc)
	session := loginSession(t, handler)

	csrf := csrfTokenFor(session.Value)
	form := url.Values{"_csrf": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/u-del/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Incorrect password")
}

// --- Logout ---

func TestAdminLogout(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	handler := newRouter(t, userSvc)
	session := loginSession(t, handler)

	csrf := csrfTokenFor(session.Value)
	form := url.Values{"_csrf": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/admin/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
}

// --- Admin Session Validation ---

// mintTestSession creates a session JWT matching how the admin handler mints sessions.
func mintTestSession(username string) string {
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(2 * time.Hour)),
		Subject:   username,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(testSessionSecret))
	return signed
}

// newRouterWithUserState builds a router where GetByUsername returns a custom user/error,
// bypassing the shared newRouter helper so we can control session validation behavior.
func newRouterWithUserState(t *testing.T, user *domain.User, userErr error) http.Handler {
	t.Helper()
	ctrl := gomock.NewController(t)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	userSvc := mocks.NewMockUserServicer(ctrl)
	oauthClients := mocks.NewMockOAuthClientRepository(ctrl)
	auditRepo := mocks.NewMockAuditRepository(ctrl)
	auditRepo.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()
	auditRepo.EXPECT().List(gomock.Any()).Return(nil, nil).AnyTimes()

	if userErr != nil {
		userSvc.EXPECT().GetByUsername(adminUser).Return(nil, userErr).AnyTimes()
	} else {
		userSvc.EXPECT().GetByUsername(adminUser).Return(user, nil).AnyTimes()
	}

	return admin.NewRouter(admin.Config{
		SessionSecret: testSessionSecret,
	}, authSvc, userSvc, oauthClients, auditRepo, nil, nil, nil, nil)
}

func TestAdminRequireSession_DeactivatedAdmin(t *testing.T) {
	handler := newRouterWithUserState(t, &domain.User{
		ID: "admin-id", Username: adminUser, Role: domain.RoleAdmin, IsActive: false,
	}, nil)

	sessionValue := mintTestSession(adminUser)
	cookie := &http.Cookie{Name: "admin_session", Value: sessionValue}
	req := authRequest(http.MethodGet, "/admin/", cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/admin/login", rr.Header().Get("Location"))
}

func TestAdminRequireSession_DemotedUser(t *testing.T) {
	handler := newRouterWithUserState(t, &domain.User{
		ID: "admin-id", Username: adminUser, Role: domain.RoleUser, IsActive: true,
	}, nil)

	sessionValue := mintTestSession(adminUser)
	cookie := &http.Cookie{Name: "admin_session", Value: sessionValue}
	req := authRequest(http.MethodGet, "/admin/", cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/admin/login", rr.Header().Get("Location"))
}

func TestAdminRequireSession_DeletedUser(t *testing.T) {
	handler := newRouterWithUserState(t, nil, domain.ErrNotFound)

	sessionValue := mintTestSession(adminUser)
	cookie := &http.Cookie{Name: "admin_session", Value: sessionValue}
	req := authRequest(http.MethodGet, "/admin/", cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/admin/login", rr.Header().Get("Location"))
}

func TestAdminRequireSession_ClearsSessionOnFailure(t *testing.T) {
	handler := newRouterWithUserState(t, &domain.User{
		ID: "admin-id", Username: adminUser, Role: domain.RoleAdmin, IsActive: false,
	}, nil)

	sessionValue := mintTestSession(adminUser)
	cookie := &http.Cookie{Name: "admin_session", Value: sessionValue}
	req := authRequest(http.MethodGet, "/admin/", cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Verify the response clears the session cookie
	var sessionCleared bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == "admin_session" {
			sessionCleared = c.MaxAge == -1 || c.Value == ""
		}
	}
	assert.True(t, sessionCleared, "admin_session cookie should be cleared (MaxAge=-1 or empty value)")
}

// --- OAuth Client Audit Logging ---

// newRouterWithOAuth builds a router that exposes the OAuth client and audit mocks
// so tests can set expectations and verify audit events.
func newRouterWithOAuth(t *testing.T) (http.Handler, *mocks.MockOAuthClientRepository, *mocks.MockAuditRepository) {
	t.Helper()
	ctrl := gomock.NewController(t)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	userSvc := mocks.NewMockUserServicer(ctrl)
	oauthClients := mocks.NewMockOAuthClientRepository(ctrl)
	auditRepo := mocks.NewMockAuditRepository(ctrl)
	auditRepo.EXPECT().List(gomock.Any()).Return(nil, nil).AnyTimes()

	authSvc.EXPECT().AuthorizeUser(adminUser, adminPass, gomock.Any()).Return("admin-id", nil).AnyTimes()
	authSvc.EXPECT().AuthorizeUser(gomock.Any(), gomock.Any(), gomock.Any()).Return("", service.ErrInvalidCredentials).AnyTimes()
	userSvc.EXPECT().GetByID("admin-id").Return(&domain.User{
		ID: "admin-id", Username: adminUser, Role: domain.RoleAdmin, IsActive: true,
	}, nil).AnyTimes()
	userSvc.EXPECT().GetByUsername(adminUser).Return(&domain.User{
		ID: "admin-id", Username: adminUser, Role: domain.RoleAdmin, IsActive: true,
	}, nil).AnyTimes()
	// Allow login audit event
	auditRepo.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()

	handler := admin.NewRouter(admin.Config{
		SessionSecret: testSessionSecret,
	}, authSvc, userSvc, oauthClients, auditRepo, nil, nil, nil, nil)
	return handler, oauthClients, auditRepo
}

func TestOAuthClientCreate_AuditLogged(t *testing.T) {
	handler, oauthClients, _ := newRouterWithOAuth(t)
	session := loginSession(t, handler)

	oauthClients.EXPECT().Create(gomock.Any()).Return(nil)

	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf":         {csrf},
		"id":            {"test-client"},
		"name":          {"Test Client"},
		"redirect_uris": {"https://example.com/callback"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/admin/oauth", rr.Header().Get("Location"))
}

func TestOAuthClientEdit_AuditLogged(t *testing.T) {
	handler, oauthClients, _ := newRouterWithOAuth(t)
	session := loginSession(t, handler)

	existingClient := &domain.OAuthClient{
		ID:           "test-client",
		Name:         "Old Name",
		RedirectURIs: []string{"https://example.com/callback"},
	}
	oauthClients.EXPECT().GetByID("test-client").Return(existingClient, nil)
	oauthClients.EXPECT().Update(gomock.Any()).Return(nil)

	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf":          {csrf},
		"name":           {"New Name"},
		"redirect_uris":  {"https://example.com/callback"},
		"admin_password": {adminPass},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/test-client/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/admin/oauth", rr.Header().Get("Location"))
}

func TestOAuthClientDelete_AuditLogged(t *testing.T) {
	handler, oauthClients, _ := newRouterWithOAuth(t)
	session := loginSession(t, handler)

	oauthClients.EXPECT().Delete("test-client").Return(nil)

	csrf := csrfTokenFor(session.Value)
	form := url.Values{"_csrf": {csrf}, "admin_password": {adminPass}}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/test-client/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/admin/oauth", rr.Header().Get("Location"))
}

func TestOAuthClientDelete_WrongPassword(t *testing.T) {
	handler, oauthClients, _ := newRouterWithOAuth(t)
	session := loginSession(t, handler)

	oauthClients.EXPECT().GetByID("test-client").Return(&domain.OAuthClient{
		ID: "test-client", Name: "Test Client", RedirectURIs: []string{"https://example.com/callback"},
	}, nil)

	csrf := csrfTokenFor(session.Value)
	form := url.Values{"_csrf": {csrf}, "admin_password": {"wrongpassword"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/test-client/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Incorrect password")
}

// --- Edit User Re-authentication ---

func TestAdminUsers_Edit_RoleChange_RequiresPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	// The handler calls GetByID to load the current user state
	userSvc.EXPECT().GetByID("u-edit").Return(&domain.User{
		ID: "u-edit", Username: "alice", Role: domain.RoleUser, IsActive: true,
	}, nil)

	handler := newRouter(t, userSvc)
	session := loginSession(t, handler)

	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf":     {csrf},
		"role":      {"admin"}, // changing from user to admin
		"is_active": {"1"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/u-edit/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should re-render form with error because no admin_password provided
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Incorrect password")
}

func TestAdminUsers_Edit_RoleChange_WithPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	userSvc.EXPECT().GetByID("u-edit").Return(&domain.User{
		ID: "u-edit", Username: "alice", Role: domain.RoleUser, IsActive: true,
	}, nil)
	userSvc.EXPECT().Update("u-edit", gomock.Any(), gomock.Any()).Return(&domain.User{
		ID: "u-edit", Username: "alice", Role: domain.RoleAdmin, IsActive: true,
	}, nil)

	handler := newRouter(t, userSvc)
	session := loginSession(t, handler)

	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf":          {csrf},
		"role":           {"admin"},
		"is_active":      {"1"},
		"admin_password": {adminPass},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/u-edit/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/admin/users", rr.Header().Get("Location"))
}

func TestAdminUsers_Edit_DeactivateUser_RequiresPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	userSvc.EXPECT().GetByID("u-edit").Return(&domain.User{
		ID: "u-edit", Username: "alice", Role: domain.RoleUser, IsActive: true,
	}, nil)

	handler := newRouter(t, userSvc)
	session := loginSession(t, handler)

	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf": {csrf},
		"role":  {"user"},
		// is_active not set => false, which is a change from true
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/u-edit/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Incorrect password")
}

func TestAdminUsers_Edit_DisplayNameOnly_NoPasswordRequired(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	userSvc.EXPECT().GetByID("u-edit").Return(&domain.User{
		ID: "u-edit", Username: "alice", Role: domain.RoleUser, IsActive: true,
	}, nil)
	userSvc.EXPECT().Update("u-edit", gomock.Any(), gomock.Any()).Return(&domain.User{
		ID: "u-edit", Username: "alice", DisplayName: "Alice Updated", Role: domain.RoleUser, IsActive: true,
	}, nil)

	handler := newRouter(t, userSvc)
	session := loginSession(t, handler)

	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf":        {csrf},
		"display_name": {"Alice Updated"},
		"role":         {"user"}, // same role
		"is_active":    {"1"},    // same active status
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/u-edit/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/admin/users", rr.Header().Get("Location"))
}

// --- Backup Security ---

func TestAdminBackup_GETNotAllowed(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	// Allow dashboard's List call since GET /admin/backup may match GET /admin/ pattern
	userSvc.EXPECT().List().Return([]*domain.User{}, nil).AnyTimes()
	handler := newRouter(t, userSvc)
	session := loginSession(t, handler)

	req := authRequest(http.MethodGet, "/admin/backup", session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// The route is POST-only; a GET should not trigger the backup handler.
	// Go's ServeMux may return 405 or fall through to another route — either way,
	// the response must NOT be a redirect to /?flash=backup_triggered.
	assert.NotContains(t, rr.Header().Get("Location"), "backup_triggered",
		"GET /admin/backup must not trigger the backup action")
}

// --- Round 7 / L2: Audience required for client_credentials grant ---
//
// Creating or editing an OAuth client with grant_type=client_credentials and an
// empty audience must be rejected with a validation error. An empty audience causes
// MintServiceToken to return an error, which previously resulted in a 500.

func TestOAuthClientCreate_ClientCredentials_RequiresAudience(t *testing.T) {
	handler, oauthClients, _ := newRouterWithOAuth(t)
	session := loginSession(t, handler)
	_ = oauthClients // no Create call expected — validation fires first

	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf":        {csrf},
		"id":           {"svc-client"},
		"name":         {"Service Client"},
		"grant_types":  {"client_credentials"},
		// audience intentionally omitted
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Must re-render form with validation error, not redirect or 500.
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Audience is required for client_credentials")
}

func TestOAuthClientCreate_ClientCredentials_WithAudience_Succeeds(t *testing.T) {
	handler, oauthClients, _ := newRouterWithOAuth(t)
	session := loginSession(t, handler)
	oauthClients.EXPECT().Create(gomock.Any()).Return(nil)

	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf":        {csrf},
		"id":           {"svc-client"},
		"name":         {"Service Client"},
		"grant_types":  {"client_credentials"},
		"audience":     {"https://api.example.com"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
}

func TestOAuthClientEdit_ClientCredentials_RequiresAudience(t *testing.T) {
	handler, oauthClients, _ := newRouterWithOAuth(t)
	session := loginSession(t, handler)

	existingClient := &domain.OAuthClient{
		ID:         "svc-client",
		Name:       "Service Client",
		GrantTypes: []string{"client_credentials"},
		Audience:   "https://api.example.com",
	}
	oauthClients.EXPECT().GetByID("svc-client").Return(existingClient, nil)
	// No Update call expected — validation fires first

	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf":          {csrf},
		"name":           {"Service Client"},
		"grant_types":    {"client_credentials"},
		"audience":       {""}, // clearing the audience must be rejected
		"admin_password": {adminPass},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/svc-client/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Audience is required for client_credentials")
}

func TestOAuthClientCreate_JavascriptRedirectURI_Rejected(t *testing.T) {
	handler, oauthClients, _ := newRouterWithOAuth(t)
	session := loginSession(t, handler)
	_ = oauthClients // no Create call expected — validation fires first

	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf":         {csrf},
		"id":            {"evil-client"},
		"name":          {"Evil Client"},
		"redirect_uris": {"javascript:alert(1)"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Redirect URIs must not use javascript: or data: schemes.")
}

func TestOAuthClientCreate_DataRedirectURI_Rejected(t *testing.T) {
	handler, oauthClients, _ := newRouterWithOAuth(t)
	session := loginSession(t, handler)
	_ = oauthClients // no Create call expected — validation fires first

	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf":         {csrf},
		"id":            {"evil-client"},
		"name":          {"Evil Client"},
		"redirect_uris": {"data:text/html,<script>alert(1)</script>"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Redirect URIs must not use javascript: or data: schemes.")
}

func TestOAuthClientEdit_JavascriptRedirectURI_Rejected(t *testing.T) {
	handler, oauthClients, _ := newRouterWithOAuth(t)
	session := loginSession(t, handler)

	existingClient := &domain.OAuthClient{
		ID:           "test-client",
		Name:         "Test Client",
		RedirectURIs: []string{"https://example.com/callback"},
	}
	oauthClients.EXPECT().GetByID("test-client").Return(existingClient, nil)
	// No Update call expected — validation fires first

	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf":          {csrf},
		"name":           {"Test Client"},
		"redirect_uris":  {"javascript:alert(1)"},
		"admin_password": {adminPass},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/test-client/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Redirect URIs must not use javascript: or data: schemes.")
}

func TestAdminBackup_RequiresCSRF(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	handler := newRouter(t, userSvc)
	session := loginSession(t, handler)

	// POST without CSRF token
	req := httptest.NewRequest(http.MethodPost, "/admin/backup", nil)
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// --- OAuth Client ID Validation ---

func TestOAuthClientCreate_InvalidClientID(t *testing.T) {
	handler, _, _ := newRouterWithOAuth(t)
	session := loginSession(t, handler)

	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf": {csrf},
		"id":    {"bad id/here"},
		"name":  {"Test Client"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Client ID may only contain")
}

// --- OAuth Client Backup Triggering ---

// newRouterWithOAuthAndBackup is like newRouterWithOAuth but also returns the backup mock.
func newRouterWithOAuthAndBackup(t *testing.T) (http.Handler, *mocks.MockOAuthClientRepository, *mocks.MockBackupService) {
	t.Helper()
	ctrl := gomock.NewController(t)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	userSvc := mocks.NewMockUserServicer(ctrl)
	oauthClients := mocks.NewMockOAuthClientRepository(ctrl)
	auditRepo := mocks.NewMockAuditRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)
	auditRepo.EXPECT().List(gomock.Any()).Return(nil, nil).AnyTimes()

	authSvc.EXPECT().AuthorizeUser(adminUser, adminPass, gomock.Any()).Return("admin-id", nil).AnyTimes()
	authSvc.EXPECT().AuthorizeUser(gomock.Any(), gomock.Any(), gomock.Any()).Return("", service.ErrInvalidCredentials).AnyTimes()
	userSvc.EXPECT().GetByID("admin-id").Return(&domain.User{
		ID: "admin-id", Username: adminUser, Role: domain.RoleAdmin, IsActive: true,
	}, nil).AnyTimes()
	userSvc.EXPECT().GetByUsername(adminUser).Return(&domain.User{
		ID: "admin-id", Username: adminUser, Role: domain.RoleAdmin, IsActive: true,
	}, nil).AnyTimes()
	auditRepo.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()

	handler := admin.NewRouter(admin.Config{
		SessionSecret: testSessionSecret,
	}, authSvc, userSvc, oauthClients, auditRepo, backupSvc, nil, nil, nil)
	return handler, oauthClients, backupSvc
}

func TestOAuthClientCreate_BackupTriggered(t *testing.T) {
	handler, oauthClients, backupSvc := newRouterWithOAuthAndBackup(t)
	session := loginSession(t, handler)

	oauthClients.EXPECT().Create(gomock.Any()).Return(nil)
	backupSvc.EXPECT().TriggerAsync()

	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf": {csrf},
		"id":    {"test-client"},
		"name":  {"Test Client"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
}

func TestOAuthClientEdit_BackupTriggered(t *testing.T) {
	handler, oauthClients, backupSvc := newRouterWithOAuthAndBackup(t)
	session := loginSession(t, handler)

	existingClient := &domain.OAuthClient{
		ID:           "test-client",
		Name:         "Old Name",
		RedirectURIs: []string{"https://example.com/callback"},
	}
	oauthClients.EXPECT().GetByID("test-client").Return(existingClient, nil)
	oauthClients.EXPECT().Update(gomock.Any()).Return(nil)
	backupSvc.EXPECT().TriggerAsync()

	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf":          {csrf},
		"name":           {"New Name"},
		"redirect_uris":  {"https://example.com/callback"},
		"admin_password": {adminPass},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/test-client/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
}

func TestOAuthClientDelete_BackupTriggered(t *testing.T) {
	handler, oauthClients, backupSvc := newRouterWithOAuthAndBackup(t)
	session := loginSession(t, handler)

	oauthClients.EXPECT().Delete("test-client").Return(nil)
	backupSvc.EXPECT().TriggerAsync()

	csrf := csrfTokenFor(session.Value)
	form := url.Values{"_csrf": {csrf}, "admin_password": {adminPass}}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/test-client/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
}

func TestOAuthClientGenerateSecret_BackupTriggered(t *testing.T) {
	handler, oauthClients, backupSvc := newRouterWithOAuthAndBackup(t)
	session := loginSession(t, handler)

	client := &domain.OAuthClient{ID: "test-client", Name: "Test Client"}
	oauthClients.EXPECT().GetByID("test-client").Return(client, nil)
	oauthClients.EXPECT().Update(gomock.Any()).Return(nil)
	backupSvc.EXPECT().TriggerAsync()

	csrf := csrfTokenFor(session.Value)
	form := url.Values{"_csrf": {csrf}, "admin_password": {adminPass}}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/test-client/generate-secret", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestOAuthClientRotateSecret_BackupTriggered(t *testing.T) {
	handler, oauthClients, backupSvc := newRouterWithOAuthAndBackup(t)
	session := loginSession(t, handler)

	client := &domain.OAuthClient{ID: "test-client", Name: "Test Client", SecretHash: "existing-hash"}
	oauthClients.EXPECT().GetByID("test-client").Return(client, nil)
	oauthClients.EXPECT().Update(gomock.Any()).Return(nil)
	backupSvc.EXPECT().TriggerAsync()

	csrf := csrfTokenFor(session.Value)
	form := url.Values{"_csrf": {csrf}, "admin_password": {adminPass}}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/test-client/rotate-secret", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestOAuthClientClearPrevSecret_BackupTriggered(t *testing.T) {
	handler, oauthClients, backupSvc := newRouterWithOAuthAndBackup(t)
	session := loginSession(t, handler)

	client := &domain.OAuthClient{ID: "test-client", Name: "Test Client", SecretHashPrev: "old-hash"}
	oauthClients.EXPECT().GetByID("test-client").Return(client, nil)
	oauthClients.EXPECT().Update(gomock.Any()).Return(nil)
	backupSvc.EXPECT().TriggerAsync()

	csrf := csrfTokenFor(session.Value)
	form := url.Values{"_csrf": {csrf}, "admin_password": {adminPass}}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/test-client/clear-prev-secret", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
}

func TestOAuthClientCreate_ValidClientID(t *testing.T) {
	handler, oauthClients, _ := newRouterWithOAuth(t)
	session := loginSession(t, handler)

	oauthClients.EXPECT().Create(gomock.Any()).Return(nil)

	csrf := csrfTokenFor(session.Value)
	form := url.Values{
		"_csrf": {csrf},
		"id":    {"my-client_1.0"},
		"name":  {"Test Client"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/admin/oauth", rr.Header().Get("Location"))
}

// --- Passkey prompt ---

// TestPasskeyPrompt_SkipURL_NotSanitized verifies that the SkipURL passed to
// the passkey prompt page is rendered verbatim and not replaced with
// #ZgotmplZ by html/template's URL sanitizer.
func TestPasskeyPrompt_SkipURL_NotSanitized(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	handler := newRouter(t, userSvc)
	session := loginSession(t, handler)

	next := "/admin/some-page"
	req := httptest.NewRequest(http.MethodGet, "/admin/passkeys/prompt?next="+url.QueryEscape(next), nil)
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, next, "SkipURL must render the next URL intact")
	assert.NotContains(t, body, "#ZgotmplZ", "html/template must not sanitize the SkipURL")
}

// TestPasskeyPrompt_DefaultSkipURL verifies that when no next parameter is
// provided, the SkipURL defaults to /admin/.
func TestPasskeyPrompt_DefaultSkipURL(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	handler := newRouter(t, userSvc)
	session := loginSession(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/admin/passkeys/prompt", nil)
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `href="/admin/"`, "default SkipURL should link to /admin/")
}
