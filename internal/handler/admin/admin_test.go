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
	}, authSvc, userSvc, oauthClients, auditRepo, nil)
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
	form := url.Values{"_csrf": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/u-del/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
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
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(8 * time.Hour)),
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
	}, authSvc, userSvc, oauthClients, auditRepo, nil)
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
