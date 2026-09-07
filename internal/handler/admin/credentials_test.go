package admin_test

// credentials_test.go covers WP10 (GHSA-m6mm-8758-jr99): credentials were read
// with r.FormValue, which consults the URL query *before* the POST body.
//
// A password in a query string is a password in the server access log, in the
// browser history, and in the Referer header of anything the page subsequently
// loads. It also means a link can carry a re-authentication confirmation:
// anything that gets an admin to follow a crafted URL satisfies the
// "confirm your password" gate without them typing anything.
//
// Credentials must come from the request body only.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/handler/admin"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

// postWithQueryCredentials sends an empty POST body and puts the credentials in
// the URL instead.
func postWithQueryCredentials(t *testing.T, h http.Handler, path string, query url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path+"?"+query.Encode(), strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestAdminLogin_CredentialsFromQueryString_Rejected(t *testing.T) {
	handler := newTestAdminRouter(t)

	rr := postWithQueryCredentials(t, handler, "/admin/login", url.Values{
		"username": {adminUser},
		"password": {adminPass},
	}, nil)

	assert.NotEqual(t, http.StatusSeeOther, rr.Code,
		"a login must not be completable from the URL query — that puts the password in logs and history")
	for _, c := range rr.Result().Cookies() {
		assert.NotEqual(t, "admin_session", c.Name,
			"no session may be established from query-string credentials")
	}
}

// The re-authentication gate in front of destructive admin actions must not be
// satisfiable by a crafted link.
func TestAdminReauth_PasswordFromQueryString_Rejected(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	oauthClients := mocks.NewMockOAuthClientRepository(ctrl)
	auditRepo := mocks.NewMockAuditRepository(ctrl)
	auditRepo.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()

	adminUsr := &domain.User{ID: "admin-id", Username: adminUser, Role: domain.RoleAdmin, IsActive: true}
	userSvc.EXPECT().GetByUsername(adminUser).Return(adminUsr, nil).AnyTimes()
	userSvc.EXPECT().GetByID("admin-id").Return(adminUsr, nil).AnyTimes()
	authSvc.EXPECT().AuthorizeUser(adminUser, adminPass, gomock.Any()).
		Return("admin-id", nil).AnyTimes()
	authSvc.EXPECT().AuthorizeUser(gomock.Any(), gomock.Any(), gomock.Any()).
		Return("", service.ErrInvalidCredentials).AnyTimes()
	// No Delete expectation: reaching it means the gate was satisfied from a URL.

	handler := admin.NewRouter(admin.Config{SessionSecret: testSessionSecret},
		authSvc, userSvc, oauthClients, auditRepo, nil, nil, nil, nil)

	session := &http.Cookie{Name: "admin_session", Value: mintTestSession(adminUser)}
	rr := postWithQueryCredentials(t, handler, "/admin/users/victim-id/delete", url.Values{
		"admin_password": {adminPass},
	}, session)

	assert.NotEqual(t, http.StatusSeeOther, rr.Code,
		"the re-auth gate must not accept a password supplied in the URL")
}

func newTestAdminRouter(t *testing.T) http.Handler {
	t.Helper()
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	oauthClients := mocks.NewMockOAuthClientRepository(ctrl)
	auditRepo := mocks.NewMockAuditRepository(ctrl)
	auditRepo.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()

	authSvc.EXPECT().AuthorizeUser(adminUser, adminPass, gomock.Any()).Return("admin-id", nil).AnyTimes()
	authSvc.EXPECT().AuthorizeUser(gomock.Any(), gomock.Any(), gomock.Any()).
		Return("", service.ErrInvalidCredentials).AnyTimes()
	userSvc.EXPECT().GetByID("admin-id").Return(&domain.User{
		ID: "admin-id", Username: adminUser, Role: domain.RoleAdmin, IsActive: true,
	}, nil).AnyTimes()
	userSvc.EXPECT().GetByUsername(adminUser).Return(&domain.User{
		ID: "admin-id", Username: adminUser, Role: domain.RoleAdmin, IsActive: true,
	}, nil).AnyTimes()

	return admin.NewRouter(admin.Config{SessionSecret: testSessionSecret},
		authSvc, userSvc, oauthClients, auditRepo, nil, nil, nil, nil)
}

var _ = require.New
