package admin_test

// session_epoch_test.go covers #33 (part of GHSA-vrh2-jqhp-4m44): the admin UI
// session cookie could not be revoked.
//
// #29 made a password change revoke every refresh token the user holds, which
// is the right response to a compromise. The admin UI's own session JWT was not
// covered: it is a self-contained 2-hour bearer cookie, so whoever held one
// kept full admin access for its remaining lifetime no matter what the real
// owner did — changing the password, logging out, even running --reset-admin on
// the host.
//
// requireSession already re-reads IsActive and Role, so disabling or demoting
// the account did take effect. Only a *credential* change did not, which is
// exactly the lever someone reaches for when they suspect a session was stolen.

import (
	"net/http"
	"net/http/httptest"
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

// getWithSession performs an authenticated GET against an admin page.
func getWithSession(t *testing.T, handler http.Handler, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// TestAdminSession_EpochBumpInvalidatesExistingCookie is the core of #33.
func TestAdminSession_EpochBumpInvalidatesExistingCookie(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	handler := newRouterWithEpoch(t, userSvc, 0)

	cookie := loginSession(t, handler)

	rr := getWithSession(t, handler, "/admin/", cookie)
	require.Equal(t, http.StatusOK, rr.Code, "baseline: the session must work before the bump")

	// The user changes their password (or an admin runs --reset-admin), which
	// bumps the epoch stored on the account.
	setEpoch(userSvc, 1)

	rr = getWithSession(t, handler, "/admin/", cookie)
	assert.Equal(t, http.StatusSeeOther, rr.Code,
		"a session minted before the credential change must stop working")
	assert.Equal(t, "/admin/login", rr.Header().Get("Location"))
}

// TestAdminSession_SurvivesUnrelatedRequests guards against the check being so
// strict it invalidates sessions that should keep working.
func TestAdminSession_SurvivesUnrelatedRequests(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	handler := newRouterWithEpoch(t, userSvc, 7)

	cookie := loginSession(t, handler)
	for i := range 3 {
		rr := getWithSession(t, handler, "/admin/", cookie)
		require.Equal(t, http.StatusOK, rr.Code, "request %d", i)
	}
}

// TestAdminSession_LegacyCookieWithoutEpochIsRejectedOnceBumped covers the
// upgrade window. Sessions minted before this change carry no epoch claim; they
// read as epoch 0, which matches an account that has never bumped, so they keep
// working — and stop the moment a credential change happens, which is the whole
// point.
func TestAdminSession_LegacyCookieWithoutEpochIsRejectedOnceBumped(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	handler := newRouterWithEpoch(t, userSvc, 0)

	cookie := legacySessionCookie(t)

	rr := getWithSession(t, handler, "/admin/", cookie)
	require.Equal(t, http.StatusOK, rr.Code,
		"a session predating the epoch claim must not be invalidated by the upgrade itself")

	setEpoch(userSvc, 1)
	rr = getWithSession(t, handler, "/admin/", cookie)
	assert.Equal(t, http.StatusSeeOther, rr.Code,
		"but it must still be revocable")
}

// TestAdminSession_ForgedEpochIsRejected checks the epoch is not simply trusted
// from the cookie. It is inside the signed JWT, so this should be impossible —
// the test exists because "the claim is signed" is the only thing making the
// comparison meaningful.
func TestAdminSession_ForgedEpochIsRejected(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	handler := newRouterWithEpoch(t, userSvc, 5)

	cookie := forgedEpochCookie(t, domain.RoleAdmin, 5)

	rr := getWithSession(t, handler, "/admin/", cookie)
	assert.Equal(t, http.StatusSeeOther, rr.Code,
		"a cookie signed with the wrong key must be refused whatever epoch it claims")
}

// --- helpers ---

// epochUser is the account the mocks return; its SessionEpoch is mutable so a
// test can simulate a credential change mid-session.
type epochUser struct {
	epoch int64
}

var currentEpoch = &epochUser{}

// setEpoch simulates the account's session epoch being bumped.
func setEpoch(_ *mocks.MockUserServicer, e int64) { currentEpoch.epoch = e }

// newRouterWithEpoch is newRouter with the admin account reporting a mutable
// session epoch, read fresh on every request as requireSession does.
func newRouterWithEpoch(t *testing.T, userSvc *mocks.MockUserServicer, start int64) http.Handler {
	t.Helper()
	currentEpoch.epoch = start
	ctrl := gomock.NewController(t)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	oauthClients := mocks.NewMockOAuthClientRepository(ctrl)
	auditRepo := mocks.NewMockAuditRepository(ctrl)
	auditRepo.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()
	auditRepo.EXPECT().List(gomock.Any()).Return(nil, nil).AnyTimes()

	authSvc.EXPECT().AuthorizeUser(adminUser, adminPass, gomock.Any()).Return("admin-id", nil).AnyTimes()
	authSvc.EXPECT().AuthorizeUser(gomock.Any(), gomock.Any(), gomock.Any()).
		Return("", service.ErrInvalidCredentials).AnyTimes()

	live := func() *domain.User {
		return &domain.User{
			ID: "admin-id", Username: adminUser, Role: domain.RoleAdmin,
			IsActive: true, SessionEpoch: currentEpoch.epoch,
		}
	}
	userSvc.EXPECT().GetByID("admin-id").DoAndReturn(func(string) (*domain.User, error) {
		return live(), nil
	}).AnyTimes()
	userSvc.EXPECT().GetByUsername(adminUser).DoAndReturn(func(string) (*domain.User, error) {
		return live(), nil
	}).AnyTimes()
	// The dashboard renders a user count.
	userSvc.EXPECT().List().Return([]*domain.User{live()}, nil).AnyTimes()
	userSvc.EXPECT().BumpSessionEpoch(gomock.Any()).DoAndReturn(func(string) error {
		currentEpoch.epoch++
		return nil
	}).AnyTimes()

	return admin.NewRouter(admin.Config{SessionSecret: testSessionSecret},
		authSvc, userSvc, oauthClients, auditRepo, nil, nil, nil, nil)
}

// legacySessionCookie mints a session carrying no epoch claim at all, as every
// cookie issued before this change does.
func legacySessionCookie(t *testing.T) *http.Cookie {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   adminUser,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	signed, err := tok.SignedString([]byte(testSessionSecret))
	require.NoError(t, err)
	return &http.Cookie{Name: "admin_session", Value: signed}
}

// forgedEpochCookie mints a session with the right shape but the wrong key.
func forgedEpochCookie(t *testing.T, _ domain.Role, epoch int64) *http.Cookie {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   adminUser,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"epoch": epoch,
	})
	signed, err := tok.SignedString([]byte("not-the-real-session-secret-at-all"))
	require.NoError(t, err)
	return &http.Cookie{Name: "admin_session", Value: signed}
}
