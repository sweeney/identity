package api_test

// scope_test.go covers the second half of #32: RequireScope is applied to the
// mutating user-management routes, so a deliberately narrowed token cannot
// administer users.
//
// WP5 (#29) made the device grant issue genuinely scoped user tokens — a device
// approved for scope=read:sensors carries that claim. Until this wiring, no
// route read it, so the scope shown on the approval screen restricted nothing.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/handler/api"
	"github.com/sweeney/identity/internal/mocks"
)

// scopeRouter builds a router whose user service tolerates any call, so a
// request that clears the guards reaches a handler rather than a nil pointer.
func scopeRouter(t *testing.T, issuer *auth.TokenIssuer) http.Handler {
	t.Helper()
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	admin := &domain.User{ID: "u1", Username: "admin", Role: domain.RoleAdmin, IsActive: true}
	userSvc.EXPECT().GetByID(gomock.Any()).Return(admin, nil).AnyTimes()
	userSvc.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(admin, nil).AnyTimes()
	userSvc.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).Return(admin, nil).AnyTimes()
	userSvc.EXPECT().Delete(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	return api.NewRouter(issuer, nil, userSvc, nil, "")
}

// mintScopedAdmin mints an admin token narrowed to the given scope, as the
// device grant does when a device is approved for a limited scope.
func mintScopedAdmin(t *testing.T, issuer *auth.TokenIssuer, scope string) string {
	t.Helper()
	tok, err := issuer.Mint(domain.TokenClaims{
		UserID:   "u1",
		Username: "admin",
		Role:     domain.RoleAdmin,
		IsActive: true,
		Scope:    scope,
	})
	require.NoError(t, err)
	return tok
}

// mutatingUserRoutes are the routes that change the user table.
var mutatingUserRoutes = []struct{ method, path, body string }{
	{"POST", "/api/v1/users", `{"username":"bob","password":"bobpassword123","role":"user"}`},
	{"PUT", "/api/v1/users/some-id", `{"name":"Bob"}`},
	{"DELETE", "/api/v1/users/some-id", ""},
}

// TestAPIRouter_NarrowedTokenCannotAdministerUsers is the point of the wiring.
// The account is an admin — the role check passes — but the token it is
// presenting was narrowed at consent to something else entirely.
func TestAPIRouter_NarrowedTokenCannotAdministerUsers(t *testing.T) {
	issuer := newTestIssuer(t)
	tok := mintScopedAdmin(t, issuer, "read:sensors")
	h := scopeRouter(t, issuer)

	for _, r := range mutatingUserRoutes {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			req := httptest.NewRequest(r.method, r.path, strings.NewReader(r.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusForbidden, rr.Code,
				"a token narrowed to read:sensors must not administer users, whatever the account's role")
			assert.Equal(t, "insufficient_scope", parseErrorCode(t, rr))
		})
	}
}

// TestAPIRouter_ScopedTokenWithTheScopePasses shows the guard is a scope check
// and not a blanket refusal of scoped tokens.
func TestAPIRouter_ScopedTokenWithTheScopePasses(t *testing.T) {
	issuer := newTestIssuer(t)
	tok := mintScopedAdmin(t, issuer, "admin:users read:sensors")
	h := scopeRouter(t, issuer)

	req := httptest.NewRequest("DELETE", "/api/v1/users/some-id", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.NotEqual(t, http.StatusForbidden, rr.Code,
		"a token carrying admin:users must clear the scope guard")
}

// TestAPIRouter_UnscopedTokenUnaffected is the compatibility guard. Every token
// in circulation from a direct login or an unscoped OAuth grant carries no
// scope claim, which means unrestricted; wiring this must not sign them out of
// user management.
func TestAPIRouter_UnscopedTokenUnaffected(t *testing.T) {
	issuer := newTestIssuer(t)
	tok := mintScopedAdmin(t, issuer, "")
	h := scopeRouter(t, issuer)

	for _, r := range mutatingUserRoutes {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			req := httptest.NewRequest(r.method, r.path, strings.NewReader(r.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			assert.NotEqual(t, http.StatusForbidden, rr.Code,
				"an unscoped token is unrestricted and must keep working")
		})
	}
}
