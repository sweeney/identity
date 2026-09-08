package api_test

// management_plane_test.go covers the routing half of #37: which routes demand
// an exclusively-scoped token, and — just as important — which must not.

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

const selfIssuer = "https://id.example.com"

// mintDelegated mints an admin token naming this server *and* siblings — the
// shape `claude` and `net.swee.mac` register in production.
func mintDelegated(t *testing.T, issuer *auth.TokenIssuer, role domain.Role) string {
	t.Helper()
	tok, err := issuer.Mint(domain.TokenClaims{
		UserID: "u1", Username: "admin", Role: role, IsActive: true,
		Audience: []string{"config", "statehouse", selfIssuer, "mqttauth"},
	})
	require.NoError(t, err)
	return tok
}

// mintExclusive mints a token naming only this server.
func mintExclusive(t *testing.T, issuer *auth.TokenIssuer, role domain.Role) string {
	t.Helper()
	tok, err := issuer.Mint(domain.TokenClaims{
		UserID: "u1", Username: "admin", Role: role, IsActive: true,
		Audience: []string{selfIssuer},
	})
	require.NoError(t, err)
	return tok
}

func managementRouter(t *testing.T, issuer *auth.TokenIssuer) http.Handler {
	t.Helper()
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	admin := &domain.User{ID: "u1", Username: "admin", Role: domain.RoleAdmin, IsActive: true}
	userSvc.EXPECT().GetByID(gomock.Any()).Return(admin, nil).AnyTimes()
	userSvc.EXPECT().List().Return([]*domain.User{admin}, nil).AnyTimes()
	userSvc.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(admin, nil).AnyTimes()
	userSvc.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).Return(admin, nil).AnyTimes()
	userSvc.EXPECT().Delete(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	return api.NewRouter(issuer, nil, userSvc, nil, "")
}

var managementRoutes = []struct{ method, path, body string }{
	{"GET", "/api/v1/users", ""},
	{"POST", "/api/v1/users", `{"username":"bob","password":"bobpassword123","role":"user"}`},
	{"PUT", "/api/v1/users/u1", `{"name":"Bob"}`},
	{"DELETE", "/api/v1/users/u1", ""},
}

func call(t *testing.T, h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// TestManagementPlane_RefusesDelegatedToken is #37. The account is an admin and
// the token names this server, so both the role check and RequireAudience pass
// — but the token is also a live bearer credential at three other services.
func TestManagementPlane_RefusesDelegatedToken(t *testing.T) {
	issuer := newURLIssuer(t, selfIssuer)
	h := managementRouter(t, issuer)
	tok := mintDelegated(t, issuer, domain.RoleAdmin)

	for _, r := range managementRoutes {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			rr := call(t, h, r.method, r.path, r.body, tok)
			assert.Equal(t, http.StatusForbidden, rr.Code,
				"a token delegated to sibling services must not administer identity")
			assert.Equal(t, "invalid_audience", parseErrorCode(t, rr))
		})
	}
}

// TestManagementPlane_AcceptsExclusiveToken — the boundary is exclusivity, not
// a blanket refusal of audience-bearing tokens.
func TestManagementPlane_AcceptsExclusiveToken(t *testing.T) {
	issuer := newURLIssuer(t, selfIssuer)
	h := managementRouter(t, issuer)
	tok := mintExclusive(t, issuer, domain.RoleAdmin)

	for _, r := range managementRoutes {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			rr := call(t, h, r.method, r.path, r.body, tok)
			assert.NotEqual(t, http.StatusForbidden, rr.Code,
				"a token naming only this server must be accepted: %s", rr.Body.String())
		})
	}
}

// TestManagementPlane_AcceptsDirectLoginToken is the compatibility case that
// matters most: an admin signing in at /api/v1/auth/login gets no aud at all,
// and must keep full access.
func TestManagementPlane_AcceptsDirectLoginToken(t *testing.T) {
	issuer := newURLIssuer(t, selfIssuer)
	h := managementRouter(t, issuer)
	tok, err := issuer.Mint(domain.TokenClaims{
		UserID: "u1", Username: "admin", Role: domain.RoleAdmin, IsActive: true,
	})
	require.NoError(t, err)

	for _, r := range managementRoutes {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			rr := call(t, h, r.method, r.path, r.body, tok)
			assert.NotEqual(t, http.StatusForbidden, rr.Code,
				"a direct-login token was never delegated anywhere and must keep working: %s", rr.Body.String())
		})
	}
}

// TestOrdinaryPlane_StillAcceptsDelegatedToken is the other half of the split,
// and the reason this is a split rather than a tightening. A delegated token
// must keep working on the ordinary routes — that is the whole point of a
// client naming several services.
func TestOrdinaryPlane_StillAcceptsDelegatedToken(t *testing.T) {
	issuer := newURLIssuer(t, selfIssuer)
	h := managementRouter(t, issuer)
	tok := mintDelegated(t, issuer, domain.RoleUser)

	rr := call(t, h, "GET", "/api/v1/auth/me", "", tok)
	assert.Equal(t, http.StatusOK, rr.Code,
		"a multi-audience token must still reach the ordinary plane: %s", rr.Body.String())

	// Reading your own record is a self-service read, not administration, so it
	// stays on the ordinary plane too.
	rr = call(t, h, "GET", "/api/v1/users/u1", "", tok)
	assert.NotEqual(t, http.StatusForbidden, rr.Code,
		"self-read must stay on the ordinary plane: %s", rr.Body.String())
}
