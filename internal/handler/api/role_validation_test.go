package api_test

// role_validation_test.go covers WP10 (GHSA-m6mm-8758-jr99): the role field was
// not validated.
//
// On create, anything that was not exactly "admin" became "user" — so a typo
// like "Admin" or "administrator" silently produced a non-admin account and the
// caller was told it succeeded. On update the string went through to the store
// unchecked, producing a 500 for the caller and, worse, a role value the rest
// of the system does not recognise: RequireAdmin compares against "admin", so a
// user carrying "Admin" is neither admin nor plain user.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/handler/api"
	"github.com/sweeney/identity/internal/mocks"
)

func TestCreateUser_UnknownRole_Rejected(t *testing.T) {
	for _, role := range []string{"Admin", "administrator", "superuser", "ADMIN", " admin"} {
		t.Run(role, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			userSvc := mocks.NewMockUserServicer(ctrl)
			issuer := newTestIssuer(t)
			expectAdminStatusLookup(userSvc)
			// No Create expectation: an unrecognised role must not reach the
			// service, silently downgraded to "user".

			h := api.NewRouter(issuer, nil, userSvc, nil, "")
			rr := postJSONAuth(t, h, "/api/v1/users", map[string]string{
				"username": "alice",
				"password": "correct horse battery staple",
				"role":     role,
			}, adminToken(t, issuer))

			require.Equal(t, http.StatusBadRequest, rr.Code,
				"an unrecognised role must be rejected, not quietly turned into 'user'")
			assert.Equal(t, "validation_error", parseErrorCode(t, rr))
		})
	}
}

func TestUpdateUser_UnknownRole_Rejected(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	issuer := newTestIssuer(t)
	expectAdminStatusLookup(userSvc)
	// No Update expectation: an unrecognised role must not reach the store.

	h := api.NewRouter(issuer, nil, userSvc, nil, "")
	rr := putJSONAuth(t, h, "/api/v1/users/u-1", map[string]string{
		"role": "superuser",
	}, adminToken(t, issuer))

	require.Equal(t, http.StatusBadRequest, rr.Code,
		"an unrecognised role must be a 400, not a 500 from the store")
	assert.Equal(t, "validation_error", parseErrorCode(t, rr))
}
