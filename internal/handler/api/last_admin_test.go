package api_test

// last_admin_test.go covers WP2 (GHSA-4p62-wv6w-4vqf) at the API surface.
// PUT /api/v1/users/{id} had no case for ErrCannotDeleteLastAdmin, so the guard
// arrived as a 500 internal_error — indistinguishable from a real fault, and
// giving the caller nothing to act on. DELETE already mapped it to a 409.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/handler/api"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

func TestUpdateUser_LastAdmin_Returns409(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	issuer := newTestIssuer(t)

	expectAdminStatusLookup(userSvc)
	userSvc.EXPECT().Update("admin-1", gomock.Any(), gomock.Any()).
		Return(nil, service.ErrCannotDeleteLastAdmin)

	h := api.NewRouter(issuer, nil, userSvc, nil, "")
	rr := putJSONAuth(t, h, "/api/v1/users/admin-1", map[string]string{
		"role": "user",
	}, adminToken(t, issuer))

	require.Equal(t, http.StatusConflict, rr.Code,
		"demoting the last admin is a conflict the caller can act on, not a server fault")
	assert.Equal(t, "cannot_delete_last_admin", parseErrorCode(t, rr))
}
