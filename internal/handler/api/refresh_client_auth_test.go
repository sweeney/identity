package api_test

// refresh_client_auth_test.go checks how #40's refusal surfaces at the API.

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

func TestRefresh_ConfidentialClientToken_Returns401(t *testing.T) {
	ctrl := gomock.NewController(t)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	authSvc.EXPECT().Refresh("some-refresh-token").
		Return(nil, service.ErrRefreshRequiresClientAuth)

	h := api.NewRouter(newTestIssuer(t), authSvc, nil, nil, "")
	rr := postJSON(t, h, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": "some-refresh-token",
	})

	require.Equal(t, http.StatusUnauthorized, rr.Code,
		"a refusal the caller can fix by using the right endpoint is a 401, not a 500")
	// Read before parsing: parseErrorCode drains the recorder's buffer.
	body := rr.Body.String()
	assert.Equal(t, "client_authentication_required", parseErrorCode(t, rr))
	assert.Contains(t, body, "/oauth/token",
		"the error must say where the token can actually be redeemed")
}
