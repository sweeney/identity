package oauth_test

// refresh_binding_test.go covers WP4 (GHSA-vrh2-jqhp-4m44) at the token
// endpoint: the refresh_token grant performed no client authentication and no
// client binding.
//
// A refresh token leaked from one OAuth client — through a log, a proxy, a
// compromised client — could be redeemed by any other registered client, for a
// user who never consented to that client. The authorization_code grant already
// authenticates confidential clients here; the refresh grant did not.

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

func TestTokenRefresh_WrongClient_Rejected(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	svc.EXPECT().
		RefreshTokenForClient("leaked-refresh-token", "attacker-app").
		Return(nil, service.ErrRefreshTokenClientMismatch)

	h := newDeviceRouter(svc, nil, nil)
	rr := postForm(t, h, "/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"leaked-refresh-token"},
		"client_id":     {"attacker-app"},
	})

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant",
		"a refresh token issued to another client must not be redeemable here")
}

func TestTokenRefresh_OwningClient_Succeeds(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	svc.EXPECT().
		RefreshTokenForClient("good-refresh-token", "photo-app").
		Return(&service.LoginResult{AccessToken: "a", RefreshToken: "r", TokenType: "Bearer", ExpiresIn: 900}, nil)

	h := newDeviceRouter(svc, nil, nil)
	rr := postForm(t, h, "/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"good-refresh-token"},
		"client_id":     {"photo-app"},
	})
	require.Equal(t, http.StatusOK, rr.Code)
}

// A confidential client must authenticate on the refresh grant, exactly as it
// does on the authorization_code grant.
func TestTokenRefresh_ConfidentialClient_RequiresSecret(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	svc.EXPECT().GetClient("device-client").Return(confidentialDeviceClient(), nil).AnyTimes()
	// No RefreshTokenForClient expectation: reaching it means an
	// unauthenticated caller redeemed the token.

	h := newDeviceRouter(svc, nil, nil)
	rr := postForm(t, h, "/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"good-refresh-token"},
		"client_id":     {"device-client"},
	})

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_client")
}

var _ = domain.GrantTypeDeviceCode
