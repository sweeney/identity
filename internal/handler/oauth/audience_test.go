package oauth_test

// audience_test.go covers WP1 (GHSA-65pj-9cmp-rvf6) at the two OAuth passkey
// bridges. Both take an access_token, parse it, and act on its subject:
//
//   POST /oauth/device/passkey    — approves the device session named by
//                                   user_code, which then yields a 30-day
//                                   refresh token. No consent screen is shown.
//   POST /oauth/authorize/passkey — mints an authorization code for the subject.
//
// tokenIssuer.Parse validates signature, issuer, expiry and typ, but never aud,
// so any holder of a user's token — including a sibling resource server that
// merely received it as a bearer — could drive either bridge on their behalf.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/handler/oauth"
	"github.com/sweeney/identity/internal/mocks"
)

// mintUserTokenWithAudience mints a user token carrying `audience`, as the
// PKCE and device grants do with the OAuth client's configured audience.
func mintUserTokenWithAudience(t *testing.T, issuer *auth.TokenIssuer, audience string) string {
	t.Helper()
	tok, err := issuer.Mint(domain.TokenClaims{
		UserID:   "victim-1",
		Username: "victim",
		Role:     domain.RoleUser,
		IsActive: true,
		Audience: []string{audience},
	})
	require.NoError(t, err)
	return tok
}

// The device bridge must not approve a session for a token that was minted for
// somewhere else. deviceSvc has no Approve expectation registered: if the
// handler calls it, gomock fails the test — which is the escalation itself.
func TestDeviceVerifyPasskey_ForeignAudience_Rejected(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	issuer := newSecurityTestIssuer(t, "https://id.example.com")

	token := mintUserTokenWithAudience(t, issuer, "https://config-api.example")
	h := deviceRouterWithIssuer(svc, deviceSvc, issuer)

	rr := postDevicePasskey(t, h, url.Values{
		"access_token": {token},
		"user_code":    {"ABCD-1234"},
	})

	assert.Equal(t, http.StatusForbidden, rr.Code,
		"a token minted for another service must not approve a device session")
	var body map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "invalid_audience", body["error"])
}

func TestDeviceVerifyPasskey_SelfAudience_Accepted(t *testing.T) {
	// Control: a token minted for this server still approves the device.
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	issuer := newSecurityTestIssuer(t, "https://id.example.com")

	deviceSvc.EXPECT().
		Approve("ABCD-1234", "victim-1", "victim", gomock.Any()).
		Return(nil)

	token := mintUserTokenWithAudience(t, issuer, "https://id.example.com")
	h := deviceRouterWithIssuer(svc, deviceSvc, issuer)

	rr := postDevicePasskey(t, h, url.Values{
		"access_token": {token},
		"user_code":    {"ABCD-1234"},
	})
	assert.Equal(t, http.StatusOK, rr.Code)
}

// The authorize bridge must not mint an authorization code for a token that was
// minted for somewhere else. svc has no AuthorizeByUserID expectation.
func TestAuthorizePasskey_ForeignAudience_Rejected(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	issuer := newSecurityTestIssuer(t, "https://id.example.com")

	token := mintUserTokenWithAudience(t, issuer, "https://config-api.example")
	h := oauth.NewRouter(svc, "", issuer, nil, nil, nil, "", "")

	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize/passkey", nil)
	req.Host = "id.example.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", "https://id.example.com")
	req.Body = http.NoBody
	req.Form = url.Values{
		"access_token":   {token},
		"client_id":      {"testapp"},
		"redirect_uri":   {"https://app.example.com/callback"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code,
		"a token minted for another service must not mint an authorization code")
	var body map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "invalid_audience", body["error"])
}
