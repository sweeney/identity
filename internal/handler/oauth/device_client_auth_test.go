package oauth_test

// device_client_auth_test.go covers the WP5 (GHSA-fj5g-j4mv-7m5g) finding that
// the device endpoints never authenticated confidential clients.
//
// /oauth/token already enforces RFC 6749 §3.2.1: a client with a registered
// secret MUST authenticate. POST /oauth/device_authorization and
// POST /oauth/device/claim took a bare client_id, so anyone who knew a
// confidential client's ID could open device sessions in its name and drive
// user_codes at its users.

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

func confidentialDeviceClient() *domain.OAuthClient {
	return &domain.OAuthClient{
		ID:         "device-client",
		Name:       "Home IoT",
		GrantTypes: []string{domain.GrantTypeDeviceCode},
		// bcrypt hash of "s3cret"
		SecretHash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
	}
}

func TestDeviceAuthorization_ConfidentialClient_RequiresSecret(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)

	svc.EXPECT().GetClient("device-client").Return(confidentialDeviceClient(), nil).AnyTimes()
	// No IssueDeviceAuthorization expectation: reaching it means an
	// unauthenticated caller opened a session in the client's name.

	h := newDeviceRouter(svc, deviceSvc, nil)
	rr := postForm(t, h, "/oauth/device_authorization", url.Values{
		"client_id": {"device-client"},
	})

	assert.Equal(t, http.StatusUnauthorized, rr.Code,
		"a client with a registered secret must authenticate")
	assert.Contains(t, rr.Body.String(), "invalid_client")
}

func TestDeviceClaim_ConfidentialClient_RequiresSecret(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)

	svc.EXPECT().GetClient("device-client").Return(confidentialDeviceClient(), nil).AnyTimes()

	h := newDeviceRouter(svc, deviceSvc, nil)
	rr := postForm(t, h, "/oauth/device/claim", url.Values{
		"client_id":  {"device-client"},
		"claim_code": {"ABCD-1234-EFGH"},
	})

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_client")
}

// Control: a public client (no registered secret) still works with client_id
// alone. Screenless devices that cannot keep a secret are the whole point of
// the device grant.
func TestDeviceAuthorization_PublicClient_NoSecretRequired(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)

	public := confidentialDeviceClient()
	public.SecretHash = ""
	svc.EXPECT().GetClient("device-client").Return(public, nil).AnyTimes()
	deviceSvc.EXPECT().
		IssueDeviceAuthorization("device-client", "", gomock.Any()).
		Return(&service.DeviceAuthorizationResult{
			DeviceCode:      "raw-device",
			UserCode:        "ABCD-EFGH",
			VerificationURI: "https://id.example.com/device",
			ExpiresIn:       600,
			Interval:        5,
		}, nil)

	h := newDeviceRouter(svc, deviceSvc, nil)
	rr := postForm(t, h, "/oauth/device_authorization", url.Values{
		"client_id": {"device-client"},
	})
	require.Equal(t, http.StatusOK, rr.Code)
}
