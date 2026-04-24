package oauth_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/handler/oauth"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

func mustHash(secret string) string {
	h, err := bcrypt.GenerateFromPassword([]byte(secret), 4)
	if err != nil {
		panic(err)
	}
	return string(h)
}

func TestClientCredentials_ValidBasicAuth(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	hash := mustHash("secret123")
	client := &domain.OAuthClient{
		ID:                      "my-service",
		Name:                    "My Service",
		SecretHash:              hash,
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"read:users"},
		TokenEndpointAuthMethod: "client_secret_basic",
		Audience:                "https://api.example.com",
	}

	svc.EXPECT().GetClient("my-service").Return(client, nil)
	svc.EXPECT().IssueClientCredentials(gomock.Any(), gomock.Eq(""), gomock.Any()).Return(&service.ClientCredentialsResult{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		ExpiresIn:   900,
		Scope:       "read:users",
	}, nil)

	h := oauth.NewRouter(svc, "", nil, nil, nil, nil, "", "")

	form := url.Values{"grant_type": {"client_credentials"}}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-service:secret123")))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "test-token", body["access_token"])
	assert.Equal(t, "Bearer", body["token_type"])
	assert.Equal(t, "read:users", body["scope"])
	// No refresh_token
	_, hasRefresh := body["refresh_token"]
	assert.False(t, hasRefresh)
}

func TestClientCredentials_FormPost(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	hash := mustHash("secret123")
	client := &domain.OAuthClient{
		ID:                      "my-service",
		SecretHash:              hash,
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"read:users"},
		TokenEndpointAuthMethod: "client_secret_post",
		Audience:                "https://api.example.com",
	}

	svc.EXPECT().GetClient("my-service").Return(client, nil)
	svc.EXPECT().IssueClientCredentials(gomock.Any(), gomock.Eq("read:users"), gomock.Any()).Return(&service.ClientCredentialsResult{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		ExpiresIn:   900,
		Scope:       "read:users",
	}, nil)

	h := oauth.NewRouter(svc, "", nil, nil, nil, nil, "", "")

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"my-service"},
		"client_secret": {"secret123"},
		"scope":         {"read:users"},
	}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestClientCredentials_NoAuth(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	h := oauth.NewRouter(svc, "", nil, nil, nil, nil, "", "")

	form := url.Values{"grant_type": {"client_credentials"}}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestClientCredentials_UnknownClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	svc.EXPECT().GetClient("unknown").Return(nil, service.ErrUnknownClient)

	h := oauth.NewRouter(svc, "", nil, nil, nil, nil, "", "")

	form := url.Values{"grant_type": {"client_credentials"}}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("unknown:secret")))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestClientCredentials_BadSecret(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	hash := mustHash("correct-secret")
	client := &domain.OAuthClient{
		ID:                      "my-service",
		SecretHash:              hash,
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}

	svc.EXPECT().GetClient("my-service").Return(client, nil)

	h := oauth.NewRouter(svc, "", nil, nil, nil, nil, "", "")

	form := url.Values{"grant_type": {"client_credentials"}}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-service:wrong-secret")))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestClientCredentials_WrongGrantType(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	hash := mustHash("secret")
	client := &domain.OAuthClient{
		ID:                      "my-service",
		SecretHash:              hash,
		GrantTypes:              []string{"authorization_code"}, // not client_credentials
		TokenEndpointAuthMethod: "client_secret_basic",
		Audience:                "https://api.example.com",
	}

	svc.EXPECT().GetClient("my-service").Return(client, nil)
	svc.EXPECT().IssueClientCredentials(gomock.Any(), gomock.Eq(""), gomock.Any()).Return(nil, service.ErrUnauthorizedClient)

	h := oauth.NewRouter(svc, "", nil, nil, nil, nil, "", "")

	form := url.Values{"grant_type": {"client_credentials"}}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-service:secret")))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestClientCredentials_InvalidScope(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	hash := mustHash("secret")
	client := &domain.OAuthClient{
		ID:                      "my-service",
		SecretHash:              hash,
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"read:users"},
		TokenEndpointAuthMethod: "client_secret_basic",
		Audience:                "https://api.example.com",
	}

	svc.EXPECT().GetClient("my-service").Return(client, nil)
	svc.EXPECT().IssueClientCredentials(gomock.Any(), gomock.Eq("write:users"), gomock.Any()).Return(nil, service.ErrInvalidScope)

	h := oauth.NewRouter(svc, "", nil, nil, nil, nil, "", "")

	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"write:users"}}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-service:secret")))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var body map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "invalid_scope", body["error"])
}

func TestClientCredentials_AuthMethodMismatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	hash := mustHash("secret")
	client := &domain.OAuthClient{
		ID:                      "my-service",
		SecretHash:              hash,
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic", // expects Basic, but we send form
	}

	svc.EXPECT().GetClient("my-service").Return(client, nil)

	h := oauth.NewRouter(svc, "", nil, nil, nil, nil, "", "")

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"my-service"},
		"client_secret": {"secret"},
	}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestClientCredentials_PublicClient_Rejected(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	client := &domain.OAuthClient{
		ID:                      "public-app",
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "none",
	}

	svc.EXPECT().GetClient("public-app").Return(client, nil)

	h := oauth.NewRouter(svc, "", nil, nil, nil, nil, "", "")

	form := url.Values{"grant_type": {"client_credentials"}}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("public-app:anything")))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestClientCredentials_SecretRotation(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	oldHash := mustHash("old-secret")
	newHash := mustHash("new-secret")
	client := &domain.OAuthClient{
		ID:                      "my-service",
		SecretHash:              newHash,
		SecretHashPrev:          oldHash,
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"read:users"},
		TokenEndpointAuthMethod: "client_secret_basic",
		Audience:                "https://api.example.com",
	}

	// Old secret should still work
	svc.EXPECT().GetClient("my-service").Return(client, nil)
	svc.EXPECT().IssueClientCredentials(gomock.Any(), gomock.Any(), gomock.Any()).Return(&service.ClientCredentialsResult{
		AccessToken: "token",
		TokenType:   "Bearer",
		ExpiresIn:   900,
		Scope:       "read:users",
	}, nil)

	h := oauth.NewRouter(svc, "", nil, nil, nil, nil, "", "")

	form := url.Values{"grant_type": {"client_credentials"}}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("my-service:old-secret")))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestDiscoveryEndpoint(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	key, err := auth.GenerateKey()
	require.NoError(t, err)
	issuer, err := auth.NewTokenIssuer(key, nil, "https://id.example.com", 15*time.Minute)
	require.NoError(t, err)

	h := oauth.NewRouter(svc, "", issuer, nil, nil, nil, "", "")

	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	req.Host = "evil.attacker.com" // Host header must be ignored
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	// Discovery document must use the configured issuer, not the Host header.
	assert.Equal(t, "https://id.example.com", body["issuer"])
	assert.Contains(t, body["token_endpoint"], "https://id.example.com")
	assert.NotContains(t, body["token_endpoint"], "evil.attacker.com")
	assert.Contains(t, body["jwks_uri"], "/.well-known/jwks.json")

	grantTypes, ok := body["grant_types_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, grantTypes, "client_credentials")
	assert.Contains(t, grantTypes, "authorization_code")
}

// --- N4: Introspect endpoint must not disclose service tokens to other clients ---

func newIntrospectTestIssuer(t *testing.T) *auth.TokenIssuer {
	t.Helper()
	key, err := auth.GenerateKey()
	require.NoError(t, err)
	ti, err := auth.NewTokenIssuer(key, nil, "https://id.example.com", 15*time.Minute)
	require.NoError(t, err)
	return ti
}

func TestIntrospect_ServiceToken_WrongClient_ReturnsInactive(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	issuer := newIntrospectTestIssuer(t)

	// client-A mints a service token
	serviceToken, err := issuer.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "client-a",
		Audience: "https://api.example.com",
		Scope:    "read:users",
	}, 15*time.Minute)
	require.NoError(t, err)

	// client-B authenticates to the introspect endpoint
	hashB := mustHash("secret-b")
	clientB := &domain.OAuthClient{
		ID:                      "client-b",
		SecretHash:              hashB,
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	svc.EXPECT().GetClient("client-b").Return(clientB, nil)

	h := oauth.NewRouter(svc, "", issuer, nil, nil, nil, "", "")

	form := url.Values{"token": {serviceToken}}
	req := httptest.NewRequest("POST", "/oauth/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("client-b:secret-b")))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, false, body["active"], "client-B must not see client-A's token as active")
	_, hasClientID := body["client_id"]
	assert.False(t, hasClientID, "client-B must not receive client-A's claims")
}

func TestIntrospect_ServiceToken_OwningClient_ReturnsActive(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	issuer := newIntrospectTestIssuer(t)

	serviceToken, err := issuer.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "client-a",
		Audience: "https://api.example.com",
		Scope:    "read:users",
	}, 15*time.Minute)
	require.NoError(t, err)

	hashA := mustHash("secret-a")
	clientA := &domain.OAuthClient{
		ID:                      "client-a",
		SecretHash:              hashA,
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	svc.EXPECT().GetClient("client-a").Return(clientA, nil)

	h := oauth.NewRouter(svc, "", issuer, nil, nil, nil, "", "")

	form := url.Values{"token": {serviceToken}}
	req := httptest.NewRequest("POST", "/oauth/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("client-a:secret-a")))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, true, body["active"])
	assert.Equal(t, "client-a", body["client_id"])
	assert.Equal(t, "read:users", body["scope"])
}

func TestIntrospect_ServiceToken_IncludesAudClaim(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	issuer := newIntrospectTestIssuer(t)

	serviceToken, err := issuer.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "client-a",
		Audience: "https://api.example.com",
		Scope:    "read:users",
	}, 15*time.Minute)
	require.NoError(t, err)

	hashA := mustHash("secret-a")
	clientA := &domain.OAuthClient{
		ID:                      "client-a",
		SecretHash:              hashA,
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	svc.EXPECT().GetClient("client-a").Return(clientA, nil)

	h := oauth.NewRouter(svc, "", issuer, nil, nil, nil, "", "")

	form := url.Values{"token": {serviceToken}}
	req := httptest.NewRequest("POST", "/oauth/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("client-a:secret-a")))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, true, body["active"])
	assert.Equal(t, "https://api.example.com", body["aud"], "introspect response must include aud claim matching the token's audience")
}
