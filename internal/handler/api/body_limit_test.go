package api_test

// body_limit_test.go covers WP7 (GHSA-g6q8-f4fr-r79h): the JSON endpoints read
// request bodies with no size limit.
//
// /api/v1/auth/login and /auth/refresh are unauthenticated, so anyone can post
// to them. The handlers io.ReadAll the body before deciding anything about it,
// so a single large POST is a memory allocation of that size, and a handful of
// concurrent ones is the process. Nothing about a login needs more than a few
// hundred bytes.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/handler/api"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

// oversizedJSON builds a syntactically valid JSON body of at least n bytes.
func oversizedJSON(n int) string {
	return `{"username":"a","password":"` + strings.Repeat("x", n) + `"}`
}

func TestUnauthenticatedEndpoints_RejectOversizedBodies(t *testing.T) {
	issuer := newURLIssuer(t, "https://id.example.com")
	h := api.NewRouter(issuer, nil, nil, nil, "")

	// 8 MB — far past anything a credential payload needs.
	body := oversizedJSON(8 << 20)

	for _, path := range []string{"/api/v1/auth/login", "/api/v1/auth/refresh"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code,
				"an unbounded body on an unauthenticated endpoint is free memory pressure")
			assert.Equal(t, "request_too_large", parseErrorCode(t, rr))
		})
	}
}

// A body of ordinary size reaches the handler untouched.
func TestUnauthenticatedEndpoints_AcceptNormalBodies(t *testing.T) {
	ctrl := gomock.NewController(t)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	issuer := newURLIssuer(t, "https://id.example.com")

	authSvc.EXPECT().
		Login("alice", "correct horse battery staple", gomock.Any(), gomock.Any()).
		Return(&service.LoginResult{AccessToken: "a", RefreshToken: "r", TokenType: "Bearer", ExpiresIn: 900}, nil)

	h := api.NewRouter(issuer, authSvc, nil, nil, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		strings.NewReader(`{"username":"alice","password":"correct horse battery staple"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code,
		"an ordinary login must pass through the body limit untouched")
}
