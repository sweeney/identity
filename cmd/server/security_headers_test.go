package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// isAllowedOrigin
// ---------------------------------------------------------------------------

func TestIsAllowedOrigin_ExplicitAllowlist(t *testing.T) {
	allowed := map[string]bool{"https://app.example.com": true}
	assert.True(t, isAllowedOrigin("https://app.example.com", allowed, false))
}

func TestIsAllowedOrigin_NotInAllowlist(t *testing.T) {
	allowed := map[string]bool{"https://app.example.com": true}
	assert.False(t, isAllowedOrigin("https://evil.com", allowed, false))
}

func TestIsAllowedOrigin_DevModeEmptyAllowlistLocalhost(t *testing.T) {
	allowed := map[string]bool{}
	assert.True(t, isAllowedOrigin("http://localhost:3000", allowed, true))
}

func TestIsAllowedOrigin_DevModeEmptyAllowlistNonLocalhost(t *testing.T) {
	allowed := map[string]bool{}
	assert.False(t, isAllowedOrigin("https://evil.com", allowed, true))
}

func TestIsAllowedOrigin_DevModeNonEmptyAllowlistLocalhostNotListed(t *testing.T) {
	// Explicit list takes precedence — localhost is NOT auto-allowed.
	allowed := map[string]bool{"https://app.example.com": true}
	assert.False(t, isAllowedOrigin("http://localhost:3000", allowed, true))
}

func TestIsAllowedOrigin_ProdModeEmptyAllowlistLocalhost(t *testing.T) {
	allowed := map[string]bool{}
	assert.False(t, isAllowedOrigin("http://localhost:3000", allowed, false))
}

// ---------------------------------------------------------------------------
// securityHeaders — CORS behaviour
// ---------------------------------------------------------------------------

// dummyHandler is the inner handler wrapped by securityHeaders.
var dummyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestCORS_AllowedOriginOnAPI(t *testing.T) {
	h := securityHeaders(dummyHandler, []string{"https://app.example.com"}, false)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, "https://app.example.com", rr.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_DisallowedOriginOnAPI(t *testing.T) {
	h := securityHeaders(dummyHandler, []string{"https://app.example.com"}, false)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("Origin", "https://evil.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_AllowedOriginOnOAuthToken(t *testing.T) {
	h := securityHeaders(dummyHandler, []string{"https://spa.example.com"}, false)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	req.Header.Set("Origin", "https://spa.example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, "https://spa.example.com", rr.Header().Get("Access-Control-Allow-Origin"))
	assert.NotEmpty(t, rr.Header().Get("Access-Control-Allow-Methods"))
}

func TestCORS_AdminPathNoCORS(t *testing.T) {
	h := securityHeaders(dummyHandler, []string{"https://app.example.com"}, false)

	req := httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_VaryOriginOnAPIPaths(t *testing.T) {
	h := securityHeaders(dummyHandler, nil, false)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, "Origin", rr.Header().Get("Vary"))
}

func TestCORS_PreflightAllowedOrigin(t *testing.T) {
	h := securityHeaders(dummyHandler, []string{"https://app.example.com"}, false)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/users", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)
	assert.Equal(t, "https://app.example.com", rr.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_PreflightDisallowedOrigin(t *testing.T) {
	h := securityHeaders(dummyHandler, []string{"https://app.example.com"}, false)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/users", nil)
	req.Header.Set("Origin", "https://evil.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)
	assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
}

// ---------------------------------------------------------------------------
// securityHeaders — static security headers
// ---------------------------------------------------------------------------

func TestSecurityHeaders_CSP(t *testing.T) {
	h := securityHeaders(dummyHandler, nil, false)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "default-src 'self'")
	assert.Contains(t, csp, "style-src 'self' 'unsafe-inline'")
	assert.Contains(t, csp, "script-src 'self'")
	assert.Contains(t, csp, "img-src 'self' data:")
	assert.Contains(t, csp, "frame-ancestors 'none'")
	assert.Contains(t, csp, "form-action 'self'")
}

func TestSecurityHeaders_CSPNoUnsafeInlineScript(t *testing.T) {
	h := securityHeaders(dummyHandler, nil, false)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	// script-src must not have unsafe-inline (style-src may have it for template compatibility)
	csp := rr.Header().Get("Content-Security-Policy")
	assert.NotContains(t, csp, "script-src 'self' 'unsafe-inline'")
}

func TestSecurityHeaders_XFrameOptions(t *testing.T) {
	h := securityHeaders(dummyHandler, nil, false)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, "DENY", rr.Header().Get("X-Frame-Options"))
}

func TestSecurityHeaders_XContentTypeOptions(t *testing.T) {
	h := securityHeaders(dummyHandler, nil, false)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
}

func TestSecurityHeaders_HSTS(t *testing.T) {
	h := securityHeaders(dummyHandler, nil, false)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, "max-age=63072000; includeSubDomains; preload", rr.Header().Get("Strict-Transport-Security"))
}

func TestSecurityHeaders_ReferrerPolicy(t *testing.T) {
	h := securityHeaders(dummyHandler, nil, false)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.NotEmpty(t, rr.Header().Get("Referrer-Policy"))
}
