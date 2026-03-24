package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/auth"
)

func TestJWKSHandler_Response(t *testing.T) {
	key, err := auth.GenerateKey()
	require.NoError(t, err)
	issuer, err := auth.NewTokenIssuer(key, nil, "identity.test", 15*time.Minute)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	jwksHandler(issuer).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.Equal(t, "public, max-age=3600", rr.Header().Get("Cache-Control"))

	var jwks auth.JWKSet
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&jwks))
	require.Len(t, jwks.Keys, 1)
	k := jwks.Keys[0]
	assert.Equal(t, "EC", k.Kty)
	assert.Equal(t, "sig", k.Use)
	assert.Equal(t, "ES256", k.Alg)
	assert.Equal(t, "P-256", k.Crv)
	assert.NotEmpty(t, k.Kid)
	assert.NotEmpty(t, k.X)
	assert.NotEmpty(t, k.Y)
}

func TestJWKSHandler_WithPrevKey(t *testing.T) {
	oldKey, err := auth.GenerateKey()
	require.NoError(t, err)
	newKey, err := auth.GenerateKey()
	require.NoError(t, err)
	issuer, err := auth.NewTokenIssuer(newKey, oldKey, "identity.test", 15*time.Minute)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	jwksHandler(issuer).ServeHTTP(rr, req)

	var jwks auth.JWKSet
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&jwks))
	assert.Len(t, jwks.Keys, 2, "should include both current and previous key during rotation")
}
