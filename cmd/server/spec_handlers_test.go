package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSpecYAMLHandler_CORSAndContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	rr := httptest.NewRecorder()

	specYAMLHandler(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "*", rr.Header().Get("Access-Control-Allow-Origin"),
		"spec must be fetchable by browser-based viewers (Swagger UI, Stoplight)")
	assert.Equal(t, "application/yaml", rr.Header().Get("Content-Type"))
	assert.NotEmpty(t, rr.Body.Bytes())
}

func TestSpecJSONHandler_CORSAndContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rr := httptest.NewRecorder()

	specJSONHandler(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "*", rr.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.NotEmpty(t, rr.Body.Bytes())
}
