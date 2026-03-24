package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/auth"
)

func TestECKeyRoundTrip(t *testing.T) {
	key, err := auth.GenerateKey()
	require.NoError(t, err)

	pem, err := encodeECKey(key)
	require.NoError(t, err)
	assert.NotEmpty(t, pem)
	assert.Contains(t, pem, "EC PRIVATE KEY")

	loaded, err := parseECKey(pem)
	require.NoError(t, err)

	// Keys are equal if their public coordinates match.
	assert.Equal(t, key.PublicKey.X, loaded.PublicKey.X)
	assert.Equal(t, key.PublicKey.Y, loaded.PublicKey.Y)
}

func TestParseECKey_InvalidPEM(t *testing.T) {
	_, err := parseECKey("this is not a pem block")
	require.Error(t, err)
}
