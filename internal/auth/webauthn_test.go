package auth_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
)

func TestWebAuthnUser_Interface(t *testing.T) {
	user := &domain.User{
		ID:          "user-123",
		Username:    "alice",
		DisplayName: "Alice Smith",
	}

	waUser := &auth.WebAuthnUser{
		User: user,
	}

	assert.Equal(t, []byte("user-123"), waUser.WebAuthnID())
	assert.Equal(t, "alice", waUser.WebAuthnName())
	assert.Equal(t, "Alice Smith", waUser.WebAuthnDisplayName())
	assert.Empty(t, waUser.WebAuthnCredentials())
}

func TestDomainCredentialToWebAuthn(t *testing.T) {
	cred := &domain.WebAuthnCredential{
		ID:              "cred-1",
		CredentialID:    []byte("raw-cred-id"),
		PublicKey:       []byte("cose-key"),
		AttestationType: "none",
		AAGUID:          []byte("0123456789abcdef"),
		SignCount:       42,
		Transports:      []string{"internal", "hybrid"},
	}

	waCred := auth.DomainCredentialToWebAuthn(cred)

	assert.Equal(t, []byte("raw-cred-id"), waCred.ID)
	assert.Equal(t, []byte("cose-key"), waCred.PublicKey)
	assert.Equal(t, "none", waCred.AttestationType)
	assert.Equal(t, uint32(42), waCred.Authenticator.SignCount)
	assert.Len(t, waCred.Transport, 2)
}

func TestDomainCredentialsToWebAuthn(t *testing.T) {
	creds := []*domain.WebAuthnCredential{
		{CredentialID: []byte("a"), PublicKey: []byte("ka"), AttestationType: "none"},
		{CredentialID: []byte("b"), PublicKey: []byte("kb"), AttestationType: "packed"},
	}

	result := auth.DomainCredentialsToWebAuthn(creds)
	assert.Len(t, result, 2)
	assert.Equal(t, []byte("a"), result[0].ID)
	assert.Equal(t, []byte("b"), result[1].ID)
}

func TestDomainCredentialsToWebAuthn_Empty(t *testing.T) {
	result := auth.DomainCredentialsToWebAuthn(nil)
	assert.Empty(t, result)
}

func TestNewWebAuthn_Success(t *testing.T) {
	wa, err := auth.NewWebAuthn("localhost", "Test Service", []string{"http://localhost:8181"})
	require.NoError(t, err)
	assert.NotNil(t, wa)
}

func TestNewWebAuthn_ValidWithOrigins(t *testing.T) {
	wa, err := auth.NewWebAuthn("example.com", "Example", []string{"https://id.example.com", "https://example.com"})
	require.NoError(t, err)
	assert.NotNil(t, wa)
}
