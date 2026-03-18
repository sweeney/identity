package auth_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/auth"
)

func TestHashPassword_ProducesHash(t *testing.T) {
	hash, err := auth.HashPassword("mysecretpassword", 4) // cost 4 for fast tests
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, "mysecretpassword", hash)
}

func TestHashPassword_DifferentCallsProduceDifferentHashes(t *testing.T) {
	h1, err := auth.HashPassword("password", 4)
	require.NoError(t, err)
	h2, err := auth.HashPassword("password", 4)
	require.NoError(t, err)
	// bcrypt uses random salt — same password hashes differently each time
	assert.NotEqual(t, h1, h2)
}

func TestCheckPassword_CorrectPassword(t *testing.T) {
	hash, err := auth.HashPassword("correctpassword", 4)
	require.NoError(t, err)

	err = auth.CheckPassword("correctpassword", hash)
	assert.NoError(t, err)
}

func TestCheckPassword_WrongPassword(t *testing.T) {
	hash, err := auth.HashPassword("correctpassword", 4)
	require.NoError(t, err)

	err = auth.CheckPassword("wrongpassword", hash)
	assert.Error(t, err)
}

func TestCheckPassword_EmptyPassword(t *testing.T) {
	hash, err := auth.HashPassword("correctpassword", 4)
	require.NoError(t, err)

	err = auth.CheckPassword("", hash)
	assert.Error(t, err)
}

func TestValidatePasswordStrength_TooShort(t *testing.T) {
	err := auth.ValidatePasswordStrength("short")
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("%d", auth.MinPasswordLength))
}

func TestValidatePasswordStrength_Sufficient(t *testing.T) {
	err := auth.ValidatePasswordStrength("longenoughpassword")
	assert.NoError(t, err)
}

func TestValidatePasswordStrength_ExactMinimum(t *testing.T) {
	err := auth.ValidatePasswordStrength("exactly8c")
	assert.NoError(t, err)
}
