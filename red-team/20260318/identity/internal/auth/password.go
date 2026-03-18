package auth

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const MinPasswordLength = 8

// HashPassword hashes a plaintext password with bcrypt at the given cost.
func HashPassword(password string, cost int) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

// CheckPassword compares a plaintext password against a bcrypt hash.
// Returns an error if they do not match.
func CheckPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// ValidatePasswordStrength returns an error if the password does not meet
// minimum strength requirements.
func ValidatePasswordStrength(password string) error {
	if len(password) < MinPasswordLength {
		return errors.New(fmt.Sprintf("password must be at least %d characters", MinPasswordLength))
	}
	return nil
}
