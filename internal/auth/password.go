package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	MinPasswordLength = 8

	// MaxPasswordLength is bcrypt's hard limit. Passwords are measured in
	// bytes, not runes.
	MaxPasswordLength = 72
)

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
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	// bcrypt refuses anything past 72 bytes. Without this check the library
	// error propagated as a 500, telling a user who chose a long passphrase —
	// or whose password manager generated one — that the server had broken.
	// The limit is in bytes, so multi-byte characters count for more than one.
	if len(password) > MaxPasswordLength {
		return fmt.Errorf("password must be at most %d bytes", MaxPasswordLength)
	}
	return nil
}
