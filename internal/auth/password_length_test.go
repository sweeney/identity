package auth_test

// password_length_test.go covers a WP13 (#27) finding: bcrypt refuses passwords
// longer than 72 bytes, and nothing checked for that before hashing. The
// library error propagated as a 500 internal_error, so a user choosing a long
// passphrase — or a password manager generating one — was told the server had
// broken rather than that their password was too long.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/auth"
)

func TestValidatePasswordStrength_Length(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{name: "too short", password: "short", wantErr: true},
		{name: "ordinary", password: "correct horse battery staple"},
		{name: "exactly 72 bytes", password: strings.Repeat("a", 72)},
		{name: "73 bytes is refused", password: strings.Repeat("a", 73), wantErr: true},
		{
			// Multi-byte characters count as bytes, not runes: 24 three-byte
			// characters is 72 bytes and fits; 25 does not.
			name: "multi-byte within the limit", password: strings.Repeat("日", 24),
		},
		{name: "multi-byte over the limit", password: strings.Repeat("日", 25), wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := auth.ValidatePasswordStrength(tc.password)
			if tc.wantErr {
				require.Error(t, err,
					"a password bcrypt cannot hash must be refused as validation, not surface as a 500")
				return
			}
			assert.NoError(t, err)
		})
	}
}

// The validator's limit and what bcrypt actually accepts must not drift apart.
func TestValidatePasswordStrength_MatchesBcrypt(t *testing.T) {
	atLimit := strings.Repeat("a", 72)
	require.NoError(t, auth.ValidatePasswordStrength(atLimit))
	_, err := auth.HashPassword(atLimit, 4)
	assert.NoError(t, err, "anything the validator accepts, bcrypt must hash")
}
