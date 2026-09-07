package cli

// restore_test.go covers the WP3 (GHSA-c9v9-fw88-f6qw) item on --restore-backup:
// an explicitly supplied key was checked against the service name but not the
// environment prefix, so a production backup could be restored into a
// development database, or the reverse. Backup keys are laid out as
// {env}/backups/{service}/..., and both segments are part of "is this the right
// database".

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRestoreKey(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		service string
		key     string
		wantErr string
	}{
		{
			name: "matching env and service", env: "production", service: "identity",
			key: "production/backups/identity/2026/09/07/identity-2026-09-07T03:00:00Z.sqlite3",
		},
		{
			name: "legacy layout without the service segment", env: "production", service: "identity",
			key: "production/backups/2026/09/07/identity-2026-09-07T03:00:00Z.sqlite3",
		},
		{
			name: "wrong environment", env: "development", service: "identity",
			key:     "production/backups/identity/2026/09/07/identity-2026-09-07T03:00:00Z.sqlite3",
			wantErr: "environment",
		},
		{
			name: "wrong service", env: "production", service: "identity",
			key:     "production/backups/config/2026/09/07/config-2026-09-07T03:00:00Z.sqlite3",
			wantErr: "service",
		},
		{
			name: "path traversal out of the environment prefix", env: "development", service: "identity",
			key:     "development/backups/../../production/backups/identity/identity-x.sqlite3",
			wantErr: "environment",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRestoreKey(tc.key, tc.env, tc.service)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.True(t, strings.Contains(err.Error(), tc.wantErr),
				"error %q should mention %q", err.Error(), tc.wantErr)
		})
	}
}
