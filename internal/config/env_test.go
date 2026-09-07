package config_test

// env_test.go covers WP9 (GHSA-j5gf-rvw7-9xcm): IDENTITY_ENV was matched with a
// switch whose default arm was development, so any value that was not exactly
// "production" — a typo like "prod", "Production", "staging" — silently started
// the server in development mode. That is the mode which relaxes the production
// controls: the https:// issuer requirement, secure-cookie enforcement, and the
// localhost WebAuthn RP ID default. A one-character typo in a deployment unit
// therefore disabled them with nothing in the output to say so.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/config"
)

func TestLoad_Environment(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		set     bool
		wantEnv config.Environment
		wantErr bool
	}{
		{name: "unset defaults to development", set: false, wantEnv: config.EnvDevelopment},
		{name: "empty defaults to development", value: "", set: true, wantEnv: config.EnvDevelopment},
		{name: "development", value: "development", set: true, wantEnv: config.EnvDevelopment},
		{name: "production", value: "production", set: true, wantEnv: config.EnvProduction},

		{name: "typo is rejected", value: "prod", set: true, wantErr: true},
		{name: "wrong case is rejected", value: "Production", set: true, wantErr: true},
		{name: "unknown environment is rejected", value: "staging", set: true, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("IDENTITY_ENV", tc.value)
			}
			// Production requires an https issuer; supply one so the only
			// thing under test is the environment parse itself.
			t.Setenv("JWT_ISSUER", "https://id.example.com")

			cfg, err := config.Load()
			if tc.wantErr {
				require.Error(t, err, "an unrecognised IDENTITY_ENV must fail startup, "+
					"not silently downgrade to development")
				assert.Contains(t, err.Error(), "IDENTITY_ENV")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantEnv, cfg.Env)
		})
	}
}
