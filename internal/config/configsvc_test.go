package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/config"
)

// clearConfigSvcEnv wipes every env var LoadConfigSvc consults so a test
// starts from a clean slate regardless of what the surrounding shell sets.
// t.Setenv registers restoration for each var so the host environment
// is unchanged after the test.
func clearConfigSvcEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"IDENTITY_ENV", "PORT", "DB_PATH",
		"IDENTITY_ISSUER_URL", "IDENTITY_ISSUER",
		"JWKS_CACHE_TTL", "BACKUP_MIN_INTERVAL",
		"TRUST_PROXY", "CORS_ORIGINS", "RATE_LIMIT_DISABLED",
		"R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET_NAME",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadConfigSvc_Defaults(t *testing.T) {
	clearConfigSvcEnv(t)

	cfg, err := config.LoadConfigSvc()
	require.NoError(t, err)

	assert.Equal(t, config.EnvDevelopment, cfg.Env)
	assert.Equal(t, 8282, cfg.Port)
	assert.Equal(t, "config.db", cfg.DBPath)
	assert.Equal(t, "http://localhost:8181", cfg.IdentityIssuerURL)
	assert.Equal(t, "http://localhost:8181", cfg.IdentityIssuer,
		"IdentityIssuer defaults to IdentityIssuerURL when unset")
	assert.Equal(t, time.Duration(0), cfg.JWKSCacheTTL,
		"JWKSCacheTTL left at zero so the verifier picks its built-in default")
	assert.Equal(t, 30*time.Second, cfg.BackupMinInterval)
	assert.Equal(t, "", cfg.TrustProxy)
	assert.Empty(t, cfg.CORSOrigins)
	assert.False(t, cfg.RateLimitDisabled)
	assert.False(t, cfg.IsProduction())
	assert.False(t, cfg.R2Configured())
}

func TestLoadConfigSvc_ExplicitOverrides(t *testing.T) {
	clearConfigSvcEnv(t)
	t.Setenv("PORT", "9090")
	t.Setenv("DB_PATH", "/var/lib/custom/config.db")
	t.Setenv("IDENTITY_ISSUER_URL", "http://id.local")
	t.Setenv("IDENTITY_ISSUER", "custom-iss")
	t.Setenv("JWKS_CACHE_TTL", "7m")
	t.Setenv("BACKUP_MIN_INTERVAL", "2s")
	t.Setenv("TRUST_PROXY", "cloudflare")
	t.Setenv("CORS_ORIGINS", "https://a.example.com, https://b.example.com ,, ")
	t.Setenv("RATE_LIMIT_DISABLED", "1")

	cfg, err := config.LoadConfigSvc()
	require.NoError(t, err)

	assert.Equal(t, 9090, cfg.Port)
	assert.Equal(t, "/var/lib/custom/config.db", cfg.DBPath)
	assert.Equal(t, "http://id.local", cfg.IdentityIssuerURL)
	assert.Equal(t, "custom-iss", cfg.IdentityIssuer,
		"IDENTITY_ISSUER overrides the default-to-IdentityIssuerURL behaviour")
	assert.Equal(t, 7*time.Minute, cfg.JWKSCacheTTL)
	assert.Equal(t, 2*time.Second, cfg.BackupMinInterval)
	assert.Equal(t, "cloudflare", cfg.TrustProxy)
	assert.Equal(t, []string{"https://a.example.com", "https://b.example.com"}, cfg.CORSOrigins,
		"CORS_ORIGINS should trim whitespace and drop empty entries")
	assert.True(t, cfg.RateLimitDisabled)
}

func TestLoadConfigSvc_RateLimitDisabled_TrueVariant(t *testing.T) {
	clearConfigSvcEnv(t)
	t.Setenv("RATE_LIMIT_DISABLED", "true")

	cfg, err := config.LoadConfigSvc()
	require.NoError(t, err)
	assert.True(t, cfg.RateLimitDisabled)
}

func TestLoadConfigSvc_TrustProxy_UnknownValueIgnored(t *testing.T) {
	clearConfigSvcEnv(t)
	t.Setenv("TRUST_PROXY", "some-other-proxy")

	cfg, err := config.LoadConfigSvc()
	require.NoError(t, err)
	assert.Equal(t, "", cfg.TrustProxy,
		"only 'cloudflare' is recognised; any other value is treated as unset")
}

func TestLoadConfigSvc_Production_RequiresIssuerURL(t *testing.T) {
	clearConfigSvcEnv(t)
	t.Setenv("IDENTITY_ENV", "production")

	_, err := config.LoadConfigSvc()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "IDENTITY_ISSUER_URL is required in production")
}

func TestLoadConfigSvc_Production_RejectsNonHTTPSIssuer(t *testing.T) {
	clearConfigSvcEnv(t)
	t.Setenv("IDENTITY_ENV", "production")
	t.Setenv("IDENTITY_ISSUER_URL", "http://id.example.com")

	_, err := config.LoadConfigSvc()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https://",
		"production mode must reject plain-http identity URLs")
}

func TestLoadConfigSvc_Production_HTTPSIssuerAccepted(t *testing.T) {
	clearConfigSvcEnv(t)
	t.Setenv("IDENTITY_ENV", "production")
	t.Setenv("IDENTITY_ISSUER_URL", "https://id.example.com")

	cfg, err := config.LoadConfigSvc()
	require.NoError(t, err)
	assert.True(t, cfg.IsProduction())
	assert.Equal(t, "https://id.example.com", cfg.IdentityIssuerURL)
}

func TestLoadConfigSvc_InvalidPort(t *testing.T) {
	clearConfigSvcEnv(t)
	t.Setenv("PORT", "not-a-number")

	_, err := config.LoadConfigSvc()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PORT")
}

func TestLoadConfigSvc_InvalidDurationValues(t *testing.T) {
	cases := map[string]string{
		"JWKS_CACHE_TTL":      "JWKS_CACHE_TTL",
		"BACKUP_MIN_INTERVAL": "BACKUP_MIN_INTERVAL",
	}
	for envVar, wantSubstr := range cases {
		t.Run(envVar, func(t *testing.T) {
			clearConfigSvcEnv(t)
			t.Setenv(envVar, "not-a-duration")
			_, err := config.LoadConfigSvc()
			require.Error(t, err)
			assert.Contains(t, err.Error(), wantSubstr)
		})
	}
}

func TestLoadConfigSvc_MultipleErrors_Joined(t *testing.T) {
	clearConfigSvcEnv(t)
	t.Setenv("PORT", "not-a-number")
	t.Setenv("JWKS_CACHE_TTL", "also-broken")
	t.Setenv("BACKUP_MIN_INTERVAL", "also-broken")

	_, err := config.LoadConfigSvc()
	require.Error(t, err)
	// errors.Join preserves each underlying error; Error() newline-joins them.
	msg := err.Error()
	assert.Contains(t, msg, "PORT")
	assert.Contains(t, msg, "JWKS_CACHE_TTL")
	assert.Contains(t, msg, "BACKUP_MIN_INTERVAL")
	assert.True(t, strings.Count(msg, "\n") >= 2,
		"multiple validation failures should all surface, not just the first")
}

func TestLoadConfigSvc_R2Configured(t *testing.T) {
	clearConfigSvcEnv(t)
	t.Setenv("R2_ACCOUNT_ID", "acct")
	t.Setenv("R2_ACCESS_KEY_ID", "key")
	t.Setenv("R2_SECRET_ACCESS_KEY", "secret")
	t.Setenv("R2_BUCKET_NAME", "bucket")

	cfg, err := config.LoadConfigSvc()
	require.NoError(t, err)
	assert.True(t, cfg.R2Configured())
	assert.Equal(t, "acct", cfg.R2AccountID)
	assert.Equal(t, "key", cfg.R2AccessKeyID)
	assert.Equal(t, "secret", cfg.R2SecretAccessKey)
	assert.Equal(t, "bucket", cfg.R2BucketName)
}

func TestLoadConfigSvc_R2PartiallyConfigured_NotConfigured(t *testing.T) {
	// Any missing R2 field should flip R2Configured() to false — the whole
	// quad is required together for backups to work.
	required := []string{
		"R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID",
		"R2_SECRET_ACCESS_KEY", "R2_BUCKET_NAME",
	}
	for _, omitted := range required {
		t.Run("missing_"+omitted, func(t *testing.T) {
			clearConfigSvcEnv(t)
			for _, k := range required {
				if k != omitted {
					t.Setenv(k, "x")
				}
			}
			cfg, err := config.LoadConfigSvc()
			require.NoError(t, err)
			assert.False(t, cfg.R2Configured(),
				"R2Configured must require ALL four vars, missing %s", omitted)
		})
	}
}

func TestLoadConfigSvc_IdentityIssuerFallsBackToURL(t *testing.T) {
	clearConfigSvcEnv(t)
	t.Setenv("IDENTITY_ISSUER_URL", "http://id.local:9000")
	// IDENTITY_ISSUER not set → should fall back to IdentityIssuerURL.

	cfg, err := config.LoadConfigSvc()
	require.NoError(t, err)
	assert.Equal(t, cfg.IdentityIssuerURL, cfg.IdentityIssuer)
}
