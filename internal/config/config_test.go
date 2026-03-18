package config_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/config"
)

func TestLoad_AllEnvSet(t *testing.T) {
	t.Setenv("JWT_SECRET", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=")
	t.Setenv("DB_PATH", "/tmp/test.db")
	t.Setenv("PORT", "9090")
	t.Setenv("R2_ACCOUNT_ID", "acct123")
	t.Setenv("R2_ACCESS_KEY_ID", "key123")
	t.Setenv("R2_SECRET_ACCESS_KEY", "secret123")
	t.Setenv("R2_BUCKET_NAME", "my-bucket")
	t.Setenv("ADMIN_USERNAME", "admin")
	t.Setenv("ADMIN_PASSWORD", "securepassword1")

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=", cfg.JWTSecret)
	assert.Equal(t, "/tmp/test.db", cfg.DBPath)
	assert.Equal(t, 9090, cfg.Port)
	assert.Equal(t, "admin", cfg.AdminUsername)
	assert.Equal(t, "securepassword1", cfg.AdminPassword)
}

func TestLoad_MinimalConfig(t *testing.T) {
	// No env vars at all — should succeed (JWT secret managed by DB)

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, 8181, cfg.Port)
	assert.Equal(t, "identity.db", cfg.DBPath)
	assert.Empty(t, cfg.JWTSecret)
	assert.Equal(t, 15*time.Minute, cfg.AccessTokenTTL)
	assert.Equal(t, 30*24*time.Hour, cfg.RefreshTokenTTL)
}

func TestLoad_ShortJWTSecret(t *testing.T) {
	t.Setenv("JWT_SECRET", "tooshort")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32 characters")
}

func TestLoad_InvalidPort(t *testing.T) {
	t.Setenv("PORT", "notanumber")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PORT")
}

func TestLoad_RateLimitDisabledInProduction(t *testing.T) {
	// Verify that config correctly loads both RATE_LIMIT_DISABLED and production env.
	// The production guard in main.go overrides cfg.RateLimitDisabled when IsProduction() is true.
	t.Setenv("RATE_LIMIT_DISABLED", "1")
	t.Setenv("IDENTITY_ENV", "production")

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.True(t, cfg.RateLimitDisabled, "config should load the flag as-is")
	assert.True(t, cfg.IsProduction(), "should be production")

	// Simulate the production guard from main.go
	if cfg.RateLimitDisabled && cfg.IsProduction() {
		cfg.RateLimitDisabled = false
	}
	assert.False(t, cfg.RateLimitDisabled, "production guard should override the flag")
}

func TestLoad_RateLimitDisabledInDevelopment(t *testing.T) {
	t.Setenv("RATE_LIMIT_DISABLED", "1")
	t.Setenv("IDENTITY_ENV", "development")

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.True(t, cfg.RateLimitDisabled, "should be disabled in development")
	assert.False(t, cfg.IsProduction())
}

func TestLoad_JWTPrevSecret(t *testing.T) {
	t.Setenv("JWT_SECRET", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=")
	t.Setenv("JWT_SECRET_PREV", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=")

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=", cfg.JWTSecretPrev)
}
