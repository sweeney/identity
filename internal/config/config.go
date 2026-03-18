package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment represents the deployment environment.
type Environment string

const (
	EnvDevelopment Environment = "development"
	EnvProduction  Environment = "production"
)

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	// Environment
	Env Environment

	// Server
	Port int

	// Database
	DBPath string

	// JWT
	JWTSecret     string
	JWTSecretPrev string // Optional: set during zero-downtime key rotation
	JWTIssuer     string

	// Token lifetimes
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration

	// Password hashing
	BCryptCost int

	// Initial admin credentials (optional — only used on first run to seed the DB)
	AdminUsername string
	AdminPassword string

	// Site name: human-readable name shown in UI (nav, OAuth login, etc.)
	SiteName string

	// Proxy trust: "cloudflare" trusts CF-Connecting-IP header, "" trusts nothing
	TrustProxy string

	// CORS
	CORSOrigins []string

	// Rate limiting
	RateLimitDisabled bool

	// WebAuthn / Passkeys
	WebAuthnRPID          string   // Relying Party ID (domain, e.g. "swee.net")
	WebAuthnRPDisplayName string   // Human-readable RP name shown in browser prompts
	WebAuthnRPOrigins     []string // Allowed origins (e.g. "https://id.swee.net")

	// Cloudflare R2 (S3-compatible backup storage)
	R2AccountID       string
	R2AccessKeyID     string
	R2SecretAccessKey string
	R2BucketName      string
}

// Load reads configuration from environment variables and returns a validated Config.
// Returns an error if any required variable is missing or any value is invalid.
func Load() (*Config, error) {
	cfg := &Config{
		// Defaults
		Port:            8181,
		DBPath:          "identity.db",
		JWTIssuer:       "identity.home",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
		BCryptCost:      12,
	}

	// Environment: defaults to development
	switch Environment(os.Getenv("IDENTITY_ENV")) {
	case EnvProduction:
		cfg.Env = EnvProduction
	default:
		cfg.Env = EnvDevelopment
	}

	var errs []error

	// Optional: JWT_SECRET (overrides DB-managed secret; minimum 32 characters if set)
	cfg.JWTSecret = os.Getenv("JWT_SECRET")
	if cfg.JWTSecret != "" && len(cfg.JWTSecret) < 32 {
		errs = append(errs, errors.New("JWT_SECRET must be at least 32 characters"))
	}

	// Optional: JWT_SECRET_PREV (for zero-downtime rotation)
	cfg.JWTSecretPrev = os.Getenv("JWT_SECRET_PREV")

	// Optional: initial admin credentials (only used for first-run seed)
	cfg.AdminUsername = os.Getenv("ADMIN_USERNAME")
	cfg.AdminPassword = os.Getenv("ADMIN_PASSWORD")

	// Optional: PORT
	if portStr := os.Getenv("PORT"); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			errs = append(errs, fmt.Errorf("PORT must be a valid integer, got %q", portStr))
		} else {
			cfg.Port = port
		}
	}

	// Optional overrides
	if v := os.Getenv("DB_PATH"); v != "" {
		cfg.DBPath = v
	}

	// SITE_NAME: human-readable name for the identity service (shown in UI)
	cfg.SiteName = os.Getenv("SITE_NAME")
	if cfg.SiteName == "" {
		cfg.SiteName = "Identity"
	}

	// TRUST_PROXY: "cloudflare" trusts CF-Connecting-IP, anything else means use RemoteAddr
	if v := os.Getenv("TRUST_PROXY"); v == "cloudflare" {
		cfg.TrustProxy = "cloudflare"
	}

	// CORS_ORIGINS: comma-separated list of allowed origins (e.g. "https://app.example.com,https://other.example.com")
	if v := os.Getenv("CORS_ORIGINS"); v != "" {
		for _, o := range strings.Split(v, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				cfg.CORSOrigins = append(cfg.CORSOrigins, o)
			}
		}
	}

	// RATE_LIMIT_DISABLED: disable rate limiting (useful for dev/testing)
	if v := os.Getenv("RATE_LIMIT_DISABLED"); v == "1" || v == "true" {
		cfg.RateLimitDisabled = true
	}

	// WebAuthn: auto-configure from environment or derive from IDENTITY_ENV
	cfg.WebAuthnRPID = os.Getenv("WEBAUTHN_RP_ID")
	cfg.WebAuthnRPDisplayName = os.Getenv("WEBAUTHN_RP_DISPLAY_NAME")
	if cfg.WebAuthnRPDisplayName == "" {
		cfg.WebAuthnRPDisplayName = "Identity Service"
	}
	if v := os.Getenv("WEBAUTHN_RP_ORIGINS"); v != "" {
		for _, o := range strings.Split(v, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				cfg.WebAuthnRPOrigins = append(cfg.WebAuthnRPOrigins, o)
			}
		}
	}
	// In development, default to localhost if no RP ID is set.
	if cfg.WebAuthnRPID == "" && cfg.Env == EnvDevelopment {
		cfg.WebAuthnRPID = "localhost"
		if len(cfg.WebAuthnRPOrigins) == 0 {
			cfg.WebAuthnRPOrigins = []string{fmt.Sprintf("http://localhost:%d", cfg.Port)}
		}
	}
	// Derive origin from RP ID if not explicitly set
	if cfg.WebAuthnRPID != "" && len(cfg.WebAuthnRPOrigins) == 0 {
		cfg.WebAuthnRPOrigins = []string{"https://" + cfg.WebAuthnRPID}
	}
	// Merge CORS origins into WebAuthn origins — if you trust an origin for
	// CORS, it should also be allowed to perform WebAuthn ceremonies. This
	// avoids hardcoding port lists and keeps configuration in one place.
	if cfg.WebAuthnRPID != "" && len(cfg.CORSOrigins) > 0 {
		existing := make(map[string]bool, len(cfg.WebAuthnRPOrigins))
		for _, o := range cfg.WebAuthnRPOrigins {
			existing[o] = true
		}
		for _, o := range cfg.CORSOrigins {
			if !existing[o] {
				cfg.WebAuthnRPOrigins = append(cfg.WebAuthnRPOrigins, o)
				existing[o] = true
			}
		}
	}

	// R2 config — optional at load time (service runs without backup if unset, logs a warning)
	cfg.R2AccountID = os.Getenv("R2_ACCOUNT_ID")
	cfg.R2AccessKeyID = os.Getenv("R2_ACCESS_KEY_ID")
	cfg.R2SecretAccessKey = os.Getenv("R2_SECRET_ACCESS_KEY")
	cfg.R2BucketName = os.Getenv("R2_BUCKET_NAME")

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return cfg, nil
}

// IsProduction returns true if running in production mode.
func (c *Config) IsProduction() bool {
	return c.Env == EnvProduction
}

// WebAuthnConfigured reports whether WebAuthn/passkeys are configured.
func (c *Config) WebAuthnConfigured() bool {
	return c.WebAuthnRPID != ""
}

// R2Configured reports whether all R2 credentials are present.
func (c *Config) R2Configured() bool {
	return c.R2AccountID != "" &&
		c.R2AccessKeyID != "" &&
		c.R2SecretAccessKey != "" &&
		c.R2BucketName != ""
}
