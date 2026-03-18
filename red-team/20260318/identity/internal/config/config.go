package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
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

// R2Configured reports whether all R2 credentials are present.
func (c *Config) R2Configured() bool {
	return c.R2AccountID != "" &&
		c.R2AccessKeyID != "" &&
		c.R2SecretAccessKey != "" &&
		c.R2BucketName != ""
}
