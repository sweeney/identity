package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// ConfigSvcConfig holds runtime configuration for the config service, loaded
// from environment variables. It is intentionally smaller than the identity
// Config: the config service issues no tokens, stores no credentials, and
// delegates JWT verification to the identity service's JWKS endpoint.
type ConfigSvcConfig struct {
	Env  Environment
	Port int

	// DBPath is the SQLite database file. Defaults to "config.db".
	DBPath string

	// IdentityIssuerURL is the base URL of the identity service. The config
	// service fetches JWKS from {IdentityIssuerURL}/.well-known/jwks.json.
	// Defaults to "http://localhost:8181" in development; required in
	// production.
	IdentityIssuerURL string

	// IdentityIssuer is the expected `iss` claim on incoming JWTs. Defaults
	// to IdentityIssuerURL if unset.
	IdentityIssuer string

	// JWKSCacheTTL controls how long the verifier caches the fetched JWKS
	// before refetching. Zero uses the verifier's built-in default.
	JWKSCacheTTL time.Duration

	// BackupMinInterval is the cooldown window between consecutive
	// triggered backups. Defaults to 30 seconds.
	BackupMinInterval time.Duration

	// RequiredAudience, when non-empty, forces the JWKS verifier to
	// assert the `aud` claim on every incoming token. Intended as the
	// config-side half of cross-service token-replay mitigation; keep
	// empty until identity stamps a matching audience on issuance.
	RequiredAudience string

	TrustProxy        string
	CORSOrigins       []string
	RateLimitDisabled bool

	// R2 backup (optional at load time; logged as disabled if unset).
	R2AccountID       string
	R2AccessKeyID     string
	R2SecretAccessKey string
	R2BucketName      string
}

// LoadConfigSvc reads configuration from environment variables and returns a
// validated ConfigSvcConfig. Environment variable names match the identity
// service where they overlap (PORT, DB_PATH, IDENTITY_ENV, R2_*,
// TRUST_PROXY, CORS_ORIGINS, RATE_LIMIT_DISABLED) so the same systemd env
// file conventions apply.
//
// Config-specific variables:
//
//	IDENTITY_ISSUER_URL  base URL of identity (for JWKS fetch)
//	IDENTITY_ISSUER      expected iss claim (defaults to IDENTITY_ISSUER_URL)
//	JWKS_CACHE_TTL       JWKS cache TTL as a Go duration (e.g. "5m")
//	BACKUP_MIN_INTERVAL  cooldown for per-write backups as a Go duration
func LoadConfigSvc() (*ConfigSvcConfig, error) {
	cfg := &ConfigSvcConfig{
		Port:              8282,
		DBPath:            "config.db",
		BackupMinInterval: 30 * time.Second,
	}

	switch Environment(os.Getenv("IDENTITY_ENV")) {
	case EnvProduction:
		cfg.Env = EnvProduction
	default:
		cfg.Env = EnvDevelopment
	}

	var errs []error

	if v := os.Getenv("PORT"); v != "" {
		port, err := strconv.Atoi(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("PORT must be a valid integer, got %q", v))
		} else {
			cfg.Port = port
		}
	}
	if v := os.Getenv("DB_PATH"); v != "" {
		cfg.DBPath = v
	}

	cfg.IdentityIssuerURL = os.Getenv("IDENTITY_ISSUER_URL")
	if cfg.IdentityIssuerURL == "" {
		if cfg.Env == EnvDevelopment {
			cfg.IdentityIssuerURL = "http://localhost:8181"
		} else {
			errs = append(errs, errors.New("IDENTITY_ISSUER_URL is required in production"))
		}
	}
	if cfg.Env == EnvProduction && cfg.IdentityIssuerURL != "" && !strings.HasPrefix(cfg.IdentityIssuerURL, "https://") {
		errs = append(errs, fmt.Errorf("IDENTITY_ISSUER_URL must be an https:// URL in production (got %q)", cfg.IdentityIssuerURL))
	}
	// Validate URL shape. Catches query strings, fragments, or accidental
	// whitespace early instead of silently producing a malformed JWKS
	// request URL at the first login.
	if cfg.IdentityIssuerURL != "" {
		if err := validateIdentityIssuerURL(cfg.IdentityIssuerURL); err != nil {
			errs = append(errs, fmt.Errorf("IDENTITY_ISSUER_URL: %w", err))
		}
	}

	cfg.IdentityIssuer = os.Getenv("IDENTITY_ISSUER")
	if cfg.IdentityIssuer == "" {
		cfg.IdentityIssuer = cfg.IdentityIssuerURL
	}

	cfg.RequiredAudience = os.Getenv("REQUIRED_AUDIENCE")

	if v := os.Getenv("JWKS_CACHE_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("JWKS_CACHE_TTL: %w", err))
		} else {
			cfg.JWKSCacheTTL = d
		}
	}

	if v := os.Getenv("BACKUP_MIN_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("BACKUP_MIN_INTERVAL: %w", err))
		} else {
			cfg.BackupMinInterval = d
		}
	}

	if v := os.Getenv("TRUST_PROXY"); v == "cloudflare" {
		cfg.TrustProxy = "cloudflare"
	}

	if v := os.Getenv("CORS_ORIGINS"); v != "" {
		for _, o := range strings.Split(v, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				cfg.CORSOrigins = append(cfg.CORSOrigins, o)
			}
		}
	}

	if v := os.Getenv("RATE_LIMIT_DISABLED"); v == "1" || v == "true" {
		cfg.RateLimitDisabled = true
	}

	cfg.R2AccountID = os.Getenv("R2_ACCOUNT_ID")
	cfg.R2AccessKeyID = os.Getenv("R2_ACCESS_KEY_ID")
	cfg.R2SecretAccessKey = os.Getenv("R2_SECRET_ACCESS_KEY")
	cfg.R2BucketName = os.Getenv("R2_BUCKET_NAME")

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return cfg, nil
}

// validateIdentityIssuerURL rejects ill-shaped values early (at startup)
// so operators see a clear error instead of a cryptic JWKS-fetch failure
// on the first request.
func validateIdentityIssuerURL(raw string) error {
	if strings.TrimSpace(raw) != raw {
		return errors.New("must not contain leading/trailing whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("host is required")
	}
	if u.RawQuery != "" {
		return errors.New("must not contain a query string")
	}
	if u.Fragment != "" {
		return errors.New("must not contain a fragment")
	}
	// A trailing slash is fine (we strip it elsewhere); a non-trivial path
	// is not — JWKS lives at a known path off the root.
	p := strings.TrimSuffix(u.Path, "/")
	if p != "" {
		return fmt.Errorf("must not contain a path (got %q)", u.Path)
	}
	return nil
}

// R2Configured reports whether all R2 credentials are present for the
// config service.
func (c *ConfigSvcConfig) R2Configured() bool {
	return c.R2AccountID != "" &&
		c.R2AccessKeyID != "" &&
		c.R2SecretAccessKey != "" &&
		c.R2BucketName != ""
}

// IsProduction reports whether this config service runs in production mode.
func (c *ConfigSvcConfig) IsProduction() bool {
	return c.Env == EnvProduction
}
