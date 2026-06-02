package config

import (
	"errors"
	"fmt"
	"log"
	"net"
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
	JWTIssuer string

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

	// RateLimitAllowlist: IPs/CIDRs that bypass rate limiting entirely
	RateLimitAllowlist []*net.IPNet

	// WebAuthn / Passkeys
	WebAuthnRPID          string   // Relying Party ID (domain, e.g. "example.com")
	WebAuthnRPDisplayName string   // Human-readable RP name shown in browser prompts
	WebAuthnRPOrigins     []string // Allowed origins (e.g. "https://id.example.com")

	// Cloudflare R2 (S3-compatible backup storage)
	R2AccountID       string
	R2AccessKeyID     string
	R2SecretAccessKey string
	R2BucketName      string

	// Backup schedule
	// BackupSchedule controls when automatic R2 backups run.
	// Valid values: "daily" (default), "weekly" (Sundays), "monthly" (1st of month), "off".
	BackupSchedule string
	// BackupHour is the UTC hour (0–23) for scheduled backups. Defaults to 3.
	BackupHour int
}

// Load reads configuration from environment variables and returns a validated Config.
// Returns an error if any required variable is missing or any value is invalid.
func Load() (*Config, error) {
	cfg := &Config{
		// Defaults
		Port:            8181,
		DBPath:          "identity.db",
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

	// JWT_ISSUER: the "iss" claim in issued JWTs; defaults to localhost URL in
	// development so discovery metadata contains valid URLs.
	cfg.JWTIssuer = os.Getenv("JWT_ISSUER")
	if cfg.JWTIssuer == "" {
		if cfg.Env == EnvDevelopment {
			cfg.JWTIssuer = fmt.Sprintf("http://localhost:%d", cfg.Port)
		} else {
			cfg.JWTIssuer = cfg.SiteName
		}
	}
	if cfg.Env == EnvProduction && !strings.HasPrefix(cfg.JWTIssuer, "https://") {
		errs = append(errs, fmt.Errorf("JWT_ISSUER must be an https:// URL in production (got %q); set JWT_ISSUER=https://yourdomain.com", cfg.JWTIssuer))
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

	// RATE_LIMIT_ALLOWLIST: comma-separated IPs/CIDRs exempt from rate limiting
	if v := os.Getenv("RATE_LIMIT_ALLOWLIST"); v != "" {
		nets, err := parseIPAllowlist(v)
		if err != nil {
			return nil, fmt.Errorf("RATE_LIMIT_ALLOWLIST: %w", err)
		}
		cfg.RateLimitAllowlist = nets
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
	// Warn if CORS origins contain entries not in WebAuthn origins.
	// The two are configured independently; this helps catch misconfigurations.
	if cfg.WebAuthnRPID != "" && len(cfg.CORSOrigins) > 0 {
		waOrigins := make(map[string]bool, len(cfg.WebAuthnRPOrigins))
		for _, o := range cfg.WebAuthnRPOrigins {
			waOrigins[o] = true
		}
		for _, o := range cfg.CORSOrigins {
			if strings.Contains(o, "*") {
				continue // wildcards are never valid WebAuthn origins; skip
			}
			if !waOrigins[o] {
				log.Printf("WARNING: CORS origin %q is not in WEBAUTHN_RP_ORIGINS — add it if passkey ceremonies should work from that origin", o)
			}
		}
	}

	// R2 config — optional at load time (service runs without backup if unset, logs a warning)
	cfg.R2AccountID = os.Getenv("R2_ACCOUNT_ID")
	cfg.R2AccessKeyID = os.Getenv("R2_ACCESS_KEY_ID")
	cfg.R2SecretAccessKey = os.Getenv("R2_SECRET_ACCESS_KEY")
	cfg.R2BucketName = os.Getenv("R2_BUCKET_NAME")

	// Backup schedule
	cfg.BackupHour = 3
	if schedStr := os.Getenv("BACKUP_SCHEDULE"); schedStr != "" {
		switch schedStr {
		case "daily", "weekly", "monthly", "off":
			cfg.BackupSchedule = schedStr
		default:
			errs = append(errs, fmt.Errorf("BACKUP_SCHEDULE must be daily, weekly, monthly, or off; got %q", schedStr))
		}
	}
	if hourStr := os.Getenv("BACKUP_HOUR"); hourStr != "" {
		h, err := strconv.Atoi(hourStr)
		if err != nil || h < 0 || h > 23 {
			errs = append(errs, fmt.Errorf("BACKUP_HOUR must be 0–23, got %q", hourStr))
		} else {
			cfg.BackupHour = h
		}
	}

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

// parseIPAllowlist parses a comma-separated list of IPs and CIDRs into networks.
// Bare IPs become /32 (IPv4) or /128 (IPv6) networks. Empty entries are skipped;
// any malformed entry is an error so a typo fails fast rather than silently
// leaving the IP rate-limited.
func parseIPAllowlist(v string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, entry := range strings.Split(v, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, ipnet, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", entry, err)
			}
			nets = append(nets, ipnet)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP %q", entry)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return nets, nil
}

// IPAllowed reports whether ipStr falls within any network in the allowlist.
// Returns false for an empty allowlist or an unparseable address.
func IPAllowed(allowlist []*net.IPNet, ipStr string) bool {
	if len(allowlist) == 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range allowlist {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
