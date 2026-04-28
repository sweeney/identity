package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sweeney/identity/common/backup"
	"github.com/sweeney/identity/common/ratelimit"
	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/config"
	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
	confighandler "github.com/sweeney/identity/internal/handler/config"
	"github.com/sweeney/identity/internal/service"
	"github.com/sweeney/identity/internal/store"
)

// runConfig dispatches config subcommand flags and serves by default.
func runConfig(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "--help", "-h", "help":
			printConfigUsage()
			return nil
		case "--list-backups":
			return listBackupsForService("config")
		case "--restore-backup":
			key := ""
			if len(args) > 1 {
				key = args[1]
			}
			cfg, err := config.LoadConfigSvc()
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
			return restoreBackupForService("config", cfg.DBPath, key)
		default:
			printConfigUsage()
			return fmt.Errorf("unknown config flag: %s", args[0])
		}
	}
	return runConfigServer()
}

func printConfigUsage() {
	fmt.Println("Usage: identity-server config [flags]")
	fmt.Println()
	fmt.Println("The config service stores structured configuration as")
	fmt.Println("named JSON documents with per-namespace read/write role ACLs.")
	fmt.Println("It validates JWTs against the identity service's JWKS endpoint.")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  (none)                  Start the config HTTP server")
	fmt.Println("  --list-backups          List available R2 backups for the config service")
	fmt.Println("  --restore-backup [key]  Restore the config DB from an R2 backup")
	fmt.Println("  --help                  Show this help")
	fmt.Println()
	fmt.Println("Environment variables:")
	fmt.Println("  PORT                    Listen port (default 8282)")
	fmt.Println("  DB_PATH                 SQLite file path (default config.db)")
	fmt.Println("  IDENTITY_ENV            development | production")
	fmt.Println("  IDENTITY_ISSUER_URL     Base URL of identity service (for JWKS)")
	fmt.Println("  IDENTITY_ISSUER         Expected JWT iss claim (defaults to IDENTITY_ISSUER_URL)")
	fmt.Println("  JWKS_CACHE_TTL          How long to cache JWKS (e.g. 5m)")
	fmt.Println("  BACKUP_MIN_INTERVAL     Per-write backup cooldown (e.g. 30s)")
	fmt.Println("  TRUST_PROXY             'cloudflare' to honour CF-Connecting-IP")
	fmt.Println("  CORS_ORIGINS            Comma-separated allowed origins")
	fmt.Println("  RATE_LIMIT_DISABLED     Set to 1 to disable rate limiting")
	fmt.Println("  R2_*                    R2 credentials for backups")
}

func runConfigServer() error {
	cfg, err := config.LoadConfigSvc()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	database, err := db.OpenConfig(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	repo := store.NewConfigStore(database)

	// Backup manager (optional — runs as noop if R2 is not configured)
	var backupMgr domain.BackupService
	if cfg.R2Configured() {
		uploader, err := backup.NewR2Uploader(backup.R2Config{
			AccountID:       cfg.R2AccountID,
			AccessKeyID:     cfg.R2AccessKeyID,
			SecretAccessKey: cfg.R2SecretAccessKey,
			BucketName:      cfg.R2BucketName,
		})
		if err != nil {
			return fmt.Errorf("r2 uploader: %w", err)
		}
		mgr := backup.NewManager(backup.Config{
			DBPath:      cfg.DBPath,
			BucketName:  cfg.R2BucketName,
			Env:         string(cfg.Env),
			ServiceName: "config",
			MinInterval: cfg.BackupMinInterval,
		}, uploader, logBackupEvent)
		backupMgr = mgr
	} else {
		log.Println("warning: R2 backup not configured — config backups disabled")
		backupMgr = &backup.NoopManager{}
	}

	// JWKS verifier points at the identity service.
	verifier, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		IssuerURL:        cfg.IdentityIssuerURL,
		Issuer:           cfg.IdentityIssuer,
		CacheTTL:         cfg.JWKSCacheTTL,
		RequiredAudience: cfg.RequiredAudience,
	})
	if err != nil {
		return fmt.Errorf("jwks verifier: %w", err)
	}
	if cfg.RequiredAudience == "" {
		log.Printf("config: verifying tokens via JWKS at %s/.well-known/jwks.json (expected iss=%s)",
			cfg.IdentityIssuerURL, cfg.IdentityIssuer)
	} else {
		log.Printf("config: verifying tokens via JWKS at %s/.well-known/jwks.json (expected iss=%s, aud=%s)",
			cfg.IdentityIssuerURL, cfg.IdentityIssuer, cfg.RequiredAudience)
	}

	svc := service.NewConfigService(repo, backupMgr)

	router := confighandler.NewRouter(confighandler.Deps{
		Service:           svc,
		Verifier:          verifier,
		Version:           version,
		IdentityPublicURL: cfg.IdentityPublicURL,
		OAuthClientID:     cfg.OAuthClientID,
	})
	if cfg.OAuthClientID != "" && cfg.IdentityPublicURL != "" {
		log.Printf("config: admin UI mounted at /; oauth client_id=%s, identity public url=%s",
			cfg.OAuthClientID, cfg.IdentityPublicURL)
	} else {
		log.Println("config: admin UI disabled (set OAUTH_CLIENT_ID and IDENTITY_PUBLIC_URL to enable)")
	}

	// Loud warning when dev-mode is active and no explicit CORS allow
	// list is set: originAllowed will let *any* http://localhost:* origin
	// drive the API. That's intentional for local dev but dangerous if
	// IDENTITY_ENV is accidentally left unset on a public host.
	if cfg.Env == config.EnvDevelopment && len(cfg.CORSOrigins) == 0 {
		log.Println("WARNING: development mode + empty CORS_ORIGINS → ANY http://localhost:* origin is allowed; set IDENTITY_ENV=production or list explicit origins for non-dev hosts")
	}

	// Context + background tasks
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if m, ok := backupMgr.(*backup.Manager); ok {
		m.Start(ctx)
	}

	// Rate limiting. Config has no credential-accepting endpoints, so we
	// apply only the general limiter.
	if cfg.RateLimitDisabled && cfg.IsProduction() {
		log.Println("WARNING: RATE_LIMIT_DISABLED ignored in production")
		cfg.RateLimitDisabled = false
	}
	var handler http.Handler = router
	if !cfg.RateLimitDisabled {
		// 5 rps (300/min) with burst 20. Chosen higher than identity's 30/min
		// because the primary callers are sibling services that read
		// config on boot — a ~8-service parallel power-on burst must not
		// throttle legitimate reads.
		limiter := ratelimit.NewLimiter(5.0, 20, cfg.TrustProxy)
		handler = limiter.Middleware(router)
		log.Println("rate limiting enabled")
	} else {
		log.Println("rate limiting disabled (RATE_LIMIT_DISABLED)")
	}

	handler = configSecurityHeaders(handler, cfg.CORSOrigins, cfg.IdentityPublicURL, cfg.Env == config.EnvDevelopment)

	// OpenAPI + discovery endpoints are served directly on the raw mux
	// inside the router; nothing to register here yet. (Added in M4.)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// Send listen errors into a channel so we can run the graceful-shutdown
	// path even when ListenAndServe fails (port in use, bind permission
	// denied, etc.) — log.Fatalf would have skipped cancel()+srv.Shutdown
	// and dropped any in-flight backup upload.
	errCh := make(chan error, 1)
	go func() {
		log.Printf("config: listening on :%d [%s]", cfg.Port, cfg.Env)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	var exitErr error
	select {
	case <-stop:
		log.Println("config: shutting down...")
	case err := <-errCh:
		log.Printf("config: listen error: %v", err)
		exitErr = err
	}
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && exitErr == nil {
		exitErr = err
	}
	return exitErr
}

// logBackupEvent is the EventRecorder we hand to the backup manager. The
// config service has no persistent audit table in v1, so backup outcomes
// are written to stdout (picked up by systemd's journal). If a real audit
// sink is added later, swap this for a closure that records into it.
func logBackupEvent(success bool, detail string) {
	outcome := domain.EventBackupSuccess
	if !success {
		outcome = domain.EventBackupFailure
	}
	if detail != "" {
		log.Printf("audit: %s user=system detail=%s", outcome, detail)
	} else {
		log.Printf("audit: %s user=system", outcome)
	}
}

// originAllowed reports whether the given Origin header value is allowlisted.
// HasPrefix-on-string matching was unsafe because
// "http://localhost.attacker.example" would match; we parse the origin and
// compare host explicitly.
func originAllowed(origin string, allowed map[string]bool, devMode bool) bool {
	if allowed[origin] {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" {
		return false
	}
	if u.Host != "localhost" && !strings.HasPrefix(u.Host, "localhost:") {
		return false
	}
	if allowed["http://localhost"] {
		return true
	}
	return devMode && len(allowed) == 0
}

// configSecurityHeaders wraps the router with two CSPs and CORS for the
// JSON API. Config has two surfaces:
//
//   - The /, /static/*, and /spa-config.json paths serve the admin SPA.
//     They need a permissive-enough CSP to load same-origin scripts and
//     stylesheets, and to reach identity's /oauth/* endpoints from JS.
//   - The /api/*, /healthz, /openapi.* paths return JSON only and get
//     the strictest CSP we can.
//
// Both responses set the static security headers (no-sniff, frame-deny,
// HSTS, referrer-policy=no-referrer) regardless.
func configSecurityHeaders(next http.Handler, corsOrigins []string, identityURL string, devMode bool) http.Handler {
	allowed := make(map[string]bool, len(corsOrigins))
	for _, o := range corsOrigins {
		allowed[o] = true
	}

	// Pre-build the SPA CSP. connect-src and form-action need to allow
	// the identity service so the OAuth flow can redirect there and the
	// SPA can fetch /oauth/token. img-src allows data: for the inline
	// favicon.
	spaCSP := "default-src 'self'; " +
		"script-src 'self'; " +
		"style-src 'self'; " +
		"img-src 'self' data:; " +
		"connect-src 'self'"
	if identityURL != "" {
		spaCSP += " " + identityURL
	}
	spaCSP += "; form-action 'self'"
	if identityURL != "" {
		spaCSP += " " + identityURL
	}
	spaCSP += "; base-uri 'self'; frame-ancestors 'none'"

	const apiCSP = "default-src 'none'; frame-ancestors 'none'"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

		if isSPAPath(r.URL.Path) {
			w.Header().Set("Content-Security-Policy", spaCSP)
		} else {
			w.Header().Set("Content-Security-Policy", apiCSP)
		}

		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Vary", "Origin")
			origin := r.Header.Get("Origin")
			if origin != "" && originAllowed(origin, allowed, devMode) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Expose-Headers", "X-Read-Role, X-Write-Role")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isSPAPath reports whether the request path serves the admin UI. Used
// by configSecurityHeaders to choose between the SPA and API CSPs.
func isSPAPath(p string) bool {
	return p == "/" || p == "/spa-config.json" || strings.HasPrefix(p, "/static/")
}
