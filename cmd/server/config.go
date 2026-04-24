package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/backup"
	"github.com/sweeney/identity/internal/config"
	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
	confighandler "github.com/sweeney/identity/internal/handler/config"
	"github.com/sweeney/identity/internal/ratelimit"
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
	fmt.Println("The config service stores structured homelab configuration as")
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
		}, uploader, nil)
		backupMgr = mgr
	} else {
		log.Println("warning: R2 backup not configured — config backups disabled")
		backupMgr = &backup.NoopManager{}
	}

	// JWKS verifier points at the identity service.
	verifier, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		IssuerURL: cfg.IdentityIssuerURL,
		Issuer:    cfg.IdentityIssuer,
		CacheTTL:  cfg.JWKSCacheTTL,
	})
	if err != nil {
		return fmt.Errorf("jwks verifier: %w", err)
	}
	log.Printf("config: verifying tokens via JWKS at %s/.well-known/jwks.json (expected iss=%s)",
		cfg.IdentityIssuerURL, cfg.IdentityIssuer)

	svc := service.NewConfigService(repo, backupMgr)

	router := confighandler.NewRouter(confighandler.Deps{
		Service:  svc,
		Verifier: verifier,
		Version:  version,
	})

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
		limiter := ratelimit.NewLimiter(30.0/60.0, 10, cfg.TrustProxy)
		handler = limiter.Middleware(router)
		log.Println("rate limiting enabled")
	} else {
		log.Println("rate limiting disabled (RATE_LIMIT_DISABLED)")
	}

	handler = configSecurityHeaders(handler, cfg.CORSOrigins, cfg.Env == config.EnvDevelopment)

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

	go func() {
		log.Printf("config: listening on :%d [%s]", cfg.Port, cfg.Env)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-stop
	log.Println("config: shutting down...")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	return srv.Shutdown(shutdownCtx)
}

// configSecurityHeaders wraps the router with a slimmer CSP than identity's.
// Config serves only JSON APIs and /healthz — no HTML, no forms, no OAuth
// redirects — so the CSP can be strict.
func configSecurityHeaders(next http.Handler, corsOrigins []string, devMode bool) http.Handler {
	allowed := make(map[string]bool, len(corsOrigins))
	for _, o := range corsOrigins {
		allowed[o] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Vary", "Origin")
			origin := r.Header.Get("Origin")
			if origin != "" && (allowed[origin] || (devMode && len(allowed) == 0 && strings.HasPrefix(origin, "http://localhost"))) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
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

