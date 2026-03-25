package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
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
	"github.com/sweeney/identity/internal/handler/admin"
	apihandler "github.com/sweeney/identity/internal/handler/api"
	oauthhandler "github.com/sweeney/identity/internal/handler/oauth"
	"github.com/sweeney/identity/internal/ratelimit"
	"github.com/sweeney/identity/internal/service"
	"github.com/sweeney/identity/internal/spec"
	"github.com/sweeney/identity/internal/store"
	"github.com/sweeney/identity/internal/ui"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--reset-admin":
			if err := resetAdmin(); err != nil {
				log.Fatalf("fatal: %v", err)
			}
			return
		case "--rotate-jwt-key":
			if err := runDBCommand(rotateJWTSecret); err != nil {
				log.Fatalf("fatal: %v", err)
			}
			return
		case "--clear-prev-jwt-key":
			if err := runDBCommand(clearPrevJWTSecret); err != nil {
				log.Fatalf("fatal: %v", err)
			}
			return
		case "--list-backups":
			if err := listBackups(); err != nil {
				log.Fatalf("fatal: %v", err)
			}
			return
		case "--restore-backup":
			key := ""
			if len(os.Args) > 2 {
				key = os.Args[2]
			}
			if err := restoreBackup(key); err != nil {
				log.Fatalf("fatal: %v", err)
			}
			return
		case "--help", "-h":
			fmt.Println("Usage: identity-server [command]")
			fmt.Println()
			fmt.Println("Commands:")
			fmt.Println("  (none)                    Start the server")
			fmt.Println("  --reset-admin             Reset the admin password (interactive)")
			fmt.Println("  --rotate-jwt-key          Generate a new JWT signing key")
			fmt.Println("  --clear-prev-jwt-key      Remove the previous JWT key after rotation")
			fmt.Println("  --list-backups            List available R2 backups")
			fmt.Println("  --restore-backup [key]    Restore from an R2 backup (interactive if no key)")
			fmt.Println("  --help                    Show this help")
			return
		}
	}

	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

// runDBCommand opens the DB and runs a function against it.
func runDBCommand(fn func(*db.Database) error) error {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "identity.db"
	}
	database, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()
	return fn(database)
}

// resetAdmin prompts for a new admin password and updates (or creates) the admin user.
func resetAdmin() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	userStore := store.NewUserStore(database)
	tokenStore := store.NewTokenStore(database)
	backupMgr := &backup.NoopManager{}
	userSvc := service.NewUserService(userStore, tokenStore, backupMgr, nil, 100)

	// Find existing admin users
	users, err := userSvc.List()
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}

	var adminUser *domain.User
	for _, u := range users {
		if u.Role == domain.RoleAdmin {
			adminUser = u
			break
		}
	}

	reader := bufio.NewReader(os.Stdin)

	if adminUser == nil {
		fmt.Print("No admin user found. Enter username for new admin: ")
		username, _ := reader.ReadString('\n')
		username = strings.TrimSpace(username)
		if username == "" {
			return fmt.Errorf("username cannot be empty")
		}

		fmt.Print("Enter password: ")
		password, _ := reader.ReadString('\n')
		password = strings.TrimSpace(password)

		_, err := userSvc.Create(username, username, password, domain.RoleAdmin)
		if err != nil {
			return fmt.Errorf("create admin: %w", err)
		}
		fmt.Printf("Admin user %q created.\n", username)
		return nil
	}

	fmt.Printf("Resetting password for admin user %q\n", adminUser.Username)
	fmt.Print("Enter new password: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	_, err = userSvc.Update(adminUser.ID, service.UpdateUserInput{Password: &password})
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	// Revoke all tokens for the admin
	if err := tokenStore.RevokeAllForUser(adminUser.ID); err != nil {
		return fmt.Errorf("revoke tokens: %w", err)
	}

	fmt.Printf("Password reset for %q. All existing sessions revoked.\n", adminUser.Username)
	return nil
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// Database
	database, err := db.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	// Stores
	userStore := store.NewUserStore(database)
	tokenStore := store.NewTokenStore(database)
	oauthClientStore := store.NewOAuthClientStore(database)
	oauthCodeStore := store.NewOAuthCodeStore(database)
	auditStore := store.NewAuditStore(database)

	// JWT signing keys and session secret (all DB-managed, generated on first run)
	secrets, err := resolveServerSecrets(database)
	if err != nil {
		return fmt.Errorf("server secrets: %w", err)
	}

	issuer, err := auth.NewTokenIssuer(secrets.JWTCurrent, secrets.JWTPrevious, cfg.JWTIssuer, cfg.AccessTokenTTL)
	if err != nil {
		return fmt.Errorf("jwt issuer: %w", err)
	}

	// Backup manager
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
			DBPath:     cfg.DBPath,
			BucketName: cfg.R2BucketName,
			Env:        string(cfg.Env),
		}, uploader, auditStore)
		backupMgr = mgr
	} else {
		log.Println("warning: R2 backup not configured — backups disabled")
		backupMgr = &backup.NoopManager{}
	}

	// Services
	authSvc := service.NewAuthService(issuer, userStore, tokenStore, backupMgr, auditStore, cfg.RefreshTokenTTL)
	userSvc := service.NewUserService(userStore, tokenStore, backupMgr, auditStore, 10)
	oauthSvc := service.NewOAuthService(authSvc, issuer, oauthClientStore, oauthCodeStore, auditStore, 60*time.Second)

	// WebAuthn / Passkeys (optional — enabled when WEBAUTHN_RP_ID is set, or automatically in development)
	var webauthnSvc service.WebAuthnServicer
	if cfg.WebAuthnConfigured() {
		waCredStore := store.NewWebAuthnCredentialStore(database)
		waChallengeStore := store.NewWebAuthnChallengeStore(database)
		wa, waErr := auth.NewWebAuthn(cfg.WebAuthnRPID, cfg.WebAuthnRPDisplayName, cfg.WebAuthnRPOrigins)
		if waErr != nil {
			return fmt.Errorf("webauthn: %w", waErr)
		}
		webauthnSvc = service.NewWebAuthnService(wa, authSvc, userStore, waCredStore, waChallengeStore, auditStore, backupMgr)
		log.Printf("passkeys enabled (RP ID: %s, origins: %v)", cfg.WebAuthnRPID, cfg.WebAuthnRPOrigins)
	} else {
		log.Println("passkeys disabled (set WEBAUTHN_RP_ID to enable)")
	}

	// First-run seed: create admin user if no users exist yet
	if err := seedIfEmpty(userSvc, cfg.AdminUsername, cfg.AdminPassword); err != nil {
		return fmt.Errorf("seed: %w", err)
	}

	// Background tasks
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if m, ok := backupMgr.(*backup.Manager); ok {
		m.Start(ctx)
	}

	// WebAuthn challenge store for cleanup (may be nil if passkeys disabled)
	var waChallengeStore *store.WebAuthnChallengeStore
	if cfg.WebAuthnConfigured() {
		waChallengeStore = store.NewWebAuthnChallengeStore(database)
	}

	// Cleanup goroutine: prune expired/old-revoked tokens, auth codes, and challenges every 24h
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := tokenStore.DeleteExpiredAndOldRevoked(7); err != nil {
					log.Printf("token cleanup error: %v", err)
				}
				if err := oauthCodeStore.DeleteExpiredAndUsed(); err != nil {
					log.Printf("oauth code cleanup error: %v", err)
				}
				if waChallengeStore != nil {
					if err := waChallengeStore.DeleteExpired(); err != nil {
						log.Printf("webauthn challenge cleanup error: %v", err)
					}
				}
			}
		}
	}()

	// Rate limiters
	// Strict: 5 req/min (≈0.083/s) with burst of 5 for auth endpoints
	// General: 30 req/min (0.5/s) with burst of 10 for all other endpoints
	if cfg.RateLimitDisabled && cfg.IsProduction() {
		log.Println("WARNING: RATE_LIMIT_DISABLED ignored in production")
		cfg.RateLimitDisabled = false
	}
	var authRateLimiter, generalRateLimiter *ratelimit.Limiter
	if !cfg.RateLimitDisabled {
		authRateLimiter = ratelimit.NewLimiter(5.0/60.0, 5, cfg.TrustProxy)
		generalRateLimiter = ratelimit.NewLimiter(30.0/60.0, 10, cfg.TrustProxy)
		log.Println("rate limiting enabled")
	} else {
		log.Println("rate limiting disabled (RATE_LIMIT_DISABLED)")
	}

	// wrapAuth applies the strict rate limiter to a handler if rate limiting is enabled.
	wrapAuth := func(h http.Handler) http.Handler {
		if authRateLimiter != nil {
			return authRateLimiter.Middleware(h)
		}
		return h
	}

	// HTTP mux
	mux := http.NewServeMux()
	apiRouter := apihandler.NewRouter(issuer, authSvc, userSvc, webauthnSvc, cfg.TrustProxy)

	// Auth endpoints get strict rate limiting; wrap only the login path
	// and let the rest of the API router handle other /api/v1/ paths.
	mux.Handle("POST /api/v1/auth/login", wrapAuth(apiRouter))
	mux.Handle("POST /api/v1/webauthn/login/begin", wrapAuth(apiRouter))
	mux.Handle("POST /api/v1/webauthn/login/finish", wrapAuth(apiRouter))
	mux.Handle("/api/v1/", apiRouter)
	// All auth endpoints that accept credentials must use the strict rate limiter:
	//   POST /api/v1/auth/login, POST /oauth/token, POST /oauth/authorize, POST /admin/login
	oauthRouter := oauthhandler.NewRouter(oauthSvc, cfg.TrustProxy, issuer, authSvc, webauthnSvc, secrets.Session, cfg.SiteName)
	mux.Handle("POST /oauth/token", wrapAuth(oauthRouter))
	mux.Handle("POST /oauth/authorize", wrapAuth(oauthRouter))
	mux.Handle("POST /oauth/introspect", wrapAuth(oauthRouter))
	mux.Handle("/oauth/", oauthRouter)
	adminRouter := admin.NewRouter(admin.Config{
		SessionSecret: secrets.Session,
		Production:    cfg.IsProduction(),
		TrustProxy:    cfg.TrustProxy,
		SiteName:      cfg.SiteName,
	}, authSvc, userSvc, oauthClientStore, auditStore, backupMgr, issuer, webauthnSvc)
	mux.Handle("POST /admin/login", wrapAuth(adminRouter))
	mux.Handle("/admin/", adminRouter)
	staticFS, _ := fs.Sub(ui.StaticFS, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	homeHTML, _ := ui.TemplateFS.ReadFile("templates/home.html")
	homeTmpl, _ := template.New("home").Funcs(template.FuncMap{
		"assetVer": func() string { return ui.AssetVersion },
	}).Parse(string(homeHTML))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		homeTmpl.Execute(w, map[string]string{"SiteName": cfg.SiteName}) //nolint:errcheck
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	mux.Handle("GET /.well-known/jwks.json", jwksHandler(issuer))
	mux.Handle("GET /.well-known/oauth-authorization-server", oauthRouter)
	mux.HandleFunc("/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		w.Write(spec.YAML)
	})
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		data, err := spec.JSON()
		if err != nil {
			http.Error(w, "spec unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})

	// Build the handler chain: rate limit -> security headers -> mux
	var handler http.Handler = securityHeaders(mux, cfg.CORSOrigins, cfg.Env == config.EnvDevelopment)
	if generalRateLimiter != nil {
		handler = generalRateLimiter.Middleware(handler)
	}

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("listening on :%d [%s]", cfg.Port, cfg.Env)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-stop
	log.Println("shutting down...")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	return srv.Shutdown(shutdownCtx)
}

// securityHeaders wraps a handler with standard security response headers.
func securityHeaders(next http.Handler, allowedOrigins []string, devMode bool) http.Handler {
	// Build origin lookup set once at startup.
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[o] = true
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		csp := "default-src 'self'; " +
			"style-src 'self' 'unsafe-inline'; " +
			"script-src 'self'; " +
			"img-src 'self' data:; " +
			"frame-ancestors 'none'; " +
			"form-action 'self'"

		// OAuth authorize forms redirect to client redirect URIs after submission.
		// Modern browsers enforce form-action on redirect destinations, so we
		// must allow CORS origins (which are the client app origins).
		if len(allowedOrigins) > 0 {
			for _, o := range allowedOrigins {
				csp += " " + o
			}
		}

		w.Header().Set("Content-Security-Policy", csp)

		// CORS for API and OAuth token endpoints (needed by SPA clients)
		path := r.URL.Path
		if strings.HasPrefix(path, "/api/") || path == "/oauth/token" {
			w.Header().Set("Vary", "Origin")
			origin := r.Header.Get("Origin")
			if origin != "" && isAllowedOrigin(origin, allowed, devMode) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
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

// jwksHandler serves the JSON Web Key Set at /.well-known/jwks.json.
// Consuming services use this to fetch the public key for JWT verification.
func jwksHandler(issuer *auth.TokenIssuer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		json.NewEncoder(w).Encode(issuer.JWKS()) //nolint:errcheck
	})
}

// isAllowedOrigin checks whether the given origin is in the allowlist.
// In dev mode with an empty allowlist, any http://localhost origin is allowed.
func isAllowedOrigin(origin string, allowed map[string]bool, devMode bool) bool {
	if allowed[origin] {
		return true
	}
	if devMode && len(allowed) == 0 && strings.HasPrefix(origin, "http://localhost") {
		return true
	}
	return false
}
