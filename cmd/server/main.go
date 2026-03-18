package main

import (
	"bufio"
	"context"
	"fmt"
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
		case "--rotate-jwt-secret":
			if err := runDBCommand(rotateJWTSecret); err != nil {
				log.Fatalf("fatal: %v", err)
			}
			return
		case "--clear-prev-jwt-secret":
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
			fmt.Println("  --rotate-jwt-secret       Generate a new JWT signing secret")
			fmt.Println("  --clear-prev-jwt-secret   Remove the previous JWT secret after rotation")
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

	// JWT secrets (from DB or env var override)
	secrets, err := resolveJWTSecrets(database, cfg.JWTSecret, cfg.JWTSecretPrev)
	if err != nil {
		return fmt.Errorf("jwt secrets: %w", err)
	}

	issuer, err := auth.NewTokenIssuer(secrets.Current, secrets.Previous, cfg.JWTIssuer, cfg.AccessTokenTTL)
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
	oauthSvc := service.NewOAuthService(authSvc, oauthClientStore, oauthCodeStore, auditStore, 60*time.Second)

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

	// Cleanup goroutine: prune expired/old-revoked tokens and auth codes every 24h
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
			}
		}
	}()

	// Rate limiters
	// Strict: 5 req/min (≈0.083/s) with burst of 5 for auth endpoints
	// General: 30 req/min (0.5/s) with burst of 10 for all other endpoints
	var authRateLimiter, generalRateLimiter *ratelimit.Limiter
	if !cfg.RateLimitDisabled {
		authRateLimiter = ratelimit.NewLimiter(5.0/60.0, 5)
		generalRateLimiter = ratelimit.NewLimiter(30.0/60.0, 10)
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
	apiRouter := apihandler.NewRouter(issuer, authSvc, userSvc, cfg.TrustProxy)

	// Auth endpoints get strict rate limiting; wrap only the login path
	// and let the rest of the API router handle other /api/v1/ paths.
	mux.Handle("POST /api/v1/auth/login", wrapAuth(apiRouter))
	mux.Handle("/api/v1/", apiRouter)
	mux.Handle("POST /oauth/token", wrapAuth(oauthhandler.NewRouter(oauthSvc, cfg.TrustProxy)))
	mux.Handle("/oauth/", oauthhandler.NewRouter(oauthSvc, cfg.TrustProxy))
	adminRouter := admin.NewRouter(admin.Config{
		SessionSecret: secrets.Current,
		Production:    cfg.IsProduction(),
		TrustProxy:    cfg.TrustProxy,
	}, authSvc, userSvc, oauthClientStore, auditStore, backupMgr)
	mux.Handle("POST /admin/login", wrapAuth(adminRouter))
	mux.Handle("/admin/", adminRouter)
	staticFS, _ := fs.Sub(ui.StaticFS, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	homeHTML, _ := ui.TemplateFS.ReadFile("templates/home.html")
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(homeHTML)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
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
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"style-src 'self'; "+
				"script-src 'self'; "+
				"img-src 'self' data:; "+
				"frame-ancestors 'none'; "+
				"form-action 'self'")

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
