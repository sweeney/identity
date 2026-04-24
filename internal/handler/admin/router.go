package admin

import (
	"html/template"
	"net/http"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/service"
	"github.com/sweeney/identity/internal/ui"
)

// Config holds admin UI configuration.
type Config struct {
	SessionSecret string
	Production    bool
	TrustProxy    string
	SiteName      string // human-readable name shown in nav and templates
}

// NewRouter builds the /admin mux.
func NewRouter(cfg Config, authSvc service.AuthServicer, userSvc service.UserServicer, oauthClients domain.OAuthClientRepository, auditRepo domain.AuditRepository, backupSvc domain.BackupService, tokenIssuer *auth.TokenIssuer, webauthnSvc service.WebAuthnServicer, deviceSvc service.DeviceFlowServicer) http.Handler {
	funcs := template.FuncMap{
		"assetVer": func() string { return ui.AssetVersion },
	}

	// Parse only the base template at startup; page templates are cloned in per-request.
	baseTmpl := template.Must(
		template.New("base.html").Funcs(funcs).ParseFS(ui.TemplateFS, "templates/base.html"),
	)
	tmpl := &tmplSet{base: baseTmpl, funcs: funcs}

	h := &adminHandler{
		cfg:          cfg,
		authSvc:      authSvc,
		userSvc:      userSvc,
		webauthnSvc:  webauthnSvc,
		deviceSvc:    deviceSvc,
		oauthClients: oauthClients,
		auditRepo:    auditRepo,
		backupSvc:    backupSvc,
		tokenIssuer:  tokenIssuer,
		tmpl:         tmpl,
	}

	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("GET /admin/login", h.loginGet)
	mux.HandleFunc("POST /admin/login", h.loginPost)
	mux.HandleFunc("POST /admin/login/passkey", h.loginPasskey)

	// Protected
	mux.Handle("POST /admin/logout", h.requireSession(h.requireCSRF(http.HandlerFunc(h.logout))))
	mux.Handle("GET /admin/", h.requireSession(http.HandlerFunc(h.dashboard)))

	// Users
	mux.Handle("GET /admin/users", h.requireSession(http.HandlerFunc(h.usersList)))
	mux.Handle("GET /admin/users/new", h.requireSession(http.HandlerFunc(h.usersNewGet)))
	mux.Handle("POST /admin/users/new", h.requireSession(h.requireCSRF(http.HandlerFunc(h.usersNewPost))))
	mux.Handle("GET /admin/users/{id}/edit", h.requireSession(http.HandlerFunc(h.usersEditGet)))
	mux.Handle("POST /admin/users/{id}/edit", h.requireSession(h.requireCSRF(http.HandlerFunc(h.usersEditPost))))
	mux.Handle("POST /admin/users/{id}/passkeys/{credID}/delete", h.requireSession(h.requireCSRF(http.HandlerFunc(h.userPasskeyDelete))))
	mux.Handle("GET /admin/users/{id}/delete", h.requireSession(http.HandlerFunc(h.usersDeleteGet)))
	mux.Handle("POST /admin/users/{id}/delete", h.requireSession(h.requireCSRF(http.HandlerFunc(h.usersDeletePost))))
	mux.Handle("POST /admin/backup", h.requireSession(h.requireCSRF(http.HandlerFunc(h.triggerBackup))))

	// OAuth clients
	mux.Handle("GET /admin/oauth", h.requireSession(http.HandlerFunc(h.oauthList)))
	mux.Handle("GET /admin/oauth/new", h.requireSession(http.HandlerFunc(h.oauthNewGet)))
	mux.Handle("POST /admin/oauth/new", h.requireSession(h.requireCSRF(http.HandlerFunc(h.oauthNewPost))))
	mux.Handle("GET /admin/oauth/{id}/edit", h.requireSession(http.HandlerFunc(h.oauthEditGet)))
	mux.Handle("POST /admin/oauth/{id}/edit", h.requireSession(h.requireCSRF(http.HandlerFunc(h.oauthEditPost))))
	mux.Handle("GET /admin/oauth/{id}/delete", h.requireSession(http.HandlerFunc(h.oauthDeleteGet)))
	mux.Handle("POST /admin/oauth/{id}/delete", h.requireSession(h.requireCSRF(http.HandlerFunc(h.oauthDeletePost))))
	mux.Handle("POST /admin/oauth/{id}/generate-secret", h.requireSession(h.requireCSRF(http.HandlerFunc(h.oauthGenerateSecret))))
	mux.Handle("POST /admin/oauth/{id}/rotate-secret", h.requireSession(h.requireCSRF(http.HandlerFunc(h.oauthRotateSecret))))
	mux.Handle("POST /admin/oauth/{id}/clear-prev-secret", h.requireSession(h.requireCSRF(http.HandlerFunc(h.oauthClearPrevSecret))))

	// Device flow claim codes (per OAuth client)
	if deviceSvc != nil {
		mux.Handle("GET /admin/oauth/{id}/claim-codes", h.requireSession(http.HandlerFunc(h.claimCodesList)))
		mux.Handle("GET /admin/oauth/{id}/claim-codes/new", h.requireSession(http.HandlerFunc(h.claimCodesNewGet)))
		mux.Handle("POST /admin/oauth/{id}/claim-codes/new", h.requireSession(h.requireCSRF(http.HandlerFunc(h.claimCodesGenerate))))
		mux.Handle("POST /admin/oauth/{id}/claim-codes/{claimID}/revoke", h.requireSession(h.requireCSRF(http.HandlerFunc(h.claimCodeRevoke))))
		mux.Handle("POST /admin/oauth/{id}/claim-codes/{claimID}/delete", h.requireSession(h.requireCSRF(http.HandlerFunc(h.claimCodeDelete))))
	}

	// Passkeys
	mux.Handle("GET /admin/passkeys/prompt", h.requireSession(http.HandlerFunc(h.passkeyPrompt)))
	mux.Handle("GET /admin/passkeys", h.requireSession(http.HandlerFunc(h.passkeys)))
	mux.Handle("POST /admin/passkeys/{id}/delete", h.requireSession(h.requireCSRF(http.HandlerFunc(h.passkeyDelete))))
	mux.Handle("POST /admin/passkeys/register/begin", h.requireSession(http.HandlerFunc(h.passkeyRegisterBegin)))
	mux.Handle("POST /admin/passkeys/register/finish", h.requireSession(http.HandlerFunc(h.passkeyRegisterFinish)))

	// Audit log
	mux.Handle("GET /admin/audit", h.requireSession(http.HandlerFunc(h.auditLog)))

	return mux
}
