package oauth

import (
	"html/template"
	"net/http"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/service"
	"github.com/sweeney/identity/internal/ui"
)

// NewRouter builds the /oauth mux.
// If svc is nil, all routes return 404 (no clients registered).
// tokenIssuer may be nil if passkeys are not enabled.
// authSvc and webauthnSvc are used for the post-login passkey prompt (may be nil).
func NewRouter(svc service.OAuthServicer, trustProxy string, tokenIssuer *auth.TokenIssuer, authSvc service.AuthServicer, webauthnSvc service.WebAuthnServicer, sessionKey, siteName string) http.Handler {
	if svc == nil {
		return http.NotFoundHandler()
	}

	funcs := template.FuncMap{}
	baseTmpl := template.Must(
		template.New("base.html").Funcs(funcs).ParseFS(ui.TemplateFS, "templates/base.html"),
	)

	h := &oauthHandler{
		svc:         svc,
		authSvc:     authSvc,
		webauthnSvc: webauthnSvc,
		tmpl:        &tmplSet{base: baseTmpl, funcs: funcs},
		trustProxy:  trustProxy,
		tokenIssuer: tokenIssuer,
		sessionKey:  sessionKey,
		siteName:    siteName,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth/authorize", h.authorizeGet)
	mux.HandleFunc("POST /oauth/authorize", h.authorizePost)
	mux.HandleFunc("POST /oauth/authorize/passkey", h.authorizePasskey)
	mux.HandleFunc("GET /oauth/passkey-prompt", h.passkeyPrompt)
	mux.HandleFunc("POST /oauth/passkey-prompt/register/begin", h.passkeyPromptRegisterBegin)
	mux.HandleFunc("POST /oauth/passkey-prompt/register/finish", h.passkeyPromptRegisterFinish)
	mux.HandleFunc("POST /oauth/token", h.token)
	return mux
}
