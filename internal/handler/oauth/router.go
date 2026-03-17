package oauth

import (
	"html/template"
	"net/http"

	"github.com/sweeney/identity/internal/service"
	"github.com/sweeney/identity/internal/ui"
)

// NewRouter builds the /oauth mux.
// If svc is nil, all routes return 404 (no clients registered).
func NewRouter(svc service.OAuthServicer) http.Handler {
	if svc == nil {
		return http.NotFoundHandler()
	}

	funcs := template.FuncMap{}
	baseTmpl := template.Must(
		template.New("base.html").Funcs(funcs).ParseFS(ui.TemplateFS, "templates/base.html"),
	)

	h := &oauthHandler{
		svc:  svc,
		tmpl: &tmplSet{base: baseTmpl, funcs: funcs},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth/authorize", h.authorizeGet)
	mux.HandleFunc("POST /oauth/authorize", h.authorizePost)
	mux.HandleFunc("POST /oauth/token", h.token)
	return mux
}
