package oauth

import (
	"encoding/json"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/url"

	"github.com/sweeney/identity/internal/service"
	"github.com/sweeney/identity/internal/ui"
)

type tmplSet struct {
	base  *template.Template
	funcs template.FuncMap
}

func (ts *tmplSet) render(w http.ResponseWriter, page string, data any) error {
	cloned, err := ts.base.Clone()
	if err != nil {
		return err
	}
	if _, err := cloned.New(page).Funcs(ts.funcs).ParseFS(ui.TemplateFS, "templates/"+page); err != nil {
		return err
	}
	return cloned.ExecuteTemplate(w, "base.html", data)
}

type oauthHandler struct {
	svc  service.OAuthServicer
	tmpl *tmplSet
}

func (h *oauthHandler) render(w http.ResponseWriter, page string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.render(w, page, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

func (h *oauthHandler) renderError(w http.ResponseWriter, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	if err := h.tmpl.render(w, "oauth_error.html", map[string]any{
		"HideNav": true,
		"Title":   title,
		"Message": message,
	}); err != nil {
		http.Error(w, message, http.StatusBadRequest)
	}
}

// authorizeGet validates the client and renders the login form.
func (h *oauthHandler) authorizeGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	responseType := q.Get("response_type")

	if responseType != "code" {
		h.renderError(w, "Invalid Request", "response_type must be 'code'")
		return
	}

	if codeChallengeMethod != "S256" {
		h.renderError(w, "Invalid Request", "code_challenge_method must be 'S256'")
		return
	}

	if codeChallenge == "" {
		h.renderError(w, "Invalid Request", "code_challenge is required")
		return
	}

	client, err := h.svc.ValidateAuthorizeRequest(clientID, redirectURI)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrUnknownClient):
			h.renderError(w, "Unknown Client", "The client_id is not registered.")
		case errors.Is(err, service.ErrInvalidRedirectURI):
			h.renderError(w, "Invalid Redirect URI", "The redirect_uri is not registered for this client.")
		default:
			h.renderError(w, "Error", "An unexpected error occurred.")
		}
		return
	}

	h.render(w, "oauth_login.html", map[string]any{
		"HideNav":             true,
		"ClientName":          client.Name,
		"ClientID":            clientID,
		"RedirectURI":         redirectURI,
		"State":               state,
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod": codeChallengeMethod,
	})
}

// authorizePost authenticates the user, issues a code, and redirects.
func (h *oauthHandler) authorizePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, "Bad Request", "Could not parse form.")
		return
	}

	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	codeChallenge := r.FormValue("code_challenge")
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Re-validate client on POST to prevent CSRF-style attacks
	client, err := h.svc.ValidateAuthorizeRequest(clientID, redirectURI)
	if err != nil {
		h.renderError(w, "Invalid Request", "Client or redirect URI is invalid.")
		return
	}

	rawCode, err := h.svc.Authorize(clientID, redirectURI, username, password, codeChallenge, extractClientIP(r))
	if err != nil {
		// Re-render login form with error
		errMsg := "Invalid username or password."
		if errors.Is(err, service.ErrAccountDisabled) {
			errMsg = "Account is disabled."
		}
		h.render(w, "oauth_login.html", map[string]any{
			"HideNav":       true,
			"ClientName":    client.Name,
			"ClientID":      clientID,
			"RedirectURI":   redirectURI,
			"State":         state,
			"CodeChallenge": codeChallenge,
			"Error":         errMsg,
			"Username":      username,
		})
		return
	}

	// Build redirect URL with code and state
	redirectURL := redirectURI + "?code=" + url.QueryEscape(rawCode)
	if state != "" {
		redirectURL += "&state=" + url.QueryEscape(state)
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// token handles authorization_code and refresh_token grant types.
func (h *oauthHandler) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request", "Could not parse form.")
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		h.tokenAuthCode(w, r)
	case "refresh_token":
		h.tokenRefresh(w, r)
	default:
		oauthError(w, "unsupported_grant_type", "grant_type must be 'authorization_code' or 'refresh_token'")
	}
}

func (h *oauthHandler) tokenAuthCode(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	if clientID == "" || code == "" || redirectURI == "" || codeVerifier == "" {
		oauthError(w, "invalid_request", "client_id, code, redirect_uri, and code_verifier are required")
		return
	}

	result, err := h.svc.ExchangeCode(clientID, code, redirectURI, codeVerifier)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidAuthCode):
			oauthError(w, "invalid_grant", "The authorization code is invalid.")
		case errors.Is(err, service.ErrAuthCodeAlreadyUsed):
			oauthError(w, "invalid_grant", "The authorization code has already been used.")
		case errors.Is(err, service.ErrAuthCodeExpired):
			oauthError(w, "invalid_grant", "The authorization code has expired.")
		case errors.Is(err, service.ErrPKCEVerificationFailed):
			oauthError(w, "invalid_grant", "PKCE verification failed.")
		case errors.Is(err, service.ErrAccountDisabled):
			oauthError(w, "access_denied", "Account is disabled.")
		default:
			oauthError(w, "server_error", "An unexpected error occurred.")
		}
		return
	}

	jsonOK(w, tokenResponse(result))
}

func (h *oauthHandler) tokenRefresh(w http.ResponseWriter, r *http.Request) {
	rawRefreshToken := r.FormValue("refresh_token")
	if rawRefreshToken == "" {
		oauthError(w, "invalid_request", "refresh_token is required")
		return
	}

	result, err := h.svc.RefreshToken(rawRefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidRefreshToken):
			oauthError(w, "invalid_grant", "The refresh token is invalid.")
		case errors.Is(err, service.ErrTokenFamilyCompromised):
			oauthError(w, "invalid_grant", "Token reuse detected — please log in again.")
		case errors.Is(err, service.ErrRefreshTokenExpired):
			oauthError(w, "invalid_grant", "The refresh token has expired.")
		case errors.Is(err, service.ErrAccountDisabled):
			oauthError(w, "access_denied", "Account is disabled.")
		default:
			oauthError(w, "server_error", "An unexpected error occurred.")
		}
		return
	}

	jsonOK(w, tokenResponse(result))
}

type tokenResponseBody struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func tokenResponse(r *service.LoginResult) tokenResponseBody {
	return tokenResponseBody{
		AccessToken:  r.AccessToken,
		TokenType:    r.TokenType,
		ExpiresIn:    r.ExpiresIn,
		RefreshToken: r.RefreshToken,
	}
}

type oauthErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func oauthError(w http.ResponseWriter, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(oauthErrorBody{Error: code, ErrorDescription: description}) //nolint:errcheck
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func extractClientIP(r *http.Request) string {
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return cf
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
