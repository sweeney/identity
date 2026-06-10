package oauth

import (
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sweeney/identity/common/httputil"
	"github.com/sweeney/identity/internal/auth"
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
	svc         service.OAuthServicer
	authSvc     service.AuthServicer
	webauthnSvc service.WebAuthnServicer
	deviceSvc   service.DeviceFlowServicer
	tmpl        *tmplSet
	trustProxy  string
	tokenIssuer *auth.TokenIssuer
	sessionKey  string // signing key for short-lived passkey prompt sessions
	siteName    string
}

func (h *oauthHandler) render(w http.ResponseWriter, page string, data any) {
	// Inject SiteName into map data for template use
	if m, ok := data.(map[string]any); ok {
		m["SiteName"] = h.siteName
	}
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

	// Mark RedirectURI as trusted — it was already validated against the client's
	// registered URIs. Without this, html/template sanitizes custom URL schemes
	// (e.g. myapp://callback) to #ZgotmplZ in the data-redirect-uri attribute.
	h.render(w, "oauth_login.html", map[string]any{
		"HideNav":             true,
		"ClientName":          client.Name,
		"ClientID":            clientID,
		"RedirectURI":         template.URL(redirectURI),
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

	ip := httputil.ExtractClientIP(r, h.trustProxy)

	// If we have an auth service, use the two-step flow (authenticate + issue code)
	// which enables the passkey prompt. Otherwise, use the single-step Authorize.
	if h.authSvc == nil {
		rawCode, err := h.svc.Authorize(clientID, redirectURI, username, password, codeChallenge, ip)
		if err != nil {
			errMsg := "Invalid username or password."
			if errors.Is(err, service.ErrAccountDisabled) {
				errMsg = "Account is disabled."
			}
			h.render(w, "oauth_login.html", map[string]any{
				"HideNav":       true,
				"ClientName":    client.Name,
				"ClientID":      clientID,
				"RedirectURI":   template.URL(redirectURI),
				"State":         state,
				"CodeChallenge": codeChallenge,
				"Error":         errMsg,
				"Username":      username,
			})
			return
		}
		redirectURL := redirectURI + "?code=" + url.QueryEscape(rawCode)
		if state != "" {
			redirectURL += "&state=" + url.QueryEscape(state)
		}
		h.clientRedirect(w, redirectURL)
		return
	}

	// Authenticate the user first to get their ID (needed for passkey prompt check)
	userID, authErr := h.authSvc.AuthorizeUser(username, password, ip)
	if authErr != nil {
		errMsg := "Invalid username or password."
		if errors.Is(authErr, service.ErrAccountDisabled) {
			errMsg = "Account is disabled."
		}
		h.render(w, "oauth_login.html", map[string]any{
			"HideNav":       true,
			"ClientName":    client.Name,
			"ClientID":      clientID,
			"RedirectURI":   template.URL(redirectURI),
			"State":         state,
			"CodeChallenge": codeChallenge,
			"Error":         errMsg,
			"Username":      username,
		})
		return
	}

	// Issue the authorization code for this pre-authenticated user
	rawCode, err := h.svc.AuthorizeByUserID(clientID, redirectURI, userID, username, codeChallenge, ip)
	if err != nil {
		h.renderError(w, "Error", "Failed to issue authorization code.")
		return
	}

	// Build redirect URL with code and state
	redirectURL := redirectURI + "?code=" + url.QueryEscape(rawCode)
	if state != "" {
		redirectURL += "&state=" + url.QueryEscape(state)
	}

	// If user has no passkeys and the browser supports WebAuthn, show the prompt.
	// redirectURL is server-built from the registered redirect_uri (validated in
	// the authorize flow) plus the issued code/state, so we carry it inside the
	// signed prompt cookie rather than as a client-controllable query parameter.
	if r.FormValue("webauthn_supported") == "1" && h.shouldPromptPasskey(userID) {
		h.setPromptSession(w, userID, redirectURL)
		http.Redirect(w, r, "/oauth/passkey-prompt", http.StatusFound)
		return
	}

	h.clientRedirect(w, redirectURL)
}

// authorizePasskey accepts an access_token from a WebAuthn login and issues an OAuth authorization code.
// This bridges the passkey ceremony (which happens in JavaScript on the login page) into the OAuth flow.
func (h *oauthHandler) authorizePasskey(w http.ResponseWriter, r *http.Request) {
	wantsJSON := r.Header.Get("Accept") == "application/json"
	errResp := func(status int, title, message string) {
		if wantsJSON {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]string{"error": title, "message": message}) //nolint:errcheck
			return
		}
		h.renderError(w, title, message)
	}

	if !httputil.CheckOrigin(r) {
		errResp(http.StatusForbidden, "origin_mismatch", "Origin mismatch.")
		return
	}

	if err := r.ParseForm(); err != nil {
		errResp(http.StatusBadRequest, "bad_request", "Could not parse form.")
		return
	}

	accessToken := r.FormValue("access_token")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	codeChallenge := r.FormValue("code_challenge")

	if accessToken == "" || clientID == "" || redirectURI == "" || codeChallenge == "" {
		errResp(http.StatusBadRequest, "missing_parameters", "Missing required parameters.")
		return
	}

	if h.tokenIssuer == nil {
		errResp(http.StatusServiceUnavailable, "not_configured", "Passkey login is not configured.")
		return
	}

	claims, err := h.tokenIssuer.Parse(r.Context(), accessToken)
	if err != nil {
		errResp(http.StatusUnauthorized, "invalid_token", "Invalid or expired token.")
		return
	}

	// Re-validate client
	_, err = h.svc.ValidateAuthorizeRequest(clientID, redirectURI)
	if err != nil {
		errResp(http.StatusBadRequest, "invalid_client", "Client or redirect URI is invalid.")
		return
	}

	rawCode, err := h.svc.AuthorizeByUserID(clientID, redirectURI, claims.UserID, claims.Username, codeChallenge, httputil.ExtractClientIP(r, h.trustProxy))
	if err != nil {
		errResp(http.StatusInternalServerError, "authorization_failed", "Could not complete authorization.")
		return
	}

	redirectURL := redirectURI + "?code=" + url.QueryEscape(rawCode)
	if state != "" {
		redirectURL += "&state=" + url.QueryEscape(state)
	}

	// If the caller accepts JSON (fetch from passkey-login.js), return the redirect URL
	// instead of a 302 — this avoids CSP form-action issues with dynamic form submission.
	if r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"redirect_uri": redirectURL}) //nolint:errcheck
		return
	}

	h.clientRedirect(w, redirectURL)
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
	case "client_credentials":
		h.tokenClientCredentials(w, r)
	case service.GrantTypeDeviceCode:
		h.tokenDeviceCode(w, r)
	default:
		oauthError(w, "unsupported_grant_type", "grant_type must be 'authorization_code', 'refresh_token', 'client_credentials', or '"+service.GrantTypeDeviceCode+"'")
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
		case errors.Is(err, service.ErrInvalidAuthCode),
			errors.Is(err, service.ErrAuthCodeAlreadyUsed),
			errors.Is(err, service.ErrAuthCodeExpired):
			oauthError(w, "invalid_grant", "The authorization code is invalid or has expired.")
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

func (h *oauthHandler) tokenClientCredentials(w http.ResponseWriter, r *http.Request) {
	creds, ok := extractClientCredentials(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Basic")
		oauthErrorWithStatus(w, http.StatusUnauthorized, "invalid_client", "Client authentication required.")
		return
	}

	client, err := h.svc.GetClient(creds.ClientID)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Basic")
		oauthErrorWithStatus(w, http.StatusUnauthorized, "invalid_client", "Unknown client.")
		return
	}

	// Verify the client's auth method matches.
	// Treat empty string same as "none" for safety.
	authMethod := client.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "none"
	}
	if authMethod == "none" {
		oauthError(w, "invalid_client", "This client is not configured for client authentication.")
		return
	}
	if authMethod != creds.Method {
		oauthError(w, "invalid_client", "Client authentication method mismatch.")
		return
	}

	if !verifyClientSecret(client, creds.ClientSecret) {
		w.Header().Set("WWW-Authenticate", "Basic")
		oauthErrorWithStatus(w, http.StatusUnauthorized, "invalid_client", "Invalid client secret.")
		return
	}

	requestedScope := r.FormValue("scope")
	ip := httputil.ExtractClientIP(r, h.trustProxy)

	result, err := h.svc.IssueClientCredentials(client, requestedScope, ip)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrUnauthorizedClient):
			oauthError(w, "unauthorized_client", "This client is not authorized for client_credentials grant.")
		case errors.Is(err, service.ErrInvalidScope):
			oauthError(w, "invalid_scope", "Requested scope exceeds client's allowed scopes.")
		default:
			oauthError(w, "server_error", "An unexpected error occurred.")
		}
		return
	}

	jsonOK(w, ccTokenResponse(result))
}

// introspect implements RFC 7662 token introspection.
func (h *oauthHandler) introspect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request", "Could not parse form.")
		return
	}

	// Require client authentication
	creds, ok := extractClientCredentials(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Basic")
		oauthErrorWithStatus(w, http.StatusUnauthorized, "invalid_client", "Client authentication required.")
		return
	}

	client, err := h.svc.GetClient(creds.ClientID)
	if err != nil || !verifyClientSecret(client, creds.ClientSecret) {
		w.Header().Set("WWW-Authenticate", "Basic")
		oauthErrorWithStatus(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials.")
		return
	}

	token := r.FormValue("token")
	if token == "" {
		oauthError(w, "invalid_request", "token parameter is required")
		return
	}

	// Try parsing as service token
	if h.tokenIssuer != nil {
		if sc, err := h.tokenIssuer.ParseServiceToken(r.Context(), token); err == nil {
			// Only the client that owns the token may introspect it.
			if sc.ClientID != creds.ClientID {
				jsonOK(w, map[string]any{"active": false})
				return
			}
			resp := map[string]any{
				"active":     true,
				"sub":        sc.ClientID,
				"client_id":  sc.ClientID,
				"aud":        sc.Audience,
				"scope":      sc.Scope,
				"token_type": "Bearer",
				"jti":        sc.JTI,
			}
			if sc.ExpiresAt != 0 {
				resp["exp"] = sc.ExpiresAt
			}
			if sc.IssuedAt != 0 {
				resp["iat"] = sc.IssuedAt
			}
			jsonOK(w, resp)
			return
		}
	}

	// Try parsing as user token. Only the client whose configured audience
	// matches the token's aud claim may introspect it (RFC 7662 §2.1). User
	// tokens minted through the OAuth/PKCE flow carry the client's audience;
	// direct-API-login tokens carry none and therefore introspect as inactive
	// against every client — the safe default.
	if h.tokenIssuer != nil {
		if uc, err := h.tokenIssuer.Parse(r.Context(), token); err == nil {
			if client.Audience == "" || uc.Audience != client.Audience {
				jsonOK(w, map[string]any{"active": false})
				return
			}
			jsonOK(w, map[string]any{
				"active":     true,
				"sub":        uc.UserID,
				"username":   uc.Username,
				"token_type": "Bearer",
			})
			return
		}
	}

	// Token is invalid or expired
	jsonOK(w, map[string]any{"active": false})
}

// discovery serves RFC 8414 authorization server metadata.
func (h *oauthHandler) discovery(w http.ResponseWriter, r *http.Request) {
	// Use the configured issuer from the token issuer — never trust the Host header.
	issuer := h.tokenIssuer.Issuer()

	grantTypes := []string{"authorization_code", "client_credentials", "refresh_token"}
	meta := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth/authorize",
		"token_endpoint":                        issuer + "/oauth/token",
		"introspection_endpoint":                issuer + "/oauth/introspect",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"response_types_supported":              []string{"code"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	if h.deviceSvc != nil {
		grantTypes = append(grantTypes, service.GrantTypeDeviceCode)
		meta["device_authorization_endpoint"] = issuer + "/oauth/device_authorization"
	}
	meta["grant_types_supported"] = grantTypes

	jsonOK(w, meta)
}

type ccTokenResponseBody struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

func ccTokenResponse(r *service.ClientCredentialsResult) ccTokenResponseBody {
	return ccTokenResponseBody{
		AccessToken: r.AccessToken,
		TokenType:   r.TokenType,
		ExpiresIn:   r.ExpiresIn,
		Scope:       r.Scope,
	}
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
	oauthErrorWithStatus(w, http.StatusBadRequest, code, description)
}

func oauthErrorWithStatus(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(oauthErrorBody{Error: code, ErrorDescription: description}) //nolint:errcheck
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// clientRedirect renders an intermediate page that redirects the browser to the
// given URL via JavaScript. This avoids CSP form-action restrictions that block
// 302 redirects to custom URL schemes (e.g. myapp://callback) after form POST.
func (h *oauthHandler) clientRedirect(w http.ResponseWriter, redirectURL string) {
	// Mark URL as trusted so html/template doesn't sanitize custom schemes (e.g. myapp://)
	// to #ZgotmplZ. The URL was already validated against the registered redirect_uri.
	h.render(w, "oauth_redirect.html", map[string]any{
		"HideNav":     true,
		"RedirectURL": template.URL(redirectURL),
	})
}

// --- Passkey prompt (shown after OAuth password login if user has no passkeys) ---

const oauthPromptCookie = "oauth_passkey_prompt"

// shouldPromptPasskey returns true if WebAuthn is enabled and the user has no passkeys.
func (h *oauthHandler) shouldPromptPasskey(userID string) bool {
	if h.webauthnSvc == nil || h.sessionKey == "" {
		return false
	}
	creds, err := h.webauthnSvc.ListCredentials(userID)
	if err != nil {
		return false
	}
	return len(creds) == 0
}

// promptClaims are the claims carried by the short-lived passkey-prompt cookie.
// next holds the server-built post-login redirect URL (the registered
// redirect_uri plus code/state). Because the cookie is HMAC-signed by the
// server, next is trusted and cannot be tampered with by the client — this is
// what lets the prompt page render it as a "Not now" deep link (including custom
// app schemes) without an open-redirect / XSS risk.
type promptClaims struct {
	Next string `json:"next,omitempty"`
	jwt.RegisteredClaims
}

// setPromptSession sets a short-lived cookie that identifies the user during the
// passkey prompt and carries the server-validated next redirect URL.
func (h *oauthHandler) setPromptSession(w http.ResponseWriter, userID, next string) {
	claims := promptClaims{
		Next: next,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(h.sessionKey))
	if err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oauthPromptCookie,
		Value:    tokenStr,
		Path:     "/oauth",
		MaxAge:   300,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// promptSession returns the user ID and trusted next URL from the prompt
// session cookie. userID is "" when the cookie is missing or invalid.
func (h *oauthHandler) promptSession(r *http.Request) (userID, next string) {
	cookie, err := r.Cookie(oauthPromptCookie)
	if err != nil {
		return "", ""
	}
	claims := &promptClaims{}
	token, err := jwt.ParseWithClaims(cookie.Value, claims,
		func(t *jwt.Token) (any, error) { return []byte(h.sessionKey), nil },
		jwt.WithExpirationRequired(),
	)
	if err != nil || !token.Valid {
		return "", ""
	}
	return claims.Subject, claims.Next
}

// promptUserID returns the user ID from the prompt session cookie, or "".
func (h *oauthHandler) promptUserID(r *http.Request) string {
	userID, _ := h.promptSession(r)
	return userID
}

// clearPromptSession removes the prompt cookie.
func (h *oauthHandler) clearPromptSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthPromptCookie,
		Value:    "",
		Path:     "/oauth",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// headerOrQuery returns the named request header if set, else the named query
// parameter. Mirrors the helpers in the admin and api handler packages so the
// passkey prompt accepts the X-Challenge-ID / X-Passkey-Name headers sent by
// passkey-prompt.js.
func headerOrQuery(r *http.Request, header, query string) string {
	if v := r.Header.Get(header); v != "" {
		return v
	}
	return r.URL.Query().Get(query)
}

// passkeyPrompt renders the passkey registration prompt page during OAuth flow.
func (h *oauthHandler) passkeyPrompt(w http.ResponseWriter, r *http.Request) {
	userID, next := h.promptSession(r)
	if userID == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	data := map[string]any{
		"HideNav":   true,
		"OAuthFlow": true,
	}
	// next comes from the HMAC-signed prompt cookie, where it was set to the
	// server-built redirect URL (registered redirect_uri + code/state). It is
	// therefore trusted and may carry a custom app scheme, so template.URL is
	// justified. We deliberately ignore any ?next= query parameter, which an
	// attacker could control and use for an open redirect. If no trusted next
	// is present, the "Not now" link is simply omitted.
	if next != "" {
		data["SkipURL"] = template.URL(next) //nolint:gosec // next is from the HMAC-signed prompt cookie, not client input
	}
	h.render(w, "passkey_prompt.html", data)
}

// passkeyPromptRegisterBegin starts registration using the prompt session.
func (h *oauthHandler) passkeyPromptRegisterBegin(w http.ResponseWriter, r *http.Request) {
	userID := h.promptUserID(r)
	if userID == "" || h.webauthnSvc == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	creation, challengeID, err := h.webauthnSvc.BeginRegistration(userID)
	if err != nil {
		http.Error(w, "failed to begin registration", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"publicKey":    creation.Response,
		"challenge_id": challengeID,
	})
}

// passkeyPromptRegisterFinish completes registration using the prompt session.
func (h *oauthHandler) passkeyPromptRegisterFinish(w http.ResponseWriter, r *http.Request) {
	userID := h.promptUserID(r)
	if userID == "" || h.webauthnSvc == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// passkey-prompt.js sends these as headers (X-Challenge-ID / X-Passkey-Name),
	// matching the admin and API finish handlers; accept the query form too.
	challengeID := headerOrQuery(r, "X-Challenge-ID", "challenge_id")
	name := headerOrQuery(r, "X-Passkey-Name", "name")
	if challengeID == "" {
		http.Error(w, "challenge_id required", http.StatusBadRequest)
		return
	}

	_, err := h.webauthnSvc.FinishRegistration(userID, challengeID, name, r)
	if err != nil {
		http.Error(w, "registration failed", http.StatusBadRequest)
		return
	}

	h.clearPromptSession(w)
	w.WriteHeader(http.StatusCreated)
}
