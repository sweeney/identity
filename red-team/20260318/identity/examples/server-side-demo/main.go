// Demo OAuth client that exercises the full Authorization Code + PKCE flow
// against the Identity server.
//
// Usage:
//
//	1. Register an OAuth client in the admin UI:
//	   - Client ID:     demo
//	   - Name:          OAuth Demo
//	   - Redirect URI:  http://localhost:9090/callback
//
//	2. Run this demo:
//	   go run ./examples/oauth-demo
//
//	3. Open http://localhost:9090 in your browser
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const (
	identityBase = "http://localhost:8181"
	clientID     = "demo"
	redirectURI  = "http://localhost:9090/callback"
	listenAddr   = ":9090"
)

// In-memory session store (demo only — not production-safe)
var (
	mu       sync.Mutex
	verifier string
	state    string
	tokens   *tokenResponse
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type meResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	IsActive bool   `json:"is_active"`
}

func main() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/refresh", handleRefresh)
	http.HandleFunc("/logout", handleLogout)

	log.Printf("OAuth demo client listening on http://localhost%s", listenAddr)
	log.Printf("Make sure the Identity server is running at %s", identityBase)
	log.Printf("Register client_id=%q with redirect_uri=%q in the admin UI first", clientID, redirectURI)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

// ── Home page ────────────────────────────────────────────────────────

var homeTmpl = template.Must(template.New("home").Parse(`<!DOCTYPE html>
<html><head><title>OAuth Demo</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem; color: #1a1a2e; }
  pre { background: #f4f4f4; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; }
  a, button { color: #02aaa2; }
  button { background: #02aaa2; color: #fff; border: none; padding: 0.5rem 1.25rem; border-radius: 6px; cursor: pointer; font-size: 0.9rem; }
  button:hover { background: #028f88; }
  .step { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 6px; padding: 1rem; margin: 1rem 0; }
  .step h3 { margin-top: 0; }
  h1 { color: #02aaa2; }
</style>
</head><body>
<h1>OAuth Demo Client</h1>
{{if .User}}
  <div class="step">
    <h3>Authenticated as {{.User.Username}}</h3>
    <p>Role: <strong>{{.User.Role}}</strong> &middot; Active: <strong>{{.User.IsActive}}</strong></p>
  </div>
  <h3>Access Token</h3>
  <pre>{{.Tokens.AccessToken}}</pre>
  <h3>Refresh Token</h3>
  <pre>{{.Tokens.RefreshToken}}</pre>
  <p>Expires in: {{.Tokens.ExpiresIn}} seconds</p>
  <p>
    <form method="POST" action="/refresh" style="display:inline"><button>Refresh Tokens</button></form>
    &nbsp;
    <form method="POST" action="/logout" style="display:inline"><button style="background:#d63031">Logout</button></form>
  </p>
{{else}}
  {{if .SessionExpired}}
  <div class="step" style="border-color:#d63031">
    <h3 style="color:#d63031">Session Ended</h3>
    <p>Your session was ended — the token could not be refreshed. This happens when your account is deactivated, the refresh token expires, or token theft is detected.</p>
  </div>
  {{end}}
  <p>This demo walks through the OAuth 2.0 Authorization Code + PKCE flow.</p>
  <div class="step">
    <h3>How it works</h3>
    <ol>
      <li>Click "Sign in" below</li>
      <li>This app generates a PKCE <code>code_verifier</code> and redirects you to the Identity server</li>
      <li>You log in on the Identity server (the app never sees your password)</li>
      <li>Identity server redirects back here with an authorization <code>code</code></li>
      <li>This app exchanges the code + verifier for tokens</li>
    </ol>
  </div>
  <form method="POST" action="/login"><button>Sign in with Identity</button></form>
{{end}}
</body></html>`))

func handleHome(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	t := tokens
	mu.Unlock()

	data := map[string]any{}
	if t != nil {
		user, err := fetchMe(t.AccessToken)
		if err != nil {
			// Access token failed — try refreshing
			log.Printf("GET /auth/me failed (%v), attempting refresh", err)
			newTok, refreshErr := doRefresh(t.RefreshToken)
			if refreshErr != nil {
				// Refresh also failed — session is dead, clear tokens
				log.Printf("Refresh failed (%v), clearing session", refreshErr)
				mu.Lock()
				tokens = nil
				mu.Unlock()
				data["SessionExpired"] = true
			} else {
				mu.Lock()
				tokens = newTok
				t = newTok
				mu.Unlock()
				user, err = fetchMe(t.AccessToken)
				if err != nil {
					// Still failing after refresh — give up
					mu.Lock()
					tokens = nil
					mu.Unlock()
					data["SessionExpired"] = true
				} else {
					data["User"] = user
					data["Tokens"] = t
				}
			}
		} else {
			data["User"] = user
			data["Tokens"] = t
		}
	}
	homeTmpl.Execute(w, data)
}

// ── Login: generate PKCE + redirect ──────────────────────────────────

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	v, err := generateVerifier()
	if err != nil {
		http.Error(w, "failed to generate verifier", 500)
		return
	}
	s, err := generateState()
	if err != nil {
		http.Error(w, "failed to generate state", 500)
		return
	}

	mu.Lock()
	verifier = v
	state = s
	tokens = nil
	mu.Unlock()

	challenge := pkceChallenge(v)

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {s},
	}

	http.Redirect(w, r, identityBase+"/oauth/authorize?"+params.Encode(), http.StatusFound)
}

// ── Callback: exchange code for tokens ───────────────────────────────

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	returnedState := r.URL.Query().Get("state")

	mu.Lock()
	expectedState := state
	v := verifier
	mu.Unlock()

	if returnedState != expectedState {
		http.Error(w, fmt.Sprintf("state mismatch: expected %q, got %q", expectedState, returnedState), 400)
		return
	}

	if code == "" {
		errCode := r.URL.Query().Get("error")
		http.Error(w, "no code returned: "+errCode, 400)
		return
	}

	// Exchange code for tokens
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {v},
	}

	resp, err := http.Post(identityBase+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), 500)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		http.Error(w, "token exchange error: "+string(body), resp.StatusCode)
		return
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		http.Error(w, "bad token response: "+err.Error(), 500)
		return
	}

	mu.Lock()
	tokens = &tok
	mu.Unlock()

	log.Printf("Token exchange successful — access_token=%s...", tok.AccessToken[:20])
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ── Refresh tokens ───────────────────────────────────────────────────

// doRefresh exchanges a refresh token for a new token pair.
func doRefresh(refreshToken string) (*tokenResponse, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	resp, err := http.Post(identityBase+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, body)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("bad response: %w", err)
	}
	return &tok, nil
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	t := tokens
	mu.Unlock()

	if t == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	newTok, err := doRefresh(t.RefreshToken)
	if err != nil {
		// Refresh failed — clear tokens and redirect to home (shows session-expired)
		log.Printf("Manual refresh failed: %v", err)
		mu.Lock()
		tokens = nil
		mu.Unlock()
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	mu.Lock()
	tokens = newTok
	mu.Unlock()

	log.Printf("Token refresh successful")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ── Logout ───────────────────────────────────────────────────────────

func handleLogout(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	tokens = nil
	mu.Unlock()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ── Helpers ──────────────────────────────────────────────────────────

func fetchMe(accessToken string) (*meResponse, error) {
	req, _ := http.NewRequest("GET", identityBase+"/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET /auth/me returned %d", resp.StatusCode)
	}
	var me meResponse
	return &me, json.NewDecoder(resp.Body).Decode(&me)
}

func generateVerifier() (string, error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func generateState() (string, error) {
	buf := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
