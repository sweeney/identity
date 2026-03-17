// BFF (Backend-for-Frontend) OAuth demo.
//
// Tokens never reach the browser. The browser gets an HttpOnly session cookie;
// the BFF holds access/refresh tokens server-side and proxies API calls.
//
// Usage:
//
//	1. Register an OAuth client in the admin UI:
//	   - Client ID:     bff-demo
//	   - Name:          BFF Demo
//	   - Redirect URI:  http://localhost:9092/callback
//
//	2. Run this demo:
//	   go run ./examples/bff-demo
//
//	3. Open http://localhost:9092 in your browser
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
	"time"
)

const (
	identityBase = "http://localhost:8181"
	clientID     = "bff-demo"
	redirectURI  = "http://localhost:9092/callback"
	listenAddr   = ":9092"
	cookieName   = "bff_session"
)

// ── Session store ────────────────────────────────────────────────────

type session struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	Username     string
	Role         string
}

var (
	mu       sync.RWMutex
	sessions = map[string]*session{}
)

func newSessionID() string {
	buf := make([]byte, 32)
	io.ReadFull(rand.Reader, buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func getSession(r *http.Request) *session {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	mu.RLock()
	defer mu.RUnlock()
	return sessions[cookie.Value]
}

func setSession(w http.ResponseWriter, s *session) string {
	id := newSessionID()
	mu.Lock()
	sessions[id] = s
	mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    id,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return id
}

func updateSession(r *http.Request, s *session) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return
	}
	mu.Lock()
	sessions[cookie.Value] = s
	mu.Unlock()
}

func deleteSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return
	}
	mu.Lock()
	delete(sessions, cookie.Value)
	mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// ── PKCE state (short-lived, per login attempt) ──────────────────────

var (
	pkceMu    sync.Mutex
	pkceStore = map[string]string{} // state -> verifier
)

// ── Token types ──────────────────────────────────────────────────────

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

// ── Main ─────────────────────────────────────────────────────────────

func main() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/refresh", handleRefresh)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/api/me", handleProxyMe)

	log.Printf("BFF demo listening on http://localhost%s", listenAddr)
	log.Printf("Register client_id=%q with redirect_uri=%q in the admin UI", clientID, redirectURI)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

// ── Home page ────────────────────────────────────────────────────────

var homeTmpl = template.Must(template.New("home").Parse(`<!DOCTYPE html>
<html><head><title>BFF Demo</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem; color: #1a1a2e; }
  h1 { color: #02aaa2; }
  pre { background: #f4f4f4; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; }
  button { background: #02aaa2; color: #fff; border: none; padding: 0.5rem 1.25rem; border-radius: 6px; cursor: pointer; font-size: 0.9rem; margin-right: 0.5rem; }
  button:hover { background: #028f88; }
  button.danger { background: #d63031; }
  button.danger:hover { background: #b71c1c; }
  .card { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 6px; padding: 1rem; margin: 1rem 0; }
  .card h3 { margin-top: 0; }
  .error { border-color: #d63031; }
  .error h3 { color: #d63031; }
  .secure { background: #e8f5e9; border-color: #4caf50; }
  .secure h3 { color: #2e7d32; }
  code { background: #f4f4f4; padding: 0.15em 0.4em; border-radius: 3px; font-size: 0.9em; }
</style>
</head><body>
<h1>BFF Demo</h1>
<p>Backend-for-Frontend pattern — tokens are held server-side. The browser only has an HttpOnly session cookie.</p>

{{if .Error}}
<div class="card error">
  <h3>Session Ended</h3>
  <p>{{.Error}}</p>
</div>
{{end}}

{{if .User}}
  <div class="card">
    <h3>Authenticated as {{.User.Username}}</h3>
    <p>Role: <strong>{{.User.Role}}</strong> · Active: <strong>{{.User.IsActive}}</strong></p>
  </div>

  <div class="card secure">
    <h3>Security: what the browser can see</h3>
    <p>Open DevTools → Application → Cookies. You'll find a single <code>bff_session</code> cookie
       that is <strong>HttpOnly</strong> (invisible to JavaScript) and <strong>Secure</strong>.</p>
    <p>No tokens are stored in localStorage, sessionStorage, or any JavaScript-accessible location.
       An XSS attack cannot steal your tokens.</p>
  </div>

  <p>
    <form method="POST" action="/refresh" style="display:inline"><button>Refresh Tokens (server-side)</button></form>
    <form method="POST" action="/logout" style="display:inline"><button class="danger">Logout</button></form>
  </p>

  <h3>Proxied API call: /api/me</h3>
  <p>The browser calls <code>GET /api/me</code> on this BFF. The BFF attaches the access token and proxies to the Identity server.</p>
  <pre id="api-result">Click the button to test.</pre>
  <button onclick="fetchMe()">Call /api/me</button>

  <script>
  async function fetchMe() {
    const el = document.getElementById('api-result');
    el.textContent = 'Loading...';
    try {
      const resp = await fetch('/api/me');
      const body = await resp.json();
      el.textContent = JSON.stringify(body, null, 2);
    } catch(e) {
      el.textContent = 'Error: ' + e.message;
    }
  }
  </script>

{{else}}
  <div class="card">
    <h3>How the BFF pattern works</h3>
    <ol>
      <li>Click "Sign in" — the BFF generates PKCE and redirects you to the Identity server</li>
      <li>You log in on the Identity server (neither the browser nor the BFF sees your password)</li>
      <li>Identity server redirects back to the BFF's <code>/callback</code> with an authorization code</li>
      <li>The BFF exchanges the code for tokens <strong>server-to-server</strong> — the browser never sees them</li>
      <li>The BFF creates a session and sets an HttpOnly cookie</li>
      <li>API calls go through the BFF, which attaches the access token from its session store</li>
    </ol>
  </div>

  <div class="card secure">
    <h3>Why this is more secure than the SPA approach</h3>
    <p>In the SPA demo, tokens live in <code>localStorage</code> — any XSS vulnerability can steal them.
       Here, tokens exist only in the BFF's memory. The browser has no way to access them.</p>
  </div>

  <form method="POST" action="/login"><button>Sign in with Identity</button></form>
{{end}}
</body></html>`))

func handleHome(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	s := getSession(r)
	if s != nil {
		user, err := fetchMe(s.AccessToken)
		if err != nil {
			// Try refresh
			newTok, refreshErr := doRefresh(s.RefreshToken)
			if refreshErr != nil {
				deleteSession(w, r)
				data["Error"] = "Your session was ended — the token could not be refreshed."
			} else {
				s.AccessToken = newTok.AccessToken
				s.RefreshToken = newTok.RefreshToken
				s.ExpiresAt = time.Now().Add(time.Duration(newTok.ExpiresIn) * time.Second)
				updateSession(r, s)
				user, err = fetchMe(s.AccessToken)
				if err != nil {
					deleteSession(w, r)
					data["Error"] = "Session could not be restored."
				} else {
					data["User"] = user
				}
			}
		} else {
			data["User"] = user
		}
	}
	homeTmpl.Execute(w, data)
}

// ── Login: generate PKCE, redirect to Identity ──────────────────────

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	verifier, _ := generateRandom(32)
	state, _ := generateRandom(16)
	challenge := pkceChallenge(verifier)

	pkceMu.Lock()
	pkceStore[state] = verifier
	pkceMu.Unlock()

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}

	http.Redirect(w, r, identityBase+"/oauth/authorize?"+params.Encode(), http.StatusFound)
}

// ── Callback: exchange code server-to-server ─────────────────────────

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	pkceMu.Lock()
	verifier, ok := pkceStore[state]
	delete(pkceStore, state)
	pkceMu.Unlock()

	if !ok {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}

	if code == "" {
		http.Error(w, "no authorization code", http.StatusBadRequest)
		return
	}

	// Server-to-server token exchange — browser never sees this
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}

	resp, err := http.Post(identityBase+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
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
		http.Error(w, "bad token response", http.StatusInternalServerError)
		return
	}

	// Fetch user info to store in session
	user, err := fetchMe(tok.AccessToken)
	if err != nil {
		http.Error(w, "failed to fetch user info", http.StatusInternalServerError)
		return
	}

	// Create server-side session — browser only gets the session ID cookie
	setSession(w, &session{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second),
		Username:     user.Username,
		Role:         user.Role,
	})

	log.Printf("Session created for %s", user.Username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ── Refresh ──────────────────────────────────────────────────────────

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	s := getSession(r)
	if s == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	newTok, err := doRefresh(s.RefreshToken)
	if err != nil {
		log.Printf("Refresh failed: %v", err)
		deleteSession(w, r)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	s.AccessToken = newTok.AccessToken
	s.RefreshToken = newTok.RefreshToken
	s.ExpiresAt = time.Now().Add(time.Duration(newTok.ExpiresIn) * time.Second)
	updateSession(r, s)

	log.Printf("Tokens refreshed for %s", s.Username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ── Logout ───────────────────────────────────────────────────────────

func handleLogout(w http.ResponseWriter, r *http.Request) {
	deleteSession(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ── Proxy: /api/me → Identity /api/v1/auth/me ───────────────────────

func handleProxyMe(w http.ResponseWriter, r *http.Request) {
	s := getSession(r)
	if s == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "not authenticated"})
		return
	}

	req, _ := http.NewRequest("GET", identityBase+"/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// If token expired, try refresh and retry
	if resp.StatusCode == http.StatusUnauthorized {
		newTok, refreshErr := doRefresh(s.RefreshToken)
		if refreshErr != nil {
			deleteSession(w, r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "session expired"})
			return
		}
		s.AccessToken = newTok.AccessToken
		s.RefreshToken = newTok.RefreshToken
		s.ExpiresAt = time.Now().Add(time.Duration(newTok.ExpiresIn) * time.Second)
		updateSession(r, s)

		// Retry
		req, _ = http.NewRequest("GET", identityBase+"/api/v1/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+s.AccessToken)
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "proxy error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
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

func generateRandom(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
