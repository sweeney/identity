// Demo service-to-service client that uses the OAuth 2.0 Client Credentials
// flow to authenticate with the Identity server.
//
// This demonstrates how a backend service (cron job, microservice, worker)
// obtains an access token without any user involvement, then uses it to call
// a protected API.
//
// # Quick start (zero manual steps)
//
// Start the server, then run:
//
//	ADMIN_PASSWORD=<your-admin-password> go run ./examples/client-credentials-demo
//
// The demo will create the OAuth client and generate a secret automatically,
// then run the full client credentials flow.
//
// # Manual setup (if you prefer)
//
//  1. Register an OAuth client in the admin UI at /admin/oauth:
//     - Client ID:                    worker
//     - Name:                         Background Worker
//     - Grant Types:                  client_credentials (check the box)
//     - Token Endpoint Auth Method:   client_secret_basic
//     - Scopes:                       read:users
//     - Audience:                     http://localhost:8181
//     - Redirect URIs:                (leave empty — not needed)
//
//  2. Generate a client secret on the edit page and copy it.
//
//  3. Run:
//     CLIENT_SECRET=<paste-secret> go run ./examples/client-credentials-demo
//
// The demo will:
//   - Obtain an access token using client_credentials
//   - Print the token's claims (decoded JWT)
//   - Introspect its own token
//   - Call a protected endpoint (expected 403 — service tokens have no user identity)
//   - Re-authenticate, demonstrating the re-auth pattern
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// ── Configuration ────────────────────────────────────────────────────

const clientID = "worker"

// identityBase is the Identity server URL.
// Override with IDENTITY_BASE env var (default: http://localhost:8181).
var identityBase = func() string {
	if v := os.Getenv("IDENTITY_BASE"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:8181"
}()

// ── Types ────────────────────────────────────────────────────────────

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type oauthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

type discoveryResponse struct {
	Issuer                string   `json:"issuer"`
	TokenEndpoint         string   `json:"token_endpoint"`
	IntrospectionEndpoint string   `json:"introspection_endpoint"`
	JWKSUri               string   `json:"jwks_uri"`
	GrantTypesSupported   []string `json:"grant_types_supported"`
}

type introspectResponse struct {
	Active   bool   `json:"active"`
	Sub      string `json:"sub"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	Exp      int64  `json:"exp"`
}

// ── Main ─────────────────────────────────────────────────────────────

func main() {
	clientSecret := os.Getenv("CLIENT_SECRET")
	adminPassword := os.Getenv("ADMIN_PASSWORD")
	adminUsername := os.Getenv("ADMIN_USERNAME")
	if adminUsername == "" {
		adminUsername = "admin"
	}

	if clientSecret == "" && adminPassword == "" {
		log.Fatal("Set CLIENT_SECRET to use an existing client secret, or\n" +
			"set ADMIN_PASSWORD to auto-create the client:\n\n" +
			"  ADMIN_PASSWORD=<password> go run ./examples/client-credentials-demo\n")
	}

	// Auto-setup: create the OAuth client and generate a secret using admin credentials.
	if clientSecret == "" {
		log.Println("=== Auto-setup ===")
		log.Printf("   Logging in as %q to create OAuth client...", adminUsername)
		var err error
		clientSecret, err = setup(adminUsername, adminPassword)
		if err != nil {
			log.Fatalf("   Setup failed: %v\n\n"+
				"   Tip: start the server first:\n"+
				"     ADMIN_USERNAME=admin ADMIN_PASSWORD=%s ./bin/identity-server\n",
				err, adminPassword)
		}
		log.Println("   OAuth client 'worker' ready.")
		log.Println()
	}

	log.Println("=== Client Credentials Demo ===")
	log.Println()

	// ── Step 1: Discover server metadata (optional but good practice) ──

	log.Println("1. Fetching server metadata...")
	disc, err := fetchDiscovery()
	if err != nil {
		log.Printf("   Discovery failed (non-fatal): %v", err)
		log.Println("   Falling back to default endpoints")
	} else {
		log.Printf("   Issuer:            %s", disc.Issuer)
		log.Printf("   Token endpoint:    %s", disc.TokenEndpoint)
		log.Printf("   JWKS URI:          %s", disc.JWKSUri)
		log.Printf("   Grant types:       %v", disc.GrantTypesSupported)
	}
	log.Println()

	// ── Step 2: Obtain an access token ──────────────────────────────

	log.Println("2. Requesting access token (client_credentials)...")
	tok, err := authenticate(clientSecret, "read:users")
	if err != nil {
		log.Fatalf("   Authentication failed: %v", err)
	}
	log.Printf("   Token type:   %s", tok.TokenType)
	log.Printf("   Expires in:   %d seconds", tok.ExpiresIn)
	log.Printf("   Scope:        %s", tok.Scope)
	log.Printf("   Access token: %s...%s", tok.AccessToken[:20], tok.AccessToken[len(tok.AccessToken)-10:])
	log.Println()

	// ── Step 3: Decode the JWT to see the claims ────────────────────

	log.Println("3. JWT claims (decoded):")
	printJWTClaims(tok.AccessToken)
	log.Println()

	// ── Step 4: Introspect the token ────────────────────────────────

	log.Println("4. Introspecting own token...")
	intro, err := introspect(clientSecret, tok.AccessToken)
	if err != nil {
		log.Printf("   Introspection failed: %v", err)
	} else {
		log.Printf("   Active:    %v", intro.Active)
		log.Printf("   Subject:   %s", intro.Sub)
		log.Printf("   Client ID: %s", intro.ClientID)
		log.Printf("   Scope:     %s", intro.Scope)
		if intro.Exp > 0 {
			log.Printf("   Expires:   %s", time.Unix(intro.Exp, 0).Format(time.RFC3339))
		}
	}
	log.Println()

	// ── Step 5: Use the token to call a protected endpoint ──────────

	log.Println("5. Calling GET /api/v1/auth/me with service token...")
	body, status, err := callAPI(tok.AccessToken, "GET", "/api/v1/auth/me")
	if err != nil {
		log.Printf("   Request failed: %v", err)
	} else {
		log.Printf("   Status: %d", status)
		if status == 401 || status == 403 {
			log.Printf("   Expected — service tokens don't have a user identity")
			log.Printf("   Response: %s", body)
		} else {
			log.Printf("   Response: %s", body)
		}
	}
	log.Println()

	// ── Step 6: Demonstrate re-authentication ───────────────────────

	log.Println("6. Re-authenticating (simulating token expiry)...")
	tok2, err := authenticate(clientSecret, "read:users")
	if err != nil {
		log.Printf("   Re-authentication failed: %v", err)
		log.Printf("   (In production, re-auth happens every 15 minutes — not back-to-back)")
	} else {
		log.Printf("   New token obtained (different from first: %v)",
			tok.AccessToken != tok2.AccessToken)
	}
	log.Println()

	log.Println("=== Demo complete ===")
	log.Println()
	log.Println("In a real service, you would:")
	log.Println("  1. Call authenticate() on startup or lazily on first API call")
	log.Println("  2. Cache the token in memory")
	log.Println("  3. Re-authenticate when the token expires (check expires_in)")
	log.Println("  4. Use a mutex if multiple goroutines share the token")
}

// ── Setup ─────────────────────────────────────────────────────────────

// setup uses the admin credentials to create the 'worker' OAuth client and
// generate a client secret. Returns the generated secret.
// Safe to call repeatedly — skips client creation if it already exists.
func setup(adminUser, adminPass string) (string, error) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// 1. Log in to the admin UI to get a session cookie.
	loginForm := url.Values{
		"username": {adminUser},
		"password": {adminPass},
	}
	resp, err := client.PostForm(identityBase+"/admin/login", loginForm)
	if err != nil {
		return "", fmt.Errorf("admin login: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("admin login returned HTTP %d — check ADMIN_PASSWORD", resp.StatusCode)
	}

	// 2. Fetch the CSRF token from the new-client form.
	csrf, err := fetchCSRF(client, identityBase+"/admin/oauth/new")
	if err != nil {
		return "", fmt.Errorf("fetch CSRF: %w", err)
	}

	// 3. Create the OAuth client (ignore conflict — already exists is fine).
	createForm := url.Values{
		"_csrf":                       {csrf},
		"id":                          {clientID},
		"name":                        {"Background Worker"},
		"grant_types":                 {"client_credentials"},
		"token_endpoint_auth_method":  {"client_secret_basic"},
		"scopes":                      {"read:users"},
		"audience":                    {identityBase},
	}
	resp, err = client.PostForm(identityBase+"/admin/oauth/new", createForm)
	if err != nil {
		return "", fmt.Errorf("create client: %w", err)
	}
	resp.Body.Close()
	// 303 = created and redirected; 422 = already exists — both are fine.
	if resp.StatusCode >= 500 {
		return "", fmt.Errorf("create client returned HTTP %d", resp.StatusCode)
	}

	// 4. Fetch a fresh CSRF token from the edit page.
	csrf, err = fetchCSRF(client, identityBase+"/admin/oauth/"+clientID+"/edit")
	if err != nil {
		return "", fmt.Errorf("fetch CSRF for secret generation: %w", err)
	}

	// 5. Generate a new client secret.
	genForm := url.Values{
		"_csrf":          {csrf},
		"admin_password": {adminPass},
	}
	resp, err = client.PostForm(identityBase+"/admin/oauth/"+clientID+"/generate-secret", genForm)
	if err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("generate secret returned HTTP %d", resp.StatusCode)
	}

	// 6. Extract the secret from the response HTML.
	bodyBytes, _ := io.ReadAll(resp.Body)
	secret := extractSecret(string(bodyBytes))
	if secret == "" {
		return "", fmt.Errorf("could not find secret in response — check admin password")
	}
	return secret, nil
}

var secretRE = regexp.MustCompile(`<code>([^<]+)</code>`)

// fetchCSRF loads a page and extracts the _csrf hidden input value.
func fetchCSRF(client *http.Client, pageURL string) (string, error) {
	resp, err := client.Get(pageURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	m := regexp.MustCompile(`name="_csrf"\s+value="([^"]+)"`).FindSubmatch(body)
	if m == nil {
		return "", fmt.Errorf("no _csrf token found on %s (HTTP %d)", pageURL, resp.StatusCode)
	}
	return string(m[1]), nil
}

// extractSecret pulls the plaintext secret out of the <code> element in the HTML response.
func extractSecret(html string) string {
	m := secretRE.FindStringSubmatch(html)
	if m == nil {
		return ""
	}
	return m[1]
}

// ── API Calls ────────────────────────────────────────────────────────

// authenticate obtains an access token using the client_credentials grant.
// This is the core of the flow — the service sends its client_id and
// client_secret to the token endpoint and receives a short-lived JWT.
func authenticate(clientSecret, scope string) (*tokenResponse, error) {
	form := url.Values{
		"grant_type": {"client_credentials"},
	}
	if scope != "" {
		form.Set("scope", scope)
	}

	req, err := http.NewRequest("POST", identityBase+"/oauth/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Authenticate using HTTP Basic (client_secret_basic).
	// The client_id and client_secret are base64-encoded in the Authorization header.
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var oErr oauthError
		json.Unmarshal(body, &oErr)
		return nil, fmt.Errorf("HTTP %d: %s — %s", resp.StatusCode, oErr.Error, oErr.Description)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}
	return &tok, nil
}

// fetchDiscovery fetches the OAuth authorization server metadata (RFC 8414).
// This tells clients where the token endpoint, JWKS, etc. are located.
func fetchDiscovery() (*discoveryResponse, error) {
	resp, err := http.Get(identityBase + "/.well-known/oauth-authorization-server")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var disc discoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return nil, err
	}
	return &disc, nil
}

// introspect calls the token introspection endpoint (RFC 7662) to check
// whether a token is still valid and see its claims.
func introspect(clientSecret, token string) (*introspectResponse, error) {
	form := url.Values{"token": {token}}

	req, err := http.NewRequest("POST", identityBase+"/oauth/introspect",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}

	var intro introspectResponse
	if err := json.NewDecoder(resp.Body).Decode(&intro); err != nil {
		return nil, err
	}
	return &intro, nil
}

// callAPI makes an authenticated request to the Identity API.
func callAPI(accessToken, method, path string) (string, int, error) {
	req, err := http.NewRequest(method, identityBase+path, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return string(body), resp.StatusCode, nil
}

// ── Helpers ──────────────────────────────────────────────────────────

// printJWTClaims decodes and pretty-prints the payload of a JWT.
// JWTs are base64url-encoded JSON — no crypto needed to read the claims.
func printJWTClaims(token string) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		log.Println("   (not a valid JWT)")
		return
	}

	// base64url → base64 → bytes
	payload := parts[1]
	payload = strings.ReplaceAll(payload, "-", "+")
	payload = strings.ReplaceAll(payload, "_", "/")
	// Add padding if needed
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		log.Printf("   (decode error: %v)", err)
		return
	}

	// Pretty-print the JSON
	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		log.Printf("   (parse error: %v)", err)
		return
	}

	pretty, _ := json.MarshalIndent(claims, "   ", "  ")
	log.Printf("   %s", pretty)
}
