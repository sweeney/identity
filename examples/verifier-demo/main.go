// Service-to-service JWT verifier demo.
//
// Shows how a consuming service (Service B) validates Bearer tokens issued
// by the Identity server without holding the private key. Public keys are
// fetched from the JWKS endpoint and cached by key ID (kid). Unknown key IDs
// trigger a JWKS refresh, so zero-downtime key rotation works automatically.
//
// Usage:
//
//  1. Start the Identity server:
//     go run ./cmd/server
//
//  2. Run this demo:
//     go run ./examples/verifier-demo
//
//  3. Open http://localhost:9093 — paste any Bearer token to verify it.
//
//  4. Or call the protected endpoint directly:
//     curl -H "Authorization: Bearer <token>" http://localhost:9093/protected
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	identityBase = "https://id.swee.net"
	jwksURL      = identityBase + "/.well-known/jwks.json"
	listenAddr   = ":9093"
)

func main() {
	ks := newKeyStore(jwksURL)

	// Fetch keys on startup — fail fast if the Identity server is unreachable.
	if err := ks.refresh(); err != nil {
		log.Fatalf("failed to fetch JWKS on startup: %v", err)
	}
	log.Printf("Fetched %d key(s) from %s", ks.count(), jwksURL)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleHome(w, r, ks)
	})
	mux.Handle("/protected", ks.middleware(http.HandlerFunc(handleProtected)))

	log.Printf("Verifier demo listening on http://localhost%s", listenAddr)
	log.Printf("Identity server expected at %s", identityBase)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

// ── Protected endpoint ───────────────────────────────────────────────

// handleProtected is the downstream endpoint that requires a valid token.
// In a real service this would be your business logic.
func handleProtected(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"message":  "access granted",
		"user_id":  claims.Subject,
		"username": claims.Username,
		"role":     claims.Role,
		"expires":  claims.ExpiresAt.Time.Format(time.RFC3339),
	})
}

// ── Home page ────────────────────────────────────────────────────────

var homeTmpl = template.Must(template.New("home").Parse(`<!DOCTYPE html>
<html><head><title>Verifier Demo</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 700px; margin: 2rem auto; padding: 0 1rem; color: #1a1a2e; }
  pre  { background: #f4f4f4; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; white-space: pre-wrap; word-break: break-all; }
  textarea { width: 100%; height: 8rem; font-family: monospace; font-size: 0.85rem; padding: 0.5rem; box-sizing: border-box; border-radius: 6px; border: 1px solid #ccc; }
  button { background: #02aaa2; color: #fff; border: none; padding: 0.5rem 1.25rem; border-radius: 6px; cursor: pointer; font-size: 0.9rem; margin-top: 0.5rem; }
  button:hover { background: #028f88; }
  .box  { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 6px; padding: 1rem; margin: 1rem 0; }
  .ok   { border-color: #02aaa2; }
  .fail { border-color: #d63031; }
  h1 { color: #02aaa2; }
  code { background: #f4f4f4; padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.9em; }
</style>
</head><body>
<h1>JWT Verifier Demo</h1>
<p>This service validates Bearer tokens issued by the Identity server at
<code>{{.IdentityBase}}</code> using its public key — the private key never leaves the Identity server.</p>

<div class="box">
  <strong>How it works</strong>
  <ol>
    <li>On startup, fetch public keys from <code>{{.JWKSURL}}</code></li>
    <li>Cache keys by <code>kid</code> (key ID)</li>
    <li>For each request: read <code>kid</code> from JWT header → look up public key → verify signature</li>
    <li>On unknown <code>kid</code>: re-fetch JWKS (handles zero-downtime key rotation)</li>
  </ol>
</div>

<h3>Try it</h3>
<p>Get a token from the Identity server, then paste it below:</p>
<form method="POST" action="/">
  <textarea name="token" placeholder="eyJ...">{{.Token}}</textarea><br>
  <button type="submit">Verify</button>
</form>

{{if .Result}}
  {{if .Result.OK}}
  <div class="box ok">
    <strong>✓ Valid token</strong>
    <pre>{{.Result.Body}}</pre>
  </div>
  {{else}}
  <div class="box fail">
    <strong>✗ Invalid:</strong> {{.Result.Body}}
  </div>
  {{end}}
{{end}}

<h3>Or via curl</h3>
<pre>curl -H "Authorization: Bearer &lt;token&gt;" http://localhost{{.ListenAddr}}/protected</pre>

</body></html>`))

type verifyResult struct {
	OK   bool
	Body string
}

func handleHome(w http.ResponseWriter, r *http.Request, ks *keyStore) {
	data := map[string]any{
		"IdentityBase": identityBase,
		"JWKSURL":      jwksURL,
		"ListenAddr":   listenAddr,
	}

	if r.Method == http.MethodPost {
		token := strings.TrimSpace(r.FormValue("token"))
		data["Token"] = token
		if token != "" {
			_, claims, err := ks.validate(token)
			if err != nil {
				data["Result"] = &verifyResult{Body: err.Error()}
			} else {
				b, _ := json.MarshalIndent(map[string]any{
					"user_id":  claims.Subject,
					"username": claims.Username,
					"role":     claims.Role,
					"expires":  claims.ExpiresAt.Time.Format(time.RFC3339),
				}, "", "  ")
				data["Result"] = &verifyResult{OK: true, Body: string(b)}
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	homeTmpl.Execute(w, data) //nolint:errcheck
}

// ── JWKS key store ───────────────────────────────────────────────────

type contextKey string

const claimsContextKey contextKey = "claims"

// identityClaims matches the custom claims minted by the Identity server.
type identityClaims struct {
	jwt.RegisteredClaims
	Username string `json:"usr"`
	Role     string `json:"rol"`
	IsActive bool   `json:"act"`
}

// keyStore fetches and caches EC public keys from a JWKS endpoint.
type keyStore struct {
	url  string
	mu   sync.RWMutex
	keys map[string]*ecdsa.PublicKey // kid → public key
}

func newKeyStore(url string) *keyStore {
	return &keyStore{url: url, keys: make(map[string]*ecdsa.PublicKey)}
}

func (ks *keyStore) count() int {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return len(ks.keys)
}

// refresh fetches the JWKS and replaces the key cache atomically.
func (ks *keyStore) refresh() error {
	resp, err := http.Get(ks.url) //nolint:noctx
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read jwks: %w", err)
	}

	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return fmt.Errorf("parse jwks: %w", err)
	}

	next := make(map[string]*ecdsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			log.Printf("skipping unsupported key kty=%s crv=%s kid=%s", k.Kty, k.Crv, k.Kid)
			continue
		}
		pub, err := jwkToPublicKey(k.X, k.Y)
		if err != nil {
			return fmt.Errorf("parse key kid=%s: %w", k.Kid, err)
		}
		next[k.Kid] = pub
		log.Printf("loaded key kid=%s", k.Kid)
	}

	ks.mu.Lock()
	ks.keys = next
	ks.mu.Unlock()
	return nil
}

func (ks *keyStore) get(kid string) *ecdsa.PublicKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.keys[kid]
}

// validate parses and verifies a JWT, returning the claims on success.
func (ks *keyStore) validate(tokenStr string) (*jwt.Token, *identityClaims, error) {
	var claims identityClaims
	token, err := jwt.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		kid, _ := t.Header["kid"].(string)
		key := ks.get(kid)
		if key == nil {
			// Unknown kid — could be a newly rotated key. Re-fetch JWKS once.
			log.Printf("unknown kid=%q, refreshing JWKS", kid)
			if err := ks.refresh(); err != nil {
				return nil, fmt.Errorf("jwks refresh: %w", err)
			}
			key = ks.get(kid)
			if key == nil {
				return nil, fmt.Errorf("unknown key id %q", kid)
			}
		}
		return key, nil
	}, jwt.WithExpirationRequired())

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, nil, fmt.Errorf("token expired")
		}
		return nil, nil, fmt.Errorf("invalid token: %w", err)
	}

	if !claims.IsActive {
		return nil, nil, fmt.Errorf("account is disabled")
	}

	return token, &claims, nil
}

// middleware validates the Bearer token and injects claims into the request context.
// Returns 401 on missing or invalid tokens.
func (ks *keyStore) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			writeError(w, http.StatusUnauthorized, "Authorization header must be: Bearer <token>")
			return
		}

		_, claims, err := ks.validate(parts[1])
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}

		ctx := context.WithValue(r.Context(), claimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ── Helpers ──────────────────────────────────────────────────────────

func claimsFromContext(ctx context.Context) *identityClaims {
	v := ctx.Value(claimsContextKey)
	if v == nil {
		return &identityClaims{}
	}
	c, _ := v.(*identityClaims)
	return c
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}

func jwkToPublicKey(xB64, yB64 string) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
