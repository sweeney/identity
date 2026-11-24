package oauth

import (
	"encoding/base64"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/sweeney/identity/internal/domain"
)

// clientCredentials holds the extracted client_id and client_secret from a request.
type clientCredentials struct {
	ClientID     string
	ClientSecret string
	Method       string // "client_secret_basic" or "client_secret_post"
}

// extractClientCredentials extracts client credentials from the request.
// Checks Authorization: Basic header first, then falls back to form body.
func extractClientCredentials(r *http.Request) (*clientCredentials, bool) {
	// Try HTTP Basic auth first (client_secret_basic)
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(auth[6:])
		if err != nil {
			return nil, false
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, false
		}
		// RFC 6749 §2.3.1: client_id and client_secret are URL-encoded before
		// base64 encoding in the Basic header.
		clientID, err1 := url.QueryUnescape(parts[0])
		clientSecret, err2 := url.QueryUnescape(parts[1])
		if err1 != nil || err2 != nil {
			return nil, false
		}
		return &clientCredentials{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Method:       "client_secret_basic",
		}, true
	}

	// Fall back to form body (client_secret_post)
	clientID := r.FormValue("client_id")
	// RFC 6749 §2.3.1 puts client_secret_post credentials in the body.
	clientSecret := r.PostFormValue("client_secret")
	if clientID != "" && clientSecret != "" {
		return &clientCredentials{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Method:       "client_secret_post",
		}, true
	}

	return nil, false
}

// verifyClientSecret checks the provided secret against the client's stored hash(es).
// Supports secret rotation by checking both current and previous hashes.
func verifyClientSecret(client *domain.OAuthClient, secret string) bool {
	if client.SecretHash == "" {
		return false
	}
	// Try current hash
	if bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(secret)) == nil {
		return true
	}
	// Try the previous hash, but only while it is still within its rotation
	// window. It used to be accepted forever, so a secret an operator
	// deliberately rotated away from stayed valid indefinitely.
	if client.PreviousSecretUsable(time.Now().UTC()) {
		return bcrypt.CompareHashAndPassword([]byte(client.SecretHashPrev), []byte(secret)) == nil
	}
	return false
}

// resolveTokenClientID names the client on a token request. RFC 6749 §4.1.3
// requires client_id in the body only when the client is not authenticating,
// so a client_secret_basic client may name itself in the Authorization header
// alone. When the body and the header both name a client they must agree;
// otherwise it writes 401 invalid_client and returns false.
func resolveTokenClientID(w http.ResponseWriter, r *http.Request) (string, bool) {
	clientID := r.FormValue("client_id")
	creds, ok := extractClientCredentials(r)
	if !ok || creds.Method != "client_secret_basic" {
		return clientID, true
	}
	if clientID != "" && clientID != creds.ClientID {
		w.Header().Set("WWW-Authenticate", "Basic")
		oauthErrorWithStatus(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed.")
		return "", false
	}
	return creds.ClientID, true
}

// authenticateTokenClient applies client authentication for the
// authorization_code and refresh_token grants. A confidential client (one with
// a registered secret) must present it (RFC 6749 §3.2.1). A public client has
// no secret to verify, so credentials presented for one are a failed
// authentication (§5.2) rather than something to ignore. An unknown client
// passes here and is reported by the grant itself. On failure it writes
// 401 invalid_client and returns false.
func (h *oauthHandler) authenticateTokenClient(w http.ResponseWriter, r *http.Request, clientID string) bool {
	client, err := h.svc.GetClient(clientID)
	if err != nil {
		return true
	}
	creds, ok := extractClientCredentials(r)
	if client.SecretHash == "" {
		if ok {
			// Logged so it can be told from traffic whether anything live
			// hits this: before it, such credentials were silently ignored.
			log.Printf("oauth: refused %s credentials for public client %q at /oauth/token (grant_type=%s)",
				creds.Method, clientID, r.FormValue("grant_type"))
			// RFC 6749 §5.2: the challenge is required when the client tried
			// the Authorization header.
			if creds.Method == "client_secret_basic" {
				w.Header().Set("WWW-Authenticate", "Basic")
			}
			oauthErrorWithStatus(w, http.StatusUnauthorized, "invalid_client", "This client is not configured for client authentication.")
			return false
		}
		return true
	}
	if !ok || creds.ClientID != clientID || !verifyClientSecret(client, creds.ClientSecret) {
		w.Header().Set("WWW-Authenticate", "Basic")
		oauthErrorWithStatus(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed.")
		return false
	}
	return true
}
