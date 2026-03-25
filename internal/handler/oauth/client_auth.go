package oauth

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

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
	clientSecret := r.FormValue("client_secret")
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
	// Try previous hash (rotation in progress)
	if client.SecretHashPrev != "" {
		return bcrypt.CompareHashAndPassword([]byte(client.SecretHashPrev), []byte(secret)) == nil
	}
	return false
}
