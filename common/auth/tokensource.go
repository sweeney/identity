package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// TokenSource fetches and caches a client_credentials access token from the
// identity service. Token() is safe for concurrent use. The cached token is
// refreshed automatically when it is within expiryBuffer of expiry.
type TokenSource struct {
	BaseURL      string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client

	mu          sync.Mutex
	cachedToken string
	expiresAt   time.Time

	// sf coalesces concurrent fetches. Identity rate-limits its token endpoint
	// at 5/min, so a service starting up — or recovering from Invalidate()
	// after a 401 — would otherwise fire one request per concurrent caller and
	// lock itself out with a 429 of its own making.
	sf singleflight.Group
}

// expiryBuffer is how early we proactively refresh before the token expires.
const expiryBuffer = 30 * time.Second

// defaultHTTPClient is used when TokenSource.HTTPClient is nil.
var defaultHTTPClient = &http.Client{Timeout: 10 * time.Second}

// Token returns a valid Bearer token, fetching a new one if the cache is
// empty or within expiryBuffer of expiry. The mutex is released before any
// network I/O so callers with a valid cached token are never blocked by an
// in-flight fetch.
func (ts *TokenSource) Token(ctx context.Context) (string, error) {
	ts.mu.Lock()
	if ts.cachedToken != "" && time.Now().Add(expiryBuffer).Before(ts.expiresAt) {
		tok := ts.cachedToken
		ts.mu.Unlock()
		return tok, nil
	}
	ts.mu.Unlock()

	// One fetch serves every caller waiting on it.
	tok, err, _ := ts.sf.Do("token", func() (any, error) {
		// Another flight may have refreshed the token while we queued.
		ts.mu.Lock()
		if ts.cachedToken != "" && time.Now().Add(expiryBuffer).Before(ts.expiresAt) {
			cached := ts.cachedToken
			ts.mu.Unlock()
			return cached, nil
		}
		ts.mu.Unlock()

		// expires_in is counted from when identity issued the token, so the
		// deadline is measured from when the request went out. Measuring it
		// from the response over-states the lifetime by the round-trip time,
		// and the cache then keeps serving a token closer to expiry than it
		// believes.
		requestedAt := time.Now()
		token, expiresIn, fetchErr := ts.fetch(ctx)
		if fetchErr != nil {
			return "", fetchErr
		}

		ts.mu.Lock()
		ts.cachedToken = token
		ts.expiresAt = requestedAt.Add(time.Duration(expiresIn) * time.Second)
		ts.mu.Unlock()
		return token, nil
	})
	if err != nil {
		return "", err
	}
	return tok.(string), nil
}

// Invalidate clears the cached token, forcing the next Token() call to fetch
// a new one. Call this when a downstream caller receives a 401.
func (ts *TokenSource) Invalidate() {
	ts.mu.Lock()
	ts.cachedToken = ""
	ts.expiresAt = time.Time{}
	ts.mu.Unlock()
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type oauthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (ts *TokenSource) fetch(ctx context.Context) (token string, expiresIn int, err error) {
	client := ts.HTTPClient
	if client == nil {
		client = defaultHTTPClient
	}

	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {ts.ClientID},
		"client_secret": {ts.ClientSecret},
	}

	// A trailing slash on BaseURL is an ordinary configuration mistake and
	// would otherwise produce //oauth/token, which identity does not route.
	tokenURL := strings.TrimRight(ts.BaseURL, "/") + "/oauth/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(body.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("identity: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("identity: token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var oerr oauthError
		if jsonErr := json.NewDecoder(resp.Body).Decode(&oerr); jsonErr == nil && oerr.Error != "" {
			return "", 0, fmt.Errorf("identity: %s: %s", oerr.Error, oerr.ErrorDescription)
		}
		return "", 0, fmt.Errorf("identity: unexpected status %d", resp.StatusCode)
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", 0, fmt.Errorf("identity: decode response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", 0, fmt.Errorf("identity: empty access_token in response")
	}
	if tr.ExpiresIn <= 0 {
		return "", 0, fmt.Errorf("identity: invalid expires_in %d in response", tr.ExpiresIn)
	}

	return tr.AccessToken, tr.ExpiresIn, nil
}
