//go:build integration

package service_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
	oauthhandler "github.com/sweeney/identity/internal/handler/oauth"
	"github.com/sweeney/identity/internal/service"
	"github.com/sweeney/identity/internal/store"
)

// --- Concurrent authorization-code exchange (issue #23) ---
//
// Two requests presenting the same authorization code both pass the
// `code.UsedAt == nil` check before either reaches MarkUsed. The conditional
// UPDATE in the store closes the race, so exactly one exchange succeeds — but
// the loser must report `invalid_grant` (RFC 6749 §5.2), not `server_error`.
//
// These tests run against a real SQLite database and the real store, service
// and HTTP handler. The database is opened with SetMaxOpenConns(1), so
// statements are serialized at the connection pool; the interleaving that
// triggers the bug happens between the two Go-level steps of the
// check-then-act, which is why a barrier at the repository seam reproduces it
// deterministically rather than probabilistically.

// raceStack is a full, real dependency graph: SQLite -> stores -> services.
type raceStack struct {
	oauthSvc *service.OAuthService
	database *db.Database
	userID   string
	clientID string
	redirect string
}

// newRaceStack wires the real stack. codeRepo lets a test interpose a
// decorator (e.g. a barrier) between the service and the real code store.
func newRaceStack(t *testing.T, wrap func(domain.OAuthCodeRepository) domain.OAuthCodeRepository) *raceStack {
	t.Helper()

	database, err := db.Open(filepath.Join(t.TempDir(), "race.db"))
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })

	users := store.NewUserStore(database)
	tokens := store.NewTokenStore(database)
	audit := store.NewAuditStore(database)
	clients := store.NewOAuthClientStore(database)
	codeStore := store.NewOAuthCodeStore(database)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuer, err := auth.NewTokenIssuer(key, nil, "https://identity.test", 15*time.Minute)
	require.NoError(t, err)

	now := time.Now().UTC()
	user := &domain.User{
		ID:           "user-race",
		Username:     "racer",
		DisplayName:  "Racer",
		PasswordHash: "$2a$04$placeholderplaceholderplaceholderplaceholderplaceholder",
		Role:         domain.RoleUser,
		IsActive:     true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, users.Create(user))

	client := &domain.OAuthClient{
		ID:           "client-race",
		Name:         "Racing App",
		RedirectURIs: []string{"https://racer.example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, clients.Create(client))

	var codeRepo domain.OAuthCodeRepository = codeStore
	if wrap != nil {
		codeRepo = wrap(codeStore)
	}

	authSvc := service.NewAuthService(issuer, users, tokens, nil, audit, 30*24*time.Hour)
	oauthSvc := service.NewOAuthService(authSvc, issuer, clients, codeRepo, audit, 60*time.Second)

	return &raceStack{
		oauthSvc: oauthSvc,
		database: database,
		userID:   user.ID,
		clientID: client.ID,
		redirect: client.RedirectURIs[0],
	}
}

// issueCode mints a real authorization code through the service.
func (s *raceStack) issueCode(t *testing.T, challenge string) string {
	t.Helper()
	rawCode, err := s.oauthSvc.AuthorizeByUserID(s.clientID, s.redirect, s.userID, "racer", challenge, "127.0.0.1")
	require.NoError(t, err)
	return rawCode
}

// barrierCodeRepo delays every MarkUsed until `n` callers have finished
// GetByHash, forcing the exact interleaving that produces the bug: both
// racers observe UsedAt == nil, then both attempt the conditional UPDATE.
type barrierCodeRepo struct {
	domain.OAuthCodeRepository
	readsDone *sync.WaitGroup
	release   chan struct{}
	arrivals  atomic.Int32
	racers    int32
	once      sync.Once
}

// gateTimeout bounds the wait at the gate. If fewer than `racers` callers ever
// reach GetByHash — a racer rejected by a validation added ahead of the lookup,
// say — the gate never opens. Without this the test would hang until the
// package timeout and dump every goroutine, pointing at `chan receive` rather
// than at the real cause; with it, the assertions run and report the failure.
const gateTimeout = 30 * time.Second

func (r *barrierCodeRepo) GetByHash(codeHash string) (*domain.AuthCode, error) {
	code, err := r.OAuthCodeRepository.GetByHash(codeHash)
	// Signal this racer has read the (still unused) row, then wait until every
	// racer has done the same before anyone is allowed to write. The count is
	// bounded so an unexpected extra read cannot drive the WaitGroup negative
	// and panic somewhere unrelated to the mistake.
	if r.arrivals.Add(1) <= r.racers {
		r.readsDone.Done()
	}
	select {
	case <-r.release:
	case <-time.After(gateTimeout):
	}
	return code, err
}

func (r *barrierCodeRepo) openGate() {
	r.once.Do(func() { close(r.release) })
}

// TestExchangeCode_ConcurrentRace_LoserGetsInvalidGrant is the deterministic
// reproduction: both racers read the code as unused, then both try to redeem it.
func TestExchangeCode_ConcurrentRace_LoserGetsInvalidGrant(t *testing.T) {
	const racers = 2

	var readsDone sync.WaitGroup
	readsDone.Add(racers)
	barrier := &barrierCodeRepo{readsDone: &readsDone, release: make(chan struct{}), racers: racers}

	st := newRaceStack(t, func(real domain.OAuthCodeRepository) domain.OAuthCodeRepository {
		barrier.OAuthCodeRepository = real
		return barrier
	})

	verifier := "concurrent-exchange-code-verifier-value"
	rawCode := st.issueCode(t, pkceChallenge(verifier))

	// Release all racers into MarkUsed only after every one has read the row.
	go func() {
		readsDone.Wait()
		barrier.openGate()
	}()

	type outcome struct {
		result *service.LoginResult
		err    error
	}
	outcomes := make([]outcome, racers)
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := st.oauthSvc.ExchangeCode(st.clientID, rawCode, st.redirect, verifier)
			outcomes[i] = outcome{res, err}
		}(i)
	}
	wg.Wait()

	var winners, losers int
	for _, o := range outcomes {
		if o.err == nil {
			winners++
			require.NotNil(t, o.result)
			assert.NotEmpty(t, o.result.AccessToken)
			continue
		}
		losers++
		assert.ErrorIs(t, o.err, service.ErrAuthCodeAlreadyUsed,
			"the losing racer must return a sentinel the handler maps to invalid_grant, got: %v", o.err)
	}

	assert.Equal(t, 1, winners, "the code must be redeemed exactly once")
	assert.Equal(t, racers-1, losers)
}

// TestExchangeCode_ConcurrentRace_NoDoubleIssuance verifies the issue's
// security claim directly: whatever the reported error, only one set of tokens
// is ever persisted for a single authorization code.
func TestExchangeCode_ConcurrentRace_NoDoubleIssuance(t *testing.T) {
	const racers = 8

	var readsDone sync.WaitGroup
	readsDone.Add(racers)
	barrier := &barrierCodeRepo{readsDone: &readsDone, release: make(chan struct{}), racers: racers}

	st := newRaceStack(t, func(real domain.OAuthCodeRepository) domain.OAuthCodeRepository {
		barrier.OAuthCodeRepository = real
		return barrier
	})

	verifier := "no-double-issuance-code-verifier-value"
	rawCode := st.issueCode(t, pkceChallenge(verifier))

	go func() {
		readsDone.Wait()
		barrier.openGate()
	}()

	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = st.oauthSvc.ExchangeCode(st.clientID, rawCode, st.redirect, verifier)
		}(i)
	}
	wg.Wait()

	var winners int
	for _, err := range errs {
		if err == nil {
			winners++
			continue
		}
		assert.ErrorIs(t, err, service.ErrAuthCodeAlreadyUsed, "unexpected error from losing racer")
	}
	require.Equal(t, 1, winners, "exactly one racer may redeem the code")

	// Exactly one refresh token row must exist for the user.
	var refreshTokens int
	require.NoError(t, st.database.DB().
		QueryRow(`SELECT COUNT(*) FROM refresh_tokens WHERE user_id = ?`, st.userID).
		Scan(&refreshTokens))
	assert.Equal(t, 1, refreshTokens, "a single authorization code must yield a single refresh token")
}

// TestTokenEndpoint_ConcurrentExchange_ReturnsInvalidGrant drives the race
// through the real HTTP token endpoint and asserts on the wire format the
// client actually sees.
func TestTokenEndpoint_ConcurrentExchange_ReturnsInvalidGrant(t *testing.T) {
	const racers = 2

	var readsDone sync.WaitGroup
	readsDone.Add(racers)
	barrier := &barrierCodeRepo{readsDone: &readsDone, release: make(chan struct{}), racers: racers}

	st := newRaceStack(t, func(real domain.OAuthCodeRepository) domain.OAuthCodeRepository {
		barrier.OAuthCodeRepository = real
		return barrier
	})

	verifier := "http-level-concurrent-exchange-verifier"
	rawCode := st.issueCode(t, pkceChallenge(verifier))

	router := oauthhandler.NewRouter(st.oauthSvc, "", nil, nil, nil, nil, "", "")

	go func() {
		readsDone.Wait()
		barrier.openGate()
	}()

	responses := make([]*httptest.ResponseRecorder, racers)
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			form := url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {st.clientID},
				"code":          {rawCode},
				"redirect_uri":  {st.redirect},
				"code_verifier": {verifier},
			}
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			responses[i] = rr
		}(i)
	}
	wg.Wait()

	var ok, rejected int
	for _, rr := range responses {
		var body map[string]any
		require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))

		if rr.Code == http.StatusOK {
			ok++
			assert.NotEmpty(t, body["access_token"])
			continue
		}
		rejected++
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Equal(t, "invalid_grant", body["error"],
			"RFC 6749 §5.2: an already-redeemed code is invalid_grant, not %v", body["error"])
		assert.NotEqual(t, "server_error", body["error"],
			"server_error is not a valid token-endpoint error code and makes clients retry a request that can never succeed")
	}

	assert.Equal(t, 1, ok, "exactly one request may receive tokens")
	assert.Equal(t, racers-1, rejected)
}

// TestExchangeCode_ConcurrentRace_Unsynchronized runs the same race without a
// barrier — closer to production timing, and a guard against the fix depending
// on the barrier's particular interleaving.
func TestExchangeCode_ConcurrentRace_Unsynchronized(t *testing.T) {
	st := newRaceStack(t, nil)

	verifier := "unsynchronized-race-code-verifier-value"

	// Repeat: without a barrier the interleaving is timing-dependent, so a
	// single attempt may not overlap. Every attempt must still be correct.
	for attempt := 0; attempt < 25; attempt++ {
		rawCode := st.issueCode(t, pkceChallenge(verifier))

		const racers = 4
		start := make(chan struct{})
		errs := make([]error, racers)
		var wg sync.WaitGroup
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				_, errs[i] = st.oauthSvc.ExchangeCode(st.clientID, rawCode, st.redirect, verifier)
			}(i)
		}
		close(start)
		wg.Wait()

		var winners int
		for _, err := range errs {
			if err == nil {
				winners++
				continue
			}
			// Whether the loser was rejected by the UsedAt check (sequential)
			// or by the conditional UPDATE (raced), the client-visible result
			// must be identical.
			assert.ErrorIs(t, err, service.ErrAuthCodeAlreadyUsed,
				"attempt %d: loser must map to invalid_grant, got: %v", attempt, err)
		}
		require.Equal(t, 1, winners, "attempt %d: the code must be redeemed exactly once", attempt)
	}
}
