package service

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
)

// dummyHash is a pre-computed bcrypt hash (cost 12) used to prevent timing-based
// username enumeration. When a login attempt targets a non-existent user, we run
// bcrypt against this hash so the response time matches a real user lookup.
var dummyHash = func() string {
	h, _ := bcrypt.GenerateFromPassword([]byte("dummy-never-matches"), 12)
	return string(h)
}()

// LoginResult holds the tokens returned on a successful login or refresh.
type LoginResult struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int // seconds
	RefreshToken string
}

// AuthService handles login, refresh, and logout business logic.
type AuthService struct {
	issuer *auth.TokenIssuer
	users  domain.UserRepository
	tokens domain.TokenRepository
	// clients resolves the OAuth client a refresh token is bound to, so
	// rotation can re-read its registered audiences rather than replay the set
	// captured at grant time. May be nil in a deployment with no OAuth clients;
	// rotation then carries the stored set forward, which is the pre-#39
	// behaviour and is correct when there is no registration to consult.
	clients         domain.OAuthClientRepository
	backup          domain.BackupService
	audit           domain.AuditRepository
	refreshTokenTTL time.Duration
}

// NewAuthService creates an AuthService.
func NewAuthService(
	issuer *auth.TokenIssuer,
	users domain.UserRepository,
	tokens domain.TokenRepository,
	clients domain.OAuthClientRepository,
	backup domain.BackupService,
	audit domain.AuditRepository,
	refreshTokenTTL time.Duration,
) *AuthService {
	return &AuthService{
		issuer:          issuer,
		users:           users,
		tokens:          tokens,
		clients:         clients,
		backup:          backup,
		audit:           audit,
		refreshTokenTTL: refreshTokenTTL,
	}
}

// loginArgs is the internal result of issuing tokens.
type loginArgs struct {
	oldTokenID string
	familyID   string // empty = generate new family
	deviceHint string
	audience   []string // optional aud claim; set for OAuth PKCE flow

	// scope is the space-delimited scope the grant was consented for, carried
	// onto both the access token and the refresh token so it survives rotation.
	scope string
	// claimCodeID ties a device-grant family to the claim code that produced it.
	claimCodeID string
	// authCodeID ties an authorization-code family to the code that produced it.
	authCodeID string
	// clientID is the OAuth client this grant was issued to; empty for a
	// direct API login.
	clientID string
}

// Login authenticates a user by username and password, returning JWT tokens.
func (s *AuthService) Login(username, password, deviceHint, clientIP string) (*LoginResult, error) {
	user, err := s.users.GetByUsername(username)
	if errors.Is(err, domain.ErrNotFound) {
		// Constant-time: still run bcrypt to prevent timing-based username enumeration
		auth.CheckPassword(password, dummyHash) //nolint:errcheck
		s.record(&domain.AuthEvent{
			EventType: domain.EventLoginFailure,
			Username:  username,
			IPAddress: clientIP,
		})
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	if err := auth.CheckPassword(password, user.PasswordHash); err != nil {
		s.record(&domain.AuthEvent{
			EventType: domain.EventLoginFailure,
			UserID:    user.ID,
			Username:  username,
			IPAddress: clientIP,
		})
		return nil, ErrInvalidCredentials
	}

	if !user.IsActive {
		// Return the generic invalid-credentials error so a disabled account is
		// indistinguishable from a non-existent user or a wrong password (no user
		// enumeration). The disabled state is preserved server-side via the audit
		// event so operators can still see the attempt.
		s.record(&domain.AuthEvent{
			EventType: domain.EventLoginFailure,
			UserID:    user.ID,
			Username:  username,
			IPAddress: clientIP,
			Detail:    "account disabled",
		})
		return nil, ErrInvalidCredentials
	}

	result, err := s.issueTokens(user, loginArgs{deviceHint: deviceHint})
	if err != nil {
		return nil, err
	}

	s.record(&domain.AuthEvent{
		EventType:  domain.EventLoginSuccess,
		UserID:     user.ID,
		Username:   user.Username,
		DeviceHint: deviceHint,
		IPAddress:  clientIP,
	})
	return result, nil
}

// AuthorizeUser authenticates without issuing tokens. Returns userID on success.
// Used by OAuthService at the authorize step and by the device verification page.
//
// Every failure is audited, exactly as Login audits its own. This is the same
// password check reachable through /oauth/authorize and /oauth/device, and
// without these records credential stuffing through either endpoint left no
// trace at all — including on the admin dashboard, which is where an operator
// would notice it.
func (s *AuthService) AuthorizeUser(username, password, clientIP string) (string, error) {
	user, err := s.users.GetByUsername(username)
	if errors.Is(err, domain.ErrNotFound) {
		auth.CheckPassword(password, dummyHash) //nolint:errcheck
		s.record(&domain.AuthEvent{
			EventType: domain.EventLoginFailure,
			Username:  username,
			IPAddress: clientIP,
		})
		return "", ErrInvalidCredentials
	}
	if err != nil {
		return "", fmt.Errorf("get user: %w", err)
	}

	if err := auth.CheckPassword(password, user.PasswordHash); err != nil {
		s.record(&domain.AuthEvent{
			EventType: domain.EventLoginFailure,
			UserID:    user.ID,
			Username:  username,
			IPAddress: clientIP,
		})
		return "", ErrInvalidCredentials
	}

	if !user.IsActive {
		s.record(&domain.AuthEvent{
			EventType: domain.EventLoginFailure,
			UserID:    user.ID,
			Username:  username,
			IPAddress: clientIP,
			Detail:    "account disabled",
		})
		return "", ErrAccountDisabled
	}

	return user.ID, nil
}

// GrantContext describes what a pre-authenticated grant was actually for. It
// travels onto the issued tokens and, via the refresh token, survives rotation.
type GrantContext struct {
	// Audience lists the services these tokens are for; empty omits the claim.
	Audience []string
	// Scope is the space-delimited scope the user consented to; empty means no
	// scope restriction. The device grant consents to a scope, so it must be
	// carried here or the device silently receives full user privileges.
	Scope string
	// ClaimCodeID records the claim code a device grant came from, so revoking
	// that code can revoke the tokens it produced.
	ClaimCodeID string
	// AuthCodeID records the authorization code this grant came from, so
	// replaying that code can revoke the tokens it produced (RFC 6749 §4.1.2).
	AuthCodeID string
	// ClientID is the OAuth client this grant was issued to. Recorded on the
	// refresh token so the refresh grant can refuse a token that belongs to a
	// different client.
	ClientID string
}

// IssueTokensForUser issues a token pair for a pre-authenticated user.
// audience is the aud claim to embed in the access token; pass "" to omit it.
// Used by OAuthService at the code exchange step.
func (s *AuthService) IssueTokensForUser(userID, audience string) (*LoginResult, error) {
	return s.IssueTokensForGrant(userID, GrantContext{Audience: domain.AudienceList(audience)})
}

// IssueTokensForGrant issues a token pair for a pre-authenticated user, carrying
// the full grant context onto the tokens. Used by the device grant, where the
// consented scope and the originating claim code both have to survive.
func (s *AuthService) IssueTokensForGrant(userID string, grant GrantContext) (*LoginResult, error) {
	user, err := s.users.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if !user.IsActive {
		return nil, ErrAccountDisabled
	}
	return s.issueTokens(user, loginArgs{
		audience:    grant.Audience,
		scope:       grant.Scope,
		claimCodeID: grant.ClaimCodeID,
		authCodeID:  grant.AuthCodeID,
		clientID:    grant.ClientID,
	})
}

// RefreshForClient is Refresh, restricted to the OAuth client the token was
// issued to.
//
// A refresh token that leaks — through a log, a proxy, a compromised client —
// could otherwise be redeemed by any other registered client, for a user who
// never consented to it. An empty clientID means the direct API login, which
// has no client; tokens issued that way carry no binding and are only
// redeemable through the same unbound path.
func (s *AuthService) RefreshForClient(rawRefreshToken, clientID string) (*LoginResult, error) {
	tok, err := s.tokens.GetByHash(HashToken(rawRefreshToken))
	if err == nil && tok.ClientID != "" && tok.ClientID != clientID {
		return nil, ErrRefreshTokenClientMismatch
	}
	// An empty ClientID is a token issued before the binding existed. It cannot
	// be attributed to a client, so there is nothing to check — refusing it
	// would sign out every session that predates the upgrade while buying no
	// security, since accepting it is exactly the pre-migration posture. It is
	// adopted instead: the rotated token comes back bound to the presenting
	// client, so the binding takes effect after one refresh per session.
	return s.refresh(rawRefreshToken, clientID)
}

// resolveAudiences returns the audience set the rotated token should carry, or
// nil to keep whatever the old token stored.
//
// A refresh token bound to an OAuth client takes its audiences from that
// client's live registration on every rotation. The alternative — replaying the
// set frozen at grant time — makes the registration advisory: removing an
// audience revokes nothing for a client that keeps refreshing, and rotation
// issues a fresh TTL with no absolute family lifetime, so that is unbounded
// (#39). Removal has to be effective; audience removal reads like a revocation
// mechanism and operators use it as one.
//
// An unbound token is a direct API login. There is no registration to consult,
// so the stored set stands.
func (s *AuthService) resolveAudiences(tokenHash, adoptClientID string) []string {
	if s.clients == nil {
		return nil
	}
	clientID := adoptClientID
	if clientID == "" {
		// Not every caller knows the binding: /api/v1/auth/refresh takes no
		// client_id, so the token itself is the only place to learn it.
		tok, err := s.tokens.GetByHash(tokenHash)
		if err != nil {
			// Leave it to RotateToken, which reads the token authoritatively
			// inside the transaction and reports a missing one properly.
			return nil
		}
		clientID = tok.ClientID
	}
	if clientID == "" {
		return nil
	}

	client, err := s.clients.GetByID(clientID)
	if err != nil {
		// A registration that no longer exists grants no audiences. Narrowing
		// is the safe direction: the token stops asserting audiences nothing
		// backs, rather than keeping them because the record is gone. Whether
		// deleting a client should revoke its live tokens outright is a
		// separate question.
		log.Printf("auth: refresh token names client %q which no longer resolves (%v); issuing with no audience", clientID, err)
		return []string{}
	}
	if client.Audiences == nil {
		// Distinct from nil-means-inherit: this client genuinely names nothing.
		return []string{}
	}
	return client.Audiences
}

// Refresh validates a refresh token and issues a new token pair via rotation.
// The read-validate-revoke-insert sequence is performed atomically within a
// single transaction by RotateToken, preventing the TOCTOU race condition
// where concurrent requests could both observe the token as valid.
func (s *AuthService) Refresh(rawRefreshToken string) (*LoginResult, error) {
	return s.refresh(rawRefreshToken, "")
}

// refresh rotates the token. adoptClientID, when non-empty, is recorded on the
// replacement for a token that carried no client binding.
func (s *AuthService) refresh(rawRefreshToken, adoptClientID string) (*LoginResult, error) {
	tokenHash := HashToken(rawRefreshToken)

	// Build the new token before entering the atomic rotation so we can
	// pass it in. We need a temporary UserID/FamilyID — these will be set
	// from the old token inside issueTokensAtomic.
	rawRefresh, err := generateRawToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	// nil means "no registration to consult" — the stored set stands, and
	// RotateToken carries it forward.
	resolvedAuds := s.resolveAudiences(tokenHash, adoptClientID)

	now := time.Now().UTC()
	newTok := &domain.RefreshToken{
		ID:         uuid.New().String(),
		TokenHash:  HashToken(rawRefresh),
		ClientID:   adoptClientID,
		IssuedAt:   now,
		LastUsedAt: now,
		ExpiresAt:  now.Add(s.refreshTokenTTL),
		Audiences:  resolvedAuds,
	}

	// Atomically: read old token, check not revoked, revoke it, insert new token.
	oldTok, err := s.tokens.RotateToken(tokenHash, newTok)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, ErrInvalidRefreshToken
	}
	if errors.Is(err, domain.ErrTokenAlreadyRevoked) {
		// Token reuse detected — potential theft, invalidate entire family
		s.record(&domain.AuthEvent{
			EventType: domain.EventTokenFamilyCompromised,
			UserID:    oldTok.UserID,
			Username:  s.lookupUsername(oldTok.UserID),
		})
		if rErr := s.tokens.RevokeFamilyByHash(tokenHash); rErr != nil {
			// The client still receives token_family_compromised, but a failed
			// family revocation must not be silent — the family may remain usable.
			log.Printf("auth: token reuse detected but family revocation failed for user %s: %v", oldTok.UserID, rErr)
		}
		return nil, ErrTokenFamilyCompromised
	}
	if err != nil {
		return nil, fmt.Errorf("rotate token: %w", err)
	}

	// Post-rotation checks: expiry and user status.
	// The token has already been revoked atomically; if these fail the old
	// token is consumed (which is correct — the client must re-login).
	if time.Now().After(oldTok.ExpiresAt) {
		return nil, ErrRefreshTokenExpired
	}

	user, err := s.users.GetByID(oldTok.UserID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	if !user.IsActive {
		return nil, ErrAccountDisabled
	}

	// The resolved set when the token names a client, the stored set otherwise.
	// Deriving this here rather than reading it back off newTok keeps the
	// access token's aud a decision this function makes, instead of one that
	// depends on RotateToken having filled the field in as a side effect.
	audience := resolvedAuds
	if audience == nil {
		audience = oldTok.Audiences
	}

	// Mint the access token now that we know the user is valid.
	claims := domain.TokenClaims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		IsActive: user.IsActive,
		Audience: audience,
		Scope:    oldTok.Scope,
	}

	accessToken, err := s.issuer.Mint(claims)
	if err != nil {
		return nil, fmt.Errorf("mint access token: %w", err)
	}

	return &LoginResult{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    900,
		RefreshToken: rawRefresh,
	}, nil
}

// Logout revokes a specific refresh token, or all tokens for the user if
// rawRefreshToken is empty.
func (s *AuthService) Logout(userID, rawRefreshToken string) error {
	username := s.lookupUsername(userID)

	if rawRefreshToken == "" {
		err := s.tokens.RevokeAllForUser(userID)
		if err == nil {
			s.record(&domain.AuthEvent{
				EventType: domain.EventLogoutAll,
				UserID:    userID,
				Username:  username,
			})
		}
		return err
	}

	tokenHash := HashToken(rawRefreshToken)
	tok, err := s.tokens.GetByHash(tokenHash)
	if errors.Is(err, domain.ErrNotFound) {
		// Token not found — treat as already logged out (idempotent)
		return nil
	}
	if err != nil {
		return fmt.Errorf("get token: %w", err)
	}

	// The token has to belong to the caller. Logout looked it up by hash and
	// revoked it on the strength of that alone, so any authenticated user
	// holding somebody else's refresh token could end their session with it.
	if tok.UserID != userID {
		s.record(&domain.AuthEvent{
			EventType: domain.EventLogout,
			UserID:    userID,
			Username:  username,
			Detail:    "refused: refresh token belongs to another user",
		})
		return ErrInvalidRefreshToken
	}

	err = s.tokens.RevokeByID(tok.ID)
	if err == nil {
		s.record(&domain.AuthEvent{
			EventType: domain.EventLogout,
			UserID:    userID,
			Username:  username,
		})
	}
	return err
}

// issueTokens mints a new access token + refresh token pair.
func (s *AuthService) issueTokens(user *domain.User, args loginArgs) (*LoginResult, error) {
	claims := domain.TokenClaims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		IsActive: user.IsActive,
		Audience: args.audience,
		Scope:    args.scope,
	}

	accessToken, err := s.issuer.Mint(claims)
	if err != nil {
		return nil, fmt.Errorf("mint access token: %w", err)
	}

	rawRefresh, err := generateRawToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	familyID := args.familyID
	if familyID == "" {
		familyID = uuid.New().String()
	}

	now := time.Now().UTC()
	newTok := &domain.RefreshToken{
		ID:            uuid.New().String(),
		UserID:        user.ID,
		TokenHash:     HashToken(rawRefresh),
		FamilyID:      familyID,
		ParentTokenID: args.oldTokenID,
		DeviceHint:    args.deviceHint,
		Audiences:     args.audience,
		Scope:         args.scope,
		ClaimCodeID:   args.claimCodeID,
		AuthCodeID:    args.authCodeID,
		ClientID:      args.clientID,
		IssuedAt:      now,
		LastUsedAt:    now,
		ExpiresAt:     now.Add(s.refreshTokenTTL),
	}

	if args.oldTokenID != "" {
		// Rotate: atomically revoke old token and insert new one
		if err := s.tokens.Rotate(args.oldTokenID, newTok); err != nil {
			return nil, fmt.Errorf("rotate token: %w", err)
		}
	} else {
		// Fresh login: insert new token
		if err := s.tokens.Create(newTok); err != nil {
			return nil, fmt.Errorf("create token: %w", err)
		}
	}

	return &LoginResult{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    900,
		RefreshToken: rawRefresh,
	}, nil
}

// lookupUsername returns the username for a userID, falling back to the ID itself.
// RevokeTokensForAuthCode revokes every refresh token descended from an
// authorization code. See TokenRepository.RevokeByAuthCodeID.
func (s *AuthService) RevokeTokensForAuthCode(authCodeID string) error {
	return s.tokens.RevokeByAuthCodeID(authCodeID)
}

// UsernameForID resolves a user id to a username for audit records.
func (s *AuthService) UsernameForID(userID string) string {
	return s.lookupUsername(userID)
}

func (s *AuthService) lookupUsername(userID string) string {
	if u, err := s.users.GetByID(userID); err == nil {
		return u.Username
	}
	return userID
}

// record writes an audit event, ignoring errors (best-effort).
func (s *AuthService) record(event *domain.AuthEvent) {
	if s.audit == nil {
		return
	}
	event.ID = uuid.New().String()
	event.OccurredAt = time.Now().UTC()
	_ = s.audit.Record(event)
}
