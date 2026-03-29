package service

import (
	"errors"
	"fmt"
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
	issuer          *auth.TokenIssuer
	users           domain.UserRepository
	tokens          domain.TokenRepository
	backup          domain.BackupService
	audit           domain.AuditRepository
	refreshTokenTTL time.Duration
}

// NewAuthService creates an AuthService.
func NewAuthService(
	issuer *auth.TokenIssuer,
	users domain.UserRepository,
	tokens domain.TokenRepository,
	backup domain.BackupService,
	audit domain.AuditRepository,
	refreshTokenTTL time.Duration,
) *AuthService {
	return &AuthService{
		issuer:          issuer,
		users:           users,
		tokens:          tokens,
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
	audience   string // optional aud claim; set for OAuth PKCE flow
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
		return nil, ErrAccountDisabled
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
// Used by OAuthService at the authorize step.
func (s *AuthService) AuthorizeUser(username, password, clientIP string) (string, error) {
	user, err := s.users.GetByUsername(username)
	if errors.Is(err, domain.ErrNotFound) {
		auth.CheckPassword(password, dummyHash) //nolint:errcheck
		return "", ErrInvalidCredentials
	}
	if err != nil {
		return "", fmt.Errorf("get user: %w", err)
	}

	if err := auth.CheckPassword(password, user.PasswordHash); err != nil {
		return "", ErrInvalidCredentials
	}

	if !user.IsActive {
		return "", ErrAccountDisabled
	}

	return user.ID, nil
}

// IssueTokensForUser issues a token pair for a pre-authenticated user.
// audience is the aud claim to embed in the access token; pass "" to omit it.
// Used by OAuthService at the code exchange step.
func (s *AuthService) IssueTokensForUser(userID, audience string) (*LoginResult, error) {
	user, err := s.users.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if !user.IsActive {
		return nil, ErrAccountDisabled
	}
	return s.issueTokens(user, loginArgs{audience: audience})
}

// Refresh validates a refresh token and issues a new token pair via rotation.
// The read-validate-revoke-insert sequence is performed atomically within a
// single transaction by RotateToken, preventing the TOCTOU race condition
// where concurrent requests could both observe the token as valid.
func (s *AuthService) Refresh(rawRefreshToken string) (*LoginResult, error) {
	tokenHash := HashToken(rawRefreshToken)

	// Build the new token before entering the atomic rotation so we can
	// pass it in. We need a temporary UserID/FamilyID — these will be set
	// from the old token inside issueTokensAtomic.
	rawRefresh, err := generateRawToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	now := time.Now().UTC()
	newTok := &domain.RefreshToken{
		ID:         uuid.New().String(),
		TokenHash:  HashToken(rawRefresh),
		IssuedAt:   now,
		LastUsedAt: now,
		ExpiresAt:  now.Add(s.refreshTokenTTL),
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
			_ = rErr
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

	// Mint the access token now that we know the user is valid.
	claims := domain.TokenClaims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		IsActive: user.IsActive,
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
