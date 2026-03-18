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
// Used by OAuthService at the code exchange step.
func (s *AuthService) IssueTokensForUser(userID string) (*LoginResult, error) {
	user, err := s.users.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if !user.IsActive {
		return nil, ErrAccountDisabled
	}
	return s.issueTokens(user, loginArgs{})
}

// Refresh validates a refresh token and issues a new token pair via rotation.
func (s *AuthService) Refresh(rawRefreshToken string) (*LoginResult, error) {
	tokenHash := HashToken(rawRefreshToken)

	tok, err := s.tokens.GetByHash(tokenHash)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, fmt.Errorf("get token: %w", err)
	}

	// Token reuse detected — potential theft, invalidate entire family
	if tok.IsRevoked {
		s.record(&domain.AuthEvent{
			EventType: domain.EventTokenFamilyCompromised,
			UserID:    tok.UserID,
			Username:  s.lookupUsername(tok.UserID),
		})
		if rErr := s.tokens.RevokeFamilyByHash(tokenHash); rErr != nil {
			_ = rErr
		}
		return nil, ErrTokenFamilyCompromised
	}

	if time.Now().After(tok.ExpiresAt) {
		return nil, ErrRefreshTokenExpired
	}

	user, err := s.users.GetByID(tok.UserID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	if !user.IsActive {
		return nil, ErrAccountDisabled
	}

	return s.issueTokens(user, loginArgs{
		oldTokenID: tok.ID,
		familyID:   tok.FamilyID,
		deviceHint: tok.DeviceHint,
	})
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
		// Fresh login: insert new token and trigger backup
		if err := s.tokens.Create(newTok); err != nil {
			return nil, fmt.Errorf("create token: %w", err)
		}
		s.backup.TriggerAsync()
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
