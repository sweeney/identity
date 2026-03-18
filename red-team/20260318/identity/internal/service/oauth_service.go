package service

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/sweeney/identity/internal/domain"
)

// OAuthService orchestrates the OAuth 2.0 authorization code flow with PKCE.
type OAuthService struct {
	auth    AuthServicer
	clients domain.OAuthClientRepository
	codes   domain.OAuthCodeRepository
	audit   domain.AuditRepository
	codeTTL time.Duration
}

// NewOAuthService creates an OAuthService.
func NewOAuthService(
	auth AuthServicer,
	clients domain.OAuthClientRepository,
	codes domain.OAuthCodeRepository,
	audit domain.AuditRepository,
	codeTTL time.Duration,
) *OAuthService {
	return &OAuthService{
		auth:    auth,
		clients: clients,
		codes:   codes,
		audit:   audit,
		codeTTL: codeTTL,
	}
}

// ValidateAuthorizeRequest looks up the client and validates the redirect URI.
func (s *OAuthService) ValidateAuthorizeRequest(clientID, redirectURI string) (*domain.OAuthClient, error) {
	client, err := s.clients.GetByID(clientID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, ErrUnknownClient
	}
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}

	if !containsURI(client.RedirectURIs, redirectURI) {
		return nil, ErrInvalidRedirectURI
	}

	return client, nil
}

// Authorize authenticates the user and issues an authorization code.
func (s *OAuthService) Authorize(clientID, redirectURI, username, password, codeChallenge, ip string) (string, error) {
	userID, err := s.auth.AuthorizeUser(username, password, ip)
	if err != nil {
		s.record(&domain.AuthEvent{
			EventType: domain.EventOAuthAuthorizeFailure,
			Username:  username,
			ClientID:  clientID,
			IPAddress: ip,
		})
		return "", err
	}

	rawCode, err := generateRawToken()
	if err != nil {
		return "", fmt.Errorf("generate code: %w", err)
	}

	now := time.Now().UTC()
	authCode := &domain.AuthCode{
		ID:            uuid.New().String(),
		CodeHash:      HashToken(rawCode),
		ClientID:      clientID,
		UserID:        userID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		IssuedAt:      now,
		ExpiresAt:     now.Add(s.codeTTL),
	}

	if err := s.codes.Create(authCode); err != nil {
		return "", fmt.Errorf("store auth code: %w", err)
	}

	s.record(&domain.AuthEvent{
		EventType: domain.EventOAuthAuthorizeSuccess,
		UserID:    userID,
		Username:  username,
		ClientID:  clientID,
		IPAddress: ip,
	})

	return rawCode, nil
}

// ExchangeCode validates the authorization code and PKCE, then issues tokens.
func (s *OAuthService) ExchangeCode(clientID, rawCode, redirectURI, codeVerifier string) (*LoginResult, error) {
	codeHash := HashToken(rawCode)
	code, err := s.codes.GetByHash(codeHash)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, ErrInvalidAuthCode
	}
	if err != nil {
		return nil, fmt.Errorf("get auth code: %w", err)
	}

	if code.ClientID != clientID {
		return nil, ErrInvalidAuthCode
	}

	if code.RedirectURI != redirectURI {
		return nil, ErrInvalidAuthCode
	}

	if code.UsedAt != nil {
		return nil, ErrAuthCodeAlreadyUsed
	}

	if time.Now().After(code.ExpiresAt) {
		return nil, ErrAuthCodeExpired
	}

	if !verifyPKCE(codeVerifier, code.CodeChallenge) {
		return nil, ErrPKCEVerificationFailed
	}

	if err := s.codes.MarkUsed(code.ID, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("mark code used: %w", err)
	}

	return s.auth.IssueTokensForUser(code.UserID)
}

// RefreshToken delegates to the underlying auth service refresh.
func (s *OAuthService) RefreshToken(rawRefreshToken string) (*LoginResult, error) {
	return s.auth.Refresh(rawRefreshToken)
}

// verifyPKCE checks that sha256(verifier) == challenge (S256 method).
func verifyPKCE(verifier, challenge string) bool {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == challenge
}

// containsURI returns true if uri is in the slice.
func containsURI(uris []string, uri string) bool {
	for _, u := range uris {
		if u == uri {
			return true
		}
	}
	return false
}

// record writes an audit event, ignoring errors (best-effort).
func (s *OAuthService) record(event *domain.AuthEvent) {
	if s.audit == nil {
		return
	}
	event.ID = uuid.New().String()
	event.OccurredAt = time.Now().UTC()
	_ = s.audit.Record(event)
}
