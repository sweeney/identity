package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
)

// WebAuthnServicer is the interface the API handler uses for passkey operations.
//
//go:generate mockgen -destination=../mocks/mock_webauthn_service.go -package=mocks github.com/sweeney/identity/internal/service WebAuthnServicer
type WebAuthnServicer interface {
	// Registration (user must be authenticated)
	BeginRegistration(userID string) (*protocol.CredentialCreation, string, error)
	FinishRegistration(userID, challengeID, name string, r *http.Request) (*domain.WebAuthnCredential, error)

	// Authentication (no auth required)
	BeginLogin(username string) (*protocol.CredentialAssertion, string, error)
	FinishLogin(challengeID string, r *http.Request, deviceHint, clientIP string) (*LoginResult, error)

	// Credential management
	ListCredentials(userID string) ([]*domain.WebAuthnCredential, error)
	RenameCredential(userID, credentialID, name string) error
	DeleteCredential(userID, credentialID string) error
}

// WebAuthnService handles passkey registration, authentication, and credential management.
type WebAuthnService struct {
	wa          *webauthn.WebAuthn
	authSvc      *AuthService
	users        domain.UserRepository
	credentials  domain.WebAuthnCredentialRepository
	challenges   domain.WebAuthnChallengeRepository
	audit        domain.AuditRepository
	backup       domain.BackupService
	challengeTTL time.Duration
}

// NewWebAuthnService creates a WebAuthnService.
func NewWebAuthnService(
	wa *webauthn.WebAuthn,
	authSvc *AuthService,
	users domain.UserRepository,
	credentials domain.WebAuthnCredentialRepository,
	challenges domain.WebAuthnChallengeRepository,
	audit domain.AuditRepository,
	backup domain.BackupService,
) *WebAuthnService {
	return &WebAuthnService{
		wa:           wa,
		authSvc:      authSvc,
		users:        users,
		credentials:  credentials,
		challenges:   challenges,
		audit:        audit,
		backup:       backup,
		challengeTTL: 120 * time.Second,
	}
}

// BeginRegistration starts the WebAuthn registration ceremony for an authenticated user.
// Returns the credential creation options and a challenge ID.
func (s *WebAuthnService) BeginRegistration(userID string) (*protocol.CredentialCreation, string, error) {
	if s.wa == nil {
		return nil, "", ErrWebAuthnNotEnabled
	}

	user, err := s.users.GetByID(userID)
	if err != nil {
		return nil, "", fmt.Errorf("get user: %w", err)
	}

	existingCreds, err := s.credentials.ListByUserID(userID)
	if err != nil {
		return nil, "", fmt.Errorf("list credentials: %w", err)
	}

	waUser := &auth.WebAuthnUser{
		User:        user,
		Credentials: auth.DomainCredentialsToWebAuthn(existingCreds),
	}

	creation, sessionData, err := s.wa.BeginRegistration(waUser)
	if err != nil {
		return nil, "", fmt.Errorf("begin registration: %w", err)
	}

	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("marshal session: %w", err)
	}

	now := time.Now().UTC()
	challengeID := uuid.New().String()
	ch := &domain.WebAuthnChallenge{
		ID:          challengeID,
		UserID:      userID,
		Challenge:   []byte(sessionData.Challenge),
		Type:        "registration",
		SessionData: string(sessionJSON),
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.challengeTTL),
	}
	if err := s.challenges.Create(ch); err != nil {
		return nil, "", fmt.Errorf("store challenge: %w", err)
	}

	return creation, challengeID, nil
}

// FinishRegistration completes the WebAuthn registration ceremony.
func (s *WebAuthnService) FinishRegistration(userID, challengeID, name string, r *http.Request) (*domain.WebAuthnCredential, error) {
	if s.wa == nil {
		return nil, ErrWebAuthnNotEnabled
	}

	ch, err := s.challenges.GetByID(challengeID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrWebAuthnInvalidChallenge
		}
		return nil, fmt.Errorf("get challenge: %w", err)
	}

	// Always clean up the challenge
	defer s.challenges.Delete(challengeID) //nolint:errcheck

	if ch.UserID != userID || ch.Type != "registration" {
		return nil, ErrWebAuthnInvalidChallenge
	}

	if time.Now().After(ch.ExpiresAt) {
		return nil, ErrWebAuthnInvalidChallenge
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(ch.SessionData), &sessionData); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	user, err := s.users.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	existingCreds, err := s.credentials.ListByUserID(userID)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}

	waUser := &auth.WebAuthnUser{
		User:        user,
		Credentials: auth.DomainCredentialsToWebAuthn(existingCreds),
	}

	credential, err := s.wa.FinishRegistration(waUser, sessionData, r)
	if err != nil {
		s.recordEvent(domain.EventPasskeyRegisterFailure, userID, user.Username, err.Error())
		return nil, ErrWebAuthnVerificationFailed
	}

	// Extract transports
	transports := make([]string, len(credential.Transport))
	for i, t := range credential.Transport {
		transports[i] = string(t)
	}

	now := time.Now().UTC()
	domainCred := &domain.WebAuthnCredential{
		ID:              uuid.New().String(),
		UserID:          userID,
		CredentialID:    credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		AAGUID:          credential.Authenticator.AAGUID,
		SignCount:       credential.Authenticator.SignCount,
		Transports:      transports,
		BackupEligible:  credential.Flags.BackupEligible,
		BackupState:     credential.Flags.BackupState,
		Name:            name,
		CreatedAt:       now,
		LastUsedAt:      now,
	}
	if err := s.credentials.Create(domainCred); err != nil {
		return nil, fmt.Errorf("store credential: %w", err)
	}

	s.recordEvent(domain.EventPasskeyRegisterSuccess, userID, user.Username, "")
	s.backup.TriggerAsync()
	return domainCred, nil
}

// BeginLogin starts the WebAuthn authentication ceremony.
// If username is empty, uses discoverable credential flow (username-less).
func (s *WebAuthnService) BeginLogin(username string) (*protocol.CredentialAssertion, string, error) {
	if s.wa == nil {
		return nil, "", ErrWebAuthnNotEnabled
	}

	var assertion *protocol.CredentialAssertion
	var sessionData *webauthn.SessionData
	var userID string
	var err error

	if username == "" {
		// Discoverable credential flow — no allowCredentials
		assertion, sessionData, err = s.wa.BeginDiscoverableLogin()
		if err != nil {
			return nil, "", fmt.Errorf("begin discoverable login: %w", err)
		}
	} else {
		user, userErr := s.users.GetByUsername(username)
		if errors.Is(userErr, domain.ErrNotFound) {
			// Don't reveal whether user exists — return a fake challenge
			// that will fail at FinishLogin. This matches the bcrypt dummy hash pattern.
			assertion, sessionData, err = s.wa.BeginDiscoverableLogin()
			if err != nil {
				return nil, "", fmt.Errorf("begin login: %w", err)
			}
		} else if userErr != nil {
			return nil, "", fmt.Errorf("get user: %w", userErr)
		} else {
			userID = user.ID
			creds, credErr := s.credentials.ListByUserID(user.ID)
			if credErr != nil {
				return nil, "", fmt.Errorf("list credentials: %w", credErr)
			}
			if len(creds) == 0 {
				return nil, "", ErrWebAuthnNoCredentials
			}

			waUser := &auth.WebAuthnUser{
				User:        user,
				Credentials: auth.DomainCredentialsToWebAuthn(creds),
			}
			assertion, sessionData, err = s.wa.BeginLogin(waUser)
			if err != nil {
				return nil, "", fmt.Errorf("begin login: %w", err)
			}
		}
	}

	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("marshal session: %w", err)
	}

	now := time.Now().UTC()
	challengeID := uuid.New().String()
	ch := &domain.WebAuthnChallenge{
		ID:          challengeID,
		UserID:      userID,
		Challenge:   []byte(sessionData.Challenge),
		Type:        "authentication",
		SessionData: string(sessionJSON),
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.challengeTTL),
	}
	if err := s.challenges.Create(ch); err != nil {
		return nil, "", fmt.Errorf("store challenge: %w", err)
	}

	return assertion, challengeID, nil
}

// FinishLogin completes the WebAuthn authentication ceremony and issues JWT tokens.
func (s *WebAuthnService) FinishLogin(challengeID string, r *http.Request, deviceHint, clientIP string) (*LoginResult, error) {
	if s.wa == nil {
		return nil, ErrWebAuthnNotEnabled
	}

	ch, err := s.challenges.GetByID(challengeID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrWebAuthnInvalidChallenge
		}
		return nil, fmt.Errorf("get challenge: %w", err)
	}

	// Always clean up the challenge
	defer s.challenges.Delete(challengeID) //nolint:errcheck

	if ch.Type != "authentication" {
		return nil, ErrWebAuthnInvalidChallenge
	}

	if time.Now().After(ch.ExpiresAt) {
		return nil, ErrWebAuthnInvalidChallenge
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(ch.SessionData), &sessionData); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	var credential *webauthn.Credential
	var authenticatedUserID string

	if ch.UserID == "" {
		// Discoverable credential flow — resolve user from the credential's user handle
		credential, err = s.wa.FinishDiscoverableLogin(
			func(rawID, userHandle []byte) (webauthn.User, error) {
				userID := string(userHandle)
				user, uErr := s.users.GetByID(userID)
				if uErr != nil {
					return nil, fmt.Errorf("user not found: %w", uErr)
				}
				creds, cErr := s.credentials.ListByUserID(userID)
				if cErr != nil {
					return nil, fmt.Errorf("list credentials: %w", cErr)
				}
				authenticatedUserID = userID
				return &auth.WebAuthnUser{
					User:        user,
					Credentials: auth.DomainCredentialsToWebAuthn(creds),
				}, nil
			},
			sessionData,
			r,
		)
	} else {
		// Known user flow
		authenticatedUserID = ch.UserID
		user, uErr := s.users.GetByID(ch.UserID)
		if uErr != nil {
			return nil, fmt.Errorf("get user: %w", uErr)
		}
		creds, cErr := s.credentials.ListByUserID(ch.UserID)
		if cErr != nil {
			return nil, fmt.Errorf("list credentials: %w", cErr)
		}
		waUser := &auth.WebAuthnUser{
			User:        user,
			Credentials: auth.DomainCredentialsToWebAuthn(creds),
		}
		credential, err = s.wa.FinishLogin(waUser, sessionData, r)
	}

	if err != nil {
		username := s.lookupUsername(authenticatedUserID)
		s.recordEvent(domain.EventPasskeyLoginFailure, authenticatedUserID, username, err.Error())
		return nil, ErrWebAuthnVerificationFailed
	}

	// Update sign count and last used
	storedCred, err := s.credentials.GetByCredentialID(credential.ID)
	if err != nil {
		return nil, fmt.Errorf("get stored credential: %w", err)
	}
	now := time.Now().UTC()
	s.credentials.UpdateSignCount(storedCred.ID, credential.Authenticator.SignCount) //nolint:errcheck
	s.credentials.UpdateLastUsed(storedCred.ID, now)                                 //nolint:errcheck

	// Check user is active
	user, err := s.users.GetByID(authenticatedUserID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if !user.IsActive {
		return nil, ErrAccountDisabled
	}

	// Issue JWT + refresh token via the existing auth service
	result, err := s.authSvc.issueTokens(user, loginArgs{deviceHint: deviceHint})
	if err != nil {
		return nil, err
	}

	s.recordEvent(domain.EventPasskeyLoginSuccess, user.ID, user.Username, "")
	return result, nil
}

// ListCredentials returns all passkeys for a user.
func (s *WebAuthnService) ListCredentials(userID string) ([]*domain.WebAuthnCredential, error) {
	return s.credentials.ListByUserID(userID)
}

// RenameCredential renames a passkey credential that belongs to the given user.
// credentialID is the internal UUID (not the raw WebAuthn credential ID).
func (s *WebAuthnService) RenameCredential(userID, credentialID, name string) error {
	cred, err := s.findOwnedCredential(userID, credentialID)
	if err != nil {
		return err
	}
	return s.credentials.Rename(cred.ID, name)
}

// DeleteCredential deletes a passkey credential that belongs to the given user.
// credentialID is the internal UUID (not the raw WebAuthn credential ID).
func (s *WebAuthnService) DeleteCredential(userID, credentialID string) error {
	cred, err := s.findOwnedCredential(userID, credentialID)
	if err != nil {
		return err
	}

	if err := s.credentials.Delete(cred.ID); err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}

	username := s.lookupUsername(userID)
	s.recordEvent(domain.EventPasskeyDeleted, userID, username, "")
	s.backup.TriggerAsync()
	return nil
}

// findOwnedCredential looks up a credential by internal ID and verifies it belongs to the user.
func (s *WebAuthnService) findOwnedCredential(userID, credentialID string) (*domain.WebAuthnCredential, error) {
	creds, err := s.credentials.ListByUserID(userID)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	for _, c := range creds {
		if c.ID == credentialID {
			return c, nil
		}
	}
	return nil, ErrWebAuthnCredentialNotFound
}

// lookupUsername returns the username for a userID, falling back to the ID itself.
func (s *WebAuthnService) lookupUsername(userID string) string {
	if userID == "" {
		return ""
	}
	if u, err := s.users.GetByID(userID); err == nil {
		return u.Username
	}
	return userID
}

// recordEvent writes an audit event, ignoring errors (best-effort).
func (s *WebAuthnService) recordEvent(eventType, userID, username, detail string) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(&domain.AuthEvent{
		ID:         uuid.New().String(),
		EventType:  eventType,
		UserID:     userID,
		Username:   username,
		Detail:     detail,
		OccurredAt: time.Now().UTC(),
	})
}
