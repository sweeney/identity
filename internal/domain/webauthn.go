package domain

import "time"

// WebAuthnCredential is a stored passkey credential.
//
//go:generate mockgen -destination=../mocks/mock_webauthn_credential_repository.go -package=mocks github.com/sweeney/identity/internal/domain WebAuthnCredentialRepository
type WebAuthnCredential struct {
	ID              string
	UserID          string
	CredentialID    []byte
	PublicKey       []byte
	AttestationType string
	AAGUID          []byte
	SignCount       uint32
	Transports      []string // e.g. ["internal", "hybrid"]
	BackupEligible  bool
	BackupState     bool
	UserPresent     bool
	UserVerified    bool
	Name            string // user-provided label
	CreatedAt       time.Time
	LastUsedAt      time.Time
}

// WebAuthnCredentialRepository defines persistence operations for WebAuthn credentials.
type WebAuthnCredentialRepository interface {
	Create(cred *WebAuthnCredential) error
	GetByCredentialID(credentialID []byte) (*WebAuthnCredential, error)
	ListByUserID(userID string) ([]*WebAuthnCredential, error)
	UpdateSignCount(id string, signCount uint32) error
	UpdateLastUsed(id string, t time.Time) error
	Rename(id, name string) error
	Delete(id string) error
	DeleteAllForUser(userID string) error
}

// WebAuthnChallenge stores ephemeral challenge data for in-flight ceremonies.
//
//go:generate mockgen -destination=../mocks/mock_webauthn_challenge_repository.go -package=mocks github.com/sweeney/identity/internal/domain WebAuthnChallengeRepository
type WebAuthnChallenge struct {
	ID          string
	UserID      string // empty for discoverable-credential login
	Challenge   []byte
	Type        string // "registration" or "authentication"
	SessionData string // JSON blob from go-webauthn library
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// WebAuthnChallengeRepository defines persistence operations for WebAuthn challenges.
type WebAuthnChallengeRepository interface {
	Create(ch *WebAuthnChallenge) error
	GetByID(id string) (*WebAuthnChallenge, error)
	// Consume atomically reads and deletes a challenge in a single transaction,
	// preventing TOCTOU race conditions where two concurrent requests could both
	// consume the same challenge.
	Consume(id string) (*WebAuthnChallenge, error)
	Delete(id string) error
	DeleteExpired() error
}

// WebAuthn audit event type constants.
const (
	EventPasskeyRegisterSuccess = "passkey_register_success"
	EventPasskeyRegisterFailure = "passkey_register_failure"
	EventPasskeyLoginSuccess    = "passkey_login_success"
	EventPasskeyLoginFailure    = "passkey_login_failure"
	EventPasskeyDeleted         = "passkey_deleted"
)
