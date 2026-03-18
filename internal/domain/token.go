package domain

import "time"

// RefreshToken represents a persisted refresh token entry.
type RefreshToken struct {
	ID            string
	UserID        string
	TokenHash     string // SHA-256 hex of the raw bearer token
	FamilyID      string // Groups a rotation chain; whole family invalidated on reuse detection
	ParentTokenID string // ID of the token this one replaced (may be empty for first in family)
	DeviceHint    string // Informational only, e.g. "iPhone 15 / iOS 18"
	IssuedAt      time.Time
	LastUsedAt    time.Time
	ExpiresAt     time.Time
	IsRevoked     bool
}

// TokenFamily groups refresh tokens issued from the same login.
// Invalidating a family immediately revokes all tokens within it.
type TokenFamily struct {
	FamilyID string
	UserID   string
}

// TokenClaims holds the parsed contents of a JWT access token.
type TokenClaims struct {
	UserID   string
	Username string
	Role     Role
	IsActive bool
}

// TokenRepository defines all persistence operations for refresh tokens.
//
//go:generate mockgen -destination=../mocks/mock_token_repository.go -package=mocks github.com/sweeney/identity/internal/domain TokenRepository
type TokenRepository interface {
	// Create inserts a new refresh token record.
	Create(token *RefreshToken) error

	// GetByHash retrieves a refresh token by its SHA-256 hash.
	GetByHash(tokenHash string) (*RefreshToken, error)

	// Rotate atomically marks oldTokenID as revoked and inserts newToken.
	// Uses BEGIN IMMEDIATE to prevent concurrent rotation races.
	Rotate(oldTokenID string, newToken *RefreshToken) error

	// RotateToken atomically validates the old token is not revoked, revokes it,
	// and inserts the new token. Returns the old token for caller inspection,
	// or an error if the token is not found, already revoked, etc.
	// This prevents the TOCTOU race condition where concurrent refresh requests
	// could both read the token as valid before either revokes it.
	RotateToken(oldTokenHash string, newToken *RefreshToken) (*RefreshToken, error)

	// RevokeFamilyByHash revokes all tokens sharing the family of the token with the given hash.
	// Used when token reuse (theft) is detected.
	RevokeFamilyByHash(tokenHash string) error

	// RevokeByID revokes a single token by its ID.
	RevokeByID(id string) error

	// RevokeAllForUser revokes every refresh token belonging to a user.
	RevokeAllForUser(userID string) error

	// DeleteExpiredAndOldRevoked removes tokens that are expired or have been
	// revoked for more than retentionDays days.
	DeleteExpiredAndOldRevoked(retentionDays int) error
}

// BackupService defines the interface for triggering database backups.
//
//go:generate mockgen -destination=../mocks/mock_backup_service.go -package=mocks github.com/sweeney/identity/internal/domain BackupService
type BackupService interface {
	// TriggerAsync queues a backup asynchronously. If a backup is already pending
	// the call is a no-op (coalescing channel).
	TriggerAsync()

	// RunNow executes a backup synchronously and returns any error.
	RunNow() error
}
