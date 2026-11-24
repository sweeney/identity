package domain

import (
	"time"

	commonauth "github.com/sweeney/identity/common/auth"
)

// RefreshToken represents a persisted refresh token entry.
type RefreshToken struct {
	ID            string
	UserID        string
	TokenHash     string   // SHA-256 hex of the raw bearer token
	FamilyID      string   // Groups a rotation chain; whole family invalidated on reuse detection
	ParentTokenID string   // ID of the token this one replaced (may be empty for first in family)
	DeviceHint    string   // Informational only, e.g. "iPhone 15 / iOS 18"
	Audiences     []string // aud claim to carry into new access tokens on rotation
	Scope         string   // space-delimited scope this grant was consented for; empty means unrestricted
	ClaimCodeID   string   // claim code that produced this family, if any; revoking it revokes the family
	AuthCodeID    string   // authorization code that produced this family, if any; replaying it revokes the family
	ClientID      string   // OAuth client this token was issued to; empty for a direct API login
	IssuedAt      time.Time
	LastUsedAt    time.Time
	ExpiresAt     time.Time
	IsRevoked     bool
	RevokedReason RevokeReason // why it was revoked; empty while live, or for a token revoked before reasons were recorded
}

// RevokeReason records why a refresh token was revoked, so that a later
// presentation of it can be classified. Only a replay of a rotated token (or
// one whose reason is unknown) is a theft signal; the others mean a client is
// still holding a token it was deliberately signed out of.
type RevokeReason string

const (
	RevokeReasonRotated          RevokeReason = "rotated"
	RevokeReasonFamilyRevoked    RevokeReason = "family_revoked"
	RevokeReasonLogout           RevokeReason = "logout"
	RevokeReasonLogoutAll        RevokeReason = "logout_all"
	RevokeReasonPasswordChange   RevokeReason = "password_change"
	RevokeReasonDeactivated      RevokeReason = "deactivated"
	RevokeReasonClaimCodeRevoked RevokeReason = "claim_code_revoked"
	RevokeReasonAuthCodeReplayed RevokeReason = "auth_code_replayed"
)

// IndicatesTheft reports whether presenting a token revoked for this reason
// is a theft signal. A rotated token should never be seen again, and an
// unknown reason (a token revoked before reasons were recorded) keeps the
// cautious treatment it always had.
func (r RevokeReason) IndicatesTheft() bool {
	return r == RevokeReasonRotated || r == ""
}

// TokenFamily groups refresh tokens issued from the same login.
// Invalidating a family immediately revokes all tokens within it.
type TokenFamily struct {
	FamilyID string
	UserID   string
}

// TokenClaims holds the parsed contents of a JWT access token.
type TokenClaims = commonauth.TokenClaims

// ServiceTokenClaims holds the parsed contents of a service (client credentials) JWT.
type ServiceTokenClaims = commonauth.ServiceTokenClaims

// AudienceList builds a token audience list from a single configured audience
// string. Retained for callers that genuinely have one value; a client's
// audiences are already a list and need no conversion.
var AudienceList = commonauth.AudienceList

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

	// RevokeByID revokes a single token by its ID, recording why.
	RevokeByID(id string, reason RevokeReason) error

	// RevokeAllForUser revokes every live refresh token belonging to a user,
	// recording why. Tokens already revoked keep their original reason.
	RevokeAllForUser(userID string, reason RevokeReason) error

	// RevokeByClaimCodeID revokes every refresh token issued from the given
	// claim code. Used when an admin revokes a device's sticker code, so the
	// tokens it already produced die with it rather than living out the
	// refresh token's 30-day window.
	RevokeByClaimCodeID(claimCodeID string) error

	// RevokeByAuthCodeID revokes every refresh token descended from the given
	// authorization code. Used when that code is replayed: a single-use code
	// presented twice has leaked, and RFC 6749 §4.1.2 asks that the tokens it
	// already produced die with it rather than outliving the compromise.
	RevokeByAuthCodeID(authCodeID string) error

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
