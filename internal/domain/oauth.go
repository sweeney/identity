package domain

import "time"

// OAuthClient is a registered OAuth application persisted to DB.
//
//go:generate mockgen -destination=../mocks/mock_oauth_client_repository.go -package=mocks github.com/sweeney/identity/internal/domain OAuthClientRepository
type OAuthClient struct {
	ID           string
	Name         string
	RedirectURIs []string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// AuthCode is a single-use authorization code persisted to DB.
//
//go:generate mockgen -destination=../mocks/mock_oauth_code_repository.go -package=mocks github.com/sweeney/identity/internal/domain OAuthCodeRepository
type AuthCode struct {
	ID            string
	CodeHash      string
	ClientID      string
	UserID        string
	RedirectURI   string
	CodeChallenge string
	IssuedAt      time.Time
	ExpiresAt     time.Time
	UsedAt        *time.Time
}

// AuthEvent is an immutable audit record (append-only).
//
//go:generate mockgen -destination=../mocks/mock_audit_repository.go -package=mocks github.com/sweeney/identity/internal/domain AuditRepository
type AuthEvent struct {
	ID         string
	EventType  string
	UserID     string // empty for unknown-user failures
	Username   string
	ClientID   string // empty for direct API logins
	DeviceHint string
	IPAddress  string
	Detail     string // free-text context, e.g. "created user alice"
	OccurredAt time.Time
}

// Auth event type constants.
const (
	EventLoginSuccess           = "login_success"
	EventLoginFailure           = "login_failure"
	EventOAuthAuthorizeSuccess  = "oauth_authorize_success"
	EventOAuthAuthorizeFailure  = "oauth_authorize_failure"
	EventTokenFamilyCompromised = "token_family_compromised"
	EventLogout                 = "logout"
	EventLogoutAll              = "logout_all"
	EventUserCreated            = "user_created"
	EventUserUpdated            = "user_updated"
	EventUserDeleted            = "user_deleted"
	EventUserDeactivated        = "user_deactivated"
	EventOAuthClientCreated     = "oauth_client_created"
	EventOAuthClientUpdated     = "oauth_client_updated"
	EventOAuthClientDeleted     = "oauth_client_deleted"
	EventBackupSuccess          = "backup_success"
	EventBackupFailure          = "backup_failure"
)

// OAuthClientRepository defines persistence operations for OAuth clients.
type OAuthClientRepository interface {
	Create(client *OAuthClient) error
	GetByID(id string) (*OAuthClient, error)
	List() ([]*OAuthClient, error)
	Update(client *OAuthClient) error
	Delete(id string) error
}

// OAuthCodeRepository defines persistence operations for authorization codes.
type OAuthCodeRepository interface {
	Create(code *AuthCode) error
	GetByHash(codeHash string) (*AuthCode, error)
	MarkUsed(id string, usedAt time.Time) error
	DeleteExpiredAndUsed() error
}

// AuditRepository defines persistence operations for the audit log.
type AuditRepository interface {
	Record(event *AuthEvent) error
	List(limit int) ([]*AuthEvent, error)
	ListForUser(userID string, limit int) ([]*AuthEvent, error)
}
