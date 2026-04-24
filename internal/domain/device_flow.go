package domain

import "time"

// Grant type identifier for RFC 8628 device authorization.
const GrantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

// Device authorization statuses.
const (
	DeviceStatusPending  = "pending"
	DeviceStatusApproved = "approved"
	DeviceStatusDenied   = "denied"
)

// DeviceAuthorization is a single in-flight device flow session.
//
// A row is created when a device calls POST /oauth/device_authorization (or
// POST /oauth/device/claim). It moves to Approved when a user verifies the
// user_code, and is consumed (ConsumedAt set) on the first successful poll
// that exchanges DeviceCode for tokens.
//
//go:generate mockgen -destination=../mocks/mock_device_authorization_repository.go -package=mocks github.com/sweeney/identity/internal/domain DeviceAuthorizationRepository
type DeviceAuthorization struct {
	ID             string
	DeviceCodeHash string  // SHA-256 hex of the opaque device_code (polling secret)
	UserCode       string  // 8-char user-typeable code (XXXX-XXXX)
	ClientID       string
	ClaimCodeID    string  // "" for standard device flow, set when the session originated from a claim code
	Scope          string  // space-delimited
	Status         string  // DeviceStatusPending | DeviceStatusApproved | DeviceStatusDenied
	UserID         string  // "" until approved
	IssuedAt       time.Time
	ExpiresAt      time.Time
	LastPolledAt   *time.Time
	PollInterval   int     // seconds
	ConsumedAt     *time.Time
}

// ClaimCode is a long-lived code printed on a device's sticker.
//
// Admins generate claim codes against an OAuth client. On first bind the
// code is associated with a user; all future device sessions using this
// claim_code are auto-approved as that user until the code is revoked.
//
//go:generate mockgen -destination=../mocks/mock_claim_code_repository.go -package=mocks github.com/sweeney/identity/internal/domain ClaimCodeRepository
type ClaimCode struct {
	ID          string
	CodeHash    string  // SHA-256 hex of the raw claim_code
	ClientID    string
	Label       string  // admin-set, e.g. "Kitchen sensor"
	BoundUserID string  // "" until first bind
	CreatedAt   time.Time
	BoundAt     *time.Time
	RevokedAt   *time.Time
}

// IsRevoked returns true if the claim code has been revoked.
func (c *ClaimCode) IsRevoked() bool { return c.RevokedAt != nil }

// IsBound returns true if the claim code has been bound to a user.
func (c *ClaimCode) IsBound() bool { return c.BoundAt != nil && c.BoundUserID != "" }

// Device flow audit event types.
const (
	EventDeviceAuthorizeIssued   = "device_authorize_issued"
	EventDeviceAuthorizeApproved = "device_authorize_approved"
	EventDeviceAuthorizeDenied   = "device_authorize_denied"
	EventDeviceTokenIssued       = "device_token_issued"
	EventClaimCodeCreated        = "claim_code_created"
	EventClaimCodeBound          = "claim_code_bound"
	EventClaimCodeRevoked        = "claim_code_revoked"
	EventClaimCodeDeleted        = "claim_code_deleted"
)

// DeviceAuthorizationRepository defines persistence operations for device
// authorization sessions.
type DeviceAuthorizationRepository interface {
	Create(da *DeviceAuthorization) error
	GetByDeviceHash(deviceCodeHash string) (*DeviceAuthorization, error)
	GetByUserCode(userCode string) (*DeviceAuthorization, error)
	// ListPendingByClaimID returns all non-expired pending sessions tied to the
	// given claim code. Used when a user binds a claim code on the verification
	// page — any in-flight device session needs to be approved in one shot.
	ListPendingByClaimID(claimCodeID string) ([]*DeviceAuthorization, error)
	Approve(id, userID string, approvedAt time.Time) error
	Deny(id string, deniedAt time.Time) error
	MarkPolled(id string, polledAt time.Time) error
	MarkConsumed(id string, consumedAt time.Time) error
	DeleteExpired() error
}

// ClaimCodeRepository defines persistence operations for sticker claim codes.
type ClaimCodeRepository interface {
	Create(c *ClaimCode) error
	GetByID(id string) (*ClaimCode, error)
	GetByHash(codeHash string) (*ClaimCode, error)
	ListByClient(clientID string) ([]*ClaimCode, error)
	Bind(id, userID string, boundAt time.Time) error
	Revoke(id string, revokedAt time.Time) error
	Delete(id string) error
}
