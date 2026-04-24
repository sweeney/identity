package service

import (
	"github.com/sweeney/identity/internal/domain"
)

// AuthServicer is the interface the API handler uses for auth operations.
//
//go:generate mockgen -destination=../mocks/mock_auth_service.go -package=mocks github.com/sweeney/identity/internal/service AuthServicer
type AuthServicer interface {
	Login(username, password, deviceHint, clientIP string) (*LoginResult, error)
	Refresh(rawRefreshToken string) (*LoginResult, error)
	Logout(userID, rawRefreshToken string) error

	// AuthorizeUser authenticates without issuing tokens. Returns userID on success.
	// Used by OAuthService at the authorize step.
	AuthorizeUser(username, password, clientIP string) (string, error)

	// IssueTokensForUser issues a token pair for a pre-authenticated user.
	// audience is the aud claim to embed in the access token; pass "" to omit it.
	// Used by OAuthService at the code exchange step.
	IssueTokensForUser(userID, audience string) (*LoginResult, error)
}

// UserServicer is the interface the API handler uses for user CRUD.
//
//go:generate mockgen -destination=../mocks/mock_user_service.go -package=mocks github.com/sweeney/identity/internal/service UserServicer
type UserServicer interface {
	Create(username, displayName, password string, role domain.Role, meta ...AuditMeta) (*domain.User, error)
	GetByID(id string) (*domain.User, error)
	GetByUsername(username string) (*domain.User, error)
	List() ([]*domain.User, error)
	Update(id string, input UpdateUserInput, meta ...AuditMeta) (*domain.User, error)
	Delete(id string, meta ...AuditMeta) error
}

// OAuthServicer is the interface the OAuth handler uses.
//
//go:generate mockgen -destination=../mocks/mock_oauth_service.go -package=mocks github.com/sweeney/identity/internal/service OAuthServicer
type OAuthServicer interface {
	ValidateAuthorizeRequest(clientID, redirectURI string) (*domain.OAuthClient, error)
	Authorize(clientID, redirectURI, username, password, codeChallenge, ip string) (rawCode string, err error)
	AuthorizeByUserID(clientID, redirectURI, userID, username, codeChallenge, ip string) (rawCode string, err error)
	ExchangeCode(clientID, code, redirectURI, codeVerifier string) (*LoginResult, error)
	RefreshToken(rawRefreshToken string) (*LoginResult, error)
	GetClient(clientID string) (*domain.OAuthClient, error)
	IssueClientCredentials(client *domain.OAuthClient, requestedScope, ip string) (*ClientCredentialsResult, error)
}

// DeviceFlowServicer is the interface the OAuth handler and the admin handler
// use for RFC 8628 device authorization and claim-code management.
//
//go:generate mockgen -destination=../mocks/mock_device_flow_service.go -package=mocks github.com/sweeney/identity/internal/service DeviceFlowServicer
type DeviceFlowServicer interface {
	// Device-facing
	IssueDeviceAuthorization(clientID, scope, ip string) (*DeviceAuthorizationResult, error)
	ClaimDevice(clientID, rawClaimCode, scope, ip string) (*DeviceAuthorizationResult, error)
	PollForToken(clientID, rawDeviceCode, ip string) (*LoginResult, error)

	// User-facing (verification page)
	LookupForVerification(rawCode string) (*DeviceApprovalView, error)
	Approve(rawCode, userID, username, ip string) error
	Deny(rawCode, ip string) error

	// Admin-facing
	CreateClaimCodes(clientID string, labels []string, ip string) ([]*ClaimCodeResult, error)
	ListClaimCodes(clientID string) ([]*domain.ClaimCode, error)
	RevokeClaimCode(id, ip string) error
}
