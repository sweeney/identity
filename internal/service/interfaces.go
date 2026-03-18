package service

import "github.com/sweeney/identity/internal/domain"

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
	// Used by OAuthService at the code exchange step.
	IssueTokensForUser(userID string) (*LoginResult, error)
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
}
