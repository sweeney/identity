package service

import "errors"

var (
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrAccountDisabled       = errors.New("account disabled")
	ErrInvalidRefreshToken   = errors.New("invalid refresh token")
	ErrRefreshTokenExpired   = errors.New("refresh token expired")
	ErrTokenFamilyCompromised = errors.New("token family compromised")
	ErrWeakPassword          = errors.New("password too weak")
	ErrCannotDeleteLastAdmin = errors.New("cannot delete last admin")

	// WebAuthn errors
	ErrWebAuthnNotEnabled     = errors.New("webauthn not enabled")
	ErrWebAuthnInvalidChallenge = errors.New("webauthn invalid challenge")
	ErrWebAuthnVerificationFailed = errors.New("webauthn verification failed")
	ErrWebAuthnNoCredentials  = errors.New("webauthn no credentials")
	ErrWebAuthnCredentialNotFound = errors.New("webauthn credential not found")
	ErrWebAuthnCredentialLimitReached = errors.New("webauthn credential limit reached")

	// OAuth errors
	ErrUnknownClient          = errors.New("unknown client")
	ErrInvalidRedirectURI     = errors.New("invalid redirect uri")
	ErrInvalidAuthCode        = errors.New("invalid auth code")
	ErrAuthCodeAlreadyUsed    = errors.New("auth code already used")
	ErrAuthCodeExpired        = errors.New("auth code expired")
	ErrPKCEVerificationFailed = errors.New("pkce verification failed")
	ErrInvalidScope           = errors.New("invalid scope")
	ErrUnauthorizedClient     = errors.New("unauthorized client")
	ErrInvalidClientSecret    = errors.New("invalid client secret")

	// Config service errors
	ErrConfigNamespaceNotFound = errors.New("config namespace not found")
	ErrConfigNamespaceExists   = errors.New("config namespace already exists")
	ErrConfigForbidden         = errors.New("config operation forbidden by namespace acl")
	ErrConfigInvalidName       = errors.New("invalid config namespace name")
	ErrConfigInvalidRole       = errors.New("invalid config role")
	ErrConfigInvalidDocument   = errors.New("config document must be a JSON object")
	ErrConfigDocumentTooLarge  = errors.New("config document exceeds size limit")

	// Device flow errors (RFC 8628)
	ErrInvalidDeviceCode        = errors.New("invalid device code")
	ErrDeviceAuthorizationPending = errors.New("authorization pending")
	ErrDeviceAuthorizationDenied  = errors.New("authorization denied")
	ErrDeviceCodeExpired        = errors.New("device code expired")
	ErrDeviceSlowDown           = errors.New("slow down")
	ErrInvalidUserCode          = errors.New("invalid user code")
	ErrInvalidClaimCode         = errors.New("invalid claim code")
	ErrClaimCodeRevoked         = errors.New("claim code revoked")
)
