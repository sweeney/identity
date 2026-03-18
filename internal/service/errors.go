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

	// OAuth errors
	ErrUnknownClient          = errors.New("unknown client")
	ErrInvalidRedirectURI     = errors.New("invalid redirect uri")
	ErrInvalidAuthCode        = errors.New("invalid auth code")
	ErrAuthCodeAlreadyUsed    = errors.New("auth code already used")
	ErrAuthCodeExpired        = errors.New("auth code expired")
	ErrPKCEVerificationFailed = errors.New("pkce verification failed")
)
