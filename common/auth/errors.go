package auth

import "errors"

var (
	// ErrTokenExpired is returned when a JWT access token has passed its expiry time.
	ErrTokenExpired = errors.New("token expired")

	// ErrTokenInvalid is returned when a JWT is malformed, has a bad signature,
	// or fails any other validation check.
	ErrTokenInvalid = errors.New("token invalid")

	// ErrKeysUnavailable is returned when the token could not be checked at
	// all — the JWKS endpoint was unreachable, errored, or returned nothing
	// usable, and no cached key covered the token's kid.
	//
	// This is deliberately distinct from ErrTokenInvalid. It is a statement
	// about our infrastructure, not a verdict on the caller's token. Clients
	// treat an invalid token as "sign the user out"; if an identity outage
	// reported itself that way, every service in the ecosystem would sign
	// every user out at the same moment. Map this to 503 and let the caller
	// retry, not to 401.
	ErrKeysUnavailable = errors.New("signing keys unavailable")
)
