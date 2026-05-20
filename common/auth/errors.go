package auth

import "errors"

var (
	// ErrTokenExpired is returned when a JWT access token has passed its expiry time.
	ErrTokenExpired = errors.New("token expired")

	// ErrTokenInvalid is returned when a JWT is malformed, has a bad signature,
	// or fails any other validation check.
	ErrTokenInvalid = errors.New("token invalid")
)
