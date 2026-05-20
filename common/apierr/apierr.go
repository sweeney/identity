package apierr

import "errors"

var (
	// ErrNotFound is returned when a requested entity does not exist.
	ErrNotFound = errors.New("not found")

	// ErrConflict is returned when a unique constraint is violated (e.g. duplicate username).
	ErrConflict = errors.New("conflict")

	// ErrUserLimitReached is returned when the user count cap would be exceeded.
	ErrUserLimitReached = errors.New("user limit reached")

	// ErrTokenAlreadyRevoked is returned when a refresh token has already been revoked.
	ErrTokenAlreadyRevoked = errors.New("token already revoked")
)
