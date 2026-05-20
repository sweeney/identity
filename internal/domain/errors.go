package domain

import commonapierr "github.com/sweeney/identity/common/apierr"

var (
	ErrNotFound            = commonapierr.ErrNotFound
	ErrConflict            = commonapierr.ErrConflict
	ErrUserLimitReached    = commonapierr.ErrUserLimitReached
	ErrTokenAlreadyRevoked = commonapierr.ErrTokenAlreadyRevoked
)
