package domain

import commonapierr "github.com/sweeney/common/web/apierr"

var (
	ErrNotFound            = commonapierr.ErrNotFound
	ErrConflict            = commonapierr.ErrConflict
	ErrUserLimitReached    = commonapierr.ErrUserLimitReached
	ErrTokenAlreadyRevoked = commonapierr.ErrTokenAlreadyRevoked
)
