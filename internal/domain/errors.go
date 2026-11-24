package domain

import (
	"errors"

	commonapierr "github.com/sweeney/common/web/apierr"
)

var (
	ErrNotFound            = commonapierr.ErrNotFound
	ErrConflict            = commonapierr.ErrConflict
	ErrUserLimitReached    = commonapierr.ErrUserLimitReached
	ErrTokenAlreadyRevoked = commonapierr.ErrTokenAlreadyRevoked
)

// ErrTokenExpired is returned by TokenRepository.RotateToken for a live token
// past its expiry. The token is revoked with RevokeReasonExpired and no
// replacement is issued.
var ErrTokenExpired = errors.New("refresh token expired")
