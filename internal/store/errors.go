package store

import "errors"

var (
	ErrNotFound       = errors.New("not found")
	ErrConflict       = errors.New("conflict")
	ErrInvalid        = errors.New("invalid")
	ErrUnauthorized   = errors.New("unauthorized")
	ErrRefreshReuse   = errors.New("refresh token reuse detected")
	ErrSeatLimit      = errors.New("activation limit reached")
	ErrLicenseState   = errors.New("license is not currently usable")
	ErrAlreadyClaimed = errors.New("license has already been claimed")
)
