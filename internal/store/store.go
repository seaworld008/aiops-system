package store

import "errors"

var ErrIdempotencyConflict = errors.New("idempotency conflict")
