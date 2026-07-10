package store

import (
	"errors"
	"time"
)

var ErrIdempotencyConflict = errors.New("idempotency conflict")

type SecurityConflict struct {
	IntegrationID   string
	ProviderEventID string
	ExistingHash    string
	IncomingHash    string
	DetectedAt      time.Time
}
