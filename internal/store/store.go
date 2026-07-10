package store

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/aiops-system/control-plane/internal/domain"
)

var (
	ErrIdempotencyConflict = errors.New("idempotency conflict")
	ErrNotFound            = errors.New("record not found")
	ErrScopeViolation      = errors.New("workspace or provider scope violation")
	ErrStaleClaim          = errors.New("stale or unknown claim")
)

var failureCodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)

type SignalRepository interface {
	CreateSignal(context.Context, domain.Signal) (bool, error)
}

type IncidentRepository interface {
	CreateIncident(context.Context, domain.Incident) error
}

type OutboxRepository interface {
	ClaimOutbox(context.Context, string, int, time.Duration) ([]domain.OutboxEvent, error)
	AckOutbox(context.Context, string, string) error
	RetryOutbox(context.Context, string, string, time.Time, string) error
}

func ValidFailureCode(value string) bool {
	return failureCodePattern.MatchString(value)
}

type SecurityConflict struct {
	IntegrationID   string
	ProviderEventID string
	ExistingHash    string
	IncomingHash    string
	DetectedAt      time.Time
}
