package store

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
)

var (
	ErrIdempotencyConflict = errors.New("idempotency conflict")
	ErrNotFound            = errors.New("record not found")
	ErrScopeViolation      = errors.New("workspace or provider scope violation")
	ErrStaleClaim          = errors.New("stale or unknown claim")
	ErrInvalidOutboxClaim  = errors.New("invalid outbox claim request")
)

var (
	failureCodePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
	outboxEventTypePattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$`)
	outboxConsumerPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]*$`)
)

const (
	MaxOutboxEventTypeBytes = 128
	MaxOutboxConsumerBytes  = 128
	MaxOutboxClaimLimit     = 100
	MinOutboxClaimLease     = time.Second
	MaxOutboxClaimLease     = 15 * time.Minute
)

type SignalRepository interface {
	CreateSignal(context.Context, domain.Signal) (bool, error)
}

type IncidentRepository interface {
	CreateIncident(context.Context, domain.Incident) error
}

type OutboxRepository interface {
	ClaimOutbox(context.Context, ClaimOutboxRequest) ([]domain.OutboxEvent, error)
	AckOutbox(context.Context, string, string, string) error
	RetryOutbox(context.Context, string, string, string, time.Time, string) error
}

type ClaimOutboxRequest struct {
	EventType  string
	ConsumerID string
	Limit      int
	Lease      time.Duration
}

func (request ClaimOutboxRequest) Validate() error {
	if !ValidOutboxEventType(request.EventType) || len(request.ConsumerID) > MaxOutboxConsumerBytes ||
		!outboxConsumerPattern.MatchString(request.ConsumerID) ||
		request.Limit < 1 || request.Limit > MaxOutboxClaimLimit ||
		request.Lease < MinOutboxClaimLease || request.Lease > MaxOutboxClaimLease {
		return ErrInvalidOutboxClaim
	}
	return nil
}

func ValidOutboxEventType(value string) bool {
	return len(value) <= MaxOutboxEventTypeBytes && outboxEventTypePattern.MatchString(value)
}

func ValidFailureCode(value string) bool {
	return failureCodePattern.MatchString(value)
}

type SecurityConflict struct {
	WorkspaceID      string
	Provider         string
	IntegrationID    string
	ProviderEventID  string
	ExistingSignalID string
	ExistingHash     string
	IncomingHash     string
	RequestID        string
	TraceID          string
	DetectedAt       time.Time
}
