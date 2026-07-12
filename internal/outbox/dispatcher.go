package outbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/store"
)

const signalIngestedEventType = "signal.ingested.v1"

var (
	ErrInvalidSignalOutboxEvent = errors.New("invalid signal outbox event")
	persistentUUIDPattern       = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
)

type StartOutcome string

const (
	StartOutcomeStarted       StartOutcome = "STARTED"
	StartOutcomeAlreadyExists StartOutcome = "ALREADY_EXISTS"
)

// SignalWorkflowStart is the complete secret-safe workflow start boundary.
// It deliberately contains only persistent identifiers and bounded facts.
type SignalWorkflowStart struct {
	Version          int    `json:"version"`
	WorkflowID       string `json:"workflow_id"`
	OutboxEventID    string `json:"outbox_event_id"`
	TenantID         string `json:"tenant_id"`
	WorkspaceID      string `json:"workspace_id"`
	SignalID         string `json:"signal_id"`
	AggregateVersion int64  `json:"aggregate_version"`
}

type SignalStarter interface {
	Start(context.Context, SignalWorkflowStart) (StartOutcome, error)
}

type Options struct {
	ConsumerID  string
	BatchSize   int
	Lease       time.Duration
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	Now         func() time.Time
}

type Result struct {
	Claimed       int
	Started       int
	AlreadyExists int
	Retried       int
}

type SignalDispatcher struct {
	repository store.OutboxRepository
	starter    SignalStarter
	options    Options
}

func NewSignalDispatcher(
	repository store.OutboxRepository,
	starter SignalStarter,
	options Options,
) (*SignalDispatcher, error) {
	if repository == nil || starter == nil {
		return nil, fmt.Errorf("signal outbox repository and starter are required")
	}
	claim := store.ClaimOutboxRequest{
		EventType:  signalIngestedEventType,
		ConsumerID: options.ConsumerID,
		Limit:      options.BatchSize,
		Lease:      options.Lease,
	}
	if err := claim.Validate(); err != nil {
		return nil, fmt.Errorf("invalid signal outbox dispatcher claim options")
	}
	if options.BaseBackoff <= 0 || options.MaxBackoff < options.BaseBackoff {
		return nil, fmt.Errorf("invalid signal outbox dispatcher backoff options")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &SignalDispatcher{repository: repository, starter: starter, options: options}, nil
}

func (dispatcher *SignalDispatcher) RunOnce(ctx context.Context) (Result, error) {
	events, err := dispatcher.repository.ClaimOutbox(ctx, store.ClaimOutboxRequest{
		EventType:  signalIngestedEventType,
		ConsumerID: dispatcher.options.ConsumerID,
		Limit:      dispatcher.options.BatchSize,
		Lease:      dispatcher.options.Lease,
	})
	if err != nil {
		return Result{}, fmt.Errorf("claim signal outbox batch: %w", err)
	}
	result := Result{Claimed: len(events)}
	for _, event := range events {
		start, validationErr := newSignalWorkflowStart(event)
		if validationErr != nil {
			return result, ErrInvalidSignalOutboxEvent
		}
		outcome, startErr := dispatcher.starter.Start(ctx, start)
		if startErr != nil {
			failureCode := "workflow_start_failed"
			var coded interface{ FailureCode() string }
			if errors.As(startErr, &coded) && store.ValidFailureCode(coded.FailureCode()) {
				failureCode = coded.FailureCode()
			}
			if err := dispatcher.retry(ctx, event, failureCode); err != nil {
				return result, err
			}
			result.Retried++
			continue
		}
		switch outcome {
		case StartOutcomeStarted, StartOutcomeAlreadyExists:
			if err := dispatcher.repository.AckOutbox(
				ctx, event.ID, signalIngestedEventType, event.ClaimToken,
			); err != nil {
				return result, fmt.Errorf("acknowledge signal outbox event: %w", err)
			}
			if outcome == StartOutcomeStarted {
				result.Started++
			} else {
				result.AlreadyExists++
			}
		default:
			if err := dispatcher.retry(ctx, event, "workflow_start_outcome_invalid"); err != nil {
				return result, err
			}
			result.Retried++
		}
	}
	return result, nil
}

func (dispatcher *SignalDispatcher) retry(ctx context.Context, event domain.OutboxEvent, failureCode string) error {
	retryAt := dispatcher.options.Now().UTC().Add(dispatcher.backoff(event.Attempts))
	if err := dispatcher.repository.RetryOutbox(
		ctx, event.ID, signalIngestedEventType, event.ClaimToken, retryAt, failureCode,
	); err != nil {
		return fmt.Errorf("schedule signal outbox retry: %w", err)
	}
	return nil
}

func (dispatcher *SignalDispatcher) backoff(attempt int) time.Duration {
	delay := dispatcher.options.BaseBackoff
	for current := 1; current < attempt && delay < dispatcher.options.MaxBackoff; current++ {
		if delay > dispatcher.options.MaxBackoff/2 {
			return dispatcher.options.MaxBackoff
		}
		delay *= 2
	}
	if delay > dispatcher.options.MaxBackoff {
		return dispatcher.options.MaxBackoff
	}
	return delay
}

func newSignalWorkflowStart(event domain.OutboxEvent) (SignalWorkflowStart, error) {
	if event.Type != signalIngestedEventType || event.AggregateType != "SIGNAL" || event.AggregateVersion != 1 ||
		!persistentUUIDPattern.MatchString(event.ID) || !persistentUUIDPattern.MatchString(event.TenantID) ||
		!persistentUUIDPattern.MatchString(event.WorkspaceID) || !persistentUUIDPattern.MatchString(event.AggregateID) {
		return SignalWorkflowStart{}, ErrInvalidSignalOutboxEvent
	}
	signalID, err := decodeExactSignalPayload(event.Payload)
	if err != nil || signalID != event.AggregateID || !persistentUUIDPattern.MatchString(signalID) {
		return SignalWorkflowStart{}, ErrInvalidSignalOutboxEvent
	}
	return SignalWorkflowStart{
		Version:          1,
		WorkflowID:       event.ID,
		OutboxEventID:    event.ID,
		TenantID:         event.TenantID,
		WorkspaceID:      event.WorkspaceID,
		SignalID:         signalID,
		AggregateVersion: event.AggregateVersion,
	}, nil
}

func decodeExactSignalPayload(payload json.RawMessage) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return "", ErrInvalidSignalOutboxEvent
	}
	if !decoder.More() {
		return "", ErrInvalidSignalOutboxEvent
	}
	name, err := decoder.Token()
	if err != nil || name != "signal_id" {
		return "", ErrInvalidSignalOutboxEvent
	}
	var signalID string
	if err := decoder.Decode(&signalID); err != nil || signalID == "" || decoder.More() {
		return "", ErrInvalidSignalOutboxEvent
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return "", ErrInvalidSignalOutboxEvent
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return "", ErrInvalidSignalOutboxEvent
	}
	return signalID, nil
}

type DispatchError struct {
	code  string
	cause error
}

func NewDispatchError(code string, cause error) error {
	if !store.ValidFailureCode(code) {
		code = "workflow_start_failed"
	}
	return &DispatchError{code: code, cause: cause}
}

func (failure *DispatchError) Error() string {
	return failure.code
}

func (failure *DispatchError) Unwrap() error {
	return failure.cause
}

func (failure *DispatchError) FailureCode() string {
	return failure.code
}
