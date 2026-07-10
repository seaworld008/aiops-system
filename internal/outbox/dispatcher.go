package outbox

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/store"
)

type Starter interface {
	Start(context.Context, string, domain.OutboxEvent) error
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
	Claimed int
	Started int
	Retried int
}

type Dispatcher struct {
	repository store.OutboxRepository
	starter    Starter
	options    Options
}

func NewDispatcher(repository store.OutboxRepository, starter Starter, options Options) (*Dispatcher, error) {
	if repository == nil || starter == nil {
		return nil, fmt.Errorf("outbox repository and starter are required")
	}
	if options.ConsumerID == "" || options.BatchSize <= 0 || options.BatchSize > 100 || options.Lease <= 0 {
		return nil, fmt.Errorf("invalid outbox dispatcher claim options")
	}
	if options.BaseBackoff <= 0 || options.MaxBackoff < options.BaseBackoff {
		return nil, fmt.Errorf("invalid outbox dispatcher backoff options")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Dispatcher{repository: repository, starter: starter, options: options}, nil
}

func (dispatcher *Dispatcher) RunOnce(ctx context.Context) (Result, error) {
	events, err := dispatcher.repository.ClaimOutbox(
		ctx,
		dispatcher.options.ConsumerID,
		dispatcher.options.BatchSize,
		dispatcher.options.Lease,
	)
	if err != nil {
		return Result{}, fmt.Errorf("claim outbox batch: %w", err)
	}
	result := Result{Claimed: len(events)}
	for _, event := range events {
		if err := dispatcher.starter.Start(ctx, event.ID, event); err != nil {
			failureCode := "workflow_start_failed"
			var coded interface{ FailureCode() string }
			if errors.As(err, &coded) && store.ValidFailureCode(coded.FailureCode()) {
				failureCode = coded.FailureCode()
			}
			retryAt := dispatcher.options.Now().UTC().Add(dispatcher.backoff(event.Attempts))
			if retryErr := dispatcher.repository.RetryOutbox(ctx, event.ID, event.ClaimToken, retryAt, failureCode); retryErr != nil {
				return result, fmt.Errorf("schedule outbox retry: %w", retryErr)
			}
			result.Retried++
			continue
		}
		if err := dispatcher.repository.AckOutbox(ctx, event.ID, event.ClaimToken); err != nil {
			return result, fmt.Errorf("acknowledge outbox event: %w", err)
		}
		result.Started++
	}
	return result, nil
}

func (dispatcher *Dispatcher) backoff(attempt int) time.Duration {
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
