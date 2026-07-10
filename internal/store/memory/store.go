package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/aiops-system/control-plane/internal/domain"
	"github.com/aiops-system/control-plane/internal/ids"
	"github.com/aiops-system/control-plane/internal/store"
)

type Store struct {
	mu                sync.RWMutex
	signals           map[string]domain.Signal
	incidents         map[string]domain.Incident
	outbox            []domain.OutboxEvent
	securityConflicts []store.SecurityConflict
	now               func() time.Time
}

func New() *Store {
	return NewWithClock(time.Now)
}

func NewWithClock(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		signals:   make(map[string]domain.Signal),
		incidents: make(map[string]domain.Incident),
		now:       now,
	}
}

func (repository *Store) CreateSignal(_ context.Context, signal domain.Signal) (bool, error) {
	if err := signal.Validate(); err != nil {
		return false, err
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()

	key := signal.IntegrationID + "\x00" + signal.ProviderEventID
	if existing, ok := repository.signals[key]; ok {
		if existing.PayloadHash != signal.PayloadHash {
			repository.securityConflicts = append(repository.securityConflicts, store.SecurityConflict{
				IntegrationID:   signal.IntegrationID,
				ProviderEventID: signal.ProviderEventID,
				ExistingHash:    existing.PayloadHash,
				IncomingHash:    signal.PayloadHash,
				DetectedAt:      repository.now().UTC(),
			})
			return false, store.ErrIdempotencyConflict
		}
		return false, nil
	}
	repository.signals[key] = signal
	return true, nil
}

func (repository *Store) SecurityConflicts() []store.SecurityConflict {
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	conflicts := make([]store.SecurityConflict, len(repository.securityConflicts))
	copy(conflicts, repository.securityConflicts)
	return conflicts
}

func (repository *Store) CreateIncident(_ context.Context, incident domain.Incident) error {
	if err := incident.ValidateForCreate(); err != nil {
		return err
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.incidents[incident.ID]; exists {
		return fmt.Errorf("incident %s already exists", incident.ID)
	}
	repository.incidents[incident.ID] = incident
	now := repository.now().UTC()
	payload, _ := json.Marshal(map[string]string{"incident_id": incident.ID})
	repository.outbox = append(repository.outbox, domain.OutboxEvent{
		ID:               ids.NewUUID(),
		WorkspaceID:      incident.WorkspaceID,
		AggregateType:    "INCIDENT",
		AggregateID:      incident.ID,
		AggregateVersion: incident.Version,
		Type:             "incident.created.v1",
		Payload:          payload,
		CreatedAt:        now,
		AvailableAt:      now,
	})
	return nil
}

func (repository *Store) PendingOutbox() []domain.OutboxEvent {
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	events := make([]domain.OutboxEvent, len(repository.outbox))
	for index := range repository.outbox {
		events[index] = cloneOutboxEvent(repository.outbox[index])
	}
	return events
}

func (repository *Store) ClaimOutbox(_ context.Context, consumerID string, limit int, lease time.Duration) ([]domain.OutboxEvent, error) {
	if consumerID == "" || limit <= 0 || lease <= 0 {
		return nil, fmt.Errorf("consumer id, positive outbox claim limit and lease are required")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()

	now := repository.now().UTC()
	claimed := make([]domain.OutboxEvent, 0, limit)
	for index := range repository.outbox {
		event := &repository.outbox[index]
		if !event.DeliveredAt.IsZero() || event.AvailableAt.After(now) || (event.ClaimToken != "" && event.ClaimExpiresAt.After(now)) {
			continue
		}
		event.ClaimedAt = now
		event.ClaimedBy = consumerID
		event.ClaimToken = ids.NewUUID()
		event.ClaimExpiresAt = now.Add(lease)
		event.Attempts++
		claimed = append(claimed, cloneOutboxEvent(*event))
		if len(claimed) == limit {
			break
		}
	}
	return claimed, nil
}

func (repository *Store) AckOutbox(_ context.Context, id, claimToken string) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	for index := range repository.outbox {
		event := &repository.outbox[index]
		if event.ID != id {
			continue
		}
		if !event.DeliveredAt.IsZero() {
			return nil
		}
		if event.ClaimToken == "" || event.ClaimToken != claimToken {
			return store.ErrStaleClaim
		}
		event.DeliveredAt = repository.now().UTC()
		event.ClaimedAt = time.Time{}
		event.ClaimedBy = ""
		event.ClaimToken = ""
		event.ClaimExpiresAt = time.Time{}
		return nil
	}
	return store.ErrStaleClaim
}

func (repository *Store) RetryOutbox(_ context.Context, id, claimToken string, availableAt time.Time, failureCode string) error {
	if availableAt.IsZero() {
		return fmt.Errorf("outbox retry availability is required")
	}
	if !store.ValidFailureCode(failureCode) {
		return fmt.Errorf("outbox retry failure code is invalid")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	for index := range repository.outbox {
		event := &repository.outbox[index]
		if event.ID != id {
			continue
		}
		if event.ClaimToken == "" || event.ClaimToken != claimToken || !event.DeliveredAt.IsZero() {
			return store.ErrStaleClaim
		}
		event.AvailableAt = availableAt.UTC()
		event.ClaimedAt = time.Time{}
		event.ClaimedBy = ""
		event.ClaimToken = ""
		event.ClaimExpiresAt = time.Time{}
		event.LastErrorCode = failureCode
		return nil
	}
	return store.ErrStaleClaim
}

func cloneOutboxEvent(event domain.OutboxEvent) domain.OutboxEvent {
	event.Payload = bytes.Clone(event.Payload)
	return event
}
