package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/ids"
	"github.com/seaworld008/aiops-system/internal/requestmeta"
	"github.com/seaworld008/aiops-system/internal/store"
)

type Store struct {
	mu                sync.RWMutex
	signals           map[string]domain.Signal
	integrations      map[string]domain.Integration
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
		signals:      make(map[string]domain.Signal),
		integrations: make(map[string]domain.Integration),
		incidents:    make(map[string]domain.Incident),
		now:          now,
	}
}

func (repository *Store) RegisterIntegration(integration domain.Integration) error {
	if err := integration.Validate(); err != nil {
		return err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.integrations[integration.ID]; exists {
		return fmt.Errorf("integration %s already exists", integration.ID)
	}
	repository.integrations[integration.ID] = integration
	return nil
}

func (repository *Store) CreateSignal(ctx context.Context, signal domain.Signal) (bool, error) {
	if err := signal.Validate(); err != nil {
		return false, err
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	integration, exists := repository.integrations[signal.IntegrationID]
	if !exists || !integration.Enabled {
		return false, store.ErrNotFound
	}
	if integration.WorkspaceID != signal.WorkspaceID || integration.Provider != signal.Provider {
		return false, store.ErrScopeViolation
	}

	key := signal.IntegrationID + "\x00" + signal.ProviderEventID
	if existing, ok := repository.signals[key]; ok {
		if existing.PayloadHash != signal.PayloadHash {
			metadata := requestmeta.From(ctx)
			if metadata.RequestID == "" {
				metadata.RequestID = ids.NewUUID()
			}
			repository.securityConflicts = append(repository.securityConflicts, store.SecurityConflict{
				WorkspaceID:      existing.WorkspaceID,
				Provider:         existing.Provider,
				IntegrationID:    signal.IntegrationID,
				ProviderEventID:  signal.ProviderEventID,
				ExistingSignalID: existing.ID,
				ExistingHash:     existing.PayloadHash,
				IncomingHash:     signal.PayloadHash,
				RequestID:        metadata.RequestID,
				TraceID:          metadata.TraceID,
				DetectedAt:       repository.now().UTC(),
			})
			return false, store.ErrIdempotencyConflict
		}
		return false, nil
	}
	signal.Labels = cloneStringMap(signal.Labels)
	repository.signals[key] = signal
	now := repository.now().UTC()
	payload, _ := json.Marshal(map[string]string{"signal_id": signal.ID})
	repository.outbox = append(repository.outbox, domain.OutboxEvent{
		ID:               ids.NewUUID(),
		TenantID:         signal.WorkspaceID,
		WorkspaceID:      signal.WorkspaceID,
		AggregateType:    "SIGNAL",
		AggregateID:      signal.ID,
		AggregateVersion: 1,
		Type:             "signal.ingested.v1",
		Payload:          payload,
		CreatedAt:        now,
		AvailableAt:      now,
	})
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
		TenantID:         incident.WorkspaceID,
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

func (repository *Store) ClaimOutbox(_ context.Context, request store.ClaimOutboxRequest) ([]domain.OutboxEvent, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()

	now := repository.now().UTC()
	claimed := make([]domain.OutboxEvent, 0, request.Limit)
	for index := range repository.outbox {
		event := &repository.outbox[index]
		if event.Type != request.EventType || !event.DeliveredAt.IsZero() || event.AvailableAt.After(now) ||
			(event.ClaimToken != "" && event.ClaimExpiresAt.After(now)) {
			continue
		}
		event.ClaimedAt = now
		event.ClaimedBy = request.ConsumerID
		event.ClaimToken = ids.NewUUID()
		event.ClaimExpiresAt = now.Add(request.Lease)
		event.Attempts++
		claimedEvent := cloneOutboxEvent(*event)
		if claimedEvent.Type != request.EventType {
			return nil, fmt.Errorf("claimed outbox event type is invalid")
		}
		claimed = append(claimed, claimedEvent)
		if len(claimed) == request.Limit {
			break
		}
	}
	return claimed, nil
}

func (repository *Store) AckOutbox(_ context.Context, id, expectedEventType, claimToken string) error {
	if !store.ValidOutboxEventType(expectedEventType) {
		return store.ErrInvalidOutboxClaim
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	for index := range repository.outbox {
		event := &repository.outbox[index]
		if event.ID != id {
			continue
		}
		if event.Type != expectedEventType {
			return store.ErrStaleClaim
		}
		if !event.DeliveredAt.IsZero() {
			if event.DeliveredClaimToken == claimToken {
				return nil
			}
			return store.ErrStaleClaim
		}
		now := repository.now().UTC()
		if event.ClaimToken == "" || event.ClaimToken != claimToken || !event.ClaimExpiresAt.After(now) {
			return store.ErrStaleClaim
		}
		event.DeliveredAt = now
		event.DeliveredClaimToken = claimToken
		event.ClaimedAt = time.Time{}
		event.ClaimedBy = ""
		event.ClaimToken = ""
		event.ClaimExpiresAt = time.Time{}
		return nil
	}
	return store.ErrStaleClaim
}

func (repository *Store) RetryOutbox(_ context.Context, id, expectedEventType, claimToken string, availableAt time.Time, failureCode string) error {
	if !store.ValidOutboxEventType(expectedEventType) || availableAt.IsZero() {
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
		if event.Type != expectedEventType {
			return store.ErrStaleClaim
		}
		if event.ClaimToken == "" || event.ClaimToken != claimToken || !event.DeliveredAt.IsZero() ||
			!event.ClaimExpiresAt.After(repository.now().UTC()) {
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

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}
