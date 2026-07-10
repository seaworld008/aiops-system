package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aiops-system/control-plane/internal/domain"
	"github.com/aiops-system/control-plane/internal/store"
)

type Store struct {
	mu                sync.RWMutex
	signals           map[string]domain.Signal
	incidents         map[string]domain.Incident
	outbox            []domain.OutboxEvent
	securityConflicts []store.SecurityConflict
}

func New() *Store {
	return &Store{
		signals:   make(map[string]domain.Signal),
		incidents: make(map[string]domain.Incident),
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
				DetectedAt:      time.Now().UTC(),
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
	if incident.ID == "" || incident.WorkspaceID == "" {
		return fmt.Errorf("incident id and workspace id are required")
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.incidents[incident.ID]; exists {
		return fmt.Errorf("incident %s already exists", incident.ID)
	}
	repository.incidents[incident.ID] = incident
	repository.outbox = append(repository.outbox, domain.OutboxEvent{
		ID:          "incident.created/" + incident.ID,
		WorkspaceID: incident.WorkspaceID,
		AggregateID: incident.ID,
		Type:        "incident.created",
		CreatedAt:   time.Now().UTC(),
	})
	return nil
}

func (repository *Store) PendingOutbox() []domain.OutboxEvent {
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	events := make([]domain.OutboxEvent, len(repository.outbox))
	copy(events, repository.outbox)
	return events
}
