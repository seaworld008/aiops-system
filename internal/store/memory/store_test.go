package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/domain"
	"github.com/aiops-system/control-plane/internal/store"
	"github.com/aiops-system/control-plane/internal/store/memory"
)

func TestCreateSignalIsIdempotentForSameProviderEventAndPayload(t *testing.T) {
	repository := memory.New()
	signal := validSignal()

	created, err := repository.CreateSignal(context.Background(), signal)
	if err != nil || !created {
		t.Fatalf("first CreateSignal() = (%v, %v), want (true, nil)", created, err)
	}
	created, err = repository.CreateSignal(context.Background(), signal)
	if err != nil || created {
		t.Fatalf("duplicate CreateSignal() = (%v, %v), want (false, nil)", created, err)
	}
}

func TestCreateSignalRejectsSameProviderEventWithDifferentPayload(t *testing.T) {
	repository := memory.New()
	signal := validSignal()
	if _, err := repository.CreateSignal(context.Background(), signal); err != nil {
		t.Fatalf("first CreateSignal() error = %v", err)
	}

	signal.PayloadHash = "different"
	_, err := repository.CreateSignal(context.Background(), signal)
	if !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("error = %v, want ErrIdempotencyConflict", err)
	}
}

func TestCreateIncidentAlsoAppendsOutboxEvent(t *testing.T) {
	repository := memory.New()
	incident := domain.NewIncident("incident-1", "workspace-1", time.Now())

	if err := repository.CreateIncident(context.Background(), incident); err != nil {
		t.Fatalf("CreateIncident() error = %v", err)
	}

	events := repository.PendingOutbox()
	if len(events) != 1 {
		t.Fatalf("len(PendingOutbox()) = %d, want 1", len(events))
	}
	if events[0].AggregateID != incident.ID || events[0].Type != "incident.created" {
		t.Fatalf("outbox event = %#v, want incident.created for %s", events[0], incident.ID)
	}
}

func validSignal() domain.Signal {
	return domain.Signal{
		ID:              "signal-1",
		WorkspaceID:     "workspace-1",
		IntegrationID:   "integration-1",
		Provider:        "alertmanager",
		ProviderEventID: "event-1",
		PayloadHash:     "payload-hash",
		ObservedAt:      time.Now(),
	}
}
