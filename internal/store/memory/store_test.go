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
	if got := len(repository.SecurityConflicts()); got != 1 {
		t.Fatalf("len(SecurityConflicts()) = %d, want 1", got)
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
	if events[0].AggregateID != incident.ID || events[0].Type != "incident.created.v1" || events[0].AggregateVersion != 1 {
		t.Fatalf("outbox event = %#v, want incident.created.v1 for %s", events[0], incident.ID)
	}
}

func TestOutboxClaimUsesFencingTokenAndRecoversExpiredLease(t *testing.T) {
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	repository := memory.NewWithClock(func() time.Time { return now })
	incident := domain.NewIncident("incident-1", "workspace-1", now)
	if err := repository.CreateIncident(context.Background(), incident); err != nil {
		t.Fatalf("CreateIncident() error = %v", err)
	}

	first, err := repository.ClaimOutbox(context.Background(), "dispatcher-1", 1, time.Minute)
	if err != nil || len(first) != 1 || first[0].ClaimToken == "" || first[0].Attempts != 1 {
		t.Fatalf("first ClaimOutbox() = (%#v, %v)", first, err)
	}
	now = now.Add(2 * time.Minute)
	second, err := repository.ClaimOutbox(context.Background(), "dispatcher-2", 1, time.Minute)
	if err != nil || len(second) != 1 || second[0].ClaimToken == first[0].ClaimToken || second[0].Attempts != 2 {
		t.Fatalf("second ClaimOutbox() = (%#v, %v)", second, err)
	}
	if err := repository.AckOutbox(context.Background(), first[0].ID, first[0].ClaimToken); !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("AckOutbox(stale) error = %v, want ErrStaleClaim", err)
	}
	if err := repository.AckOutbox(context.Background(), second[0].ID, second[0].ClaimToken); err != nil {
		t.Fatalf("AckOutbox(current) error = %v", err)
	}
	if err := repository.AckOutbox(context.Background(), second[0].ID, second[0].ClaimToken); err != nil {
		t.Fatalf("AckOutbox(retry after uncertain response) error = %v", err)
	}
	if claimed, err := repository.ClaimOutbox(context.Background(), "dispatcher-1", 1, time.Minute); err != nil || len(claimed) != 0 {
		t.Fatalf("ClaimOutbox(delivered) = (%#v, %v), want empty", claimed, err)
	}
}

func TestOutboxRetryRequiresCurrentClaim(t *testing.T) {
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	repository := memory.NewWithClock(func() time.Time { return now })
	if err := repository.CreateIncident(context.Background(), domain.NewIncident("incident-1", "workspace-1", now)); err != nil {
		t.Fatalf("CreateIncident() error = %v", err)
	}
	claimed, err := repository.ClaimOutbox(context.Background(), "dispatcher-1", 1, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("ClaimOutbox() = (%#v, %v)", claimed, err)
	}
	retryAt := now.Add(5 * time.Minute)
	if err := repository.RetryOutbox(context.Background(), claimed[0].ID, "wrong-token", retryAt, "temporal_unavailable"); !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("RetryOutbox(stale) error = %v, want ErrStaleClaim", err)
	}
	if err := repository.RetryOutbox(context.Background(), claimed[0].ID, claimed[0].ClaimToken, retryAt, "temporal_unavailable"); err != nil {
		t.Fatalf("RetryOutbox(current) error = %v", err)
	}
	now = retryAt.Add(-time.Second)
	if retry, _ := repository.ClaimOutbox(context.Background(), "dispatcher-1", 1, time.Minute); len(retry) != 0 {
		t.Fatalf("ClaimOutbox(before retry) = %#v, want empty", retry)
	}
	now = retryAt
	if retry, _ := repository.ClaimOutbox(context.Background(), "dispatcher-1", 1, time.Minute); len(retry) != 1 || retry[0].LastErrorCode != "temporal_unavailable" {
		t.Fatalf("ClaimOutbox(at retry) = %#v", retry)
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
