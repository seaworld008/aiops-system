package memory_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/store"
	"github.com/seaworld008/aiops-system/internal/store/memory"
)

func TestCreateSignalIsIdempotentForSameProviderEventAndPayload(t *testing.T) {
	repository := newSignalRepository(t)
	signal := validSignal()

	created, err := repository.CreateSignal(context.Background(), signal)
	if err != nil || !created {
		t.Fatalf("first CreateSignal() = (%v, %v), want (true, nil)", created, err)
	}
	created, err = repository.CreateSignal(context.Background(), signal)
	if err != nil || created {
		t.Fatalf("duplicate CreateSignal() = (%v, %v), want (false, nil)", created, err)
	}
	events := repository.PendingOutbox()
	if len(events) != 1 || events[0].TenantID != signal.WorkspaceID ||
		events[0].AggregateID != signal.ID || events[0].Type != "signal.ingested.v1" {
		t.Fatalf("PendingOutbox() = %#v, want one signal.ingested.v1", events)
	}
	events[0].Payload[0] = 'x'
	if fresh := repository.PendingOutbox(); string(fresh[0].Payload) != `{"signal_id":"signal-1"}` {
		t.Fatalf("PendingOutbox() payload alias = %q, want detached fixture", fresh[0].Payload)
	}
}

func TestCreateSignalRejectsSameProviderEventWithDifferentPayload(t *testing.T) {
	repository := newSignalRepository(t)
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

func TestCreateSignalRejectsIntegrationScopeMismatch(t *testing.T) {
	repository := newSignalRepository(t)
	item := validSignal()
	item.WorkspaceID = "workspace-2"
	if _, err := repository.CreateSignal(context.Background(), item); !errors.Is(err, store.ErrScopeViolation) {
		t.Fatalf("CreateSignal() error = %v, want ErrScopeViolation", err)
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
	if events[0].TenantID != incident.WorkspaceID || events[0].AggregateID != incident.ID ||
		events[0].Type != "incident.created.v1" || events[0].AggregateVersion != 1 {
		t.Fatalf("outbox event = %#v, want incident.created.v1 for %s", events[0], incident.ID)
	}
}

func TestOutboxClaimsOnlyTheRequestedExactEventType(t *testing.T) {
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	repository := memory.NewWithClock(func() time.Time { return now })
	for index := 0; index < 3; index++ {
		if err := repository.CreateIncident(context.Background(), domain.NewIncident(
			"incident-"+string(rune('a'+index)), "workspace-1", now,
		)); err != nil {
			t.Fatalf("CreateIncident(%d) error = %v", index, err)
		}
	}
	if err := repository.RegisterIntegration(domain.Integration{
		ID: "integration-1", WorkspaceID: "workspace-1", Provider: "alertmanager", Enabled: true,
	}); err != nil {
		t.Fatalf("RegisterIntegration() error = %v", err)
	}
	signal := validSignal()
	if _, err := repository.CreateSignal(context.Background(), signal); err != nil {
		t.Fatalf("CreateSignal() error = %v", err)
	}

	signals, err := repository.ClaimOutbox(context.Background(), store.ClaimOutboxRequest{
		EventType: "signal.ingested.v1", ConsumerID: "signal-dispatcher", Limit: 1, Lease: time.Minute,
	})
	if err != nil || len(signals) != 1 || signals[0].Type != "signal.ingested.v1" {
		t.Fatalf("ClaimOutbox(signal) = (%#v, %v)", signals, err)
	}
	incidents, err := repository.ClaimOutbox(context.Background(), store.ClaimOutboxRequest{
		EventType: "incident.created.v1", ConsumerID: "incident-dispatcher", Limit: 2, Lease: time.Minute,
	})
	if err != nil || len(incidents) != 2 {
		t.Fatalf("ClaimOutbox(incident) = (%#v, %v)", incidents, err)
	}
	for _, event := range incidents {
		if event.Type != "incident.created.v1" {
			t.Fatalf("incident dispatcher claimed %q", event.Type)
		}
	}
}

func TestOutboxClaimRejectsNonExactAndUnboundedParameters(t *testing.T) {
	repository := memory.New()
	tests := []struct {
		name, eventType, consumerID string
		limit                       int
		lease                       time.Duration
	}{
		{name: "empty type", eventType: "", consumerID: "worker-1", limit: 1, lease: time.Minute},
		{name: "wildcard", eventType: "signal.ingested.*", consumerID: "worker-1", limit: 1, lease: time.Minute},
		{name: "sql wildcard", eventType: "signal.ingested.%", consumerID: "worker-1", limit: 1, lease: time.Minute},
		{name: "prefix", eventType: "signal.ingested", consumerID: "worker-1", limit: 1, lease: time.Minute},
		{name: "oversized type", eventType: strings.Repeat("a", 126) + ".v1", consumerID: "worker-1", limit: 1, lease: time.Minute},
		{name: "empty consumer", eventType: "signal.ingested.v1", consumerID: "", limit: 1, lease: time.Minute},
		{name: "oversized consumer", eventType: "signal.ingested.v1", consumerID: strings.Repeat("w", 129), limit: 1, lease: time.Minute},
		{name: "zero limit", eventType: "signal.ingested.v1", consumerID: "worker-1", limit: 0, lease: time.Minute},
		{name: "oversized limit", eventType: "signal.ingested.v1", consumerID: "worker-1", limit: 101, lease: time.Minute},
		{name: "subsecond lease", eventType: "signal.ingested.v1", consumerID: "worker-1", limit: 1, lease: time.Second - 1},
		{name: "oversized lease", eventType: "signal.ingested.v1", consumerID: "worker-1", limit: 1, lease: 15*time.Minute + 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := repository.ClaimOutbox(context.Background(), store.ClaimOutboxRequest{
				EventType: test.eventType, ConsumerID: test.consumerID, Limit: test.limit, Lease: test.lease,
			}); err == nil {
				t.Fatal("ClaimOutbox() error = nil, want bounded validation error")
			}
		})
	}
}

func TestOutboxAckAndRetryBindExpectedEventType(t *testing.T) {
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	repository := memory.NewWithClock(func() time.Time { return now })
	if err := repository.CreateIncident(context.Background(), domain.NewIncident("incident-1", "workspace-1", now)); err != nil {
		t.Fatalf("CreateIncident() error = %v", err)
	}
	claimed, err := repository.ClaimOutbox(context.Background(), store.ClaimOutboxRequest{
		EventType: "incident.created.v1", ConsumerID: "dispatcher-1", Limit: 1, Lease: time.Minute,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("ClaimOutbox() = (%#v, %v)", claimed, err)
	}
	event := claimed[0]
	if err := repository.AckOutbox(context.Background(), event.ID, "signal.ingested.v1", event.ClaimToken); !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("AckOutbox(wrong type) error = %v, want ErrStaleClaim", err)
	}
	if err := repository.RetryOutbox(context.Background(), event.ID, "signal.ingested.v1", event.ClaimToken, now.Add(time.Minute), "wrong_handler"); !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("RetryOutbox(wrong type) error = %v, want ErrStaleClaim", err)
	}
	if err := repository.AckOutbox(context.Background(), event.ID, "incident.created.v1", event.ClaimToken); err != nil {
		t.Fatalf("AckOutbox(correct type) error = %v", err)
	}
}

func TestOutboxClaimUsesFencingTokenAndRecoversExpiredLease(t *testing.T) {
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	repository := memory.NewWithClock(func() time.Time { return now })
	incident := domain.NewIncident("incident-1", "workspace-1", now)
	if err := repository.CreateIncident(context.Background(), incident); err != nil {
		t.Fatalf("CreateIncident() error = %v", err)
	}

	first, err := repository.ClaimOutbox(context.Background(), store.ClaimOutboxRequest{
		EventType: "incident.created.v1", ConsumerID: "dispatcher-1", Limit: 1, Lease: time.Minute,
	})
	if err != nil || len(first) != 1 || first[0].ClaimToken == "" || first[0].Attempts != 1 {
		t.Fatalf("first ClaimOutbox() = (%#v, %v)", first, err)
	}
	now = now.Add(2 * time.Minute)
	second, err := repository.ClaimOutbox(context.Background(), store.ClaimOutboxRequest{
		EventType: "incident.created.v1", ConsumerID: "dispatcher-2", Limit: 1, Lease: time.Minute,
	})
	if err != nil || len(second) != 1 || second[0].ClaimToken == first[0].ClaimToken || second[0].Attempts != 2 {
		t.Fatalf("second ClaimOutbox() = (%#v, %v)", second, err)
	}
	if err := repository.AckOutbox(context.Background(), first[0].ID, "incident.created.v1", first[0].ClaimToken); !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("AckOutbox(stale) error = %v, want ErrStaleClaim", err)
	}
	if err := repository.AckOutbox(context.Background(), second[0].ID, "incident.created.v1", second[0].ClaimToken); err != nil {
		t.Fatalf("AckOutbox(current) error = %v", err)
	}
	if err := repository.AckOutbox(context.Background(), second[0].ID, "incident.created.v1", second[0].ClaimToken); err != nil {
		t.Fatalf("AckOutbox(retry after uncertain response) error = %v", err)
	}
	if err := repository.AckOutbox(context.Background(), second[0].ID, "incident.created.v1", "wrong-token"); !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("AckOutbox(delivered with wrong token) error = %v, want ErrStaleClaim", err)
	}
	if claimed, err := repository.ClaimOutbox(context.Background(), store.ClaimOutboxRequest{
		EventType: "incident.created.v1", ConsumerID: "dispatcher-1", Limit: 1, Lease: time.Minute,
	}); err != nil || len(claimed) != 0 {
		t.Fatalf("ClaimOutbox(delivered) = (%#v, %v), want empty", claimed, err)
	}
}

func TestOutboxExpiredLeaseCannotAckBeforeReclaim(t *testing.T) {
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	repository := memory.NewWithClock(func() time.Time { return now })
	if err := repository.CreateIncident(context.Background(), domain.NewIncident("incident-1", "workspace-1", now)); err != nil {
		t.Fatalf("CreateIncident() error = %v", err)
	}
	claimed, err := repository.ClaimOutbox(context.Background(), store.ClaimOutboxRequest{
		EventType: "incident.created.v1", ConsumerID: "dispatcher-1", Limit: 1, Lease: time.Minute,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("ClaimOutbox() = (%#v, %v)", claimed, err)
	}
	now = now.Add(time.Minute)
	if err := repository.AckOutbox(context.Background(), claimed[0].ID, "incident.created.v1", claimed[0].ClaimToken); !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("AckOutbox(expired) error = %v, want ErrStaleClaim", err)
	}
}

func TestOutboxRetryRequiresCurrentClaim(t *testing.T) {
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	repository := memory.NewWithClock(func() time.Time { return now })
	if err := repository.CreateIncident(context.Background(), domain.NewIncident("incident-1", "workspace-1", now)); err != nil {
		t.Fatalf("CreateIncident() error = %v", err)
	}
	claimed, err := repository.ClaimOutbox(context.Background(), store.ClaimOutboxRequest{
		EventType: "incident.created.v1", ConsumerID: "dispatcher-1", Limit: 1, Lease: time.Minute,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("ClaimOutbox() = (%#v, %v)", claimed, err)
	}
	retryAt := now.Add(5 * time.Minute)
	if err := repository.RetryOutbox(context.Background(), claimed[0].ID, "incident.created.v1", "wrong-token", retryAt, "temporal_unavailable"); !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("RetryOutbox(stale) error = %v, want ErrStaleClaim", err)
	}
	if err := repository.RetryOutbox(context.Background(), claimed[0].ID, "incident.created.v1", claimed[0].ClaimToken, retryAt, "temporal_unavailable"); err != nil {
		t.Fatalf("RetryOutbox(current) error = %v", err)
	}
	now = retryAt.Add(-time.Second)
	if retry, _ := repository.ClaimOutbox(context.Background(), store.ClaimOutboxRequest{
		EventType: "incident.created.v1", ConsumerID: "dispatcher-1", Limit: 1, Lease: time.Minute,
	}); len(retry) != 0 {
		t.Fatalf("ClaimOutbox(before retry) = %#v, want empty", retry)
	}
	now = retryAt
	if retry, _ := repository.ClaimOutbox(context.Background(), store.ClaimOutboxRequest{
		EventType: "incident.created.v1", ConsumerID: "dispatcher-1", Limit: 1, Lease: time.Minute,
	}); len(retry) != 1 || retry[0].LastErrorCode != "temporal_unavailable" {
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
		Fingerprint:     "fingerprint-1",
		Status:          "firing",
		ObservedAt:      time.Now(),
	}
}

func newSignalRepository(t *testing.T) *memory.Store {
	t.Helper()
	repository := memory.New()
	if err := repository.RegisterIntegration(domain.Integration{
		ID: "integration-1", WorkspaceID: "workspace-1", Provider: "alertmanager", Enabled: true,
	}); err != nil {
		t.Fatalf("RegisterIntegration() error = %v", err)
	}
	return repository
}
