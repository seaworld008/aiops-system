package outbox_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/outbox"
	"github.com/seaworld008/aiops-system/internal/store"
	"github.com/seaworld008/aiops-system/internal/store/memory"
)

const (
	testTenantID      = "11111111-1111-4111-8111-111111111111"
	testWorkspaceID   = "22222222-2222-4222-8222-222222222222"
	testIntegrationID = "33333333-3333-4333-8333-333333333333"
	testSignalID      = "44444444-4444-4444-8444-444444444444"
	testOutboxID      = "55555555-5555-4555-8555-555555555555"
	testClaimToken    = "66666666-6666-4666-8666-666666666666"
	secretCanary      = "payload-token-fence-canary"
)

func TestSignalDispatcherClaimsOnlySignalsDespiteEarlierIncidentBacklog(t *testing.T) {
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	repository := memory.NewWithClock(func() time.Time { return now })
	for index := 0; index < 4; index++ {
		incidentID := fmt.Sprintf("70000000-0000-4000-8000-%012d", index+1)
		if err := repository.CreateIncident(context.Background(), domain.NewIncident(incidentID, testWorkspaceID, now)); err != nil {
			t.Fatalf("CreateIncident(%d) error = %v", index, err)
		}
	}
	if err := repository.RegisterIntegration(domain.Integration{
		ID: testIntegrationID, WorkspaceID: testWorkspaceID, Provider: "alertmanager", Enabled: true,
	}); err != nil {
		t.Fatalf("RegisterIntegration() error = %v", err)
	}
	if _, err := repository.CreateSignal(context.Background(), domain.Signal{
		ID: testSignalID, WorkspaceID: testWorkspaceID, IntegrationID: testIntegrationID,
		Provider: "alertmanager", ProviderEventID: "event-1", PayloadHash: "hash",
		Fingerprint: "fingerprint", Status: "firing", ObservedAt: now,
	}); err != nil {
		t.Fatalf("CreateSignal() error = %v", err)
	}
	starter := &fakeSignalStarter{}
	dispatcher := newTestDispatcher(t, repository, starter, now, 1)

	result, err := dispatcher.RunOnce(context.Background())
	if err != nil || result.Claimed != 1 || result.Started != 1 || len(starter.starts) != 1 {
		t.Fatalf("RunOnce() = (%#v, %v), starts=%#v", result, err, starter.starts)
	}
	if starter.starts[0].SignalID != testSignalID {
		t.Fatalf("started signal = %q, want %q", starter.starts[0].SignalID, testSignalID)
	}
	incidents, err := repository.ClaimOutbox(context.Background(), store.ClaimOutboxRequest{
		EventType: "incident.created.v1", ConsumerID: "incident-dispatcher", Limit: 4, Lease: time.Minute,
	})
	if err != nil || len(incidents) != 4 {
		t.Fatalf("incident backlog after signal dispatch = (%d, %v), want 4 untouched", len(incidents), err)
	}
}

func TestSignalDispatcherBuildsSecretSafeTypedStart(t *testing.T) {
	event := validSignalEvent()
	event.ClaimedBy = secretCanary
	event.ClaimToken = secretCanary
	event.LastErrorCode = secretCanary
	repository := &fakeOutboxRepository{batches: [][]domain.OutboxEvent{{event}}}
	starter := &fakeSignalStarter{}
	dispatcher := newTestDispatcher(t, repository, starter, event.ClaimedAt, 1)

	result, err := dispatcher.RunOnce(context.Background())
	if err != nil || result.Started != 1 || len(starter.starts) != 1 {
		t.Fatalf("RunOnce() = (%#v, %v), starts=%#v", result, err, starter.starts)
	}
	if len(repository.claimTypes) != 1 || repository.claimTypes[0] != "signal.ingested.v1" {
		t.Fatalf("dispatcher claim types = %#v", repository.claimTypes)
	}
	start := starter.starts[0]
	if start.Version != 1 || start.WorkflowID != event.ID || start.OutboxEventID != event.ID ||
		start.TenantID != event.TenantID || start.WorkspaceID != event.WorkspaceID ||
		start.SignalID != event.AggregateID || start.AggregateVersion != 1 {
		t.Fatalf("SignalWorkflowStart = %#v", start)
	}
	encoded, err := json.Marshal(start)
	if err != nil {
		t.Fatalf("json.Marshal(start) error = %v", err)
	}
	rendered := string(encoded) + fmt.Sprintf(" %#v", start)
	for _, forbidden := range []string{secretCanary, "payload", "claim_token", "claimed_by", "attempts", "last_error"} {
		if strings.Contains(strings.ToLower(rendered), strings.ToLower(forbidden)) {
			t.Fatalf("typed start leaked forbidden %q: %s", forbidden, rendered)
		}
	}
}

func TestSignalDispatcherAcknowledgesBothTerminalStartOutcomes(t *testing.T) {
	first := validSignalEvent()
	second := validSignalEvent()
	second.ID = "77777777-7777-4777-8777-777777777777"
	second.ClaimToken = "88888888-8888-4888-8888-888888888888"
	repository := &fakeOutboxRepository{batches: [][]domain.OutboxEvent{{first, second}}}
	starter := &fakeSignalStarter{outcomes: []outbox.StartOutcome{
		outbox.StartOutcomeStarted,
		outbox.StartOutcomeAlreadyExists,
	}}
	dispatcher := newTestDispatcher(t, repository, starter, first.ClaimedAt, 2)

	result, err := dispatcher.RunOnce(context.Background())
	if err != nil || result.Started != 1 || result.AlreadyExists != 1 || result.Retried != 0 {
		t.Fatalf("RunOnce() = (%#v, %v)", result, err)
	}
	if repository.ackCalls != 2 || repository.retryCalls != 0 {
		t.Fatalf("ack/retry calls = %d/%d, want 2/0", repository.ackCalls, repository.retryCalls)
	}
	for _, eventType := range repository.ackTypes {
		if eventType != "signal.ingested.v1" {
			t.Fatalf("AckOutbox expected type = %q", eventType)
		}
	}
}

func TestSignalDispatcherRetriesUnknownNilErrorOutcomeWithoutAck(t *testing.T) {
	event := validSignalEvent()
	repository := &fakeOutboxRepository{batches: [][]domain.OutboxEvent{{event}}}
	starter := &fakeSignalStarter{outcomes: []outbox.StartOutcome{outbox.StartOutcome("FUTURE_OUTCOME")}}
	dispatcher := newTestDispatcher(t, repository, starter, event.ClaimedAt, 1)

	result, err := dispatcher.RunOnce(context.Background())
	if err != nil || result.Retried != 1 || repository.ackCalls != 0 || repository.retryCalls != 1 {
		t.Fatalf("RunOnce() = (%#v, %v), ack/retry=%d/%d", result, err, repository.ackCalls, repository.retryCalls)
	}
	if repository.failureCodes[0] != "workflow_start_outcome_invalid" {
		t.Fatalf("retry failure code = %q", repository.failureCodes[0])
	}
}

func TestSignalDispatcherRetriesStartErrorWithSanitizedBoundedBackoff(t *testing.T) {
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	event := validSignalEvent()
	event.Attempts = 10
	repository := &fakeOutboxRepository{batches: [][]domain.OutboxEvent{{event}}}
	starter := &fakeSignalStarter{errs: []error{
		outbox.NewDispatchError("temporal_unavailable", errors.New(secretCanary)),
	}}
	dispatcher, err := outbox.NewSignalDispatcher(repository, starter, outbox.Options{
		ConsumerID: "signal-worker-1", BatchSize: 1, Lease: time.Minute,
		BaseBackoff: 5 * time.Second, MaxBackoff: 20 * time.Second, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewSignalDispatcher() error = %v", err)
	}

	result, err := dispatcher.RunOnce(context.Background())
	if err != nil || result.Retried != 1 || repository.ackCalls != 0 || repository.retryCalls != 1 {
		t.Fatalf("RunOnce() = (%#v, %v), ack/retry=%d/%d", result, err, repository.ackCalls, repository.retryCalls)
	}
	if repository.failureCodes[0] != "temporal_unavailable" || !repository.retryAt[0].Equal(now.Add(20*time.Second)) {
		t.Fatalf("retry = %q at %s", repository.failureCodes[0], repository.retryAt[0])
	}
}

func TestSignalDispatcherRejectsPoisonEventsWithoutStartingAcknowledgingOrRetrying(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*domain.OutboxEvent)
	}{
		{name: "malformed payload", mutate: func(event *domain.OutboxEvent) { event.Payload = json.RawMessage(`{"signal_id":`) }},
		{name: "extra payload member", mutate: func(event *domain.OutboxEvent) {
			event.Payload = json.RawMessage(`{"signal_id":"` + testSignalID + `","extra":"` + secretCanary + `"}`)
		}},
		{name: "duplicate payload member", mutate: func(event *domain.OutboxEvent) {
			event.Payload = json.RawMessage(`{"signal_id":"` + testSignalID + `","signal_id":"` + testSignalID + `"}`)
		}},
		{name: "aggregate mismatch", mutate: func(event *domain.OutboxEvent) {
			event.Payload = json.RawMessage(`{"signal_id":"99999999-9999-4999-8999-999999999999"}`)
		}},
		{name: "wrong type", mutate: func(event *domain.OutboxEvent) { event.Type = "incident.created.v1" }},
		{name: "wrong aggregate", mutate: func(event *domain.OutboxEvent) { event.AggregateType = "INCIDENT" }},
		{name: "wrong version", mutate: func(event *domain.OutboxEvent) { event.AggregateVersion = 2 }},
		{name: "non UUID outbox", mutate: func(event *domain.OutboxEvent) { event.ID = "outbox-1" }},
		{name: "non UUID tenant", mutate: func(event *domain.OutboxEvent) { event.TenantID = "tenant-1" }},
		{name: "non UUID workspace", mutate: func(event *domain.OutboxEvent) { event.WorkspaceID = "workspace-1" }},
		{name: "non UUID signal", mutate: func(event *domain.OutboxEvent) {
			event.AggregateID = "signal-1"
			event.Payload = json.RawMessage(`{"signal_id":"signal-1"}`)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := validSignalEvent()
			event.ClaimToken = secretCanary
			test.mutate(&event)
			repository := &fakeOutboxRepository{batches: [][]domain.OutboxEvent{{event}}}
			starter := &fakeSignalStarter{}
			dispatcher := newTestDispatcher(t, repository, starter, event.ClaimedAt, 1)

			result, err := dispatcher.RunOnce(context.Background())
			if err == nil || result.Claimed != 1 {
				t.Fatalf("RunOnce() = (%#v, %v), want retained poison error", result, err)
			}
			if len(starter.starts) != 0 || repository.ackCalls != 0 || repository.retryCalls != 0 {
				t.Fatalf("poison side effects: starts=%d ack=%d retry=%d", len(starter.starts), repository.ackCalls, repository.retryCalls)
			}
			if strings.Contains(err.Error(), secretCanary) {
				t.Fatalf("poison error leaked payload/token: %v", err)
			}
		})
	}
}

func TestSignalDispatcherRecoversWhenStartSucceededButAckWasLost(t *testing.T) {
	first := validSignalEvent()
	second := validSignalEvent()
	second.ClaimToken = "77777777-7777-4777-8777-777777777777"
	second.Attempts = 2
	repository := &fakeOutboxRepository{
		batches:   [][]domain.OutboxEvent{{first}, {second}},
		ackErrors: []error{errors.New("ack response lost"), nil},
	}
	starter := &fakeSignalStarter{outcomes: []outbox.StartOutcome{
		outbox.StartOutcomeStarted,
		outbox.StartOutcomeAlreadyExists,
	}}
	dispatcher := newTestDispatcher(t, repository, starter, first.ClaimedAt, 1)

	if _, err := dispatcher.RunOnce(context.Background()); err == nil {
		t.Fatal("first RunOnce() error = nil, want lost ACK response")
	}
	result, err := dispatcher.RunOnce(context.Background())
	if err != nil || result.AlreadyExists != 1 || repository.ackCalls != 2 || repository.retryCalls != 0 {
		t.Fatalf("redelivery RunOnce() = (%#v, %v), ack/retry=%d/%d", result, err, repository.ackCalls, repository.retryCalls)
	}
}

func newTestDispatcher(
	t *testing.T,
	repository outboxRepository,
	starter *fakeSignalStarter,
	now time.Time,
	batchSize int,
) *outbox.SignalDispatcher {
	t.Helper()
	dispatcher, err := outbox.NewSignalDispatcher(repository, starter, outbox.Options{
		ConsumerID: "signal-worker-1", BatchSize: batchSize, Lease: time.Minute,
		BaseBackoff: time.Second, MaxBackoff: time.Minute, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewSignalDispatcher() error = %v", err)
	}
	return dispatcher
}

type outboxRepository interface {
	ClaimOutbox(context.Context, store.ClaimOutboxRequest) ([]domain.OutboxEvent, error)
	AckOutbox(context.Context, string, string, string) error
	RetryOutbox(context.Context, string, string, string, time.Time, string) error
}

type fakeOutboxRepository struct {
	batches      [][]domain.OutboxEvent
	claims       int
	claimTypes   []string
	ackCalls     int
	ackTypes     []string
	ackErrors    []error
	retryCalls   int
	retryTypes   []string
	retryAt      []time.Time
	failureCodes []string
}

func (repository *fakeOutboxRepository) ClaimOutbox(
	_ context.Context,
	request store.ClaimOutboxRequest,
) ([]domain.OutboxEvent, error) {
	repository.claimTypes = append(repository.claimTypes, request.EventType)
	if repository.claims >= len(repository.batches) {
		return nil, nil
	}
	batch := repository.batches[repository.claims]
	repository.claims++
	return batch, nil
}

func (repository *fakeOutboxRepository) AckOutbox(_ context.Context, _, eventType, _ string) error {
	repository.ackCalls++
	repository.ackTypes = append(repository.ackTypes, eventType)
	index := repository.ackCalls - 1
	if index < len(repository.ackErrors) {
		return repository.ackErrors[index]
	}
	return nil
}

func (repository *fakeOutboxRepository) RetryOutbox(
	_ context.Context,
	_, eventType, _ string,
	availableAt time.Time,
	failureCode string,
) error {
	repository.retryCalls++
	repository.retryTypes = append(repository.retryTypes, eventType)
	repository.retryAt = append(repository.retryAt, availableAt)
	repository.failureCodes = append(repository.failureCodes, failureCode)
	return nil
}

type fakeSignalStarter struct {
	outcomes []outbox.StartOutcome
	errs     []error
	starts   []outbox.SignalWorkflowStart
}

func (starter *fakeSignalStarter) Start(
	_ context.Context,
	start outbox.SignalWorkflowStart,
) (outbox.StartOutcome, error) {
	index := len(starter.starts)
	starter.starts = append(starter.starts, start)
	var outcome outbox.StartOutcome
	if index < len(starter.outcomes) {
		outcome = starter.outcomes[index]
	} else {
		outcome = outbox.StartOutcomeStarted
	}
	if index < len(starter.errs) {
		return outcome, starter.errs[index]
	}
	return outcome, nil
}

func validSignalEvent() domain.OutboxEvent {
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	return domain.OutboxEvent{
		ID: testOutboxID, TenantID: testTenantID, WorkspaceID: testWorkspaceID,
		AggregateType: "SIGNAL", AggregateID: testSignalID, AggregateVersion: 1,
		Type: "signal.ingested.v1", Payload: json.RawMessage(`{"signal_id":"` + testSignalID + `"}`),
		CreatedAt: now, AvailableAt: now, ClaimedAt: now, ClaimedBy: "signal-worker-1",
		ClaimToken: testClaimToken, ClaimExpiresAt: now.Add(time.Minute), Attempts: 1,
	}
}
