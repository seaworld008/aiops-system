package outbox_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/outbox"
	"github.com/seaworld008/aiops-system/internal/store/memory"
)

func TestDispatcherUsesOutboxIDAsStableWorkflowIDAndAcknowledges(t *testing.T) {
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	repository := memory.NewWithClock(func() time.Time { return now })
	if err := repository.CreateIncident(context.Background(), domain.NewIncident("incident-1", "workspace-1", now)); err != nil {
		t.Fatalf("CreateIncident() error = %v", err)
	}
	starter := &fakeStarter{}
	dispatcher, err := outbox.NewDispatcher(repository, starter, outbox.Options{
		ConsumerID: "worker-1", BatchSize: 10, Lease: time.Minute,
		BaseBackoff: time.Second, MaxBackoff: time.Minute, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewDispatcher() error = %v", err)
	}

	result, err := dispatcher.RunOnce(context.Background())
	if err != nil || result.Started != 1 || len(starter.workflowIDs) != 1 {
		t.Fatalf("RunOnce() = (%#v, %v), workflowIDs=%#v", result, err, starter.workflowIDs)
	}
	if starter.workflowIDs[0] == "" || starter.workflowIDs[0] != starter.events[0].ID {
		t.Fatalf("workflow ID = %q, event ID = %q", starter.workflowIDs[0], starter.events[0].ID)
	}
	second, err := dispatcher.RunOnce(context.Background())
	if err != nil || second.Claimed != 0 {
		t.Fatalf("second RunOnce() = (%#v, %v), want no redelivery", second, err)
	}
}

func TestDispatcherSchedulesSanitizedRetryWithBoundedBackoff(t *testing.T) {
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	repository := memory.NewWithClock(func() time.Time { return now })
	if err := repository.CreateIncident(context.Background(), domain.NewIncident("incident-1", "workspace-1", now)); err != nil {
		t.Fatalf("CreateIncident() error = %v", err)
	}
	starter := &fakeStarter{err: outbox.NewDispatchError("temporal_unavailable", errors.New("sensitive upstream body"))}
	dispatcher, err := outbox.NewDispatcher(repository, starter, outbox.Options{
		ConsumerID: "worker-1", BatchSize: 1, Lease: time.Minute,
		BaseBackoff: 5 * time.Second, MaxBackoff: time.Minute, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewDispatcher() error = %v", err)
	}

	result, err := dispatcher.RunOnce(context.Background())
	if err != nil || result.Retried != 1 {
		t.Fatalf("RunOnce() = (%#v, %v), want scheduled retry", result, err)
	}
	now = now.Add(4 * time.Second)
	before, err := dispatcher.RunOnce(context.Background())
	if err != nil || before.Claimed != 0 {
		t.Fatalf("RunOnce(before retry) = (%#v, %v)", before, err)
	}
	now = now.Add(time.Second)
	starter.err = nil
	after, err := dispatcher.RunOnce(context.Background())
	if err != nil || after.Started != 1 {
		t.Fatalf("RunOnce(at retry) = (%#v, %v)", after, err)
	}
}

type fakeStarter struct {
	err         error
	workflowIDs []string
	events      []domain.OutboxEvent
}

func (starter *fakeStarter) Start(_ context.Context, workflowID string, event domain.OutboxEvent) error {
	starter.workflowIDs = append(starter.workflowIDs, workflowID)
	starter.events = append(starter.events, event)
	return starter.err
}
