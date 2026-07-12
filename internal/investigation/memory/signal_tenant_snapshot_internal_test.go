package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func TestSignalReadersFailClosedWhenTenantSnapshotIsMissing(t *testing.T) {
	now := time.Date(2026, 7, 12, 5, 0, 0, 0, time.UTC)
	repository, err := New(Options{
		TaskRuntimeBinder: testTaskRuntimeBinder,
		Clock:             func() time.Time { return now }, IDFactory: func() string { return "77777777-7777-4777-8777-777777777777" },
		TenantResolver:     func(string) (string, error) { return "11111111-1111-4111-8111-111111111111", nil },
		TaskSpecAuthorizer: func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error { return nil },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	signal := snapshotSignal(now)
	if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
		t.Fatalf("RegisterSignal() error = %v", err)
	}
	repository.mu.Lock()
	delete(repository.signalTenants, scoped(signal.WorkspaceID, signal.ID))
	repository.mu.Unlock()
	if _, err := repository.GetRegisteredSignal(context.Background(), signal.ID); !errors.Is(err, store.ErrScopeViolation) {
		t.Fatalf("GetRegisteredSignal(missing snapshot) error = %v", err)
	}
	if _, err := repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
		WorkspaceID: signal.WorkspaceID, SignalID: signal.ID, CorrelationKey: "payments:staging",
		MappingStatus: domain.MappingUnresolved,
	}); !errors.Is(err, store.ErrScopeViolation) {
		t.Fatalf("CorrelateSignal(missing snapshot) error = %v", err)
	}
	if _, err := repository.RegisterSignal(context.Background(), signal); !errors.Is(err, store.ErrScopeViolation) {
		t.Fatalf("RegisterSignal(replay missing snapshot) error = %v", err)
	}
}

func TestConcurrentFirstSignalRegistrationDoubleChecksAtomicTenantSnapshot(t *testing.T) {
	now := time.Date(2026, 7, 12, 5, 0, 0, 0, time.UTC)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	repository, err := New(Options{
		TaskRuntimeBinder: testTaskRuntimeBinder,
		Clock:             func() time.Time { return now }, IDFactory: func() string { return "77777777-7777-4777-8777-777777777777" },
		TenantResolver: func(string) (string, error) {
			entered <- struct{}{}
			<-release
			return "11111111-1111-4111-8111-111111111111", nil
		},
		TaskSpecAuthorizer: func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error { return nil },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	signal := snapshotSignal(now)
	type result struct {
		created bool
		err     error
	}
	results := make(chan result, 2)
	var wait sync.WaitGroup
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			created, registerErr := repository.RegisterSignal(context.Background(), signal)
			results <- result{created: created, err: registerErr}
		}()
	}
	<-entered
	<-entered
	close(release)
	wait.Wait()
	close(results)
	createdCount := 0
	for item := range results {
		if item.err != nil {
			t.Fatalf("RegisterSignal(concurrent) error = %v", item.err)
		}
		if item.created {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("concurrent created count = %d, want 1", createdCount)
	}
	registered, err := repository.GetRegisteredSignal(context.Background(), signal.ID)
	if err != nil || registered.TenantID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("GetRegisteredSignal() = %#v, %v", registered, err)
	}
}

func snapshotSignal(now time.Time) domain.Signal {
	return domain.Signal{
		ID: "55555555-5555-4555-8555-555555555555", WorkspaceID: "33333333-3333-4333-8333-333333333333",
		IntegrationID: "66666666-6666-4666-8666-666666666666", Provider: "alertmanager",
		ProviderEventID: "event-snapshot", PayloadHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Fingerprint: "payments", Status: "firing", Labels: map[string]string{"service": "payments"}, ObservedAt: now,
	}
}
