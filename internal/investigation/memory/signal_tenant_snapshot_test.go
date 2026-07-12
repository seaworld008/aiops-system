package memory_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigation/memory"
)

func TestSignalTenantSnapshotIsResolvedOnceAtFirstRegistration(t *testing.T) {
	now := time.Date(2026, 7, 12, 3, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	resolverCalls := 0
	failResolver := false
	repository, err := memory.New(memory.Options{
		TaskRuntimeBinder: testTaskRuntimeBinder,
		Clock:             func() time.Time { return now }, IDFactory: func() string { return "77777777-7777-4777-8777-777777777777" },
		TenantResolver: func(string) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			resolverCalls++
			if failResolver {
				return "", errors.New("resolver drift canary")
			}
			return registrationTenantA, nil
		},
		TaskSpecAuthorizer: func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error { return nil },
	})
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	signal := registrationSignal(registrationWorkspaceA, "event-snapshot")
	created, err := repository.RegisterSignal(context.Background(), signal)
	if err != nil || !created {
		t.Fatalf("RegisterSignal(first) = %v, %v", created, err)
	}
	mu.Lock()
	failResolver = true
	mu.Unlock()
	created, err = repository.RegisterSignal(context.Background(), signal)
	if err != nil || created {
		t.Fatalf("RegisterSignal(exact replay with failed resolver) = %v, %v", created, err)
	}
	registered, err := repository.GetRegisteredSignal(context.Background(), signal.ID)
	if err != nil || registered.TenantID != registrationTenantA {
		t.Fatalf("GetRegisteredSignal(snapshot) = %#v, %v", registered, err)
	}
	correlated, err := repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
		WorkspaceID: signal.WorkspaceID, SignalID: signal.ID, CorrelationKey: "payments:staging",
		ServiceID: "88888888-8888-4888-8888-888888888888", EnvironmentID: "99999999-9999-4999-8999-999999999999",
		MappingStatus: domain.MappingExact,
	})
	if err != nil || correlated.Incident.TenantID != registrationTenantA {
		t.Fatalf("CorrelateSignal(snapshot) = %#v, %v", correlated, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if resolverCalls != 1 {
		t.Fatalf("tenant resolver calls = %d, want exactly one at first registration", resolverCalls)
	}
}

func TestSignalRegistrationResolverFailureLeavesNoFact(t *testing.T) {
	now := time.Date(2026, 7, 12, 3, 0, 0, 0, time.UTC)
	repository, err := memory.New(memory.Options{
		TaskRuntimeBinder: testTaskRuntimeBinder,
		Clock:             func() time.Time { return now }, IDFactory: func() string { return "77777777-7777-4777-8777-777777777777" },
		TenantResolver:     func(string) (string, error) { return "", errors.New("resolver unavailable") },
		TaskSpecAuthorizer: func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error { return nil },
	})
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	signal := registrationSignal(registrationWorkspaceA, "event-failed")
	if created, err := repository.RegisterSignal(context.Background(), signal); created || !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("RegisterSignal(failed resolver) = %v, %v", created, err)
	}
	if _, err := repository.GetRegisteredSignal(context.Background(), signal.ID); err == nil {
		t.Fatalf("GetRegisteredSignal() succeeded after failed registration")
	}
}
