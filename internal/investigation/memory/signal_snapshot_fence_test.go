package memory_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigation/memory"
	"github.com/seaworld008/aiops-system/internal/store"
)

func TestCorrelateSignalChecksExpectedSnapshotInsideMemoryLock(t *testing.T) {
	repository := newRegistrationRepository(t)
	signal := registrationSignal(registrationWorkspaceA, "event-fenced")
	if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
		t.Fatalf("RegisterSignal() error = %v", err)
	}
	hash, err := investigation.RegisteredSignalSnapshotHash(investigation.RegisteredSignal{
		TenantID: registrationTenantA, WorkspaceID: signal.WorkspaceID, Signal: signal,
	})
	if err != nil {
		t.Fatalf("RegisteredSignalSnapshotHash() error = %v", err)
	}
	request := investigation.CorrelateSignalRequest{
		WorkspaceID: signal.WorkspaceID, SignalID: signal.ID, CorrelationKey: "payments:staging:fenced",
		MappingStatus: domain.MappingUnresolved, ExpectedSignalHash: strings.Repeat("b", 64),
	}
	if _, err := repository.CorrelateSignal(context.Background(), request); !errors.Is(err, store.ErrScopeViolation) {
		t.Fatalf("CorrelateSignal(stale snapshot) error = %v, want ErrScopeViolation", err)
	}
	request.ExpectedSignalHash = hash
	result, err := repository.CorrelateSignal(context.Background(), request)
	if err != nil || !result.Associated {
		t.Fatalf("CorrelateSignal(exact snapshot) = %#v, %v", result, err)
	}
}

func TestCorrelateSignalTenantBoundSnapshotPreventsCrossTenantMiswireWrites(t *testing.T) {
	signal := registrationSignal(registrationWorkspaceA, "event-cross-tenant")
	hashFromTenantA, err := investigation.RegisteredSignalSnapshotHash(investigation.RegisteredSignal{
		TenantID: registrationTenantA, WorkspaceID: signal.WorkspaceID, Signal: signal,
	})
	if err != nil {
		t.Fatalf("RegisteredSignalSnapshotHash(tenant A) error = %v", err)
	}
	repository, err := memory.New(memory.Options{
		Clock:              func() time.Time { return time.Date(2026, 7, 12, 1, 0, 0, 0, time.UTC) },
		IDFactory:          func() string { return "77777777-7777-4777-8777-777777777777" },
		TenantResolver:     func(string) (string, error) { return registrationTenantB, nil },
		TaskSpecAuthorizer: func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error { return nil },
	})
	if err != nil {
		t.Fatalf("memory.New(tenant B) error = %v", err)
	}
	if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
		t.Fatalf("RegisterSignal(tenant B) error = %v", err)
	}
	_, err = repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
		WorkspaceID: signal.WorkspaceID, SignalID: signal.ID,
		ExpectedSignalHash: hashFromTenantA, CorrelationKey: "payments:staging:cross-tenant",
		MappingStatus: domain.MappingUnresolved,
	})
	if !errors.Is(err, store.ErrScopeViolation) {
		t.Fatalf("CorrelateSignal(cross tenant) error = %v, want ErrScopeViolation", err)
	}
	incidents, err := repository.ListIncidents(context.Background(), investigation.ListIncidentsRequest{WorkspaceID: signal.WorkspaceID})
	if err != nil || len(incidents) != 0 {
		t.Fatalf("cross-tenant snapshot left incidents = %#v, %v", incidents, err)
	}
}
