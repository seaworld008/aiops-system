package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigation/memory"
	"github.com/seaworld008/aiops-system/internal/store"
)

const (
	registrationTenantA     = "11111111-1111-4111-8111-111111111111"
	registrationTenantB     = "22222222-2222-4222-8222-222222222222"
	registrationWorkspaceA  = "33333333-3333-4333-8333-333333333333"
	registrationWorkspaceB  = "44444444-4444-4444-8444-444444444444"
	registrationSignalID    = "55555555-5555-4555-8555-555555555555"
	registrationIntegration = "66666666-6666-4666-8666-666666666666"
	registrationPayloadHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func TestGetRegisteredSignalResolvesTrustedScopeFromGlobalSignalID(t *testing.T) {
	repository := newRegistrationRepository(t)
	signal := registrationSignal(registrationWorkspaceA, "event-a")
	if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
		t.Fatalf("RegisterSignal() error = %v", err)
	}

	registered, err := repository.GetRegisteredSignal(context.Background(), registrationSignalID)
	if err != nil {
		t.Fatalf("GetRegisteredSignal() error = %v", err)
	}
	if registered.TenantID != registrationTenantA || registered.WorkspaceID != registrationWorkspaceA ||
		registered.Signal.ID != registrationSignalID || registered.Signal.WorkspaceID != registrationWorkspaceA {
		t.Fatalf("GetRegisteredSignal() = %#v", registered)
	}
	registered.Signal.Labels["service"] = "mutated"
	again, err := repository.GetRegisteredSignal(context.Background(), registrationSignalID)
	if err != nil || again.Signal.Labels["service"] != "payments" {
		t.Fatalf("GetRegisteredSignal(detached) = %#v, %v", again, err)
	}
}

func TestGetRegisteredSignalFailsClosedWhenMemoryIDIsAmbiguousAcrossWorkspaces(t *testing.T) {
	repository := newRegistrationRepository(t)
	for _, signal := range []domain.Signal{
		registrationSignal(registrationWorkspaceA, "event-a"),
		registrationSignal(registrationWorkspaceB, "event-b"),
	} {
		if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
			t.Fatalf("RegisterSignal() error = %v", err)
		}
	}
	if _, err := repository.GetRegisteredSignal(context.Background(), registrationSignalID); !errors.Is(err, store.ErrScopeViolation) {
		t.Fatalf("GetRegisteredSignal(ambiguous) error = %v, want ErrScopeViolation", err)
	}
}

func TestGetRegisteredSignalRejectsInvalidOrMissingGlobalID(t *testing.T) {
	repository := newRegistrationRepository(t)
	for name, signalID := range map[string]string{"empty": "", "not canonical": "NOT-A-UUID", "missing": registrationSignalID} {
		t.Run(name, func(t *testing.T) {
			_, err := repository.GetRegisteredSignal(context.Background(), signalID)
			if signalID == registrationSignalID {
				if !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("error = %v, want ErrNotFound", err)
				}
				return
			}
			if !errors.Is(err, investigation.ErrInvalidRequest) {
				t.Fatalf("error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func newRegistrationRepository(t *testing.T) *memory.Repository {
	t.Helper()
	now := time.Date(2026, 7, 12, 1, 0, 0, 0, time.UTC)
	repository, err := memory.New(memory.Options{
		Clock:     func() time.Time { return now },
		IDFactory: func() string { return "77777777-7777-4777-8777-777777777777" },
		TenantResolver: func(workspaceID string) (string, error) {
			switch workspaceID {
			case registrationWorkspaceA:
				return registrationTenantA, nil
			case registrationWorkspaceB:
				return registrationTenantB, nil
			default:
				return "", errors.New("unknown workspace")
			}
		},
		TaskSpecAuthorizer: func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error { return nil },
	})
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	return repository
}

func registrationSignal(workspaceID, eventID string) domain.Signal {
	return domain.Signal{
		ID: registrationSignalID, WorkspaceID: workspaceID, IntegrationID: registrationIntegration,
		Provider: "alertmanager", ProviderEventID: eventID, PayloadHash: registrationPayloadHash,
		Fingerprint: "payments-api", Status: "firing", Labels: map[string]string{"service": "payments"},
		ObservedAt: time.Date(2026, 7, 12, 0, 59, 0, 0, time.UTC),
	}
}
