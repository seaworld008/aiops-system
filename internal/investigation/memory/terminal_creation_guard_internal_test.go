package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

func TestCreateOrGetInvestigationRejectsNewFactsForTerminalIncident(t *testing.T) {
	now := time.Date(2026, 7, 12, 2, 0, 0, 0, time.UTC)
	for _, status := range []domain.IncidentStatus{domain.IncidentResolved, domain.IncidentClosed} {
		t.Run(string(status), func(t *testing.T) {
			authorizerCalls := 0
			repository, err := New(Options{
				TaskRuntimeBinder: testTaskRuntimeBinder,
				Clock:             func() time.Time { return now }, IDFactory: func() string { return "generated-id" },
				TenantResolver: func(string) (string, error) { return "tenant-1", nil },
				TaskSpecAuthorizer: func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error {
					authorizerCalls++
					return errors.New("terminal authorizer must not run")
				},
			})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			incident := domain.NewIncidentForTenant("incident-1", "tenant-1", "workspace-1", now)
			incident.ServiceID = "service-1"
			incident.EnvironmentID = "environment-1"
			incident.CorrelationKey = "payments:staging"
			incident.MappingStatus = domain.MappingExact
			incident.LastSignalAt = now
			incident.SignalCount = 1
			incident.Status = status
			repository.incidents[scoped("workspace-1", incident.ID)] = incident

			_, createErr := repository.CreateOrGetInvestigation(context.Background(), boundCreateRequest(t, investigation.CreateOrGetInvestigationRequest{
				WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "temporal.prepare.v1/event-1",
				Tasks: []investigation.TaskSpec{{
					Key: "metrics", ConnectorID: "prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", Operation: "range_query",
					Input: []byte(`{"lookback_minutes":15}`),
				}},
			}))

			if !errors.Is(createErr, investigation.ErrInvalidTransition) {
				t.Fatalf("CreateOrGetInvestigation(%s) error = %v, want ErrInvalidTransition", status, createErr)
			}
			if authorizerCalls != 0 {
				t.Fatalf("terminal authorizer calls = %d, want 0", authorizerCalls)
			}
			if len(repository.investigations) != 0 || len(repository.tasks) != 0 ||
				len(repository.investigationIdempotency) != 0 || len(repository.idempotencyOwners) != 0 {
				t.Fatalf("terminal create left writes: investigations=%d tasks=%d idempotency=%d owners=%d",
					len(repository.investigations), len(repository.tasks), len(repository.investigationIdempotency), len(repository.idempotencyOwners))
			}
		})
	}
}
