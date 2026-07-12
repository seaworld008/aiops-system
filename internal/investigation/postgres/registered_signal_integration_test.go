package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func TestPostgresGetRegisteredSignalUsesGlobalPrimaryKeyAndTrustedCompositeScope(t *testing.T) {
	fixture := newRepositoryWriteFixture(t, nil)
	want := fixture.registerSignal(t, repositorySignalID, "firing", fixture.base, "event-global-registration")
	registered, err := fixture.repository.GetRegisteredSignal(context.Background(), want.ID)
	if err != nil {
		t.Fatalf("GetRegisteredSignal() error = %v", err)
	}
	if registered.TenantID != testTenantID || registered.WorkspaceID != testWorkspaceID ||
		registered.Signal.ID != want.ID || registered.Signal.WorkspaceID != testWorkspaceID ||
		registered.Signal.ProviderEventID != want.ProviderEventID {
		t.Fatalf("GetRegisteredSignal() = %#v", registered)
	}
	registered.Signal.Labels["service"] = "mutated"
	again, err := fixture.repository.GetRegisteredSignal(context.Background(), want.ID)
	if err != nil || again.Signal.Labels["service"] != "payments" {
		t.Fatalf("GetRegisteredSignal(detached) = %#v, %v", again, err)
	}
}

func TestPostgresTerminalIncidentGuardPreventsNewInvestigationFacts(t *testing.T) {
	fixture := newRepositoryWriteFixture(t, nil)
	signal := fixture.registerSignal(t, repositorySignalID, "firing", fixture.base, "event-terminal-guard")
	correlated, err := fixture.repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
		WorkspaceID: testWorkspaceID, SignalID: signal.ID, CorrelationKey: "payments:staging:terminal-guard",
		ServiceID: testServiceID, EnvironmentID: testEnvironmentID, MappingStatus: domain.MappingExact,
	})
	if err != nil || !correlated.Associated {
		t.Fatalf("CorrelateSignal() = %#v, %v", correlated, err)
	}
	if _, err := fixture.harness.db.Exec(context.Background(), `
		UPDATE incidents SET status = 'RESOLVED' WHERE id = $1
	`, correlated.Incident.ID); err != nil {
		t.Fatalf("resolve incident fixture: %v", err)
	}
	const idempotencyKey = "temporal.prepare.v1/90000000-0000-4000-8000-000000000009"
	_, err = fixture.repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: testWorkspaceID, IncidentID: correlated.Incident.ID, IdempotencyKey: idempotencyKey,
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-staging", Operation: "range_query",
			Input: []byte(`{"lookback_minutes":15}`),
		}},
	})
	if !errors.Is(err, investigation.ErrInvalidTransition) {
		t.Fatalf("CreateOrGetInvestigation(terminal) error = %v, want ErrInvalidTransition", err)
	}
	var investigations, tasks, idempotency int
	if err := fixture.harness.db.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*) FROM investigations WHERE incident_id = $1),
			(SELECT count(*) FROM tool_invocations WHERE incident_id = $1),
			(SELECT count(*) FROM investigation_idempotency_records WHERE workspace_id = $2 AND idempotency_key = $3)
	`, correlated.Incident.ID, testWorkspaceID, idempotencyKey).Scan(&investigations, &tasks, &idempotency); err != nil {
		t.Fatalf("read terminal guard facts: %v", err)
	}
	if investigations != 0 || tasks != 0 || idempotency != 0 {
		t.Fatalf("terminal guard left facts: investigations=%d tasks=%d idempotency=%d", investigations, tasks, idempotency)
	}
}

func TestPostgresCorrelationSnapshotFenceRejectsChangedSignalFacts(t *testing.T) {
	fixture := newRepositoryWriteFixture(t, nil)
	signal := fixture.registerSignal(t, repositorySignalID, "firing", fixture.base, "event-snapshot-fence")
	hash, err := investigation.RegisteredSignalSnapshotHash(investigation.RegisteredSignal{
		TenantID: testTenantID, WorkspaceID: signal.WorkspaceID, Signal: signal,
	})
	if err != nil {
		t.Fatalf("RegisteredSignalSnapshotHash() error = %v", err)
	}
	if _, err := fixture.harness.db.Exec(context.Background(), `
		UPDATE signals
		SET payload_summary = jsonb_set(payload_summary, '{labels,service}', '"checkout"'::jsonb)
		WHERE id = $1
	`, signal.ID); err != nil {
		t.Fatalf("mutate signal fixture: %v", err)
	}
	_, err = fixture.repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
		WorkspaceID: testWorkspaceID, SignalID: signal.ID, ExpectedSignalHash: hash,
		CorrelationKey: "payments:staging:snapshot-fence", ServiceID: testServiceID,
		EnvironmentID: testEnvironmentID, MappingStatus: domain.MappingExact,
	})
	if !errors.Is(err, store.ErrScopeViolation) {
		t.Fatalf("CorrelateSignal(changed snapshot) error = %v, want ErrScopeViolation", err)
	}
	var incidents, correlations int
	if err := fixture.harness.db.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*) FROM incidents WHERE correlation_key = 'payments:staging:snapshot-fence'),
			(SELECT count(*) FROM investigation_signal_correlations WHERE signal_id = $1)
	`, signal.ID).Scan(&incidents, &correlations); err != nil {
		t.Fatalf("read snapshot fence facts: %v", err)
	}
	if incidents != 0 || correlations != 0 {
		t.Fatalf("snapshot fence left facts: incidents=%d correlations=%d", incidents, correlations)
	}
}
