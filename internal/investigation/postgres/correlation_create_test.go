package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

const (
	writeMockTenantID        = "11000000-0000-4000-8000-000000000001"
	writeMockWorkspaceID     = "21000000-0000-4000-8000-000000000001"
	writeMockSignalID        = "41000000-0000-4000-8000-000000000001"
	writeMockServiceID       = "71000000-0000-4000-8000-000000000001"
	writeMockEnvironmentID   = "81000000-0000-4000-8000-000000000001"
	writeMockIncidentID      = "51000000-0000-4000-8000-000000000001"
	writeMockInvestigationID = "61000000-0000-4000-8000-000000000001"
	writeMockTaskID          = "a1000000-0000-4000-8000-000000000001"
	writeMockOutboxID        = "91000000-0000-4000-8000-000000000001"
)

func TestCorrelateSignalAtomicallyCreatesIncidentAssociationAndOutbox(t *testing.T) {
	database, repository := newWriteMockRepository(t, []string{writeMockIncidentID, writeMockOutboxID}, nil)
	now := time.Date(2026, 7, 12, 8, 0, 0, 123000, time.UTC)
	request := investigation.CorrelateSignalRequest{
		WorkspaceID: writeMockWorkspaceID, SignalID: writeMockSignalID,
		CorrelationKey: "payments:staging:latency",
		ServiceID:      writeMockServiceID, EnvironmentID: writeMockEnvironmentID, MappingStatus: domain.MappingExact,
	}
	database.ExpectBegin()
	expectWriteMockWorkspace(database)
	database.ExpectQuery("FROM signals AS signal").
		WithArgs(writeMockTenantID, writeMockWorkspaceID, writeMockSignalID).
		WillReturnRows(pgxmock.NewRows([]string{"status", "observed_at"}).AddRow("firing", now))
	database.ExpectQuery("FROM investigation_signal_correlations AS correlation").
		WithArgs(writeMockTenantID, writeMockWorkspaceID, writeMockSignalID).
		WillReturnRows(emptyWriteMockCorrelationRows())
	database.ExpectQuery("FROM incidents AS incident").
		WithArgs(writeMockTenantID, writeMockWorkspaceID, request.CorrelationKey, runtimeSchemaVersion).
		WillReturnRows(emptyWriteMockIncidentRows())
	database.ExpectQuery("INSERT INTO incidents AS incident").
		WithArgs(
			writeMockIncidentID, writeMockTenantID, writeMockWorkspaceID,
			writeMockServiceID, writeMockEnvironmentID, now, request.CorrelationKey,
			request.MappingStatus, runtimeSchemaVersion,
		).
		WillReturnRows(writeMockIncidentRows(now))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(
			writeMockOutboxID, writeMockTenantID, writeMockWorkspaceID,
			writeMockIncidentID, int64(1), incidentCreatedEventType,
			`{"incident_id":"`+writeMockIncidentID+`"}`,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO incident_signals").
		WithArgs(writeMockTenantID, writeMockWorkspaceID, writeMockIncidentID, writeMockSignalID).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO investigation_signal_correlations").
		WithArgs(
			writeMockTenantID, writeMockWorkspaceID, writeMockSignalID, writeMockIncidentID,
			request.CorrelationKey, request.MappingStatus, writeMockServiceID, writeMockEnvironmentID,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	result, err := repository.CorrelateSignal(context.Background(), request)
	if err != nil || !result.Created || !result.Associated || !result.Counted || result.Incident.ID != writeMockIncidentID {
		t.Fatalf("CorrelateSignal() = %#v, %v", result, err)
	}
	assertWriteMockExpectations(t, database)
}

func TestCorrelateSignalRejectsStaleExpectedSignalSnapshotUnderRowLock(t *testing.T) {
	database, repository := newWriteMockRepository(t, nil, nil)
	now := time.Date(2026, 7, 12, 8, 0, 0, 123000, time.UTC)
	database.ExpectBegin()
	expectWriteMockWorkspace(database)
	database.ExpectQuery(`(?s)SELECT.*signal\.id::text.*FROM signals AS signal.*FOR UPDATE OF signal`).
		WithArgs(writeMockTenantID, writeMockWorkspaceID, writeMockSignalID).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "tenant_id", "workspace_id", "integration_id", "provider", "provider_event_id",
			"payload_hash", "fingerprint", "status", "labels", "observed_at",
		}).AddRow(
			writeMockSignalID, writeMockTenantID, writeMockWorkspaceID, writeMockServiceID,
			"alertmanager", "event-1", strings.Repeat("a", 64), "payments", "firing",
			[]byte(`{"service":"payments"}`), now,
		))
	database.ExpectRollback()
	_, err := repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
		WorkspaceID: writeMockWorkspaceID, SignalID: writeMockSignalID,
		ExpectedSignalHash: strings.Repeat("b", 64), CorrelationKey: "payments:staging:fenced",
		MappingStatus: domain.MappingUnresolved,
	})
	if !errors.Is(err, store.ErrScopeViolation) {
		t.Fatalf("CorrelateSignal(stale snapshot) error = %v, want ErrScopeViolation", err)
	}
	assertWriteMockExpectations(t, database)
}

func TestCorrelateSignalSnapshotHashBindsTenantResolvedByWorkspaceTransaction(t *testing.T) {
	const otherTenantID = "12000000-0000-4000-8000-000000000001"
	database, repository := newWriteMockRepository(t, nil, nil)
	now := time.Date(2026, 7, 12, 8, 0, 0, 123000, time.UTC)
	signal := domain.Signal{
		ID: writeMockSignalID, WorkspaceID: writeMockWorkspaceID, IntegrationID: writeMockServiceID,
		Provider: "alertmanager", ProviderEventID: "event-1", PayloadHash: strings.Repeat("a", 64),
		Fingerprint: "payments", Status: "firing", Labels: map[string]string{"service": "payments"}, ObservedAt: now,
	}
	hashFromOtherTenant, err := investigation.RegisteredSignalSnapshotHash(investigation.RegisteredSignal{
		TenantID: otherTenantID, WorkspaceID: writeMockWorkspaceID, Signal: signal,
	})
	if err != nil {
		t.Fatalf("RegisteredSignalSnapshotHash(other tenant) error = %v", err)
	}
	database.ExpectBegin()
	expectWriteMockWorkspace(database)
	database.ExpectQuery(`(?s)SELECT.*signal\.id::text.*FROM signals AS signal.*FOR UPDATE OF signal`).
		WithArgs(writeMockTenantID, writeMockWorkspaceID, writeMockSignalID).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "tenant_id", "workspace_id", "integration_id", "provider", "provider_event_id",
			"payload_hash", "fingerprint", "status", "labels", "observed_at",
		}).AddRow(
			writeMockSignalID, writeMockTenantID, writeMockWorkspaceID, writeMockServiceID,
			"alertmanager", "event-1", strings.Repeat("a", 64), "payments", "firing",
			[]byte(`{"service":"payments"}`), now,
		))
	database.ExpectRollback()
	_, err = repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
		WorkspaceID: writeMockWorkspaceID, SignalID: writeMockSignalID,
		ExpectedSignalHash: hashFromOtherTenant, CorrelationKey: "payments:staging:tenant-fenced",
		MappingStatus: domain.MappingUnresolved,
	})
	if !errors.Is(err, store.ErrScopeViolation) {
		t.Fatalf("CorrelateSignal(other tenant snapshot) error = %v, want ErrScopeViolation", err)
	}
	assertWriteMockExpectations(t, database)
}

func TestCreateInvestigationAtomicallyPersistsTasksTransitionAndLedger(t *testing.T) {
	authorizerCalls := 0
	database, repository := newWriteMockRepository(
		t,
		[]string{writeMockInvestigationID, writeMockTaskID},
		func(_ context.Context, scope investigation.TaskSpecScope, _ investigation.TaskSpec) error {
			authorizerCalls++
			if scope != (investigation.TaskSpecScope{
				TenantID: writeMockTenantID, WorkspaceID: writeMockWorkspaceID,
				EnvironmentID: writeMockEnvironmentID, ServiceID: writeMockServiceID,
				MappingStatus: domain.MappingExact,
			}) {
				return fmt.Errorf("unexpected trusted scope")
			}
			return nil
		},
	)
	now := time.Date(2026, 7, 12, 9, 0, 0, 456000, time.UTC)
	request := writeMockCreateRequest()
	canonical, taskHash, err := investigation.CanonicalTaskSpecs(request.Tasks)
	if err != nil {
		t.Fatalf("CanonicalTaskSpecs() error = %v", err)
	}
	requestHash, err := investigation.CreateOrGetInvestigationRequestHash(request, taskHash)
	if err != nil {
		t.Fatalf("CreateOrGetInvestigationRequestHash() error = %v", err)
	}

	// Pure durable replay probe. It deliberately closes before calling the
	// mutable authorizer.
	database.ExpectBegin()
	expectWriteMockWorkspace(database)
	expectWriteMockIdempotencyLock(database, request.IdempotencyKey)
	database.ExpectQuery("FROM investigation_idempotency_records").
		WithArgs(writeMockTenantID, writeMockWorkspaceID, request.IdempotencyKey).
		WillReturnRows(emptyWriteMockIdempotencyRows())
	database.ExpectRollback()

	// Authorized write transaction repeats the durable check under the same
	// advisory key, then locks the exact Incident before inserting facts.
	database.ExpectBegin()
	expectWriteMockWorkspace(database)
	expectWriteMockIdempotencyLock(database, request.IdempotencyKey)
	database.ExpectQuery("FROM investigation_idempotency_records").
		WithArgs(writeMockTenantID, writeMockWorkspaceID, request.IdempotencyKey).
		WillReturnRows(emptyWriteMockIdempotencyRows())
	database.ExpectQuery("FROM incidents AS incident").
		WithArgs(writeMockTenantID, writeMockWorkspaceID, writeMockIncidentID, runtimeSchemaVersion).
		WillReturnRows(writeMockIncidentRows(now))
	database.ExpectQuery("FROM investigations AS investigation").
		WithArgs(writeMockTenantID, writeMockWorkspaceID, writeMockIncidentID, runtimeSchemaVersion).
		WillReturnRows(emptyWriteMockInvestigationRows())
	database.ExpectQuery("INSERT INTO investigations AS investigation").
		WithArgs(
			writeMockInvestigationID, writeMockTenantID, writeMockWorkspaceID, writeMockIncidentID,
			request.IdempotencyKey, now, now, now, investigationTaskSchemaVersion,
			requestHash, requestVersionCreateInvestigation, writeMockServiceID, writeMockEnvironmentID,
			domain.MappingExact, runtimeSchemaVersion,
		).
		WillReturnRows(writeMockInvestigationRows(now, request.IdempotencyKey, requestHash))
	inputHash := writeMockSHA256(canonical[0].Input)
	database.ExpectQuery("INSERT INTO tool_invocations AS task").
		WithArgs(
			writeMockTaskID, writeMockTenantID, writeMockWorkspaceID, writeMockInvestigationID,
			canonical[0].ConnectorID, canonical[0].Operation, inputHash,
			writeMockIncidentID, canonical[0].Key, 1, []byte(canonical[0].Input), now, runtimeSchemaVersion,
		).
		WillReturnRows(writeMockTaskRows(now, canonical[0], inputHash))
	database.ExpectExec("UPDATE incidents AS incident").
		WithArgs(writeMockTenantID, writeMockWorkspaceID, writeMockIncidentID, now, runtimeSchemaVersion).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	database.ExpectExec("INSERT INTO investigation_idempotency_records").
		WithArgs(
			writeMockTenantID, writeMockWorkspaceID, request.IdempotencyKey,
			operationCreateInvestigation, requestHash, requestVersionCreateInvestigation,
			"INVESTIGATION", writeMockInvestigationID, nil, nil, nil,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	result, err := repository.CreateOrGetInvestigation(context.Background(), request)
	if err != nil || !result.Created || result.Investigation.ID != writeMockInvestigationID ||
		len(result.Tasks) != 1 || result.Tasks[0].ID != writeMockTaskID || authorizerCalls != 1 {
		t.Fatalf("CreateOrGetInvestigation() = %#v, %v; authorizer calls = %d", result, err, authorizerCalls)
	}
	assertWriteMockExpectations(t, database)
}

func TestCreateInvestigationDurableReplayBypassesMutableAuthorizer(t *testing.T) {
	authorizerCalls := 0
	database, repository := newWriteMockRepository(
		t,
		nil,
		func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error {
			authorizerCalls++
			return fmt.Errorf("revoked")
		},
	)
	now := time.Date(2026, 7, 12, 10, 0, 0, 789000, time.UTC)
	request := writeMockCreateRequest()
	canonical, taskHash, err := investigation.CanonicalTaskSpecs(request.Tasks)
	if err != nil {
		t.Fatalf("CanonicalTaskSpecs() error = %v", err)
	}
	requestHash, err := investigation.CreateOrGetInvestigationRequestHash(request, taskHash)
	if err != nil {
		t.Fatalf("CreateOrGetInvestigationRequestHash() error = %v", err)
	}
	database.ExpectBegin()
	expectWriteMockWorkspace(database)
	expectWriteMockIdempotencyLock(database, request.IdempotencyKey)
	database.ExpectQuery("FROM investigation_idempotency_records").
		WithArgs(writeMockTenantID, writeMockWorkspaceID, request.IdempotencyKey).
		WillReturnRows(emptyWriteMockIdempotencyRows().AddRow(
			operationCreateInvestigation, requestHash, requestVersionCreateInvestigation,
			"INVESTIGATION", writeMockInvestigationID, nil, nil, nil,
		))
	database.ExpectQuery("FROM tool_invocations AS task").
		WithArgs(writeMockTenantID, writeMockWorkspaceID, writeMockInvestigationID, runtimeSchemaVersion).
		WillReturnRows(writeMockTaskRows(now, canonical[0], writeMockSHA256(canonical[0].Input)))
	database.ExpectQuery("FROM investigations AS investigation").
		WithArgs(writeMockTenantID, writeMockWorkspaceID, writeMockInvestigationID, runtimeSchemaVersion).
		WillReturnRows(writeMockInvestigationRows(now, request.IdempotencyKey, requestHash))
	database.ExpectCommit()

	result, err := repository.CreateOrGetInvestigation(context.Background(), request)
	if err != nil || result.Created || result.Investigation.ID != writeMockInvestigationID || authorizerCalls != 0 {
		t.Fatalf("CreateOrGetInvestigation(replay) = %#v, %v; authorizer calls = %d", result, err, authorizerCalls)
	}
	assertWriteMockExpectations(t, database)
}

func TestCreateInvestigationRejectsWrongEnvironmentInsideLockedTransaction(t *testing.T) {
	authorizerCalls := 0
	database, repository := newWriteMockRepository(t, nil, func(_ context.Context, scope investigation.TaskSpecScope, _ investigation.TaskSpec) error {
		authorizerCalls++
		if scope != (investigation.TaskSpecScope{
			TenantID: writeMockTenantID, WorkspaceID: writeMockWorkspaceID,
			EnvironmentID: writeMockEnvironmentID, ServiceID: writeMockServiceID,
			MappingStatus: domain.MappingExact,
		}) {
			return fmt.Errorf("unexpected-scope-canary")
		}
		return fmt.Errorf("wrong-environment-canary")
	})
	now := time.Date(2026, 7, 12, 10, 10, 0, 0, time.UTC)
	request := writeMockCreateRequest()
	expectWriteMockCreateAdmission(database, request, writeMockIncidentRows(now))

	_, err := repository.CreateOrGetInvestigation(context.Background(), request)
	if !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("CreateOrGetInvestigation(wrong environment) error = %v, want ErrInvalidRequest", err)
	}
	if strings.Contains(fmt.Sprint(err), "canary") {
		t.Fatalf("CreateOrGetInvestigation(wrong environment) leaked authorizer detail: %v", err)
	}
	if authorizerCalls != 1 {
		t.Fatalf("authorizer calls = %d, want 1", authorizerCalls)
	}
	assertWriteMockExpectations(t, database)
}

func TestCreateInvestigationRejectsUnresolvedIncidentBeforeAuthorizerOrWrites(t *testing.T) {
	authorizerCalls := 0
	database, repository := newWriteMockRepository(t, nil, func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error {
		authorizerCalls++
		return nil
	})
	now := time.Date(2026, 7, 12, 10, 20, 0, 0, time.UTC)
	request := writeMockCreateRequest()
	expectWriteMockCreateAdmission(database, request, writeMockIncidentRowsForScope(now, nil, nil, domain.MappingUnresolved))

	_, err := repository.CreateOrGetInvestigation(context.Background(), request)
	if !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("CreateOrGetInvestigation(unresolved) error = %v, want ErrInvalidRequest", err)
	}
	if authorizerCalls != 0 {
		t.Fatalf("authorizer calls = %d, want 0 for unresolved scope", authorizerCalls)
	}
	assertWriteMockExpectations(t, database)
}

func TestCreateInvestigationRejectsNewFactsForTerminalIncidentInsideLock(t *testing.T) {
	for _, status := range []domain.IncidentStatus{domain.IncidentResolved, domain.IncidentClosed} {
		t.Run(string(status), func(t *testing.T) {
			authorizerCalls := 0
			database, repository := newWriteMockRepository(t, nil, func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error {
				authorizerCalls++
				return fmt.Errorf("terminal authorizer must not run")
			})
			now := time.Date(2026, 7, 12, 10, 30, 0, 0, time.UTC)
			request := writeMockCreateRequest()
			database.ExpectBegin()
			expectWriteMockWorkspace(database)
			expectWriteMockIdempotencyLock(database, request.IdempotencyKey)
			database.ExpectQuery("FROM investigation_idempotency_records").
				WithArgs(writeMockTenantID, writeMockWorkspaceID, request.IdempotencyKey).
				WillReturnRows(emptyWriteMockIdempotencyRows())
			database.ExpectRollback()

			database.ExpectBegin()
			expectWriteMockWorkspace(database)
			expectWriteMockIdempotencyLock(database, request.IdempotencyKey)
			database.ExpectQuery("FROM investigation_idempotency_records").
				WithArgs(writeMockTenantID, writeMockWorkspaceID, request.IdempotencyKey).
				WillReturnRows(emptyWriteMockIdempotencyRows())
			database.ExpectQuery("FROM incidents AS incident").
				WithArgs(writeMockTenantID, writeMockWorkspaceID, writeMockIncidentID, runtimeSchemaVersion).
				WillReturnRows(writeMockIncidentRowsWithStatus(now, status))
			database.ExpectQuery("FROM investigations AS investigation").
				WithArgs(writeMockTenantID, writeMockWorkspaceID, writeMockIncidentID, runtimeSchemaVersion).
				WillReturnRows(emptyWriteMockInvestigationRows())
			database.ExpectRollback()

			_, err := repository.CreateOrGetInvestigation(context.Background(), request)
			if !errors.Is(err, investigation.ErrInvalidTransition) {
				t.Fatalf("CreateOrGetInvestigation(%s) error = %v, want ErrInvalidTransition", status, err)
			}
			if authorizerCalls != 0 {
				t.Fatalf("terminal authorizer calls = %d, want 0", authorizerCalls)
			}
			assertWriteMockExpectations(t, database)
		})
	}
}

func expectWriteMockCreateAdmission(
	database pgxmock.PgxPoolIface,
	request investigation.CreateOrGetInvestigationRequest,
	incidentRows *pgxmock.Rows,
) {
	database.ExpectBegin()
	expectWriteMockWorkspace(database)
	expectWriteMockIdempotencyLock(database, request.IdempotencyKey)
	database.ExpectQuery("FROM investigation_idempotency_records").
		WithArgs(writeMockTenantID, writeMockWorkspaceID, request.IdempotencyKey).
		WillReturnRows(emptyWriteMockIdempotencyRows())
	database.ExpectRollback()

	database.ExpectBegin()
	expectWriteMockWorkspace(database)
	expectWriteMockIdempotencyLock(database, request.IdempotencyKey)
	database.ExpectQuery("FROM investigation_idempotency_records").
		WithArgs(writeMockTenantID, writeMockWorkspaceID, request.IdempotencyKey).
		WillReturnRows(emptyWriteMockIdempotencyRows())
	database.ExpectQuery("FROM incidents AS incident").
		WithArgs(writeMockTenantID, writeMockWorkspaceID, writeMockIncidentID, runtimeSchemaVersion).
		WillReturnRows(incidentRows)
	database.ExpectQuery("FROM investigations AS investigation").
		WithArgs(writeMockTenantID, writeMockWorkspaceID, writeMockIncidentID, runtimeSchemaVersion).
		WillReturnRows(emptyWriteMockInvestigationRows())
	database.ExpectRollback()
}

func newWriteMockRepository(
	t *testing.T,
	generatedIDs []string,
	authorizer investigation.TaskSpecAuthorizer,
) (pgxmock.PgxPoolIface, *Repository) {
	t.Helper()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("create pgx mock: %v", err)
	}
	t.Cleanup(database.Close)
	if authorizer == nil {
		authorizer = func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error { return nil }
	}
	nextID := 0
	repository, err := New(database, Options{
		IDFactory: func() string {
			if nextID >= len(generatedIDs) {
				return writeMockOutboxID
			}
			id := generatedIDs[nextID]
			nextID++
			return id
		},
		TaskSpecAuthorizer: authorizer,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return database, repository
}

func expectWriteMockWorkspace(database pgxmock.PgxPoolIface) {
	database.ExpectQuery("FROM workspaces").
		WithArgs(writeMockWorkspaceID).
		WillReturnRows(pgxmock.NewRows([]string{"tenant_id"}).AddRow(writeMockTenantID))
}

func expectWriteMockIdempotencyLock(database pgxmock.PgxPoolIface, idempotencyKey string) {
	database.ExpectExec("pg_catalog.pg_advisory_xact_lock").
		WithArgs(writeMockTenantID, writeMockWorkspaceID, idempotencyKey).
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
}

func emptyWriteMockCorrelationRows() *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"incident_id", "correlation_key", "mapping_status", "service_id", "environment_id",
	})
}

func emptyWriteMockIncidentRows() *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"id", "tenant_id", "workspace_id", "service_id", "environment_id", "correlation_key",
		"mapping_status", "severity", "title", "status", "confirmed_hypothesis_id",
		"opened_at", "last_signal_at", "updated_at", "signal_count", "version",
	})
}

func writeMockIncidentRows(now time.Time) *pgxmock.Rows {
	return writeMockIncidentRowsForScope(now, writeMockServiceID, writeMockEnvironmentID, domain.MappingExact)
}

func writeMockIncidentRowsWithStatus(now time.Time, status domain.IncidentStatus) *pgxmock.Rows {
	return emptyWriteMockIncidentRows().AddRow(
		writeMockIncidentID, writeMockTenantID, writeMockWorkspaceID,
		writeMockServiceID, writeMockEnvironmentID, "payments:staging:latency",
		domain.MappingExact, "UNKNOWN", "Unclassified operational incident", status,
		nil, now, now, now, 1, int64(2),
	)
}

func writeMockIncidentRowsForScope(now time.Time, serviceID, environmentID any, mappingStatus domain.MappingStatus) *pgxmock.Rows {
	return emptyWriteMockIncidentRows().AddRow(
		writeMockIncidentID, writeMockTenantID, writeMockWorkspaceID,
		serviceID, environmentID, "payments:staging:latency",
		mappingStatus, "UNKNOWN", "Unclassified operational incident", domain.IncidentOpen,
		nil, now, now, now, 1, int64(1),
	)
}

func emptyWriteMockIdempotencyRows() *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"operation", "request_hash", "request_hash_version", "resource_type", "resource_id",
		"result_snapshot", "result_snapshot_sha256", "result_snapshot_version",
	})
}

func emptyWriteMockInvestigationRows() *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"id", "tenant_id", "workspace_id", "incident_id", "status", "model_status",
		"idempotency_key", "request_hash", "failure_code", "model_failure_code",
		"created_at", "started_at", "completed_at", "updated_at",
	})
}

func writeMockInvestigationRows(now time.Time, idempotencyKey, requestHash string) *pgxmock.Rows {
	return emptyWriteMockInvestigationRows().AddRow(
		writeMockInvestigationID, writeMockTenantID, writeMockWorkspaceID, writeMockIncidentID,
		domain.InvestigationQueued, domain.ModelPending, idempotencyKey, requestHash,
		"", "", now, nil, nil, now,
	)
}

func writeMockTaskRows(now time.Time, spec investigation.TaskSpec, inputHash string) *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"id", "tenant_id", "workspace_id", "incident_id", "investigation_id", "task_key", "position",
		"tool_name", "tool_version", "input_document", "input_hash", "status", "evidence_id",
		"failure_code", "created_at", "started_at", "completed_at", "updated_at",
	}).AddRow(
		writeMockTaskID, writeMockTenantID, writeMockWorkspaceID, writeMockIncidentID,
		writeMockInvestigationID, spec.Key, 1, spec.ConnectorID, spec.Operation,
		[]byte(spec.Input), inputHash, domain.ReadTaskQueued, nil, "", now, nil, nil, now,
	)
}

func writeMockCreateRequest() investigation.CreateOrGetInvestigationRequest {
	return investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: writeMockWorkspaceID, IncidentID: writeMockIncidentID,
		IdempotencyKey: "investigate:write-mock",
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-staging", Operation: "range_query",
			Input: []byte(`{"lookback_minutes":15}`),
		}},
	}
}

func writeMockSHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return fmt.Sprintf("%x", digest[:])
}

func assertWriteMockExpectations(t *testing.T, database pgxmock.PgxPoolIface) {
	t.Helper()
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet PostgreSQL expectations: %v", err)
	}
}
