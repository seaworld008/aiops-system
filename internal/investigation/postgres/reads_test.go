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
)

const (
	coreIncidentID      = "60000000-0000-4000-8000-000000000006"
	coreServiceID       = "70000000-0000-4000-8000-000000000007"
	coreEnvironmentID   = "80000000-0000-4000-8000-000000000008"
	coreInvestigationID = "90000000-0000-4000-8000-000000000009"
	coreTaskID          = "a0000000-0000-4000-8000-00000000000a"
	coreEvidenceID      = "b0000000-0000-4000-8000-00000000000b"
	coreHypothesisID    = "c0000000-0000-4000-8000-00000000000c"
)

func TestGetOperationsStrictlyScanEveryRuntimeResource(t *testing.T) {
	now := time.Date(2026, 7, 12, 13, 0, 0, 123456000, time.UTC)
	t.Run("incident", func(t *testing.T) {
		directRows := coreIncidentRows(coreIncidentID, now).Kind()
		if !directRows.Next() {
			t.Fatal("direct incident row is empty")
		}
		if _, directErr := scanIncident(directRows); directErr != nil {
			t.Fatalf("scanIncident(direct) error = %#v", directErr)
		}
		database, repository := newCoreMockRepository(t, func() string { return coreOutboxID })
		database.ExpectBegin()
		expectCoreWorkspaceLock(database)
		database.ExpectQuery("FROM incidents AS incident").
			WithArgs(coreTenantID, coreWorkspaceID, coreIncidentID, runtimeSchemaVersion).
			WillReturnRows(coreIncidentRows(coreIncidentID, now))
		database.ExpectCommit()
		item, err := repository.GetIncident(context.Background(), coreWorkspaceID, coreIncidentID)
		if err != nil || item.ID != coreIncidentID || item.TenantID != coreTenantID || item.SignalCount != 1 {
			t.Fatalf("GetIncident() = %#v, %v", item, err)
		}
		assertCoreExpectations(t, database)
	})

	t.Run("investigation", func(t *testing.T) {
		database, repository := newCoreMockRepository(t, func() string { return coreOutboxID })
		database.ExpectBegin()
		expectCoreWorkspaceLock(database)
		database.ExpectQuery("FROM investigations AS investigation").
			WithArgs(coreTenantID, coreWorkspaceID, coreInvestigationID, runtimeSchemaVersion).
			WillReturnRows(coreInvestigationRows(coreInvestigationID, now))
		database.ExpectCommit()
		item, err := repository.GetInvestigation(context.Background(), coreWorkspaceID, coreInvestigationID)
		if err != nil || item.ID != coreInvestigationID || item.Status != domain.InvestigationQueued {
			t.Fatalf("GetInvestigation() = %#v, %v", item, err)
		}
		assertCoreExpectations(t, database)
	})

	t.Run("task", func(t *testing.T) {
		database, repository := newCoreMockRepository(t, func() string { return coreOutboxID })
		database.ExpectBegin()
		expectCoreWorkspaceLock(database)
		database.ExpectQuery("FROM tool_invocations AS task").
			WithArgs(coreTenantID, coreWorkspaceID, coreTaskID, runtimeSchemaVersion).
			WillReturnRows(coreTaskRows(coreTaskID, 1, now))
		database.ExpectCommit()
		item, err := repository.GetTask(context.Background(), coreWorkspaceID, coreTaskID)
		if err != nil || item.ID != coreTaskID || item.Position != 1 || string(item.Input) != `{"lookback_minutes":15}` {
			t.Fatalf("GetTask() = %#v, %v", item, err)
		}
		assertCoreExpectations(t, database)
	})

	t.Run("evidence", func(t *testing.T) {
		database, repository := newCoreMockRepository(t, func() string { return coreOutboxID })
		database.ExpectBegin()
		expectCoreWorkspaceLock(database)
		database.ExpectQuery("FROM evidence AS evidence_fact").
			WithArgs(coreTenantID, coreWorkspaceID, coreEvidenceID, runtimeSchemaVersion).
			WillReturnRows(coreEvidenceRows(coreEvidenceID, now))
		database.ExpectCommit()
		item, err := repository.GetEvidence(context.Background(), coreWorkspaceID, coreEvidenceID)
		if err != nil || item.ID != coreEvidenceID || item.Attributes["source"] != "prometheus" {
			t.Fatalf("GetEvidence() = %#v, %v", item, err)
		}
		item.Attributes["source"] = "mutated"
		item.Payload[0] = '['
		assertCoreExpectations(t, database)
	})

	t.Run("hypothesis", func(t *testing.T) {
		database, repository := newCoreMockRepository(t, func() string { return coreOutboxID })
		database.ExpectBegin()
		expectCoreWorkspaceLock(database)
		database.ExpectQuery("FROM hypotheses AS hypothesis").
			WithArgs(coreTenantID, coreWorkspaceID, coreHypothesisID, runtimeSchemaVersion).
			WillReturnRows(coreHypothesisRows(coreHypothesisID, 1, 0.9, now))
		database.ExpectCommit()
		item, err := repository.GetHypothesis(context.Background(), coreWorkspaceID, coreHypothesisID)
		if err != nil || item.ID != coreHypothesisID || len(item.EvidenceIDs) != 1 || item.EvidenceIDs[0] != coreEvidenceID {
			t.Fatalf("GetHypothesis() = %#v, %v", item, err)
		}
		item.Unknowns[0] = "mutated"
		item.EvidenceIDs[0] = coreTaskID
		assertCoreExpectations(t, database)
	})
}

func TestListTasksAndHypothesesApplyStableDomainOrdering(t *testing.T) {
	now := time.Date(2026, 7, 12, 14, 0, 0, 0, time.UTC)
	secondTaskID := "a1000000-0000-4000-8000-00000000000a"
	t.Run("tasks", func(t *testing.T) {
		database, repository := newCoreMockRepository(t, func() string { return coreOutboxID })
		database.ExpectBegin()
		expectCoreWorkspaceLock(database)
		database.ExpectQuery("SELECT EXISTS").
			WithArgs(coreTenantID, coreWorkspaceID, coreInvestigationID, runtimeSchemaVersion).
			WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
		rows := emptyCoreTaskRows()
		addCoreTaskRow(rows, secondTaskID, 2, now)
		addCoreTaskRow(rows, coreTaskID, 1, now)
		database.ExpectQuery("FROM tool_invocations AS task").
			WithArgs(coreTenantID, coreWorkspaceID, coreInvestigationID, runtimeSchemaVersion).
			WillReturnRows(rows)
		database.ExpectCommit()
		items, err := repository.ListTasks(context.Background(), investigation.ListTasksRequest{
			WorkspaceID: coreWorkspaceID, InvestigationID: coreInvestigationID,
		})
		if err != nil || len(items) != 2 || items[0].ID != coreTaskID || items[1].ID != secondTaskID {
			t.Fatalf("ListTasks() = %#v, %v", items, err)
		}
		assertCoreExpectations(t, database)
	})

	secondHypothesisID := "c1000000-0000-4000-8000-00000000000c"
	t.Run("hypotheses", func(t *testing.T) {
		database, repository := newCoreMockRepository(t, func() string { return coreOutboxID })
		database.ExpectBegin()
		expectCoreWorkspaceLock(database)
		database.ExpectQuery("SELECT EXISTS").
			WithArgs(coreTenantID, coreWorkspaceID, coreInvestigationID, runtimeSchemaVersion).
			WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
		rows := emptyCoreHypothesisRows()
		addCoreHypothesisRow(rows, secondHypothesisID, 2, 0.6, now)
		addCoreHypothesisRow(rows, coreHypothesisID, 1, 0.9, now)
		database.ExpectQuery("FROM hypotheses AS hypothesis").
			WithArgs(coreTenantID, coreWorkspaceID, coreInvestigationID, runtimeSchemaVersion).
			WillReturnRows(rows)
		database.ExpectCommit()
		items, err := repository.ListHypotheses(context.Background(), investigation.ListHypothesesRequest{
			WorkspaceID: coreWorkspaceID, InvestigationID: coreInvestigationID,
		})
		if err != nil || len(items) != 2 || items[0].ID != coreHypothesisID || items[1].ID != secondHypothesisID {
			t.Fatalf("ListHypotheses() = %#v, %v", items, err)
		}
		assertCoreExpectations(t, database)
	})
}

func TestReadRejectsInvalidPersistedRuntimeRowWithoutLeakingDetails(t *testing.T) {
	database, repository := newCoreMockRepository(t, func() string { return coreOutboxID })
	now := time.Date(2026, 7, 12, 15, 0, 0, 0, time.UTC)
	database.ExpectBegin()
	expectCoreWorkspaceLock(database)
	rows := coreIncidentRows(coreIncidentID, now)
	// A second malformed row shape is easier to express with the same columns.
	rows = emptyCoreIncidentRows().AddRow(
		"NOT-A-UUID", coreTenantID, coreWorkspaceID, coreServiceID, coreEnvironmentID,
		"payments:prod", domain.MappingExact, "UNKNOWN", "Operational incident", domain.IncidentOpen,
		nil, now, now, now, 1, int64(1),
	)
	database.ExpectQuery("FROM incidents AS incident").
		WithArgs(coreTenantID, coreWorkspaceID, coreIncidentID, runtimeSchemaVersion).
		WillReturnRows(rows)
	database.ExpectRollback()

	_, err := repository.GetIncident(context.Background(), coreWorkspaceID, coreIncidentID)
	if err == nil || !containsDatabaseSentinel(err) {
		t.Fatalf("GetIncident(corrupt row) error = %v; want redacted database sentinel", err)
	}
	assertCoreExpectations(t, database)
}

func coreIncidentRows(incidentID string, now time.Time) *pgxmock.Rows {
	return emptyCoreIncidentRows().AddRow(
		incidentID, coreTenantID, coreWorkspaceID, coreServiceID, coreEnvironmentID,
		"payments:prod", domain.MappingExact, "UNKNOWN", "Operational incident", domain.IncidentOpen,
		nil, now, now, now, 1, int64(1),
	)
}

func emptyCoreIncidentRows() *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"id", "tenant_id", "workspace_id", "service_id", "environment_id", "correlation_key", "mapping_status",
		"severity", "title", "status", "confirmed_hypothesis_id", "opened_at", "last_signal_at", "updated_at", "signal_count", "version",
	})
}

func coreInvestigationRows(investigationID string, now time.Time) *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"id", "tenant_id", "workspace_id", "incident_id", "status", "model_status", "idempotency_key", "request_hash",
		"failure_code", "model_failure_code", "created_at", "started_at", "completed_at", "updated_at",
	}).AddRow(
		investigationID, coreTenantID, coreWorkspaceID, coreIncidentID,
		domain.InvestigationQueued, domain.ModelPending, "investigate:payments", coreHash('d'),
		"", "", now, nil, nil, now,
	)
}

func coreTaskRows(taskID string, position int, now time.Time) *pgxmock.Rows {
	rows := emptyCoreTaskRows()
	addCoreTaskRow(rows, taskID, position, now)
	return rows
}

func emptyCoreTaskRows() *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"id", "tenant_id", "workspace_id", "incident_id", "investigation_id", "task_key", "position",
		"tool_name", "tool_version", "input_document", "input_hash", "status", "evidence_id", "failure_code",
		"created_at", "started_at", "completed_at", "updated_at",
	})
}

func addCoreTaskRow(rows *pgxmock.Rows, taskID string, position int, now time.Time) {
	input := []byte(`{"lookback_minutes":15}`)
	digest := sha256.Sum256(input)
	rows.AddRow(
		taskID, coreTenantID, coreWorkspaceID, coreIncidentID, coreInvestigationID,
		fmt.Sprintf("metrics-%d", position), position, "prometheus-prod", "range_query",
		input, fmt.Sprintf("%x", digest[:]), domain.ReadTaskQueued, nil, "", now, nil, nil, now,
	)
}

func coreEvidenceRows(evidenceID string, now time.Time) *pgxmock.Rows {
	payload := []byte(`{"result":"healthy"}`)
	digest := sha256.Sum256(payload)
	return pgxmock.NewRows([]string{
		"id", "tenant_id", "workspace_id", "incident_id", "investigation_id", "task_id",
		"connector", "content_hash", "payload_document", "attributes", "collected_at", "created_at",
	}).AddRow(
		evidenceID, coreTenantID, coreWorkspaceID, coreIncidentID, coreInvestigationID, coreTaskID,
		"prometheus-prod", fmt.Sprintf("%x", digest[:]), payload, []byte(`{"source":"prometheus"}`), now, now,
	)
}

func coreHypothesisRows(hypothesisID string, rank int, confidence float64, now time.Time) *pgxmock.Rows {
	rows := emptyCoreHypothesisRows()
	addCoreHypothesisRow(rows, hypothesisID, rank, confidence, now)
	return rows
}

func emptyCoreHypothesisRows() *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"id", "tenant_id", "workspace_id", "incident_id", "investigation_id", "status", "rank", "confidence",
		"confidence_band", "summary", "proposal_document", "proposal_hash", "unknowns", "evidence_ids", "created_at",
	})
}

func addCoreHypothesisRow(rows *pgxmock.Rows, hypothesisID string, rank int, confidence float64, now time.Time) {
	proposal := []byte(`{"cause":"saturation"}`)
	digest := sha256.Sum256(proposal)
	rows.AddRow(
		hypothesisID, coreTenantID, coreWorkspaceID, coreIncidentID, coreInvestigationID,
		domain.HypothesisProposed, rank, confidence, expectedConfidenceBand(confidence), "Capacity saturation",
		proposal, fmt.Sprintf("%x", digest[:]), []string{"confirm upstream rate"}, []string{coreEvidenceID}, now,
	)
}

func coreHash(character byte) string {
	return strings.Repeat(string(character), 64)
}

func assertCoreExpectations(t *testing.T, database pgxmock.PgxPoolIface) {
	t.Helper()
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func containsDatabaseSentinel(err error) bool {
	return errors.Is(err, errDatabaseOperation)
}
