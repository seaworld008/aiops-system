package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

const coreFeedbackID = "d0000000-0000-4000-8000-00000000000d"

func TestRecordFeedbackRejectsUntrustedIdentityBeforeDatabaseAccess(t *testing.T) {
	database, repository := newCoreMockRepository(t, func() string { return coreFeedbackID })
	_, err := repository.RecordFeedback(context.Background(), investigation.RecordFeedbackRequest{
		WorkspaceID: coreWorkspaceID, IncidentID: coreIncidentID,
		InvestigationID: coreInvestigationID, HypothesisID: coreHypothesisID,
		Actor:   domain.Actor{Type: domain.ActorModel, ID: "model-1"},
		Verdict: domain.FeedbackRejected, Details: []byte(`{"reason_code":"unsafe_actor"}`),
		IdempotencyKey: "feedback:reject",
	})
	if !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("RecordFeedback(untrusted actor) error = %v, want ErrInvalidRequest", err)
	}
	assertCoreExpectations(t, database)
}

func TestRecordFeedbackRejectsProposedHypothesisAtomically(t *testing.T) {
	now := time.Date(2026, 7, 12, 16, 0, 0, 123456000, time.UTC)
	database, repository := newCoreMockRepository(t, func() string { return coreFeedbackID })

	database.ExpectBegin()
	expectCoreWorkspaceLock(database)
	database.ExpectExec("pg_advisory_xact_lock").
		WithArgs(coreTenantID, coreWorkspaceID, "feedback:reject").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	database.ExpectQuery("FROM investigation_idempotency_records").
		WithArgs(coreTenantID, coreWorkspaceID, "feedback:reject").
		WillReturnRows(emptyCoreIdempotencyRows())
	database.ExpectQuery("FROM incidents AS incident").
		WithArgs(coreTenantID, coreWorkspaceID, coreIncidentID, runtimeSchemaVersion).
		WillReturnRows(coreIncidentRows(coreIncidentID, now))
	database.ExpectQuery("FROM investigations AS investigation").
		WithArgs(coreTenantID, coreWorkspaceID, coreIncidentID, coreInvestigationID, runtimeSchemaVersion).
		WillReturnRows(coreCompletedInvestigationRows(now))
	database.ExpectQuery("FROM hypotheses AS hypothesis").
		WithArgs(coreTenantID, coreWorkspaceID, coreIncidentID, coreInvestigationID, coreHypothesisID, runtimeSchemaVersion).
		WillReturnRows(coreHypothesisRows(coreHypothesisID, 1, 0.9, now))
	database.ExpectQuery("SELECT clock_timestamp").
		WithArgs(coreTenantID, coreWorkspaceID).
		WillReturnRows(pgxmock.NewRows([]string{"clock_timestamp"}).AddRow(now.Add(time.Minute)))
	database.ExpectExec("UPDATE hypotheses AS hypothesis").
		WithArgs(
			coreTenantID, coreWorkspaceID, coreIncidentID, coreInvestigationID,
			coreHypothesisID, domain.HypothesisRejected, runtimeSchemaVersion,
		).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	database.ExpectExec("INSERT INTO feedback").
		WithArgs(
			coreFeedbackID, coreTenantID, coreWorkspaceID, coreInvestigationID, coreHypothesisID,
			"user-1", domain.FeedbackRejected, now.Add(time.Minute), coreIncidentID, domain.ActorHuman,
			[]byte(`{"reason_code":"not_supported"}`),
			snapshotSHA256Hex([]byte(`{"reason_code":"not_supported"}`)), runtimeSchemaVersion,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO investigation_idempotency_records").
		WithArgs(
			coreTenantID, coreWorkspaceID, "feedback:reject", operationRecordFeedback,
			pgxmock.AnyArg(), requestVersionRecordFeedback, "FEEDBACK", coreFeedbackID,
			nil, nil, nil,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	result, err := repository.RecordFeedback(context.Background(), investigation.RecordFeedbackRequest{
		WorkspaceID: coreWorkspaceID, IncidentID: coreIncidentID,
		InvestigationID: coreInvestigationID, HypothesisID: coreHypothesisID,
		Actor:   domain.Actor{Type: domain.ActorHuman, ID: "user-1"},
		Verdict: domain.FeedbackRejected, Details: []byte(` { "reason_code" : "not_supported" } `),
		IdempotencyKey: "feedback:reject",
	})
	if err != nil {
		if expectationsErr := database.ExpectationsWereMet(); expectationsErr != nil {
			t.Fatalf("RecordFeedback() error = %v; expectations = %v", err, expectationsErr)
		}
	}
	if err != nil || !result.Created || result.Feedback.ID != coreFeedbackID ||
		result.Feedback.Verdict != domain.FeedbackRejected ||
		string(result.Feedback.Details) != `{"reason_code":"not_supported"}` {
		t.Fatalf("RecordFeedback() = %#v, %v", result, err)
	}
	assertCoreExpectations(t, database)
}

func emptyCoreIdempotencyRows() *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"operation", "request_hash", "request_hash_version", "resource_type", "resource_id",
		"result_snapshot", "result_snapshot_sha256", "result_snapshot_version",
	})
}

func coreCompletedInvestigationRows(now time.Time) *pgxmock.Rows {
	createdAt := now.Add(-2 * time.Hour)
	startedAt := now.Add(-time.Hour)
	return pgxmock.NewRows([]string{
		"id", "tenant_id", "workspace_id", "incident_id", "status", "model_status", "idempotency_key", "request_hash",
		"request_hash_version", "plan_schema_version", "plan_manifest_digest", "plan_registry_digest", "plan_profile_digest", "plan_tasks_hash",
		"failure_code", "model_failure_code", "created_at", "started_at", "completed_at", "updated_at",
	}).AddRow(
		coreInvestigationID, coreTenantID, coreWorkspaceID, coreIncidentID,
		domain.InvestigationCompleted, domain.ModelCompleted, "investigate:payments", coreHash('d'),
		domain.InvestigationCreateRequestVersionV1, nil, nil, nil, nil, nil,
		"", "", createdAt, startedAt, now, now,
	)
}
