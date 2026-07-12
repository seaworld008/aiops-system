package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	investigationpostgres "github.com/seaworld008/aiops-system/internal/investigation/postgres"
	"github.com/seaworld008/aiops-system/internal/store"
)

const testFeedbackID = "80000000-0000-4000-8000-000000000001"

func TestInvestigationLifecycleUpdateDoesNotReverseLockIncident(t *testing.T) {
	fixture := newRuntimeFixture(t)
	ctx := context.Background()

	incidentTx, err := fixture.harness.db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin incident lock transaction: %v", err)
	}
	defer func() { _ = incidentTx.Rollback(ctx) }()
	if _, err := incidentTx.Exec(ctx, `
		SELECT 1 FROM incidents WHERE id = $1 FOR NO KEY UPDATE
	`, testIncidentID); err != nil {
		t.Fatalf("lock incident: %v", err)
	}

	lifecycleTx, err := fixture.harness.db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lifecycle transaction: %v", err)
	}
	defer func() { _ = lifecycleTx.Rollback(ctx) }()
	if _, err := lifecycleTx.Exec(ctx, `
		SELECT 1 FROM tool_invocations WHERE id = $1 FOR NO KEY UPDATE
	`, testTaskID); err != nil {
		t.Fatalf("lock lifecycle task: %v", err)
	}
	if _, err := lifecycleTx.Exec(ctx, `SET LOCAL lock_timeout = '250ms'`); err != nil {
		t.Fatalf("bound lifecycle lock acquisition: %v", err)
	}
	transitionAt := fixture.base.Add(10 * time.Second)
	if _, err := lifecycleTx.Exec(ctx, `
		UPDATE investigations
		SET status = 'RUNNING', started_at = $2, updated_at = $2
		WHERE id = $1
	`, testInvestigationID, transitionAt); err != nil {
		t.Fatalf("lifecycle update waited on the already locked Incident: %v", err)
	}
}

func TestPostgresRepositoryLifecyclePersistsImmutableReplayAndHumanFeedback(t *testing.T) {
	fixture := newRuntimeFixture(t)
	ctx := context.Background()
	payload := []byte(`{"series_count":3}`)
	taskCompletedAt := fixture.base.Add(10 * time.Second)

	tx, err := fixture.harness.db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin task completion fixture: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, `
		INSERT INTO evidence (
			id, tenant_id, workspace_id, investigation_id, connector, query_summary,
			collected_at, redacted_summary, content_hash, trust_level, truncated, created_at,
			incident_id, task_id, payload_document, attributes, runtime_schema_version
		) VALUES (
			$1, $2, $3, $4, 'prometheus-staging', '{}', $5, $6::jsonb, $7,
			'AUTHENTICATED_READ_RUNNER', false, $8, $9, $10, $11, $12::jsonb,
			'investigation-runtime.v1'
		)
	`, testEvidenceID, testTenantID, testWorkspaceID, testInvestigationID,
		fixture.base.Add(9*time.Second), string(payload), sha256Hex(payload), taskCompletedAt,
		testIncidentID, testTaskID, payload, `{"source":"prometheus"}`); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("insert task evidence fixture: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE tool_invocations
		SET status = 'EVIDENCE', evidence_id = $2, output_hash = $3,
		    started_at = $4, completed_at = $4, updated_at = $4
		WHERE id = $1
	`, testTaskID, testEvidenceID, sha256Hex(payload), taskCompletedAt); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("complete task fixture: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE investigations
		SET status = 'RUNNING', started_at = $2, updated_at = $2
		WHERE id = $1
	`, testInvestigationID, taskCompletedAt); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("start investigation fixture: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit task completion fixture: %v", err)
	}
	committed = true

	generatedIDs := []string{testHypothesisID, testFeedbackID}
	generatedIndex := 0
	repository, err := investigationpostgres.New(fixture.harness.extendedPool(t), investigationpostgres.Options{
		IDFactory: func() string {
			if generatedIndex >= len(generatedIDs) {
				t.Fatalf("unexpected persistent ID request %d", generatedIndex+1)
			}
			id := generatedIDs[generatedIndex]
			generatedIndex++
			return id
		},
		TaskSpecAuthorizer: func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error { return nil },
	})
	if err != nil {
		t.Fatalf("construct PostgreSQL repository: %v", err)
	}

	startRequest := investigation.StartModelRequest{
		WorkspaceID: testWorkspaceID, InvestigationID: testInvestigationID,
		IdempotencyKey: "model:start:postgres",
	}
	started, err := repository.StartModel(ctx, startRequest)
	if err != nil || started.Replayed || started.Investigation.ModelStatus != domain.ModelRunning {
		t.Fatalf("StartModel(first) = %#v, %v", started, err)
	}
	startReplay, err := repository.StartModel(ctx, startRequest)
	if err != nil || !startReplay.Replayed || startReplay.Investigation != started.Investigation {
		t.Fatalf("StartModel(replay) = %#v, %v", startReplay, err)
	}

	proposal := []byte(` { "cause": "pool_saturation" } `)
	finalizeRequest := investigation.FinalizeInvestigationRequest{
		WorkspaceID: testWorkspaceID, InvestigationID: testInvestigationID,
		IdempotencyKey: "finalize:postgres", Status: domain.InvestigationCompleted,
		ModelStatus: domain.ModelCompleted,
		Hypotheses: []investigation.HypothesisSpec{{
			Rank: 1, Confidence: 0.91, Summary: "Connection pool saturation",
			Proposal: proposal, ProposalHash: sha256Hex(proposal), EvidenceIDs: []string{testEvidenceID},
		}},
	}
	finalized, err := repository.FinalizeInvestigation(ctx, finalizeRequest)
	if err != nil || finalized.Replayed || finalized.Investigation.Status != domain.InvestigationCompleted ||
		len(finalized.Hypotheses) != 1 || finalized.Hypotheses[0].ID != testHypothesisID {
		t.Fatalf("FinalizeInvestigation(first) = %#v, %v", finalized, err)
	}
	if string(finalized.Hypotheses[0].Proposal) != string(proposal) ||
		finalized.Hypotheses[0].Status != domain.HypothesisProposed {
		t.Fatalf("FinalizeInvestigation(first) lost immutable proposal: %#v", finalized.Hypotheses[0])
	}

	feedbackRequest := investigation.RecordFeedbackRequest{
		WorkspaceID: testWorkspaceID, IncidentID: testIncidentID,
		InvestigationID: testInvestigationID, HypothesisID: testHypothesisID,
		Actor:   domain.Actor{Type: domain.ActorHuman, ID: "platform-admin@example.com"},
		Verdict: domain.FeedbackConfirmed, Details: []byte(` { "reason_code" : "evidence_matches" } `),
		IdempotencyKey: "feedback:postgres",
	}
	feedback, err := repository.RecordFeedback(ctx, feedbackRequest)
	if err != nil || !feedback.Created || feedback.Feedback.ID != testFeedbackID ||
		string(feedback.Feedback.Details) != `{"reason_code":"evidence_matches"}` {
		t.Fatalf("RecordFeedback(first) = %#v, %v", feedback, err)
	}
	feedbackReplay, err := repository.RecordFeedback(ctx, feedbackRequest)
	if err != nil || feedbackReplay.Created || feedbackReplay.Feedback.ID != feedback.Feedback.ID {
		t.Fatalf("RecordFeedback(replay) = %#v, %v", feedbackReplay, err)
	}
	conflict := feedbackRequest
	conflict.Details = []byte(`{"reason_code":"different"}`)
	if _, err := repository.RecordFeedback(ctx, conflict); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("RecordFeedback(conflict) error = %v, want ErrIdempotencyConflict", err)
	}

	incident, err := repository.GetIncident(ctx, testWorkspaceID, testIncidentID)
	if err != nil || incident.ConfirmedHypothesisID != testHypothesisID {
		t.Fatalf("GetIncident(after feedback) = %#v, %v", incident, err)
	}
	hypothesis, err := repository.GetHypothesis(ctx, testWorkspaceID, testHypothesisID)
	if err != nil || hypothesis.Status != domain.HypothesisConfirmed {
		t.Fatalf("GetHypothesis(after feedback) = %#v, %v", hypothesis, err)
	}
	finalizeReplay, err := repository.FinalizeInvestigation(ctx, finalizeRequest)
	if err != nil || !finalizeReplay.Replayed || len(finalizeReplay.Hypotheses) != 1 ||
		finalizeReplay.Hypotheses[0].Status != domain.HypothesisProposed ||
		string(finalizeReplay.Hypotheses[0].Proposal) != string(proposal) {
		t.Fatalf("FinalizeInvestigation(replay after feedback) = %#v, %v", finalizeReplay, err)
	}
	terminalStartReplay, err := repository.StartModel(ctx, startRequest)
	if err != nil || !terminalStartReplay.Replayed ||
		terminalStartReplay.Investigation.Status != domain.InvestigationRunning ||
		terminalStartReplay.Investigation.ModelStatus != domain.ModelRunning {
		t.Fatalf("StartModel(replay after terminal feedback) = %#v, %v", terminalStartReplay, err)
	}
	if generatedIndex != len(generatedIDs) {
		t.Fatalf("persistent ID factory calls = %d, want %d", generatedIndex, len(generatedIDs))
	}
}
