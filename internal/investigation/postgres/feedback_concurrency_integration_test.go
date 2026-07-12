package postgres_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	investigationpostgres "github.com/seaworld008/aiops-system/internal/investigation/postgres"
)

func TestPostgresConcurrentHumanConfirmCommitsOneRootCause(t *testing.T) {
	fixture := newLatestRuntimeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	prepareEvidenceTaskForFeedbackConcurrency(t, ctx, fixture)

	generatedIDs := []string{
		testHypothesisID,
		"70000000-0000-4000-8000-000000000002",
		testFeedbackID,
	}
	var generated atomic.Uint32
	repository, err := investigationpostgres.New(fixture.harness.extendedPool(t), investigationpostgres.Options{
		TaskRuntimeBinder: testTaskRuntimeBinder,
		IDFactory: func() string {
			index := int(generated.Add(1)) - 1
			if index >= len(generatedIDs) {
				return "unexpected-id-factory-call"
			}
			return generatedIDs[index]
		},
		TaskSpecAuthorizer: func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error { return nil },
	})
	if err != nil {
		t.Fatalf("construct feedback concurrency repository: %v", err)
	}
	if _, err := repository.StartModel(ctx, investigation.StartModelRequest{
		WorkspaceID: testWorkspaceID, InvestigationID: testInvestigationID,
		IdempotencyKey: "model:start:feedback-concurrency",
	}); err != nil {
		t.Fatalf("StartModel(feedback concurrency) error = %v", err)
	}
	proposalOne := []byte(`{"cause":"pool_saturation"}`)
	proposalTwo := []byte(`{"cause":"upstream_throttle"}`)
	finalized, err := repository.FinalizeInvestigation(ctx, investigation.FinalizeInvestigationRequest{
		WorkspaceID: testWorkspaceID, InvestigationID: testInvestigationID,
		IdempotencyKey: "finalize:feedback-concurrency",
		Status:         domain.InvestigationCompleted, ModelStatus: domain.ModelCompleted,
		Hypotheses: []investigation.HypothesisSpec{
			{
				Rank: 1, Confidence: 0.9, Summary: "Connection pool saturation",
				Proposal: proposalOne, ProposalHash: sha256Hex(proposalOne),
				EvidenceIDs: []string{testEvidenceID},
			},
			{
				Rank: 2, Confidence: 0.7, Summary: "Upstream request throttling",
				Proposal: proposalTwo, ProposalHash: sha256Hex(proposalTwo),
				EvidenceIDs: []string{testEvidenceID},
			},
		},
	})
	if err != nil || len(finalized.Hypotheses) != 2 {
		t.Fatalf("FinalizeInvestigation(feedback concurrency) = %#v, %v", finalized, err)
	}

	requests := []investigation.RecordFeedbackRequest{
		{
			WorkspaceID: testWorkspaceID, IncidentID: testIncidentID,
			InvestigationID: testInvestigationID, HypothesisID: finalized.Hypotheses[0].ID,
			Actor:   domain.Actor{Type: domain.ActorHuman, ID: "platform-admin-1"},
			Verdict: domain.FeedbackConfirmed, Details: []byte(`{"reason_code":"candidate_one"}`),
			IdempotencyKey: "feedback:concurrent:one",
		},
		{
			WorkspaceID: testWorkspaceID, IncidentID: testIncidentID,
			InvestigationID: testInvestigationID, HypothesisID: finalized.Hypotheses[1].ID,
			Actor:   domain.Actor{Type: domain.ActorHuman, ID: "platform-admin-2"},
			Verdict: domain.FeedbackConfirmed, Details: []byte(`{"reason_code":"candidate_two"}`),
			IdempotencyKey: "feedback:concurrent:two",
		},
	}
	type outcome struct {
		request investigation.RecordFeedbackRequest
		result  investigation.RecordFeedbackResult
		err     error
	}
	start := make(chan struct{})
	done := make(chan outcome, len(requests))
	for _, request := range requests {
		go func(candidate investigation.RecordFeedbackRequest) {
			<-start
			result, operationErr := repository.RecordFeedback(ctx, candidate)
			done <- outcome{request: candidate, result: result, err: operationErr}
		}(request)
	}
	close(start)
	outcomes := []outcome{<-done, <-done}

	var winner outcome
	successes := 0
	for _, candidate := range outcomes {
		if candidate.err == nil {
			successes++
			winner = candidate
			if !candidate.result.Created || candidate.result.Feedback.HypothesisID != candidate.request.HypothesisID {
				t.Fatalf("successful feedback outcome = %#v", candidate)
			}
		} else if !errors.Is(candidate.err, investigation.ErrInvalidTransition) {
			t.Fatalf("losing feedback error = %v, want ErrInvalidTransition", candidate.err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent feedback successes = %d, outcomes = %#v", successes, outcomes)
	}

	var confirmedHypothesisID string
	var confirmed, proposed, feedbackRows, feedbackLedgers int
	if err := fixture.harness.db.QueryRow(ctx, `
		SELECT incident.confirmed_hypothesis_id::text,
		       (SELECT count(*) FROM hypotheses AS hypothesis
		        WHERE hypothesis.tenant_id = incident.tenant_id
		          AND hypothesis.workspace_id = incident.workspace_id
		          AND hypothesis.investigation_id = $4
		          AND hypothesis.status = 'CONFIRMED'
		          AND hypothesis.runtime_schema_version = 'investigation-runtime.v1'),
		       (SELECT count(*) FROM hypotheses AS hypothesis
		        WHERE hypothesis.tenant_id = incident.tenant_id
		          AND hypothesis.workspace_id = incident.workspace_id
		          AND hypothesis.investigation_id = $4
		          AND hypothesis.status = 'PROPOSED'
		          AND hypothesis.runtime_schema_version = 'investigation-runtime.v1'),
		       (SELECT count(*) FROM feedback AS human_feedback
		        WHERE human_feedback.tenant_id = incident.tenant_id
		          AND human_feedback.workspace_id = incident.workspace_id
		          AND human_feedback.investigation_id = $4
		          AND human_feedback.runtime_schema_version = 'investigation-runtime.v1'),
		       (SELECT count(*) FROM investigation_idempotency_records AS ledger
		        WHERE ledger.tenant_id = incident.tenant_id
		          AND ledger.workspace_id = incident.workspace_id
		          AND ledger.operation = 'record_feedback')
		FROM incidents AS incident
		WHERE incident.tenant_id = $1 AND incident.workspace_id = $2 AND incident.id = $3
	`, testTenantID, testWorkspaceID, testIncidentID, testInvestigationID).Scan(
		&confirmedHypothesisID, &confirmed, &proposed, &feedbackRows, &feedbackLedgers,
	); err != nil {
		t.Fatalf("read concurrent feedback projection: %v", err)
	}
	if confirmedHypothesisID != winner.request.HypothesisID || confirmed != 1 || proposed != 1 ||
		feedbackRows != 1 || feedbackLedgers != 1 || generated.Load() != 3 {
		t.Fatalf(
			"feedback projection = root:%s confirmed:%d proposed:%d feedback:%d ledgers:%d IDs:%d; winner:%s",
			confirmedHypothesisID, confirmed, proposed, feedbackRows, feedbackLedgers,
			generated.Load(), winner.request.HypothesisID,
		)
	}
}

func prepareEvidenceTaskForFeedbackConcurrency(t *testing.T, ctx context.Context, fixture runtimeFixture) {
	t.Helper()
	payload := []byte(`{"series_count":3}`)
	completedAt := fixture.base.Add(10 * time.Second)
	tx, err := fixture.harness.db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin feedback evidence fixture: %v", err)
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
			$1, $2, $3, $4, 'prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', '{}', $5, $6::jsonb, $7,
			'AUTHENTICATED_READ_RUNNER', false, $8, $9, $10, $11, '{}',
			'investigation-runtime.v1'
		)
	`, testEvidenceID, testTenantID, testWorkspaceID, testInvestigationID,
		fixture.base.Add(9*time.Second), string(payload), sha256Hex(payload), completedAt,
		testIncidentID, testTaskID, payload); err != nil {
		t.Fatalf("insert feedback evidence fixture: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE tool_invocations
		SET status = 'EVIDENCE', evidence_id = $2, output_hash = $3,
		    started_at = $4, completed_at = $4, updated_at = $4
		WHERE id = $1
	`, testTaskID, testEvidenceID, sha256Hex(payload), completedAt); err != nil {
		t.Fatalf("complete feedback evidence task: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE investigations
		SET status = 'RUNNING', started_at = $2, updated_at = $2
		WHERE id = $1
	`, testInvestigationID, completedAt); err != nil {
		t.Fatalf("start feedback investigation fixture: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit feedback evidence fixture: %v", err)
	}
	committed = true
}
