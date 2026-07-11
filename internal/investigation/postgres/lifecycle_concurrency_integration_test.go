package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

func TestPostgresConcurrentFinalizeAndFailCommitExactlyOneTerminalOutcome(t *testing.T) {
	fixture := newRuntimeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	repository := newTerminalLifecycleRepository(t, fixture)
	taskCompletedAt := prepareFailedTaskAndRunningInvestigation(t, ctx, fixture)

	started, err := repository.StartModel(ctx, investigation.StartModelRequest{
		WorkspaceID: testWorkspaceID, InvestigationID: testInvestigationID,
		IdempotencyKey: "model:start:concurrent-terminal",
	})
	if err != nil || started.Investigation.Status != domain.InvestigationRunning ||
		started.Investigation.ModelStatus != domain.ModelRunning {
		t.Fatalf("StartModel(concurrency fixture) = %#v, %v", started, err)
	}

	finalizeRequest := investigation.FinalizeInvestigationRequest{
		WorkspaceID: testWorkspaceID, InvestigationID: testInvestigationID,
		IdempotencyKey: "finalize:concurrent-terminal",
		Status:         domain.InvestigationPartial, ModelStatus: domain.ModelFailed,
		ModelFailureCode: "model_unavailable",
	}
	failRequest := investigation.FailInvestigationRequest{
		WorkspaceID: testWorkspaceID, InvestigationID: testInvestigationID,
		IdempotencyKey: "fail:concurrent-terminal", FailureCode: "investigation_runtime_failed",
	}

	type finalizeOutcome struct {
		result investigation.FinalizeInvestigationResult
		err    error
	}
	type failOutcome struct {
		result investigation.FailInvestigationResult
		err    error
	}
	start := make(chan struct{})
	finalizeDone := make(chan finalizeOutcome, 1)
	failDone := make(chan failOutcome, 1)
	go func() {
		<-start
		result, operationErr := repository.FinalizeInvestigation(ctx, finalizeRequest)
		finalizeDone <- finalizeOutcome{result: result, err: operationErr}
	}()
	go func() {
		<-start
		result, operationErr := repository.FailInvestigation(ctx, failRequest)
		failDone <- failOutcome{result: result, err: operationErr}
	}()
	close(start)

	var finalized finalizeOutcome
	select {
	case finalized = <-finalizeDone:
	case <-ctx.Done():
		t.Fatalf("FinalizeInvestigation did not finish before deadline: %v", ctx.Err())
	}
	var failed failOutcome
	select {
	case failed = <-failDone:
	case <-ctx.Done():
		t.Fatalf("FailInvestigation did not finish before deadline: %v", ctx.Err())
	}

	finalizeWon := finalized.err == nil
	failWon := failed.err == nil
	if finalizeWon == failWon {
		t.Fatalf(
			"concurrent terminal outcomes = finalize %#v/%v, fail %#v/%v; want exactly one success",
			finalized.result, finalized.err, failed.result, failed.err,
		)
	}
	winnerOperation := "fail_investigation"
	if finalizeWon {
		winnerOperation = "finalize_investigation"
		if finalized.result.Investigation.Status != domain.InvestigationPartial ||
			finalized.result.Investigation.ModelStatus != domain.ModelFailed ||
			finalized.result.Investigation.ModelFailureCode != finalizeRequest.ModelFailureCode ||
			len(finalized.result.Hypotheses) != 0 {
			t.Fatalf("FinalizeInvestigation winner = %#v", finalized.result)
		}
		if !errors.Is(failed.err, investigation.ErrInvalidTransition) {
			t.Fatalf("FailInvestigation loser error = %v, want ErrInvalidTransition", failed.err)
		}
	} else {
		if failed.result.Investigation.Status != domain.InvestigationFailed ||
			failed.result.Investigation.ModelStatus != domain.ModelCancelled ||
			failed.result.Investigation.FailureCode != failRequest.FailureCode {
			t.Fatalf("FailInvestigation winner = %#v", failed.result)
		}
		if !errors.Is(finalized.err, investigation.ErrInvalidTransition) {
			t.Fatalf("FinalizeInvestigation loser error = %v, want ErrInvalidTransition", finalized.err)
		}
	}

	var status domain.InvestigationStatus
	var modelStatus domain.ModelStatus
	var failureCode, modelFailureCode string
	if err := fixture.harness.db.QueryRow(ctx, `
		SELECT status, model_status, COALESCE(failure_code, ''), COALESCE(model_failure_code, '')
		FROM investigations
		WHERE tenant_id = $1 AND workspace_id = $2 AND id = $3
		  AND runtime_schema_version = 'investigation-runtime.v1'
	`, testTenantID, testWorkspaceID, testInvestigationID).Scan(
		&status, &modelStatus, &failureCode, &modelFailureCode,
	); err != nil {
		t.Fatalf("read concurrent terminal Investigation: %v", err)
	}
	if finalizeWon {
		if status != domain.InvestigationPartial || modelStatus != domain.ModelFailed ||
			failureCode != "" || modelFailureCode != finalizeRequest.ModelFailureCode {
			t.Fatalf("persisted finalize winner = %s/%s/%q/%q", status, modelStatus, failureCode, modelFailureCode)
		}
	} else if status != domain.InvestigationFailed || modelStatus != domain.ModelCancelled ||
		failureCode != failRequest.FailureCode || modelFailureCode != "" {
		t.Fatalf("persisted fail winner = %s/%s/%q/%q", status, modelStatus, failureCode, modelFailureCode)
	}

	var taskStatus domain.ReadTaskStatus
	var taskFailureCode string
	var taskStartedAt, storedTaskCompletedAt, taskUpdatedAt time.Time
	var evidenceAbsent, outputHashAbsent bool
	if err := fixture.harness.db.QueryRow(ctx, `
		SELECT status, failure_code, started_at, completed_at, updated_at,
		       evidence_id IS NULL, output_hash IS NULL
		FROM tool_invocations
		WHERE tenant_id = $1 AND workspace_id = $2 AND investigation_id = $3 AND id = $4
		  AND runtime_schema_version = 'investigation-runtime.v1'
	`, testTenantID, testWorkspaceID, testInvestigationID, testTaskID).Scan(
		&taskStatus, &taskFailureCode, &taskStartedAt, &storedTaskCompletedAt, &taskUpdatedAt,
		&evidenceAbsent, &outputHashAbsent,
	); err != nil {
		t.Fatalf("read original failed task: %v", err)
	}
	if taskStatus != domain.ReadTaskFailed || taskFailureCode != "connector_unavailable" ||
		!taskStartedAt.Equal(taskCompletedAt) || !storedTaskCompletedAt.Equal(taskCompletedAt) ||
		!taskUpdatedAt.Equal(taskCompletedAt) || !evidenceAbsent || !outputHashAbsent {
		t.Fatalf(
			"failed task was rewritten: %s/%q started=%s completed=%s updated=%s evidenceAbsent=%v outputAbsent=%v",
			taskStatus, taskFailureCode, taskStartedAt, storedTaskCompletedAt, taskUpdatedAt,
			evidenceAbsent, outputHashAbsent,
		)
	}

	var terminalLedgers, winnerLedgers, hypotheses int
	if err := fixture.harness.db.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE operation IN ('finalize_investigation', 'fail_investigation')),
			count(*) FILTER (WHERE operation = $4),
			(SELECT count(*) FROM hypotheses
			 WHERE tenant_id = $1 AND workspace_id = $2 AND investigation_id = $3
			   AND runtime_schema_version = 'investigation-runtime.v1')
		FROM investigation_idempotency_records
		WHERE tenant_id = $1 AND workspace_id = $2 AND resource_id = $3
	`, testTenantID, testWorkspaceID, testInvestigationID, winnerOperation).Scan(
		&terminalLedgers, &winnerLedgers, &hypotheses,
	); err != nil {
		t.Fatalf("read concurrent terminal ledger outcome: %v", err)
	}
	if terminalLedgers != 1 || winnerLedgers != 1 || hypotheses != 0 {
		t.Fatalf(
			"terminal ledgers/winner ledgers/hypotheses = %d/%d/%d, want 1/1/0",
			terminalLedgers, winnerLedgers, hypotheses,
		)
	}
}
