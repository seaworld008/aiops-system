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

func TestPostgresFailQueuedInvestigationCancelsTasksAndOwnsReplayKey(t *testing.T) {
	fixture := newRuntimeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	repository := newTerminalLifecycleRepository(t, fixture)

	request := investigation.FailInvestigationRequest{
		WorkspaceID: testWorkspaceID, InvestigationID: testInvestigationID,
		IdempotencyKey: "fail:queued:postgres", FailureCode: "read_pipeline_failed",
	}
	first, err := repository.FailInvestigation(ctx, request)
	if err != nil || first.Replayed || first.Investigation.Status != domain.InvestigationFailed ||
		first.Investigation.ModelStatus != domain.ModelCancelled ||
		first.Investigation.FailureCode != request.FailureCode || first.Investigation.CompletedAt.IsZero() {
		t.Fatalf("FailInvestigation(first) = %#v, %v", first, err)
	}
	if !first.Investigation.StartedAt.IsZero() {
		t.Fatalf("queued investigation acquired a start time while failing: %#v", first.Investigation)
	}
	task, err := repository.GetTask(ctx, testWorkspaceID, testTaskID)
	if err != nil || task.Status != domain.ReadTaskCancelled || task.FailureCode != request.FailureCode ||
		!task.StartedAt.IsZero() || task.CompletedAt.IsZero() ||
		!task.CompletedAt.Equal(first.Investigation.CompletedAt) {
		t.Fatalf("GetTask(after queued failure) = %#v, %v", task, err)
	}

	replay, err := repository.FailInvestigation(ctx, request)
	if err != nil || !replay.Replayed || replay.Investigation != first.Investigation {
		t.Fatalf("FailInvestigation(replay) = %#v, %v", replay, err)
	}
	conflict := request
	conflict.FailureCode = "different_failure"
	if _, err := repository.FailInvestigation(ctx, conflict); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("FailInvestigation(conflicting replay) error = %v, want ErrIdempotencyConflict", err)
	}
	terminalRetry := request
	terminalRetry.IdempotencyKey = "fail:queued:after-terminal"
	if _, err := repository.FailInvestigation(ctx, terminalRetry); !errors.Is(err, investigation.ErrInvalidTransition) {
		t.Fatalf("FailInvestigation(after terminal state) error = %v, want ErrInvalidTransition", err)
	}

	stored, err := repository.GetInvestigation(ctx, testWorkspaceID, testInvestigationID)
	if err != nil || stored != first.Investigation {
		t.Fatalf("GetInvestigation(after rejected retries) = %#v, %v", stored, err)
	}
	assertLifecycleLedger(t, ctx, fixture, "fail_investigation", 1, 0)
}

func TestPostgresFinalizeModelFailedRejectsWrongDerivedStatusWithoutPartialWrite(t *testing.T) {
	fixture := newRuntimeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	repository := newTerminalLifecycleRepository(t, fixture)
	taskCompletedAt := prepareFailedTaskAndRunningInvestigation(t, ctx, fixture)

	startRequest := investigation.StartModelRequest{
		WorkspaceID: testWorkspaceID, InvestigationID: testInvestigationID,
		IdempotencyKey: "model:start:terminal-failure",
	}
	started, err := repository.StartModel(ctx, startRequest)
	if err != nil || started.Replayed || started.Investigation.Status != domain.InvestigationRunning ||
		started.Investigation.ModelStatus != domain.ModelRunning {
		t.Fatalf("StartModel(model failure fixture) = %#v, %v", started, err)
	}

	wrongDerivedStatus := investigation.FinalizeInvestigationRequest{
		WorkspaceID: testWorkspaceID, InvestigationID: testInvestigationID,
		IdempotencyKey: "finalize:model-failed:wrong-derived-status",
		Status:         domain.InvestigationCompleted, ModelStatus: domain.ModelFailed,
		ModelFailureCode: "model_unavailable",
	}
	if _, err := repository.FinalizeInvestigation(ctx, wrongDerivedStatus); !errors.Is(err, investigation.ErrInvalidTransition) {
		t.Fatalf("FinalizeInvestigation(wrong derived status) error = %v, want ErrInvalidTransition", err)
	}
	unchanged, err := repository.GetInvestigation(ctx, testWorkspaceID, testInvestigationID)
	if err != nil || unchanged.Status != domain.InvestigationRunning || unchanged.ModelStatus != domain.ModelRunning ||
		!unchanged.CompletedAt.IsZero() {
		t.Fatalf("GetInvestigation(after rejected finalization) = %#v, %v", unchanged, err)
	}
	hypotheses, err := repository.ListHypotheses(ctx, investigation.ListHypothesesRequest{
		WorkspaceID: testWorkspaceID, InvestigationID: testInvestigationID,
	})
	if err != nil || len(hypotheses) != 0 {
		t.Fatalf("ListHypotheses(after rejected finalization) = %#v, %v", hypotheses, err)
	}
	assertLifecycleLedger(t, ctx, fixture, "finalize_investigation", 0, 0)

	request := wrongDerivedStatus
	request.IdempotencyKey = "finalize:model-failed:partial"
	request.Status = domain.InvestigationPartial
	first, err := repository.FinalizeInvestigation(ctx, request)
	if err != nil || first.Replayed || first.Investigation.Status != domain.InvestigationPartial ||
		first.Investigation.ModelStatus != domain.ModelFailed ||
		first.Investigation.ModelFailureCode != request.ModelFailureCode || len(first.Hypotheses) != 0 ||
		first.Investigation.CompletedAt.Before(taskCompletedAt) {
		t.Fatalf("FinalizeInvestigation(model failed) = %#v, %v", first, err)
	}
	replay, err := repository.FinalizeInvestigation(ctx, request)
	if err != nil || !replay.Replayed || replay.Investigation != first.Investigation || len(replay.Hypotheses) != 0 {
		t.Fatalf("FinalizeInvestigation(model failed replay) = %#v, %v", replay, err)
	}
	conflict := request
	conflict.ModelFailureCode = "different_model_failure"
	if _, err := repository.FinalizeInvestigation(ctx, conflict); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("FinalizeInvestigation(model failed conflict) error = %v, want ErrIdempotencyConflict", err)
	}
	assertLifecycleLedger(t, ctx, fixture, "start_model", 1, 1)
	assertLifecycleLedger(t, ctx, fixture, "finalize_investigation", 1, 1)
}

func TestPostgresFinalizeSkippedPersistsPartialWithoutHypotheses(t *testing.T) {
	fixture := newRuntimeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	repository := newTerminalLifecycleRepository(t, fixture)
	taskCompletedAt := prepareFailedTaskAndRunningInvestigation(t, ctx, fixture)

	request := investigation.FinalizeInvestigationRequest{
		WorkspaceID: testWorkspaceID, InvestigationID: testInvestigationID,
		IdempotencyKey: "finalize:model-skipped:partial",
		Status:         domain.InvestigationPartial, ModelStatus: domain.ModelSkipped,
	}
	first, err := repository.FinalizeInvestigation(ctx, request)
	if err != nil || first.Replayed || first.Investigation.Status != domain.InvestigationPartial ||
		first.Investigation.ModelStatus != domain.ModelSkipped ||
		first.Investigation.FailureCode != "" || first.Investigation.ModelFailureCode != "" ||
		len(first.Hypotheses) != 0 || first.Investigation.CompletedAt.Before(taskCompletedAt) {
		t.Fatalf("FinalizeInvestigation(model skipped) = %#v, %v", first, err)
	}
	task, err := repository.GetTask(ctx, testWorkspaceID, testTaskID)
	if err != nil || task.Status != domain.ReadTaskFailed || task.FailureCode != "connector_unavailable" ||
		!task.CompletedAt.Equal(taskCompletedAt) {
		t.Fatalf("GetTask(after skipped model) = %#v, %v", task, err)
	}
	hypotheses, err := repository.ListHypotheses(ctx, investigation.ListHypothesesRequest{
		WorkspaceID: testWorkspaceID, InvestigationID: testInvestigationID,
	})
	if err != nil || len(hypotheses) != 0 {
		t.Fatalf("ListHypotheses(after skipped model) = %#v, %v", hypotheses, err)
	}
	replay, err := repository.FinalizeInvestigation(ctx, request)
	if err != nil || !replay.Replayed || replay.Investigation != first.Investigation || len(replay.Hypotheses) != 0 {
		t.Fatalf("FinalizeInvestigation(model skipped replay) = %#v, %v", replay, err)
	}
	assertLifecycleLedger(t, ctx, fixture, "start_model", 0, 0)
	assertLifecycleLedger(t, ctx, fixture, "finalize_investigation", 1, 1)
}

func newTerminalLifecycleRepository(
	t *testing.T,
	fixture runtimeFixture,
) *investigationpostgres.Repository {
	t.Helper()
	repository, err := investigationpostgres.New(fixture.harness.extendedPool(t), investigationpostgres.Options{
		TaskRuntimeBinder: testTaskRuntimeBinder,
		IDFactory:         func() string { return "89000000-0000-4000-8000-000000000001" },
		TaskSpecAuthorizer: func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("construct terminal lifecycle repository: %v", err)
	}
	return repository
}

func prepareFailedTaskAndRunningInvestigation(
	t *testing.T,
	ctx context.Context,
	fixture runtimeFixture,
) time.Time {
	t.Helper()
	completedAt := fixture.base.Add(10 * time.Second)
	tx, err := fixture.harness.db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin failed-task lifecycle fixture: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, `
		UPDATE tool_invocations
		SET status = 'FAILED', failure_code = 'connector_unavailable',
		    started_at = $2, completed_at = $2, updated_at = $2
		WHERE id = $1
	`, testTaskID, completedAt); err != nil {
		t.Fatalf("fail runtime read task fixture: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE investigations
		SET status = 'RUNNING', started_at = $2, updated_at = $2
		WHERE id = $1
	`, testInvestigationID, completedAt); err != nil {
		t.Fatalf("start runtime investigation fixture: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit failed-task lifecycle fixture: %v", err)
	}
	committed = true
	return completedAt
}

func assertLifecycleLedger(
	t *testing.T,
	ctx context.Context,
	fixture runtimeFixture,
	operation string,
	wantRows, wantSnapshots int,
) {
	t.Helper()
	var rows, snapshots int
	if err := fixture.harness.db.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE result_snapshot IS NOT NULL)
		FROM investigation_idempotency_records
		WHERE tenant_id = $1 AND workspace_id = $2
		  AND operation = $3 AND resource_id = $4
	`, testTenantID, testWorkspaceID, operation, testInvestigationID).Scan(&rows, &snapshots); err != nil {
		t.Fatalf("read %s lifecycle ledger: %v", operation, err)
	}
	if rows != wantRows || snapshots != wantSnapshots {
		t.Fatalf("%s lifecycle ledger rows/snapshots = %d/%d, want %d/%d",
			operation, rows, snapshots, wantRows, wantSnapshots)
	}
}
