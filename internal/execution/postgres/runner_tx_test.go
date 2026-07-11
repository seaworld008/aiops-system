package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executionlease"
)

const (
	runnerTxActionLockPattern = `(?s)SELECT .*FROM action_queue.*WHERE action_id = \$1.*FOR UPDATE`
	runnerTxClaimPattern      = `(?s)WITH exact_scope.*unnest\(\$4::text\[\], \$5::text\[\]\).*SELECT candidate\.action_id, candidate\.lease_epoch, candidate\.workspace_id, candidate\.environment_id.*FROM action_queue AS candidate.*candidate\.runner_pool = \$1.*candidate\.production = false.*runner_active\.runner_id = \$2.*< \$3.*FOR UPDATE OF candidate SKIP LOCKED`
)

func TestClaimRunnerTxUsesOnlyTrustedScopeAndLeavesTransactionOpen(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	tx := beginRunnerRepositoryTx(t, database)
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, err := marshalTestEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	scope := runnerTxScope(t, "runner-1", 7, 2, envelope.WorkspaceID, envelope.Target.EnvironmentID)
	leased := runnerTxExecution(envelope.ActionID, envelope.WorkspaceID, envelope.Target.EnvironmentID, executionlease.StatusLeased, 1, now)
	leased.ScopeRevision = 7

	database.ExpectExec(`SELECT pg_advisory_xact_lock\(\$1\)`).
		WithArgs(actionClaimLock).WillReturnResult(pgxmock.NewResult("SELECT", 1))
	database.ExpectQuery(runnerTxClaimPattern).
		WithArgs(executionlease.PoolWrite, "runner-1", 2,
			[]string{envelope.WorkspaceID}, []string{envelope.Target.EnvironmentID}).
		WillReturnRows(pgxmock.NewRows([]string{"action_id", "lease_epoch", "workspace_id", "environment_id"}).
			AddRow(envelope.ActionID, int64(0), envelope.WorkspaceID, envelope.Target.EnvironmentID))
	database.ExpectQuery(`(?s)UPDATE action_queue AS queued.*status = 'LEASED'.*runner_tenant_id = \$6.*scope_revision = \$5.*queued\.production = false.*RETURNING`).
		WithArgs(envelope.ActionID, "runner-1", tokenHash(testLeaseToken), float64(60), int64(7),
			testTenantID, envelope.WorkspaceID, envelope.Target.EnvironmentID, executionlease.PoolWrite).
		WillReturnRows(actionQueueRowsDetailed(leased, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(testLeaseToken), nil, nil, now, nil))

	claimed, err := repository.ClaimRunnerTx(context.Background(), tx, scope, time.Minute)
	if err != nil {
		t.Fatalf("ClaimRunnerTx() error = %v", err)
	}
	if claimed.Execution.LeaseToken != testLeaseToken || claimed.Execution.Status != executionlease.StatusLeased {
		t.Fatalf("ClaimRunnerTx() = %#v", claimed)
	}
	rollbackRunnerRepositoryTx(t, database, tx)
}

func TestClaimRunnerTxRejectsReadPoolBeforeActionSQL(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	tx := beginRunnerRepositoryTx(t, database)
	scope := runnerTxScopeForPool(t, "reader-1", 1, 1, "workspace-1", "PROD", executionlease.PoolRead)

	_, err := repository.ClaimRunnerTx(context.Background(), tx, scope, time.Minute)
	if !errors.Is(err, executionlease.ErrInvalidRequest) {
		t.Fatalf("ClaimRunnerTx(READ) error = %v, want %v", err, executionlease.ErrInvalidRequest)
	}
	rollbackRunnerRepositoryTx(t, database, tx)
}

func TestClaimRunnerTxNoLeaseLeavesTransactionOpen(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	tx := beginRunnerRepositoryTx(t, database)
	scope := runnerTxScope(t, "runner-1", 1, 1, "workspace-1", "PROD")

	database.ExpectExec(`SELECT pg_advisory_xact_lock\(\$1\)`).
		WithArgs(actionClaimLock).WillReturnResult(pgxmock.NewResult("SELECT", 1))
	database.ExpectQuery(runnerTxClaimPattern).
		WithArgs(executionlease.PoolWrite, "runner-1", 1, []string{"workspace-1"}, []string{"PROD"}).
		WillReturnRows(pgxmock.NewRows([]string{"action_id", "lease_epoch", "workspace_id", "environment_id"}))

	_, err := repository.ClaimRunnerTx(context.Background(), tx, scope, time.Minute)
	if !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("ClaimRunnerTx(empty) error = %v, want %v", err, executionlease.ErrNoLeaseAvailable)
	}
	rollbackRunnerRepositoryTx(t, database, tx)
}

func TestRunnerMutationTxMethodsRejectReadPoolBeforeActionSQL(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	tx := beginRunnerRepositoryTx(t, database)
	scope := runnerTxScopeForPool(t, "runner-1", 1, 1, "workspace-1", "PROD", executionlease.PoolRead)
	fence := executionlease.LeaseIdentity{ExecutionID: "action-1", RunnerID: "runner-1", Token: testLeaseToken, Epoch: 2}
	result := execution.ExecutorResult{Outcome: execution.ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: execution.VerificationPassed}

	tests := []struct {
		name string
		call func() error
	}{
		{name: "start", call: func() error { _, err := repository.StartRunnerTx(context.Background(), tx, scope, fence); return err }},
		{name: "heartbeat", call: func() error {
			_, err := repository.HeartbeatRunnerTx(context.Background(), tx, scope, execution.ActionHeartbeatRequest{Lease: fence, Sequence: 1, Extension: time.Minute})
			return err
		}},
		{name: "release", call: func() error {
			_, err := repository.ReleaseRunnerTx(context.Background(), tx, scope, fence, "EXECUTOR_NOT_READY", time.Minute)
			return err
		}},
		{name: "complete", call: func() error {
			_, err := repository.CompleteRunnerTx(context.Background(), tx, scope, fence, result, strings.Repeat("c", 64))
			return err
		}},
		{name: "finalize", call: func() error {
			_, err := repository.FinalizeRunnerTx(context.Background(), tx, scope, fence)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); !errors.Is(err, executionlease.ErrInvalidRequest) {
				t.Fatalf("READ mutation error = %v, want %v", err, executionlease.ErrInvalidRequest)
			}
		})
	}
	rollbackRunnerRepositoryTx(t, database, tx)
}

func TestStartRunnerTxLocksActionBeforeRevalidatingCurrentScope(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	tx := beginRunnerRepositoryTx(t, database)
	now, envelope, envelopeJSON, scope, fence := runnerTxTestState(t)
	leased := runnerTxExecution(fence.ExecutionID, envelope.WorkspaceID, envelope.Target.EnvironmentID, executionlease.StatusLeased, fence.Epoch, now)
	running := leased
	running.Status = executionlease.StatusRunning
	running.StartedAt = now

	database.ExpectQuery(runnerTxActionLockPattern).WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(leased, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(fence.Token), nil, nil, now, nil))
	database.ExpectQuery(`(?s)UPDATE action_queue.*status = 'RUNNING'.*runner_tenant_id = \$5.*scope_revision = \$8.*production = false.*RETURNING`).
		WithArgs(fence.ExecutionID, fence.RunnerID, tokenHash(fence.Token), fence.Epoch,
			testTenantID, envelope.WorkspaceID, envelope.Target.EnvironmentID, int64(1), executionlease.PoolWrite).
		WillReturnRows(actionQueueRowsDetailed(running, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(fence.Token), nil, nil, now, nil))

	got, err := repository.StartRunnerTx(context.Background(), tx, scope, fence)
	if err != nil || got.Status != executionlease.StatusRunning {
		t.Fatalf("StartRunnerTx() = %#v, %v", got, err)
	}
	rollbackRunnerRepositoryTx(t, database, tx)
}

func TestStartRunnerTxRejectsOldFenceScopeAndStateWithoutMutation(t *testing.T) {
	tests := []struct {
		name       string
		mutateRow  func(*executionlease.Execution)
		mutateCall func(*execution.RunnerScope, *executionlease.LeaseIdentity)
		want       error
	}{
		{name: "old token", mutateCall: func(_ *execution.RunnerScope, fence *executionlease.LeaseIdentity) {
			fence.Token = strings.Repeat("b", 64)
		}, want: executionlease.ErrStaleLease},
		{name: "old epoch", mutateCall: func(_ *execution.RunnerScope, fence *executionlease.LeaseIdentity) { fence.Epoch-- }, want: executionlease.ErrStaleLease},
		{name: "old scope revision", mutateCall: func(scope *execution.RunnerScope, _ *executionlease.LeaseIdentity) {
			*scope = runnerTxScope(t, "runner-1", 2, 1, "workspace-1", "PROD")
		}, want: executionlease.ErrStaleLease},
		{name: "wrong exact binding", mutateCall: func(scope *execution.RunnerScope, _ *executionlease.LeaseIdentity) {
			*scope = runnerTxScope(t, "runner-1", 1, 1, "workspace-2", "PROD")
		}, want: executionlease.ErrStaleLease},
		{name: "wrong state", mutateRow: func(value *executionlease.Execution) { value.Status = executionlease.StatusQueued }, want: executionlease.ErrInvalidTransition},
		{name: "production action", mutateRow: func(value *executionlease.Execution) { value.Production = true }, want: executionlease.ErrStaleLease},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database, repository := newActionQueueRepository(t)
			defer database.Close()
			tx := beginRunnerRepositoryTx(t, database)
			now, envelope, envelopeJSON, scope, fence := runnerTxTestState(t)
			leased := runnerTxExecution(fence.ExecutionID, envelope.WorkspaceID, envelope.Target.EnvironmentID, executionlease.StatusLeased, fence.Epoch, now)
			if test.mutateRow != nil {
				test.mutateRow(&leased)
			}
			if test.mutateCall != nil {
				test.mutateCall(&scope, &fence)
			}
			database.ExpectQuery(runnerTxActionLockPattern).WithArgs(fence.ExecutionID).
				WillReturnRows(actionQueueRowsDetailed(leased, envelopeJSON, envelope.PlanHash, "environment-1",
					envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(testLeaseToken), nil, nil, now, nil))

			_, err := repository.StartRunnerTx(context.Background(), tx, scope, fence)
			if !errors.Is(err, test.want) {
				t.Fatalf("StartRunnerTx() error = %v, want %v", err, test.want)
			}
			rollbackRunnerRepositoryTx(t, database, tx)
		})
	}
}

func TestStartRunnerTxRejectsIdempotentRetryAfterCancellationIntent(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	tx := beginRunnerRepositoryTx(t, database)
	now, envelope, envelopeJSON, scope, fence := runnerTxTestState(t)
	running := runnerTxExecution(fence.ExecutionID, envelope.WorkspaceID, envelope.Target.EnvironmentID, executionlease.StatusRunning, fence.Epoch, now)
	running.CancelRequestedAt = now
	running.CancelReasonHash = strings.Repeat("e", 64)

	database.ExpectQuery(runnerTxActionLockPattern).WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(running, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(fence.Token), nil, nil, now, nil))

	_, err := repository.StartRunnerTx(context.Background(), tx, scope, fence)
	if !errors.Is(err, executionlease.ErrInvalidTransition) {
		t.Fatalf("StartRunnerTx(cancelled retry) error = %v, want %v", err, executionlease.ErrInvalidTransition)
	}
	rollbackRunnerRepositoryTx(t, database, tx)
}

func TestHeartbeatRunnerTxReplayDoesNotRenewLease(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	tx := beginRunnerRepositoryTx(t, database)
	now, envelope, envelopeJSON, scope, fence := runnerTxTestState(t)
	running := runnerTxExecution(fence.ExecutionID, envelope.WorkspaceID, envelope.Target.EnvironmentID, executionlease.StatusRunning, fence.Epoch, now)
	running.HeartbeatSeq = 3

	database.ExpectQuery(runnerTxActionLockPattern).WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(running, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(fence.Token), nil, nil, now, nil))
	database.ExpectQuery(`(?s)SELECT COALESCE\(lease_expires_at > statement_timestamp\(\), false\).*authorization_expires_at > statement_timestamp\(\).*FROM action_queue`).
		WithArgs(fence.ExecutionID).WillReturnRows(pgxmock.NewRows([]string{"lease_current", "authorization_current"}).AddRow(true, true))

	result, err := repository.HeartbeatRunnerTx(context.Background(), tx, scope, execution.ActionHeartbeatRequest{
		Lease: fence, Sequence: 3, Extension: time.Minute,
	})
	if err != nil || result.Execution.HeartbeatSeq != 3 || !result.Execution.LeaseExpiresAt.Equal(running.LeaseExpiresAt) {
		t.Fatalf("HeartbeatRunnerTx(replay) = %#v, %v", result, err)
	}
	rollbackRunnerRepositoryTx(t, database, tx)
}

func TestHeartbeatRunnerTxRenewsOnlyTheNextExactSequence(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	tx := beginRunnerRepositoryTx(t, database)
	now, envelope, envelopeJSON, scope, fence := runnerTxTestState(t)
	running := runnerTxExecution(fence.ExecutionID, envelope.WorkspaceID, envelope.Target.EnvironmentID, executionlease.StatusRunning, fence.Epoch, now)
	updated := running
	updated.HeartbeatSeq = 1
	updated.LastHeartbeatAt = now
	updated.LeaseExpiresAt = now.Add(2 * time.Minute)

	database.ExpectQuery(runnerTxActionLockPattern).WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(running, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(fence.Token), nil, nil, now, nil))
	database.ExpectQuery(`(?s)SELECT COALESCE\(lease_expires_at > statement_timestamp\(\), false\).*authorization_expires_at > statement_timestamp\(\).*FROM action_queue`).
		WithArgs(fence.ExecutionID).WillReturnRows(pgxmock.NewRows([]string{"lease_current", "authorization_current"}).AddRow(true, true))
	database.ExpectQuery(`(?s)UPDATE action_queue.*heartbeat_seq = \$5.*runner_tenant_id = \$7.*scope_revision = \$10.*production = false.*RETURNING`).
		WithArgs(fence.ExecutionID, fence.RunnerID, tokenHash(fence.Token), fence.Epoch, int64(1), float64(60),
			testTenantID, envelope.WorkspaceID, envelope.Target.EnvironmentID, int64(1), executionlease.PoolWrite).
		WillReturnRows(actionQueueRowsDetailed(updated, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(fence.Token), nil, nil, now, nil))

	result, err := repository.HeartbeatRunnerTx(context.Background(), tx, scope, execution.ActionHeartbeatRequest{
		Lease: fence, Sequence: 1, Extension: time.Minute,
	})
	if err != nil || result.Directive != execution.HeartbeatContinue || result.Execution.HeartbeatSeq != 1 {
		t.Fatalf("HeartbeatRunnerTx(next) = %#v, %v", result, err)
	}
	rollbackRunnerRepositoryTx(t, database, tx)
}

func TestHeartbeatRunnerTxScopeNarrowingTerminatesWithoutRenewal(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	tx := beginRunnerRepositoryTx(t, database)
	now, envelope, envelopeJSON, _, fence := runnerTxTestState(t)
	running := runnerTxExecution(fence.ExecutionID, envelope.WorkspaceID, envelope.Target.EnvironmentID, executionlease.StatusRunning, fence.Epoch, now)
	currentScope := runnerTxScope(t, fence.RunnerID, 2, 1, "workspace-2", "PROD")

	database.ExpectQuery(runnerTxActionLockPattern).WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(running, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(fence.Token), nil, nil, now, nil))

	result, err := repository.HeartbeatRunnerTx(context.Background(), tx, currentScope, execution.ActionHeartbeatRequest{
		Lease: fence, Sequence: 1, Extension: time.Minute,
	})
	if err != nil || result.Directive != execution.HeartbeatTerminate || !result.Execution.LeaseExpiresAt.Equal(running.LeaseExpiresAt) {
		t.Fatalf("HeartbeatRunnerTx(narrowed scope) = %#v, %v", result, err)
	}
	rollbackRunnerRepositoryTx(t, database, tx)
}

func TestReleaseRunnerTxRejectsRunningJob(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	tx := beginRunnerRepositoryTx(t, database)
	now, envelope, envelopeJSON, scope, fence := runnerTxTestState(t)
	running := runnerTxExecution(fence.ExecutionID, envelope.WorkspaceID, envelope.Target.EnvironmentID, executionlease.StatusRunning, fence.Epoch, now)

	database.ExpectQuery(runnerTxActionLockPattern).WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(running, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(fence.Token), nil, nil, now, nil))

	_, err := repository.ReleaseRunnerTx(context.Background(), tx, scope, fence, "EXECUTOR_NOT_READY", time.Minute)
	if !errors.Is(err, executionlease.ErrInvalidTransition) {
		t.Fatalf("ReleaseRunnerTx(RUNNING) error = %v", err)
	}
	rollbackRunnerRepositoryTx(t, database, tx)
}

func TestReleaseRunnerTxRejectsUnrecognizedReasonBeforeActionSQL(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	tx := beginRunnerRepositoryTx(t, database)
	_, _, _, scope, fence := runnerTxTestState(t)

	_, err := repository.ReleaseRunnerTx(context.Background(), tx, scope, fence, "ARBITRARY_RUNNER_REASON", time.Minute)
	if !errors.Is(err, executionlease.ErrInvalidRequest) {
		t.Fatalf("ReleaseRunnerTx(arbitrary reason) error = %v, want %v", err, executionlease.ErrInvalidRequest)
	}
	rollbackRunnerRepositoryTx(t, database, tx)
}

func TestReleaseRunnerTxHashesServerReasonAndRequeuesOnlyLeasedJob(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	tx := beginRunnerRepositoryTx(t, database)
	now, envelope, envelopeJSON, scope, fence := runnerTxTestState(t)
	leased := runnerTxExecution(fence.ExecutionID, envelope.WorkspaceID, envelope.Target.EnvironmentID, executionlease.StatusLeased, fence.Epoch, now)
	queued := leased
	queued.Status = executionlease.StatusQueued
	queued.RunnerID, queued.RunnerTenantID, queued.RunnerWorkspaceID, queued.RunnerEnvironmentID = "", "", "", ""
	queued.ScopeRevision = 0
	queued.LeaseExpiresAt, queued.LeaseAcquiredAt, queued.LastHeartbeatAt = time.Time{}, time.Time{}, time.Time{}
	reasonHash := runnerReleaseReasonHash("EXECUTOR_NOT_READY")

	database.ExpectQuery(runnerTxActionLockPattern).WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(leased, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(fence.Token), nil, nil, now, nil))
	database.ExpectQuery(`(?s)UPDATE action_queue AS leased.*status = 'QUEUED'.*last_nack_hash = \$9.*runner_tenant_id = \$5.*scope_revision = \$8.*production = false.*leased\.status = 'LEASED'.*RETURNING`).
		WithArgs(fence.ExecutionID, fence.RunnerID, tokenHash(fence.Token), fence.Epoch,
			testTenantID, envelope.WorkspaceID, envelope.Target.EnvironmentID, int64(1), reasonHash, float64(60), executionlease.PoolWrite).
		WillReturnRows(actionQueueRowsDetailed(queued, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, nil, nil, now, reasonHash))

	got, err := repository.ReleaseRunnerTx(context.Background(), tx, scope, fence, "EXECUTOR_NOT_READY", time.Minute)
	if err != nil || got.Status != executionlease.StatusQueued || got.RunnerID != "" {
		t.Fatalf("ReleaseRunnerTx() = %#v, %v", got, err)
	}
	rollbackRunnerRepositoryTx(t, database, tx)
}

func TestCompleteRunnerTxBuildsAndPersistsCertificateBoundV2Receipt(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	tx := beginRunnerRepositoryTx(t, database)
	now, envelope, envelopeJSON, scope, fence := runnerTxTestState(t)
	running := runnerTxExecution(fence.ExecutionID, envelope.WorkspaceID, envelope.Target.EnvironmentID, executionlease.StatusRunning, fence.Epoch, now)
	summary := execution.ExecutorResult{Outcome: execution.ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: execution.VerificationPassed, Changed: true}
	request := execution.ActionCompleteRequest{Lease: fence, Summary: summary}
	certificateSHA256 := strings.Repeat("c", 64)
	wantReceipt, err := execution.BuildRunnerResultReceiptV2(execution.ClaimedAction{
		Execution: running, Envelope: envelope, PlanHash: envelope.PlanHash,
		TargetKey: running.TargetKey, EnvironmentRevision: "environment-1", Production: false,
	}, request, executionlease.StatusSucceeded, certificateSHA256, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	finalizing := running
	finalizing.Status = executionlease.StatusFinalizing
	finalizing.CompletionStatus = executionlease.StatusSucceeded
	finalizing.ResultHash = wantReceipt.ResultHash
	finalizing.LeaseExpiresAt = time.Time{}

	database.ExpectQuery(runnerTxActionLockPattern).WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(running, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), tokenHash(fence.Token), nil, nil, now, nil))
	database.ExpectQuery(`(?s)UPDATE action_queue.*status = 'FINALIZING'.*runner_tenant_id = \$7.*scope_revision = \$10.*production = false.*RETURNING`).
		WithArgs(fence.ExecutionID, fence.RunnerID, tokenHash(fence.Token), fence.Epoch,
			executionlease.StatusSucceeded, wantReceipt.ResultHash, testTenantID, envelope.WorkspaceID,
			envelope.Target.EnvironmentID, int64(1), executionlease.PoolWrite).
		WillReturnRows(actionQueueRowsDetailed(finalizing, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, tokenHash(fence.Token), fence.Epoch, now, nil))
	database.ExpectQuery(`(?s)INSERT INTO runner_result_receipts.*certificate_sha256.*schema_version.*'runner-result\.v2'.*RETURNING received_at`).
		WithArgs(fence.ExecutionID, testTenantID, envelope.WorkspaceID, envelope.Target.EnvironmentID,
			fence.RunnerID, fence.Epoch, int64(1), certificateSHA256, wantReceipt.ResultHash,
			executionlease.StatusSucceeded, pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"received_at"}).AddRow(now))
	wantReceipt.ReceivedAt = now

	got, err := repository.CompleteRunnerTx(context.Background(), tx, scope, fence, summary, certificateSHA256)
	if err != nil {
		t.Fatalf("CompleteRunnerTx() error = %v", err)
	}
	if got.Execution.Status != executionlease.StatusFinalizing || got.Execution.ResultHash != wantReceipt.ResultHash || got.Receipt != wantReceipt {
		t.Fatalf("CompleteRunnerTx() = %#v, want receipt %#v", got, wantReceipt)
	}
	rollbackRunnerRepositoryTx(t, database, tx)
}

func TestCompleteRunnerTxDetectsConflictingIdempotentResult(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	tx := beginRunnerRepositoryTx(t, database)
	now, envelope, envelopeJSON, scope, fence := runnerTxTestState(t)
	finalizing := runnerTxExecution(fence.ExecutionID, envelope.WorkspaceID, envelope.Target.EnvironmentID, executionlease.StatusFinalizing, fence.Epoch, now)
	finalizing.CompletionStatus = executionlease.StatusSucceeded
	finalizing.ResultHash = strings.Repeat("d", 64)

	database.ExpectQuery(runnerTxActionLockPattern).WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(finalizing, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, tokenHash(fence.Token), fence.Epoch, now, nil))

	_, err := repository.CompleteRunnerTx(context.Background(), tx, scope, fence,
		execution.ExecutorResult{Outcome: execution.ExecutorSucceeded, Code: "DIFFERENT_RESULT", Verification: execution.VerificationPassed},
		strings.Repeat("c", 64))
	if !errors.Is(err, executionlease.ErrCompletionConflict) {
		t.Fatalf("CompleteRunnerTx(conflict) error = %v", err)
	}
	rollbackRunnerRepositoryTx(t, database, tx)
}

func TestCompleteRunnerTxReturnsExactIdempotentV2ReceiptWithoutMutation(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	tx := beginRunnerRepositoryTx(t, database)
	now, envelope, envelopeJSON, scope, fence := runnerTxTestState(t)
	finalizing := runnerTxExecution(fence.ExecutionID, envelope.WorkspaceID, envelope.Target.EnvironmentID, executionlease.StatusFinalizing, fence.Epoch, now)
	result := execution.ExecutorResult{Outcome: execution.ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: execution.VerificationPassed, Changed: true}
	request := execution.ActionCompleteRequest{Lease: fence, Summary: result}
	certificateSHA256 := strings.Repeat("c", 64)
	receipt, err := execution.BuildRunnerResultReceiptV2(execution.ClaimedAction{
		Execution: finalizing, Envelope: envelope, PlanHash: envelope.PlanHash,
		TargetKey: finalizing.TargetKey, EnvironmentRevision: "environment-1", Production: false,
	}, request, executionlease.StatusSucceeded, certificateSHA256, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	finalizing.CompletionStatus = executionlease.StatusSucceeded
	finalizing.ResultHash = receipt.ResultHash

	database.ExpectQuery(runnerTxActionLockPattern).WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(finalizing, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, tokenHash(fence.Token), fence.Epoch, now, nil))
	database.ExpectQuery(`(?s)SELECT receipt_hash, schema_version, certificate_sha256, received_at.*FROM runner_result_receipts`).
		WithArgs(fence.ExecutionID, fence.Epoch).
		WillReturnRows(pgxmock.NewRows([]string{"receipt_hash", "schema_version", "certificate_sha256", "received_at"}).
			AddRow(receipt.ResultHash, "runner-result.v2", certificateSHA256, now))
	receipt.ReceivedAt = now

	got, err := repository.CompleteRunnerTx(context.Background(), tx, scope, fence, result, certificateSHA256)
	if err != nil || got.Execution.Status != executionlease.StatusFinalizing || got.Receipt != receipt {
		t.Fatalf("CompleteRunnerTx(idempotent) = %#v, %v; want receipt %#v", got, err, receipt)
	}
	rollbackRunnerRepositoryTx(t, database, tx)
}

func TestFinalizeRunnerTxLocksActionAndRequiresV2Receipt(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	tx := beginRunnerRepositoryTx(t, database)
	now, envelope, envelopeJSON, scope, fence := runnerTxTestState(t)
	finalizing := runnerTxExecution(fence.ExecutionID, envelope.WorkspaceID, envelope.Target.EnvironmentID, executionlease.StatusFinalizing, fence.Epoch, now)
	finalizing.CompletionStatus = executionlease.StatusSucceeded
	finalizing.ResultHash = strings.Repeat("d", 64)
	succeeded := finalizing
	succeeded.Status = executionlease.StatusSucceeded
	succeeded.CompletedAt = now

	database.ExpectQuery(runnerTxActionLockPattern).WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(finalizing, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, tokenHash(fence.Token), fence.Epoch, now, nil))
	database.ExpectQuery(`(?s)UPDATE action_queue AS finalizing.*runner_tenant_id = \$5.*scope_revision = \$8.*production = false.*receipt\.schema_version = 'runner-result\.v2'.*RETURNING`).
		WithArgs(fence.ExecutionID, fence.RunnerID, tokenHash(fence.Token), fence.Epoch,
			testTenantID, envelope.WorkspaceID, envelope.Target.EnvironmentID, int64(1), executionlease.PoolWrite).
		WillReturnRows(actionQueueRowsDetailed(succeeded, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, tokenHash(fence.Token), fence.Epoch, now, nil))

	got, err := repository.FinalizeRunnerTx(context.Background(), tx, scope, fence)
	if err != nil || got.Status != executionlease.StatusSucceeded {
		t.Fatalf("FinalizeRunnerTx() = %#v, %v", got, err)
	}
	rollbackRunnerRepositoryTx(t, database, tx)
}

func TestFinalizeRunnerTxIdempotentTerminalStillRequiresV2Proof(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	tx := beginRunnerRepositoryTx(t, database)
	now, envelope, envelopeJSON, scope, fence := runnerTxTestState(t)
	succeeded := runnerTxExecution(fence.ExecutionID, envelope.WorkspaceID, envelope.Target.EnvironmentID, executionlease.StatusSucceeded, fence.Epoch, now)
	succeeded.CompletionStatus = executionlease.StatusSucceeded
	succeeded.ResultHash = strings.Repeat("d", 64)
	succeeded.CompletedAt = now

	database.ExpectQuery(runnerTxActionLockPattern).WithArgs(fence.ExecutionID).
		WillReturnRows(actionQueueRowsDetailed(succeeded, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, tokenHash(fence.Token), fence.Epoch, now, nil))
	database.ExpectQuery(`(?s)SELECT EXISTS.*FROM runner_result_receipts AS receipt.*receipt\.schema_version = 'runner-result\.v2'`).
		WithArgs(fence.ExecutionID, fence.Epoch, strings.Repeat("d", 64), executionlease.StatusSucceeded,
			fence.RunnerID, testTenantID, envelope.WorkspaceID, envelope.Target.EnvironmentID, int64(1)).
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))

	got, err := repository.FinalizeRunnerTx(context.Background(), tx, scope, fence)
	if err != nil || got.Status != executionlease.StatusSucceeded {
		t.Fatalf("FinalizeRunnerTx(idempotent terminal) = %#v, %v", got, err)
	}
	rollbackRunnerRepositoryTx(t, database, tx)
}

func beginRunnerRepositoryTx(t *testing.T, database pgxmock.PgxPoolIface) pgx.Tx {
	t.Helper()
	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	return tx
}

func rollbackRunnerRepositoryTx(t *testing.T, database pgxmock.PgxPoolIface, tx pgx.Tx) {
	t.Helper()
	database.ExpectRollback()
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatalf("caller Rollback() error = %v", err)
	}
	assertExpectations(t, database)
}

func runnerTxTestState(t *testing.T) (time.Time, action.Envelope, []byte, execution.RunnerScope, executionlease.LeaseIdentity) {
	t.Helper()
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, err := marshalTestEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	scope := runnerTxScope(t, "runner-1", 1, 1, envelope.WorkspaceID, envelope.Target.EnvironmentID)
	fence := executionlease.LeaseIdentity{ExecutionID: envelope.ActionID, RunnerID: "runner-1", Token: testLeaseToken, Epoch: 2}
	return now, envelope, envelopeJSON, scope, fence
}

func marshalTestEnvelope(value action.Envelope) ([]byte, error) {
	return json.Marshal(value)
}

func runnerTxScope(t *testing.T, runnerID string, revision int64, maxConcurrency int, workspaceID, environmentID string) execution.RunnerScope {
	return runnerTxScopeForPool(t, runnerID, revision, maxConcurrency, workspaceID, environmentID, executionlease.PoolWrite)
}

func runnerTxScopeForPool(t *testing.T, runnerID string, revision int64, maxConcurrency int, workspaceID, environmentID string, pool executionlease.Pool) execution.RunnerScope {
	t.Helper()
	scope, err := (execution.RunnerRegistration{
		RunnerID: runnerID, TenantID: testTenantID, Pool: pool, Enabled: true,
		ScopeRevision: revision, MaxConcurrency: maxConcurrency,
		ScopeBindings: []execution.RunnerScopeBinding{{WorkspaceID: workspaceID, EnvironmentID: environmentID}},
	}).Scope()
	if err != nil {
		t.Fatalf("RunnerRegistration.Scope() error = %v", err)
	}
	return scope
}

func runnerTxExecution(actionID, workspaceID, environmentID string, status executionlease.Status, epoch int64, now time.Time) executionlease.Execution {
	return executionlease.Execution{
		ExecutionID: actionID, TargetKey: "k8s-deployment:sha256:" + strings.Repeat("a", 64),
		Pool: executionlease.PoolWrite, Production: false, Status: status,
		RunnerID: "runner-1", RunnerTenantID: testTenantID, RunnerWorkspaceID: workspaceID,
		RunnerEnvironmentID: environmentID, ScopeRevision: 1, LeaseEpoch: epoch,
		LeaseAcquiredAt: now.Add(-time.Minute), LastHeartbeatAt: now.Add(-time.Minute), LeaseExpiresAt: now.Add(time.Minute),
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
}
