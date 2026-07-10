package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executionlease"
)

var testLeaseToken = strings.Repeat("a", 64)

func TestSubmitAtomicallyPersistsImmutableEnvelopeMetadataAndQueuedLease(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	submission := execution.ActionSubmission{
		Envelope: envelope, PlanHash: envelope.PlanHash,
		TargetKey:           "k8s-deployment:sha256:" + strings.Repeat("a", 64),
		EnvironmentRevision: "environment-1", Production: true, Pool: executionlease.PoolWrite,
	}
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	want := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: submission.TargetKey, Pool: submission.Pool,
		Production: true, Status: executionlease.StatusQueued, CreatedAt: now, UpdatedAt: now,
	}
	database.ExpectQuery(`(?s)INSERT INTO action_queue .*envelope.*submission_hash.*ON CONFLICT \(action_id\) DO NOTHING.*RETURNING`).
		WithArgs(
			envelope.ActionID, string(envelopeJSON), pgxmock.AnyArg(), envelope.PlanHash,
			envelope.WorkspaceID, envelope.Target.EnvironmentID, submission.TargetKey,
			submission.EnvironmentRevision, submission.Pool, submission.Production,
		).
		WillReturnRows(actionQueueRows(want, envelopeJSON, envelope.PlanHash, submission.EnvironmentRevision,
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64)))

	got, err := repository.Submit(context.Background(), submission)
	if err != nil || got != want {
		t.Fatalf("Submit() = %#v, %v; want %#v", got, err, want)
	}
	assertExpectations(t, database)
}

func TestSubmitIsIdempotentOnlyForTheExactImmutableSubmission(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	submission := execution.ActionSubmission{
		Envelope: envelope, PlanHash: envelope.PlanHash,
		TargetKey:           "k8s-deployment:sha256:" + strings.Repeat("a", 64),
		EnvironmentRevision: "environment-1", Production: true, Pool: executionlease.PoolWrite,
	}
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	wantHash, err := hashSubmission(submission, envelopeJSON)
	if err != nil {
		t.Fatalf("hashSubmission() error = %v", err)
	}
	want := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: submission.TargetKey, Pool: submission.Pool,
		Production: true, Status: executionlease.StatusQueued, CreatedAt: now, UpdatedAt: now,
	}

	for name, storedHash := range map[string]string{
		"exact duplicate":                        wantHash,
		"same id different immutable submission": strings.Repeat("f", 64),
	} {
		t.Run(name, func(t *testing.T) {
			database, repository := newActionQueueRepository(t)
			defer database.Close()
			database.ExpectQuery("INSERT INTO action_queue").
				WithArgs(
					envelope.ActionID, string(envelopeJSON), wantHash, envelope.PlanHash,
					envelope.WorkspaceID, envelope.Target.EnvironmentID, submission.TargetKey,
					submission.EnvironmentRevision, submission.Pool, submission.Production,
				).
				WillReturnRows(actionQueueRowsEmpty())
			database.ExpectQuery(`(?s)SELECT .*submission_hash.*FROM action_queue.*WHERE action_id = \$1`).
				WithArgs(envelope.ActionID).
				WillReturnRows(actionQueueRows(want, envelopeJSON, envelope.PlanHash, submission.EnvironmentRevision,
					envelope.WorkspaceID, envelope.Target.EnvironmentID, storedHash))

			got, err := repository.Submit(context.Background(), submission)
			if name == "exact duplicate" {
				if err != nil || got != want {
					t.Fatalf("Submit() = %#v, %v; want idempotent %#v", got, err, want)
				}
			} else if !errors.Is(err, execution.ErrJobConflict) {
				t.Fatalf("Submit() error = %v, want %v", err, execution.ErrJobConflict)
			}
			assertExpectations(t, database)
		})
	}
}

func TestClaimSweepsAndScopesBeforeAtomicallyLeasingWithSkipLocked(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	targetKey := "k8s-deployment:sha256:" + strings.Repeat("a", 64)
	wantExecution := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: targetKey, Pool: executionlease.PoolWrite,
		Production: true, Status: executionlease.StatusLeased, RunnerID: "runner-1",
		LeaseToken: testLeaseToken, LeaseEpoch: 1, LeaseAcquiredAt: now,
		LastHeartbeatAt: now, LeaseExpiresAt: now.Add(time.Minute), CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
	}
	wantTokenHash := tokenHash(testLeaseToken)
	database.ExpectBegin()
	database.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("SELECT", 1))
	database.ExpectExec("UPDATE action_queue AS expired_running").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectExec("UPDATE action_queue AS expired_lease").WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectQuery(`(?s)SELECT candidate\.action_id, candidate\.lease_epoch.*candidate\.workspace_id = ANY\(\$2::text\[\]\).*candidate\.environment_id = ANY\(\$3::text\[\]\).*FOR UPDATE OF candidate SKIP LOCKED`).
		WithArgs(executionlease.PoolWrite, []string{"workspace-1"}, []string{"PROD"}).
		WillReturnRows(pgxmock.NewRows([]string{"action_id", "lease_epoch"}).AddRow(envelope.ActionID, int64(0)))
	database.ExpectQuery(`(?s)UPDATE action_queue AS queued.*lease_token_sha256 = \$3.*lease_epoch = queued\.lease_epoch \+ 1.*WHERE queued\.action_id = \$1 AND queued\.status = 'QUEUED'.*RETURNING`).
		WithArgs(envelope.ActionID, "runner-1", wantTokenHash, float64(60)).
		WillReturnRows(actionQueueRowsDetailed(wantExecution, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), wantTokenHash, nil, nil, now, nil))
	database.ExpectCommit()

	got, err := repository.Claim(context.Background(), execution.ActionClaimRequest{
		Scope: execution.RunnerScope{
			RunnerID: "runner-1", Pool: executionlease.PoolWrite,
			AllowedWorkspaceIDs: []string{"workspace-1"}, AllowedEnvironmentIDs: []string{"PROD"},
		},
		LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if got.Execution != wantExecution || got.Envelope.PlanHash != envelope.PlanHash || got.EnvironmentRevision != "environment-1" || !got.Production {
		t.Fatalf("Claim() = %#v, want execution %#v", got, wantExecution)
	}
	assertExpectations(t, database)
}

func TestClaimRejectsTokenSourcesBelowTheEntropyContract(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	repository, err := New(database, Options{TokenSource: func() (string, error) { return "predictable-token", nil }})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	database.ExpectBegin()
	database.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("SELECT", 1))
	database.ExpectExec("UPDATE action_queue AS expired_running").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectExec("UPDATE action_queue AS expired_lease").WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectQuery("SELECT candidate.action_id, candidate.lease_epoch").
		WithArgs(executionlease.PoolWrite, []string{"workspace-1"}, []string{"PROD"}).
		WillReturnRows(pgxmock.NewRows([]string{"action_id", "lease_epoch"}).AddRow("action-1", int64(0)))
	database.ExpectRollback()

	_, err = repository.Claim(context.Background(), execution.ActionClaimRequest{
		Scope: execution.RunnerScope{
			RunnerID: "runner-1", Pool: executionlease.PoolWrite,
			AllowedWorkspaceIDs: []string{"workspace-1"}, AllowedEnvironmentIDs: []string{"PROD"},
		},
		LeaseDuration: time.Minute,
	})
	if !errors.Is(err, executionlease.ErrInvalidRequest) {
		t.Fatalf("Claim() error = %v, want entropy rejection", err)
	}
	assertExpectations(t, database)
}

func TestLeaseMissUsesServerClockAndDistinguishesExpiredFromStarted(t *testing.T) {
	fence := executionlease.LeaseIdentity{ExecutionID: "action-1", RunnerID: "runner-1", Token: testLeaseToken, Epoch: 2}
	digest := tokenHash(fence.Token)

	t.Run("expired matching heartbeat fence is stale", func(t *testing.T) {
		database, repository := newActionQueueRepository(t)
		defer database.Close()
		database.ExpectQuery("UPDATE action_queue").
			WithArgs(fence.ExecutionID, fence.RunnerID, digest, fence.Epoch, float64(60)).
			WillReturnRows(actionQueueRowsEmpty())
		database.ExpectQuery(`(?s)SELECT runner_id, lease_epoch, lease_token_sha256, status,.*statement_timestamp\(\).*FROM action_queue.*WHERE action_id = \$1`).
			WithArgs(fence.ExecutionID).
			WillReturnRows(pgxmock.NewRows([]string{"runner_id", "lease_epoch", "lease_token_sha256", "status", "lease_current"}).
				AddRow(fence.RunnerID, fence.Epoch, digest, executionlease.StatusRunning, false))
		_, err := repository.Heartbeat(context.Background(), executionlease.HeartbeatRequest{Lease: fence, Extension: time.Minute})
		if !errors.Is(err, executionlease.ErrStaleLease) {
			t.Fatalf("Heartbeat() error = %v, want stale expired fence", err)
		}
		assertExpectations(t, database)
	})

	t.Run("nack after start is invalid transition", func(t *testing.T) {
		database, repository := newActionQueueRepository(t)
		defer database.Close()
		reason := execution.ActionQueueReason{Code: "TEMPORARY_FAILURE", DetailHash: strings.Repeat("d", 64)}
		reasonDigest, _ := reasonHash(reason)
		database.ExpectQuery("UPDATE action_queue").
			WithArgs(fence.ExecutionID, fence.RunnerID, digest, fence.Epoch, reasonDigest, float64(30)).
			WillReturnRows(actionQueueRowsEmpty())
		database.ExpectQuery(`(?s)SELECT runner_id, lease_epoch, lease_token_sha256, status,.*statement_timestamp\(\).*FROM action_queue.*WHERE action_id = \$1`).
			WithArgs(fence.ExecutionID).
			WillReturnRows(pgxmock.NewRows([]string{"runner_id", "lease_epoch", "lease_token_sha256", "status", "lease_current"}).
				AddRow(fence.RunnerID, fence.Epoch, digest, executionlease.StatusRunning, true))
		_, err := repository.Nack(context.Background(), execution.ActionNackRequest{
			Lease: fence, Reason: reason, RetryAfter: 30 * time.Second,
		})
		if !errors.Is(err, executionlease.ErrInvalidTransition) {
			t.Fatalf("Nack() error = %v, want invalid transition", err)
		}
		assertExpectations(t, database)
	})
}

func TestStartAndHeartbeatFenceWithTokenHashAndNeverReturnBearer(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, _ := json.Marshal(envelope)
	fence := executionlease.LeaseIdentity{ExecutionID: envelope.ActionID, RunnerID: "runner-1", Token: testLeaseToken, Epoch: 2}
	targetKey := "k8s-deployment:sha256:" + strings.Repeat("a", 64)
	running := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: targetKey, Pool: executionlease.PoolWrite,
		Production: true, Status: executionlease.StatusRunning, RunnerID: fence.RunnerID,
		LeaseEpoch: fence.Epoch, LeaseAcquiredAt: now.Add(-time.Minute), LastHeartbeatAt: now.Add(-time.Minute),
		LeaseExpiresAt: now.Add(time.Minute), StartedAt: now, CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	digest := tokenHash(fence.Token)
	database.ExpectQuery(`(?s)UPDATE action_queue.*lease_token_sha256 = \$3.*lease_expires_at > statement_timestamp\(\).*RETURNING`).
		WithArgs(fence.ExecutionID, fence.RunnerID, digest, fence.Epoch).
		WillReturnRows(actionQueueRowsDetailed(running, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), digest, nil, nil, now, nil))
	started, err := repository.Start(context.Background(), fence)
	if err != nil || started.Status != executionlease.StatusRunning || started.LeaseToken != "" {
		t.Fatalf("Start() = %#v, %v", started, err)
	}

	running.LastHeartbeatAt = now
	running.LeaseExpiresAt = now.Add(2 * time.Minute)
	database.ExpectQuery(`(?s)UPDATE action_queue.*make_interval\(secs => \$5::double precision\).*lease_token_sha256 = \$3.*RETURNING`).
		WithArgs(fence.ExecutionID, fence.RunnerID, digest, fence.Epoch, float64(120)).
		WillReturnRows(actionQueueRowsDetailed(running, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), digest, nil, nil, now, nil))
	heartbeat, err := repository.Heartbeat(context.Background(), executionlease.HeartbeatRequest{Lease: fence, Extension: 2 * time.Minute})
	if err != nil || !heartbeat.LeaseExpiresAt.Equal(running.LeaseExpiresAt) || heartbeat.LeaseToken != "" {
		t.Fatalf("Heartbeat() = %#v, %v", heartbeat, err)
	}
	assertExpectations(t, database)
}

func TestCompleteAtomicallyConsumesFenceAndKeepsOnlyTokenHashForIdempotency(t *testing.T) {
	database, repository := newActionQueueRepository(t)
	defer database.Close()
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, _ := json.Marshal(envelope)
	fence := executionlease.LeaseIdentity{ExecutionID: envelope.ActionID, RunnerID: "runner-1", Token: testLeaseToken, Epoch: 3}
	digest := tokenHash(fence.Token)
	resultHash := strings.Repeat("c", 64)
	completed := executionlease.Execution{
		ExecutionID: envelope.ActionID, TargetKey: "k8s-deployment:sha256:" + strings.Repeat("a", 64),
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusSucceeded,
		RunnerID: fence.RunnerID, LeaseEpoch: fence.Epoch, LeaseAcquiredAt: now.Add(-2 * time.Minute),
		LastHeartbeatAt: now.Add(-time.Minute), StartedAt: now.Add(-time.Minute), CompletedAt: now,
		ResultHash: resultHash, CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	database.ExpectBegin()
	database.ExpectQuery(`(?s)UPDATE action_queue.*completed_lease_token_sha256 = lease_token_sha256.*lease_token_sha256 = NULL.*status = \$5.*result_hash = \$6.*RETURNING`).
		WithArgs(fence.ExecutionID, fence.RunnerID, digest, fence.Epoch, executionlease.StatusSucceeded, resultHash).
		WillReturnRows(actionQueueRowsDetailed(completed, envelopeJSON, envelope.PlanHash, "environment-1",
			envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, digest, fence.Epoch, now, nil))
	database.ExpectCommit()

	got, err := repository.Complete(context.Background(), executionlease.CompleteRequest{
		Lease: fence, Status: executionlease.StatusSucceeded, ResultHash: resultHash,
	})
	if err != nil || got != completed || got.LeaseToken != "" {
		t.Fatalf("Complete() = %#v, %v; want %#v", got, err, completed)
	}
	assertExpectations(t, database)
}

func TestRejectAndNackUseFencedStructuredReasonHashes(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, _ := json.Marshal(envelope)
	fence := executionlease.LeaseIdentity{ExecutionID: envelope.ActionID, RunnerID: "runner-1", Token: testLeaseToken, Epoch: 1}
	digest := tokenHash(fence.Token)
	reason := execution.ActionQueueReason{Code: "PERMANENT_POLICY_DENIAL", DetailHash: strings.Repeat("d", 64)}
	reasonDigest, err := reasonHash(reason)
	if err != nil {
		t.Fatalf("reasonHash() error = %v", err)
	}
	targetKey := "k8s-deployment:sha256:" + strings.Repeat("a", 64)

	t.Run("reject is terminal", func(t *testing.T) {
		database, repository := newActionQueueRepository(t)
		defer database.Close()
		rejected := executionlease.Execution{
			ExecutionID: envelope.ActionID, TargetKey: targetKey, Pool: executionlease.PoolWrite,
			Production: true, Status: executionlease.StatusFailed, RunnerID: fence.RunnerID,
			LeaseEpoch: fence.Epoch, LeaseAcquiredAt: now.Add(-time.Minute), LastHeartbeatAt: now.Add(-time.Minute),
			CompletedAt: now, ResultHash: reasonDigest, CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
		}
		database.ExpectBegin()
		database.ExpectQuery(`(?s)UPDATE action_queue.*status = 'FAILED'.*completed_lease_token_sha256 = lease_token_sha256.*lease_token_sha256 = NULL.*result_hash = \$5.*status = 'LEASED'.*RETURNING`).
			WithArgs(fence.ExecutionID, fence.RunnerID, digest, fence.Epoch, reasonDigest).
			WillReturnRows(actionQueueRowsDetailed(rejected, envelopeJSON, envelope.PlanHash, "environment-1",
				envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, digest, fence.Epoch, now, nil))
		database.ExpectCommit()
		got, err := repository.Reject(context.Background(), execution.ActionRejectRequest{Lease: fence, Reason: reason})
		if err != nil || got != rejected || got.LeaseToken != "" {
			t.Fatalf("Reject() = %#v, %v", got, err)
		}
		assertExpectations(t, database)
	})

	t.Run("nack queues with server-side backoff", func(t *testing.T) {
		database, repository := newActionQueueRepository(t)
		defer database.Close()
		queued := executionlease.Execution{
			ExecutionID: envelope.ActionID, TargetKey: targetKey, Pool: executionlease.PoolWrite,
			Production: true, Status: executionlease.StatusQueued, LeaseEpoch: fence.Epoch,
			CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
		}
		database.ExpectQuery(`(?s)UPDATE action_queue.*status = 'QUEUED'.*last_nack_hash = \$5.*not_before = statement_timestamp\(\) \+ make_interval\(secs => \$6::double precision\).*lease_token_sha256 = NULL.*status = 'LEASED'.*RETURNING`).
			WithArgs(fence.ExecutionID, fence.RunnerID, digest, fence.Epoch, reasonDigest, float64(30)).
			WillReturnRows(actionQueueRowsDetailed(queued, envelopeJSON, envelope.PlanHash, "environment-1",
				envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, nil, nil, now.Add(30*time.Second), reasonDigest))
		got, err := repository.Nack(context.Background(), execution.ActionNackRequest{
			Lease: fence, Reason: reason, RetryAfter: 30 * time.Second,
		})
		if err != nil || got.Status != executionlease.StatusQueued || got.LeaseToken != "" {
			t.Fatalf("Nack() = %#v, %v", got, err)
		}
		assertExpectations(t, database)
	})
}

func TestSweepExpiredAndGetUseServerClockAndMaterializeUncertainState(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, _ := json.Marshal(envelope)

	t.Run("global sweep", func(t *testing.T) {
		database, repository := newActionQueueRepository(t)
		defer database.Close()
		database.ExpectBegin()
		database.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("SELECT", 1))
		database.ExpectExec(`(?s)UPDATE action_queue AS expired_running.*completed_lease_token_sha256 = lease_token_sha256.*completed_lease_epoch = lease_epoch.*lease_token_sha256 = NULL`).
			WithArgs(expiredResultHash()).WillReturnResult(pgxmock.NewResult("UPDATE", 2))
		database.ExpectExec("UPDATE action_queue AS expired_lease").WillReturnResult(pgxmock.NewResult("UPDATE", 3))
		database.ExpectCommit()
		if err := repository.SweepExpired(context.Background()); err != nil {
			t.Fatalf("SweepExpired() error = %v", err)
		}
		assertExpectations(t, database)
	})

	t.Run("get materializes one target", func(t *testing.T) {
		database, repository := newActionQueueRepository(t)
		defer database.Close()
		database.ExpectBegin()
		database.ExpectExec("UPDATE action_queue AS expired_running").
			WithArgs(expiredResultHash(), envelope.ActionID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		database.ExpectExec("UPDATE action_queue AS expired_lease").
			WithArgs(envelope.ActionID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))
		database.ExpectCommit()
		uncertain := executionlease.Execution{
			ExecutionID: envelope.ActionID, TargetKey: "k8s-deployment:sha256:" + strings.Repeat("a", 64),
			Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusUncertain,
			RunnerID: "runner-1", LeaseEpoch: 2, CompletedAt: now, ResultHash: expiredResultHash(),
			CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
		}
		database.ExpectQuery(`(?s)SELECT .*FROM action_queue.*WHERE action_id = \$1`).
			WithArgs(envelope.ActionID).
			WillReturnRows(actionQueueRowsDetailed(uncertain, envelopeJSON, envelope.PlanHash, "environment-1",
				envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, tokenHash(testLeaseToken), int64(2), now, nil))
		got, err := repository.Get(context.Background(), envelope.ActionID)
		if err != nil || got != uncertain || got.LeaseToken != "" {
			t.Fatalf("Get() = %#v, %v", got, err)
		}
		assertExpectations(t, database)
	})
}

func TestReconcileAndCancelResolveUncertainOutcomesWithoutReusableToken(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope := signedTestEnvelope(t, now)
	envelopeJSON, _ := json.Marshal(envelope)
	targetKey := "k8s-deployment:sha256:" + strings.Repeat("a", 64)

	t.Run("reconcile", func(t *testing.T) {
		database, repository := newActionQueueRepository(t)
		defer database.Close()
		request := executionlease.ReconcileRequest{
			ExecutionID: envelope.ActionID, ReconciliationID: "reconciliation-1", ActorID: "sre-1",
			Status: executionlease.StatusSucceeded, ResultHash: strings.Repeat("e", 64),
		}
		reconciled := executionlease.Execution{
			ExecutionID: envelope.ActionID, TargetKey: targetKey, Pool: executionlease.PoolWrite,
			Production: true, Status: request.Status, RunnerID: "runner-1", LeaseEpoch: 2,
			CompletedAt: now.Add(-time.Minute), ResultHash: expiredResultHash(), CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
			ReconciliationID: request.ReconciliationID, ReconciliationActor: request.ActorID,
			ReconciliationResultHash: request.ResultHash, ReconciledAt: now,
		}
		database.ExpectBegin()
		database.ExpectExec("UPDATE action_queue AS expired_running").
			WithArgs(expiredResultHash(), envelope.ActionID).WillReturnResult(pgxmock.NewResult("UPDATE", 0))
		database.ExpectExec("UPDATE action_queue AS expired_lease").
			WithArgs(envelope.ActionID).WillReturnResult(pgxmock.NewResult("UPDATE", 0))
		database.ExpectQuery(`(?s)UPDATE action_queue.*reconciliation_id = \$2.*status = \$4.*status = 'UNCERTAIN'.*RETURNING`).
			WithArgs(request.ExecutionID, request.ReconciliationID, request.ActorID, request.Status, request.ResultHash).
			WillReturnRows(actionQueueRowsDetailed(reconciled, envelopeJSON, envelope.PlanHash, "environment-1",
				envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, tokenHash(testLeaseToken), int64(2), now, nil))
		database.ExpectCommit()
		got, err := repository.Reconcile(context.Background(), request)
		if err != nil || got != reconciled || got.LeaseToken != "" {
			t.Fatalf("Reconcile() = %#v, %v", got, err)
		}
		assertExpectations(t, database)
	})

	t.Run("cancel running becomes uncertain", func(t *testing.T) {
		database, repository := newActionQueueRepository(t)
		defer database.Close()
		cancelled := executionlease.Execution{
			ExecutionID: envelope.ActionID, TargetKey: targetKey, Pool: executionlease.PoolWrite,
			Production: true, Status: executionlease.StatusUncertain, RunnerID: "runner-1", LeaseEpoch: 2,
			StartedAt: now.Add(-time.Minute), CompletedAt: now, ResultHash: cancellationResultHash(),
			CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
		}
		database.ExpectQuery(`(?s)UPDATE action_queue.*status = CASE WHEN status = 'RUNNING' THEN 'UNCERTAIN' ELSE 'CANCELLED' END.*result_hash = CASE WHEN status = 'RUNNING' THEN \$2 ELSE NULL END.*completed_lease_token_sha256 = CASE WHEN status = 'RUNNING' THEN lease_token_sha256 ELSE NULL END.*completed_lease_epoch = CASE WHEN status = 'RUNNING' THEN lease_epoch ELSE NULL END.*lease_token_sha256 = NULL.*RETURNING`).
			WithArgs(envelope.ActionID, cancellationResultHash()).
			WillReturnRows(actionQueueRowsDetailed(cancelled, envelopeJSON, envelope.PlanHash, "environment-1",
				envelope.WorkspaceID, envelope.Target.EnvironmentID, strings.Repeat("b", 64), nil, tokenHash(testLeaseToken), int64(2), now, nil))
		got, err := repository.Cancel(context.Background(), envelope.ActionID)
		if err != nil || got != cancelled || got.LeaseToken != "" {
			t.Fatalf("Cancel() = %#v, %v", got, err)
		}
		assertExpectations(t, database)
	})
}

func newActionQueueRepository(t *testing.T) (pgxmock.PgxPoolIface, *Repository) {
	t.Helper()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	repository, err := New(database, Options{TokenSource: func() (string, error) { return testLeaseToken, nil }})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return database, repository
}

func actionQueueRows(value executionlease.Execution, envelopeJSON []byte, planHash, environmentRevision, workspaceID, environmentID, submissionHash string) *pgxmock.Rows {
	return actionQueueRowsDetailed(value, envelopeJSON, planHash, environmentRevision, workspaceID, environmentID, submissionHash, nil, nil, nil, value.CreatedAt, nil)
}

func actionQueueRowsDetailed(value executionlease.Execution, envelopeJSON []byte, planHash, environmentRevision, workspaceID, environmentID, submissionHash string, leaseTokenHash, completedLeaseTokenHash, completedLeaseEpoch, notBefore, lastNackHash any) *pgxmock.Rows {
	if submissionHash == strings.Repeat("b", 64) {
		var envelope action.Envelope
		if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
			panic(err)
		}
		computed, err := hashSubmission(execution.ActionSubmission{
			Envelope: envelope, PlanHash: planHash, TargetKey: value.TargetKey,
			EnvironmentRevision: environmentRevision, Production: value.Production, Pool: value.Pool,
		}, envelopeJSON)
		if err != nil {
			panic(err)
		}
		submissionHash = computed
	}
	return actionQueueRowsEmpty().AddRow(
		value.ExecutionID, value.TargetKey, value.Pool, value.Production, value.Status,
		nullString(value.RunnerID), value.LeaseEpoch, nullTime(value.LeaseExpiresAt), nullTime(value.LeaseAcquiredAt), nullTime(value.LastHeartbeatAt),
		nullTime(value.StartedAt), nullTime(value.CompletedAt), nullString(value.ResultHash), value.CreatedAt, value.UpdatedAt,
		nullString(value.ReconciliationID), nullString(value.ReconciliationActor), nullString(value.ReconciliationResultHash), nullTime(value.ReconciledAt),
		envelopeJSON, planHash, environmentRevision, workspaceID, environmentID,
		submissionHash, leaseTokenHash, completedLeaseTokenHash, completedLeaseEpoch, notBefore, lastNackHash,
	)
}

func actionQueueRowsEmpty() *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"action_id", "target_key", "runner_pool", "production", "status",
		"runner_id", "lease_epoch", "lease_expires_at", "lease_acquired_at", "last_heartbeat_at",
		"started_at", "completed_at", "result_hash", "created_at", "updated_at",
		"reconciliation_id", "reconciliation_actor", "reconciliation_result_hash", "reconciled_at",
		"envelope", "plan_hash", "environment_revision", "workspace_id", "environment_id",
		"submission_hash", "lease_token_sha256", "completed_lease_token_sha256", "completed_lease_epoch",
		"not_before", "last_nack_hash",
	})
}

func signedTestEnvelope(t *testing.T, now time.Time) action.Envelope {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	signer, err := action.NewEd25519Signer("queue-test-key", privateKey)
	if err != nil {
		t.Fatalf("action.NewEd25519Signer() error = %v", err)
	}
	envelope := action.Envelope{
		SchemaVersion: action.SchemaVersionV1, ActionID: "action-1", WorkspaceID: "workspace-1",
		IncidentID: "incident-1", RequestedBy: "requester-1", ActionType: action.ActionKubernetesRolloutRestart,
		Target: action.TargetRef{ServiceID: "payments", EnvironmentID: "PROD", KubernetesDeployment: &action.KubernetesDeploymentTarget{
			ClusterID: "cluster-1", Namespace: "payments", Name: "api", UID: "uid-1", ResourceVersion: "7",
		}},
		Parameters: action.ActionParameters{KubernetesRolloutRestart: &action.KubernetesRolloutRestartParameters{Reason: "deadlock"}},
		ObservedState: action.ObservedState{KubernetesDeployment: &action.KubernetesDeploymentObservedState{
			Generation: 3, Replicas: 2, AvailableReplicas: 2, UpdatedReplicas: 2,
		}},
		Preconditions:   action.Preconditions{MappingResult: "EXACT", ExpectedResourceVersion: "7", RequireWhitelist: true},
		Verification:    action.VerificationPlan{Mode: "KUBERNETES_ROLLOUT", TimeoutSeconds: 300},
		Compensation:    action.CompensationPlan{Mode: "MANUAL_ONLY", Summary: "runbook"},
		Risk:            action.RiskAssessment{Level: "MEDIUM", ReasonCodes: []string{"PRODUCTION_CHANGE", "RESTART"}},
		PolicyVersion:   "policy.v1",
		CredentialScope: action.CredentialScope{ConnectorID: "kubernetes-prod", Permission: "PATCH_DEPLOYMENT_RESTART", Resource: "cluster-1/payments/deployment/api", TTLSeconds: 600},
		IdempotencyKey:  "idem-action-1", NotBefore: now, ExpiresAt: now.Add(30 * time.Minute), TraceID: strings.Repeat("a", 32),
	}
	sealed, err := action.Seal(context.Background(), envelope, envelope.RequestedBy, signer)
	if err != nil {
		t.Fatalf("action.Seal() error = %v", err)
	}
	return sealed
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func assertExpectations(t *testing.T, database pgxmock.PgxPoolIface) {
	t.Helper()
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}
