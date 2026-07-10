package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/executionlease"
	executionpostgres "github.com/aiops-system/control-plane/internal/executionlease/postgres"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v4"
)

var executionColumns = []string{
	"execution_id", "target_key", "runner_pool", "production", "status",
	"runner_id", "lease_token", "lease_epoch", "lease_expires_at", "lease_acquired_at",
	"last_heartbeat_at", "started_at", "completed_at", "result_hash", "created_at", "updated_at",
	"reconciliation_id", "reconciliation_actor", "reconciled_at",
}

func TestEnqueuePersistsPoolTargetAndProductionIsolation(t *testing.T) {
	database, repository, now := newPostgresRepository(t)
	defer database.Close()
	want := executionlease.Execution{
		ExecutionID: "execution-01", TargetKey: "prod/cluster/deployment/api",
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusQueued,
		CreatedAt: now, UpdatedAt: now,
	}
	database.ExpectQuery("INSERT INTO execution_leases").
		WithArgs(want.ExecutionID, want.TargetKey, want.Pool, want.Production).
		WillReturnRows(executionRows(want))

	got, err := repository.Enqueue(context.Background(), executionlease.EnqueueRequest{
		ExecutionID: want.ExecutionID, TargetKey: want.TargetKey, Pool: want.Pool, Production: want.Production,
	})
	if err != nil || got != want {
		t.Fatalf("Enqueue() = %+v, %v; want %+v", got, err, want)
	}
	assertExpectations(t, database)
}

func TestClaimSerializesExpiryAndEnforcesPoolTargetAndGlobalWriteGuards(t *testing.T) {
	database, repository, now := newPostgresRepository(t)
	defer database.Close()
	database.ExpectBegin()
	database.ExpectExec("SELECT pg_advisory_xact_lock").
		WithArgs(pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	database.ExpectExec("UPDATE execution_leases AS expired_running").
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectExec("UPDATE execution_leases AS expired_lease").
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectQuery(`(?s)SELECT candidate\.execution_id, candidate\.lease_epoch.*candidate\.runner_pool = \$1.*active\.target_key = candidate\.target_key.*active\.status IN \('LEASED', 'RUNNING', 'UNCERTAIN'\).*active\.runner_pool = 'WRITE'.*active\.production = true.*FOR UPDATE OF candidate SKIP LOCKED`).
		WithArgs(executionlease.PoolWrite).
		WillReturnRows(pgxmock.NewRows([]string{"execution_id", "lease_epoch"}).AddRow("execution-01", int64(0)))
	want := executionlease.Execution{
		ExecutionID: "execution-01", TargetKey: "prod/cluster/deployment/api",
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusLeased,
		RunnerID: "runner-01", LeaseToken: "lease-token-01", LeaseEpoch: 1,
		LeaseAcquiredAt: now, LastHeartbeatAt: now, LeaseExpiresAt: now.Add(time.Minute),
		CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
	}
	database.ExpectQuery(`(?s)UPDATE execution_leases AS execution.*lease_epoch = execution\.lease_epoch \+ 1.*WHERE execution\.execution_id = \$1 AND execution\.status = 'QUEUED'`).
		WithArgs(want.ExecutionID, want.RunnerID, want.LeaseToken, float64(60)).
		WillReturnRows(executionRows(want))
	database.ExpectCommit()

	got, err := repository.Claim(context.Background(), executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: want.RunnerID,
		LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil || got != want {
		t.Fatalf("Claim() = %+v, %v; want %+v", got, err, want)
	}
	assertExpectations(t, database)
}

func TestClaimReclaimsExpiredLeaseWithMonotonicallyHigherEpoch(t *testing.T) {
	database, repository, now := newPostgresRepository(t)
	defer database.Close()
	database.ExpectBegin()
	database.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("SELECT", 1))
	database.ExpectExec("UPDATE execution_leases AS expired_running").WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectExec("UPDATE execution_leases AS expired_lease").WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	database.ExpectQuery("SELECT candidate.execution_id, candidate.lease_epoch").
		WithArgs(executionlease.PoolWrite).
		WillReturnRows(pgxmock.NewRows([]string{"execution_id", "lease_epoch"}).AddRow("execution-01", int64(1)))
	want := executionlease.Execution{
		ExecutionID: "execution-01", TargetKey: "prod/cluster/deployment/api",
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusLeased,
		RunnerID: "runner-new", LeaseToken: "lease-token-01", LeaseEpoch: 2,
		LeaseAcquiredAt: now, LastHeartbeatAt: now, LeaseExpiresAt: now.Add(time.Minute),
		CreatedAt: now.Add(-2 * time.Minute), UpdatedAt: now,
	}
	database.ExpectQuery("UPDATE execution_leases AS execution").
		WithArgs(want.ExecutionID, want.RunnerID, want.LeaseToken, float64(60)).
		WillReturnRows(executionRows(want))
	database.ExpectCommit()

	got, err := repository.Claim(context.Background(), executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: want.RunnerID,
		LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil || got.LeaseEpoch != 2 {
		t.Fatalf("reclaimed Claim() = %+v, %v", got, err)
	}
	assertExpectations(t, database)
}

func TestClaimFailsClosedBeforeSQLWhenClaimsAreDisabled(t *testing.T) {
	database, repository, _ := newPostgresRepository(t)
	defer database.Close()

	_, err := repository.Claim(context.Background(), executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-01", LeaseDuration: time.Minute,
	})
	if !errors.Is(err, executionlease.ErrClaimBlocked) {
		t.Fatalf("Claim() error = %v, want ErrClaimBlocked", err)
	}
	assertExpectations(t, database)
}

func TestClaimCommitsExpiredStateTransitionsWhenNoLeaseIsAvailable(t *testing.T) {
	database, repository, _ := newPostgresRepository(t)
	defer database.Close()
	database.ExpectBegin()
	database.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("SELECT", 1))
	database.ExpectExec("UPDATE execution_leases AS expired_running").WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	database.ExpectExec("UPDATE execution_leases AS expired_lease").WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	database.ExpectQuery("SELECT candidate.execution_id, candidate.lease_epoch").
		WithArgs(executionlease.PoolWrite).
		WillReturnRows(pgxmock.NewRows([]string{"execution_id", "lease_epoch"}))
	database.ExpectCommit()

	_, err := repository.Claim(context.Background(), executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-01", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("Claim() error = %v, want ErrNoLeaseAvailable", err)
	}
	assertExpectations(t, database)
}

func TestStartAndHeartbeatRequireTheCurrentTokenEpochAndUnexpiredLease(t *testing.T) {
	database, repository, now := newPostgresRepository(t)
	defer database.Close()
	fence := executionlease.LeaseIdentity{ExecutionID: "execution-01", Token: "lease-token-01", Epoch: 3}
	running := executionlease.Execution{
		ExecutionID: fence.ExecutionID, TargetKey: "prod/cluster/deployment/api",
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusRunning,
		RunnerID: "runner-01", LeaseToken: fence.Token, LeaseEpoch: fence.Epoch,
		LeaseAcquiredAt: now.Add(-time.Minute), LastHeartbeatAt: now.Add(-time.Minute),
		LeaseExpiresAt: now.Add(time.Minute), StartedAt: now, CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	database.ExpectQuery(`(?s)UPDATE execution_leases.*lease_token = \$2.*lease_epoch = \$3.*lease_expires_at > statement_timestamp\(\)`).
		WithArgs(fence.ExecutionID, fence.Token, fence.Epoch).
		WillReturnRows(executionRows(running))

	started, err := repository.Start(context.Background(), fence)
	if err != nil || started.Status != executionlease.StatusRunning {
		t.Fatalf("Start() = %+v, %v", started, err)
	}

	heartbeatAt := now
	heartbeatExpiry := now.Add(2 * time.Minute)
	running.LastHeartbeatAt = heartbeatAt
	running.LeaseExpiresAt = heartbeatExpiry
	database.ExpectQuery(`(?s)UPDATE execution_leases.*lease_token = \$2.*lease_epoch = \$3.*lease_expires_at > statement_timestamp\(\)`).
		WithArgs(fence.ExecutionID, fence.Token, fence.Epoch, float64(120)).
		WillReturnRows(executionRows(running))

	heartbeat, err := repository.Heartbeat(context.Background(), executionlease.HeartbeatRequest{Lease: fence, Extension: 2 * time.Minute})
	if err != nil || !heartbeat.LeaseExpiresAt.Equal(heartbeatExpiry) {
		t.Fatalf("Heartbeat() = %+v, %v", heartbeat, err)
	}
	assertExpectations(t, database)
}

func TestHeartbeatZeroRowUpdateChecksStateAndReturnsStaleLease(t *testing.T) {
	database, repository, now := newPostgresRepository(t)
	defer database.Close()
	stale := executionlease.LeaseIdentity{ExecutionID: "execution-01", Token: "lease-token-old", Epoch: 2}
	database.ExpectQuery("UPDATE execution_leases").
		WithArgs(stale.ExecutionID, stale.Token, stale.Epoch, float64(60)).
		WillReturnRows(executionRows())
	current := executionlease.Execution{
		ExecutionID: stale.ExecutionID, TargetKey: "prod/cluster/deployment/api",
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusRunning,
		RunnerID: "runner-new", LeaseToken: "lease-token-new", LeaseEpoch: 3,
		LeaseAcquiredAt: now.Add(-time.Minute), LastHeartbeatAt: now,
		LeaseExpiresAt: now.Add(time.Minute), StartedAt: now.Add(-time.Minute),
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	database.ExpectQuery("SELECT execution_id, target_key, runner_pool").
		WithArgs(stale.ExecutionID).
		WillReturnRows(executionRows(current))

	_, err := repository.Heartbeat(context.Background(), executionlease.HeartbeatRequest{Lease: stale, Extension: time.Minute})
	if !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("Heartbeat() error = %v, want ErrStaleLease", err)
	}
	assertExpectations(t, database)
}

func TestCompleteIsIdempotentForSameFenceStatusAndHashAndRejectsConflict(t *testing.T) {
	database, repository, now := newPostgresRepository(t)
	defer database.Close()
	fence := executionlease.LeaseIdentity{ExecutionID: "execution-01", Token: "lease-token-01", Epoch: 4}
	resultHash := strings.Repeat("a", 64)
	completed := executionlease.Execution{
		ExecutionID: fence.ExecutionID, TargetKey: "prod/cluster/deployment/api",
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusSucceeded,
		RunnerID: "runner-01", LeaseToken: fence.Token, LeaseEpoch: fence.Epoch,
		LeaseAcquiredAt: now.Add(-2 * time.Minute), LastHeartbeatAt: now.Add(-time.Minute),
		StartedAt: now.Add(-time.Minute), CompletedAt: now, ResultHash: resultHash,
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}

	expectCompleteUpdate(database, fence, executionlease.StatusSucceeded, resultHash, executionRows(completed))
	database.ExpectCommit()
	first, err := repository.Complete(context.Background(), executionlease.CompleteRequest{
		Lease: fence, Status: executionlease.StatusSucceeded, ResultHash: resultHash,
	})
	if err != nil || first != completed {
		t.Fatalf("Complete() = %+v, %v", first, err)
	}

	expectCompleteUpdate(database, fence, executionlease.StatusSucceeded, resultHash, executionRows())
	database.ExpectQuery("SELECT execution_id, target_key, runner_pool").
		WithArgs(fence.ExecutionID).
		WillReturnRows(executionRows(completed))
	database.ExpectCommit()
	idempotent, err := repository.Complete(context.Background(), executionlease.CompleteRequest{
		Lease: fence, Status: executionlease.StatusSucceeded, ResultHash: resultHash,
	})
	if err != nil || idempotent != completed {
		t.Fatalf("idempotent Complete() = %+v, %v", idempotent, err)
	}

	conflictingHash := strings.Repeat("b", 64)
	expectCompleteUpdate(database, fence, executionlease.StatusSucceeded, conflictingHash, executionRows())
	database.ExpectQuery("SELECT execution_id, target_key, runner_pool").
		WithArgs(fence.ExecutionID).
		WillReturnRows(executionRows(completed))
	database.ExpectRollback()
	_, err = repository.Complete(context.Background(), executionlease.CompleteRequest{
		Lease: fence, Status: executionlease.StatusSucceeded, ResultHash: conflictingHash,
	})
	if !errors.Is(err, executionlease.ErrCompletionConflict) {
		t.Fatalf("conflicting Complete() error = %v", err)
	}
	assertExpectations(t, database)
}

func TestCompleteZeroRowUpdateWithDifferentFenceReturnsStaleLease(t *testing.T) {
	database, repository, now := newPostgresRepository(t)
	defer database.Close()
	stale := executionlease.LeaseIdentity{ExecutionID: "execution-01", Token: "lease-token-old", Epoch: 2}
	resultHash := strings.Repeat("c", 64)
	expectCompleteUpdate(database, stale, executionlease.StatusFailed, resultHash, executionRows())
	current := executionlease.Execution{
		ExecutionID: stale.ExecutionID, TargetKey: "prod/cluster/deployment/api",
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusRunning,
		RunnerID: "runner-new", LeaseToken: "lease-token-new", LeaseEpoch: 3,
		LeaseAcquiredAt: now.Add(-time.Minute), LastHeartbeatAt: now,
		LeaseExpiresAt: now.Add(time.Minute), StartedAt: now.Add(-time.Minute),
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	database.ExpectQuery("SELECT execution_id, target_key, runner_pool").
		WithArgs(stale.ExecutionID).
		WillReturnRows(executionRows(current))
	database.ExpectRollback()

	_, err := repository.Complete(context.Background(), executionlease.CompleteRequest{
		Lease: stale, Status: executionlease.StatusFailed, ResultHash: resultHash,
	})
	if !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("Complete() error = %v, want ErrStaleLease", err)
	}
	assertExpectations(t, database)
}

func TestCompleteAllowsRunnerToReportUncertainResult(t *testing.T) {
	database, repository, now := newPostgresRepository(t)
	defer database.Close()
	fence := executionlease.LeaseIdentity{ExecutionID: "execution-01", Token: "lease-token-01", Epoch: 1}
	resultHash := strings.Repeat("d", 64)
	want := executionlease.Execution{
		ExecutionID: fence.ExecutionID, TargetKey: "prod/cluster/deployment/api",
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusUncertain,
		RunnerID: "runner-01", LeaseToken: fence.Token, LeaseEpoch: fence.Epoch,
		LeaseAcquiredAt: now.Add(-time.Minute), LastHeartbeatAt: now.Add(-time.Minute),
		StartedAt: now.Add(-time.Minute), CompletedAt: now, ResultHash: resultHash,
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	expectCompleteUpdate(database, fence, executionlease.StatusUncertain, resultHash, executionRows(want))
	database.ExpectCommit()

	got, err := repository.Complete(context.Background(), executionlease.CompleteRequest{
		Lease: fence, Status: executionlease.StatusUncertain, ResultHash: resultHash,
	})
	if err != nil || got != want {
		t.Fatalf("Complete(UNCERTAIN) = %+v, %v; want %+v", got, err, want)
	}
	assertExpectations(t, database)
}

func TestCompleteAfterReconciliationAlwaysTreatsTheOldRunnerAsStale(t *testing.T) {
	database, repository, now := newPostgresRepository(t)
	defer database.Close()
	fence := executionlease.LeaseIdentity{ExecutionID: "execution-01", Token: "lease-token-01", Epoch: 1}
	requestHash := strings.Repeat("d", 64)
	expectCompleteUpdate(database, fence, executionlease.StatusSucceeded, requestHash, executionRows())
	reconciled := executionlease.Execution{
		ExecutionID: fence.ExecutionID, TargetKey: "prod/cluster/deployment/api",
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusSucceeded,
		LeaseToken: fence.Token, LeaseEpoch: fence.Epoch, ResultHash: requestHash,
		CompletedAt: now.Add(-time.Minute), ReconciliationID: "audit/reconciliation/42",
		ReconciliationActor: "operator/alice", ReconciledAt: now,
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	database.ExpectQuery("SELECT execution_id, target_key, runner_pool").
		WithArgs(fence.ExecutionID).
		WillReturnRows(executionRows(reconciled))
	database.ExpectRollback()

	_, err := repository.Complete(context.Background(), executionlease.CompleteRequest{
		Lease: fence, Status: executionlease.StatusSucceeded, ResultHash: requestHash,
	})
	if !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("Complete() after reconciliation error = %v, want ErrStaleLease", err)
	}
	assertExpectations(t, database)
}

func TestReconcileResolvesOnlyUncertainAndIsIdempotentByAuditIdentity(t *testing.T) {
	database, repository, now := newPostgresRepository(t)
	defer database.Close()
	request := executionlease.ReconcileRequest{
		ExecutionID: "execution-01", ReconciliationID: "audit/reconciliation/42",
		ActorID: "operator/alice@example.com", Status: executionlease.StatusSucceeded,
		ResultHash: strings.Repeat("e", 64),
	}
	resolved := executionlease.Execution{
		ExecutionID: request.ExecutionID, TargetKey: "prod/cluster/deployment/api",
		Pool: executionlease.PoolWrite, Production: true, Status: request.Status,
		LeaseEpoch: 2, LeaseAcquiredAt: now.Add(-2 * time.Minute), LastHeartbeatAt: now.Add(-time.Minute),
		StartedAt: now.Add(-time.Minute), CompletedAt: now.Add(-30 * time.Second), ResultHash: request.ResultHash,
		ReconciliationID: request.ReconciliationID, ReconciliationActor: request.ActorID, ReconciledAt: now,
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}

	expectReconcileUpdate(database, request, executionRows(resolved))
	database.ExpectCommit()
	got, err := repository.Reconcile(context.Background(), request)
	if err != nil || got != resolved {
		t.Fatalf("Reconcile() = %+v, %v; want %+v", got, err, resolved)
	}

	expectReconcileUpdate(database, request, executionRows())
	database.ExpectQuery("SELECT execution_id, target_key, runner_pool").
		WithArgs(request.ExecutionID).
		WillReturnRows(executionRows(resolved))
	database.ExpectCommit()
	idempotent, err := repository.Reconcile(context.Background(), request)
	if err != nil || idempotent != resolved {
		t.Fatalf("idempotent Reconcile() = %+v, %v", idempotent, err)
	}

	conflict := request
	conflict.ActorID = "operator/bob@example.com"
	expectReconcileUpdate(database, conflict, executionRows())
	database.ExpectQuery("SELECT execution_id, target_key, runner_pool").
		WithArgs(request.ExecutionID).
		WillReturnRows(executionRows(resolved))
	database.ExpectRollback()
	_, err = repository.Reconcile(context.Background(), conflict)
	if !errors.Is(err, executionlease.ErrReconciliationConflict) {
		t.Fatalf("conflicting Reconcile() error = %v", err)
	}
	assertExpectations(t, database)
}

func TestReconcileMapsGloballyReusedAuditIdentityToConflict(t *testing.T) {
	database, repository, _ := newPostgresRepository(t)
	defer database.Close()
	request := executionlease.ReconcileRequest{
		ExecutionID: "execution-02", ReconciliationID: "audit/reconciliation/already-used",
		ActorID: "operator/alice", Status: executionlease.StatusFailed, ResultHash: strings.Repeat("f", 64),
	}
	database.ExpectBegin()
	database.ExpectQuery("UPDATE execution_leases").
		WithArgs(request.ExecutionID, request.ReconciliationID, request.ActorID, request.Status, request.ResultHash).
		WillReturnError(&pgconn.PgError{Code: "23505", ConstraintName: "execution_leases_reconciliation_id_uk"})
	database.ExpectRollback()

	_, err := repository.Reconcile(context.Background(), request)
	if !errors.Is(err, executionlease.ErrReconciliationConflict) {
		t.Fatalf("Reconcile() error = %v, want ErrReconciliationConflict", err)
	}
	assertExpectations(t, database)
}

func TestCancelRunningExecutionBecomesUncertainAndFencesTheOldRunner(t *testing.T) {
	database, repository, now := newPostgresRepository(t)
	defer database.Close()
	want := executionlease.Execution{
		ExecutionID: "execution-01", TargetKey: "prod/cluster/deployment/api",
		Pool: executionlease.PoolWrite, Production: true, Status: executionlease.StatusUncertain,
		LeaseEpoch: 2, LeaseAcquiredAt: now.Add(-time.Minute), LastHeartbeatAt: now.Add(-time.Minute),
		StartedAt: now.Add(-time.Minute), CompletedAt: now,
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	database.ExpectQuery(`(?s)UPDATE execution_leases.*WHEN status = 'RUNNING' THEN 'UNCERTAIN'.*lease_token = NULL`).
		WithArgs(want.ExecutionID).
		WillReturnRows(executionRows(want))

	got, err := repository.Cancel(context.Background(), want.ExecutionID)
	if err != nil || got != want {
		t.Fatalf("Cancel() = %+v, %v; want %+v", got, err, want)
	}
	assertExpectations(t, database)
}

func expectCompleteUpdate(database pgxmock.PgxPoolIface, fence executionlease.LeaseIdentity, status executionlease.Status, hash string, rows *pgxmock.Rows) {
	database.ExpectBegin()
	database.ExpectQuery(`(?s)UPDATE execution_leases.*completed_lease_token = lease_token.*lease_token = \$2.*lease_epoch = \$3.*status = 'RUNNING'.*lease_expires_at > statement_timestamp\(\)`).
		WithArgs(fence.ExecutionID, fence.Token, fence.Epoch, status, hash).
		WillReturnRows(rows)
}

func expectReconcileUpdate(database pgxmock.PgxPoolIface, request executionlease.ReconcileRequest, rows *pgxmock.Rows) {
	database.ExpectBegin()
	database.ExpectQuery(`(?s)UPDATE execution_leases.*reconciliation_id = \$2.*reconciliation_actor = \$3.*status = 'UNCERTAIN'`).
		WithArgs(request.ExecutionID, request.ReconciliationID, request.ActorID, request.Status, request.ResultHash).
		WillReturnRows(rows)
}

func newPostgresRepository(t *testing.T) (pgxmock.PgxPoolIface, *executionpostgres.Repository, time.Time) {
	t.Helper()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	repository, err := executionpostgres.New(database, executionpostgres.Options{
		TokenSource: func() (string, error) {
			return "lease-token-01", nil
		},
	})
	if err != nil {
		database.Close()
		t.Fatalf("New() error = %v", err)
	}
	return database, repository, now
}

func executionRows(executions ...executionlease.Execution) *pgxmock.Rows {
	rows := pgxmock.NewRows(executionColumns)
	for _, execution := range executions {
		rows.AddRow(
			execution.ExecutionID, execution.TargetKey, string(execution.Pool), execution.Production, string(execution.Status),
			nullableString(execution.RunnerID), nullableString(execution.LeaseToken), execution.LeaseEpoch,
			nullableTime(execution.LeaseExpiresAt), nullableTime(execution.LeaseAcquiredAt), nullableTime(execution.LastHeartbeatAt),
			nullableTime(execution.StartedAt), nullableTime(execution.CompletedAt), nullableString(execution.ResultHash),
			execution.CreatedAt, execution.UpdatedAt,
			nullableString(execution.ReconciliationID), nullableString(execution.ReconciliationActor), nullableTime(execution.ReconciledAt),
		)
	}
	return rows
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableTime(value time.Time) any {
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
