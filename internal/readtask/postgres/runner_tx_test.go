package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executionlease"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

const (
	testTenantID        = "10000000-0000-4000-8000-000000000001"
	testWorkspaceID     = "20000000-0000-4000-8000-000000000001"
	testEnvironmentID   = "30000000-0000-4000-8000-000000000001"
	testServiceID       = "35000000-0000-4000-8000-000000000001"
	testIncidentID      = "40000000-0000-4000-8000-000000000001"
	testInvestigationID = "50000000-0000-4000-8000-000000000001"
	testTaskID          = "60000000-0000-4000-8000-000000000001"
	testRunnerID        = "read-runner-01"
	testLeaseToken      = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testCertificateHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testEvidenceID      = "70000000-0000-4000-8000-000000000001"
	testReceiptID       = "80000000-0000-4000-8000-000000000001"
)

func TestClaimRunnerTxRejectsWriteScopeBeforeTaskSQL(t *testing.T) {
	database, repository := newReadTaskRepository(t)
	tx := beginReadTaskTx(t, database)

	_, err := repository.ClaimRunnerTx(
		context.Background(), tx, testRunnerScope(t, executionlease.PoolWrite),
		readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: testNow().Add(time.Minute)},
		testTaskID, 30*time.Second,
	)
	if !errors.Is(err, readtask.ErrInvalidRequest) {
		t.Fatalf("ClaimRunnerTx(WRITE) error = %v, want ErrInvalidRequest", err)
	}
	rollbackReadTaskTx(t, database, tx)
}

func TestClaimRunnerTxBindsPersistedTaskExactScopeCertificateRuntimeAndHashedToken(t *testing.T) {
	database, repository := newReadTaskRepository(t)
	tx := beginReadTaskTx(t, database)
	now := testNow()
	leaseNow := now.Add(2 * time.Second)
	certificate := readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: now.Add(time.Minute)}
	descriptor, input := testDescriptorAndInput()
	tokenDigest := sha256.Sum256([]byte(testLeaseToken))

	database.ExpectExec(`SELECT pg_advisory_xact_lock\(hashtextextended\(\$1, 0\)\)`).
		WithArgs("read-task-runner:" + testTenantID + ":" + testRunnerID).
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	database.ExpectQuery(`(?s)SELECT .*FROM tool_invocations AS task.*JOIN investigations AS investigation.*WHERE task.tenant_id = \$1.*task.id = \$2.*FOR NO KEY UPDATE OF task`).
		WithArgs(testTenantID, testTaskID).
		WillReturnRows(pgxmock.NewRows(taskLockColumns()).AddRow(
			testTenantID, testWorkspaceID, testEnvironmentID, testServiceID, testIncidentID, testInvestigationID,
			testTaskID, "metrics.up", int16(1), descriptor.ConnectorID, "query_range",
			[]byte(input), descriptor.InputHash,
			descriptor.PlanBinding.SchemaVersion, descriptor.PlanBinding.ManifestDigest,
			descriptor.PlanBinding.RegistryDigest, descriptor.PlanBinding.ProfileDigest, descriptor.PlanBinding.TasksHash,
			descriptor.RuntimeBinding.SchemaVersion, descriptor.RuntimeBinding.ConnectorDigest,
			descriptor.RuntimeBinding.TargetDigest, descriptor.RuntimeBinding.ExecutorDigest,
			descriptor.RuntimeBinding.RuntimeDigest, descriptor.RuntimeBinding.BoundAt,
			"QUEUED", "QUEUED",
		))
	expectDatabaseClock(database, now)
	database.ExpectExec(`(?s)UPDATE investigation_task_attempts.*SET status = 'EXPIRED'.*lease_expires_at <= \$5`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, now).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectQuery(`(?s)SELECT EXISTS.*investigation_task_attempts.*runner_active.*max\(history.lease_epoch\)`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, testRunnerID, now).
		WillReturnRows(pgxmock.NewRows([]string{"task_active", "runner_active", "max_epoch", "last_terminal_at"}).
			AddRow(false, int64(0), int64(0), nil))
	expectDatabaseClock(database, leaseNow)
	leased := testAttempt(leaseNow, certificate, readtask.AttemptLeased)
	leased.LeaseExpiresAt = leaseNow.Add(30 * time.Second)
	database.ExpectQuery(`(?s)INSERT INTO investigation_task_attempts.*lease_token_sha256.*certificate_not_after.*'LEASED'.*RETURNING`).
		WithArgs(
			testTenantID, testWorkspaceID, testEnvironmentID, testInvestigationID, testTaskID,
			int64(1), hex.EncodeToString(tokenDigest[:]), testRunnerID, int64(7), testCertificateHash,
			certificate.NotAfter, leaseNow.Add(30*time.Second),
		).
		WillReturnRows(attemptRows(leased))

	claim, err := repository.ClaimRunnerTx(
		context.Background(), tx, testRunnerScope(t, executionlease.PoolRead), certificate, testTaskID, 30*time.Second,
	)
	if err != nil {
		var databaseFailure databaseOperationError
		if errors.As(err, &databaseFailure) {
			t.Fatalf("ClaimRunnerTx() error = %v (test cause: %v)", err, databaseFailure.cause)
		}
		t.Fatalf("ClaimRunnerTx() error = %v", err)
	}
	defer claim.Destroy()
	if !claim.Valid() || claim.Attempt().Epoch != 1 || claim.Attempt().ScopeRevision != 7 ||
		claim.Descriptor().WorkspaceID != testWorkspaceID || claim.Descriptor().EnvironmentID != testEnvironmentID ||
		!claim.Descriptor().PlanBinding.Equal(descriptor.PlanBinding) ||
		!claim.Descriptor().RuntimeBinding.Equal(descriptor.RuntimeBinding) ||
		!claim.Attempt().PlanBinding.Equal(descriptor.PlanBinding) ||
		!claim.Attempt().RuntimeBinding.Equal(descriptor.RuntimeBinding) ||
		claim.TokenSHA256() != hex.EncodeToString(tokenDigest[:]) {
		t.Fatalf("ClaimRunnerTx() = %s / %#v / %#v", claim.String(), claim.Descriptor(), claim.Attempt())
	}
	if strings.Contains(claim.String(), testLeaseToken) {
		t.Fatal("claim rendering leaked the lease token")
	}
	rollbackReadTaskTx(t, database, tx)
}

func TestClaimRunnerTxUnboundTaskIsInvisibleWithoutGeneratingToken(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	t.Cleanup(database.Close)
	tokenCalls := 0
	repository, err := New(database, Options{
		TokenSource: func() ([]byte, error) {
			tokenCalls++
			return make([]byte, 32), nil
		},
		IDSource: func() string { return testEvidenceID },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	tx := beginReadTaskTx(t, database)
	database.ExpectExec(`SELECT pg_advisory_xact_lock\(hashtextextended\(\$1, 0\)\)`).
		WithArgs("read-task-runner:" + testTenantID + ":" + testRunnerID).
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	database.ExpectQuery(`(?s)SELECT .*FROM tool_invocations AS task.*task.read_runtime_schema_version = 'read-task-runtime-binding.v1'.*investigation.request_hash_version = 'investigation.create.v2'.*investigation.plan_schema_version = 'investigation-plan-manifest.v1'.*FOR NO KEY UPDATE OF task`).
		WithArgs(testTenantID, testTaskID).
		WillReturnError(pgx.ErrNoRows)

	claim, err := repository.ClaimRunnerTx(
		context.Background(), tx, testRunnerScope(t, executionlease.PoolRead),
		readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: testNow().Add(time.Minute)},
		testTaskID, 30*time.Second,
	)
	if !errors.Is(err, readtask.ErrNotFound) || claim.Valid() || tokenCalls != 0 {
		t.Fatalf("ClaimRunnerTx(unbound) = %s, %v; token calls=%d", claim.String(), err, tokenCalls)
	}
	rollbackReadTaskTx(t, database, tx)
}

func TestStartRunnerAuthorizedTxLocksTaskAttemptParentAndTransitionsExactlyOnce(t *testing.T) {
	database, repository := newReadTaskRepository(t)
	tx := beginReadTaskTx(t, database)
	now := testNow()
	certificate := readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: now.Add(time.Minute)}
	descriptor, input := testDescriptorAndInput()
	fence, err := readtask.NewFence(testTaskID, testRunnerID, []byte(testLeaseToken), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Destroy()
	leased := testAttempt(now, certificate, readtask.AttemptLeased)
	running := leased
	running.Status = readtask.AttemptRunning
	running.StartedAt = now.Add(time.Second)
	running.UpdatedAt = running.StartedAt

	expectTaskLock(database, descriptor, input, "QUEUED", "QUEUED")
	database.ExpectQuery(`(?s)SELECT .*FROM investigation_task_attempts AS attempt.*WHERE attempt.tenant_id = \$1.*attempt.lease_epoch = \$5.*FOR UPDATE OF attempt`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1)).
		WillReturnRows(attemptRows(leased))
	database.ExpectQuery(`(?s)SELECT status.*FROM investigations.*FOR NO KEY UPDATE`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID).
		WillReturnRows(pgxmock.NewRows([]string{"status"}).AddRow("QUEUED"))
	expectDatabaseClock(database, now)
	database.ExpectQuery(`(?s)UPDATE investigation_task_attempts.*SET status = 'RUNNING'.*lease_expires_at > clock_timestamp\(\).*RETURNING`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1)).
		WillReturnRows(attemptRows(running))
	database.ExpectExec(`(?s)UPDATE tool_invocations.*SET status = 'RUNNING'.*status = 'QUEUED'`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	database.ExpectExec(`(?s)UPDATE investigations.*SET status = 'RUNNING'.*status = 'QUEUED'`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	got, err := repository.StartRunnerAuthorizedTx(
		context.Background(), tx, testRunnerScope(t, executionlease.PoolRead), certificate,
		readtask.Start{Fence: fence}, func(context.Context, readtask.Descriptor) error { return nil },
	)
	if err != nil || got.Status != readtask.AttemptRunning || got.StartedAt.IsZero() {
		t.Fatalf("StartRunnerAuthorizedTx() = %#v, %v", got, err)
	}
	rollbackReadTaskTx(t, database, tx)
}

func TestStartRunnerAuthorizedTxRequiresFinalTrustedAuthorizer(t *testing.T) {
	database, repository := newReadTaskRepository(t)
	tx := beginReadTaskTx(t, database)
	now := testNow()
	certificate := readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: now.Add(time.Minute)}
	fence, err := readtask.NewFence(testTaskID, testRunnerID, []byte(testLeaseToken), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Destroy()

	got, err := repository.StartRunnerAuthorizedTx(
		context.Background(), tx, testRunnerScope(t, executionlease.PoolRead), certificate,
		readtask.Start{Fence: fence}, nil,
	)
	if !errors.Is(err, readtask.ErrInvalidRequest) || got != (readtask.Attempt{}) {
		t.Fatalf("StartRunnerAuthorizedTx(nil) = %#v, %v", got, err)
	}
	rollbackReadTaskTx(t, database, tx)
}

func TestStartRunnerAuthorizedTxRechecksLeaseAfterAllLockWaits(t *testing.T) {
	database, repository := newReadTaskRepository(t)
	tx := beginReadTaskTx(t, database)
	base := testNow()
	certificate := readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: base.Add(time.Minute)}
	descriptor, input := testDescriptorAndInput()
	fence, err := readtask.NewFence(testTaskID, testRunnerID, []byte(testLeaseToken), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Destroy()
	running := testAttempt(base, certificate, readtask.AttemptRunning)
	running.StartedAt = base.Add(time.Second)
	running.UpdatedAt = running.StartedAt

	expectTaskLock(database, descriptor, input, "RUNNING", "RUNNING")
	database.ExpectQuery(`(?s)SELECT .*FROM investigation_task_attempts AS attempt.*FOR UPDATE OF attempt`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1)).
		WillReturnRows(attemptRows(running))
	database.ExpectQuery(`(?s)SELECT status.*FROM investigations.*FOR NO KEY UPDATE`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID).
		WillReturnRows(pgxmock.NewRows([]string{"status"}).AddRow("RUNNING"))
	expectDatabaseClock(database, running.LeaseExpiresAt)
	authorizerCalled := false

	got, err := repository.StartRunnerAuthorizedTx(
		context.Background(), tx, testRunnerScope(t, executionlease.PoolRead), certificate,
		readtask.Start{Fence: fence}, func(context.Context, readtask.Descriptor) error {
			authorizerCalled = true
			return nil
		},
	)
	if !errors.Is(err, readtask.ErrStaleFence) || got != (readtask.Attempt{}) || authorizerCalled {
		t.Fatalf("StartRunnerAuthorizedTx(expired after locks) = %#v, %v; authorizer=%t", got, err, authorizerCalled)
	}
	rollbackReadTaskTx(t, database, tx)
}

func TestStartRunnerAuthorizedTxRechecksRunningReplayLeaseAfterAuthorizer(t *testing.T) {
	database, repository := newReadTaskRepository(t)
	tx := beginReadTaskTx(t, database)
	base := testNow()
	certificate := readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: base.Add(time.Minute)}
	descriptor, input := testDescriptorAndInput()
	fence, err := readtask.NewFence(testTaskID, testRunnerID, []byte(testLeaseToken), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Destroy()
	running := testAttempt(base, certificate, readtask.AttemptRunning)
	running.StartedAt = base.Add(time.Second)
	running.UpdatedAt = running.StartedAt

	expectTaskLock(database, descriptor, input, "RUNNING", "RUNNING")
	database.ExpectQuery(`(?s)SELECT .*FROM investigation_task_attempts AS attempt.*FOR UPDATE OF attempt`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1)).
		WillReturnRows(attemptRows(running))
	database.ExpectQuery(`(?s)SELECT status.*FROM investigations.*FOR NO KEY UPDATE`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID).
		WillReturnRows(pgxmock.NewRows([]string{"status"}).AddRow("RUNNING"))
	expectDatabaseClock(database, running.LeaseExpiresAt.Add(-time.Nanosecond))
	expectDatabaseClock(database, running.LeaseExpiresAt)
	authorizerCalled := false

	got, err := repository.StartRunnerAuthorizedTx(
		context.Background(), tx, testRunnerScope(t, executionlease.PoolRead), certificate,
		readtask.Start{Fence: fence}, func(context.Context, readtask.Descriptor) error {
			authorizerCalled = true
			return nil
		},
	)
	if !errors.Is(err, readtask.ErrStaleFence) || got != (readtask.Attempt{}) || !authorizerCalled {
		t.Fatalf("StartRunnerAuthorizedTx(replay expired during authorizer) = %#v, %v; authorizer=%t", got, err, authorizerCalled)
	}
	rollbackReadTaskTx(t, database, tx)
}

func TestRunnerMutationEntrypointsClassifyCorruptLockedProjectionAsIntegrity(t *testing.T) {
	for _, test := range []struct {
		name                string
		status              readtask.AttemptStatus
		taskStatus          string
		investigationStatus string
		call                func(context.Context, *Repository, pgx.Tx, execution.RunnerScope, readtask.CertificateBinding, readtask.Fence) error
	}{
		{
			name: "start", status: readtask.AttemptLeased, taskStatus: "QUEUED", investigationStatus: "QUEUED",
			call: func(ctx context.Context, repository *Repository, tx pgx.Tx, scope execution.RunnerScope, certificate readtask.CertificateBinding, fence readtask.Fence) error {
				_, err := repository.StartRunnerAuthorizedTx(ctx, tx, scope, certificate, readtask.Start{Fence: fence},
					func(context.Context, readtask.Descriptor) error { return nil })
				return err
			},
		},
		{
			name: "heartbeat", status: readtask.AttemptRunning, taskStatus: "RUNNING", investigationStatus: "RUNNING",
			call: func(ctx context.Context, repository *Repository, tx pgx.Tx, scope execution.RunnerScope, certificate readtask.CertificateBinding, fence readtask.Fence) error {
				_, err := repository.HeartbeatRunnerTx(ctx, tx, scope, certificate,
					readtask.Heartbeat{Fence: fence, Sequence: 1}, 30*time.Second)
				return err
			},
		},
		{
			name: "release", status: readtask.AttemptLeased, taskStatus: "QUEUED", investigationStatus: "QUEUED",
			call: func(ctx context.Context, repository *Repository, tx pgx.Tx, scope execution.RunnerScope, certificate readtask.CertificateBinding, fence readtask.Fence) error {
				_, err := repository.ReleaseRunnerTx(ctx, tx, scope, certificate,
					readtask.Release{Fence: fence, ReasonCode: readtask.ReleaseConnectorNotReady})
				return err
			},
		},
		{
			name: "complete", status: readtask.AttemptRunning, taskStatus: "RUNNING", investigationStatus: "RUNNING",
			call: func(ctx context.Context, repository *Repository, tx pgx.Tx, scope execution.RunnerScope, certificate readtask.CertificateBinding, fence readtask.Fence) error {
				_, err := repository.CompleteRunnerAuthorizedTx(ctx, tx, scope, certificate, readtask.Completion{
					Fence: fence, Outcome: readtask.CompletionFailed, FailureCode: readtask.FailureTimeout,
				}, func(context.Context, readtask.Descriptor, readtask.EvidenceCompletion) error { return nil })
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, repository := newReadTaskRepository(t)
			tx := beginReadTaskTx(t, database)
			base := testNow()
			certificate := readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: base.Add(time.Minute)}
			descriptor, input := testDescriptorAndInput()
			attempt := testAttempt(base, certificate, test.status)
			if test.status == readtask.AttemptRunning {
				attempt.StartedAt = base
			}
			attempt.TokenSHA256 = "corrupt-persisted-token-hash"
			expectTaskLock(database, descriptor, input, test.taskStatus, test.investigationStatus)
			database.ExpectQuery(`(?s)SELECT .*FROM investigation_task_attempts AS attempt.*FOR UPDATE OF attempt`).
				WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1)).
				WillReturnRows(attemptRows(attempt))
			fence, err := readtask.NewFence(testTaskID, testRunnerID, []byte(testLeaseToken), 1)
			if err != nil {
				t.Fatal(err)
			}
			err = test.call(context.Background(), repository, tx, testRunnerScope(t, executionlease.PoolRead), certificate, fence)
			fence.Destroy()
			if !errors.Is(err, readtask.ErrIntegrity) || errors.Is(err, readtask.ErrStaleFence) {
				t.Fatalf("%s corrupt projection error = %v, want ErrIntegrity only", test.name, err)
			}
			rollbackReadTaskTx(t, database, tx)
		})
	}
}

func TestHeartbeatRunnerTxUsesStrictSequenceAndServerLeaseExtension(t *testing.T) {
	database, repository := newReadTaskRepository(t)
	tx := beginReadTaskTx(t, database)
	now := testNow()
	certificate := readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: now.Add(time.Minute)}
	descriptor, input := testDescriptorAndInput()
	fence, err := readtask.NewFence(testTaskID, testRunnerID, []byte(testLeaseToken), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Destroy()
	running := testAttempt(now, certificate, readtask.AttemptRunning)
	running.StartedAt = now
	updated := running
	updated.HeartbeatSequence = 1
	updated.LastHeartbeatAt = now.Add(time.Second)
	updated.LeaseExpiresAt = now.Add(31 * time.Second)
	updated.UpdatedAt = updated.LastHeartbeatAt

	expectTaskLock(database, descriptor, input, "RUNNING", "RUNNING")
	database.ExpectQuery(`(?s)SELECT .*FROM investigation_task_attempts AS attempt.*FOR UPDATE OF attempt`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1)).
		WillReturnRows(attemptRows(running))
	database.ExpectQuery(`(?s)SELECT status.*FROM investigations.*FOR NO KEY UPDATE`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID).
		WillReturnRows(pgxmock.NewRows([]string{"status"}).AddRow("RUNNING"))
	expectDatabaseClock(database, now.Add(time.Second))
	database.ExpectQuery(`(?s)UPDATE investigation_task_attempts.*heartbeat_seq = \$6.*GREATEST.*certificate_not_after.*RETURNING`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1), int64(1), float64(30)).
		WillReturnRows(attemptRows(updated))

	result, err := repository.HeartbeatRunnerTx(
		context.Background(), tx, testRunnerScope(t, executionlease.PoolRead), certificate,
		readtask.Heartbeat{Fence: fence, Sequence: 1}, 30*time.Second,
	)
	if err != nil || result.Directive != readtask.HeartbeatContinue || result.AcceptedSequence != 1 ||
		result.Attempt.HeartbeatSequence != 1 {
		t.Fatalf("HeartbeatRunnerTx() = %#v, %v", result, err)
	}
	rollbackReadTaskTx(t, database, tx)
}

func TestHeartbeatRunnerTxSameSequencePersistsTerminationAfterTrustDrift(t *testing.T) {
	database, repository := newReadTaskRepository(t)
	tx := beginReadTaskTx(t, database)
	base := testNow()
	certificate := readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: base.Add(time.Minute)}
	descriptor, input := testDescriptorAndInput()
	fence, err := readtask.NewFence(testTaskID, testRunnerID, []byte(testLeaseToken), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Destroy()
	running := testAttempt(base, certificate, readtask.AttemptRunning)
	running.StartedAt = base
	running.HeartbeatSequence = 4
	cancelled := running
	cancelled.Status = readtask.AttemptCancelled
	cancelled.TerminalAt = base.Add(time.Second)
	cancelled.UpdatedAt = cancelled.TerminalAt

	expectTaskLock(database, descriptor, input, "RUNNING", "RUNNING")
	database.ExpectQuery(`(?s)SELECT .*FROM investigation_task_attempts AS attempt.*FOR UPDATE OF attempt`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1)).
		WillReturnRows(attemptRows(running))
	database.ExpectQuery(`(?s)SELECT status.*FROM investigations.*FOR NO KEY UPDATE`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID).
		WillReturnRows(pgxmock.NewRows([]string{"status"}).AddRow("RUNNING"))
	expectDatabaseClock(database, base.Add(time.Second))
	database.ExpectQuery(`(?s)UPDATE investigation_task_attempts.*SET status = 'CANCELLED'.*status = 'RUNNING'.*RETURNING`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1)).
		WillReturnRows(attemptRows(cancelled))

	result, err := repository.HeartbeatRunnerTx(
		context.Background(), tx, testRunnerScopeRevision(t, executionlease.PoolRead, 8), certificate,
		readtask.Heartbeat{Fence: fence, Sequence: 4}, 30*time.Second,
	)
	if err != nil || result.Directive != readtask.HeartbeatTerminate || result.AcceptedSequence != 4 ||
		result.Attempt.Status != readtask.AttemptCancelled {
		t.Fatalf("HeartbeatRunnerTx(same sequence after trust drift) = %#v, %v", result, err)
	}
	rollbackReadTaskTx(t, database, tx)
}

func TestHeartbeatRunnerTxNextSequenceAtomicallyTerminatesAfterTrustDrift(t *testing.T) {
	database, repository := newReadTaskRepository(t)
	tx := beginReadTaskTx(t, database)
	base := testNow()
	certificate := readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: base.Add(time.Minute)}
	descriptor, input := testDescriptorAndInput()
	fence, err := readtask.NewFence(testTaskID, testRunnerID, []byte(testLeaseToken), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Destroy()
	running := testAttempt(base, certificate, readtask.AttemptRunning)
	running.StartedAt = base
	running.HeartbeatSequence = 4
	cancelled := running
	cancelled.Status = readtask.AttemptCancelled
	cancelled.HeartbeatSequence = 5
	cancelled.LastHeartbeatAt = base.Add(time.Second)
	cancelled.TerminalAt = cancelled.LastHeartbeatAt
	cancelled.UpdatedAt = cancelled.TerminalAt

	expectTaskLock(database, descriptor, input, "RUNNING", "RUNNING")
	database.ExpectQuery(`(?s)SELECT .*FROM investigation_task_attempts AS attempt.*FOR UPDATE OF attempt`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1)).
		WillReturnRows(attemptRows(running))
	database.ExpectQuery(`(?s)SELECT status.*FROM investigations.*FOR NO KEY UPDATE`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID).
		WillReturnRows(pgxmock.NewRows([]string{"status"}).AddRow("RUNNING"))
	expectDatabaseClock(database, base.Add(time.Second))
	database.ExpectQuery(`(?s)UPDATE investigation_task_attempts.*heartbeat_seq = \$6.*status = 'CANCELLED'.*heartbeat_seq \+ 1 = \$6.*RETURNING`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1), int64(5)).
		WillReturnRows(attemptRows(cancelled))

	result, err := repository.HeartbeatRunnerTx(
		context.Background(), tx, testRunnerScopeRevision(t, executionlease.PoolRead, 8), certificate,
		readtask.Heartbeat{Fence: fence, Sequence: 5}, 30*time.Second,
	)
	if err != nil || result.Directive != readtask.HeartbeatTerminate || result.AcceptedSequence != 5 ||
		result.Attempt.Status != readtask.AttemptCancelled {
		t.Fatalf("HeartbeatRunnerTx(next sequence after trust drift) = %#v, %v", result, err)
	}
	rollbackReadTaskTx(t, database, tx)
}

func TestReleaseRunnerTxOnlyTerminatesPreStartAttempt(t *testing.T) {
	database, repository := newReadTaskRepository(t)
	tx := beginReadTaskTx(t, database)
	now := testNow()
	certificate := readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: now.Add(time.Minute)}
	descriptor, input := testDescriptorAndInput()
	fence, err := readtask.NewFence(testTaskID, testRunnerID, []byte(testLeaseToken), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Destroy()
	leased := testAttempt(now, certificate, readtask.AttemptLeased)
	released := leased
	released.Status = readtask.AttemptReleased
	released.TerminalAt = now.Add(time.Second)
	released.UpdatedAt = released.TerminalAt

	expectTaskLock(database, descriptor, input, "QUEUED", "QUEUED")
	database.ExpectQuery(`(?s)SELECT .*FROM investigation_task_attempts AS attempt.*FOR UPDATE OF attempt`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1)).
		WillReturnRows(attemptRows(leased))
	expectDatabaseClock(database, now.Add(time.Second))
	database.ExpectQuery(`(?s)UPDATE investigation_task_attempts.*SET status = 'RELEASED'.*RETURNING`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1)).
		WillReturnRows(attemptRows(released))

	result, err := repository.ReleaseRunnerTx(
		context.Background(), tx, testRunnerScope(t, executionlease.PoolRead), certificate,
		readtask.Release{Fence: fence, ReasonCode: readtask.ReleaseConnectorNotReady},
	)
	if err != nil || result.Status != readtask.AttemptReleased || result.TerminalAt.IsZero() {
		t.Fatalf("ReleaseRunnerTx() = %#v, %v", result, err)
	}
	rollbackReadTaskTx(t, database, tx)
}

func TestCompleteRunnerAuthorizedTxAtomicallyPersistsEvidenceTaskAttemptAndV3Receipt(t *testing.T) {
	database, repository := newReadTaskRepository(t)
	tx := beginReadTaskTx(t, database)
	now := testNow().Add(2 * time.Second)
	certificate := readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: now.Add(time.Minute)}
	descriptor, input := testDescriptorAndInput()
	fence, err := readtask.NewFence(testTaskID, testRunnerID, []byte(testLeaseToken), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Destroy()
	running := testAttempt(now.Add(-2*time.Second), certificate, readtask.AttemptRunning)
	running.StartedAt = now.Add(-time.Second)
	running.UpdatedAt = running.StartedAt
	running.LeaseExpiresAt = now.Add(30 * time.Second)
	completion := readtask.Completion{
		Fence: fence, Outcome: readtask.CompletionEvidence,
		Evidence: &readtask.EvidenceCompletion{
			CollectedAt: now.Add(-500 * time.Millisecond),
			Items:       []json.RawMessage{json.RawMessage(`{"status":"healthy","value":1}`)},
		},
	}
	projection, err := readtask.ProjectCompletion(descriptor, running, completion, now)
	if err != nil {
		t.Fatalf("ProjectCompletion() error = %v", err)
	}
	completed := running
	completed.Status = readtask.AttemptCompleted
	completed.TerminalAt = now.Add(time.Millisecond)
	completed.UpdatedAt = completed.TerminalAt
	completed.RequestHash = projection.RequestHash()
	completed.ReceiptHash = projection.ReceiptHash()
	completed.RequestHashVersion = readtask.CompletionRequestHashVersionV3
	completed.ReceiptHashVersion = readtask.CompletionReceiptHashVersionV3

	expectTaskLock(database, descriptor, input, "RUNNING", "RUNNING")
	database.ExpectQuery(`(?s)SELECT .*FROM investigation_task_attempts AS attempt.*FOR UPDATE OF attempt`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1)).
		WillReturnRows(attemptRows(running))
	database.ExpectQuery(`(?s)SELECT status.*FROM investigations.*FOR NO KEY UPDATE`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID).
		WillReturnRows(pgxmock.NewRows([]string{"status"}).AddRow("RUNNING"))
	expectDatabaseClock(database, now)
	database.ExpectQuery(`(?s)INSERT INTO evidence .*payload_document.*runtime_schema_version.*RETURNING created_at`).
		WithArgs(
			testEvidenceID, testTenantID, testWorkspaceID, testInvestigationID, descriptor.ConnectorID,
			pgxmock.AnyArg(), projection.CollectedAt(), pgxmock.AnyArg(), projection.ContentHash(),
			false, testIncidentID, testTaskID, []byte(projection.Payload()), pgxmock.AnyArg(),
		).
		WillReturnRows(pgxmock.NewRows([]string{"created_at"}).AddRow(now.Add(time.Millisecond)))
	database.ExpectExec(`(?s)UPDATE tool_invocations.*SET status = \$5, evidence_id = \$6, output_hash = \$7`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, "EVIDENCE", testEvidenceID, projection.ContentHash(), nil).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	database.ExpectQuery(`(?s)UPDATE investigation_task_attempts.*status = 'COMPLETED'.*request_hash = \$6.*receipt_hash = \$7.*request_hash_version = \$8.*receipt_hash_version = \$9.*RETURNING`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1),
			projection.RequestHash(), projection.ReceiptHash(),
			readtask.CompletionRequestHashVersionV3, readtask.CompletionReceiptHashVersionV3).
		WillReturnRows(attemptRows(completed))
	database.ExpectQuery(`(?s)INSERT INTO runner_evidence_receipts .*request_hash_version.*receipt_hash_version.*'read-task-completion-request.v3'.*'read-task-completion-receipt.v3'.*'runner-evidence.v3'.*RETURNING received_at`).
		WithArgs(
			testReceiptID, testTenantID, testWorkspaceID, testEnvironmentID, testInvestigationID, testTaskID,
			testRunnerID, int64(7), testCertificateHash, descriptor.ConnectorID, testEvidenceID,
			projection.ContentHash(), nil, projection.IdempotencyKey(), projection.RequestHash(),
			projection.ReceiptHash(), int64(1),
		).
		WillReturnRows(pgxmock.NewRows([]string{"received_at"}).AddRow(now.Add(time.Millisecond)))

	authorizerCalled := false
	result, err := repository.CompleteRunnerAuthorizedTx(
		context.Background(), tx, testRunnerScope(t, executionlease.PoolRead), certificate, completion,
		func(_ context.Context, gotDescriptor readtask.Descriptor, gotEvidence readtask.EvidenceCompletion) error {
			authorizerCalled = true
			if gotDescriptor.TaskID != descriptor.TaskID || len(gotEvidence.Items) != 1 ||
				string(gotEvidence.Items[0]) != `{"status":"healthy","value":1}` {
				t.Fatalf("completion authorizer received %#v / %#v", gotDescriptor, gotEvidence)
			}
			// The trusted contract receives detached data and cannot rewrite the
			// projection that will be persisted.
			gotDescriptor.Input[0] = '['
			gotEvidence.Items[0][0] = '['
			return nil
		},
	)
	if err != nil || !authorizerCalled || result.Replayed || result.EvidenceID != testEvidenceID || result.ReceiptID != testReceiptID ||
		result.Attempt.Status != readtask.AttemptCompleted || result.Projection.ReceiptHash() != projection.ReceiptHash() {
		t.Fatalf("CompleteRunnerAuthorizedTx() = %#v, %v; authorizer=%t", result, err, authorizerCalled)
	}
	rollbackReadTaskTx(t, database, tx)
}

func TestCompleteRunnerAuthorizedTxReplaysOriginalReceiptWithoutMutablePolicy(t *testing.T) {
	database, repository := newReadTaskRepository(t)
	tx := beginReadTaskTx(t, database)
	base := testNow()
	certificate := readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: base.Add(time.Minute)}
	descriptor, input := testDescriptorAndInput()
	fence, err := readtask.NewFence(testTaskID, testRunnerID, []byte(testLeaseToken), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Destroy()
	running := testAttempt(base, certificate, readtask.AttemptRunning)
	running.StartedAt = base.Add(time.Second)
	running.UpdatedAt = running.StartedAt
	completion := readtask.Completion{
		Fence: fence, Outcome: readtask.CompletionEvidence,
		Evidence: &readtask.EvidenceCompletion{
			CollectedAt: base.Add(1500 * time.Millisecond),
			Items:       []json.RawMessage{json.RawMessage(`{"status":"healthy"}`)},
		},
	}
	projection, err := readtask.ProjectCompletion(descriptor, running, completion, base.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	completed := running
	completed.Status = readtask.AttemptCompleted
	completed.TerminalAt = base.Add(2500 * time.Millisecond)
	completed.UpdatedAt = completed.TerminalAt
	completed.RequestHash = projection.RequestHash()
	completed.ReceiptHash = projection.ReceiptHash()
	completed.RequestHashVersion = readtask.CompletionRequestHashVersionV3
	completed.ReceiptHashVersion = readtask.CompletionReceiptHashVersionV3

	expectTaskLock(database, descriptor, input, "EVIDENCE", "RUNNING")
	database.ExpectQuery(`(?s)SELECT .*FROM investigation_task_attempts AS attempt.*FOR UPDATE OF attempt`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1)).
		WillReturnRows(attemptRows(completed))
	database.ExpectQuery(`(?s)SELECT status.*FROM investigations.*FOR NO KEY UPDATE`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID).
		WillReturnRows(pgxmock.NewRows([]string{"status"}).AddRow("RUNNING"))
	expectDatabaseClock(database, base.Add(5*time.Second))
	database.ExpectQuery(`(?s)SELECT receipt.id::text.*FROM runner_evidence_receipts AS receipt.*receipt.schema_version = 'runner-evidence.v3'.*receipt.request_hash_version = 'read-task-completion-request.v3'.*receipt.receipt_hash_version = 'read-task-completion-receipt.v3'.*receipt.runtime_bound_at = \$19.*FOR SHARE OF receipt`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, testRunnerID,
			int64(1), projection.RequestHash(), projection.ReceiptHash(),
			descriptor.PlanBinding.SchemaVersion, descriptor.PlanBinding.ManifestDigest,
			descriptor.PlanBinding.RegistryDigest, descriptor.PlanBinding.ProfileDigest, descriptor.PlanBinding.TasksHash,
			descriptor.RuntimeBinding.SchemaVersion, descriptor.RuntimeBinding.ConnectorDigest,
			descriptor.RuntimeBinding.TargetDigest, descriptor.RuntimeBinding.ExecutorDigest,
			descriptor.RuntimeBinding.RuntimeDigest, descriptor.RuntimeBinding.BoundAt).
		WillReturnRows(pgxmock.NewRows([]string{"id", "evidence_id", "received_at"}).
			AddRow(testReceiptID, testEvidenceID, base.Add(3*time.Second)))

	result, err := repository.CompleteRunnerAuthorizedTx(
		context.Background(), tx, testRunnerScope(t, executionlease.PoolRead), certificate, completion,
		func(context.Context, readtask.Descriptor, readtask.EvidenceCompletion) error {
			t.Fatal("committed replay re-ran mutable completion policy")
			return errors.New("policy changed")
		},
	)
	if err != nil || !result.Replayed || result.EvidenceID != testEvidenceID || result.ReceiptID != testReceiptID {
		t.Fatalf("CompleteRunnerAuthorizedTx(replay) = %#v, %v", result, err)
	}
	rollbackReadTaskTx(t, database, tx)
}

func TestCompleteRunnerAuthorizedTxRejectsTypedOutputBeforeAnyEvidenceWrite(t *testing.T) {
	database, repository := newReadTaskRepository(t)
	tx := beginReadTaskTx(t, database)
	now := testNow().Add(2 * time.Second)
	certificate := readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: now.Add(time.Minute)}
	descriptor, input := testDescriptorAndInput()
	fence, err := readtask.NewFence(testTaskID, testRunnerID, []byte(testLeaseToken), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Destroy()
	running := testAttempt(now.Add(-2*time.Second), certificate, readtask.AttemptRunning)
	running.StartedAt = now.Add(-time.Second)
	running.UpdatedAt = running.StartedAt
	running.LeaseExpiresAt = now.Add(30 * time.Second)
	completion := readtask.Completion{
		Fence: fence, Outcome: readtask.CompletionEvidence,
		Evidence: &readtask.EvidenceCompletion{
			CollectedAt: now.Add(-500 * time.Millisecond),
			Items:       []json.RawMessage{json.RawMessage(`{"unexpected_shape":true}`)},
		},
	}

	expectTaskLock(database, descriptor, input, "RUNNING", "RUNNING")
	database.ExpectQuery(`(?s)SELECT .*FROM investigation_task_attempts AS attempt.*FOR UPDATE OF attempt`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1)).
		WillReturnRows(attemptRows(running))
	database.ExpectQuery(`(?s)SELECT status.*FROM investigations.*FOR NO KEY UPDATE`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID).
		WillReturnRows(pgxmock.NewRows([]string{"status"}).AddRow("RUNNING"))
	expectDatabaseClock(database, now)

	result, err := repository.CompleteRunnerAuthorizedTx(
		context.Background(), tx, testRunnerScope(t, executionlease.PoolRead), certificate, completion,
		func(_ context.Context, gotDescriptor readtask.Descriptor, gotEvidence readtask.EvidenceCompletion) error {
			if gotDescriptor.ConnectorID != descriptor.ConnectorID || len(gotEvidence.Items) != 1 {
				t.Fatalf("typed output authorizer received %#v / %#v", gotDescriptor, gotEvidence)
			}
			return errors.New("connector schema detail canary")
		},
	)
	if !errors.Is(err, readtask.ErrProjectionRejected) || err.Error() != readtask.ErrProjectionRejected.Error() ||
		result.Attempt.TaskID != "" || result.EvidenceID != "" || result.ReceiptID != "" {
		t.Fatalf("CompleteRunnerAuthorizedTx(rejected output) = %#v, %v", result, err)
	}
	rollbackReadTaskTx(t, database, tx)
}

func TestCompleteRunnerAuthorizedTxRejectsMissingTypedContractBeforeDatabaseAccess(t *testing.T) {
	database, repository := newReadTaskRepository(t)
	result, err := repository.CompleteRunnerAuthorizedTx(
		context.Background(), nil, execution.RunnerScope{}, readtask.CertificateBinding{}, readtask.Completion{}, nil,
	)
	if !errors.Is(err, readtask.ErrInvalidRequest) || result.Attempt.TaskID != "" ||
		result.EvidenceID != "" || result.ReceiptID != "" || result.Replayed {
		t.Fatalf("CompleteRunnerAuthorizedTx(nil authorizer) = %#v, %v", result, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("missing contract accessed database: %v", err)
	}
}

func TestProjectRunnerCompletionClassifiesChangedCommittedReplayByHash(t *testing.T) {
	base := testNow()
	certificate := readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: base.Add(time.Minute)}
	descriptor, _ := testDescriptorAndInput()
	fence, err := readtask.NewFence(testTaskID, testRunnerID, []byte(testLeaseToken), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Destroy()
	running := testAttempt(base, certificate, readtask.AttemptRunning)
	running.StartedAt = base
	completion := readtask.Completion{
		Fence: fence, Outcome: readtask.CompletionEvidence,
		Evidence: &readtask.EvidenceCompletion{
			CollectedAt: base.Add(time.Second), Items: []json.RawMessage{json.RawMessage(`{"value":1}`)},
		},
	}
	original, err := projectRunnerCompletion(descriptor, running, completion, base.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	completed := running
	completed.Status = readtask.AttemptCompleted
	completed.TerminalAt = base.Add(2 * time.Second)
	completed.UpdatedAt = completed.TerminalAt
	completed.RequestHash = original.RequestHash()
	completed.ReceiptHash = original.ReceiptHash()
	completed.RequestHashVersion = readtask.CompletionRequestHashVersionV3
	completed.ReceiptHashVersion = readtask.CompletionReceiptHashVersionV3

	same, err := projectRunnerCompletion(descriptor, completed, completion, base.Add(5*time.Second))
	if err != nil || same.RequestHash() != original.RequestHash() || same.ReceiptHash() != original.ReceiptHash() {
		t.Fatalf("same committed replay projection = %#v, %v", same.Receipt(), err)
	}
	changed := completion
	changed.Evidence = &readtask.EvidenceCompletion{
		CollectedAt: base.Add(time.Second), Items: []json.RawMessage{json.RawMessage(`{"value":2}`)},
	}
	different, err := projectRunnerCompletion(descriptor, completed, changed, base.Add(5*time.Second))
	if err != nil || different.RequestHash() == original.RequestHash() || different.ReceiptHash() == original.ReceiptHash() {
		t.Fatalf("changed committed replay projection = %#v, %v", different.Receipt(), err)
	}
}

func newReadTaskRepository(t *testing.T) (pgxmock.PgxPoolIface, *Repository) {
	t.Helper()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	t.Cleanup(database.Close)
	ids := []string{testEvidenceID, testReceiptID}
	idIndex := 0
	repository, err := New(database, Options{
		TokenSource: func() ([]byte, error) { return make([]byte, 32), nil },
		IDSource: func() string {
			if idIndex >= len(ids) {
				return "90000000-0000-4000-8000-000000000001"
			}
			id := ids[idIndex]
			idIndex++
			return id
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return database, repository
}

func beginReadTaskTx(t *testing.T, database pgxmock.PgxPoolIface) pgx.Tx {
	t.Helper()
	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	return tx
}

func rollbackReadTaskTx(t *testing.T, database pgxmock.PgxPoolIface, tx pgx.Tx) {
	t.Helper()
	database.ExpectRollback()
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet PostgreSQL expectations: %v", err)
	}
}

func testRunnerScope(t *testing.T, pool executionlease.Pool) execution.RunnerScope {
	return testRunnerScopeRevision(t, pool, 7)
}

func testRunnerScopeRevision(t *testing.T, pool executionlease.Pool, revision int64) execution.RunnerScope {
	t.Helper()
	scope, err := (execution.RunnerRegistration{
		RunnerID: testRunnerID, TenantID: testTenantID, Pool: pool, Enabled: true,
		ScopeRevision: revision, MaxConcurrency: 2,
		ScopeBindings: []execution.RunnerScopeBinding{{WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID}},
	}).Scope()
	if err != nil {
		t.Fatalf("RunnerRegistration.Scope() error = %v", err)
	}
	return scope
}

func testNow() time.Time {
	return time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
}

func testDescriptorAndInput() (readtask.Descriptor, json.RawMessage) {
	input := json.RawMessage(`{"query":"up","window_seconds":300}`)
	digest := sha256.Sum256(input)
	connectorDigest := strings.Repeat("a", 64)
	descriptor := readtask.Descriptor{
		TenantID: testTenantID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID,
		ServiceID:  testServiceID,
		IncidentID: testIncidentID, InvestigationID: testInvestigationID, TaskID: testTaskID,
		TaskKey: "metrics.up", Position: 1,
		ConnectorID: "prometheus-staging-v1-" + connectorDigest, Operation: "query_range",
		Input: input, InputHash: hex.EncodeToString(digest[:]),
		PlanBinding: domain.InvestigationPlanBinding{
			SchemaVersion:  domain.InvestigationPlanBindingSchemaVersion,
			ManifestDigest: strings.Repeat("b", 64), RegistryDigest: strings.Repeat("c", 64),
			ProfileDigest: strings.Repeat("d", 64), TasksHash: strings.Repeat("e", 64),
		},
		RuntimeBinding: domain.ReadTaskRuntimeBinding{
			SchemaVersion: domain.ReadTaskRuntimeBindingSchemaVersion, ConnectorDigest: connectorDigest,
			TargetDigest: strings.Repeat("f", 64), ExecutorDigest: strings.Repeat("1", 64),
			RuntimeDigest: strings.Repeat("2", 64), BoundAt: testNow().Add(-time.Minute),
		},
	}
	runtimeDigest, err := investigation.ReadTaskRuntimeDigest(
		investigation.TaskSpecScope{
			TenantID: descriptor.TenantID, WorkspaceID: descriptor.WorkspaceID,
			EnvironmentID: descriptor.EnvironmentID, ServiceID: descriptor.ServiceID,
			MappingStatus: domain.MappingExact,
		}, descriptor.PlanBinding,
		investigation.TaskSpec{
			Key: descriptor.TaskKey, ConnectorID: descriptor.ConnectorID,
			Operation: descriptor.Operation, Input: append(json.RawMessage(nil), descriptor.Input...),
		}, descriptor.Position,
		investigation.TaskRuntimeComponents{
			ConnectorDigest: descriptor.RuntimeBinding.ConnectorDigest,
			TargetDigest:    descriptor.RuntimeBinding.TargetDigest,
			ExecutorDigest:  descriptor.RuntimeBinding.ExecutorDigest,
		},
	)
	if err != nil {
		panic(err)
	}
	descriptor.RuntimeBinding.RuntimeDigest = runtimeDigest
	return descriptor, input
}

func expectTaskLock(
	database pgxmock.PgxPoolIface,
	descriptor readtask.Descriptor,
	input json.RawMessage,
	taskStatus, investigationStatus string,
) {
	database.ExpectQuery(`(?s)SELECT .*FROM tool_invocations AS task.*JOIN investigations AS investigation.*WHERE task.tenant_id = \$1.*task.id = \$2.*FOR NO KEY UPDATE OF task`).
		WithArgs(testTenantID, testTaskID).
		WillReturnRows(pgxmock.NewRows(taskLockColumns()).AddRow(
			descriptor.TenantID, descriptor.WorkspaceID, descriptor.EnvironmentID, descriptor.ServiceID, descriptor.IncidentID,
			descriptor.InvestigationID, descriptor.TaskID, descriptor.TaskKey, int16(descriptor.Position),
			descriptor.ConnectorID, descriptor.Operation, []byte(input), descriptor.InputHash,
			descriptor.PlanBinding.SchemaVersion, descriptor.PlanBinding.ManifestDigest,
			descriptor.PlanBinding.RegistryDigest, descriptor.PlanBinding.ProfileDigest, descriptor.PlanBinding.TasksHash,
			descriptor.RuntimeBinding.SchemaVersion, descriptor.RuntimeBinding.ConnectorDigest,
			descriptor.RuntimeBinding.TargetDigest, descriptor.RuntimeBinding.ExecutorDigest,
			descriptor.RuntimeBinding.RuntimeDigest, descriptor.RuntimeBinding.BoundAt,
			taskStatus, investigationStatus,
		))
}

func expectDatabaseClock(database pgxmock.PgxPoolIface, now time.Time) {
	database.ExpectQuery(`SELECT clock_timestamp\(\)`).
		WillReturnRows(pgxmock.NewRows([]string{"clock_timestamp"}).AddRow(now))
}

func testAttempt(now time.Time, certificate readtask.CertificateBinding, status readtask.AttemptStatus) readtask.Attempt {
	digest := sha256.Sum256([]byte(testLeaseToken))
	descriptor, _ := testDescriptorAndInput()
	return readtask.Attempt{
		TaskID: testTaskID, RunnerID: testRunnerID, ScopeRevision: 7, Certificate: certificate,
		TokenSHA256: hex.EncodeToString(digest[:]), Epoch: 1, Status: status,
		PlanBinding: descriptor.PlanBinding, RuntimeBinding: descriptor.RuntimeBinding,
		LeaseAcquiredAt: now, LastHeartbeatAt: now, LeaseExpiresAt: now.Add(30 * time.Second), UpdatedAt: now,
	}
}

func attemptRows(attempt readtask.Attempt) *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"task_id", "runner_id", "scope_revision", "certificate_sha256", "certificate_not_after",
		"lease_token_sha256", "lease_epoch", "status", "heartbeat_seq", "lease_acquired_at",
		"last_heartbeat_at", "lease_expires_at", "started_at", "terminal_at", "request_hash", "receipt_hash",
		"request_hash_version", "receipt_hash_version",
		"plan_schema_version", "plan_manifest_digest", "plan_registry_digest", "plan_profile_digest", "plan_tasks_hash",
		"read_runtime_schema_version", "connector_digest", "target_digest", "executor_digest", "runtime_digest", "runtime_bound_at",
		"updated_at",
	}).AddRow(
		attempt.TaskID, attempt.RunnerID, attempt.ScopeRevision, attempt.Certificate.SHA256, attempt.Certificate.NotAfter,
		attempt.TokenSHA256, attempt.Epoch, attempt.Status, attempt.HeartbeatSequence, attempt.LeaseAcquiredAt,
		attempt.LastHeartbeatAt, attempt.LeaseExpiresAt, nullableTime(attempt.StartedAt), nullableTime(attempt.TerminalAt),
		nullableString(attempt.RequestHash), nullableString(attempt.ReceiptHash),
		nullableString(attempt.RequestHashVersion), nullableString(attempt.ReceiptHashVersion),
		attempt.PlanBinding.SchemaVersion, attempt.PlanBinding.ManifestDigest, attempt.PlanBinding.RegistryDigest,
		attempt.PlanBinding.ProfileDigest, attempt.PlanBinding.TasksHash,
		attempt.RuntimeBinding.SchemaVersion, attempt.RuntimeBinding.ConnectorDigest, attempt.RuntimeBinding.TargetDigest,
		attempt.RuntimeBinding.ExecutorDigest, attempt.RuntimeBinding.RuntimeDigest, attempt.RuntimeBinding.BoundAt,
		attempt.UpdatedAt,
	)
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func taskLockColumns() []string {
	return []string{
		"tenant_id", "workspace_id", "environment_id", "service_id", "incident_id", "investigation_id",
		"task_id", "task_key", "position", "connector_id", "operation", "input_document", "input_hash",
		"plan_schema_version", "plan_manifest_digest", "plan_registry_digest", "plan_profile_digest", "plan_tasks_hash",
		"read_runtime_schema_version", "connector_digest", "target_digest", "executor_digest", "runtime_digest", "runtime_bound_at",
		"task_status", "investigation_status",
	}
}
