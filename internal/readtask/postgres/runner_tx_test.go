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
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executionlease"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

const (
	testTenantID        = "10000000-0000-4000-8000-000000000001"
	testWorkspaceID     = "20000000-0000-4000-8000-000000000001"
	testEnvironmentID   = "30000000-0000-4000-8000-000000000001"
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

func TestClaimRunnerTxBindsPersistedTaskExactScopeCertificateAndHashedToken(t *testing.T) {
	database, repository := newReadTaskRepository(t)
	tx := beginReadTaskTx(t, database)
	now := testNow()
	leaseNow := now.Add(2 * time.Second)
	certificate := readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: now.Add(time.Minute)}
	input := json.RawMessage(`{"query":"up","window_seconds":300}`)
	inputDigest := sha256.Sum256(input)
	tokenDigest := sha256.Sum256([]byte(testLeaseToken))

	database.ExpectExec(`SELECT pg_advisory_xact_lock\(hashtextextended\(\$1, 0\)\)`).
		WithArgs("read-task-runner:" + testTenantID + ":" + testRunnerID).
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	database.ExpectQuery(`(?s)SELECT .*FROM tool_invocations AS task.*JOIN investigations AS investigation.*WHERE task.tenant_id = \$1.*task.id = \$2.*FOR NO KEY UPDATE OF task`).
		WithArgs(testTenantID, testTaskID).
		WillReturnRows(pgxmock.NewRows(taskLockColumns()).AddRow(
			testTenantID, testWorkspaceID, testEnvironmentID, testIncidentID, testInvestigationID,
			testTaskID, "metrics.up", int16(1), "prometheus-staging", "query_range",
			[]byte(input), hex.EncodeToString(inputDigest[:]), "QUEUED", "QUEUED",
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
	database.ExpectQuery(`(?s)INSERT INTO investigation_task_attempts.*lease_token_sha256.*certificate_not_after.*'LEASED'.*RETURNING`).
		WithArgs(
			testTenantID, testWorkspaceID, testEnvironmentID, testInvestigationID, testTaskID,
			int64(1), hex.EncodeToString(tokenDigest[:]), testRunnerID, int64(7), testCertificateHash,
			certificate.NotAfter, leaseNow.Add(30*time.Second),
		).
		WillReturnRows(pgxmock.NewRows([]string{
			"lease_acquired_at", "last_heartbeat_at", "lease_expires_at", "certificate_not_after", "updated_at",
		}).AddRow(leaseNow, leaseNow, leaseNow.Add(30*time.Second), certificate.NotAfter, leaseNow))

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
		claim.TokenSHA256() != hex.EncodeToString(tokenDigest[:]) {
		t.Fatalf("ClaimRunnerTx() = %s / %#v / %#v", claim.String(), claim.Descriptor(), claim.Attempt())
	}
	if strings.Contains(claim.String(), testLeaseToken) {
		t.Fatal("claim rendering leaked the lease token")
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

func TestCompleteRunnerTxAtomicallyPersistsEvidenceTaskAttemptAndV2Receipt(t *testing.T) {
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
	database.ExpectQuery(`(?s)UPDATE investigation_task_attempts.*status = 'COMPLETED'.*request_hash = \$6.*receipt_hash = \$7.*RETURNING`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1), projection.RequestHash(), projection.ReceiptHash()).
		WillReturnRows(attemptRows(completed))
	database.ExpectQuery(`(?s)INSERT INTO runner_evidence_receipts .*'runner-evidence.v2'.*RETURNING received_at`).
		WithArgs(
			testReceiptID, testTenantID, testWorkspaceID, testEnvironmentID, testInvestigationID, testTaskID,
			testRunnerID, int64(7), testCertificateHash, descriptor.ConnectorID, testEvidenceID,
			projection.ContentHash(), nil, projection.IdempotencyKey(), projection.RequestHash(),
			projection.ReceiptHash(), int64(1),
		).
		WillReturnRows(pgxmock.NewRows([]string{"received_at"}).AddRow(now.Add(time.Millisecond)))

	result, err := repository.CompleteRunnerTx(
		context.Background(), tx, testRunnerScope(t, executionlease.PoolRead), certificate, completion,
	)
	if err != nil || result.Replayed || result.EvidenceID != testEvidenceID || result.ReceiptID != testReceiptID ||
		result.Attempt.Status != readtask.AttemptCompleted || result.Projection.ReceiptHash() != projection.ReceiptHash() {
		t.Fatalf("CompleteRunnerTx() = %#v, %v", result, err)
	}
	rollbackReadTaskTx(t, database, tx)
}

func TestCompleteRunnerTxReplaysOriginalReceiptWithoutAnotherWrite(t *testing.T) {
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

	expectTaskLock(database, descriptor, input, "EVIDENCE", "RUNNING")
	database.ExpectQuery(`(?s)SELECT .*FROM investigation_task_attempts AS attempt.*FOR UPDATE OF attempt`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, int64(1)).
		WillReturnRows(attemptRows(completed))
	database.ExpectQuery(`(?s)SELECT status.*FROM investigations.*FOR NO KEY UPDATE`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID).
		WillReturnRows(pgxmock.NewRows([]string{"status"}).AddRow("RUNNING"))
	expectDatabaseClock(database, base.Add(5*time.Second))
	database.ExpectQuery(`(?s)SELECT receipt.id::text.*FROM runner_evidence_receipts AS receipt.*FOR SHARE OF receipt`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, testRunnerID,
			int64(1), projection.RequestHash(), projection.ReceiptHash()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "evidence_id", "received_at"}).
			AddRow(testReceiptID, testEvidenceID, base.Add(3*time.Second)))

	result, err := repository.CompleteRunnerTx(
		context.Background(), tx, testRunnerScope(t, executionlease.PoolRead), certificate, completion,
	)
	if err != nil || !result.Replayed || result.EvidenceID != testEvidenceID || result.ReceiptID != testReceiptID {
		t.Fatalf("CompleteRunnerTx(replay) = %#v, %v", result, err)
	}
	rollbackReadTaskTx(t, database, tx)
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
	return readtask.Descriptor{
		TenantID: testTenantID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID,
		IncidentID: testIncidentID, InvestigationID: testInvestigationID, TaskID: testTaskID,
		TaskKey: "metrics.up", Position: 1, ConnectorID: "prometheus-staging", Operation: "query_range",
		Input: input, InputHash: hex.EncodeToString(digest[:]),
	}, input
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
			descriptor.TenantID, descriptor.WorkspaceID, descriptor.EnvironmentID, descriptor.IncidentID,
			descriptor.InvestigationID, descriptor.TaskID, descriptor.TaskKey, int16(descriptor.Position),
			descriptor.ConnectorID, descriptor.Operation, []byte(input), descriptor.InputHash,
			taskStatus, investigationStatus,
		))
}

func expectDatabaseClock(database pgxmock.PgxPoolIface, now time.Time) {
	database.ExpectQuery(`SELECT clock_timestamp\(\)`).
		WillReturnRows(pgxmock.NewRows([]string{"clock_timestamp"}).AddRow(now))
}

func testAttempt(now time.Time, certificate readtask.CertificateBinding, status readtask.AttemptStatus) readtask.Attempt {
	digest := sha256.Sum256([]byte(testLeaseToken))
	return readtask.Attempt{
		TaskID: testTaskID, RunnerID: testRunnerID, ScopeRevision: 7, Certificate: certificate,
		TokenSHA256: hex.EncodeToString(digest[:]), Epoch: 1, Status: status,
		LeaseAcquiredAt: now, LastHeartbeatAt: now, LeaseExpiresAt: now.Add(30 * time.Second), UpdatedAt: now,
	}
}

func attemptRows(attempt readtask.Attempt) *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"task_id", "runner_id", "scope_revision", "certificate_sha256", "certificate_not_after",
		"lease_token_sha256", "lease_epoch", "status", "heartbeat_seq", "lease_acquired_at",
		"last_heartbeat_at", "lease_expires_at", "started_at", "terminal_at", "request_hash", "receipt_hash", "updated_at",
	}).AddRow(
		attempt.TaskID, attempt.RunnerID, attempt.ScopeRevision, attempt.Certificate.SHA256, attempt.Certificate.NotAfter,
		attempt.TokenSHA256, attempt.Epoch, attempt.Status, attempt.HeartbeatSequence, attempt.LeaseAcquiredAt,
		attempt.LastHeartbeatAt, attempt.LeaseExpiresAt, nullableTime(attempt.StartedAt), nullableTime(attempt.TerminalAt),
		nullableString(attempt.RequestHash), nullableString(attempt.ReceiptHash), attempt.UpdatedAt,
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
		"tenant_id", "workspace_id", "environment_id", "incident_id", "investigation_id",
		"task_id", "task_key", "position", "connector_id", "operation", "input_document", "input_hash",
		"task_status", "investigation_status",
	}
}
