package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

func TestRecoveryRepositoryRequiresDatabaseAndRejectsInvalidRequestBeforeSQL(t *testing.T) {
	if repository, err := NewRecoveryRepository(nil); !errors.Is(err, readtask.ErrInvalidRequest) || repository != nil {
		t.Fatalf("NewRecoveryRepository(nil) = %#v, %v", repository, err)
	}
	database, repository := newRecoveryRepository(t)
	descriptor, _ := testDescriptorAndInput()
	request := recoveryRequest(descriptor)
	request.TenantID = "tenant"
	result, err := repository.Recover(context.Background(), request)
	if !errors.Is(err, readtask.ErrInvalidRequest) || result.State != "" {
		t.Fatalf("Recover(invalid request) = %#v, %v", result, err)
	}
	assertRecoveryExpectations(t, database)
}

func TestRecoveryRepositoryPreservesContextTerminationBeforeSQL(t *testing.T) {
	database, repository := newRecoveryRepository(t)
	descriptor, _ := testDescriptorAndInput()
	request := recoveryRequest(descriptor)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := repository.Recover(ctx, request)
	if !errors.Is(err, context.Canceled) || result.State != "" {
		t.Fatalf("Recover(cancelled context) = %#v, %v", result, err)
	}
	assertRecoveryExpectations(t, database)
}

func TestRecoveryRepositoryReturnsPendingFromReadOnlyCurrentSchemaSnapshot(t *testing.T) {
	database, repository := newRecoveryRepository(t)
	descriptor, input := testDescriptorAndInput()
	request := recoveryRequest(descriptor)

	database.ExpectBeginTx(pgx.TxOptions{AccessMode: pgx.ReadOnly})
	expectRecoveryTask(database, descriptor, input, domain.ReadTaskQueued, "QUEUED")
	database.ExpectCommit()

	result, err := repository.Recover(context.Background(), request)
	if err != nil || result.State != readtask.RecoveryPending || result.TaskStatus != domain.ReadTaskQueued ||
		result.TaskID != testTaskID || result.ReceiptID != "" || result.EvidenceID != "" {
		t.Fatalf("Recover(pending) = %#v, %v", result, err)
	}
	assertRecoveryExpectations(t, database)
}

func TestRecoveryRepositoryRebuildsCommittedEvidenceWithoutCompletionBody(t *testing.T) {
	database, repository := newRecoveryRepository(t)
	descriptor, input := testDescriptorAndInput()
	request := recoveryRequest(descriptor)
	committed, receipt := committedRecoveryFixture(t, descriptor, readtask.CompletionEvidence)

	database.ExpectBeginTx(pgx.TxOptions{AccessMode: pgx.ReadOnly})
	expectRecoveryTask(database, descriptor, input, domain.ReadTaskEvidence, "RUNNING")
	expectRecoveryReceipt(database, descriptor, receipt, testEvidenceID)
	database.ExpectQuery(`(?s)SELECT .*FROM investigation_task_attempts AS attempt.*lease_epoch = \$5`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, committed.Epoch).
		WillReturnRows(attemptRows(committed))
	database.ExpectCommit()

	result, err := repository.Recover(context.Background(), request)
	if err != nil || result.State != readtask.RecoveryCommitted || result.TaskStatus != domain.ReadTaskEvidence ||
		result.EvidenceID != testEvidenceID || result.ContentHash != receipt.ContentHash ||
		result.ReceiptID != testReceiptID || result.ReceiptHash != receipt.ReceiptHash {
		var integrityFailure repositoryIntegrityError
		if errors.As(err, &integrityFailure) {
			t.Fatalf("Recover(committed Evidence) = %#v, %v (test cause: %v)", result, err, integrityFailure.cause)
		}
		t.Fatalf("Recover(committed Evidence) = %#v, %v", result, err)
	}
	assertRecoveryExpectations(t, database)
}

func TestRecoveryRepositoryRebuildsCommittedFailureAndRunnerCancellation(t *testing.T) {
	tests := []struct {
		name       string
		outcome    readtask.CompletionOutcome
		taskStatus domain.ReadTaskStatus
	}{
		{"failed", readtask.CompletionFailed, domain.ReadTaskFailed},
		{"cancelled", readtask.CompletionCancelled, domain.ReadTaskCancelled},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database, repository := newRecoveryRepository(t)
			descriptor, input := testDescriptorAndInput()
			request := recoveryRequest(descriptor)
			committed, receipt := committedRecoveryFixture(t, descriptor, test.outcome)

			database.ExpectBeginTx(pgx.TxOptions{AccessMode: pgx.ReadOnly})
			expectRecoveryTask(database, descriptor, input, test.taskStatus, "RUNNING")
			expectRecoveryReceipt(database, descriptor, receipt, "")
			database.ExpectQuery(`(?s)SELECT .*FROM investigation_task_attempts AS attempt.*lease_epoch = \$5`).
				WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, committed.Epoch).
				WillReturnRows(attemptRows(committed))
			database.ExpectCommit()

			result, err := repository.Recover(context.Background(), request)
			if err != nil || result.State != readtask.RecoveryCommitted || result.TaskStatus != test.taskStatus ||
				result.EvidenceID != "" || result.ContentHash != "" ||
				result.ReceiptID != testReceiptID || result.ReceiptHash != receipt.ReceiptHash {
				t.Fatalf("Recover(%s) = %#v, %v", test.name, result, err)
			}
			assertRecoveryExpectations(t, database)
		})
	}
}

func TestRecoveryRepositoryTreatsControlPlaneCancellationWithoutReceiptAsTerminal(t *testing.T) {
	database, repository := newRecoveryRepository(t)
	descriptor, input := testDescriptorAndInput()
	request := recoveryRequest(descriptor)

	database.ExpectBeginTx(pgx.TxOptions{AccessMode: pgx.ReadOnly})
	expectRecoveryTask(database, descriptor, input, domain.ReadTaskCancelled, "CANCELLED")
	database.ExpectQuery(`(?s)SELECT .*FROM runner_evidence_receipts AS receipt.*receipt.task_id = \$4`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID).
		WillReturnError(pgx.ErrNoRows)
	database.ExpectCommit()

	result, err := repository.Recover(context.Background(), request)
	if err != nil || result.State != readtask.RecoveryControlCancelled ||
		result.TaskStatus != domain.ReadTaskCancelled || result.ReceiptID != "" || result.EvidenceID != "" {
		t.Fatalf("Recover(control cancellation) = %#v, %v", result, err)
	}
	assertRecoveryExpectations(t, database)
}

func TestRecoveryRepositoryRejectsTerminalEvidenceWithoutReceipt(t *testing.T) {
	database, repository := newRecoveryRepository(t)
	descriptor, input := testDescriptorAndInput()
	request := recoveryRequest(descriptor)

	database.ExpectBeginTx(pgx.TxOptions{AccessMode: pgx.ReadOnly})
	expectRecoveryTask(database, descriptor, input, domain.ReadTaskEvidence, "RUNNING")
	database.ExpectQuery(`(?s)SELECT .*FROM runner_evidence_receipts AS receipt.*receipt.task_id = \$4`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID).
		WillReturnError(pgx.ErrNoRows)
	database.ExpectRollback()

	result, err := repository.Recover(context.Background(), request)
	if !errors.Is(err, readtask.ErrIntegrity) || result.State != "" {
		t.Fatalf("Recover(Evidence without receipt) = %#v, %v; want integrity error", result, err)
	}
	assertRecoveryExpectations(t, database)
}

func TestRecoveryRepositoryRejectsPendingTaskUnderTerminalParent(t *testing.T) {
	database, repository := newRecoveryRepository(t)
	descriptor, input := testDescriptorAndInput()
	request := recoveryRequest(descriptor)

	database.ExpectBeginTx(pgx.TxOptions{AccessMode: pgx.ReadOnly})
	expectRecoveryTask(database, descriptor, input, domain.ReadTaskRunning, "FAILED")
	database.ExpectRollback()

	result, err := repository.Recover(context.Background(), request)
	if !errors.Is(err, readtask.ErrIntegrity) || result.State != "" {
		t.Fatalf("Recover(pending under terminal parent) = %#v, %v; want integrity error", result, err)
	}
	assertRecoveryExpectations(t, database)
}

func TestRecoveryRepositoryRejectsFailedTaskUnderCompletedParent(t *testing.T) {
	database, repository := newRecoveryRepository(t)
	descriptor, input := testDescriptorAndInput()
	request := recoveryRequest(descriptor)

	database.ExpectBeginTx(pgx.TxOptions{AccessMode: pgx.ReadOnly})
	expectRecoveryTask(database, descriptor, input, domain.ReadTaskFailed, "COMPLETED")
	database.ExpectRollback()

	result, err := repository.Recover(context.Background(), request)
	if !errors.Is(err, readtask.ErrIntegrity) || result.State != "" {
		t.Fatalf("Recover(Failed under Completed parent) = %#v, %v; want integrity error", result, err)
	}
	assertRecoveryExpectations(t, database)
}

func TestRecoveryRepositoryClassifiesLegacyNullableReceiptAsIntegrity(t *testing.T) {
	database, repository := newRecoveryRepository(t)
	descriptor, input := testDescriptorAndInput()
	request := recoveryRequest(descriptor)
	_, receipt := committedRecoveryFixture(t, descriptor, readtask.CompletionEvidence)

	database.ExpectBeginTx(pgx.TxOptions{AccessMode: pgx.ReadOnly})
	expectRecoveryTask(database, descriptor, input, domain.ReadTaskEvidence, "RUNNING")
	database.ExpectQuery(`(?s)SELECT .*FROM runner_evidence_receipts AS receipt.*receipt.task_id = \$4`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID).
		WillReturnRows(pgxmock.NewRows(recoveryReceiptColumns()).AddRow(
			testReceiptID, "runner-evidence.v1", receipt.TenantID, receipt.WorkspaceID,
			receipt.EnvironmentID, receipt.InvestigationID, receipt.TaskID, receipt.RunnerID,
			receipt.ScopeRevision, receipt.CertificateSHA256, nil, receipt.ConnectorID,
			testEvidenceID, receipt.ContentHash, nil, receipt.IdempotencyKey,
			receipt.RequestHash, receipt.ReceiptHash, nil, nil, receipt.ReceivedAt,
			nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		))
	database.ExpectRollback()

	result, err := repository.Recover(context.Background(), request)
	if !errors.Is(err, readtask.ErrIntegrity) || result.State != "" {
		t.Fatalf("Recover(legacy nullable receipt) = %#v, %v; want integrity error", result, err)
	}
	assertRecoveryExpectations(t, database)
}

func TestRecoveryRepositoryRejectsReceiptProvenanceDrift(t *testing.T) {
	database, repository := newRecoveryRepository(t)
	descriptor, input := testDescriptorAndInput()
	request := recoveryRequest(descriptor)
	committed, receipt := committedRecoveryFixture(t, descriptor, readtask.CompletionFailed)
	receipt.ReceiptHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	database.ExpectBeginTx(pgx.TxOptions{AccessMode: pgx.ReadOnly})
	expectRecoveryTask(database, descriptor, input, domain.ReadTaskFailed, "RUNNING")
	expectRecoveryReceipt(database, descriptor, receipt, "")
	database.ExpectQuery(`(?s)SELECT .*FROM investigation_task_attempts AS attempt.*lease_epoch = \$5`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID, committed.Epoch).
		WillReturnRows(attemptRows(committed))
	database.ExpectRollback()

	result, err := repository.Recover(context.Background(), request)
	if !errors.Is(err, readtask.ErrIntegrity) || result.State != "" {
		t.Fatalf("Recover(drifted receipt) = %#v, %v; want integrity error", result, err)
	}
	assertRecoveryExpectations(t, database)
}

func newRecoveryRepository(t *testing.T) (pgxmock.PgxPoolIface, *RecoveryRepository) {
	t.Helper()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	t.Cleanup(database.Close)
	repository, err := NewRecoveryRepository(database)
	if err != nil {
		t.Fatalf("NewRecoveryRepository() error = %v", err)
	}
	return database, repository
}

func recoveryRequest(descriptor readtask.Descriptor) readtask.RecoveryRequest {
	return readtask.RecoveryRequest{
		TenantID: descriptor.TenantID, WorkspaceID: descriptor.WorkspaceID,
		IncidentID: descriptor.IncidentID, InvestigationID: descriptor.InvestigationID,
		TaskID: descriptor.TaskID, Position: descriptor.Position, PlanBinding: descriptor.PlanBinding,
	}
}

func expectRecoveryTask(
	database pgxmock.PgxPoolIface,
	descriptor readtask.Descriptor,
	input []byte,
	taskStatus domain.ReadTaskStatus,
	investigationStatus string,
) {
	database.ExpectQuery(`(?s)SELECT .*FROM workspaces AS workspace.*JOIN investigations AS investigation.*JOIN tool_invocations AS task.*workspace.id = \$1.*investigation.id = \$2.*task.id = \$3`).
		WithArgs(
			descriptor.WorkspaceID, descriptor.InvestigationID, descriptor.TaskID,
			descriptor.IncidentID, descriptor.Position,
			descriptor.PlanBinding.SchemaVersion, descriptor.PlanBinding.ManifestDigest,
			descriptor.PlanBinding.RegistryDigest, descriptor.PlanBinding.ProfileDigest,
			descriptor.PlanBinding.TasksHash,
		).
		WillReturnRows(pgxmock.NewRows(recoveryTaskColumns()).AddRow(
			descriptor.TenantID, descriptor.WorkspaceID, descriptor.EnvironmentID, descriptor.ServiceID,
			descriptor.IncidentID, descriptor.InvestigationID, descriptor.TaskID, descriptor.TaskKey,
			int16(descriptor.Position), descriptor.ConnectorID, descriptor.Operation, input, descriptor.InputHash,
			descriptor.PlanBinding.SchemaVersion, descriptor.PlanBinding.ManifestDigest,
			descriptor.PlanBinding.RegistryDigest, descriptor.PlanBinding.ProfileDigest,
			descriptor.PlanBinding.TasksHash, descriptor.RuntimeBinding.SchemaVersion,
			descriptor.RuntimeBinding.ConnectorDigest, descriptor.RuntimeBinding.TargetDigest,
			descriptor.RuntimeBinding.ExecutorDigest, descriptor.RuntimeBinding.RuntimeDigest,
			descriptor.RuntimeBinding.BoundAt, taskStatus, investigationStatus,
		))
}

func expectRecoveryReceipt(
	database pgxmock.PgxPoolIface,
	descriptor readtask.Descriptor,
	receipt readtask.Receipt,
	evidenceID string,
) {
	database.ExpectQuery(`(?s)SELECT .*FROM runner_evidence_receipts AS receipt.*receipt.task_id = \$4`).
		WithArgs(testTenantID, testWorkspaceID, testInvestigationID, testTaskID).
		WillReturnRows(pgxmock.NewRows(recoveryReceiptColumns()).AddRow(
			testReceiptID, receipt.SchemaVersion, receipt.TenantID, receipt.WorkspaceID,
			receipt.EnvironmentID, receipt.InvestigationID, receipt.TaskID, receipt.RunnerID,
			receipt.ScopeRevision, receipt.CertificateSHA256, receipt.LeaseEpoch, receipt.ConnectorID,
			nullableString(evidenceID), nullableString(receipt.ContentHash), nullableString(string(receipt.FailureCode)),
			receipt.IdempotencyKey, receipt.RequestHash, receipt.ReceiptHash,
			receipt.RequestHashVersion, receipt.ReceiptHashVersion, receipt.ReceivedAt,
			receipt.PlanBinding.SchemaVersion, receipt.PlanBinding.ManifestDigest,
			receipt.PlanBinding.RegistryDigest, receipt.PlanBinding.ProfileDigest, receipt.PlanBinding.TasksHash,
			receipt.RuntimeBinding.SchemaVersion, receipt.RuntimeBinding.ConnectorDigest,
			receipt.RuntimeBinding.TargetDigest, receipt.RuntimeBinding.ExecutorDigest,
			receipt.RuntimeBinding.RuntimeDigest, receipt.RuntimeBinding.BoundAt,
		))
}

func committedRecoveryFixture(
	t *testing.T,
	descriptor readtask.Descriptor,
	outcome readtask.CompletionOutcome,
) (readtask.Attempt, readtask.Receipt) {
	t.Helper()
	now := testNow()
	certificate := readtask.CertificateBinding{SHA256: testCertificateHash, NotAfter: now.Add(time.Minute)}
	attempt := testAttempt(now, certificate, readtask.AttemptRunning)
	attempt.StartedAt = now.Add(time.Second)
	attempt.UpdatedAt = attempt.StartedAt
	fence, err := readtask.NewFence(testTaskID, testRunnerID, []byte(testLeaseToken), attempt.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Destroy()
	completion := readtask.Completion{Fence: fence, Outcome: outcome}
	switch outcome {
	case readtask.CompletionEvidence:
		completion.Evidence = &readtask.EvidenceCompletion{
			CollectedAt: now.Add(2 * time.Second),
			Items:       []json.RawMessage{json.RawMessage(`{"value":1}`)},
		}
	case readtask.CompletionFailed:
		completion.FailureCode = readtask.FailureTimeout
	case readtask.CompletionCancelled:
		completion.FailureCode = readtask.FailureCancelled
	default:
		t.Fatalf("unsupported recovery outcome %q", outcome)
	}
	receivedAt := now.Add(3 * time.Second)
	projection, err := readtask.ProjectCompletion(descriptor, attempt, completion, receivedAt)
	if err != nil {
		t.Fatalf("ProjectCompletion() error = %v", err)
	}
	attempt.Status = readtask.AttemptCompleted
	attempt.TerminalAt = receivedAt
	attempt.UpdatedAt = receivedAt
	attempt.RequestHash = projection.RequestHash()
	attempt.ReceiptHash = projection.ReceiptHash()
	attempt.RequestHashVersion = readtask.CompletionRequestHashVersionV3
	attempt.ReceiptHashVersion = readtask.CompletionReceiptHashVersionV3
	receipt := projection.Receipt()
	if err := receipt.ValidateAgainst(descriptor, attempt); err != nil {
		t.Fatalf("committed recovery Receipt invalid: %v", err)
	}
	return attempt, receipt
}

func assertRecoveryExpectations(t *testing.T, database pgxmock.PgxPoolIface) {
	t.Helper()
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet recovery PostgreSQL expectations: %v", err)
	}
}

func recoveryTaskColumns() []string {
	return taskLockColumns()
}

func recoveryReceiptColumns() []string {
	return []string{
		"id", "schema_version", "tenant_id", "workspace_id", "environment_id",
		"investigation_id", "task_id", "runner_id", "scope_revision", "certificate_sha256",
		"lease_epoch", "connector_id", "evidence_id", "content_hash", "failure_code",
		"idempotency_key", "request_hash", "receipt_hash", "request_hash_version",
		"receipt_hash_version", "received_at", "plan_schema_version", "plan_manifest_digest",
		"plan_registry_digest", "plan_profile_digest", "plan_tasks_hash",
		"read_runtime_schema_version", "connector_digest", "target_digest", "executor_digest",
		"runtime_digest", "runtime_bound_at",
	}
}
