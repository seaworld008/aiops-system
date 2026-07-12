package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

const recoveryRollbackTimeout = 5 * time.Second

var errInvalidRecoveryReceiptProjection = errors.New("invalid recoverable READ receipt projection")

// RecoveryDB is intentionally read-only and separate from the mutation
// Repository dependencies. A recovery worker never receives a lease token or
// an ID source and cannot claim, start, heartbeat, release, or complete work.
type RecoveryDB interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// RecoveryRepository rebuilds only compact committed-result facts from the
// immutable Task -> v3 Receipt -> exact completed Attempt chain. It is a
// control-plane boundary, not a Runner HTTP authorization boundary.
type RecoveryRepository struct {
	database RecoveryDB
}

func NewRecoveryRepository(database RecoveryDB) (*RecoveryRepository, error) {
	if nilInterface(database) {
		return nil, fmt.Errorf("%w: trusted PostgreSQL recovery database is required", readtask.ErrInvalidRequest)
	}
	return &RecoveryRepository{database: database}, nil
}

func (repository *RecoveryRepository) Recover(
	ctx context.Context,
	request readtask.RecoveryRequest,
) (readtask.RecoveryResult, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || request.Validate() != nil {
		return readtask.RecoveryResult{}, readtask.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return readtask.RecoveryResult{}, err
	}
	tx, err := repository.database.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return readtask.RecoveryResult{}, persistenceError("begin READ result recovery", err)
	}
	committed := false
	defer func() {
		if !committed {
			rollbackContext, cancel := context.WithTimeout(context.Background(), recoveryRollbackTimeout)
			defer cancel()
			_ = tx.Rollback(rollbackContext)
		}
	}()

	task, err := readRecoveryTask(ctx, tx, request)
	if errors.Is(err, pgx.ErrNoRows) {
		return readtask.RecoveryResult{}, readtask.ErrNotFound
	}
	if err != nil {
		return readtask.RecoveryResult{}, persistenceError("read recoverable READ task", err)
	}
	if task.descriptor.Validate() != nil || task.descriptor.TenantID != request.TenantID ||
		task.descriptor.WorkspaceID != request.WorkspaceID || task.descriptor.IncidentID != request.IncidentID ||
		task.descriptor.InvestigationID != request.InvestigationID || task.descriptor.TaskID != request.TaskID ||
		task.descriptor.Position != request.Position || !task.descriptor.PlanBinding.Equal(request.PlanBinding) {
		return readtask.RecoveryResult{}, integrityError(
			"validate recoverable READ task", errors.New("persisted recovery task projection mismatch"),
		)
	}

	taskStatus := domain.ReadTaskStatus(task.taskStatus)
	if !validRecoveryTaskState(taskStatus, task.investigationStatus) {
		return readtask.RecoveryResult{}, integrityError(
			"validate recoverable READ task state", errors.New("invalid persisted READ task parent state"),
		)
	}
	switch taskStatus {
	case domain.ReadTaskQueued, domain.ReadTaskRunning:
		result := readtask.RecoveryResult{
			State: readtask.RecoveryPending, InvestigationID: request.InvestigationID,
			TaskID: request.TaskID, Position: request.Position, TaskStatus: taskStatus,
		}
		if result.ValidateAgainst(request) != nil {
			return readtask.RecoveryResult{}, integrityError(
				"validate pending READ result recovery", errors.New("invalid pending recovery projection"),
			)
		}
		if err := tx.Commit(ctx); err != nil {
			return readtask.RecoveryResult{}, persistenceError("commit pending READ result recovery", err)
		}
		committed = true
		return result, nil
	case domain.ReadTaskEvidence, domain.ReadTaskFailed, domain.ReadTaskCancelled:
	default:
		return readtask.RecoveryResult{}, integrityError(
			"validate recoverable READ task state", errors.New("invalid persisted READ task state"),
		)
	}

	storedReceipt, err := readRecoveryReceipt(ctx, tx, task.descriptor)
	if errors.Is(err, pgx.ErrNoRows) {
		if taskStatus != domain.ReadTaskCancelled {
			return readtask.RecoveryResult{}, integrityError(
				"read committed READ result receipt", errors.New("terminal READ result receipt is missing"),
			)
		}
		result := readtask.RecoveryResult{
			State: readtask.RecoveryControlCancelled, InvestigationID: request.InvestigationID,
			TaskID: request.TaskID, Position: request.Position, TaskStatus: domain.ReadTaskCancelled,
		}
		if result.ValidateAgainst(request) != nil {
			return readtask.RecoveryResult{}, integrityError(
				"validate cancelled READ result recovery", errors.New("invalid cancellation recovery projection"),
			)
		}
		if err := tx.Commit(ctx); err != nil {
			return readtask.RecoveryResult{}, persistenceError("commit cancelled READ result recovery", err)
		}
		committed = true
		return result, nil
	}
	if err != nil {
		if errors.Is(err, errInvalidRecoveryReceiptProjection) {
			return readtask.RecoveryResult{}, integrityError(
				"validate committed READ result receipt", errInvalidRecoveryReceiptProjection,
			)
		}
		return readtask.RecoveryResult{}, persistenceError("read committed READ result receipt", err)
	}

	attempt, err := readRecoveryAttempt(ctx, tx, task.descriptor, storedReceipt.receipt.LeaseEpoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return readtask.RecoveryResult{}, integrityError(
			"read committed READ result attempt", errors.New("receipt attempt is missing"),
		)
	}
	if err != nil {
		return readtask.RecoveryResult{}, persistenceError("read committed READ result attempt", err)
	}
	committedResult := readtask.CommittedResult{
		Attempt: attempt, Receipt: storedReceipt.receipt, TaskStatus: taskStatus,
		EvidenceID: storedReceipt.evidenceID, ReceiptID: storedReceipt.receiptID,
	}
	if validationErr := validateRecoveredCommit(task.descriptor, committedResult); validationErr != nil {
		return readtask.RecoveryResult{}, integrityError(
			"validate committed READ result provenance", validationErr,
		)
	}
	result := readtask.RecoveryResult{
		State: readtask.RecoveryCommitted, InvestigationID: request.InvestigationID,
		TaskID: request.TaskID, Position: request.Position, TaskStatus: taskStatus,
		EvidenceID: committedResult.EvidenceID, ContentHash: committedResult.Receipt.ContentHash,
		ReceiptID: committedResult.ReceiptID, ReceiptHash: committedResult.Receipt.ReceiptHash,
	}
	if result.ValidateAgainst(request) != nil {
		return readtask.RecoveryResult{}, integrityError(
			"validate committed READ result recovery", errors.New("invalid safe recovery projection"),
		)
	}
	if err := tx.Commit(ctx); err != nil {
		return readtask.RecoveryResult{}, persistenceError("commit READ result recovery", err)
	}
	committed = true
	return result, nil
}

func validRecoveryTaskState(taskStatus domain.ReadTaskStatus, investigationStatus string) bool {
	switch taskStatus {
	case domain.ReadTaskQueued:
		return investigationStatus == "QUEUED" || investigationStatus == "RUNNING"
	case domain.ReadTaskRunning:
		return investigationStatus == "RUNNING"
	case domain.ReadTaskEvidence:
		return investigationStatus == "RUNNING" || investigationStatus == "PARTIAL" ||
			investigationStatus == "COMPLETED" || investigationStatus == "FAILED" ||
			investigationStatus == "CANCELLED"
	case domain.ReadTaskFailed:
		return investigationStatus == "RUNNING" || investigationStatus == "PARTIAL" ||
			investigationStatus == "FAILED" || investigationStatus == "CANCELLED"
	case domain.ReadTaskCancelled:
		return investigationStatus == "RUNNING" || investigationStatus == "PARTIAL" ||
			investigationStatus == "FAILED" ||
			investigationStatus == "CANCELLED"
	default:
		return false
	}
}

func validateRecoveredCommit(descriptor readtask.Descriptor, result readtask.CommittedResult) error {
	if result.Attempt.ValidateAgainst(descriptor) != nil {
		return errors.New("invalid persisted completed attempt")
	}
	if result.Receipt.ValidateAgainst(descriptor, result.Attempt) != nil {
		return errors.New("invalid persisted v3 receipt")
	}
	if result.ValidateAgainst(descriptor) != nil {
		return errors.New("invalid persisted terminal result union")
	}
	return nil
}

func readRecoveryTask(
	ctx context.Context,
	tx pgx.Tx,
	request readtask.RecoveryRequest,
) (storedTask, error) {
	var task storedTask
	err := tx.QueryRow(ctx, `
		SELECT workspace.tenant_id::text, task.workspace_id::text,
			COALESCE(investigation.environment_id_snapshot::text, ''),
			COALESCE(investigation.service_id_snapshot::text, ''),
			task.incident_id::text, task.investigation_id::text, task.id::text,
			task.task_key, task.position, task.tool_name, task.tool_version,
			task.input_document, task.input_hash,
			investigation.plan_schema_version, investigation.plan_manifest_digest,
			investigation.plan_registry_digest, investigation.plan_profile_digest,
			investigation.plan_tasks_hash,
			task.read_runtime_schema_version, task.connector_digest, task.target_digest,
			task.executor_digest, task.runtime_digest, task.runtime_bound_at,
			task.status, investigation.status
		FROM workspaces AS workspace
		JOIN investigations AS investigation
		  ON investigation.tenant_id = workspace.tenant_id
		 AND investigation.workspace_id = workspace.id
		JOIN tool_invocations AS task
		  ON task.tenant_id = investigation.tenant_id
		 AND task.workspace_id = investigation.workspace_id
		 AND task.investigation_id = investigation.id
		WHERE workspace.id = $1 AND investigation.id = $2 AND task.id = $3
		  AND task.incident_id = $4 AND task.position = $5
		  AND investigation.runtime_schema_version = 'investigation-runtime.v1'
		  AND investigation.request_hash_version = 'investigation.create.v2'
		  AND investigation.plan_schema_version = $6
		  AND investigation.plan_manifest_digest = $7
		  AND investigation.plan_registry_digest = $8
		  AND investigation.plan_profile_digest = $9
		  AND investigation.plan_tasks_hash = $10
		  AND task.runtime_schema_version = 'investigation-runtime.v1'
		  AND task.read_runtime_schema_version = 'read-task-runtime-binding.v1'
	`, request.WorkspaceID, request.InvestigationID, request.TaskID, request.IncidentID, request.Position,
		request.PlanBinding.SchemaVersion, request.PlanBinding.ManifestDigest, request.PlanBinding.RegistryDigest,
		request.PlanBinding.ProfileDigest, request.PlanBinding.TasksHash).Scan(
		&task.descriptor.TenantID, &task.descriptor.WorkspaceID, &task.descriptor.EnvironmentID,
		&task.descriptor.ServiceID, &task.descriptor.IncidentID, &task.descriptor.InvestigationID,
		&task.descriptor.TaskID, &task.descriptor.TaskKey, &task.descriptor.Position,
		&task.descriptor.ConnectorID, &task.descriptor.Operation, &task.descriptor.Input,
		&task.descriptor.InputHash, &task.descriptor.PlanBinding.SchemaVersion,
		&task.descriptor.PlanBinding.ManifestDigest, &task.descriptor.PlanBinding.RegistryDigest,
		&task.descriptor.PlanBinding.ProfileDigest, &task.descriptor.PlanBinding.TasksHash,
		&task.descriptor.RuntimeBinding.SchemaVersion, &task.descriptor.RuntimeBinding.ConnectorDigest,
		&task.descriptor.RuntimeBinding.TargetDigest, &task.descriptor.RuntimeBinding.ExecutorDigest,
		&task.descriptor.RuntimeBinding.RuntimeDigest, &task.descriptor.RuntimeBinding.BoundAt,
		&task.taskStatus, &task.investigationStatus,
	)
	task.descriptor.RuntimeBinding.BoundAt = task.descriptor.RuntimeBinding.BoundAt.UTC()
	return task, err
}

type storedRecoveryReceipt struct {
	receiptID  string
	evidenceID string
	receipt    readtask.Receipt
}

func readRecoveryReceipt(
	ctx context.Context,
	tx pgx.Tx,
	descriptor readtask.Descriptor,
) (storedRecoveryReceipt, error) {
	var stored storedRecoveryReceipt
	var evidenceID, contentHash, failureCode pgtype.Text
	var leaseEpoch pgtype.Int8
	var requestHashVersion, receiptHashVersion pgtype.Text
	var planSchema, planManifest, planRegistry, planProfile, planTasks pgtype.Text
	var runtimeSchema, connectorDigest, targetDigest, executorDigest, runtimeDigest pgtype.Text
	var runtimeBoundAt pgtype.Timestamptz
	err := tx.QueryRow(ctx, `
		SELECT receipt.id::text, receipt.schema_version, receipt.tenant_id::text,
			receipt.workspace_id::text, receipt.environment_id::text,
			receipt.investigation_id::text, receipt.task_id::text, receipt.runner_id,
			receipt.scope_revision, receipt.certificate_sha256, receipt.lease_epoch,
			receipt.connector_id, receipt.evidence_id::text, receipt.content_hash,
			receipt.failure_code, receipt.idempotency_key, receipt.request_hash,
			receipt.receipt_hash, receipt.request_hash_version, receipt.receipt_hash_version,
			receipt.received_at, receipt.plan_schema_version, receipt.plan_manifest_digest,
			receipt.plan_registry_digest, receipt.plan_profile_digest, receipt.plan_tasks_hash,
			receipt.read_runtime_schema_version, receipt.connector_digest,
			receipt.target_digest, receipt.executor_digest, receipt.runtime_digest,
			receipt.runtime_bound_at
		FROM runner_evidence_receipts AS receipt
		WHERE receipt.tenant_id = $1 AND receipt.workspace_id = $2
		  AND receipt.investigation_id = $3 AND receipt.task_id = $4
	`, descriptor.TenantID, descriptor.WorkspaceID, descriptor.InvestigationID, descriptor.TaskID).Scan(
		&stored.receiptID, &stored.receipt.SchemaVersion, &stored.receipt.TenantID,
		&stored.receipt.WorkspaceID, &stored.receipt.EnvironmentID, &stored.receipt.InvestigationID,
		&stored.receipt.TaskID, &stored.receipt.RunnerID, &stored.receipt.ScopeRevision,
		&stored.receipt.CertificateSHA256, &leaseEpoch, &stored.receipt.ConnectorID,
		&evidenceID, &contentHash, &failureCode, &stored.receipt.IdempotencyKey,
		&stored.receipt.RequestHash, &stored.receipt.ReceiptHash, &requestHashVersion,
		&receiptHashVersion, &stored.receipt.ReceivedAt,
		&planSchema, &planManifest, &planRegistry, &planProfile, &planTasks,
		&runtimeSchema, &connectorDigest, &targetDigest, &executorDigest, &runtimeDigest, &runtimeBoundAt,
	)
	if err != nil {
		return storedRecoveryReceipt{}, err
	}
	if !leaseEpoch.Valid || leaseEpoch.Int64 <= 0 {
		return storedRecoveryReceipt{}, errInvalidRecoveryReceiptProjection
	}
	stored.receipt.LeaseEpoch = leaseEpoch.Int64
	stored.receipt.ServiceID = descriptor.ServiceID
	stored.receipt.IncidentID = descriptor.IncidentID
	stored.receipt.Operation = descriptor.Operation
	if evidenceID.Valid {
		stored.evidenceID = evidenceID.String
	}
	if contentHash.Valid {
		stored.receipt.ContentHash = contentHash.String
	}
	if failureCode.Valid {
		stored.receipt.FailureCode = readtask.FailureCode(failureCode.String)
	}
	switch {
	case evidenceID.Valid && contentHash.Valid && !failureCode.Valid:
		stored.receipt.Outcome = readtask.CompletionEvidence
	case !evidenceID.Valid && !contentHash.Valid && failureCode.Valid &&
		stored.receipt.FailureCode == readtask.FailureCancelled:
		stored.receipt.Outcome = readtask.CompletionCancelled
	case !evidenceID.Valid && !contentHash.Valid && failureCode.Valid:
		stored.receipt.Outcome = readtask.CompletionFailed
	}
	if requestHashVersion.Valid {
		stored.receipt.RequestHashVersion = requestHashVersion.String
	}
	if receiptHashVersion.Valid {
		stored.receipt.ReceiptHashVersion = receiptHashVersion.String
	}
	if planSchema.Valid {
		stored.receipt.PlanBinding = domain.InvestigationPlanBinding{
			SchemaVersion: planSchema.String, ManifestDigest: planManifest.String,
			RegistryDigest: planRegistry.String, ProfileDigest: planProfile.String, TasksHash: planTasks.String,
		}
	}
	if runtimeSchema.Valid {
		stored.receipt.RuntimeBinding = domain.ReadTaskRuntimeBinding{
			SchemaVersion: runtimeSchema.String, ConnectorDigest: connectorDigest.String,
			TargetDigest: targetDigest.String, ExecutorDigest: executorDigest.String,
			RuntimeDigest: runtimeDigest.String,
		}
		if runtimeBoundAt.Valid {
			stored.receipt.RuntimeBinding.BoundAt = runtimeBoundAt.Time.UTC()
		}
	}
	stored.receipt.ReceivedAt = stored.receipt.ReceivedAt.UTC()
	return stored, nil
}

func readRecoveryAttempt(
	ctx context.Context,
	tx pgx.Tx,
	descriptor readtask.Descriptor,
	epoch int64,
) (readtask.Attempt, error) {
	return scanAttempt(tx.QueryRow(ctx, `
		SELECT `+attemptProjection+`
		FROM investigation_task_attempts AS attempt
		WHERE attempt.tenant_id = $1 AND attempt.workspace_id = $2
		  AND attempt.investigation_id = $3 AND attempt.task_id = $4
		  AND attempt.lease_epoch = $5
	`, descriptor.TenantID, descriptor.WorkspaceID, descriptor.InvestigationID, descriptor.TaskID, epoch))
}
