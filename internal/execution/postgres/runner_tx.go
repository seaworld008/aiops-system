package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executionlease"
)

// RunnerCompletion is the server-authored completion proof returned to the
// Gateway. Receipt.ResultHash is computed from the authenticated action fence,
// the structured executor result, and the mTLS leaf certificate fingerprint;
// no caller-supplied result hash is accepted by CompleteRunnerTx.
type RunnerCompletion struct {
	Execution executionlease.Execution
	Receipt   execution.RunnerResultReceipt
}

// ClaimRunnerTx leases one non-production action using a RunnerScope already
// authenticated and locked by the Gateway in tx. Transaction ownership stays
// with the caller: this method never begins, commits, or rolls back tx.
func (repository *Repository) ClaimRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	leaseDuration time.Duration,
) (execution.ClaimedAction, error) {
	if err := runnerTxContext(ctx, tx); err != nil {
		return execution.ClaimedAction{}, err
	}
	if err := validateRunnerWriteScope(scope, leaseDuration); err != nil {
		return execution.ClaimedAction{}, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, actionClaimLock); err != nil {
		return execution.ClaimedAction{}, fmt.Errorf("serialize authenticated Runner action claim: %w", err)
	}

	bindings := scope.Bindings()
	workspaceIDs := make([]string, len(bindings))
	environmentIDs := make([]string, len(bindings))
	for index, binding := range bindings {
		workspaceIDs[index] = binding.WorkspaceID
		environmentIDs[index] = binding.EnvironmentID
	}

	var actionID, workspaceID, environmentID string
	var leaseEpoch int64
	err := tx.QueryRow(ctx, `
		WITH exact_scope(workspace_id, environment_id) AS (
			SELECT * FROM unnest($4::text[], $5::text[])
		)
		SELECT candidate.action_id, candidate.lease_epoch, candidate.workspace_id, candidate.environment_id
		FROM action_queue AS candidate
		WHERE candidate.runner_pool = $1
		  AND candidate.production = false
		  AND candidate.status = 'QUEUED'
		  AND candidate.not_before <= statement_timestamp()
		  AND candidate.authorization_expires_at > statement_timestamp()
		  AND EXISTS (
			SELECT 1 FROM exact_scope AS binding
			WHERE binding.workspace_id = candidate.workspace_id
			  AND binding.environment_id = candidate.environment_id
		  )
		  AND (
			SELECT count(*) FROM action_queue AS runner_active
			WHERE runner_active.runner_id = $2
			  AND runner_active.status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')
		  ) < $3
		  AND NOT EXISTS (
			SELECT 1 FROM action_queue AS target_active
			WHERE target_active.action_id <> candidate.action_id
			  AND target_active.target_key = candidate.target_key
			  AND target_active.status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')
		  )
		ORDER BY candidate.created_at, candidate.action_id
		FOR UPDATE OF candidate SKIP LOCKED
		LIMIT 1
	`, scope.Pool(), scope.RunnerID(), scope.MaxConcurrency(), workspaceIDs, environmentIDs).Scan(
		&actionID, &leaseEpoch, &workspaceID, &environmentID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return execution.ClaimedAction{}, executionlease.ErrNoLeaseAvailable
	}
	if err != nil {
		return execution.ClaimedAction{}, fmt.Errorf("select authenticated Runner action claim: %w", err)
	}
	if leaseEpoch == math.MaxInt64 {
		return execution.ClaimedAction{}, fmt.Errorf("%w: lease epoch exhausted", executionlease.ErrInvalidTransition)
	}
	if !runnerScopeAllows(scope, workspaceID, environmentID) {
		return execution.ClaimedAction{}, execution.ErrJobConflict
	}

	token, err := repository.tokenSource()
	if err != nil {
		return execution.ClaimedAction{}, fmt.Errorf("generate authenticated Runner lease token: %w", err)
	}
	if !hashPattern.MatchString(token) {
		return execution.ClaimedAction{}, fmt.Errorf("%w: lease token must contain 256 bits encoded as 64 lowercase hexadecimal characters", executionlease.ErrInvalidRequest)
	}
	digest := tokenHash(token)
	record, err := scanStoredAction(tx.QueryRow(ctx, `
		UPDATE action_queue AS queued
		SET status = 'LEASED', runner_id = $2,
			runner_tenant_id = $6, runner_workspace_id = $7, runner_environment_id = $8,
			lease_token_sha256 = $3, lease_epoch = queued.lease_epoch + 1,
			credential_expected = false, credential_lease_epoch = NULL,
			scope_revision = $5, heartbeat_seq = 0,
			lease_acquired_at = statement_timestamp(), last_heartbeat_at = statement_timestamp(),
			lease_expires_at = LEAST(
				statement_timestamp() + make_interval(secs => $4::double precision),
				queued.authorization_expires_at
			),
			started_at = NULL, completed_at = NULL, completed_lease_token_sha256 = NULL,
			completed_lease_epoch = NULL, result_hash = NULL, completion_status = NULL,
			cancel_requested_at = NULL, cancel_reason_hash = NULL,
			reconciliation_id = NULL, reconciliation_actor = NULL,
			reconciliation_result_hash = NULL, reconciled_at = NULL,
			updated_at = statement_timestamp()
		WHERE queued.action_id = $1 AND queued.status = 'QUEUED'
		  AND queued.runner_pool = $9 AND queued.production = false
		  AND queued.authorization_expires_at > statement_timestamp()
		RETURNING `+actionQueueProjection,
		actionID, scope.RunnerID(), digest, leaseDuration.Seconds(), scope.ScopeRevision(),
		scope.TenantID(), workspaceID, environmentID, scope.Pool(),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return execution.ClaimedAction{}, execution.ErrJobConflict
	}
	if err != nil {
		return execution.ClaimedAction{}, fmt.Errorf("lease authenticated Runner action: %w", err)
	}
	if record.claimed.Execution.LeaseEpoch != leaseEpoch+1 || record.leaseTokenHash != digest ||
		!runnerScopeMatchesAction(scope, record.claimed) {
		return execution.ClaimedAction{}, execution.ErrJobConflict
	}
	record.claimed.Execution.LeaseToken = token
	return record.claimed, nil
}

// StartRunnerTx transitions an authenticated, current LEASED action to
// RUNNING. The action row is locked before the trusted scope snapshot and
// lease fence are revalidated.
func (repository *Repository) StartRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	fence executionlease.LeaseIdentity,
) (executionlease.Execution, error) {
	if err := validateRunnerMutation(ctx, tx, scope, fence); err != nil {
		return executionlease.Execution{}, err
	}
	record, err := lockRunnerActionTx(ctx, tx, fence.ExecutionID, "start")
	if err != nil {
		return executionlease.Execution{}, err
	}
	if err := validateRunnerActiveFence(record, scope, fence); err != nil {
		return executionlease.Execution{}, err
	}
	if record.claimed.Execution.Status != executionlease.StatusLeased &&
		record.claimed.Execution.Status != executionlease.StatusRunning {
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	if !record.claimed.Execution.CancelRequestedAt.IsZero() {
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	digest := tokenHash(fence.Token)
	record, err = scanStoredAction(tx.QueryRow(ctx, `
		UPDATE action_queue
		SET status = 'RUNNING', started_at = COALESCE(started_at, statement_timestamp()),
			updated_at = CASE WHEN status = 'LEASED' THEN statement_timestamp() ELSE updated_at END
		WHERE action_id = $1 AND runner_id = $2 AND lease_token_sha256 = $3 AND lease_epoch = $4
		  AND runner_tenant_id = $5 AND runner_workspace_id = $6 AND runner_environment_id = $7
		  AND scope_revision = $8 AND runner_pool = $9 AND production = false
		  AND status IN ('LEASED', 'RUNNING')
		  AND cancel_requested_at IS NULL
		  AND lease_expires_at > statement_timestamp()
		  AND authorization_expires_at > statement_timestamp()
		RETURNING `+actionQueueProjection,
		fence.ExecutionID, fence.RunnerID, digest, fence.Epoch,
		scope.TenantID(), record.claimed.Execution.RunnerWorkspaceID, record.claimed.Execution.RunnerEnvironmentID,
		scope.ScopeRevision(), scope.Pool(),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("start authenticated Runner action: %w", err)
	}
	if err := validateRunnerActiveFence(record, scope, fence); err != nil {
		return executionlease.Execution{}, err
	}
	return redact(record.claimed.Execution), nil
}

// HeartbeatRunnerTx applies one strictly sequenced heartbeat. A replay returns
// the stored state without extending the lease; narrowed scope or expired
// authorization returns TERMINATE without mutating the action.
func (repository *Repository) HeartbeatRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	request execution.ActionHeartbeatRequest,
) (execution.ActionHeartbeatResult, error) {
	if err := validateRunnerMutation(ctx, tx, scope, request.Lease); err != nil {
		return execution.ActionHeartbeatResult{}, err
	}
	if request.Extension < minimumLeaseDuration || request.Extension > maximumLeaseDuration {
		return execution.ActionHeartbeatResult{}, executionlease.ErrInvalidRequest
	}
	if request.Sequence <= 0 {
		return execution.ActionHeartbeatResult{}, execution.ErrHeartbeatSequence
	}
	record, err := lockRunnerActionTx(ctx, tx, request.Lease.ExecutionID, "heartbeat")
	if err != nil {
		return execution.ActionHeartbeatResult{}, err
	}
	if !runnerFenceMatches(record, request.Lease, false) || request.Lease.RunnerID != scope.RunnerID() {
		return execution.ActionHeartbeatResult{}, executionlease.ErrStaleLease
	}
	if record.claimed.Execution.Status != executionlease.StatusLeased &&
		record.claimed.Execution.Status != executionlease.StatusRunning {
		return execution.ActionHeartbeatResult{}, executionlease.ErrInvalidTransition
	}
	if !runnerScopeMatchesAction(scope, record.claimed) {
		return execution.ActionHeartbeatResult{
			Execution: redact(record.claimed.Execution), Directive: execution.HeartbeatTerminate,
		}, nil
	}
	leaseCurrent, authorizationCurrent, err := heartbeatTimeBoundaries(ctx, tx, request.Lease.ExecutionID)
	if err != nil {
		return execution.ActionHeartbeatResult{}, fmt.Errorf("read authenticated Runner heartbeat boundaries: %w", err)
	}
	if !authorizationCurrent {
		return execution.ActionHeartbeatResult{
			Execution: redact(record.claimed.Execution), Directive: execution.HeartbeatTerminate,
		}, nil
	}
	if !leaseCurrent {
		return execution.ActionHeartbeatResult{}, executionlease.ErrStaleLease
	}
	if request.Sequence == record.claimed.Execution.HeartbeatSeq {
		return heartbeatResult(record.claimed.Execution), nil
	}
	if request.Sequence != record.claimed.Execution.HeartbeatSeq+1 {
		return execution.ActionHeartbeatResult{}, execution.ErrHeartbeatSequence
	}

	digest := tokenHash(request.Lease.Token)
	updated, err := scanStoredAction(tx.QueryRow(ctx, `
		UPDATE action_queue
		SET heartbeat_seq = $5,
			last_heartbeat_at = CASE WHEN cancel_requested_at IS NULL THEN statement_timestamp() ELSE last_heartbeat_at END,
			lease_expires_at = CASE WHEN cancel_requested_at IS NULL
				THEN LEAST(statement_timestamp() + make_interval(secs => $6::double precision), authorization_expires_at)
				ELSE lease_expires_at END,
			updated_at = statement_timestamp()
		WHERE action_id = $1 AND runner_id = $2 AND lease_token_sha256 = $3 AND lease_epoch = $4
		  AND heartbeat_seq + 1 = $5
		  AND runner_tenant_id = $7 AND runner_workspace_id = $8 AND runner_environment_id = $9
		  AND scope_revision = $10 AND runner_pool = $11 AND production = false
		  AND status IN ('LEASED', 'RUNNING')
		  AND lease_expires_at > statement_timestamp()
		  AND authorization_expires_at > statement_timestamp()
		RETURNING `+actionQueueProjection,
		request.Lease.ExecutionID, request.Lease.RunnerID, digest, request.Lease.Epoch,
		request.Sequence, request.Extension.Seconds(), scope.TenantID(),
		record.claimed.Execution.RunnerWorkspaceID, record.claimed.Execution.RunnerEnvironmentID,
		scope.ScopeRevision(), scope.Pool(),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		_, authorizationCurrent, boundaryErr := heartbeatTimeBoundaries(ctx, tx, request.Lease.ExecutionID)
		if boundaryErr != nil {
			return execution.ActionHeartbeatResult{}, fmt.Errorf("recheck authenticated Runner heartbeat boundaries: %w", boundaryErr)
		}
		if !authorizationCurrent {
			return execution.ActionHeartbeatResult{
				Execution: redact(record.claimed.Execution), Directive: execution.HeartbeatTerminate,
			}, nil
		}
		return execution.ActionHeartbeatResult{}, executionlease.ErrStaleLease
	}
	if err != nil {
		return execution.ActionHeartbeatResult{}, fmt.Errorf("heartbeat authenticated Runner action: %w", err)
	}
	if err := validateRunnerActiveFence(updated, scope, request.Lease); err != nil {
		return execution.ActionHeartbeatResult{}, err
	}
	return heartbeatResult(updated.claimed.Execution), nil
}

// ReleaseRunnerTx requeues only a LEASED (GO-before) job. The caller supplies a
// bounded reason code, while the repository creates the persisted reason hash;
// arbitrary Runner-controlled detail hashes are not accepted.
func (repository *Repository) ReleaseRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	fence executionlease.LeaseIdentity,
	reasonCode string,
	retryAfter time.Duration,
) (executionlease.Execution, error) {
	if err := validateRunnerMutation(ctx, tx, scope, fence); err != nil {
		return executionlease.Execution{}, err
	}
	if !validRunnerReleaseReasonCode(reasonCode) || retryAfter < minimumLeaseDuration || retryAfter > maximumLeaseDuration {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	record, err := lockRunnerActionTx(ctx, tx, fence.ExecutionID, "release")
	if err != nil {
		return executionlease.Execution{}, err
	}
	if err := validateRunnerActiveFence(record, scope, fence); err != nil {
		return executionlease.Execution{}, err
	}
	if record.claimed.Execution.Status != executionlease.StatusLeased {
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}

	digest := tokenHash(fence.Token)
	lastNackHash := runnerReleaseReasonHash(reasonCode)
	updated, err := scanStoredAction(tx.QueryRow(ctx, `
		UPDATE action_queue AS leased
		SET status = 'QUEUED', last_nack_hash = $9,
			not_before = statement_timestamp() + make_interval(secs => $10::double precision),
			runner_id = NULL, runner_tenant_id = NULL, runner_workspace_id = NULL, runner_environment_id = NULL,
			lease_token_sha256 = NULL, lease_acquired_at = NULL,
			lease_expires_at = NULL, last_heartbeat_at = NULL, scope_revision = NULL,
			heartbeat_seq = 0, cancel_requested_at = NULL, cancel_reason_hash = NULL,
			credential_expected = false, credential_lease_epoch = NULL,
			updated_at = statement_timestamp()
		WHERE leased.action_id = $1 AND leased.runner_id = $2
		  AND leased.lease_token_sha256 = $3 AND leased.lease_epoch = $4
		  AND leased.runner_tenant_id = $5 AND leased.runner_workspace_id = $6 AND leased.runner_environment_id = $7
		  AND leased.scope_revision = $8 AND leased.runner_pool = $11 AND leased.production = false
		  AND leased.status = 'LEASED' AND leased.lease_expires_at > statement_timestamp()
		  AND `+credentialCleanupPredicate("leased", "lease_token_sha256", credentialCleanupAllowAbsent)+`
		RETURNING `+actionQueueProjection,
		fence.ExecutionID, fence.RunnerID, digest, fence.Epoch,
		scope.TenantID(), record.claimed.Execution.RunnerWorkspaceID, record.claimed.Execution.RunnerEnvironmentID,
		scope.ScopeRevision(), lastNackHash, retryAfter.Seconds(), scope.Pool(),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		leaseCurrent, cleanupAllowed, inspectErr := inspectCurrentLeaseCleanup(ctx, tx, fence.ExecutionID, fence.Epoch)
		if inspectErr != nil {
			return executionlease.Execution{}, inspectErr
		}
		if !leaseCurrent {
			return executionlease.Execution{}, executionlease.ErrStaleLease
		}
		if !cleanupAllowed {
			return executionlease.Execution{}, execution.ErrCredentialCleanupPending
		}
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("release authenticated Runner action: %w", err)
	}
	if updated.lastNackHash != lastNackHash || updated.claimed.Execution.Status != executionlease.StatusQueued {
		return executionlease.Execution{}, execution.ErrJobConflict
	}
	return redact(updated.claimed.Execution), nil
}

// CompleteRunnerTx records a bounded structured result as FINALIZING and
// persists a certificate-bound runner-result.v2 receipt. Credential state is
// deliberately untouched; FinalizeRunnerTx owns the cleanup gate.
func (repository *Repository) CompleteRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	fence executionlease.LeaseIdentity,
	result execution.ExecutorResult,
	certificateSHA256 string,
) (RunnerCompletion, error) {
	if err := validateRunnerMutation(ctx, tx, scope, fence); err != nil {
		return RunnerCompletion{}, err
	}
	completionStatus, err := execution.ResultSummaryStatus(result)
	if err != nil || !hashPattern.MatchString(certificateSHA256) {
		return RunnerCompletion{}, executionlease.ErrInvalidRequest
	}
	record, err := lockRunnerActionTx(ctx, tx, fence.ExecutionID, "completion")
	if err != nil {
		return RunnerCompletion{}, err
	}
	if !runnerScopeMatchesAction(scope, record.claimed) || fence.RunnerID != scope.RunnerID() {
		return RunnerCompletion{}, executionlease.ErrStaleLease
	}
	request := execution.ActionCompleteRequest{Lease: fence, Summary: result}
	receipt, err := execution.BuildRunnerResultReceiptV2(record.claimed, request, completionStatus, certificateSHA256, time.Time{})
	if err != nil {
		return RunnerCompletion{}, err
	}
	digest := tokenHash(fence.Token)

	if record.claimed.Execution.Status == executionlease.StatusFinalizing || record.claimed.Execution.Terminal() {
		if !runnerFenceMatches(record, fence, true) || record.claimed.Execution.ReconciliationID != "" {
			return RunnerCompletion{}, executionlease.ErrStaleLease
		}
		if record.claimed.Execution.CompletionStatus != completionStatus || record.claimed.Execution.ResultHash != receipt.ResultHash {
			return RunnerCompletion{}, executionlease.ErrCompletionConflict
		}
		var storedHash, schemaVersion, storedCertificate string
		var receivedAt time.Time
		receiptErr := tx.QueryRow(ctx, `
			SELECT receipt_hash, schema_version, certificate_sha256, received_at
			FROM runner_result_receipts
			WHERE action_id = $1 AND lease_epoch = $2
		`, fence.ExecutionID, fence.Epoch).Scan(&storedHash, &schemaVersion, &storedCertificate, &receivedAt)
		if errors.Is(receiptErr, pgx.ErrNoRows) {
			return RunnerCompletion{}, executionlease.ErrCompletionConflict
		}
		if receiptErr != nil {
			return RunnerCompletion{}, fmt.Errorf("read idempotent authenticated Runner result receipt: %w", receiptErr)
		}
		if storedHash != receipt.ResultHash || schemaVersion != "runner-result.v2" || storedCertificate != certificateSHA256 {
			return RunnerCompletion{}, executionlease.ErrCompletionConflict
		}
		receipt.ReceivedAt = receivedAt
		return RunnerCompletion{Execution: redact(record.claimed.Execution), Receipt: receipt}, nil
	}
	if !runnerFenceMatches(record, fence, false) {
		return RunnerCompletion{}, executionlease.ErrStaleLease
	}
	if record.claimed.Execution.Status != executionlease.StatusRunning {
		return RunnerCompletion{}, executionlease.ErrInvalidTransition
	}
	summaryJSON, err := json.Marshal(result)
	if err != nil {
		return RunnerCompletion{}, fmt.Errorf("marshal authenticated Runner result summary: %w", err)
	}

	record, err = scanStoredAction(tx.QueryRow(ctx, `
		UPDATE action_queue
		SET status = 'FINALIZING', completion_status = $5, result_hash = $6,
			completed_lease_token_sha256 = lease_token_sha256, completed_lease_epoch = lease_epoch,
			lease_token_sha256 = NULL, lease_expires_at = NULL, updated_at = statement_timestamp()
		WHERE action_id = $1 AND runner_id = $2 AND lease_token_sha256 = $3 AND lease_epoch = $4
		  AND runner_tenant_id = $7 AND runner_workspace_id = $8 AND runner_environment_id = $9
		  AND scope_revision = $10 AND runner_pool = $11 AND production = false
		  AND status = 'RUNNING' AND lease_expires_at > statement_timestamp()
		RETURNING `+actionQueueProjection,
		fence.ExecutionID, fence.RunnerID, digest, fence.Epoch, completionStatus, receipt.ResultHash,
		scope.TenantID(), record.claimed.Execution.RunnerWorkspaceID, record.claimed.Execution.RunnerEnvironmentID,
		scope.ScopeRevision(), scope.Pool(),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return RunnerCompletion{}, executionlease.ErrStaleLease
	}
	if err != nil {
		return RunnerCompletion{}, fmt.Errorf("prepare authenticated Runner completion: %w", err)
	}
	if !runnerFenceMatches(record, fence, true) || record.claimed.Execution.Status != executionlease.StatusFinalizing ||
		record.claimed.Execution.CompletionStatus != completionStatus || record.claimed.Execution.ResultHash != receipt.ResultHash ||
		!runnerScopeMatchesAction(scope, record.claimed) {
		return RunnerCompletion{}, execution.ErrJobConflict
	}
	var receivedAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO runner_result_receipts (
			action_id, tenant_id, workspace_id, environment_id, runner_id, lease_epoch, scope_revision,
			certificate_sha256, receipt_hash, completion_status, schema_version, summary, received_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'runner-result.v2', $11, statement_timestamp())
		RETURNING received_at
	`, receipt.ActionID, receipt.TenantID, receipt.WorkspaceID, receipt.EnvironmentID, receipt.RunnerID,
		receipt.LeaseEpoch, receipt.ScopeRevision, receipt.CertificateSHA256, receipt.ResultHash,
		receipt.CompletionStatus, string(summaryJSON)).Scan(&receivedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return RunnerCompletion{}, executionlease.ErrCompletionConflict
		}
		return RunnerCompletion{}, fmt.Errorf("persist authenticated Runner result receipt: %w", err)
	}
	receipt.ReceivedAt = receivedAt
	return RunnerCompletion{Execution: redact(record.claimed.Execution), Receipt: receipt}, nil
}

// FinalizeRunnerTx releases FINALIZING only after the v2 receipt and credential
// cleanup proof are visible in the same caller-owned transaction.
func (repository *Repository) FinalizeRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	fence executionlease.LeaseIdentity,
) (executionlease.Execution, error) {
	if err := validateRunnerMutation(ctx, tx, scope, fence); err != nil {
		return executionlease.Execution{}, err
	}
	record, err := lockRunnerActionTx(ctx, tx, fence.ExecutionID, "finalization")
	if err != nil {
		return executionlease.Execution{}, err
	}
	if !runnerScopeMatchesAction(scope, record.claimed) || fence.RunnerID != scope.RunnerID() ||
		!runnerFenceMatches(record, fence, true) || record.claimed.Execution.ReconciliationID != "" {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if record.claimed.Execution.Terminal() {
		proofExists, proofErr := runnerV2ReceiptProofExists(ctx, tx, record)
		if proofErr != nil {
			return executionlease.Execution{}, proofErr
		}
		if !proofExists {
			return executionlease.Execution{}, executionlease.ErrCompletionConflict
		}
		return redact(record.claimed.Execution), nil
	}
	if record.claimed.Execution.Status != executionlease.StatusFinalizing ||
		!validCompletionStatus(record.claimed.Execution.CompletionStatus) {
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	digest := tokenHash(fence.Token)
	updated, err := scanStoredAction(tx.QueryRow(ctx, `
		UPDATE action_queue AS finalizing
		SET status = finalizing.completion_status,
			completed_at = statement_timestamp(), updated_at = statement_timestamp()
		WHERE finalizing.action_id = $1 AND finalizing.runner_id = $2
		  AND finalizing.completed_lease_token_sha256 = $3 AND finalizing.completed_lease_epoch = $4
		  AND finalizing.runner_tenant_id = $5 AND finalizing.runner_workspace_id = $6
		  AND finalizing.runner_environment_id = $7 AND finalizing.scope_revision = $8
		  AND finalizing.runner_pool = $9 AND finalizing.production = false
		  AND finalizing.status = 'FINALIZING'
		  AND EXISTS (
			SELECT 1 FROM runner_result_receipts AS receipt
			WHERE receipt.action_id = finalizing.action_id
			  AND receipt.lease_epoch = finalizing.lease_epoch
			  AND receipt.tenant_id = finalizing.runner_tenant_id
			  AND receipt.workspace_id = finalizing.runner_workspace_id
			  AND receipt.environment_id = finalizing.runner_environment_id
			  AND receipt.runner_id = finalizing.runner_id
			  AND receipt.scope_revision = finalizing.scope_revision
			  AND receipt.receipt_hash = finalizing.result_hash
			  AND receipt.completion_status = finalizing.completion_status
			  AND receipt.schema_version = 'runner-result.v2'
		  )
		  AND (
			finalizing.completion_status = 'UNCERTAIN' OR
			`+credentialCleanupPredicate("finalizing", "completed_lease_token_sha256", credentialCleanupStrict)+`
		  )
		RETURNING `+actionQueueProjection,
		fence.ExecutionID, fence.RunnerID, digest, fence.Epoch,
		scope.TenantID(), record.claimed.Execution.RunnerWorkspaceID, record.claimed.Execution.RunnerEnvironmentID,
		scope.ScopeRevision(), scope.Pool(),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		if record.claimed.Execution.CompletionStatus == executionlease.StatusSucceeded ||
			record.claimed.Execution.CompletionStatus == executionlease.StatusFailed {
			cleanupAllowed, inspectErr := inspectCredentialCleanup(ctx, tx, fence.ExecutionID, fence.Epoch, credentialCleanupStrict)
			if inspectErr != nil {
				return executionlease.Execution{}, inspectErr
			}
			if !cleanupAllowed {
				return executionlease.Execution{}, execution.ErrCredentialCleanupPending
			}
		}
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("finalize authenticated Runner action: %w", err)
	}
	if !runnerScopeMatchesAction(scope, updated.claimed) || !runnerFenceMatches(updated, fence, true) || !updated.claimed.Execution.Terminal() {
		return executionlease.Execution{}, execution.ErrJobConflict
	}
	return redact(updated.claimed.Execution), nil
}

func runnerTxContext(ctx context.Context, tx pgx.Tx) error {
	if ctx == nil || tx == nil {
		return executionlease.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func validateRunnerMutation(ctx context.Context, tx pgx.Tx, scope execution.RunnerScope, fence executionlease.LeaseIdentity) error {
	if err := runnerTxContext(ctx, tx); err != nil {
		return err
	}
	if err := validateRunnerWriteScope(scope, minimumLeaseDuration); err != nil {
		return err
	}
	if !validFence(fence) {
		return executionlease.ErrInvalidRequest
	}
	return nil
}

func validateRunnerWriteScope(scope execution.RunnerScope, leaseDuration time.Duration) error {
	if err := validateClaim(execution.ActionClaimRequest{Scope: scope, LeaseDuration: leaseDuration}); err != nil {
		return err
	}
	if scope.Pool() != executionlease.PoolWrite {
		return executionlease.ErrInvalidRequest
	}
	return nil
}

func lockRunnerActionTx(ctx context.Context, tx pgx.Tx, actionID, operation string) (storedAction, error) {
	record, err := scanStoredAction(tx.QueryRow(ctx, `
		SELECT `+actionQueueProjection+`
		FROM action_queue
		WHERE action_id = $1
		FOR UPDATE
	`, actionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return storedAction{}, executionlease.ErrNotFound
	}
	if err != nil {
		return storedAction{}, fmt.Errorf("lock authenticated Runner action %s state: %w", operation, err)
	}
	return record, nil
}

func validateRunnerActiveFence(record storedAction, scope execution.RunnerScope, fence executionlease.LeaseIdentity) error {
	if !runnerFenceMatches(record, fence, false) || fence.RunnerID != scope.RunnerID() ||
		!runnerScopeMatchesAction(scope, record.claimed) {
		return executionlease.ErrStaleLease
	}
	return nil
}

func runnerFenceMatches(record storedAction, fence executionlease.LeaseIdentity, completed bool) bool {
	if record.claimed.Execution.ExecutionID != fence.ExecutionID ||
		record.claimed.Execution.RunnerID != fence.RunnerID || record.claimed.Execution.LeaseEpoch != fence.Epoch {
		return false
	}
	digest := tokenHash(fence.Token)
	if completed {
		return record.completedLeaseEpoch == fence.Epoch && record.completedLeaseTokenHash == digest
	}
	return record.leaseTokenHash == digest
}

func runnerScopeMatchesAction(scope execution.RunnerScope, claimed execution.ClaimedAction) bool {
	value := claimed.Execution
	return !value.Production && value.RunnerID == scope.RunnerID() && value.RunnerTenantID == scope.TenantID() &&
		value.Pool == scope.Pool() && value.ScopeRevision == scope.ScopeRevision() &&
		value.RunnerWorkspaceID == claimed.Envelope.WorkspaceID &&
		value.RunnerEnvironmentID == claimed.Envelope.Target.EnvironmentID &&
		runnerScopeAllows(scope, value.RunnerWorkspaceID, value.RunnerEnvironmentID)
}

func runnerScopeAllows(scope execution.RunnerScope, workspaceID, environmentID string) bool {
	for _, binding := range scope.Bindings() {
		if binding.WorkspaceID == workspaceID && binding.EnvironmentID == environmentID {
			return true
		}
	}
	return false
}

func runnerV2ReceiptProofExists(ctx context.Context, tx pgx.Tx, record storedAction) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM runner_result_receipts AS receipt
			WHERE receipt.action_id = $1 AND receipt.lease_epoch = $2
			  AND receipt.receipt_hash = $3 AND receipt.completion_status = $4
			  AND receipt.runner_id = $5 AND receipt.tenant_id = $6
			  AND receipt.workspace_id = $7 AND receipt.environment_id = $8
			  AND receipt.scope_revision = $9
			  AND receipt.schema_version = 'runner-result.v2'
		)
	`, record.claimed.Execution.ExecutionID, record.claimed.Execution.LeaseEpoch,
		record.claimed.Execution.ResultHash, record.claimed.Execution.CompletionStatus,
		record.claimed.Execution.RunnerID, record.claimed.Execution.RunnerTenantID,
		record.claimed.Execution.RunnerWorkspaceID, record.claimed.Execution.RunnerEnvironmentID,
		record.claimed.Execution.ScopeRevision,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("verify authenticated Runner v2 result receipt: %w", err)
	}
	return exists, nil
}

func runnerReleaseReasonHash(reasonCode string) string {
	digest := sha256.Sum256([]byte("runner-release-reason.v1\x00" + reasonCode))
	return hex.EncodeToString(digest[:])
}

func validRunnerReleaseReasonCode(reasonCode string) bool {
	switch reasonCode {
	case "EXECUTOR_NOT_READY", "LOCAL_CAPACITY_UNAVAILABLE", "TRANSIENT_RUNNER_FAILURE":
		return true
	default:
		return false
	}
}
