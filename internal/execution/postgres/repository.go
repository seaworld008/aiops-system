package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executionlease"
)

const actionQueueProjection = `
	action_id, target_key, runner_pool, production, status,
	runner_id, lease_epoch, lease_expires_at, lease_acquired_at, last_heartbeat_at,
	started_at, completed_at, result_hash, created_at, updated_at,
	reconciliation_id, reconciliation_actor, reconciliation_result_hash, reconciled_at,
	envelope, plan_hash, environment_revision, authorization_expires_at, workspace_id, environment_id,
	submission_hash, lease_token_sha256, completed_lease_token_sha256, completed_lease_epoch,
	not_before, last_nack_hash,
	idempotency_key, request_hash, request_hash_version, scope_revision, heartbeat_seq,
	cancel_requested_at, cancel_reason_hash, completion_status
`

const (
	minimumLeaseDuration = time.Second
	maximumLeaseDuration = 30 * time.Minute
	actionClaimLock      = int64(0x4143545155455545)
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]*\z`)
	hashPattern       = regexp.MustCompile(`^[a-f0-9]{64}$`)
	reasonCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

type DB interface {
	Begin(context.Context) (pgx.Tx, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type Options struct {
	TokenSource func() (string, error)
}

type Repository struct {
	database    DB
	tokenSource func() (string, error)
}

var _ execution.ActionQueue = (*Repository)(nil)

type storedAction struct {
	claimed                 execution.ClaimedAction
	submissionHash          string
	leaseTokenHash          string
	completedLeaseTokenHash string
	completedLeaseEpoch     int64
	notBefore               time.Time
	lastNackHash            string
	idempotencyKey          string
	requestHash             string
	requestHashVersion      string
	authorizationExpiresAt  time.Time
}

const requestHashVersion = "action-request.v1"

func New(database DB, options Options) (*Repository, error) {
	if database == nil {
		return nil, fmt.Errorf("%w: PostgreSQL database is required", executionlease.ErrInvalidRequest)
	}
	if options.TokenSource == nil {
		options.TokenSource = randomToken
	}
	return &Repository{database: database, tokenSource: options.TokenSource}, nil
}

func (repository *Repository) Submit(ctx context.Context, submission execution.ActionSubmission) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if err := validateSubmission(submission); err != nil {
		return executionlease.Execution{}, err
	}
	envelopeJSON, err := json.Marshal(submission.Envelope)
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("marshal action envelope: %w", err)
	}
	submissionHash, err := hashSubmission(submission, envelopeJSON)
	if err != nil {
		return executionlease.Execution{}, err
	}
	requestHash, err := execution.RequestSemanticHash(submission)
	if err != nil {
		return executionlease.Execution{}, err
	}
	record, err := scanStoredAction(repository.database.QueryRow(ctx, `
		INSERT INTO action_queue (
			action_id, envelope, submission_hash, idempotency_key, request_hash, request_hash_version,
			plan_hash, workspace_id, environment_id,
			target_key, environment_revision, authorization_expires_at, runner_pool, production, status, not_before,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'QUEUED',
			statement_timestamp(), statement_timestamp(), statement_timestamp())
		ON CONFLICT DO NOTHING
		RETURNING `+actionQueueProjection,
		submission.Envelope.ActionID, string(envelopeJSON), submissionHash, submission.Envelope.IdempotencyKey,
		requestHash, requestHashVersion, submission.PlanHash,
		submission.Envelope.WorkspaceID, submission.Envelope.Target.EnvironmentID,
		submission.TargetKey, submission.EnvironmentRevision, submission.Envelope.ExpiresAt, submission.Pool, submission.Production,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		existing, getErr := scanStoredAction(repository.database.QueryRow(ctx, `
			SELECT `+actionQueueProjection+`
			FROM action_queue
			WHERE action_id = $1 OR (workspace_id = $2 AND idempotency_key = $3)
			ORDER BY (action_id = $1) DESC
			LIMIT 1
		`, submission.Envelope.ActionID, submission.Envelope.WorkspaceID, submission.Envelope.IdempotencyKey))
		if errors.Is(getErr, pgx.ErrNoRows) {
			return executionlease.Execution{}, executionlease.ErrNotFound
		}
		if getErr != nil {
			return executionlease.Execution{}, fmt.Errorf("read conflicting action submission: %w", getErr)
		}
		if existing.claimed.Execution.ExecutionID == submission.Envelope.ActionID {
			if existing.submissionHash != submissionHash {
				return executionlease.Execution{}, execution.ErrJobConflict
			}
			return redact(existing.claimed.Execution), nil
		}
		if existing.idempotencyKey != submission.Envelope.IdempotencyKey ||
			existing.claimed.Envelope.WorkspaceID != submission.Envelope.WorkspaceID ||
			existing.requestHashVersion != requestHashVersion || existing.requestHash != requestHash {
			return executionlease.Execution{}, execution.ErrIdempotencyConflict
		}
		if existing.submissionHash == "" {
			return executionlease.Execution{}, execution.ErrJobConflict
		}
		return redact(existing.claimed.Execution), nil
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("submit action queue entry: %w", err)
	}
	return redact(record.claimed.Execution), nil
}

func (repository *Repository) Claim(ctx context.Context, request execution.ActionClaimRequest) (execution.ClaimedAction, error) {
	if err := ctx.Err(); err != nil {
		return execution.ClaimedAction{}, err
	}
	if err := validateClaim(request); err != nil {
		return execution.ClaimedAction{}, err
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return execution.ClaimedAction{}, fmt.Errorf("begin action claim: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, actionClaimLock); err != nil {
		return execution.ClaimedAction{}, fmt.Errorf("serialize action claim: %w", err)
	}
	if err := sweepExpired(ctx, tx, ""); err != nil {
		return execution.ClaimedAction{}, err
	}

	var actionID string
	var epoch, scopeRevision int64
	err = tx.QueryRow(ctx, `
		SELECT candidate.action_id, candidate.lease_epoch, registration.scope_revision
		FROM action_queue AS candidate
		JOIN runner_registrations AS registration
		  ON registration.runner_id = $2 AND registration.enabled = true
		 AND registration.runner_pool = $1 AND registration.scope_revision = $3
		JOIN runner_scope_bindings AS binding
		  ON binding.runner_id = registration.runner_id
		 AND binding.tenant_id = registration.tenant_id
		 AND binding.workspace_id::text = candidate.workspace_id
		 AND binding.environment_id::text = candidate.environment_id
		WHERE candidate.runner_pool = $1
		  AND candidate.status = 'QUEUED'
		  AND candidate.not_before <= statement_timestamp()
		  AND (
			SELECT count(*) FROM action_queue AS runner_active
			WHERE runner_active.runner_id = registration.runner_id
			  AND runner_active.status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')
		  ) < registration.max_concurrency
		  AND NOT EXISTS (
			SELECT 1 FROM action_queue AS active
			WHERE active.action_id <> candidate.action_id
			  AND active.target_key = candidate.target_key
			  AND active.status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')
		  )
		  AND (
			candidate.runner_pool <> 'WRITE' OR candidate.production = false OR NOT EXISTS (
				SELECT 1 FROM action_queue AS active
				WHERE active.action_id <> candidate.action_id
				  AND active.runner_pool = 'WRITE' AND active.production = true
				  AND active.status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')
			)
		  )
		ORDER BY candidate.created_at, candidate.action_id
		FOR SHARE OF registration
		FOR UPDATE OF candidate SKIP LOCKED
		LIMIT 1
	`, request.Scope.Pool(), request.Scope.RunnerID(), request.Scope.ScopeRevision()).Scan(&actionID, &epoch, &scopeRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return execution.ClaimedAction{}, fmt.Errorf("commit empty action claim: %w", err)
		}
		committed = true
		return execution.ClaimedAction{}, executionlease.ErrNoLeaseAvailable
	}
	if err != nil {
		return execution.ClaimedAction{}, fmt.Errorf("select scoped action claim: %w", err)
	}
	if epoch == math.MaxInt64 {
		return execution.ClaimedAction{}, fmt.Errorf("%w: lease epoch exhausted", executionlease.ErrInvalidTransition)
	}
	token, err := repository.tokenSource()
	if err != nil {
		return execution.ClaimedAction{}, fmt.Errorf("generate action lease token: %w", err)
	}
	if !hashPattern.MatchString(token) {
		return execution.ClaimedAction{}, fmt.Errorf("%w: lease token must contain 256 bits encoded as 64 lowercase hexadecimal characters", executionlease.ErrInvalidRequest)
	}
	digest := tokenHash(token)
	record, err := scanStoredAction(tx.QueryRow(ctx, `
		UPDATE action_queue AS queued
		SET status = 'LEASED', runner_id = $2, lease_token_sha256 = $3,
			lease_epoch = queued.lease_epoch + 1,
			scope_revision = $5, heartbeat_seq = 0,
			lease_acquired_at = statement_timestamp(), last_heartbeat_at = statement_timestamp(),
			lease_expires_at = statement_timestamp() + make_interval(secs => $4::double precision),
			started_at = NULL, completed_at = NULL, completed_lease_token_sha256 = NULL,
			completed_lease_epoch = NULL, result_hash = NULL, completion_status = NULL,
			cancel_requested_at = NULL, cancel_reason_hash = NULL,
			reconciliation_id = NULL, reconciliation_actor = NULL,
			reconciliation_result_hash = NULL, reconciled_at = NULL,
			updated_at = statement_timestamp()
		WHERE queued.action_id = $1 AND queued.status = 'QUEUED'
		RETURNING `+actionQueueProjection,
		actionID, request.Scope.RunnerID(), digest, request.LeaseDuration.Seconds(), scopeRevision,
	))
	if err != nil {
		return execution.ClaimedAction{}, fmt.Errorf("lease scoped action: %w", err)
	}
	if record.leaseTokenHash != digest || record.claimed.Execution.RunnerID != request.Scope.RunnerID() {
		return execution.ClaimedAction{}, execution.ErrJobConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return execution.ClaimedAction{}, fmt.Errorf("commit action claim: %w", err)
	}
	committed = true
	record.claimed.Execution.LeaseToken = token
	return record.claimed, nil
}

func (repository *Repository) Start(ctx context.Context, fence executionlease.LeaseIdentity) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validFence(fence) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	digest := tokenHash(fence.Token)
	record, err := scanStoredAction(repository.database.QueryRow(ctx, `
		UPDATE action_queue
		SET status = 'RUNNING', started_at = COALESCE(started_at, statement_timestamp()),
			updated_at = CASE WHEN status = 'LEASED' THEN statement_timestamp() ELSE updated_at END
		WHERE action_id = $1 AND runner_id = $2 AND lease_token_sha256 = $3 AND lease_epoch = $4
		  AND status IN ('LEASED', 'RUNNING') AND lease_expires_at > statement_timestamp()
		RETURNING `+actionQueueProjection,
		fence.ExecutionID, fence.RunnerID, digest, fence.Epoch,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.leaseMiss(ctx, fence, executionlease.StatusLeased, executionlease.StatusRunning)
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("start action execution: %w", err)
	}
	if record.leaseTokenHash != digest {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	return redact(record.claimed.Execution), nil
}

func (repository *Repository) Heartbeat(ctx context.Context, request execution.ActionHeartbeatRequest) (execution.ActionHeartbeatResult, error) {
	if err := ctx.Err(); err != nil {
		return execution.ActionHeartbeatResult{}, err
	}
	if !validFence(request.Lease) || request.Extension < minimumLeaseDuration || request.Extension > maximumLeaseDuration {
		return execution.ActionHeartbeatResult{}, executionlease.ErrInvalidRequest
	}
	if request.Sequence <= 0 {
		return execution.ActionHeartbeatResult{}, execution.ErrHeartbeatSequence
	}
	digest := tokenHash(request.Lease.Token)
	record, err := scanStoredAction(repository.database.QueryRow(ctx, `
		UPDATE action_queue
		SET heartbeat_seq = $5,
			last_heartbeat_at = CASE WHEN cancel_requested_at IS NULL THEN statement_timestamp() ELSE last_heartbeat_at END,
			lease_expires_at = CASE WHEN cancel_requested_at IS NULL
				THEN statement_timestamp() + make_interval(secs => $6::double precision)
				ELSE lease_expires_at END,
			updated_at = statement_timestamp()
		WHERE action_id = $1 AND runner_id = $2 AND lease_token_sha256 = $3 AND lease_epoch = $4
		  AND status IN ('LEASED', 'RUNNING') AND lease_expires_at > statement_timestamp()
		  AND heartbeat_seq + 1 = $5
		RETURNING `+actionQueueProjection,
		request.Lease.ExecutionID, request.Lease.RunnerID, digest, request.Lease.Epoch, request.Sequence, request.Extension.Seconds(),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.heartbeatMiss(ctx, request, digest)
	}
	if err != nil {
		return execution.ActionHeartbeatResult{}, fmt.Errorf("heartbeat action execution: %w", err)
	}
	if record.leaseTokenHash != digest {
		return execution.ActionHeartbeatResult{}, executionlease.ErrStaleLease
	}
	return heartbeatResult(record.claimed.Execution), nil
}

func (repository *Repository) heartbeatMiss(ctx context.Context, request execution.ActionHeartbeatRequest, digest string) (execution.ActionHeartbeatResult, error) {
	var runnerID, storedTokenHash pgtype.Text
	var epoch, heartbeatSequence int64
	var status string
	var leaseCurrent bool
	err := repository.database.QueryRow(ctx, `
		SELECT runner_id, lease_epoch, lease_token_sha256, status, heartbeat_seq,
			COALESCE(lease_expires_at > statement_timestamp(), false) AS lease_current
		FROM action_queue
		WHERE action_id = $1
	`, request.Lease.ExecutionID).Scan(&runnerID, &epoch, &storedTokenHash, &status, &heartbeatSequence, &leaseCurrent)
	if errors.Is(err, pgx.ErrNoRows) {
		return execution.ActionHeartbeatResult{}, executionlease.ErrNotFound
	}
	if err != nil {
		return execution.ActionHeartbeatResult{}, fmt.Errorf("read action heartbeat state: %w", err)
	}
	if textValue(runnerID) != request.Lease.RunnerID || epoch != request.Lease.Epoch || textValue(storedTokenHash) != digest || !leaseCurrent {
		return execution.ActionHeartbeatResult{}, executionlease.ErrStaleLease
	}
	if executionlease.Status(status) != executionlease.StatusLeased && executionlease.Status(status) != executionlease.StatusRunning {
		return execution.ActionHeartbeatResult{}, executionlease.ErrInvalidTransition
	}
	if request.Sequence != heartbeatSequence {
		return execution.ActionHeartbeatResult{}, execution.ErrHeartbeatSequence
	}
	record, err := repository.get(ctx, request.Lease.ExecutionID)
	if err != nil {
		return execution.ActionHeartbeatResult{}, err
	}
	return heartbeatResult(record.claimed.Execution), nil
}

func heartbeatResult(value executionlease.Execution) execution.ActionHeartbeatResult {
	directive := execution.HeartbeatContinue
	if !value.CancelRequestedAt.IsZero() {
		directive = execution.HeartbeatTerminate
	}
	return execution.ActionHeartbeatResult{Execution: redact(value), Directive: directive}
}

func (repository *Repository) Complete(ctx context.Context, request execution.ActionCompleteRequest) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	completionStatus, summaryErr := execution.ResultSummaryStatus(request.Summary)
	if !validFence(request.Lease) || summaryErr != nil {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("begin action completion: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	record, err := scanStoredAction(tx.QueryRow(ctx, `
		SELECT `+actionQueueProjection+` FROM action_queue WHERE action_id = $1 FOR UPDATE
	`, request.Lease.ExecutionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("lock action completion state: %w", err)
	}
	receipt, err := execution.BuildRunnerResultReceipt(record.claimed, request, completionStatus, time.Time{})
	if err != nil {
		return executionlease.Execution{}, err
	}
	digest := tokenHash(request.Lease.Token)
	if record.claimed.Execution.Status == executionlease.StatusFinalizing || record.claimed.Execution.Terminal() {
		if record.claimed.Execution.ReconciliationID != "" || record.completedLeaseTokenHash != digest ||
			record.completedLeaseEpoch != request.Lease.Epoch || record.claimed.Execution.RunnerID != request.Lease.RunnerID {
			return executionlease.Execution{}, executionlease.ErrStaleLease
		}
		if record.claimed.Execution.CompletionStatus != completionStatus || record.claimed.Execution.ResultHash != receipt.ResultHash {
			return executionlease.Execution{}, executionlease.ErrCompletionConflict
		}
		var storedReceiptHash string
		if err := tx.QueryRow(ctx, `
			SELECT receipt_hash FROM runner_result_receipts WHERE action_id = $1 AND lease_epoch = $2
		`, request.Lease.ExecutionID, request.Lease.Epoch).Scan(&storedReceiptHash); err != nil || storedReceiptHash != receipt.ResultHash {
			return executionlease.Execution{}, executionlease.ErrCompletionConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return executionlease.Execution{}, fmt.Errorf("commit idempotent action completion: %w", err)
		}
		committed = true
		return redact(record.claimed.Execution), nil
	}
	if record.claimed.Execution.RunnerID != request.Lease.RunnerID || record.claimed.Execution.LeaseEpoch != request.Lease.Epoch ||
		record.leaseTokenHash != digest {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if record.claimed.Execution.Status != executionlease.StatusRunning {
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	record, err = scanStoredAction(tx.QueryRow(ctx, `
		UPDATE action_queue
		SET status = 'FINALIZING', completion_status = $5, result_hash = $6,
			completed_lease_token_sha256 = lease_token_sha256, completed_lease_epoch = lease_epoch,
			lease_token_sha256 = NULL, lease_expires_at = NULL, updated_at = statement_timestamp()
		WHERE action_id = $1 AND runner_id = $2 AND lease_token_sha256 = $3 AND lease_epoch = $4
		  AND status = 'RUNNING' AND lease_expires_at > statement_timestamp()
		RETURNING `+actionQueueProjection,
		request.Lease.ExecutionID, request.Lease.RunnerID, digest, request.Lease.Epoch, completionStatus, receipt.ResultHash,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("prepare action completion: %w", err)
	}
	summaryJSON, err := json.Marshal(request.Summary)
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("marshal runner result summary: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO runner_result_receipts (
			action_id, workspace_id, runner_id, lease_epoch, scope_revision,
			receipt_hash, completion_status, schema_version, summary, received_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'runner-result.v1', $8, statement_timestamp())
	`, receipt.ActionID, receipt.WorkspaceID, receipt.RunnerID, receipt.LeaseEpoch, receipt.ScopeRevision,
		receipt.ResultHash, receipt.CompletionStatus, string(summaryJSON)); err != nil {
		if isUniqueViolation(err) {
			return executionlease.Execution{}, executionlease.ErrCompletionConflict
		}
		return executionlease.Execution{}, fmt.Errorf("persist runner result receipt: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return executionlease.Execution{}, fmt.Errorf("commit action completion receipt: %w", err)
	}
	committed = true
	return redact(record.claimed.Execution), nil
}

func (repository *Repository) Finalize(ctx context.Context, fence executionlease.LeaseIdentity) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validFence(fence) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	digest := tokenHash(fence.Token)
	record, err := scanStoredAction(repository.database.QueryRow(ctx, `
		UPDATE action_queue AS finalizing
		SET status = finalizing.completion_status, completed_at = statement_timestamp(), updated_at = statement_timestamp()
		WHERE finalizing.action_id = $1 AND finalizing.runner_id = $2
		  AND finalizing.completed_lease_token_sha256 = $3 AND finalizing.completed_lease_epoch = $4
		  AND finalizing.status = 'FINALIZING'
		  AND EXISTS (
			SELECT 1 FROM runner_result_receipts AS receipt
			WHERE receipt.action_id = finalizing.action_id AND receipt.lease_epoch = finalizing.lease_epoch
			  AND receipt.receipt_hash = finalizing.result_hash
			  AND receipt.completion_status = finalizing.completion_status
		  )
		RETURNING `+actionQueueProjection,
		fence.ExecutionID, fence.RunnerID, digest, fence.Epoch,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		record, getErr := repository.get(ctx, fence.ExecutionID)
		if getErr != nil {
			return executionlease.Execution{}, getErr
		}
		if record.claimed.Execution.ReconciliationID != "" || record.claimed.Execution.RunnerID != fence.RunnerID ||
			record.completedLeaseTokenHash != digest || record.completedLeaseEpoch != fence.Epoch {
			return executionlease.Execution{}, executionlease.ErrStaleLease
		}
		if record.claimed.Execution.Terminal() {
			return redact(record.claimed.Execution), nil
		}
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("finalize action result receipt: %w", err)
	}
	return redact(record.claimed.Execution), nil
}

func (repository *Repository) Reject(ctx context.Context, request execution.ActionRejectRequest) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validFence(request.Lease) || !validReason(request.Reason) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	resultHash, err := reasonHash(request.Reason)
	if err != nil {
		return executionlease.Execution{}, err
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("begin action rejection: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	digest := tokenHash(request.Lease.Token)
	record, err := scanStoredAction(tx.QueryRow(ctx, `
		UPDATE action_queue
		SET status = 'FAILED', completion_status = 'FAILED', completed_lease_token_sha256 = lease_token_sha256,
			completed_lease_epoch = lease_epoch, lease_token_sha256 = NULL,
			lease_expires_at = NULL, result_hash = $5,
			completed_at = statement_timestamp(), updated_at = statement_timestamp()
		WHERE action_id = $1 AND runner_id = $2 AND lease_token_sha256 = $3 AND lease_epoch = $4
		  AND status = 'LEASED' AND lease_expires_at > statement_timestamp()
		RETURNING `+actionQueueProjection,
		request.Lease.ExecutionID, request.Lease.RunnerID, digest, request.Lease.Epoch, resultHash,
	))
	if err == nil {
		if err := tx.Commit(ctx); err != nil {
			return executionlease.Execution{}, fmt.Errorf("commit action rejection: %w", err)
		}
		committed = true
		return redact(record.claimed.Execution), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return executionlease.Execution{}, fmt.Errorf("reject queued action: %w", err)
	}
	record, err = scanStoredAction(tx.QueryRow(ctx, `SELECT `+actionQueueProjection+` FROM action_queue WHERE action_id = $1 FOR SHARE`, request.Lease.ExecutionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("read action rejection state: %w", err)
	}
	if record.completedLeaseTokenHash == digest && record.completedLeaseEpoch == request.Lease.Epoch &&
		record.claimed.Execution.RunnerID == request.Lease.RunnerID {
		if record.claimed.Execution.Status != executionlease.StatusFailed || record.claimed.Execution.ResultHash != resultHash {
			return executionlease.Execution{}, executionlease.ErrCompletionConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return executionlease.Execution{}, fmt.Errorf("commit idempotent action rejection: %w", err)
		}
		committed = true
		return redact(record.claimed.Execution), nil
	}
	if record.claimed.Execution.RunnerID != request.Lease.RunnerID || record.claimed.Execution.LeaseEpoch != request.Lease.Epoch ||
		record.leaseTokenHash != digest {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if record.claimed.Execution.Status != executionlease.StatusLeased {
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	return executionlease.Execution{}, executionlease.ErrStaleLease
}

func (repository *Repository) Nack(ctx context.Context, request execution.ActionNackRequest) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validFence(request.Lease) || !validReason(request.Reason) ||
		request.RetryAfter < minimumLeaseDuration || request.RetryAfter > maximumLeaseDuration {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	lastNackHash, err := reasonHash(request.Reason)
	if err != nil {
		return executionlease.Execution{}, err
	}
	digest := tokenHash(request.Lease.Token)
	record, err := scanStoredAction(repository.database.QueryRow(ctx, `
		UPDATE action_queue
		SET status = 'QUEUED', last_nack_hash = $5,
			not_before = statement_timestamp() + make_interval(secs => $6::double precision),
			runner_id = NULL, lease_token_sha256 = NULL, lease_acquired_at = NULL,
			lease_expires_at = NULL, last_heartbeat_at = NULL, scope_revision = NULL,
			heartbeat_seq = 0, cancel_requested_at = NULL, cancel_reason_hash = NULL,
			updated_at = statement_timestamp()
		WHERE action_id = $1 AND runner_id = $2 AND lease_token_sha256 = $3 AND lease_epoch = $4
		  AND status = 'LEASED' AND lease_expires_at > statement_timestamp()
		RETURNING `+actionQueueProjection,
		request.Lease.ExecutionID, request.Lease.RunnerID, digest, request.Lease.Epoch,
		lastNackHash, request.RetryAfter.Seconds(),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.leaseMiss(ctx, request.Lease, executionlease.StatusLeased)
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("nack queued action: %w", err)
	}
	if record.lastNackHash != lastNackHash {
		return executionlease.Execution{}, execution.ErrJobConflict
	}
	return redact(record.claimed.Execution), nil
}

func (repository *Repository) Reconcile(ctx context.Context, request executionlease.ReconcileRequest) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validIdentifier(request.ExecutionID, 256) || !validIdentifier(request.ReconciliationID, 256) ||
		!validIdentifier(request.ActorID, 256) ||
		(request.Status != executionlease.StatusSucceeded && request.Status != executionlease.StatusFailed) ||
		!hashPattern.MatchString(request.ResultHash) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("begin action reconciliation: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := sweepExpired(ctx, tx, request.ExecutionID); err != nil {
		return executionlease.Execution{}, err
	}
	record, err := scanStoredAction(tx.QueryRow(ctx, `
		UPDATE action_queue
		SET reconciliation_id = $2, reconciliation_actor = $3, status = $4,
			reconciliation_result_hash = $5, reconciled_at = statement_timestamp(),
			updated_at = statement_timestamp()
		WHERE action_id = $1 AND status = 'UNCERTAIN' AND reconciliation_id IS NULL
		RETURNING `+actionQueueProjection,
		request.ExecutionID, request.ReconciliationID, request.ActorID, request.Status, request.ResultHash,
	))
	if err == nil {
		if err := tx.Commit(ctx); err != nil {
			return executionlease.Execution{}, fmt.Errorf("commit action reconciliation: %w", err)
		}
		committed = true
		return redact(record.claimed.Execution), nil
	}
	if isUniqueViolation(err) {
		return executionlease.Execution{}, executionlease.ErrReconciliationConflict
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return executionlease.Execution{}, fmt.Errorf("reconcile action execution: %w", err)
	}
	record, err = scanStoredAction(tx.QueryRow(ctx, `SELECT `+actionQueueProjection+` FROM action_queue WHERE action_id = $1 FOR SHARE`, request.ExecutionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("read action reconciliation state: %w", err)
	}
	if record.claimed.Execution.ReconciliationID == "" {
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	if record.claimed.Execution.ReconciliationID != request.ReconciliationID ||
		record.claimed.Execution.ReconciliationActor != request.ActorID ||
		record.claimed.Execution.Status != request.Status ||
		record.claimed.Execution.ReconciliationResultHash != request.ResultHash {
		return executionlease.Execution{}, executionlease.ErrReconciliationConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return executionlease.Execution{}, fmt.Errorf("commit idempotent action reconciliation: %w", err)
	}
	committed = true
	return redact(record.claimed.Execution), nil
}

func (repository *Repository) Cancel(ctx context.Context, actionID string) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validIdentifier(actionID, 256) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	record, err := scanStoredAction(repository.database.QueryRow(ctx, `
		UPDATE action_queue
		SET status = CASE WHEN status = 'RUNNING' THEN status ELSE 'CANCELLED' END,
			cancel_requested_at = CASE WHEN status = 'RUNNING' THEN COALESCE(cancel_requested_at, statement_timestamp()) ELSE NULL END,
			cancel_reason_hash = CASE WHEN status = 'RUNNING' THEN COALESCE(cancel_reason_hash, $2) ELSE NULL END,
			runner_id = CASE WHEN status = 'RUNNING' THEN runner_id ELSE NULL END,
			scope_revision = CASE WHEN status = 'RUNNING' THEN scope_revision ELSE NULL END,
			lease_token_sha256 = CASE WHEN status = 'RUNNING' THEN lease_token_sha256 ELSE NULL END,
			lease_expires_at = CASE WHEN status = 'RUNNING' THEN lease_expires_at ELSE NULL END,
			completed_at = CASE WHEN status = 'RUNNING' THEN completed_at ELSE statement_timestamp() END,
			updated_at = CASE WHEN status = 'RUNNING' AND cancel_requested_at IS NOT NULL THEN updated_at ELSE statement_timestamp() END
		WHERE action_id = $1 AND status IN ('QUEUED', 'LEASED', 'RUNNING')
		RETURNING `+actionQueueProjection,
		actionID, cancellationResultHash(),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		existing, getErr := repository.get(ctx, actionID)
		if getErr != nil {
			return executionlease.Execution{}, getErr
		}
		if existing.claimed.Execution.Terminal() {
			return redact(existing.claimed.Execution), nil
		}
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("cancel action execution: %w", err)
	}
	return redact(record.claimed.Execution), nil
}

func validReason(reason execution.ActionQueueReason) bool {
	return reasonCodePattern.MatchString(reason.Code) && hashPattern.MatchString(reason.DetailHash)
}

func reasonHash(reason execution.ActionQueueReason) (string, error) {
	encoded, err := json.Marshal(struct {
		SchemaVersion string `json:"schema_version"`
		Code          string `json:"code"`
		DetailHash    string `json:"detail_hash"`
	}{SchemaVersion: "action-queue-reason.v1", Code: reason.Code, DetailHash: reason.DetailHash})
	if err != nil {
		return "", fmt.Errorf("hash action queue reason: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validCompletionStatus(status executionlease.Status) bool {
	return status == executionlease.StatusSucceeded || status == executionlease.StatusFailed || status == executionlease.StatusUncertain
}

func validateClaim(request execution.ActionClaimRequest) error {
	if !validIdentifier(request.Scope.RunnerID(), 256) || !validPool(request.Scope.Pool()) || request.Scope.ScopeRevision() <= 0 ||
		request.Scope.MaxConcurrency() < 1 || request.Scope.MaxConcurrency() > 1024 ||
		request.LeaseDuration < minimumLeaseDuration || request.LeaseDuration > maximumLeaseDuration {
		return executionlease.ErrInvalidRequest
	}
	bindings := request.Scope.Bindings()
	if len(bindings) == 0 {
		return executionlease.ErrInvalidRequest
	}
	seen := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if !validIdentifier(binding.WorkspaceID, 256) || !validIdentifier(binding.EnvironmentID, 256) {
			return executionlease.ErrInvalidRequest
		}
		key := binding.WorkspaceID + "\x00" + binding.EnvironmentID
		if _, duplicate := seen[key]; duplicate {
			return executionlease.ErrInvalidRequest
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validFence(fence executionlease.LeaseIdentity) bool {
	return validIdentifier(fence.ExecutionID, 256) && validIdentifier(fence.RunnerID, 256) &&
		hashPattern.MatchString(fence.Token) && fence.Epoch > 0
}

func (repository *Repository) leaseMiss(ctx context.Context, fence executionlease.LeaseIdentity, allowedStatuses ...executionlease.Status) (executionlease.Execution, error) {
	var runnerID, storedTokenHash pgtype.Text
	var epoch int64
	var status string
	var leaseCurrent bool
	err := repository.database.QueryRow(ctx, `
		SELECT runner_id, lease_epoch, lease_token_sha256, status,
			COALESCE(lease_expires_at > statement_timestamp(), false) AS lease_current
		FROM action_queue
		WHERE action_id = $1
	`, fence.ExecutionID).Scan(&runnerID, &epoch, &storedTokenHash, &status, &leaseCurrent)
	if errors.Is(err, pgx.ErrNoRows) {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("read action lease state: %w", err)
	}
	digest := tokenHash(fence.Token)
	if textValue(runnerID) != fence.RunnerID || epoch != fence.Epoch || textValue(storedTokenHash) != digest || !leaseCurrent {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	for _, allowed := range allowedStatuses {
		if executionlease.Status(status) == allowed {
			return executionlease.Execution{}, executionlease.ErrStaleLease
		}
	}
	return executionlease.Execution{}, executionlease.ErrInvalidTransition
}

func (repository *Repository) get(ctx context.Context, actionID string) (storedAction, error) {
	record, err := scanStoredAction(repository.database.QueryRow(ctx, `
		SELECT `+actionQueueProjection+`
		FROM action_queue
		WHERE action_id = $1
	`, actionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return storedAction{}, executionlease.ErrNotFound
	}
	if err != nil {
		return storedAction{}, fmt.Errorf("get queued action: %w", err)
	}
	return record, nil
}

func validateIdentifiers(values []string) error {
	if len(values) == 0 {
		return executionlease.ErrInvalidRequest
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validIdentifier(value, 256) {
			return executionlease.ErrInvalidRequest
		}
		if _, duplicate := seen[value]; duplicate {
			return executionlease.ErrInvalidRequest
		}
		seen[value] = struct{}{}
	}
	return nil
}

func sweepExpired(ctx context.Context, tx pgx.Tx, actionID string) error {
	predicate := ""
	args := []any{expiredResultHash()}
	if actionID != "" {
		predicate = " AND expired_running.action_id = $2"
		args = append(args, actionID)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE action_queue AS expired_running
		SET status = 'UNCERTAIN', completion_status = 'UNCERTAIN', result_hash = $1,
			completed_lease_token_sha256 = lease_token_sha256, completed_lease_epoch = lease_epoch,
			lease_token_sha256 = NULL,
			lease_expires_at = NULL, completed_at = statement_timestamp(), updated_at = statement_timestamp()
		WHERE expired_running.status = 'RUNNING'
		  AND expired_running.lease_expires_at <= statement_timestamp()
	`+predicate, args...); err != nil {
		return fmt.Errorf("mark expired running action uncertain: %w", err)
	}
	predicate = ""
	args = nil
	if actionID != "" {
		predicate = " AND expired_finalizing.action_id = $1"
		args = append(args, actionID)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE action_queue AS expired_finalizing
		SET status = expired_finalizing.completion_status,
			completed_at = statement_timestamp(), updated_at = statement_timestamp()
		WHERE expired_finalizing.status = 'FINALIZING'
		  AND expired_finalizing.authorization_expires_at <= statement_timestamp()
		  AND EXISTS (
			SELECT 1 FROM runner_result_receipts AS receipt
			WHERE receipt.action_id = expired_finalizing.action_id
			  AND receipt.lease_epoch = expired_finalizing.lease_epoch
			  AND receipt.receipt_hash = expired_finalizing.result_hash
			  AND receipt.completion_status = expired_finalizing.completion_status
		  )
	`+predicate, args...); err != nil {
		return fmt.Errorf("recover expired finalizing action: %w", err)
	}
	predicate = ""
	args = nil
	if actionID != "" {
		predicate = " AND expired_lease.action_id = $1"
		args = append(args, actionID)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE action_queue AS expired_lease
		SET status = 'QUEUED', runner_id = NULL, lease_token_sha256 = NULL,
			lease_acquired_at = NULL, lease_expires_at = NULL, last_heartbeat_at = NULL,
			scope_revision = NULL, heartbeat_seq = 0, cancel_requested_at = NULL, cancel_reason_hash = NULL,
			not_before = statement_timestamp(), updated_at = statement_timestamp()
		WHERE expired_lease.status = 'LEASED'
		  AND expired_lease.lease_expires_at <= statement_timestamp()
	`+predicate, args...); err != nil {
		return fmt.Errorf("release expired unstarted action: %w", err)
	}
	return nil
}

func (repository *Repository) SweepExpired(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin action expiry sweep: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, actionClaimLock); err != nil {
		return fmt.Errorf("serialize action expiry sweep: %w", err)
	}
	if err := sweepExpired(ctx, tx, ""); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit action expiry sweep: %w", err)
	}
	committed = true
	return nil
}

func (repository *Repository) Get(ctx context.Context, actionID string) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validIdentifier(actionID, 256) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	if err := repository.materialize(ctx, actionID); err != nil {
		return executionlease.Execution{}, err
	}
	record, err := repository.get(ctx, actionID)
	if err != nil {
		return executionlease.Execution{}, err
	}
	return redact(record.claimed.Execution), nil
}

func (repository *Repository) materialize(ctx context.Context, actionID string) error {
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin action expiry materialization: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := sweepExpired(ctx, tx, actionID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit action expiry materialization: %w", err)
	}
	committed = true
	return nil
}

func tokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func expiredResultHash() string {
	digest := sha256.Sum256([]byte("action-queue-result.v1\x00RUNNING_LEASE_EXPIRED"))
	return hex.EncodeToString(digest[:])
}

func cancellationResultHash() string {
	return execution.CancellationIntentHash()
}

func isUniqueViolation(err error) bool {
	var databaseError *pgconn.PgError
	return errors.As(err, &databaseError) && databaseError.Code == "23505"
}

func validateSubmission(submission execution.ActionSubmission) error {
	if err := submission.Envelope.Validate(); err != nil {
		return fmt.Errorf("%w: %v", execution.ErrInvalidAction, err)
	}
	if submission.PlanHash == "" || submission.PlanHash != submission.Envelope.PlanHash ||
		!validIdentifier(submission.TargetKey, 512) || !validIdentifier(submission.EnvironmentRevision, 256) ||
		!validPool(submission.Pool) {
		return executionlease.ErrInvalidRequest
	}
	return nil
}

func hashSubmission(submission execution.ActionSubmission, envelopeJSON []byte) (string, error) {
	encoded, err := json.Marshal(struct {
		SchemaVersion       string              `json:"schema_version"`
		Envelope            json.RawMessage     `json:"envelope"`
		PlanHash            string              `json:"plan_hash"`
		TargetKey           string              `json:"target_key"`
		EnvironmentRevision string              `json:"environment_revision"`
		Production          bool                `json:"production"`
		Pool                executionlease.Pool `json:"pool"`
	}{
		SchemaVersion: "action-queue-submission.v1", Envelope: envelopeJSON,
		PlanHash: submission.PlanHash, TargetKey: submission.TargetKey,
		EnvironmentRevision: submission.EnvironmentRevision, Production: submission.Production, Pool: submission.Pool,
	})
	if err != nil {
		return "", fmt.Errorf("hash action submission: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func scanStoredAction(row pgx.Row) (storedAction, error) {
	var record storedAction
	var pool, status string
	var runnerID, resultHash pgtype.Text
	var reconciliationID, reconciliationActor, reconciliationResultHash pgtype.Text
	var leaseTokenHash, completedLeaseTokenHash, lastNackHash pgtype.Text
	var cancelReasonHash, completionStatus pgtype.Text
	var leaseExpiresAt, leaseAcquiredAt, lastHeartbeatAt, authorizationExpiresAt pgtype.Timestamptz
	var startedAt, completedAt, reconciledAt, cancelRequestedAt pgtype.Timestamptz
	var completedLeaseEpoch, scopeRevision pgtype.Int8
	var envelopeJSON []byte
	var workspaceID, environmentID string
	err := row.Scan(
		&record.claimed.Execution.ExecutionID, &record.claimed.Execution.TargetKey, &pool,
		&record.claimed.Execution.Production, &status, &runnerID, &record.claimed.Execution.LeaseEpoch,
		&leaseExpiresAt, &leaseAcquiredAt, &lastHeartbeatAt, &startedAt, &completedAt, &resultHash,
		&record.claimed.Execution.CreatedAt, &record.claimed.Execution.UpdatedAt,
		&reconciliationID, &reconciliationActor, &reconciliationResultHash, &reconciledAt,
		&envelopeJSON, &record.claimed.PlanHash, &record.claimed.EnvironmentRevision, &authorizationExpiresAt, &workspaceID, &environmentID,
		&record.submissionHash, &leaseTokenHash, &completedLeaseTokenHash, &completedLeaseEpoch,
		&record.notBefore, &lastNackHash,
		&record.idempotencyKey, &record.requestHash, &record.requestHashVersion, &scopeRevision,
		&record.claimed.Execution.HeartbeatSeq, &cancelRequestedAt, &cancelReasonHash, &completionStatus,
	)
	if err != nil {
		return storedAction{}, err
	}
	if err := json.Unmarshal(envelopeJSON, &record.claimed.Envelope); err != nil {
		return storedAction{}, fmt.Errorf("decode stored action envelope: %w", err)
	}
	record.claimed.Execution.Pool = executionlease.Pool(pool)
	record.claimed.Execution.Status = executionlease.Status(status)
	record.claimed.Execution.RunnerID = textValue(runnerID)
	record.claimed.Execution.ResultHash = textValue(resultHash)
	record.claimed.Execution.ReconciliationID = textValue(reconciliationID)
	record.claimed.Execution.ReconciliationActor = textValue(reconciliationActor)
	record.claimed.Execution.ReconciliationResultHash = textValue(reconciliationResultHash)
	record.claimed.Execution.LeaseExpiresAt = timeValue(leaseExpiresAt)
	record.claimed.Execution.LeaseAcquiredAt = timeValue(leaseAcquiredAt)
	record.claimed.Execution.LastHeartbeatAt = timeValue(lastHeartbeatAt)
	record.claimed.Execution.StartedAt = timeValue(startedAt)
	record.claimed.Execution.CompletedAt = timeValue(completedAt)
	record.claimed.Execution.ReconciledAt = timeValue(reconciledAt)
	record.claimed.Execution.CancelRequestedAt = timeValue(cancelRequestedAt)
	record.claimed.Execution.CancelReasonHash = textValue(cancelReasonHash)
	record.claimed.Execution.CompletionStatus = executionlease.Status(textValue(completionStatus))
	record.authorizationExpiresAt = timeValue(authorizationExpiresAt)
	record.claimed.TargetKey = record.claimed.Execution.TargetKey
	record.claimed.Production = record.claimed.Execution.Production
	record.leaseTokenHash = textValue(leaseTokenHash)
	record.completedLeaseTokenHash = textValue(completedLeaseTokenHash)
	record.lastNackHash = textValue(lastNackHash)
	if completedLeaseEpoch.Valid {
		record.completedLeaseEpoch = completedLeaseEpoch.Int64
	}
	if scopeRevision.Valid {
		record.claimed.Execution.ScopeRevision = scopeRevision.Int64
	}
	if record.claimed.Envelope.WorkspaceID != workspaceID || record.claimed.Envelope.Target.EnvironmentID != environmentID ||
		record.claimed.Envelope.PlanHash != record.claimed.PlanHash || record.claimed.Envelope.ActionID != record.claimed.Execution.ExecutionID ||
		record.claimed.Envelope.IdempotencyKey != record.idempotencyKey || record.authorizationExpiresAt.IsZero() ||
		absDuration(record.authorizationExpiresAt.Sub(record.claimed.Envelope.ExpiresAt.UTC())) > time.Microsecond {
		return storedAction{}, execution.ErrJobConflict
	}
	canonicalEnvelope, err := json.Marshal(record.claimed.Envelope)
	if err != nil {
		return storedAction{}, fmt.Errorf("canonicalize stored action envelope: %w", err)
	}
	expectedSubmissionHash, err := hashSubmission(execution.ActionSubmission{
		Envelope: record.claimed.Envelope, PlanHash: record.claimed.PlanHash,
		TargetKey: record.claimed.TargetKey, EnvironmentRevision: record.claimed.EnvironmentRevision,
		Production: record.claimed.Production, Pool: record.claimed.Execution.Pool,
	}, canonicalEnvelope)
	if err != nil {
		return storedAction{}, err
	}
	if record.submissionHash != expectedSubmissionHash {
		return storedAction{}, execution.ErrJobConflict
	}
	switch record.requestHashVersion {
	case requestHashVersion:
		expectedRequestHash, err := execution.RequestSemanticHash(execution.ActionSubmission{
			Envelope: record.claimed.Envelope, PlanHash: record.claimed.PlanHash,
			TargetKey: record.claimed.TargetKey, EnvironmentRevision: record.claimed.EnvironmentRevision,
			Production: record.claimed.Production, Pool: record.claimed.Execution.Pool,
		})
		if err != nil {
			return storedAction{}, err
		}
		if record.requestHash != expectedRequestHash {
			return storedAction{}, execution.ErrJobConflict
		}
	case "legacy-submission.v1":
		if record.requestHash != record.submissionHash {
			return storedAction{}, execution.ErrJobConflict
		}
	default:
		return storedAction{}, execution.ErrJobConflict
	}
	return record, nil
}

func validPool(pool executionlease.Pool) bool {
	return pool == executionlease.PoolRead || pool == executionlease.PoolWrite
}

func validIdentifier(value string, maximumBytes int) bool {
	return len(value) <= maximumBytes && identifierPattern.MatchString(value)
}

func textValue(value pgtype.Text) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func timeValue(value pgtype.Timestamptz) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return value.Time.UTC()
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

func redact(value executionlease.Execution) executionlease.Execution {
	value.LeaseToken = ""
	return value
}

func randomToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
