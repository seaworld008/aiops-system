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
	runner_id, runner_tenant_id::text, runner_workspace_id::text, runner_environment_id::text,
	lease_epoch, lease_expires_at, lease_acquired_at, last_heartbeat_at,
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

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type credentialCleanupMode uint8

const (
	credentialCleanupStrict credentialCleanupMode = iota
	credentialCleanupAllowAbsent
)

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
		existingRequestHash, hashErr := storedRequestSemanticHash(existing)
		if hashErr != nil {
			return executionlease.Execution{}, hashErr
		}
		if existing.claimed.Execution.ExecutionID == submission.Envelope.ActionID {
			if existingRequestHash == requestHash {
				return redact(existing.claimed.Execution), nil
			}
			if existing.submissionHash == submissionHash {
				return redact(existing.claimed.Execution), nil
			}
			return executionlease.Execution{}, execution.ErrJobConflict
		}
		if existing.idempotencyKey != submission.Envelope.IdempotencyKey ||
			existing.claimed.Envelope.WorkspaceID != submission.Envelope.WorkspaceID ||
			existingRequestHash != requestHash {
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

	for {
		var actionID, runnerTenantID, runnerWorkspaceID, runnerEnvironmentID string
		var epoch, scopeRevision int64
		err = tx.QueryRow(ctx, `
		SELECT candidate.action_id, candidate.lease_epoch, registration.scope_revision,
			registration.tenant_id::text, binding.workspace_id::text, binding.environment_id::text
		FROM action_queue AS candidate
		JOIN runner_registrations AS registration
		  ON registration.runner_id = $2 AND registration.enabled = true
		 AND registration.runner_pool = $1 AND registration.scope_revision = $3
		 AND registration.tenant_id::text = $4
		JOIN runner_scope_bindings AS binding
		  ON binding.runner_id = registration.runner_id
		 AND binding.tenant_id = registration.tenant_id
		 AND binding.workspace_id::text = candidate.workspace_id
		 AND binding.environment_id::text = candidate.environment_id
		WHERE candidate.runner_pool = $1
		  AND candidate.status = 'QUEUED'
		  AND candidate.not_before <= statement_timestamp()
		  AND candidate.authorization_expires_at > statement_timestamp()
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
		  AND (candidate.runner_pool <> 'WRITE' OR candidate.production = false)
		ORDER BY candidate.created_at, candidate.action_id
		FOR SHARE OF registration
		FOR UPDATE OF candidate SKIP LOCKED
		LIMIT 1
	`, request.Scope.Pool(), request.Scope.RunnerID(), request.Scope.ScopeRevision(), request.Scope.TenantID()).Scan(
			&actionID, &epoch, &scopeRevision, &runnerTenantID, &runnerWorkspaceID, &runnerEnvironmentID,
		)
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
		SET status = 'LEASED', runner_id = $2,
			runner_tenant_id = $6, runner_workspace_id = $7, runner_environment_id = $8,
			lease_token_sha256 = $3,
			lease_epoch = queued.lease_epoch + 1,
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
		  AND queued.authorization_expires_at > statement_timestamp()
		  AND (queued.runner_pool <> 'WRITE' OR queued.production = false)
		RETURNING `+actionQueueProjection,
			actionID, request.Scope.RunnerID(), digest, request.LeaseDuration.Seconds(), scopeRevision,
			runnerTenantID, runnerWorkspaceID, runnerEnvironmentID,
		))
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return execution.ClaimedAction{}, fmt.Errorf("lease scoped action: %w", err)
		}
		if (record.claimed.Execution.Pool == executionlease.PoolWrite && record.claimed.Execution.Production) ||
			record.leaseTokenHash != digest || record.claimed.Execution.RunnerID != request.Scope.RunnerID() ||
			record.claimed.Execution.RunnerTenantID != runnerTenantID ||
			record.claimed.Execution.RunnerWorkspaceID != runnerWorkspaceID ||
			record.claimed.Execution.RunnerEnvironmentID != runnerEnvironmentID {
			return execution.ClaimedAction{}, execution.ErrJobConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return execution.ClaimedAction{}, fmt.Errorf("commit action claim: %w", err)
		}
		committed = true
		record.claimed.Execution.LeaseToken = token
		return record.claimed, nil
	}
}

func (repository *Repository) Start(ctx context.Context, fence executionlease.LeaseIdentity) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validFence(fence) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	digest := tokenHash(fence.Token)
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("begin action start: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	registration, err := lockRunnerRegistration(ctx, tx, fence.RunnerID)
	if err != nil {
		return executionlease.Execution{}, err
	}
	record, err := scanStoredAction(tx.QueryRow(ctx, `
		SELECT `+actionQueueProjection+`
		FROM action_queue
		WHERE action_id = $1
		FOR UPDATE
	`, fence.ExecutionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("lock action start state: %w", err)
	}
	if record.claimed.Execution.RunnerID != fence.RunnerID || record.claimed.Execution.LeaseEpoch != fence.Epoch ||
		record.leaseTokenHash != digest {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if record.claimed.Execution.Status != executionlease.StatusLeased && record.claimed.Execution.Status != executionlease.StatusRunning {
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	if !registration.matches(record.claimed.Execution) {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	record, err = scanStoredAction(tx.QueryRow(ctx, `
		UPDATE action_queue
		SET status = 'RUNNING', started_at = COALESCE(started_at, statement_timestamp()),
			updated_at = CASE WHEN status = 'LEASED' THEN statement_timestamp() ELSE updated_at END
		WHERE action_id = $1 AND runner_id = $2 AND lease_token_sha256 = $3 AND lease_epoch = $4
		  AND status IN ('LEASED', 'RUNNING') AND lease_expires_at > statement_timestamp()
		  AND authorization_expires_at > statement_timestamp()
		RETURNING `+actionQueueProjection,
		fence.ExecutionID, fence.RunnerID, digest, fence.Epoch,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("start action execution: %w", err)
	}
	if record.leaseTokenHash != digest {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if err := tx.Commit(ctx); err != nil {
		return executionlease.Execution{}, fmt.Errorf("commit action start: %w", err)
	}
	committed = true
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
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return execution.ActionHeartbeatResult{}, fmt.Errorf("begin action heartbeat: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	registration, err := lockRunnerRegistration(ctx, tx, request.Lease.RunnerID)
	if err != nil {
		return execution.ActionHeartbeatResult{}, err
	}
	record, err := scanStoredAction(tx.QueryRow(ctx, `
		SELECT `+actionQueueProjection+`
		FROM action_queue
		WHERE action_id = $1
		FOR UPDATE
	`, request.Lease.ExecutionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return execution.ActionHeartbeatResult{}, executionlease.ErrNotFound
	}
	if err != nil {
		return execution.ActionHeartbeatResult{}, fmt.Errorf("lock action heartbeat state: %w", err)
	}
	if record.claimed.Execution.RunnerID != request.Lease.RunnerID || record.claimed.Execution.LeaseEpoch != request.Lease.Epoch ||
		record.leaseTokenHash != digest {
		return execution.ActionHeartbeatResult{}, executionlease.ErrStaleLease
	}
	if record.claimed.Execution.Status != executionlease.StatusLeased && record.claimed.Execution.Status != executionlease.StatusRunning {
		return execution.ActionHeartbeatResult{}, executionlease.ErrInvalidTransition
	}
	if !registration.matches(record.claimed.Execution) {
		if err := tx.Commit(ctx); err != nil {
			return execution.ActionHeartbeatResult{}, fmt.Errorf("commit terminated action heartbeat: %w", err)
		}
		committed = true
		return execution.ActionHeartbeatResult{Execution: redact(record.claimed.Execution), Directive: execution.HeartbeatTerminate}, nil
	}
	var leaseCurrent, authorizationCurrent bool
	leaseCurrent, authorizationCurrent, err = heartbeatTimeBoundaries(ctx, tx, request.Lease.ExecutionID)
	if err != nil {
		return execution.ActionHeartbeatResult{}, fmt.Errorf("read action heartbeat time boundaries: %w", err)
	}
	if !authorizationCurrent {
		if err := tx.Commit(ctx); err != nil {
			return execution.ActionHeartbeatResult{}, fmt.Errorf("commit expired-authorization heartbeat: %w", err)
		}
		committed = true
		return execution.ActionHeartbeatResult{Execution: redact(record.claimed.Execution), Directive: execution.HeartbeatTerminate}, nil
	}
	if !leaseCurrent {
		return execution.ActionHeartbeatResult{}, executionlease.ErrStaleLease
	}
	if request.Sequence == record.claimed.Execution.HeartbeatSeq {
		if err := tx.Commit(ctx); err != nil {
			return execution.ActionHeartbeatResult{}, fmt.Errorf("commit replayed action heartbeat: %w", err)
		}
		committed = true
		return heartbeatResult(record.claimed.Execution), nil
	}
	if request.Sequence != record.claimed.Execution.HeartbeatSeq+1 {
		return execution.ActionHeartbeatResult{}, execution.ErrHeartbeatSequence
	}
	updatedRecord, err := scanStoredAction(tx.QueryRow(ctx, `
		UPDATE action_queue
		SET heartbeat_seq = $5,
			last_heartbeat_at = CASE WHEN cancel_requested_at IS NULL THEN statement_timestamp() ELSE last_heartbeat_at END,
			lease_expires_at = CASE WHEN cancel_requested_at IS NULL
				THEN LEAST(statement_timestamp() + make_interval(secs => $6::double precision), authorization_expires_at)
				ELSE lease_expires_at END,
			updated_at = statement_timestamp()
		WHERE action_id = $1 AND runner_id = $2 AND lease_token_sha256 = $3 AND lease_epoch = $4
		  AND status IN ('LEASED', 'RUNNING') AND lease_expires_at > statement_timestamp()
		  AND authorization_expires_at > statement_timestamp()
		  AND heartbeat_seq + 1 = $5
		RETURNING `+actionQueueProjection,
		request.Lease.ExecutionID, request.Lease.RunnerID, digest, request.Lease.Epoch, request.Sequence, request.Extension.Seconds(),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		_, authorizationCurrent, boundaryErr := heartbeatTimeBoundaries(ctx, tx, request.Lease.ExecutionID)
		if boundaryErr != nil {
			return execution.ActionHeartbeatResult{}, fmt.Errorf("recheck action heartbeat time boundaries: %w", boundaryErr)
		}
		if !authorizationCurrent {
			if err := tx.Commit(ctx); err != nil {
				return execution.ActionHeartbeatResult{}, fmt.Errorf("commit expired-authorization heartbeat: %w", err)
			}
			committed = true
			return execution.ActionHeartbeatResult{Execution: redact(record.claimed.Execution), Directive: execution.HeartbeatTerminate}, nil
		}
		return execution.ActionHeartbeatResult{}, executionlease.ErrStaleLease
	}
	if err != nil {
		return execution.ActionHeartbeatResult{}, fmt.Errorf("heartbeat action execution: %w", err)
	}
	record = updatedRecord
	if record.leaseTokenHash != digest {
		return execution.ActionHeartbeatResult{}, executionlease.ErrStaleLease
	}
	if err := tx.Commit(ctx); err != nil {
		return execution.ActionHeartbeatResult{}, fmt.Errorf("commit action heartbeat: %w", err)
	}
	committed = true
	return heartbeatResult(record.claimed.Execution), nil
}

func heartbeatTimeBoundaries(ctx context.Context, tx pgx.Tx, actionID string) (bool, bool, error) {
	var leaseCurrent, authorizationCurrent bool
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(lease_expires_at > statement_timestamp(), false),
			authorization_expires_at > statement_timestamp()
		FROM action_queue
		WHERE action_id = $1
	`, actionID).Scan(&leaseCurrent, &authorizationCurrent)
	return leaseCurrent, authorizationCurrent, err
}

type lockedRunnerRegistration struct {
	tenantID      string
	pool          executionlease.Pool
	enabled       bool
	scopeRevision int64
	found         bool
}

func (registration lockedRunnerRegistration) matches(value executionlease.Execution) bool {
	return registration.found && registration.enabled && registration.tenantID == value.RunnerTenantID &&
		registration.pool == value.Pool && registration.scopeRevision == value.ScopeRevision
}

func lockRunnerRegistration(ctx context.Context, tx pgx.Tx, runnerID string) (lockedRunnerRegistration, error) {
	var registration lockedRunnerRegistration
	var pool string
	err := tx.QueryRow(ctx, `
		SELECT tenant_id::text, runner_pool, enabled, scope_revision
		FROM runner_registrations
		WHERE runner_id = $1
		FOR SHARE
	`, runnerID).Scan(&registration.tenantID, &pool, &registration.enabled, &registration.scopeRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return registration, nil
	}
	if err != nil {
		return lockedRunnerRegistration{}, fmt.Errorf("lock runner registration: %w", err)
	}
	registration.pool = executionlease.Pool(pool)
	registration.found = true
	return registration, nil
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
	registration, err := lockRunnerRegistration(ctx, tx, request.Lease.RunnerID)
	if err != nil {
		return executionlease.Execution{}, err
	}
	record, err := scanStoredAction(tx.QueryRow(ctx, `
		SELECT `+actionQueueProjection+` FROM action_queue WHERE action_id = $1 FOR UPDATE
	`, request.Lease.ExecutionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("lock action completion state: %w", err)
	}
	if record.claimed.Execution.Status == executionlease.StatusRunning && !registration.matches(record.claimed.Execution) {
		return executionlease.Execution{}, executionlease.ErrStaleLease
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
		receiptErr := tx.QueryRow(ctx, `
			SELECT receipt_hash FROM runner_result_receipts WHERE action_id = $1 AND lease_epoch = $2
		`, request.Lease.ExecutionID, request.Lease.Epoch).Scan(&storedReceiptHash)
		if errors.Is(receiptErr, pgx.ErrNoRows) {
			return executionlease.Execution{}, executionlease.ErrCompletionConflict
		}
		if receiptErr != nil {
			return executionlease.Execution{}, fmt.Errorf("read idempotent action completion receipt: %w", receiptErr)
		}
		if storedReceiptHash != receipt.ResultHash {
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
			action_id, tenant_id, workspace_id, environment_id, runner_id, lease_epoch, scope_revision,
			receipt_hash, completion_status, schema_version, summary, received_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'runner-result.v1', $10, statement_timestamp())
	`, receipt.ActionID, receipt.TenantID, receipt.WorkspaceID, receipt.EnvironmentID, receipt.RunnerID,
		receipt.LeaseEpoch, receipt.ScopeRevision, receipt.ResultHash, receipt.CompletionStatus, string(summaryJSON)); err != nil {
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
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("begin action finalization: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	digest := tokenHash(fence.Token)
	tryFinalize := func() (storedAction, error) {
		return scanStoredAction(tx.QueryRow(ctx, `
			UPDATE action_queue AS finalizing
			SET status = finalizing.completion_status, completed_at = statement_timestamp(), updated_at = statement_timestamp()
			WHERE finalizing.action_id = $1 AND finalizing.runner_id = $2
			  AND finalizing.completed_lease_token_sha256 = $3 AND finalizing.completed_lease_epoch = $4
			  AND finalizing.status = 'FINALIZING'
			  AND EXISTS (
				SELECT 1 FROM runner_result_receipts AS receipt
				WHERE receipt.action_id = finalizing.action_id AND receipt.lease_epoch = finalizing.lease_epoch
				  AND receipt.tenant_id = finalizing.runner_tenant_id
				  AND receipt.workspace_id = finalizing.runner_workspace_id
				  AND receipt.environment_id = finalizing.runner_environment_id
				  AND receipt.runner_id = finalizing.runner_id
				  AND receipt.scope_revision = finalizing.scope_revision
				  AND receipt.receipt_hash = finalizing.result_hash
				  AND receipt.completion_status = finalizing.completion_status
				  AND receipt.schema_version = 'runner-result.v1'
			  )
			  AND (
				finalizing.completion_status = 'UNCERTAIN' OR
				`+credentialCleanupPredicate("finalizing", "completed_lease_token_sha256", credentialCleanupStrict)+`
			  )
			RETURNING `+actionQueueProjection,
			fence.ExecutionID, fence.RunnerID, digest, fence.Epoch,
		))
	}
	record, err := tryFinalize()
	if errors.Is(err, pgx.ErrNoRows) {
		record, err = scanStoredAction(tx.QueryRow(ctx, `
			SELECT `+actionQueueProjection+`
			FROM action_queue
			WHERE action_id = $1
			FOR UPDATE
		`, fence.ExecutionID))
		if errors.Is(err, pgx.ErrNoRows) {
			return executionlease.Execution{}, executionlease.ErrNotFound
		}
		if err != nil {
			return executionlease.Execution{}, fmt.Errorf("read action finalization state: %w", err)
		}
		if record.claimed.Execution.ReconciliationID != "" || record.claimed.Execution.RunnerID != fence.RunnerID ||
			record.completedLeaseTokenHash != digest || record.completedLeaseEpoch != fence.Epoch {
			return executionlease.Execution{}, executionlease.ErrStaleLease
		}
		if record.claimed.Execution.Terminal() {
			if err := tx.Commit(ctx); err != nil {
				return executionlease.Execution{}, fmt.Errorf("commit idempotent action finalization: %w", err)
			}
			committed = true
			return redact(record.claimed.Execution), nil
		}
		if record.claimed.Execution.Status == executionlease.StatusFinalizing &&
			(record.claimed.Execution.CompletionStatus == executionlease.StatusSucceeded ||
				record.claimed.Execution.CompletionStatus == executionlease.StatusFailed) {
			cleanupAllowed, inspectErr := inspectCredentialCleanup(
				ctx, tx, fence.ExecutionID, fence.Epoch, credentialCleanupStrict,
			)
			if inspectErr != nil {
				return executionlease.Execution{}, inspectErr
			}
			if !cleanupAllowed {
				return executionlease.Execution{}, execution.ErrCredentialCleanupPending
			}
			record, err = tryFinalize()
			if err == nil {
				if err := tx.Commit(ctx); err != nil {
					return executionlease.Execution{}, fmt.Errorf("commit action finalization after credential cleanup: %w", err)
				}
				committed = true
				return redact(record.claimed.Execution), nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return executionlease.Execution{}, fmt.Errorf("finalize action after credential cleanup: %w", err)
			}
		}
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("finalize action result receipt: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return executionlease.Execution{}, fmt.Errorf("commit action finalization: %w", err)
	}
	committed = true
	return redact(record.claimed.Execution), nil
}

func credentialCleanupPredicate(alias, tokenColumn string, mode credentialCleanupMode) string {
	terminal := `(
		` + alias + `.credential_expected = true
		AND ` + alias + `.credential_lease_epoch = ` + alias + `.lease_epoch
		AND EXISTS (
			SELECT 1
			FROM credential_revocations AS cleanup
			WHERE cleanup.action_id = ` + alias + `.action_id
			  AND cleanup.tenant_id = ` + alias + `.runner_tenant_id
			  AND cleanup.workspace_id = ` + alias + `.runner_workspace_id
			  AND cleanup.environment_id = ` + alias + `.runner_environment_id
			  AND cleanup.target_key = ` + alias + `.target_key
			  AND cleanup.production = ` + alias + `.production
			  AND cleanup.runner_id = ` + alias + `.runner_id
			  AND cleanup.action_lease_epoch = ` + alias + `.lease_epoch
			  AND cleanup.action_lease_token_sha256 = ` + alias + `.` + tokenColumn + `
			  AND cleanup.status IN ('REVOKED', 'NO_CREDENTIAL')
		)
	)`
	if mode == credentialCleanupStrict {
		return `(` + alias + `.runner_pool <> 'WRITE' OR ` + terminal + `)`
	}
	return `(
		` + alias + `.runner_pool <> 'WRITE' OR
		(
			(
				` + alias + `.credential_expected = false
				AND ` + alias + `.credential_lease_epoch IS NULL
				AND NOT EXISTS (
					SELECT 1
					FROM credential_revocations AS existing_cleanup
					WHERE existing_cleanup.action_id = ` + alias + `.action_id
					  AND existing_cleanup.action_lease_epoch = ` + alias + `.lease_epoch
				)
			) OR ` + terminal + `
		)
	)`
}

func inspectCredentialCleanup(
	ctx context.Context,
	database queryRower,
	actionID string,
	leaseEpoch int64,
	mode credentialCleanupMode,
) (bool, error) {
	tokenColumn := "completed_lease_token_sha256"
	if mode == credentialCleanupAllowAbsent {
		tokenColumn = "lease_token_sha256"
	}
	var cleanupAllowed bool
	err := database.QueryRow(ctx, `
		SELECT `+credentialCleanupPredicate("action", tokenColumn, mode)+` AS cleanup_allowed
		FROM action_queue AS action
		WHERE action.action_id = $1 AND action.lease_epoch = $2
	`, actionID, leaseEpoch).Scan(&cleanupAllowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, executionlease.ErrStaleLease
	}
	if err != nil {
		return false, fmt.Errorf("inspect action credential cleanup: %w", err)
	}
	return cleanupAllowed, nil
}

func inspectCurrentLeaseCleanup(
	ctx context.Context,
	database queryRower,
	actionID string,
	leaseEpoch int64,
) (bool, bool, error) {
	var leaseCurrent, cleanupAllowed bool
	err := database.QueryRow(ctx, `
		SELECT COALESCE(action.lease_expires_at > statement_timestamp(), false) AS lease_current,
			`+credentialCleanupPredicate("action", "lease_token_sha256", credentialCleanupAllowAbsent)+` AS cleanup_allowed
		FROM action_queue AS action
		WHERE action.action_id = $1 AND action.lease_epoch = $2
	`, actionID, leaseEpoch).Scan(&leaseCurrent, &cleanupAllowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, executionlease.ErrStaleLease
	}
	if err != nil {
		return false, false, fmt.Errorf("inspect current action lease cleanup: %w", err)
	}
	return leaseCurrent, cleanupAllowed, nil
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
		UPDATE action_queue AS leased
		SET status = 'FAILED', completion_status = 'FAILED', completed_lease_token_sha256 = lease_token_sha256,
			completed_lease_epoch = lease_epoch, lease_token_sha256 = NULL,
			lease_expires_at = NULL, result_hash = $5,
			completed_at = statement_timestamp(), updated_at = statement_timestamp()
		WHERE leased.action_id = $1 AND leased.runner_id = $2
		  AND leased.lease_token_sha256 = $3 AND leased.lease_epoch = $4
		  AND leased.status = 'LEASED' AND leased.lease_expires_at > statement_timestamp()
		  AND `+credentialCleanupPredicate("leased", "lease_token_sha256", credentialCleanupAllowAbsent)+`
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
	leaseCurrent, cleanupAllowed, inspectErr := inspectCurrentLeaseCleanup(
		ctx, tx, request.Lease.ExecutionID, request.Lease.Epoch,
	)
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
		UPDATE action_queue AS leased
		SET status = 'QUEUED', last_nack_hash = $5,
			not_before = statement_timestamp() + make_interval(secs => $6::double precision),
			runner_id = NULL, runner_tenant_id = NULL, runner_workspace_id = NULL, runner_environment_id = NULL,
			lease_token_sha256 = NULL, lease_acquired_at = NULL,
			lease_expires_at = NULL, last_heartbeat_at = NULL, scope_revision = NULL,
			heartbeat_seq = 0, cancel_requested_at = NULL, cancel_reason_hash = NULL,
			credential_expected = false, credential_lease_epoch = NULL,
			updated_at = statement_timestamp()
		WHERE leased.action_id = $1 AND leased.runner_id = $2
		  AND leased.lease_token_sha256 = $3 AND leased.lease_epoch = $4
		  AND leased.status = 'LEASED' AND leased.lease_expires_at > statement_timestamp()
		  AND `+credentialCleanupPredicate("leased", "lease_token_sha256", credentialCleanupAllowAbsent)+`
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
		UPDATE action_queue AS uncertain
		SET reconciliation_id = $2, reconciliation_actor = $3, status = $4,
			reconciliation_result_hash = $5, reconciled_at = statement_timestamp(),
			updated_at = statement_timestamp()
		WHERE uncertain.action_id = $1 AND uncertain.status = 'UNCERTAIN' AND uncertain.reconciliation_id IS NULL
		  AND `+credentialCleanupPredicate("uncertain", "completed_lease_token_sha256", credentialCleanupStrict)+`
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
		if record.claimed.Execution.Status == executionlease.StatusUncertain {
			cleanupAllowed, inspectErr := inspectCredentialCleanup(
				ctx, tx, request.ExecutionID, record.claimed.Execution.LeaseEpoch, credentialCleanupStrict,
			)
			if inspectErr != nil {
				return executionlease.Execution{}, inspectErr
			}
			if !cleanupAllowed {
				return executionlease.Execution{}, execution.ErrCredentialCleanupPending
			}
		}
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
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("begin action cancellation: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	tryCancel := func() (storedAction, error) {
		return scanStoredAction(tx.QueryRow(ctx, `
			UPDATE action_queue AS cancellable
			SET status = CASE WHEN status = 'RUNNING' THEN status ELSE 'CANCELLED' END,
				cancel_requested_at = CASE WHEN status = 'RUNNING' THEN COALESCE(cancel_requested_at, statement_timestamp()) ELSE NULL END,
				cancel_reason_hash = CASE WHEN status = 'RUNNING' THEN COALESCE(cancel_reason_hash, $2) ELSE NULL END,
				runner_id = CASE WHEN status = 'RUNNING' THEN runner_id ELSE NULL END,
				runner_tenant_id = CASE WHEN status = 'RUNNING' THEN runner_tenant_id ELSE NULL END,
				runner_workspace_id = CASE WHEN status = 'RUNNING' THEN runner_workspace_id ELSE NULL END,
				runner_environment_id = CASE WHEN status = 'RUNNING' THEN runner_environment_id ELSE NULL END,
				scope_revision = CASE WHEN status = 'RUNNING' THEN scope_revision ELSE NULL END,
				lease_token_sha256 = CASE WHEN status = 'RUNNING' THEN lease_token_sha256 ELSE NULL END,
				lease_expires_at = CASE WHEN status = 'RUNNING' THEN lease_expires_at ELSE NULL END,
				completed_at = CASE WHEN status = 'RUNNING' THEN completed_at ELSE statement_timestamp() END,
				updated_at = CASE WHEN status = 'RUNNING' AND cancel_requested_at IS NOT NULL THEN updated_at ELSE statement_timestamp() END
			WHERE cancellable.action_id = $1 AND cancellable.status IN ('QUEUED', 'LEASED', 'RUNNING')
			  AND (
				cancellable.status <> 'LEASED' OR
				`+credentialCleanupPredicate("cancellable", "lease_token_sha256", credentialCleanupAllowAbsent)+`
			  )
			RETURNING `+actionQueueProjection,
			actionID, cancellationResultHash(),
		))
	}
	record, err := tryCancel()
	if errors.Is(err, pgx.ErrNoRows) {
		existing, getErr := scanStoredAction(tx.QueryRow(ctx, `
			SELECT `+actionQueueProjection+`
			FROM action_queue
			WHERE action_id = $1
			FOR UPDATE
		`, actionID))
		if errors.Is(getErr, pgx.ErrNoRows) {
			return executionlease.Execution{}, executionlease.ErrNotFound
		}
		if getErr != nil {
			return executionlease.Execution{}, fmt.Errorf("read action cancellation state: %w", getErr)
		}
		if existing.claimed.Execution.Terminal() {
			if err := tx.Commit(ctx); err != nil {
				return executionlease.Execution{}, fmt.Errorf("commit idempotent action cancellation: %w", err)
			}
			committed = true
			return redact(existing.claimed.Execution), nil
		}
		if existing.claimed.Execution.Status == executionlease.StatusLeased {
			cleanupAllowed, inspectErr := inspectCredentialCleanup(
				ctx, tx, actionID, existing.claimed.Execution.LeaseEpoch, credentialCleanupAllowAbsent,
			)
			if inspectErr != nil {
				return executionlease.Execution{}, inspectErr
			}
			if !cleanupAllowed {
				return executionlease.Execution{}, execution.ErrCredentialCleanupPending
			}
			record, err = tryCancel()
			if err == nil {
				if err := tx.Commit(ctx); err != nil {
					return executionlease.Execution{}, fmt.Errorf("commit action cancellation after credential cleanup: %w", err)
				}
				committed = true
				return redact(record.claimed.Execution), nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return executionlease.Execution{}, fmt.Errorf("cancel action after credential cleanup: %w", err)
			}
		}
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("cancel action execution: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return executionlease.Execution{}, fmt.Errorf("commit action cancellation: %w", err)
	}
	committed = true
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
	if !validIdentifier(request.Scope.RunnerID(), 256) || !validIdentifier(request.Scope.TenantID(), 256) ||
		!validPool(request.Scope.Pool()) || request.Scope.ScopeRevision() <= 0 ||
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
	var leaseCurrent, cleanupAllowed bool
	err := repository.database.QueryRow(ctx, `
		SELECT runner_id, lease_epoch, lease_token_sha256, status,
			COALESCE(lease_expires_at > statement_timestamp(), false) AS lease_current,
			`+credentialCleanupPredicate("action", "lease_token_sha256", credentialCleanupAllowAbsent)+` AS cleanup_allowed
		FROM action_queue AS action
		WHERE action.action_id = $1
	`, fence.ExecutionID).Scan(&runnerID, &epoch, &storedTokenHash, &status, &leaseCurrent, &cleanupAllowed)
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
			if !cleanupAllowed {
				return executionlease.Execution{}, execution.ErrCredentialCleanupPending
			}
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
	limit := "100"
	if actionID != "" {
		predicate = " AND finalizing.action_id = $1"
		args = append(args, actionID)
		limit = "1"
	}
	if _, err := tx.Exec(ctx, `
		WITH recoverable_finalizing AS (
			SELECT finalizing.action_id
			FROM action_queue AS finalizing
			WHERE finalizing.status = 'FINALIZING'
			  AND EXISTS (
				SELECT 1
				FROM runner_result_receipts AS receipt
				WHERE receipt.action_id = finalizing.action_id
				  AND receipt.tenant_id = finalizing.runner_tenant_id
				  AND receipt.workspace_id = finalizing.runner_workspace_id
				  AND receipt.environment_id = finalizing.runner_environment_id
				  AND receipt.runner_id = finalizing.runner_id
				  AND receipt.lease_epoch = finalizing.lease_epoch
				  AND receipt.scope_revision = finalizing.scope_revision
				  AND receipt.receipt_hash = finalizing.result_hash
				  AND receipt.completion_status = finalizing.completion_status
				  AND receipt.schema_version = 'runner-result.v1'
			  )
			  AND (
				finalizing.completion_status = 'UNCERTAIN' OR
				`+credentialCleanupPredicate("finalizing", "completed_lease_token_sha256", credentialCleanupStrict)+`
			  )
			`+predicate+`
			ORDER BY finalizing.updated_at, finalizing.action_id
			FOR UPDATE OF finalizing SKIP LOCKED
			LIMIT `+limit+`
		)
		UPDATE action_queue AS finalizing
		SET status = finalizing.completion_status,
			completed_at = statement_timestamp(), updated_at = statement_timestamp()
		FROM recoverable_finalizing
		WHERE finalizing.action_id = recoverable_finalizing.action_id
	`, args...); err != nil {
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
		SET status = 'QUEUED', runner_id = NULL,
			runner_tenant_id = NULL, runner_workspace_id = NULL, runner_environment_id = NULL,
			lease_token_sha256 = NULL,
			lease_acquired_at = NULL, lease_expires_at = NULL, last_heartbeat_at = NULL,
			scope_revision = NULL, heartbeat_seq = 0, cancel_requested_at = NULL, cancel_reason_hash = NULL,
			credential_expected = false, credential_lease_epoch = NULL,
			not_before = statement_timestamp(), updated_at = statement_timestamp()
		WHERE expired_lease.status = 'LEASED'
		  AND expired_lease.lease_expires_at <= statement_timestamp()
		  AND `+credentialCleanupPredicate("expired_lease", "lease_token_sha256", credentialCleanupAllowAbsent)+`
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

func storedRequestSemanticHash(record storedAction) (string, error) {
	switch record.requestHashVersion {
	case requestHashVersion:
		return record.requestHash, nil
	case "legacy-submission.v1":
		requestHash, err := execution.RequestSemanticHash(execution.ActionSubmission{
			Envelope: record.claimed.Envelope, PlanHash: record.claimed.PlanHash,
			TargetKey: record.claimed.TargetKey, EnvironmentRevision: record.claimed.EnvironmentRevision,
			Production: record.claimed.Production, Pool: record.claimed.Execution.Pool,
		})
		if err != nil {
			return "", fmt.Errorf("rebuild legacy action request semantics: %w", err)
		}
		return requestHash, nil
	default:
		return "", execution.ErrJobConflict
	}
}

func scanStoredAction(row pgx.Row) (storedAction, error) {
	var record storedAction
	var pool, status string
	var runnerID, runnerTenantID, runnerWorkspaceID, runnerEnvironmentID, resultHash pgtype.Text
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
		&record.claimed.Execution.Production, &status, &runnerID,
		&runnerTenantID, &runnerWorkspaceID, &runnerEnvironmentID, &record.claimed.Execution.LeaseEpoch,
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
	record.claimed.Execution.RunnerTenantID = textValue(runnerTenantID)
	record.claimed.Execution.RunnerWorkspaceID = textValue(runnerWorkspaceID)
	record.claimed.Execution.RunnerEnvironmentID = textValue(runnerEnvironmentID)
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
	runnerIdentityPresent := record.claimed.Execution.RunnerTenantID != "" ||
		record.claimed.Execution.RunnerWorkspaceID != "" || record.claimed.Execution.RunnerEnvironmentID != ""
	if runnerIdentityPresent && (record.claimed.Execution.RunnerID == "" || record.claimed.Execution.RunnerTenantID == "" ||
		record.claimed.Execution.RunnerWorkspaceID == "" || record.claimed.Execution.RunnerEnvironmentID == "" ||
		record.claimed.Execution.RunnerWorkspaceID != record.claimed.Envelope.WorkspaceID ||
		record.claimed.Execution.RunnerEnvironmentID != record.claimed.Envelope.Target.EnvironmentID) {
		return storedAction{}, execution.ErrJobConflict
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
