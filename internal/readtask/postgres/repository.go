// Package postgres persists authenticated READ Runner task attempts. Every
// mutation is transaction-scoped so the Gateway can re-authenticate the mTLS
// identity and apply the attempt fence in one PostgreSQL transaction.
package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executionlease"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

const (
	minimumLeaseDuration = time.Second
	maximumLeaseDuration = 5 * time.Minute
	releaseRetryDelay    = 5 * time.Second
)

var (
	uuidPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
	hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// DB is the minimum pool contract required by the standalone repository and
// by the Runner Gateway's caller-owned transaction boundary.
type DB interface {
	Begin(context.Context) (pgx.Tx, error)
}

type Options struct {
	// TokenSource transfers ownership of exactly 32 cryptographically random
	// bytes. The repository clears them after encoding and persists only the
	// SHA-256 digest of their canonical unpadded base64url representation.
	TokenSource func() ([]byte, error)
	// IDSource returns persistent UUIDs for Evidence and immutable receipts.
	IDSource func() string
}

type Repository struct {
	database    DB
	tokenSource func() ([]byte, error)
	idSource    func() string
}

func New(database DB, options Options) (*Repository, error) {
	if nilInterface(database) || options.TokenSource == nil || options.IDSource == nil {
		return nil, fmt.Errorf("%w: trusted PostgreSQL READ task dependencies are required", readtask.ErrInvalidRequest)
	}
	return &Repository{database: database, tokenSource: options.TokenSource, idSource: options.IDSource}, nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface ||
		kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}

type storedTask struct {
	descriptor          readtask.Descriptor
	taskStatus          string
	investigationStatus string
}

// ClaimRunnerTx creates one append-only attempt for an explicit task ID. The
// caller owns tx and must have authenticated scope and certificate in that
// same transaction before invoking this method.
func (repository *Repository) ClaimRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	certificate readtask.CertificateBinding,
	taskID string,
	leaseDuration time.Duration,
) (readtask.Claim, error) {
	if err := validateRunnerRequest(ctx, tx, scope, certificate); err != nil {
		return readtask.Claim{}, err
	}
	if !uuidPattern.MatchString(taskID) || leaseDuration < minimumLeaseDuration || leaseDuration > maximumLeaseDuration {
		return readtask.Claim{}, readtask.ErrInvalidRequest
	}
	capacityLockKey := "read-task-runner:" + scope.TenantID() + ":" + scope.RunnerID()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, capacityLockKey); err != nil {
		return readtask.Claim{}, persistenceError("serialize READ Runner capacity", err)
	}

	task, err := lockTask(ctx, tx, scope.TenantID(), taskID)
	if errors.Is(err, pgx.ErrNoRows) {
		return readtask.Claim{}, readtask.ErrNotFound
	}
	if err != nil {
		return readtask.Claim{}, persistenceError("lock READ task", err)
	}
	databaseNow, err := databaseClock(ctx, tx)
	if err != nil {
		return readtask.Claim{}, err
	}
	if task.descriptor.Validate() != nil {
		return readtask.Claim{}, integrityError("validate READ task projection", errors.New("invalid persisted task"))
	}
	if !runnerScopeAllows(scope, task.descriptor.WorkspaceID, task.descriptor.EnvironmentID) {
		return readtask.Claim{}, readtask.ErrNotFound
	}
	if (task.taskStatus != "QUEUED" && task.taskStatus != "RUNNING") ||
		(task.investigationStatus != "QUEUED" && task.investigationStatus != "RUNNING") {
		return readtask.Claim{}, readtask.ErrNoClaimAvailable
	}
	if !databaseNow.Before(certificate.NotAfter) {
		return readtask.Claim{}, readtask.ErrNoClaimAvailable
	}

	if _, err := tx.Exec(ctx, `
		UPDATE investigation_task_attempts
		SET status = 'EXPIRED'
		WHERE tenant_id = $1 AND workspace_id = $2 AND investigation_id = $3 AND task_id = $4
		  AND status IN ('LEASED', 'RUNNING') AND lease_expires_at <= $5
	`, scope.TenantID(), task.descriptor.WorkspaceID, task.descriptor.InvestigationID, taskID, databaseNow); err != nil {
		return readtask.Claim{}, persistenceError("expire stale READ task attempt", err)
	}

	var taskActive bool
	var runnerActive, maxEpoch int64
	var lastTerminalAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT
			EXISTS (
				SELECT 1 FROM investigation_task_attempts AS task_active
				WHERE task_active.tenant_id = $1 AND task_active.workspace_id = $2
				  AND task_active.investigation_id = $3 AND task_active.task_id = $4
				  AND task_active.status IN ('LEASED', 'RUNNING')
			),
			(
				SELECT count(*) FROM investigation_task_attempts AS runner_active
				WHERE runner_active.tenant_id = $1 AND runner_active.runner_id = $5
				  AND runner_active.status IN ('LEASED', 'RUNNING') AND runner_active.lease_expires_at > $6
			),
			COALESCE((
				SELECT max(history.lease_epoch) FROM investigation_task_attempts AS history
				WHERE history.tenant_id = $1 AND history.workspace_id = $2
				  AND history.investigation_id = $3 AND history.task_id = $4
			), 0),
			(
				SELECT max(history.terminal_at) FROM investigation_task_attempts AS history
				WHERE history.tenant_id = $1 AND history.workspace_id = $2
				  AND history.investigation_id = $3 AND history.task_id = $4
			)
	`, scope.TenantID(), task.descriptor.WorkspaceID, task.descriptor.InvestigationID,
		taskID, scope.RunnerID(), databaseNow).Scan(&taskActive, &runnerActive, &maxEpoch, &lastTerminalAt)
	if err != nil {
		return readtask.Claim{}, persistenceError("inspect READ task attempt capacity", err)
	}
	if taskActive || runnerActive >= int64(scope.MaxConcurrency()) ||
		lastTerminalAt != nil && databaseNow.Before(lastTerminalAt.Add(releaseRetryDelay)) {
		return readtask.Claim{}, readtask.ErrNoClaimAvailable
	}
	if maxEpoch == math.MaxInt64 {
		return readtask.Claim{}, readtask.ErrInvalidTransition
	}

	rawToken, err := repository.tokenSource()
	if rawToken != nil {
		defer clear(rawToken)
	}
	if err != nil {
		return readtask.Claim{}, persistenceError("generate READ task lease token", errors.New("invalid token source"))
	}
	tokenBytes, err := encodeLeaseToken(rawToken)
	if err != nil {
		return readtask.Claim{}, integrityError("generate READ task lease token", err)
	}
	defer clear(tokenBytes)
	digest := sha256.Sum256(tokenBytes)
	tokenHash := hex.EncodeToString(digest[:])
	leaseNow, err := databaseClock(ctx, tx)
	if err != nil {
		return readtask.Claim{}, err
	}
	if !leaseNow.Before(certificate.NotAfter) {
		return readtask.Claim{}, readtask.ErrNoClaimAvailable
	}
	expiresAt := leaseNow.Add(leaseDuration)
	if certificate.NotAfter.Before(expiresAt) {
		expiresAt = certificate.NotAfter
	}
	if !expiresAt.After(leaseNow) {
		return readtask.Claim{}, readtask.ErrNoClaimAvailable
	}

	attempt := readtask.Attempt{
		TaskID: taskID, RunnerID: scope.RunnerID(), ScopeRevision: scope.ScopeRevision(),
		Certificate: certificate, TokenSHA256: tokenHash, Epoch: maxEpoch + 1, Status: readtask.AttemptLeased,
	}
	var updatedAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO investigation_task_attempts (
			tenant_id, workspace_id, environment_id, investigation_id, task_id,
			lease_epoch, lease_token_sha256, runner_id, scope_revision,
			certificate_sha256, certificate_not_after, heartbeat_seq,
			lease_acquired_at, last_heartbeat_at, lease_expires_at, status, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 0,
			$12, $12, $12, 'LEASED', $12
		)
		RETURNING lease_acquired_at, last_heartbeat_at, lease_expires_at, certificate_not_after, updated_at
	`, scope.TenantID(), task.descriptor.WorkspaceID, task.descriptor.EnvironmentID,
		task.descriptor.InvestigationID, taskID, attempt.Epoch, tokenHash, scope.RunnerID(),
		scope.ScopeRevision(), certificate.SHA256, certificate.NotAfter, expiresAt).Scan(
		&attempt.LeaseAcquiredAt, &attempt.LastHeartbeatAt, &attempt.LeaseExpiresAt, &attempt.Certificate.NotAfter, &updatedAt,
	)
	if staleLeaseTransition(err) {
		return readtask.Claim{}, readtask.ErrNoClaimAvailable
	}
	if err != nil {
		return readtask.Claim{}, persistenceError("persist READ task attempt", err)
	}
	attempt.UpdatedAt = updatedAt
	if !validFiniteTime(updatedAt) || attempt.ValidateAgainst(task.descriptor) != nil {
		return readtask.Claim{}, integrityError("validate persisted READ task attempt", errors.New("invalid persisted attempt"))
	}
	if !attemptIdentityCurrent(scope, certificate, task.descriptor, attempt) {
		return readtask.Claim{}, integrityError("bind persisted READ task identity", errors.New("identity snapshot mismatch"))
	}
	claim, err := readtask.NewClaim(task.descriptor, attempt, tokenBytes)
	if err != nil {
		return readtask.Claim{}, integrityError("bind READ task claim", err)
	}
	return claim, nil
}

func encodeLeaseToken(raw []byte) ([]byte, error) {
	if len(raw) != 32 {
		return nil, errors.New("READ task token source must return exactly 32 bytes")
	}
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	base64.RawURLEncoding.Encode(encoded, raw)
	return encoded, nil
}

// StartAuthorizer validates the trusted connector/operation/input and current
// environment-local read configuration while Task, Attempt, and Investigation
// remain locked. It must be side-effect-free.
type StartAuthorizer func(context.Context, readtask.Descriptor) error

// StartRunnerAuthorizedTx is the mandatory Gateway start path. The final
// authorizer is rerun for an idempotent RUNNING replay so a disabled connector
// or narrowed local configuration cannot be bypassed with a lost response.
func (repository *Repository) StartRunnerAuthorizedTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	certificate readtask.CertificateBinding,
	start readtask.Start,
	authorizer StartAuthorizer,
) (readtask.Attempt, error) {
	if authorizer == nil {
		return readtask.Attempt{}, readtask.ErrInvalidRequest
	}
	return repository.startRunnerTx(ctx, tx, scope, certificate, start, authorizer)
}

func (repository *Repository) startRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	certificate readtask.CertificateBinding,
	start readtask.Start,
	authorizer StartAuthorizer,
) (readtask.Attempt, error) {
	if err := validateRunnerRequest(ctx, tx, scope, certificate); err != nil {
		return readtask.Attempt{}, err
	}
	if !start.Fence.Valid() {
		return readtask.Attempt{}, readtask.ErrInvalidRequest
	}
	task, err := lockTask(ctx, tx, scope.TenantID(), start.Fence.TaskID())
	if errors.Is(err, pgx.ErrNoRows) {
		return readtask.Attempt{}, readtask.ErrNotFound
	}
	if err != nil {
		return readtask.Attempt{}, persistenceError("lock READ task for start", err)
	}
	attempt, err := lockAttempt(ctx, tx, task.descriptor, start.Fence.Epoch())
	if errors.Is(err, pgx.ErrNoRows) {
		return readtask.Attempt{}, readtask.ErrStaleFence
	}
	if err != nil {
		return readtask.Attempt{}, persistenceError("lock READ task attempt for start", err)
	}
	if err := validateLockedTaskAttemptProjection("validate locked READ task start", task.descriptor, attempt); err != nil {
		return readtask.Attempt{}, err
	}
	if !attemptIdentityCurrent(scope, certificate, task.descriptor, attempt) ||
		!fenceMatchesAttempt(start.Fence, attempt) {
		return readtask.Attempt{}, readtask.ErrStaleFence
	}
	var parentStatus string
	err = tx.QueryRow(ctx, `
		SELECT status
		FROM investigations
		WHERE tenant_id = $1 AND workspace_id = $2 AND id = $3
		  AND runtime_schema_version = 'investigation-runtime.v1'
		FOR NO KEY UPDATE
	`, scope.TenantID(), task.descriptor.WorkspaceID, task.descriptor.InvestigationID).Scan(&parentStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return readtask.Attempt{}, readtask.ErrNotFound
	}
	if err != nil {
		return readtask.Attempt{}, persistenceError("lock READ task parent for start", err)
	}
	databaseNow, err := databaseClock(ctx, tx)
	if err != nil {
		return readtask.Attempt{}, err
	}
	if !databaseNow.Before(attempt.LeaseExpiresAt) {
		return readtask.Attempt{}, readtask.ErrStaleFence
	}
	if (task.taskStatus != "QUEUED" && task.taskStatus != "RUNNING") ||
		(parentStatus != "QUEUED" && parentStatus != "RUNNING") {
		return readtask.Attempt{}, readtask.ErrInvalidTransition
	}
	descriptor := task.descriptor
	descriptor.Input = bytes.Clone(task.descriptor.Input)
	if err := authorizer(ctx, descriptor); err != nil {
		return readtask.Attempt{}, err
	}
	if attempt.Status == readtask.AttemptRunning {
		postAuthorizationNow, clockErr := databaseClock(ctx, tx)
		if clockErr != nil {
			return readtask.Attempt{}, clockErr
		}
		if !postAuthorizationNow.Before(attempt.LeaseExpiresAt) {
			return readtask.Attempt{}, readtask.ErrStaleFence
		}
		return attempt, nil
	}
	if start.ValidateAgainst(task.descriptor, attempt) != nil || attempt.Status != readtask.AttemptLeased {
		return readtask.Attempt{}, readtask.ErrInvalidTransition
	}

	attempt, err = scanAttempt(tx.QueryRow(ctx, `
		UPDATE investigation_task_attempts
		SET status = 'RUNNING'
		WHERE tenant_id = $1 AND workspace_id = $2 AND investigation_id = $3 AND task_id = $4
		  AND lease_epoch = $5 AND status = 'LEASED' AND lease_expires_at > clock_timestamp()
		RETURNING `+attemptProjection,
		scope.TenantID(), task.descriptor.WorkspaceID, task.descriptor.InvestigationID,
		task.descriptor.TaskID, start.Fence.Epoch()))
	if errors.Is(err, pgx.ErrNoRows) {
		return readtask.Attempt{}, readtask.ErrStaleFence
	}
	if staleLeaseTransition(err) {
		return readtask.Attempt{}, readtask.ErrStaleFence
	}
	if err != nil {
		return readtask.Attempt{}, persistenceError("start READ task attempt", err)
	}
	if err := validateLockedTaskAttemptProjection("validate started READ task attempt", task.descriptor, attempt); err != nil {
		return readtask.Attempt{}, err
	}
	if !attemptIdentityCurrent(scope, certificate, task.descriptor, attempt) || attempt.Status != readtask.AttemptRunning {
		return readtask.Attempt{}, integrityError("validate started READ task attempt", errors.New("invalid attempt projection"))
	}
	if task.taskStatus == "QUEUED" {
		updated, updateErr := tx.Exec(ctx, `
			UPDATE tool_invocations
			SET status = 'RUNNING', started_at = COALESCE(started_at, clock_timestamp()),
				updated_at = GREATEST(updated_at, clock_timestamp())
			WHERE tenant_id = $1 AND workspace_id = $2 AND investigation_id = $3 AND id = $4
			  AND runtime_schema_version = 'investigation-runtime.v1' AND status = 'QUEUED'
		`, scope.TenantID(), task.descriptor.WorkspaceID, task.descriptor.InvestigationID, task.descriptor.TaskID)
		if updateErr != nil {
			return readtask.Attempt{}, persistenceError("start READ task", updateErr)
		}
		if updated.RowsAffected() != 1 {
			return readtask.Attempt{}, readtask.ErrInvalidTransition
		}
	}
	if parentStatus == "QUEUED" {
		updated, updateErr := tx.Exec(ctx, `
			UPDATE investigations
			SET status = 'RUNNING', started_at = COALESCE(started_at, clock_timestamp()),
				updated_at = GREATEST(updated_at, clock_timestamp())
			WHERE tenant_id = $1 AND workspace_id = $2 AND id = $3
			  AND runtime_schema_version = 'investigation-runtime.v1' AND status = 'QUEUED'
		`, scope.TenantID(), task.descriptor.WorkspaceID, task.descriptor.InvestigationID)
		if updateErr != nil {
			return readtask.Attempt{}, persistenceError("start READ task parent", updateErr)
		}
		if updated.RowsAffected() != 1 {
			return readtask.Attempt{}, readtask.ErrInvalidTransition
		}
	}
	return attempt, nil
}

// HeartbeatRunnerTx accepts exactly one next sequence and lets PostgreSQL pick
// the effective lease time. Replays of the last accepted sequence never
// extend the lease.
func (repository *Repository) HeartbeatRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	certificate readtask.CertificateBinding,
	heartbeat readtask.Heartbeat,
	extension time.Duration,
) (readtask.HeartbeatResult, error) {
	if err := validateRunnerRequest(ctx, tx, scope, certificate); err != nil {
		return readtask.HeartbeatResult{}, err
	}
	if !heartbeat.Fence.Valid() || extension < minimumLeaseDuration || extension > maximumLeaseDuration || heartbeat.Sequence <= 0 {
		return readtask.HeartbeatResult{}, readtask.ErrInvalidRequest
	}
	task, err := lockTask(ctx, tx, scope.TenantID(), heartbeat.Fence.TaskID())
	if errors.Is(err, pgx.ErrNoRows) {
		return readtask.HeartbeatResult{}, readtask.ErrNotFound
	}
	if err != nil {
		return readtask.HeartbeatResult{}, persistenceError("lock READ task for heartbeat", err)
	}
	attempt, err := lockAttempt(ctx, tx, task.descriptor, heartbeat.Fence.Epoch())
	if errors.Is(err, pgx.ErrNoRows) {
		return readtask.HeartbeatResult{}, readtask.ErrStaleFence
	}
	if err != nil {
		return readtask.HeartbeatResult{}, persistenceError("lock READ task attempt for heartbeat", err)
	}
	if err := validateLockedTaskAttemptProjection("validate locked READ task heartbeat", task.descriptor, attempt); err != nil {
		return readtask.HeartbeatResult{}, err
	}
	if !fenceMatchesAttempt(heartbeat.Fence, attempt) {
		return readtask.HeartbeatResult{}, readtask.ErrStaleFence
	}
	parentStatus, err := lockParentStatus(ctx, tx, task.descriptor)
	if err != nil {
		return readtask.HeartbeatResult{}, err
	}
	databaseNow, err := databaseClock(ctx, tx)
	if err != nil {
		return readtask.HeartbeatResult{}, err
	}

	identityCurrent := attemptIdentityCurrent(scope, certificate, task.descriptor, attempt)
	leaseCurrent := databaseNow.Before(attempt.LeaseExpiresAt)
	shouldTerminate := !identityCurrent || task.taskStatus != "RUNNING" || parentStatus != "RUNNING"
	if heartbeat.Sequence == attempt.HeartbeatSequence {
		if !leaseCurrent && attempt.Status == readtask.AttemptRunning {
			return readtask.HeartbeatResult{}, readtask.ErrStaleFence
		}
		if attempt.Status == readtask.AttemptCancelled {
			return heartbeatResult(task.descriptor, attempt, readtask.HeartbeatTerminate)
		}
		if attempt.Status == readtask.AttemptRunning && !shouldTerminate {
			return heartbeatResult(task.descriptor, attempt, readtask.HeartbeatContinue)
		}
		if attempt.Status == readtask.AttemptRunning && shouldTerminate {
			attempt, err = scanAttempt(tx.QueryRow(ctx, `
				UPDATE investigation_task_attempts
				SET status = 'CANCELLED'
				WHERE tenant_id = $1 AND workspace_id = $2 AND investigation_id = $3 AND task_id = $4
				  AND lease_epoch = $5 AND status = 'RUNNING' AND lease_expires_at > clock_timestamp()
				RETURNING `+attemptProjection,
				scope.TenantID(), task.descriptor.WorkspaceID, task.descriptor.InvestigationID,
				task.descriptor.TaskID, heartbeat.Fence.Epoch()))
			if errors.Is(err, pgx.ErrNoRows) {
				return readtask.HeartbeatResult{}, readtask.ErrStaleFence
			}
			if err != nil {
				return readtask.HeartbeatResult{}, persistenceError("terminate replayed READ task heartbeat", err)
			}
			return heartbeatResult(task.descriptor, attempt, readtask.HeartbeatTerminate)
		}
		return readtask.HeartbeatResult{}, readtask.ErrInvalidTransition
	}
	if attempt.Status != readtask.AttemptRunning || !leaseCurrent {
		return readtask.HeartbeatResult{}, readtask.ErrStaleFence
	}
	if heartbeat.ValidateAgainst(task.descriptor, attempt) != nil {
		return readtask.HeartbeatResult{}, readtask.ErrHeartbeatConflict
	}

	if shouldTerminate {
		attempt, err = scanAttempt(tx.QueryRow(ctx, `
			UPDATE investigation_task_attempts
			SET heartbeat_seq = $6, last_heartbeat_at = clock_timestamp(), status = 'CANCELLED'
			WHERE tenant_id = $1 AND workspace_id = $2 AND investigation_id = $3 AND task_id = $4
			  AND lease_epoch = $5 AND status = 'RUNNING' AND heartbeat_seq + 1 = $6
			  AND lease_expires_at > clock_timestamp()
			RETURNING `+attemptProjection,
			scope.TenantID(), task.descriptor.WorkspaceID, task.descriptor.InvestigationID,
			task.descriptor.TaskID, heartbeat.Fence.Epoch(), heartbeat.Sequence))
		if errors.Is(err, pgx.ErrNoRows) {
			return readtask.HeartbeatResult{}, readtask.ErrStaleFence
		}
		if staleLeaseTransition(err) {
			return readtask.HeartbeatResult{}, readtask.ErrStaleFence
		}
		if err != nil {
			return readtask.HeartbeatResult{}, persistenceError("terminate READ task heartbeat", err)
		}
		return heartbeatResult(task.descriptor, attempt, readtask.HeartbeatTerminate)
	}

	attempt, err = scanAttempt(tx.QueryRow(ctx, `
		UPDATE investigation_task_attempts
		SET heartbeat_seq = $6, last_heartbeat_at = clock_timestamp(),
			lease_expires_at = GREATEST(
				lease_expires_at,
				LEAST(clock_timestamp() + make_interval(secs => $7::double precision), certificate_not_after)
			)
		WHERE tenant_id = $1 AND workspace_id = $2 AND investigation_id = $3 AND task_id = $4
		  AND lease_epoch = $5 AND status = 'RUNNING' AND heartbeat_seq + 1 = $6
		  AND lease_expires_at > clock_timestamp()
		RETURNING `+attemptProjection,
		scope.TenantID(), task.descriptor.WorkspaceID, task.descriptor.InvestigationID,
		task.descriptor.TaskID, heartbeat.Fence.Epoch(), heartbeat.Sequence, extension.Seconds()))
	if errors.Is(err, pgx.ErrNoRows) {
		return readtask.HeartbeatResult{}, readtask.ErrStaleFence
	}
	if staleLeaseTransition(err) {
		return readtask.HeartbeatResult{}, readtask.ErrStaleFence
	}
	if err != nil {
		return readtask.HeartbeatResult{}, persistenceError("heartbeat READ task attempt", err)
	}
	if err := validateLockedTaskAttemptProjection("validate READ task heartbeat", task.descriptor, attempt); err != nil {
		return readtask.HeartbeatResult{}, err
	}
	if !attemptIdentityCurrent(scope, certificate, task.descriptor, attempt) {
		return readtask.HeartbeatResult{}, integrityError("validate READ task heartbeat", errors.New("invalid attempt projection"))
	}
	return heartbeatResult(task.descriptor, attempt, readtask.HeartbeatContinue)
}

func heartbeatResult(
	descriptor readtask.Descriptor,
	attempt readtask.Attempt,
	directive readtask.HeartbeatDirective,
) (readtask.HeartbeatResult, error) {
	result := readtask.HeartbeatResult{
		Attempt: attempt, AcceptedSequence: attempt.HeartbeatSequence,
		Directive: directive, LeaseExpiresAt: attempt.LeaseExpiresAt,
	}
	if result.ValidateAgainst(descriptor) != nil {
		return readtask.HeartbeatResult{}, integrityError("validate READ task heartbeat result", errors.New("invalid heartbeat projection"))
	}
	return result, nil
}

// ReleaseRunnerTx terminates only a LEASED, pre-start attempt. The task stays
// QUEUED (or RUNNING after a re-lease) and a later claim receives a new epoch.
func (repository *Repository) ReleaseRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	certificate readtask.CertificateBinding,
	release readtask.Release,
) (readtask.Attempt, error) {
	if err := validateRunnerRequest(ctx, tx, scope, certificate); err != nil {
		return readtask.Attempt{}, err
	}
	if !release.Fence.Valid() {
		return readtask.Attempt{}, readtask.ErrInvalidRequest
	}
	task, err := lockTask(ctx, tx, scope.TenantID(), release.Fence.TaskID())
	if errors.Is(err, pgx.ErrNoRows) {
		return readtask.Attempt{}, readtask.ErrNotFound
	}
	if err != nil {
		return readtask.Attempt{}, persistenceError("lock READ task for release", err)
	}
	attempt, err := lockAttempt(ctx, tx, task.descriptor, release.Fence.Epoch())
	if errors.Is(err, pgx.ErrNoRows) {
		return readtask.Attempt{}, readtask.ErrStaleFence
	}
	if err != nil {
		return readtask.Attempt{}, persistenceError("lock READ task attempt for release", err)
	}
	if err := validateLockedTaskAttemptProjection("validate locked READ task release", task.descriptor, attempt); err != nil {
		return readtask.Attempt{}, err
	}
	databaseNow, err := databaseClock(ctx, tx)
	if err != nil {
		return readtask.Attempt{}, err
	}
	if !attemptIdentityCurrent(scope, certificate, task.descriptor, attempt) ||
		!fenceMatchesAttempt(release.Fence, attempt) {
		return readtask.Attempt{}, readtask.ErrStaleFence
	}
	if attempt.Status == readtask.AttemptReleased {
		return attempt, nil
	}
	if release.ValidateAgainst(task.descriptor, attempt) != nil || !databaseNow.Before(attempt.LeaseExpiresAt) {
		return readtask.Attempt{}, readtask.ErrInvalidTransition
	}
	attempt, err = scanAttempt(tx.QueryRow(ctx, `
		UPDATE investigation_task_attempts
		SET status = 'RELEASED'
		WHERE tenant_id = $1 AND workspace_id = $2 AND investigation_id = $3 AND task_id = $4
		  AND lease_epoch = $5 AND status = 'LEASED' AND lease_expires_at > clock_timestamp()
		RETURNING `+attemptProjection,
		scope.TenantID(), task.descriptor.WorkspaceID, task.descriptor.InvestigationID,
		task.descriptor.TaskID, release.Fence.Epoch()))
	if errors.Is(err, pgx.ErrNoRows) {
		return readtask.Attempt{}, readtask.ErrStaleFence
	}
	if staleLeaseTransition(err) {
		return readtask.Attempt{}, readtask.ErrStaleFence
	}
	if err != nil {
		return readtask.Attempt{}, persistenceError("release READ task attempt", err)
	}
	if err := validateLockedTaskAttemptProjection("validate released READ task attempt", task.descriptor, attempt); err != nil {
		return readtask.Attempt{}, err
	}
	if attempt.Status != readtask.AttemptReleased {
		return readtask.Attempt{}, integrityError("validate released READ task attempt", errors.New("invalid attempt projection"))
	}
	return attempt, nil
}

// CompletionAuthorizer is the trusted connector-specific output-schema
// boundary. It receives detached, secret-free values only: the lease Fence is
// deliberately excluded so a connector contract can never observe a bearer.
// The callback must be side-effect-free.
type CompletionAuthorizer func(context.Context, readtask.Descriptor, readtask.EvidenceCompletion) error

// CompleteRunnerAuthorizedTx projects bounded Runner output and atomically
// persists the Evidence (when present), terminal Task, COMPLETED attempt, and
// immutable v2 receipt. A non-nil connector-specific output authorizer is
// mandatory even for failure-only completions so callers cannot accidentally
// construct a completion path that skips the typed contract. The same
// attempt/body replays the original IDs without re-running mutable admission
// policy; any other body is a completion conflict.
func (repository *Repository) CompleteRunnerAuthorizedTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	certificate readtask.CertificateBinding,
	completion readtask.Completion,
	authorizer CompletionAuthorizer,
) (readtask.CompletionResult, error) {
	if authorizer == nil {
		return readtask.CompletionResult{}, readtask.ErrInvalidRequest
	}
	if err := validateRunnerRequest(ctx, tx, scope, certificate); err != nil {
		return readtask.CompletionResult{}, err
	}
	if !completion.Fence.Valid() {
		return readtask.CompletionResult{}, readtask.ErrInvalidRequest
	}
	task, err := lockTask(ctx, tx, scope.TenantID(), completion.Fence.TaskID())
	if errors.Is(err, pgx.ErrNoRows) {
		return readtask.CompletionResult{}, readtask.ErrNotFound
	}
	if err != nil {
		return readtask.CompletionResult{}, persistenceError("lock READ task for completion", err)
	}
	attempt, err := lockAttempt(ctx, tx, task.descriptor, completion.Fence.Epoch())
	if errors.Is(err, pgx.ErrNoRows) {
		return readtask.CompletionResult{}, readtask.ErrStaleFence
	}
	if err != nil {
		return readtask.CompletionResult{}, persistenceError("lock READ task attempt for completion", err)
	}
	if err := validateLockedTaskAttemptProjection("validate locked READ task completion", task.descriptor, attempt); err != nil {
		return readtask.CompletionResult{}, err
	}
	if !attemptIdentityCurrent(scope, certificate, task.descriptor, attempt) ||
		!fenceMatchesAttempt(completion.Fence, attempt) {
		return readtask.CompletionResult{}, readtask.ErrStaleFence
	}
	parentStatus, err := lockParentStatus(ctx, tx, task.descriptor)
	if err != nil {
		return readtask.CompletionResult{}, err
	}
	databaseNow, err := databaseClock(ctx, tx)
	if err != nil {
		return readtask.CompletionResult{}, err
	}

	projection, err := projectRunnerCompletion(task.descriptor, attempt, completion, databaseNow)
	if err != nil {
		return readtask.CompletionResult{}, readtask.ErrProjectionRejected
	}
	if attempt.Status == readtask.AttemptCompleted {
		if attempt.RequestHash != projection.RequestHash() || attempt.ReceiptHash != projection.ReceiptHash() {
			return readtask.CompletionResult{}, readtask.ErrCompletionConflict
		}
		return loadCompletionReplay(ctx, tx, task.descriptor, attempt, projection)
	}
	if attempt.Status != readtask.AttemptRunning || task.taskStatus != "RUNNING" || parentStatus != "RUNNING" {
		return readtask.CompletionResult{}, readtask.ErrInvalidTransition
	}
	if !databaseNow.Before(attempt.LeaseExpiresAt) {
		return readtask.CompletionResult{}, readtask.ErrStaleFence
	}
	if completion.Outcome == readtask.CompletionEvidence {
		descriptorCopy := task.descriptor
		descriptorCopy.Input = bytes.Clone(task.descriptor.Input)
		evidenceCopy := cloneEvidenceCompletion(completion.Evidence)
		if evidenceCopy == nil {
			return readtask.CompletionResult{}, readtask.ErrProjectionRejected
		}
		if err := authorizer(ctx, descriptorCopy, *evidenceCopy); err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return readtask.CompletionResult{}, contextErr
			}
			if errors.Is(err, readtask.ErrClaimsDisabled) {
				return readtask.CompletionResult{}, readtask.ErrClaimsDisabled
			}
			return readtask.CompletionResult{}, readtask.ErrProjectionRejected
		}
	}

	evidenceID := ""
	if projection.Outcome() == readtask.CompletionEvidence {
		evidenceID = repository.idSource()
		if !uuidPattern.MatchString(evidenceID) {
			return readtask.CompletionResult{}, integrityError("allocate Evidence ID", errors.New("invalid ID source"))
		}
		querySummary, marshalErr := json.Marshal(map[string]any{
			"operation": task.descriptor.Operation,
		})
		if marshalErr != nil {
			return readtask.CompletionResult{}, integrityError("encode Evidence query summary", marshalErr)
		}
		attributes := projection.Attributes()
		redactedSummary, marshalErr := json.Marshal(attributes)
		if marshalErr != nil {
			return readtask.CompletionResult{}, integrityError("encode Evidence redacted summary", marshalErr)
		}
		attributesJSON, marshalErr := json.Marshal(attributes)
		if marshalErr != nil {
			return readtask.CompletionResult{}, integrityError("encode Evidence attributes", marshalErr)
		}
		truncated := attributes["truncated"] == "true"
		var createdAt time.Time
		err = tx.QueryRow(ctx, `
			INSERT INTO evidence (
				id, tenant_id, workspace_id, investigation_id, connector, resource_ref,
				query_summary, collected_at, redacted_summary, raw_ref, content_hash,
				trust_level, truncated, created_at, incident_id, task_id,
				payload_document, attributes, runtime_schema_version
			) VALUES (
				$1, $2, $3, $4, $5, NULL, $6, $7, $8, NULL, $9,
				'AUTHENTICATED_READ_RUNNER', $10, clock_timestamp(), $11, $12,
				$13, $14, 'investigation-runtime.v1'
			)
			RETURNING created_at
		`, evidenceID, scope.TenantID(), task.descriptor.WorkspaceID, task.descriptor.InvestigationID,
			task.descriptor.ConnectorID, string(querySummary), projection.CollectedAt(), string(redactedSummary),
			projection.ContentHash(), truncated, task.descriptor.IncidentID, task.descriptor.TaskID,
			[]byte(projection.Payload()), string(attributesJSON)).Scan(&createdAt)
		if err != nil {
			return readtask.CompletionResult{}, persistenceError("persist authenticated READ Evidence", err)
		}
		if !validFiniteTime(createdAt) {
			return readtask.CompletionResult{}, integrityError("validate Evidence receipt time", errors.New("invalid database time"))
		}
	}

	if err := updateTerminalTask(ctx, tx, task.descriptor, projection, evidenceID); err != nil {
		return readtask.CompletionResult{}, err
	}
	attempt, err = scanAttempt(tx.QueryRow(ctx, `
		UPDATE investigation_task_attempts
		SET status = 'COMPLETED', request_hash = $6, receipt_hash = $7
		WHERE tenant_id = $1 AND workspace_id = $2 AND investigation_id = $3 AND task_id = $4
		  AND lease_epoch = $5 AND status = 'RUNNING' AND lease_expires_at > clock_timestamp()
		RETURNING `+attemptProjection,
		scope.TenantID(), task.descriptor.WorkspaceID, task.descriptor.InvestigationID,
		task.descriptor.TaskID, completion.Fence.Epoch(), projection.RequestHash(), projection.ReceiptHash()))
	if errors.Is(err, pgx.ErrNoRows) {
		return readtask.CompletionResult{}, readtask.ErrStaleFence
	}
	if staleLeaseTransition(err) {
		return readtask.CompletionResult{}, readtask.ErrStaleFence
	}
	if err != nil {
		return readtask.CompletionResult{}, persistenceError("complete READ task attempt", err)
	}
	if err := validateLockedTaskAttemptProjection("validate completed READ task attempt", task.descriptor, attempt); err != nil {
		return readtask.CompletionResult{}, err
	}
	if attempt.Status != readtask.AttemptCompleted || attempt.RequestHash != projection.RequestHash() ||
		attempt.ReceiptHash != projection.ReceiptHash() {
		return readtask.CompletionResult{}, integrityError("validate completed READ task attempt", errors.New("invalid attempt projection"))
	}

	receiptID := repository.idSource()
	if !uuidPattern.MatchString(receiptID) {
		return readtask.CompletionResult{}, integrityError("allocate READ receipt ID", errors.New("invalid ID source"))
	}
	var evidenceArgument, contentHashArgument, failureArgument any
	if projection.Outcome() == readtask.CompletionEvidence {
		evidenceArgument = evidenceID
		contentHashArgument = projection.ContentHash()
	} else {
		failureArgument = string(projection.FailureCode())
	}
	var receivedAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO runner_evidence_receipts (
			id, tenant_id, workspace_id, environment_id, investigation_id, task_id,
			runner_id, scope_revision, certificate_sha256, connector_id,
			evidence_id, content_hash, failure_code, idempotency_key,
			request_hash, receipt_hash, schema_version, received_at, lease_epoch
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15, $16, 'runner-evidence.v2', clock_timestamp(), $17
		)
		RETURNING received_at
	`, receiptID, scope.TenantID(), task.descriptor.WorkspaceID, task.descriptor.EnvironmentID,
		task.descriptor.InvestigationID, task.descriptor.TaskID, scope.RunnerID(), scope.ScopeRevision(),
		certificate.SHA256, task.descriptor.ConnectorID, evidenceArgument, contentHashArgument, failureArgument,
		projection.IdempotencyKey(), projection.RequestHash(), projection.ReceiptHash(), attempt.Epoch).Scan(&receivedAt)
	if err != nil {
		return readtask.CompletionResult{}, persistenceError("persist authenticated READ receipt", err)
	}
	projection, err = projection.WithReceivedAt(receivedAt, task.descriptor, attempt)
	if err != nil {
		return readtask.CompletionResult{}, integrityError("bind READ receipt database time", err)
	}
	result := readtask.CompletionResult{
		Attempt: attempt, Projection: projection, EvidenceID: evidenceID, ReceiptID: receiptID,
	}
	if result.ValidateAgainst(task.descriptor) != nil {
		return readtask.CompletionResult{}, integrityError("validate READ completion result", errors.New("invalid completion projection"))
	}
	return result, nil
}

func cloneEvidenceCompletion(source *readtask.EvidenceCompletion) *readtask.EvidenceCompletion {
	if source == nil {
		return nil
	}
	cloned := &readtask.EvidenceCompletion{CollectedAt: source.CollectedAt}
	if source.Items != nil {
		cloned.Items = make([]json.RawMessage, len(source.Items))
		for index := range source.Items {
			cloned.Items[index] = bytes.Clone(source.Items[index])
		}
	}
	return cloned
}

func projectRunnerCompletion(
	descriptor readtask.Descriptor,
	attempt readtask.Attempt,
	completion readtask.Completion,
	receivedAt time.Time,
) (readtask.ProjectedCompletion, error) {
	projectionAttempt := attempt
	if attempt.Status == readtask.AttemptCompleted {
		receivedAt = attempt.TerminalAt
		// Rebuild the semantic request independently of committed hashes so a
		// changed replay is a conflict, not a malformed projection.
		projectionAttempt.Status = readtask.AttemptRunning
		projectionAttempt.TerminalAt = time.Time{}
		projectionAttempt.RequestHash = ""
		projectionAttempt.ReceiptHash = ""
	}
	return readtask.ProjectCompletion(descriptor, projectionAttempt, completion, receivedAt)
}

func updateTerminalTask(
	ctx context.Context,
	tx pgx.Tx,
	descriptor readtask.Descriptor,
	projection readtask.ProjectedCompletion,
	evidenceID string,
) error {
	var status string
	var evidenceArgument, hashArgument, failureArgument any
	switch projection.Outcome() {
	case readtask.CompletionEvidence:
		status = "EVIDENCE"
		evidenceArgument = evidenceID
		hashArgument = projection.ContentHash()
	case readtask.CompletionFailed:
		status = "FAILED"
		failureArgument = string(projection.FailureCode())
	case readtask.CompletionCancelled:
		status = "CANCELLED"
		failureArgument = string(projection.FailureCode())
	default:
		return readtask.ErrProjectionRejected
	}
	updated, err := tx.Exec(ctx, `
		UPDATE tool_invocations
		SET status = $5, evidence_id = $6, output_hash = $7, failure_code = $8,
			completed_at = clock_timestamp(), updated_at = GREATEST(updated_at, clock_timestamp())
		WHERE tenant_id = $1 AND workspace_id = $2 AND investigation_id = $3 AND id = $4
		  AND runtime_schema_version = 'investigation-runtime.v1' AND status = 'RUNNING'
	`, descriptor.TenantID, descriptor.WorkspaceID, descriptor.InvestigationID, descriptor.TaskID,
		status, evidenceArgument, hashArgument, failureArgument)
	if err != nil {
		return persistenceError("complete READ task", err)
	}
	if updated.RowsAffected() != 1 {
		return readtask.ErrInvalidTransition
	}
	return nil
}

func loadCompletionReplay(
	ctx context.Context,
	tx pgx.Tx,
	descriptor readtask.Descriptor,
	attempt readtask.Attempt,
	projection readtask.ProjectedCompletion,
) (readtask.CompletionResult, error) {
	var receiptID, evidenceID string
	var receivedAt time.Time
	err := tx.QueryRow(ctx, `
		SELECT receipt.id::text, COALESCE(receipt.evidence_id::text, ''), receipt.received_at
		FROM runner_evidence_receipts AS receipt
		WHERE receipt.tenant_id = $1 AND receipt.workspace_id = $2
		  AND receipt.investigation_id = $3 AND receipt.task_id = $4
		  AND receipt.runner_id = $5 AND receipt.lease_epoch = $6
		  AND receipt.request_hash = $7 AND receipt.receipt_hash = $8
		  AND receipt.schema_version = 'runner-evidence.v2'
		FOR SHARE OF receipt
	`, descriptor.TenantID, descriptor.WorkspaceID, descriptor.InvestigationID, descriptor.TaskID,
		attempt.RunnerID, attempt.Epoch, attempt.RequestHash, attempt.ReceiptHash).Scan(
		&receiptID, &evidenceID, &receivedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return readtask.CompletionResult{}, readtask.ErrCompletionConflict
	}
	if err != nil {
		return readtask.CompletionResult{}, persistenceError("load READ completion replay", err)
	}
	projection, err = projection.WithReceivedAt(receivedAt, descriptor, attempt)
	if err != nil {
		return readtask.CompletionResult{}, integrityError("bind READ replay database time", err)
	}
	result := readtask.CompletionResult{
		Attempt: attempt, Projection: projection, EvidenceID: evidenceID, ReceiptID: receiptID, Replayed: true,
	}
	if result.ValidateAgainst(descriptor) != nil {
		return readtask.CompletionResult{}, integrityError("validate READ completion replay", errors.New("invalid replay projection"))
	}
	return result, nil
}

func lockParentStatus(ctx context.Context, tx pgx.Tx, descriptor readtask.Descriptor) (string, error) {
	var status string
	err := tx.QueryRow(ctx, `
		SELECT status
		FROM investigations
		WHERE tenant_id = $1 AND workspace_id = $2 AND id = $3
		  AND runtime_schema_version = 'investigation-runtime.v1'
		FOR NO KEY UPDATE
	`, descriptor.TenantID, descriptor.WorkspaceID, descriptor.InvestigationID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", readtask.ErrNotFound
	}
	if err != nil {
		return "", persistenceError("lock READ task parent", err)
	}
	return status, nil
}

const attemptProjection = `
	task_id::text, runner_id, scope_revision, certificate_sha256, certificate_not_after,
	lease_token_sha256, lease_epoch, status, heartbeat_seq, lease_acquired_at,
	last_heartbeat_at, lease_expires_at, started_at, terminal_at, request_hash, receipt_hash, updated_at
`

func lockAttempt(
	ctx context.Context,
	tx pgx.Tx,
	descriptor readtask.Descriptor,
	epoch int64,
) (readtask.Attempt, error) {
	return scanAttempt(tx.QueryRow(ctx, `
		SELECT `+attemptProjection+`
		FROM investigation_task_attempts AS attempt
		WHERE attempt.tenant_id = $1 AND attempt.workspace_id = $2
		  AND attempt.investigation_id = $3 AND attempt.task_id = $4 AND attempt.lease_epoch = $5
		FOR UPDATE OF attempt
	`, descriptor.TenantID, descriptor.WorkspaceID, descriptor.InvestigationID, descriptor.TaskID, epoch))
}

func scanAttempt(row pgx.Row) (readtask.Attempt, error) {
	var attempt readtask.Attempt
	var status string
	var startedAt, terminalAt pgtype.Timestamptz
	var requestHash, receiptHash pgtype.Text
	err := row.Scan(
		&attempt.TaskID, &attempt.RunnerID, &attempt.ScopeRevision, &attempt.Certificate.SHA256,
		&attempt.Certificate.NotAfter, &attempt.TokenSHA256, &attempt.Epoch, &status,
		&attempt.HeartbeatSequence, &attempt.LeaseAcquiredAt, &attempt.LastHeartbeatAt,
		&attempt.LeaseExpiresAt, &startedAt, &terminalAt, &requestHash, &receiptHash, &attempt.UpdatedAt,
	)
	if err != nil {
		return readtask.Attempt{}, err
	}
	attempt.Status = readtask.AttemptStatus(status)
	if startedAt.Valid {
		attempt.StartedAt = startedAt.Time.UTC()
	}
	if terminalAt.Valid {
		attempt.TerminalAt = terminalAt.Time.UTC()
	}
	if requestHash.Valid {
		attempt.RequestHash = requestHash.String
	}
	if receiptHash.Valid {
		attempt.ReceiptHash = receiptHash.String
	}
	attempt.Certificate.NotAfter = attempt.Certificate.NotAfter.UTC()
	attempt.LeaseAcquiredAt = attempt.LeaseAcquiredAt.UTC()
	attempt.LastHeartbeatAt = attempt.LastHeartbeatAt.UTC()
	attempt.LeaseExpiresAt = attempt.LeaseExpiresAt.UTC()
	attempt.UpdatedAt = attempt.UpdatedAt.UTC()
	return attempt, nil
}

func attemptIdentityCurrent(
	scope execution.RunnerScope,
	certificate readtask.CertificateBinding,
	descriptor readtask.Descriptor,
	attempt readtask.Attempt,
) bool {
	return attempt.RunnerID == scope.RunnerID() &&
		attempt.ScopeRevision == scope.ScopeRevision() && attempt.Certificate.SHA256 == certificate.SHA256 &&
		attempt.Certificate.NotAfter.Equal(certificate.NotAfter) &&
		runnerScopeAllows(scope, descriptor.WorkspaceID, descriptor.EnvironmentID)
}

func validateLockedTaskAttemptProjection(
	operation string,
	descriptor readtask.Descriptor,
	attempt readtask.Attempt,
) error {
	if descriptor.Validate() != nil || attempt.ValidateAgainst(descriptor) != nil {
		return integrityError(operation, errors.New("invalid persisted task attempt"))
	}
	return nil
}

func fenceMatchesAttempt(fence readtask.Fence, attempt readtask.Attempt) bool {
	return fence.Valid() && fence.TaskID() == attempt.TaskID && fence.RunnerID() == attempt.RunnerID &&
		fence.Epoch() == attempt.Epoch && fence.MatchesTokenSHA256(attempt.TokenSHA256)
}

func lockTask(ctx context.Context, tx pgx.Tx, tenantID, taskID string) (storedTask, error) {
	var task storedTask
	err := tx.QueryRow(ctx, `
		SELECT task.tenant_id::text, task.workspace_id::text,
			COALESCE(investigation.environment_id_snapshot::text, ''),
			COALESCE(investigation.service_id_snapshot::text, ''),
			task.incident_id::text, task.investigation_id::text, task.id::text,
			task.task_key, task.position, task.tool_name, task.tool_version,
			task.input_document, task.input_hash, task.status, investigation.status
		FROM tool_invocations AS task
		JOIN investigations AS investigation
		  ON investigation.tenant_id = task.tenant_id
		 AND investigation.workspace_id = task.workspace_id
		 AND investigation.id = task.investigation_id
		WHERE task.tenant_id = $1 AND task.id = $2
		  AND task.runtime_schema_version = 'investigation-runtime.v1'
		  AND investigation.runtime_schema_version = 'investigation-runtime.v1'
		FOR NO KEY UPDATE OF task
	`, tenantID, taskID).Scan(
		&task.descriptor.TenantID, &task.descriptor.WorkspaceID, &task.descriptor.EnvironmentID,
		&task.descriptor.ServiceID, &task.descriptor.IncidentID, &task.descriptor.InvestigationID, &task.descriptor.TaskID,
		&task.descriptor.TaskKey, &task.descriptor.Position, &task.descriptor.ConnectorID,
		&task.descriptor.Operation, &task.descriptor.Input, &task.descriptor.InputHash,
		&task.taskStatus, &task.investigationStatus,
	)
	if err != nil {
		return storedTask{}, err
	}
	if task.descriptor.EnvironmentID == "" || task.descriptor.ServiceID == "" {
		return storedTask{}, pgx.ErrNoRows
	}
	return task, nil
}

// databaseClock is intentionally read only after all operation-specific row
// locks have been acquired. statement_timestamp() is fixed at statement start
// and can therefore validate an already-expired lease after a lock wait.
func databaseClock(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return time.Time{}, persistenceError("read PostgreSQL clock", err)
	}
	if !validFiniteTime(now) {
		return time.Time{}, integrityError("validate PostgreSQL clock", errors.New("invalid database time"))
	}
	return now.UTC(), nil
}

func validateRunnerRequest(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	certificate readtask.CertificateBinding,
) error {
	if ctx == nil || tx == nil || scope.Pool() != executionlease.PoolRead ||
		!uuidPattern.MatchString(scope.TenantID()) || scope.RunnerID() == "" || scope.ScopeRevision() <= 0 ||
		scope.MaxConcurrency() < 1 || len(scope.Bindings()) == 0 || certificate.Validate() != nil {
		return readtask.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func runnerScopeAllows(scope execution.RunnerScope, workspaceID, environmentID string) bool {
	for _, binding := range scope.Bindings() {
		if binding.WorkspaceID == workspaceID && binding.EnvironmentID == environmentID {
			return true
		}
	}
	return false
}

func validFiniteTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999
}

func staleLeaseTransition(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "55000" &&
		postgresError.ConstraintName == "investigation_task_attempts_lease_current_guard"
}

func persistenceError(operation string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return databaseOperationError{operation: operation, cause: err}
}

func integrityError(operation string, err error) error {
	return repositoryIntegrityError{operation: operation, cause: err}
}

type databaseOperationError struct {
	operation string
	cause     error
}

func (failure databaseOperationError) Error() string {
	return failure.operation + ": " + readtask.ErrPersistence.Error()
}
func (failure databaseOperationError) Unwrap() []error {
	return []error{readtask.ErrPersistence, failure.cause}
}

type repositoryIntegrityError struct {
	operation string
	cause     error
}

func (failure repositoryIntegrityError) Error() string {
	return failure.operation + ": " + readtask.ErrIntegrity.Error()
}
func (failure repositoryIntegrityError) Unwrap() []error {
	return []error{readtask.ErrIntegrity, failure.cause}
}
