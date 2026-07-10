package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/seaworld008/aiops-system/internal/executionlease"
)

const (
	minLeaseDuration    = time.Second
	maxLeaseDuration    = 30 * time.Minute
	claimAdvisoryLock   = int64(0x455845434C454153)
	executionProjection = `
		execution_id, target_key, runner_pool, production, status,
		runner_id, COALESCE(lease_token_sha256, completed_lease_token_sha256) AS lease_token_hash,
		lease_epoch, lease_expires_at, lease_acquired_at, last_heartbeat_at,
		started_at, completed_at, result_hash, created_at, updated_at,
		reconciliation_id, reconciliation_actor, reconciliation_result_hash, reconciled_at
	`
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]*\z`)
	resultHashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
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

var _ executionlease.Repository = (*Repository)(nil)

func New(database DB, options Options) (*Repository, error) {
	if database == nil {
		return nil, fmt.Errorf("%w: PostgreSQL database is required", executionlease.ErrInvalidRequest)
	}
	if options.TokenSource == nil {
		options.TokenSource = randomToken
	}
	return &Repository{database: database, tokenSource: options.TokenSource}, nil
}

func (repository *Repository) Enqueue(ctx context.Context, request executionlease.EnqueueRequest) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validIdentifier(request.ExecutionID, 256) || !validIdentifier(request.TargetKey, 512) || !validPool(request.Pool) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	row := repository.database.QueryRow(ctx, `
		INSERT INTO execution_leases (
			execution_id, target_key, runner_pool, production, status, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'QUEUED', statement_timestamp(), statement_timestamp())
		ON CONFLICT (execution_id) DO NOTHING
		RETURNING `+executionProjection,
		request.ExecutionID, request.TargetKey, request.Pool, request.Production,
	)
	execution, err := scanExecution(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return executionlease.Execution{}, executionlease.ErrAlreadyExists
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("enqueue execution lease: %w", err)
	}
	return execution, nil
}

func (repository *Repository) Claim(ctx context.Context, request executionlease.ClaimRequest) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validPool(request.Pool) || !validIdentifier(request.RunnerID, 256) || request.LeaseDuration < minLeaseDuration || request.LeaseDuration > maxLeaseDuration {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}

	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("begin execution claim transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, claimAdvisoryLock); err != nil {
		return executionlease.Execution{}, fmt.Errorf("lock execution claim queue: %w", err)
	}
	if err := sweepExpired(ctx, tx, ""); err != nil {
		return executionlease.Execution{}, err
	}
	if !request.ClaimsEnabled {
		if err := tx.Commit(ctx); err != nil {
			return executionlease.Execution{}, fmt.Errorf("commit disabled execution claim sweep: %w", err)
		}
		committed = true
		return executionlease.Execution{}, executionlease.ErrClaimBlocked
	}

	var executionID string
	var leaseEpoch int64
	err = tx.QueryRow(ctx, `
		SELECT candidate.execution_id, candidate.lease_epoch
		FROM execution_leases AS candidate
		WHERE candidate.runner_pool = $1
		  AND candidate.status = 'QUEUED'
		  AND NOT EXISTS (
			SELECT 1
			FROM execution_leases AS active
			WHERE active.execution_id <> candidate.execution_id
			  AND active.target_key = candidate.target_key
			  AND active.status IN ('LEASED', 'RUNNING', 'UNCERTAIN')
		  )
		  AND (
			candidate.runner_pool <> 'WRITE'
			OR candidate.production = false
			OR NOT EXISTS (
				SELECT 1
				FROM execution_leases AS active
				WHERE active.execution_id <> candidate.execution_id
				  AND active.runner_pool = 'WRITE'
				  AND active.production = true
				  AND active.status IN ('LEASED', 'RUNNING', 'UNCERTAIN')
			)
		  )
		ORDER BY candidate.created_at, candidate.execution_id
		FOR UPDATE OF candidate SKIP LOCKED
		LIMIT 1
	`, request.Pool).Scan(&executionID, &leaseEpoch)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return executionlease.Execution{}, fmt.Errorf("commit execution expiry transitions: %w", err)
		}
		committed = true
		return executionlease.Execution{}, executionlease.ErrNoLeaseAvailable
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("select execution claim candidate: %w", err)
	}
	if leaseEpoch == math.MaxInt64 {
		return executionlease.Execution{}, fmt.Errorf("%w: lease epoch exhausted", executionlease.ErrInvalidTransition)
	}
	token, err := repository.tokenSource()
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("generate execution lease token: %w", err)
	}
	if !validIdentifier(token, 256) {
		return executionlease.Execution{}, fmt.Errorf("%w: token source returned an invalid token", executionlease.ErrInvalidRequest)
	}
	tokenDigest := tokenHash(token)
	execution, err := scanExecution(tx.QueryRow(ctx, `
		UPDATE execution_leases AS execution
		SET status = 'LEASED', runner_id = $2, lease_token_sha256 = $3,
			lease_epoch = execution.lease_epoch + 1,
			lease_acquired_at = statement_timestamp(),
			last_heartbeat_at = statement_timestamp(),
			lease_expires_at = statement_timestamp() + make_interval(secs => $4::double precision),
			started_at = NULL, completed_at = NULL, result_hash = NULL,
			completed_lease_token_sha256 = NULL, completed_lease_epoch = NULL,
			reconciliation_id = NULL, reconciliation_actor = NULL,
			reconciliation_result_hash = NULL, reconciled_at = NULL,
			updated_at = statement_timestamp()
		WHERE execution.execution_id = $1 AND execution.status = 'QUEUED'
		RETURNING `+executionProjection,
		executionID, request.RunnerID, tokenDigest, request.LeaseDuration.Seconds(),
	))
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("claim execution: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return executionlease.Execution{}, fmt.Errorf("commit execution claim: %w", err)
	}
	committed = true
	execution.LeaseToken = token
	return execution, nil
}

func (repository *Repository) SweepExpired(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin execution expiry sweep: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, claimAdvisoryLock); err != nil {
		return fmt.Errorf("lock execution expiry sweep: %w", err)
	}
	if err := sweepExpired(ctx, tx, ""); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit execution expiry sweep: %w", err)
	}
	committed = true
	return nil
}

func (repository *Repository) Start(ctx context.Context, lease executionlease.LeaseIdentity) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validLease(lease) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	digest := tokenHash(lease.Token)
	execution, err := scanExecution(repository.database.QueryRow(ctx, `
		UPDATE execution_leases
		SET status = 'RUNNING', started_at = COALESCE(started_at, statement_timestamp()),
			updated_at = CASE WHEN status = 'LEASED' THEN statement_timestamp() ELSE updated_at END
		WHERE execution_id = $1 AND runner_id = $2 AND lease_token_sha256 = $3 AND lease_epoch = $4
		  AND status IN ('LEASED', 'RUNNING')
		  AND lease_expires_at > statement_timestamp()
		RETURNING `+executionProjection,
		lease.ExecutionID, lease.RunnerID, digest, lease.Epoch,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.leaseMiss(ctx, lease)
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("start execution lease: %w", err)
	}
	return redactedExecution(execution), nil
}

func (repository *Repository) Heartbeat(ctx context.Context, request executionlease.HeartbeatRequest) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validLease(request.Lease) || request.Extension < minLeaseDuration || request.Extension > maxLeaseDuration {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	digest := tokenHash(request.Lease.Token)
	execution, err := scanExecution(repository.database.QueryRow(ctx, `
		UPDATE execution_leases
		SET last_heartbeat_at = statement_timestamp(),
			lease_expires_at = statement_timestamp() + make_interval(secs => $5::double precision),
			updated_at = statement_timestamp()
		WHERE execution_id = $1 AND runner_id = $2 AND lease_token_sha256 = $3 AND lease_epoch = $4
		  AND status IN ('LEASED', 'RUNNING')
		  AND lease_expires_at > statement_timestamp()
		RETURNING `+executionProjection,
		request.Lease.ExecutionID, request.Lease.RunnerID, digest, request.Lease.Epoch, request.Extension.Seconds(),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.leaseMiss(ctx, request.Lease)
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("heartbeat execution lease: %w", err)
	}
	return redactedExecution(execution), nil
}

func (repository *Repository) Complete(ctx context.Context, request executionlease.CompleteRequest) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validLease(request.Lease) || !validCompletionStatus(request.Status) || !resultHashPattern.MatchString(request.ResultHash) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("begin execution completion transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	digest := tokenHash(request.Lease.Token)
	execution, err := scanExecution(tx.QueryRow(ctx, `
		UPDATE execution_leases
		SET status = $5, result_hash = $6,
			completed_lease_token_sha256 = lease_token_sha256, completed_lease_epoch = lease_epoch,
			lease_token_sha256 = NULL, lease_expires_at = NULL,
			completed_at = statement_timestamp(), updated_at = statement_timestamp()
		WHERE execution_id = $1 AND runner_id = $2 AND lease_token_sha256 = $3 AND lease_epoch = $4
		  AND status = 'RUNNING'
		  AND lease_expires_at > statement_timestamp()
		RETURNING `+executionProjection,
		request.Lease.ExecutionID, request.Lease.RunnerID, digest, request.Lease.Epoch,
		request.Status, request.ResultHash,
	))
	if err == nil {
		if err := tx.Commit(ctx); err != nil {
			return executionlease.Execution{}, fmt.Errorf("commit execution completion: %w", err)
		}
		committed = true
		return redactedExecution(execution), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return executionlease.Execution{}, fmt.Errorf("complete execution lease: %w", err)
	}
	execution, err = scanExecution(tx.QueryRow(ctx, `
		SELECT `+executionProjection+`
		FROM execution_leases
		WHERE execution_id = $1
		FOR SHARE
	`, request.Lease.ExecutionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("read execution completion state: %w", err)
	}
	if execution.ReconciliationID != "" {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if execution.Terminal() {
		if execution.RunnerID != request.Lease.RunnerID || execution.LeaseToken != digest || execution.LeaseEpoch != request.Lease.Epoch {
			return executionlease.Execution{}, executionlease.ErrStaleLease
		}
		if execution.Status != request.Status || execution.ResultHash != request.ResultHash {
			return executionlease.Execution{}, executionlease.ErrCompletionConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return executionlease.Execution{}, fmt.Errorf("commit idempotent execution completion: %w", err)
		}
		committed = true
		return redactedExecution(execution), nil
	}
	if execution.RunnerID != request.Lease.RunnerID || execution.LeaseToken != digest || execution.LeaseEpoch != request.Lease.Epoch {
		return executionlease.Execution{}, executionlease.ErrStaleLease
	}
	if execution.Status != executionlease.StatusRunning {
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	return executionlease.Execution{}, executionlease.ErrStaleLease
}

func (repository *Repository) Reconcile(ctx context.Context, request executionlease.ReconcileRequest) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validIdentifier(request.ExecutionID, 256) || !validIdentifier(request.ReconciliationID, 256) ||
		!validIdentifier(request.ActorID, 256) || !validReconciliationStatus(request.Status) ||
		!resultHashPattern.MatchString(request.ResultHash) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	if err := repository.materializeTarget(ctx, request.ExecutionID); err != nil {
		return executionlease.Execution{}, err
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("begin execution reconciliation transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	execution, err := scanExecution(tx.QueryRow(ctx, `
		UPDATE execution_leases
		SET reconciliation_id = $2, reconciliation_actor = $3,
			status = $4, reconciliation_result_hash = $5,
			reconciled_at = statement_timestamp(), updated_at = statement_timestamp()
		WHERE execution_id = $1 AND status = 'UNCERTAIN' AND reconciliation_id IS NULL
		RETURNING `+executionProjection,
		request.ExecutionID, request.ReconciliationID, request.ActorID, request.Status, request.ResultHash,
	))
	if err == nil {
		if err := tx.Commit(ctx); err != nil {
			return executionlease.Execution{}, fmt.Errorf("commit execution reconciliation: %w", err)
		}
		committed = true
		return redactedExecution(execution), nil
	}
	if isUniqueViolation(err) {
		return executionlease.Execution{}, executionlease.ErrReconciliationConflict
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return executionlease.Execution{}, fmt.Errorf("reconcile execution: %w", err)
	}
	execution, err = scanExecution(tx.QueryRow(ctx, `
		SELECT `+executionProjection+`
		FROM execution_leases
		WHERE execution_id = $1
		FOR SHARE
	`, request.ExecutionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("read execution reconciliation state: %w", err)
	}
	if execution.ReconciliationID != "" {
		if execution.ReconciliationID != request.ReconciliationID || execution.ReconciliationActor != request.ActorID ||
			execution.Status != request.Status || execution.ReconciliationResultHash != request.ResultHash {
			return executionlease.Execution{}, executionlease.ErrReconciliationConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return executionlease.Execution{}, fmt.Errorf("commit idempotent execution reconciliation: %w", err)
		}
		committed = true
		return redactedExecution(execution), nil
	}
	return executionlease.Execution{}, executionlease.ErrInvalidTransition
}

func (repository *Repository) Cancel(ctx context.Context, executionID string) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validIdentifier(executionID, 256) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	execution, err := scanExecution(repository.database.QueryRow(ctx, `
		UPDATE execution_leases
		SET status = CASE WHEN status = 'RUNNING' THEN 'UNCERTAIN' ELSE 'CANCELLED' END,
			runner_id = CASE WHEN status = 'RUNNING' THEN runner_id ELSE NULL END,
			lease_token_sha256 = NULL, lease_expires_at = NULL,
			completed_at = statement_timestamp(), updated_at = statement_timestamp()
		WHERE execution_id = $1
		  AND status IN ('QUEUED', 'LEASED', 'RUNNING')
		RETURNING `+executionProjection,
		executionID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		existing, getErr := repository.get(ctx, executionID)
		if getErr != nil {
			return executionlease.Execution{}, getErr
		}
		if existing.Terminal() {
			return redactedExecution(existing), nil
		}
		return executionlease.Execution{}, executionlease.ErrInvalidTransition
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("cancel execution: %w", err)
	}
	return redactedExecution(execution), nil
}

func (repository *Repository) Get(ctx context.Context, executionID string) (executionlease.Execution, error) {
	if err := ctx.Err(); err != nil {
		return executionlease.Execution{}, err
	}
	if !validIdentifier(executionID, 256) {
		return executionlease.Execution{}, executionlease.ErrInvalidRequest
	}
	if err := repository.materializeTarget(ctx, executionID); err != nil {
		return executionlease.Execution{}, err
	}
	execution, err := repository.get(ctx, executionID)
	if err != nil {
		return executionlease.Execution{}, err
	}
	return redactedExecution(execution), nil
}

func (repository *Repository) materializeTarget(ctx context.Context, executionID string) error {
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin execution target materialization: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	if err := sweepExpired(ctx, tx, executionID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit execution target materialization: %w", err)
	}
	committed = true
	return nil
}

func sweepExpired(ctx context.Context, tx pgx.Tx, executionID string) error {
	targetPredicate := ""
	var args []any
	if executionID != "" {
		targetPredicate = " AND expired_running.execution_id = $1"
		args = append(args, executionID)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE execution_leases AS expired_running
		SET status = 'UNCERTAIN', lease_token_sha256 = NULL,
			lease_expires_at = NULL, completed_at = statement_timestamp(),
			updated_at = statement_timestamp()
		WHERE expired_running.status = 'RUNNING'
		  AND expired_running.lease_expires_at <= statement_timestamp()
	`+targetPredicate, args...); err != nil {
		return fmt.Errorf("mark expired running execution uncertain: %w", err)
	}

	targetPredicate = ""
	args = nil
	if executionID != "" {
		targetPredicate = " AND expired_lease.execution_id = $1"
		args = append(args, executionID)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE execution_leases AS expired_lease
		SET status = 'QUEUED', runner_id = NULL, lease_token_sha256 = NULL,
			lease_acquired_at = NULL, lease_expires_at = NULL,
			last_heartbeat_at = NULL, updated_at = statement_timestamp()
		WHERE expired_lease.status = 'LEASED'
		  AND expired_lease.lease_expires_at <= statement_timestamp()
	`+targetPredicate, args...); err != nil {
		return fmt.Errorf("release expired unstarted execution lease: %w", err)
	}
	return nil
}

func (repository *Repository) get(ctx context.Context, executionID string) (executionlease.Execution, error) {
	execution, err := scanExecution(repository.database.QueryRow(ctx, `
		SELECT `+executionProjection+`
		FROM execution_leases
		WHERE execution_id = $1
	`, executionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return executionlease.Execution{}, executionlease.ErrNotFound
	}
	if err != nil {
		return executionlease.Execution{}, fmt.Errorf("get execution lease: %w", err)
	}
	return execution, nil
}

func (repository *Repository) leaseMiss(ctx context.Context, lease executionlease.LeaseIdentity) (executionlease.Execution, error) {
	_, err := repository.get(ctx, lease.ExecutionID)
	if err != nil {
		return executionlease.Execution{}, err
	}
	return executionlease.Execution{}, executionlease.ErrStaleLease
}

func scanExecution(row pgx.Row) (executionlease.Execution, error) {
	var execution executionlease.Execution
	var pool, status string
	var runnerID, leaseToken, resultHash pgtype.Text
	var reconciliationID, reconciliationActor, reconciliationResultHash pgtype.Text
	var leaseExpiresAt, leaseAcquiredAt, lastHeartbeatAt pgtype.Timestamptz
	var startedAt, completedAt, reconciledAt pgtype.Timestamptz
	err := row.Scan(
		&execution.ExecutionID, &execution.TargetKey, &pool, &execution.Production, &status,
		&runnerID, &leaseToken, &execution.LeaseEpoch, &leaseExpiresAt, &leaseAcquiredAt,
		&lastHeartbeatAt, &startedAt, &completedAt, &resultHash, &execution.CreatedAt, &execution.UpdatedAt,
		&reconciliationID, &reconciliationActor, &reconciliationResultHash, &reconciledAt,
	)
	if err != nil {
		return executionlease.Execution{}, err
	}
	execution.Pool = executionlease.Pool(pool)
	execution.Status = executionlease.Status(status)
	execution.RunnerID = textValue(runnerID)
	execution.LeaseToken = textValue(leaseToken)
	execution.ResultHash = textValue(resultHash)
	execution.ReconciliationID = textValue(reconciliationID)
	execution.ReconciliationActor = textValue(reconciliationActor)
	execution.ReconciliationResultHash = textValue(reconciliationResultHash)
	execution.LeaseExpiresAt = timeValue(leaseExpiresAt)
	execution.LeaseAcquiredAt = timeValue(leaseAcquiredAt)
	execution.LastHeartbeatAt = timeValue(lastHeartbeatAt)
	execution.StartedAt = timeValue(startedAt)
	execution.CompletedAt = timeValue(completedAt)
	execution.ReconciledAt = timeValue(reconciledAt)
	return execution, nil
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

func validPool(pool executionlease.Pool) bool {
	return pool == executionlease.PoolRead || pool == executionlease.PoolWrite
}

func validLease(lease executionlease.LeaseIdentity) bool {
	return validIdentifier(lease.ExecutionID, 256) && validIdentifier(lease.RunnerID, 256) &&
		validIdentifier(lease.Token, 256) && lease.Epoch > 0
}

func validCompletionStatus(status executionlease.Status) bool {
	return status == executionlease.StatusSucceeded || status == executionlease.StatusFailed || status == executionlease.StatusUncertain
}

func validReconciliationStatus(status executionlease.Status) bool {
	return status == executionlease.StatusSucceeded || status == executionlease.StatusFailed
}

func validIdentifier(value string, maxBytes int) bool {
	return len(value) <= maxBytes && identifierPattern.MatchString(value)
}

func redactedExecution(execution executionlease.Execution) executionlease.Execution {
	execution.LeaseToken = ""
	return execution
}

func tokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func isUniqueViolation(err error) bool {
	var databaseError *pgconn.PgError
	return errors.As(err, &databaseError) && databaseError.Code == "23505"
}

func randomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
