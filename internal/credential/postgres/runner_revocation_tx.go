package postgres

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/execution"
)

var runnerRevocationRawTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)

// RunnerRevocationClaimTicket is an opaque, repository-bound claim candidate.
// ClaimRevocationRunnerTx deliberately keeps the bearer and revoke accessor in
// this ticket until the caller-owned transaction has committed. The type is
// not serializable, printable, or reusable.
type RunnerRevocationClaimTicket struct {
	mu sync.Mutex

	owner             *Repository
	rawToken          string
	accessor          *credential.SensitiveReference
	revocation        credential.Revocation
	runnerID          string
	tenantID          string
	workspaceID       string
	environmentID     string
	scopeRevision     int64
	certificateSHA256 string
	claimEpoch        int64
	claimTokenSHA256  string
	consumed          bool
}

func (*RunnerRevocationClaimTicket) String() string {
	return "RunnerRevocationClaimTicket{claim:[REDACTED]}"
}

func (ticket *RunnerRevocationClaimTicket) GoString() string { return ticket.String() }

func (ticket *RunnerRevocationClaimTicket) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(ticket.String()))
}

func (*RunnerRevocationClaimTicket) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrInvalidRevocationRequest
}

// Discard destroys any sensitive claim material that has not already been
// transferred by FinalizeRevocationClaimAfterCommit. It is safe to call more
// than once and on a nil ticket.
func (ticket *RunnerRevocationClaimTicket) Discard() {
	if ticket == nil {
		return
	}
	ticket.mu.Lock()
	defer ticket.mu.Unlock()
	ticket.destroyLocked()
}

func (ticket *RunnerRevocationClaimTicket) destroyLocked() {
	if ticket.accessor != nil {
		ticket.accessor.Destroy()
	}
	ticket.accessor = nil
	ticket.rawToken = ""
	ticket.revocation = credential.Revocation{}
	ticket.claimTokenSHA256 = ""
	ticket.certificateSHA256 = ""
	ticket.consumed = true
}

// ClaimRevocationRunnerTx claims at most one eligible revocation for exactly
// 30 seconds. scope and certificateSHA256 must come from authentication in the
// same caller-owned transaction. No raw claim token or accessor leaves this
// method; the returned ticket must be finalized only after a successful,
// unambiguous caller commit.
func (repository *Repository) ClaimRevocationRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	certificateSHA256 string,
) (*RunnerRevocationClaimTicket, error) {
	if err := validateRunnerCredentialCall(ctx, tx, scope); err != nil {
		return nil, err
	}
	if !credential.ValidSHA256(certificateSHA256) {
		return nil, credential.ErrInvalidRevocationRequest
	}
	if err := lockCurrentRunnerRevocationPrincipal(ctx, tx, scope, certificateSHA256); err != nil {
		return nil, err
	}

	bindings := scope.Bindings()
	workspaceIDs := make([]string, len(bindings))
	environmentIDs := make([]string, len(bindings))
	for index, binding := range bindings {
		workspaceIDs[index] = binding.WorkspaceID
		environmentIDs[index] = binding.EnvironmentID
	}

	var revocationID string
	err := tx.QueryRow(ctx, `
		WITH exact_scope(workspace_id, environment_id) AS (
			SELECT * FROM unnest($3::text[], $4::text[])
		)
		SELECT candidate.revocation_id::text
		FROM credential_revocations AS candidate
		JOIN exact_scope AS allowed
		  ON allowed.workspace_id = candidate.workspace_id::text
		 AND allowed.environment_id = candidate.environment_id::text
		JOIN runner_scope_bindings AS binding
		  ON binding.runner_id = $1
		 AND binding.tenant_id = candidate.tenant_id
		 AND binding.workspace_id = candidate.workspace_id
		 AND binding.environment_id = candidate.environment_id
		WHERE candidate.tenant_id = $2::uuid
		  AND (
			(candidate.status = 'REVOCATION_PENDING' AND candidate.available_at <= clock_timestamp())
			OR (candidate.status = 'REVOKING' AND candidate.claim_expires_at <= clock_timestamp())
		  )
		  AND candidate.attempt - candidate.retry_cycle_attempt_base < $5
		  AND candidate.retry_cycle_started_at >
			clock_timestamp() - make_interval(secs => $6::double precision)
		ORDER BY candidate.available_at, candidate.created_at, candidate.revocation_id
		FOR UPDATE OF candidate SKIP LOCKED
		LIMIT 1
	`, scope.RunnerID(), scope.TenantID(), workspaceIDs, environmentIDs,
		credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds()).Scan(&revocationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, databaseError("select authenticated Runner credential revocation claim", err)
	}

	rawToken, err := repository.tokenSource()
	if err != nil || !validRunnerRevocationRawToken(rawToken) {
		return nil, credential.ErrRevocationPersistence
	}
	tokenDigest := credential.SHA256Hex([]byte(rawToken))
	record, err := selectStored(ctx, tx, `
		WITH claim_boundary AS (
			SELECT clock_timestamp() AS claimed_at
		)
		UPDATE credential_revocations AS candidate
		SET status = 'REVOKING', claim_epoch = candidate.claim_epoch + 1,
			claimed_by = $2, claim_token_sha256 = $3,
			claimed_at = claim_boundary.claimed_at, last_heartbeat_at = claim_boundary.claimed_at,
			claim_expires_at = claim_boundary.claimed_at + interval '30 seconds',
			heartbeat_seq = 0, attempt = candidate.attempt + 1,
			updated_at = claim_boundary.claimed_at, version = candidate.version + 1
		FROM claim_boundary
		WHERE candidate.revocation_id = $1::uuid
		  AND candidate.tenant_id = $4::uuid
		  AND candidate.claim_epoch < 9223372036854775807
		  AND (
			(candidate.status = 'REVOCATION_PENDING' AND candidate.available_at <= clock_timestamp())
			OR (candidate.status = 'REVOKING' AND candidate.claim_expires_at <= clock_timestamp())
		  )
		  AND candidate.attempt - candidate.retry_cycle_attempt_base < $5
		  AND candidate.retry_cycle_started_at >
			clock_timestamp() - make_interval(secs => $6::double precision)
		  AND EXISTS (
			SELECT 1 FROM runner_registrations AS registration
			WHERE registration.runner_id = $2
			  AND registration.tenant_id = candidate.tenant_id
			  AND registration.enabled = true
			  AND registration.runner_pool = 'WRITE'
			  AND registration.credential_revocation_capable = true
			  AND registration.scope_revision = $7
		  )
		  AND EXISTS (
			SELECT 1 FROM runner_scope_bindings AS binding
			WHERE binding.runner_id = $2
			  AND binding.tenant_id = candidate.tenant_id
			  AND binding.workspace_id = candidate.workspace_id
			  AND binding.environment_id = candidate.environment_id
		  )
		  AND EXISTS (
			SELECT 1 FROM runner_certificates AS certificate
			WHERE certificate.runner_id = $2
			  AND certificate.tenant_id = candidate.tenant_id
			  AND certificate.certificate_sha256 = $8
			  AND certificate.status = 'ACTIVE'
			  AND certificate.not_before <= statement_timestamp()
			  AND certificate.not_after > statement_timestamp()
		  )
		RETURNING `+revocationProjection,
		revocationID, scope.RunnerID(), tokenDigest, scope.TenantID(),
		credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds(),
		scope.ScopeRevision(), certificateSHA256)
	if err != nil {
		return nil, mapTransitionError("claim authenticated Runner credential revocation", err)
	}
	if record.revocation.ClaimEpoch <= 0 || record.revocation.ClaimedBy != scope.RunnerID() ||
		record.claimTokenSHA256 != tokenDigest || record.revocation.TenantID != scope.TenantID() ||
		!runnerScopeAllowsPair(scope, record.revocation.WorkspaceID, record.revocation.EnvironmentID) {
		return nil, credential.ErrStaleClaim
	}
	var heartbeatSequence int64
	if err := tx.QueryRow(ctx, `
		SELECT heartbeat_seq FROM credential_revocations
		WHERE revocation_id = $1::uuid
	`, revocationID).Scan(&heartbeatSequence); err != nil {
		return nil, databaseError("read authenticated Runner credential revocation heartbeat sequence", err)
	}
	if heartbeatSequence != 0 {
		return nil, credential.ErrRevocationPersistence
	}
	if err := writeStateChange(ctx, tx, record.revocation, "RUNNER", scope.RunnerID(),
		"credential.revocation.claimed", "credential.revocation.claimed.v1"); err != nil {
		return nil, err
	}

	accessor, openErr := repository.protector.Unprotect(referenceContext(record.revocation), record.protected)
	if openErr != nil || !credential.ValidSensitiveReference(accessor) {
		if accessor != nil {
			accessor.Destroy()
		}
		alert := record.revocation
		alert.FailureCode = credential.FailureInvalidReference
		alert.FailureDetailSHA256 = credential.SHA256Hex([]byte(credential.FailureDetailProtectedRefInvalid))
		if err := writeStateChange(ctx, tx, alert, "RUNNER", scope.RunnerID(),
			"credential.revocation.protected_reference_unavailable",
			"credential.revocation.protected_reference_unavailable.v1"); err != nil {
			return nil, err
		}
		// The active claim deliberately remains REVOKING. Database-owned expiry
		// and exhaustion recovery are the only allowed quarantine path.
		return nil, nil
	}

	return &RunnerRevocationClaimTicket{
		owner: repository, rawToken: rawToken, accessor: accessor,
		revocation: record.revocation, runnerID: scope.RunnerID(), tenantID: scope.TenantID(),
		workspaceID: record.revocation.WorkspaceID, environmentID: record.revocation.EnvironmentID,
		scopeRevision: scope.ScopeRevision(), certificateSHA256: certificateSHA256,
		claimEpoch: record.revocation.ClaimEpoch, claimTokenSHA256: tokenDigest,
	}, nil
}

// FinalizeRevocationClaimAfterCommit verifies that the caller's claim is
// durably visible and that the original authenticated identity remains current
// before releasing its one-use bearer and accessor. Every attempt consumes the
// ticket, including cross-repository, rolled-back, expired, and failed commits.
func (repository *Repository) FinalizeRevocationClaimAfterCommit(
	ctx context.Context,
	ticket *RunnerRevocationClaimTicket,
) (credential.ClaimedRevocation, error) {
	if repository == nil || ctx == nil || ticket == nil {
		return credential.ClaimedRevocation{}, credential.ErrInvalidRevocationRequest
	}
	if err := ctx.Err(); err != nil {
		return credential.ClaimedRevocation{}, err
	}

	ticket.mu.Lock()
	defer ticket.mu.Unlock()
	if ticket.consumed || ticket.owner != repository || ticket.accessor == nil ||
		!credential.ValidSensitiveReference(ticket.accessor) ||
		!validRunnerRevocationRawToken(ticket.rawToken) ||
		!credential.ValidSHA256(ticket.claimTokenSHA256) ||
		!credential.ValidSHA256(ticket.certificateSHA256) ||
		!credential.ValidRevocationID(ticket.revocation.ID) || ticket.claimEpoch <= 0 {
		ticket.destroyLocked()
		return credential.ClaimedRevocation{}, credential.ErrInvalidRevocationRequest
	}
	// A same-owner attempt is one-use even when the database check fails.
	ticket.consumed = true

	tx, err := repository.database.Begin(ctx)
	if err != nil {
		ticket.destroyLocked()
		return credential.ClaimedRevocation{}, databaseError("begin authenticated Runner revocation claim finalization", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := lockCurrentRunnerRevocationBinding(ctx, tx, ticket.runnerID, ticket.tenantID,
		ticket.workspaceID, ticket.environmentID, ticket.scopeRevision, ticket.certificateSHA256); err != nil {
		ticket.destroyLocked()
		return credential.ClaimedRevocation{}, err
	}

	record, err := selectStored(ctx, tx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE revocation_id = $1::uuid
		  AND tenant_id = $2::uuid
		  AND workspace_id = $3::uuid
		  AND environment_id = $4::uuid
		  AND status = 'REVOKING'
		  AND claim_epoch = $5
		  AND claimed_by = $6
		  AND claim_token_sha256 = $7
		  AND claim_expires_at > statement_timestamp()
		FOR SHARE
	`, ticket.revocation.ID, ticket.tenantID, ticket.workspaceID, ticket.environmentID,
		ticket.claimEpoch, ticket.runnerID, ticket.claimTokenSHA256)
	if errors.Is(err, pgx.ErrNoRows) {
		ticket.destroyLocked()
		return credential.ClaimedRevocation{}, credential.ErrStaleClaim
	}
	if err != nil {
		ticket.destroyLocked()
		return credential.ClaimedRevocation{}, databaseError("verify committed authenticated Runner revocation claim", err)
	}
	if !sameRunnerRevocationTicketRecord(ticket, record) {
		ticket.destroyLocked()
		return credential.ClaimedRevocation{}, credential.ErrStaleClaim
	}
	var heartbeatSequence int64
	var initialHeartbeat, canonicalExpiry bool
	if err := tx.QueryRow(ctx, `
		SELECT heartbeat_seq,
			last_heartbeat_at IS NOT DISTINCT FROM claimed_at,
			claim_expires_at IS NOT DISTINCT FROM claimed_at + interval '30 seconds'
		FROM credential_revocations
		WHERE revocation_id = $1::uuid
	`, ticket.revocation.ID).Scan(&heartbeatSequence, &initialHeartbeat, &canonicalExpiry); err != nil {
		ticket.destroyLocked()
		return credential.ClaimedRevocation{}, databaseError("verify initial authenticated Runner revocation claim", err)
	}
	if heartbeatSequence != 0 || !initialHeartbeat || !canonicalExpiry {
		ticket.destroyLocked()
		return credential.ClaimedRevocation{}, credential.ErrStaleClaim
	}
	if err := tx.Commit(ctx); err != nil {
		ticket.destroyLocked()
		return credential.ClaimedRevocation{}, databaseError("commit authenticated Runner revocation claim finalization", err)
	}
	committed = true

	claim := credential.ClaimedRevocation{
		Revocation: publicRevocation(record),
		Fence: credential.ClaimFence{
			RevocationID: record.revocation.ID, WorkerID: ticket.runnerID,
			Token: ticket.rawToken, Epoch: ticket.claimEpoch,
		},
		Accessor: ticket.accessor,
	}
	ticket.accessor = nil
	ticket.rawToken = ""
	ticket.revocation = credential.Revocation{}
	ticket.claimTokenSHA256 = ""
	ticket.certificateSHA256 = ""
	return claim, nil
}

func sameRunnerRevocationTicketRecord(ticket *RunnerRevocationClaimTicket, record *storedRevocation) bool {
	return record != nil && record.revocation.ID == ticket.revocation.ID &&
		record.revocation.TenantID == ticket.tenantID &&
		record.revocation.WorkspaceID == ticket.workspaceID &&
		record.revocation.EnvironmentID == ticket.environmentID &&
		record.revocation.ClaimedBy == ticket.runnerID &&
		record.revocation.ClaimEpoch == ticket.claimEpoch &&
		record.claimTokenSHA256 == ticket.claimTokenSHA256 &&
		record.revocation.Issuer == ticket.revocation.Issuer &&
		record.revocation.IssuerRevision == ticket.revocation.IssuerRevision
}

func lockCurrentRunnerRevocationPrincipal(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	certificateSHA256 string,
) error {
	return lockCurrentRunnerRevocationBinding(ctx, tx, scope.RunnerID(), scope.TenantID(),
		"", "", scope.ScopeRevision(), certificateSHA256)
}

func lockCurrentRunnerRevocationBinding(
	ctx context.Context,
	tx pgx.Tx,
	runnerID, tenantID, workspaceID, environmentID string,
	scopeRevision int64,
	certificateSHA256 string,
) error {
	var lockedRunnerID string
	err := tx.QueryRow(ctx, `
		SELECT registration.runner_id
		FROM runner_registrations AS registration
		WHERE registration.runner_id = $1
		  AND registration.tenant_id = $2::uuid
		  AND registration.enabled = true
		  AND registration.runner_pool = 'WRITE'
		  AND registration.credential_revocation_capable = true
		  AND registration.scope_revision = $3
		FOR SHARE OF registration
	`, runnerID, tenantID, scopeRevision).Scan(&lockedRunnerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.ErrStaleClaim
	}
	if err != nil {
		return databaseError("lock authenticated credential revocation Runner", err)
	}
	if lockedRunnerID != runnerID {
		return credential.ErrStaleClaim
	}
	var lockedCertificateRunnerID string
	err = tx.QueryRow(ctx, `
		SELECT certificate.runner_id
		FROM runner_certificates AS certificate
		WHERE certificate.runner_id = $1
		  AND certificate.tenant_id = $2::uuid
		  AND certificate.certificate_sha256 = $3
		  AND certificate.status = 'ACTIVE'
		  AND certificate.not_before <= statement_timestamp()
		  AND certificate.not_after > statement_timestamp()
		FOR SHARE OF certificate
	`, runnerID, tenantID, certificateSHA256).Scan(&lockedCertificateRunnerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.ErrStaleClaim
	}
	if err != nil {
		return databaseError("lock authenticated credential revocation Runner certificate", err)
	}
	if lockedCertificateRunnerID != runnerID {
		return credential.ErrStaleClaim
	}
	if workspaceID == "" && environmentID == "" {
		return nil
	}
	var lockedWorkspaceID, lockedEnvironmentID string
	err = tx.QueryRow(ctx, `
		SELECT binding.workspace_id::text, binding.environment_id::text
		FROM runner_scope_bindings AS binding
		WHERE binding.runner_id = $1
		  AND binding.tenant_id = $2::uuid
		  AND binding.workspace_id = $3::uuid
		  AND binding.environment_id = $4::uuid
		FOR SHARE OF binding
	`, runnerID, tenantID, workspaceID, environmentID).Scan(&lockedWorkspaceID, &lockedEnvironmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.ErrStaleClaim
	}
	if err != nil {
		return databaseError("lock authenticated credential revocation exact scope binding", err)
	}
	if lockedWorkspaceID != workspaceID || lockedEnvironmentID != environmentID {
		return credential.ErrStaleClaim
	}
	return nil
}

// Keep the compiler checking the intentionally hostile wire behavior.
var _ json.Marshaler = (*RunnerRevocationClaimTicket)(nil)

// Constant-time digest comparison is kept in one helper for the heartbeat and
// completion implementations below.
func runnerRevocationTokenMatches(stored, raw string) bool {
	if stored == "" || !validRunnerRevocationRawToken(raw) {
		return false
	}
	digest := credential.SHA256Hex([]byte(raw))
	return subtle.ConstantTimeCompare([]byte(stored), []byte(digest)) == 1
}

func validRunnerRevocationRawToken(token string) bool {
	return runnerRevocationRawTokenPattern.MatchString(token)
}

// HeartbeatRevocationRunnerTx applies a strictly monotonic heartbeat using
// the database-enforced 30 second extension. A replay returns the current
// evidence without extending it. Losing the current capability or exact scope
// returns TERMINATE and deliberately performs no parent update.
func (repository *Repository) HeartbeatRevocationRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	fence credential.ClaimFence,
	sequence int64,
) (credential.RunnerRevocationHeartbeatResult, error) {
	if err := validateRunnerCredentialCall(ctx, tx, scope); err != nil {
		return credential.RunnerRevocationHeartbeatResult{}, err
	}
	if !credential.ValidClaimFence(fence) || !validRunnerRevocationRawToken(fence.Token) ||
		fence.WorkerID != scope.RunnerID() || sequence <= 0 {
		return credential.RunnerRevocationHeartbeatResult{}, credential.ErrInvalidRevocationRequest
	}
	tenantID, workspaceID, environmentID, err := peekRunnerRevocationScope(ctx, tx, fence.RevocationID)
	if err != nil {
		return credential.RunnerRevocationHeartbeatResult{}, err
	}
	if tenantID != scope.TenantID() {
		return credential.RunnerRevocationHeartbeatResult{}, credential.ErrStaleClaim
	}
	scopeCurrent, err := lockCurrentRunnerRevocationScope(ctx, tx, scope, workspaceID, environmentID)
	if err != nil {
		return credential.RunnerRevocationHeartbeatResult{}, err
	}
	record, currentSequence, claimCurrent, err := lockRunnerRevocationClaim(ctx, tx, fence)
	if err != nil {
		return credential.RunnerRevocationHeartbeatResult{}, err
	}
	if err := validateRunnerRevocationFence(record, scope, fence, claimCurrent); err != nil {
		return credential.RunnerRevocationHeartbeatResult{}, err
	}
	if record.revocation.WorkspaceID != workspaceID || record.revocation.EnvironmentID != environmentID {
		return credential.RunnerRevocationHeartbeatResult{}, credential.ErrStaleClaim
	}
	if sequence != currentSequence && sequence != currentSequence+1 {
		return credential.RunnerRevocationHeartbeatResult{}, execution.ErrHeartbeatSequence
	}
	if !scopeCurrent {
		return runnerRevocationHeartbeatResult(record, sequence, credential.RunnerRevocationTerminate), nil
	}
	if sequence == currentSequence {
		return runnerRevocationHeartbeatResult(record, currentSequence, credential.RunnerRevocationContinue), nil
	}

	updated, err := selectStored(ctx, tx, `
		UPDATE credential_revocations AS revocation
		SET heartbeat_seq = $5, updated_at = clock_timestamp(), version = revocation.version + 1
		WHERE revocation.revocation_id = $1::uuid
		  AND revocation.claimed_by = $2
		  AND revocation.claim_token_sha256 = $3
		  AND revocation.claim_epoch = $4
		  AND revocation.status = 'REVOKING'
		  AND revocation.claim_expires_at > statement_timestamp()
		  AND revocation.heartbeat_seq + 1 = $5
		  AND revocation.tenant_id = $6::uuid
		  AND revocation.workspace_id = $7::uuid
		  AND revocation.environment_id = $8::uuid
		  AND EXISTS (
			SELECT 1 FROM runner_registrations AS registration
			WHERE registration.runner_id = $2
			  AND registration.tenant_id = revocation.tenant_id
			  AND registration.enabled = true
			  AND registration.runner_pool = 'WRITE'
			  AND registration.credential_revocation_capable = true
			  AND registration.scope_revision = $9
		  )
		  AND EXISTS (
			SELECT 1 FROM runner_scope_bindings AS binding
			WHERE binding.runner_id = $2
			  AND binding.tenant_id = revocation.tenant_id
			  AND binding.workspace_id = revocation.workspace_id
			  AND binding.environment_id = revocation.environment_id
		  )
		RETURNING `+revocationProjection,
		fence.RevocationID, fence.WorkerID, credential.SHA256Hex([]byte(fence.Token)), fence.Epoch,
		sequence, scope.TenantID(), record.revocation.WorkspaceID, record.revocation.EnvironmentID,
		scope.ScopeRevision())
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.RunnerRevocationHeartbeatResult{}, credential.ErrStaleClaim
	}
	if err != nil {
		return credential.RunnerRevocationHeartbeatResult{}, databaseError("heartbeat authenticated Runner credential revocation", err)
	}
	return runnerRevocationHeartbeatResult(updated, sequence, credential.RunnerRevocationContinue), nil
}

// CompleteRevocationRunnerTx persists the immutable Runner receipt before it
// mutates the parent. Both writes remain in the caller-owned transaction, and
// the migration's deferred constraint proves their final committed shape.
func (repository *Repository) CompleteRevocationRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	fence credential.ClaimFence,
	outcome credential.RunnerRevocationOutcome,
	failureCode credential.FailureCode,
	certificateSHA256 string,
) (credential.RunnerRevocationCompletionResult, error) {
	if err := validateRunnerCredentialCall(ctx, tx, scope); err != nil {
		return credential.RunnerRevocationCompletionResult{}, err
	}
	if !credential.ValidClaimFence(fence) || !validRunnerRevocationRawToken(fence.Token) ||
		fence.WorkerID != scope.RunnerID() ||
		!credential.ValidSHA256(certificateSHA256) || !validRunnerRevocationCompletion(outcome, failureCode) {
		return credential.RunnerRevocationCompletionResult{}, credential.ErrInvalidRevocationRequest
	}
	tenantID, workspaceID, environmentID, err := peekRunnerRevocationScope(ctx, tx, fence.RevocationID)
	if err != nil {
		return credential.RunnerRevocationCompletionResult{}, err
	}
	if tenantID != scope.TenantID() || !runnerScopeAllowsPair(scope, workspaceID, environmentID) {
		return credential.RunnerRevocationCompletionResult{}, credential.ErrStaleClaim
	}
	if err := lockCurrentRunnerRevocationBinding(ctx, tx, scope.RunnerID(), scope.TenantID(),
		workspaceID, environmentID, scope.ScopeRevision(), certificateSHA256); err != nil {
		return credential.RunnerRevocationCompletionResult{}, err
	}
	record, currentSequence, claimCurrent, err := lockRunnerRevocationClaim(ctx, tx, fence)
	if err != nil {
		return credential.RunnerRevocationCompletionResult{}, err
	}
	if !runnerRevocationRecordIdentifiedByScope(record, scope) ||
		record.revocation.WorkspaceID != workspaceID || record.revocation.EnvironmentID != environmentID {
		return credential.RunnerRevocationCompletionResult{}, credential.ErrStaleClaim
	}
	completion := credential.RunnerRevocationCompletion{
		ClaimEpoch: fence.Epoch, Outcome: outcome, FailureCode: failureCode,
	}
	if record.revocation.Status != credential.StatusRevoking {
		return repository.idempotentRunnerRevocationCompletion(ctx, tx, scope, fence, completion,
			certificateSHA256, record)
	}
	if err := validateRunnerRevocationFence(record, scope, fence, claimCurrent); err != nil {
		return credential.RunnerRevocationCompletionResult{}, err
	}

	databaseNow, err := databaseClockTime(ctx, tx)
	if err != nil {
		return credential.RunnerRevocationCompletionResult{}, err
	}
	claim := credential.RunnerRevocationClaim{
		Revocation: record.revocation, RunnerID: scope.RunnerID(), ScopeRevision: scope.ScopeRevision(),
		CertificateSHA256: certificateSHA256, ClaimTokenSHA256: record.claimTokenSHA256,
		HeartbeatSequence: currentSequence,
	}
	receipt, err := credential.BuildRunnerRevocationReceiptV1(claim, completion, databaseNow)
	if err != nil {
		return credential.RunnerRevocationCompletionResult{}, err
	}

	var receivedAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO credential_revocation_receipts (
			revocation_id, claim_epoch, tenant_id, workspace_id, environment_id,
			runner_id, scope_revision, certificate_sha256, issuer, issuer_revision,
			claim_token_sha256, heartbeat_seq, outcome, failure_count, failure_code,
			failure_detail_sha256, receipt_hash, schema_version
		) VALUES (
			$1::uuid, $2, $3::uuid, $4::uuid, $5::uuid,
			$6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
			'credential-revocation-result.v1'
		)
		ON CONFLICT (revocation_id, claim_epoch) DO NOTHING
		RETURNING received_at
	`, receipt.RevocationID, receipt.ClaimEpoch, receipt.TenantID, receipt.WorkspaceID, receipt.EnvironmentID,
		receipt.RunnerID, receipt.ScopeRevision, receipt.CertificateSHA256, receipt.Issuer, receipt.IssuerRevision,
		receipt.ClaimTokenSHA256, receipt.HeartbeatSequence, string(receipt.Outcome),
		nullableRunnerFailureCount(receipt), nullableRunnerFailureCode(receipt),
		nullableRunnerFailureDetail(receipt), receipt.ReceiptHash).Scan(&receivedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.conflictingActiveRunnerRevocationReceipt(ctx, tx, scope, fence, completion,
			certificateSHA256, record)
	}
	if err != nil {
		return credential.RunnerRevocationCompletionResult{}, databaseError("insert authenticated Runner credential revocation receipt", err)
	}
	receipt.ReceivedAt = receivedAt.UTC()
	transitionAt := receipt.ReceivedAt

	var retryDelay time.Duration
	var auditAction, eventType string
	if outcome == credential.RunnerRevocationRevoked {
		record, err = selectStored(ctx, tx, `
			UPDATE credential_revocations AS revocation
			SET status = 'REVOKED',
				completed_claim_epoch = revocation.claim_epoch,
				completed_claim_token_sha256 = revocation.claim_token_sha256,
				completed_claimed_by = revocation.claimed_by,
				claimed_by = NULL, claim_token_sha256 = NULL, claimed_at = NULL,
				claim_expires_at = NULL, last_heartbeat_at = NULL,
				accessor_ciphertext = NULL, encryption_key_id = NULL,
				revoked_at = $5::timestamptz, updated_at = $5::timestamptz,
				version = revocation.version + 1
			WHERE revocation.revocation_id = $1::uuid
			  AND revocation.claimed_by = $2
			  AND revocation.claim_token_sha256 = $3
			  AND revocation.claim_epoch = $4
			  AND revocation.status = 'REVOKING'
			  AND revocation.claim_expires_at > $5::timestamptz
			RETURNING `+revocationProjection,
			fence.RevocationID, fence.WorkerID, receipt.ClaimTokenSHA256, fence.Epoch, transitionAt)
		auditAction, eventType = "credential.revocation.completed", "credential.revocation.completed.v1"
	} else {
		retryDelay = credential.FullJitterRevocationRetryDelay(record.revocation.Attempt, cryptorand.Reader)
		record, err = selectStored(ctx, tx, `
			UPDATE credential_revocations AS revocation
			SET status = CASE
					WHEN revocation.attempt - revocation.retry_cycle_attempt_base >= $8
					  OR revocation.retry_cycle_started_at <= $10::timestamptz - make_interval(secs => $9::double precision)
					THEN 'MANUAL_REQUIRED'
					ELSE 'REVOCATION_PENDING'
				END,
				claimed_by = NULL, claim_token_sha256 = NULL, claimed_at = NULL,
				claim_expires_at = NULL, last_heartbeat_at = NULL,
				failure_count = $5, failure_code = $6, failure_detail_sha256 = $7,
				available_at = CASE
					WHEN revocation.attempt - revocation.retry_cycle_attempt_base >= $8
					  OR revocation.retry_cycle_started_at <= $10::timestamptz - make_interval(secs => $9::double precision)
					THEN revocation.available_at
					ELSE $10::timestamptz + make_interval(secs => $11::double precision)
				END,
				manual_required_at = CASE
					WHEN revocation.attempt - revocation.retry_cycle_attempt_base >= $8
					  OR revocation.retry_cycle_started_at <= $10::timestamptz - make_interval(secs => $9::double precision)
					THEN $10::timestamptz
					ELSE revocation.manual_required_at
				END,
				updated_at = $10::timestamptz, version = revocation.version + 1
			WHERE revocation.revocation_id = $1::uuid
			  AND revocation.claimed_by = $2
			  AND revocation.claim_token_sha256 = $3
			  AND revocation.claim_epoch = $4
			  AND revocation.status = 'REVOKING'
			  AND revocation.claim_expires_at > $10::timestamptz
			RETURNING `+revocationProjection,
			fence.RevocationID, fence.WorkerID, receipt.ClaimTokenSHA256, fence.Epoch,
			receipt.FailureCount, string(receipt.FailureCode), receipt.FailureDetailSHA256,
			credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds(), transitionAt, retryDelay.Seconds())
		auditAction, eventType = "credential.revocation.failed", "credential.revocation.failed.v1"
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.RunnerRevocationCompletionResult{}, credential.ErrStaleClaim
	}
	if err != nil {
		return credential.RunnerRevocationCompletionResult{}, databaseError("complete authenticated Runner credential revocation", err)
	}
	if outcome == credential.RunnerRevocationFailed && record.revocation.Status == credential.StatusManualRequired {
		retryDelay = 0
		auditAction, eventType = "credential.revocation.manual_required", "credential.revocation.manual_required.v1"
	}
	if err := writeStateChange(ctx, tx, record.revocation, "RUNNER", scope.RunnerID(), auditAction, eventType); err != nil {
		return credential.RunnerRevocationCompletionResult{}, err
	}
	return credential.RunnerRevocationCompletionResult{
		Revocation: publicRevocation(record), Receipt: receipt, RetryDelay: retryDelay,
	}, nil
}

func lockRunnerRevocationClaim(
	ctx context.Context,
	tx pgx.Tx,
	fence credential.ClaimFence,
) (*storedRevocation, int64, bool, error) {
	record, err := selectStored(ctx, tx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE revocation_id = $1::uuid
		FOR UPDATE
	`, fence.RevocationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, false, credential.ErrRevocationNotFound
	}
	if err != nil {
		return nil, 0, false, databaseError("lock authenticated Runner credential revocation claim", err)
	}
	var heartbeatSequence int64
	var claimCurrent bool
	if err := tx.QueryRow(ctx, `
		SELECT heartbeat_seq, COALESCE(claim_expires_at > statement_timestamp(), false)
		FROM credential_revocations
		WHERE revocation_id = $1::uuid
	`, fence.RevocationID).Scan(&heartbeatSequence, &claimCurrent); err != nil {
		return nil, 0, false, databaseError("read authenticated Runner credential revocation claim boundary", err)
	}
	return record, heartbeatSequence, claimCurrent, nil
}

func peekRunnerRevocationScope(
	ctx context.Context,
	tx pgx.Tx,
	revocationID string,
) (string, string, string, error) {
	var tenantID, workspaceID, environmentID string
	err := tx.QueryRow(ctx, `
		SELECT tenant_id::text, workspace_id::text, environment_id::text
		FROM credential_revocations
		WHERE revocation_id = $1::uuid
	`, revocationID).Scan(&tenantID, &workspaceID, &environmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", credential.ErrRevocationNotFound
	}
	if err != nil {
		return "", "", "", databaseError("read authenticated Runner credential revocation scope", err)
	}
	return tenantID, workspaceID, environmentID, nil
}

func validateRunnerRevocationFence(
	record *storedRevocation,
	scope execution.RunnerScope,
	fence credential.ClaimFence,
	claimCurrent bool,
) error {
	if record == nil || record.revocation.Status != credential.StatusRevoking || !claimCurrent ||
		record.revocation.ClaimEpoch != fence.Epoch || record.revocation.ClaimedBy != fence.WorkerID ||
		fence.WorkerID != scope.RunnerID() || !runnerRevocationTokenMatches(record.claimTokenSHA256, fence.Token) ||
		record.revocation.TenantID != scope.TenantID() {
		return credential.ErrStaleClaim
	}
	return nil
}

func runnerRevocationRecordIdentifiedByScope(record *storedRevocation, scope execution.RunnerScope) bool {
	return record != nil && record.revocation.TenantID == scope.TenantID() &&
		runnerScopeAllowsPair(scope, record.revocation.WorkspaceID, record.revocation.EnvironmentID)
}

func lockCurrentRunnerRevocationScope(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	workspaceID, environmentID string,
) (bool, error) {
	var runnerID string
	err := tx.QueryRow(ctx, `
		SELECT registration.runner_id
		FROM runner_registrations AS registration
		WHERE registration.runner_id = $1
		  AND registration.tenant_id = $2::uuid
		  AND registration.enabled = true
		  AND registration.runner_pool = 'WRITE'
		  AND registration.credential_revocation_capable = true
		  AND registration.scope_revision = $3
		FOR SHARE OF registration
	`, scope.RunnerID(), scope.TenantID(), scope.ScopeRevision()).Scan(&runnerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, databaseError("lock authenticated credential revocation Runner scope", err)
	}
	if runnerID != scope.RunnerID() {
		return false, nil
	}
	var lockedWorkspaceID, lockedEnvironmentID string
	err = tx.QueryRow(ctx, `
		SELECT binding.workspace_id::text, binding.environment_id::text
		FROM runner_scope_bindings AS binding
		WHERE binding.runner_id = $1
		  AND binding.tenant_id = $2::uuid
		  AND binding.workspace_id = $3::uuid
		  AND binding.environment_id = $4::uuid
		FOR SHARE OF binding
	`, scope.RunnerID(), scope.TenantID(), workspaceID, environmentID).Scan(&lockedWorkspaceID, &lockedEnvironmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, databaseError("lock authenticated credential revocation exact scope", err)
	}
	return lockedWorkspaceID == workspaceID && lockedEnvironmentID == environmentID, nil
}

func runnerRevocationHeartbeatResult(
	record *storedRevocation,
	sequence int64,
	directive credential.RunnerRevocationHeartbeatDirective,
) credential.RunnerRevocationHeartbeatResult {
	return credential.RunnerRevocationHeartbeatResult{
		RevocationID: record.revocation.ID, ClaimEpoch: record.revocation.ClaimEpoch,
		AcceptedSequence: sequence, Directive: directive,
		ClaimExpiresAt: record.revocation.ClaimExpiresAt,
	}
}

func validRunnerRevocationCompletion(outcome credential.RunnerRevocationOutcome, code credential.FailureCode) bool {
	return outcome == credential.RunnerRevocationRevoked && code == "" ||
		outcome == credential.RunnerRevocationFailed && credential.ValidFailureCode(code)
}

func nullableRunnerFailureCount(receipt credential.RunnerRevocationReceipt) any {
	if receipt.Outcome != credential.RunnerRevocationFailed {
		return nil
	}
	return receipt.FailureCount
}

func nullableRunnerFailureCode(receipt credential.RunnerRevocationReceipt) any {
	if receipt.Outcome != credential.RunnerRevocationFailed {
		return nil
	}
	return string(receipt.FailureCode)
}

func nullableRunnerFailureDetail(receipt credential.RunnerRevocationReceipt) any {
	if receipt.Outcome != credential.RunnerRevocationFailed {
		return nil
	}
	return receipt.FailureDetailSHA256
}

func (repository *Repository) idempotentRunnerRevocationCompletion(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	fence credential.ClaimFence,
	completion credential.RunnerRevocationCompletion,
	certificateSHA256 string,
	record *storedRevocation,
) (credential.RunnerRevocationCompletionResult, error) {
	receipt, err := readRunnerRevocationReceipt(ctx, tx, fence.RevocationID, fence.Epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.RunnerRevocationCompletionResult{}, credential.ErrStaleClaim
	}
	if err != nil {
		return credential.RunnerRevocationCompletionResult{}, databaseError("read idempotent Runner credential revocation receipt", err)
	}
	receipt.ActionID = record.revocation.ActionID
	if receipt.ClaimEpoch != fence.Epoch || receipt.RunnerID != fence.WorkerID ||
		receipt.ClaimTokenSHA256 != credential.SHA256Hex([]byte(fence.Token)) {
		return credential.RunnerRevocationCompletionResult{}, credential.ErrStaleClaim
	}
	if err := validateIdempotentRunnerRevocationReceipt(record, scope, fence, completion, certificateSHA256, receipt); err != nil {
		return credential.RunnerRevocationCompletionResult{}, err
	}
	return credential.RunnerRevocationCompletionResult{Revocation: publicRevocation(record), Receipt: receipt}, nil
}

func (repository *Repository) conflictingActiveRunnerRevocationReceipt(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	fence credential.ClaimFence,
	completion credential.RunnerRevocationCompletion,
	certificateSHA256 string,
	record *storedRevocation,
) (credential.RunnerRevocationCompletionResult, error) {
	receipt, err := readRunnerRevocationReceipt(ctx, tx, fence.RevocationID, fence.Epoch)
	if err != nil {
		return credential.RunnerRevocationCompletionResult{}, credential.ErrCompletionConflict
	}
	receipt.ActionID = record.revocation.ActionID
	// A committed receipt cannot legitimately have an active parent because
	// the final-shape trigger is deferred to its transaction commit. Treat even
	// an otherwise identical row as a conflict instead of trusting partial data.
	if validateIdempotentRunnerRevocationReceipt(record, scope, fence, completion, certificateSHA256, receipt) == nil {
		return credential.RunnerRevocationCompletionResult{}, credential.ErrCompletionConflict
	}
	return credential.RunnerRevocationCompletionResult{}, credential.ErrCompletionConflict
}

func readRunnerRevocationReceipt(
	ctx context.Context,
	tx pgx.Tx,
	revocationID string,
	claimEpoch int64,
) (credential.RunnerRevocationReceipt, error) {
	var receipt credential.RunnerRevocationReceipt
	var outcome string
	var failureCount *int
	var failureCode, failureDetail *string
	err := tx.QueryRow(ctx, `
		SELECT schema_version, revocation_id::text, tenant_id::text, workspace_id::text,
			environment_id::text, runner_id, scope_revision, certificate_sha256,
			issuer, issuer_revision, claim_epoch, heartbeat_seq, claim_token_sha256,
			outcome, failure_count, failure_code, failure_detail_sha256, receipt_hash, received_at
		FROM credential_revocation_receipts
		WHERE revocation_id = $1::uuid AND claim_epoch = $2
	`, revocationID, claimEpoch).Scan(
		&receipt.SchemaVersion, &receipt.RevocationID, &receipt.TenantID, &receipt.WorkspaceID,
		&receipt.EnvironmentID, &receipt.RunnerID, &receipt.ScopeRevision, &receipt.CertificateSHA256,
		&receipt.Issuer, &receipt.IssuerRevision, &receipt.ClaimEpoch, &receipt.HeartbeatSequence,
		&receipt.ClaimTokenSHA256, &outcome, &failureCount, &failureCode, &failureDetail,
		&receipt.ReceiptHash, &receipt.ReceivedAt,
	)
	if err != nil {
		return credential.RunnerRevocationReceipt{}, err
	}
	receipt.Outcome = credential.RunnerRevocationOutcome(outcome)
	if failureCount != nil {
		receipt.FailureCount = *failureCount
	}
	if failureCode != nil {
		receipt.FailureCode = credential.FailureCode(*failureCode)
	}
	if failureDetail != nil {
		receipt.FailureDetailSHA256 = *failureDetail
	}
	receipt.ReceivedAt = receipt.ReceivedAt.UTC()
	return receipt, nil
}

func validateIdempotentRunnerRevocationReceipt(
	record *storedRevocation,
	scope execution.RunnerScope,
	fence credential.ClaimFence,
	completion credential.RunnerRevocationCompletion,
	certificateSHA256 string,
	receipt credential.RunnerRevocationReceipt,
) error {
	if record == nil || receipt.SchemaVersion != "credential-revocation-result.v1" ||
		receipt.RevocationID != record.revocation.ID || receipt.TenantID != record.revocation.TenantID ||
		receipt.WorkspaceID != record.revocation.WorkspaceID || receipt.EnvironmentID != record.revocation.EnvironmentID ||
		receipt.Issuer != record.revocation.Issuer || receipt.IssuerRevision != record.revocation.IssuerRevision ||
		receipt.RunnerID != scope.RunnerID() || receipt.ScopeRevision != scope.ScopeRevision() ||
		receipt.CertificateSHA256 != certificateSHA256 || receipt.ClaimEpoch != fence.Epoch ||
		receipt.ClaimTokenSHA256 != credential.SHA256Hex([]byte(fence.Token)) ||
		receipt.Outcome != completion.Outcome || receipt.FailureCode != completion.FailureCode ||
		!credential.ValidSHA256(receipt.ReceiptHash) {
		return credential.ErrCompletionConflict
	}
	preCompletion := record.revocation
	preCompletion.Status = credential.StatusRevoking
	preCompletion.ClaimEpoch = receipt.ClaimEpoch
	preCompletion.ClaimedBy = receipt.RunnerID
	if receipt.Outcome == credential.RunnerRevocationFailed {
		if receipt.FailureCount <= 0 || record.revocation.Status != credential.StatusRevocationPending &&
			record.revocation.Status != credential.StatusManualRequired ||
			record.revocation.FailureCount != receipt.FailureCount ||
			record.revocation.FailureCode != receipt.FailureCode ||
			record.revocation.FailureDetailSHA256 != receipt.FailureDetailSHA256 {
			return credential.ErrCompletionConflict
		}
		preCompletion.FailureCount = receipt.FailureCount - 1
	} else if record.revocation.Status != credential.StatusRevoked ||
		record.completedClaimEpoch != receipt.ClaimEpoch || record.completedClaimedBy != receipt.RunnerID ||
		record.completedClaimTokenSHA256 != receipt.ClaimTokenSHA256 {
		return credential.ErrCompletionConflict
	}
	expected, err := credential.BuildRunnerRevocationReceiptV1(credential.RunnerRevocationClaim{
		Revocation: preCompletion, RunnerID: receipt.RunnerID, ScopeRevision: receipt.ScopeRevision,
		CertificateSHA256: receipt.CertificateSHA256, ClaimTokenSHA256: receipt.ClaimTokenSHA256,
		HeartbeatSequence: receipt.HeartbeatSequence,
	}, completion, receipt.ReceivedAt)
	if err != nil || expected.ReceiptHash != receipt.ReceiptHash ||
		expected.FailureDetailSHA256 != receipt.FailureDetailSHA256 || expected.FailureCount != receipt.FailureCount {
		return credential.ErrCompletionConflict
	}
	return nil
}
