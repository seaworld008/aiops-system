package postgres

import (
	"context"
	"crypto/subtle"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executionlease"
)

// Transaction trust contract: every exported RunnerTx method requires scope
// to come from runneridentity/postgres authentication performed in the same tx,
// with the registration/certificate/scope rows still locked. Request data must
// never construct scope. These methods then lock the action before its
// credential row and deliberately do not Begin, Commit, or Rollback tx.

// RunnerChildCreateAuthorizationTicket is an opaque, repository-bound pending
// authorization. Its fields are deliberately private so code outside this
// package cannot invoke Vault before the caller-owned transaction commits.
// It is neither serializable nor reusable.
type RunnerChildCreateAuthorizationTicket struct {
	mu                  sync.Mutex
	owner               *Repository
	authorization       credential.ChildCreateAuthorization
	commitWindowStarted time.Time
	finalized           bool
}

func (*RunnerChildCreateAuthorizationTicket) String() string {
	return "RunnerChildCreateAuthorizationTicket{authorization:[REDACTED]}"
}

func (ticket *RunnerChildCreateAuthorizationTicket) GoString() string { return ticket.String() }

func (*RunnerChildCreateAuthorizationTicket) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrInvalidRevocationRequest
}

// FinalizeChildCreateAuthorizationAfterCommit is the only operation that
// releases the database authorization. The caller must invoke it immediately
// after an unambiguously successful commit; a failed or ambiguous commit must
// discard the ticket. The repository uses its own monotonic clock, rejects
// clock rollback/timeout, zero or cross-repository tickets, and consumes the
// ticket exactly once.
func (repository *Repository) FinalizeChildCreateAuthorizationAfterCommit(
	ticket *RunnerChildCreateAuthorizationTicket,
) (credential.ChildCreateAuthorization, error) {
	if repository == nil || ticket == nil {
		return credential.ChildCreateAuthorization{}, credential.ErrInvalidRevocationRequest
	}
	ticket.mu.Lock()
	defer ticket.mu.Unlock()
	if ticket.owner != repository || ticket.finalized || ticket.commitWindowStarted.IsZero() ||
		!validRunnerChildCreateAuthorization(ticket.authorization) {
		return credential.ChildCreateAuthorization{}, credential.ErrInvalidRevocationRequest
	}
	// Every same-owner attempt consumes the ticket. In particular, an expired
	// or rolled-back clock cannot be retried with a more favorable timestamp.
	ticket.finalized = true
	committedAt := repository.monotonicNow()
	elapsed := committedAt.Sub(ticket.commitWindowStarted)
	if elapsed < 0 || elapsed > credential.MaxChildCreateDBCommitLatency {
		return credential.ChildCreateAuthorization{}, credential.ErrChildCreateWindowExpired
	}
	authorization := ticket.authorization
	ticket.authorization = credential.ChildCreateAuthorization{}
	return authorization, nil
}

// RunnerCompletionCleanup is the credential state derived from a trusted
// FINALIZING action fence. Terminal is true only for REVOKED or NO_CREDENTIAL;
// false deliberately keeps the action target locked.
type RunnerCompletionCleanup struct {
	Revocation credential.Revocation
	Terminal   bool
}

// PrepareRunnerTx creates the durable PREPARED parent for one authenticated
// WRITE/non-production action. tx is caller-owned and is never committed or
// rolled back here. A returned raw Permit is only an internal candidate: the
// caller must not return or use it until tx commits successfully. Commit
// failure, including an ambiguous failure, requires discarding the permit.
func (repository *Repository) PrepareRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	request credential.PrepareRequest,
) (credential.PrepareResult, error) {
	if err := validateRunnerCredentialCall(ctx, tx, scope); err != nil {
		return credential.PrepareResult{}, err
	}
	request.CredentialExpiresAt = credential.CanonicalCredentialExpiry(request.CredentialExpiresAt)
	if !credential.ValidRevocationID(request.RevocationID) || !credential.ValidActionFence(request.Fence) ||
		!credential.ValidOpaqueText(request.Issuer, 256) || !credential.ValidIdentifier(request.IssuerRevision, 256) ||
		request.CredentialExpiresAt.IsZero() {
		return credential.PrepareResult{}, credential.ErrInvalidRevocationRequest
	}

	metadata, err := resolvePrepareActionFence(ctx, tx, request.Fence, request.CredentialExpiresAt)
	if err != nil {
		return credential.PrepareResult{}, err
	}
	if metadata.Production {
		return credential.PrepareResult{}, credential.ErrInvalidRevocationRequest
	}
	if !runnerScopeAuthorizesMetadata(scope, metadata) || metadata.Status != credential.ActionStatusRunning ||
		!metadata.CancelRequestedAt.IsZero() {
		return credential.PrepareResult{}, credential.ErrStaleActionFence
	}
	tokenDigest := credential.SHA256Hex([]byte(request.Fence.Token))

	existing, getErr := selectStored(ctx, tx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE action_id = $1 AND action_lease_epoch = $2
		FOR SHARE
	`, request.Fence.ActionID, request.Fence.Epoch)
	if getErr == nil {
		if !samePrepare(existing, request, metadata, tokenDigest) {
			return credential.PrepareResult{}, credential.ErrIdempotencyConflict
		}
		if existing.revocation.ID != request.RevocationID {
			var candidateOccupied bool
			if err := tx.QueryRow(ctx, `
				SELECT EXISTS (SELECT 1 FROM credential_revocations WHERE revocation_id = $1)
			`, request.RevocationID).Scan(&candidateOccupied); err != nil {
				return credential.PrepareResult{}, databaseError("check Runner credential revocation candidate identifier", err)
			}
			if candidateOccupied {
				return credential.PrepareResult{}, credential.ErrIdempotencyConflict
			}
		}
		if err := markActionCredentialExpected(ctx, tx, metadata, tokenDigest); err != nil {
			return credential.PrepareResult{}, err
		}
		if err := revalidateRunnerPrepareFence(ctx, tx, scope, request, metadata); err != nil {
			return credential.PrepareResult{}, err
		}
		return credential.PrepareResult{Revocation: publicRevocation(existing)}, nil
	}
	if !errors.Is(getErr, pgx.ErrNoRows) {
		return credential.PrepareResult{}, mapReadError("read idempotent Runner credential revocation prepare", getErr)
	}

	permitToken, err := repository.permitSource()
	if err != nil || !credential.ValidOpaqueText(permitToken, 4096) {
		return credential.PrepareResult{}, credential.ErrRevocationPersistence
	}
	permitDigest := credential.SHA256Hex([]byte(permitToken))
	var status string
	var availableAt, createdAt, updatedAt time.Time
	var version int64
	err = tx.QueryRow(ctx, `
		INSERT INTO credential_revocations (
			revocation_id, tenant_id, workspace_id, environment_id,
			action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
			issuer, issuer_revision, action_type, connector_id, scope_permission, scope_resource,
			credential_ttl_seconds, credential_expires_at, child_create_permit_sha256
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		ON CONFLICT (action_id, action_lease_epoch) DO NOTHING
		RETURNING status, available_at, created_at, updated_at, version
	`, request.RevocationID, metadata.TenantID, metadata.WorkspaceID, metadata.EnvironmentID,
		metadata.ActionID, metadata.TargetKey, metadata.Production, metadata.RunnerID, metadata.LeaseEpoch, tokenDigest,
		request.Issuer, request.IssuerRevision, metadata.ActionType, metadata.ConnectorID, metadata.Permission, metadata.Resource,
		metadata.CredentialTTLSeconds, request.CredentialExpiresAt, permitDigest,
	).Scan(&status, &availableAt, &createdAt, &updatedAt, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		existing, getErr = selectStored(ctx, tx, `
			SELECT `+revocationProjection+`
			FROM credential_revocations
			WHERE action_id = $1 AND action_lease_epoch = $2
			FOR SHARE
		`, request.Fence.ActionID, request.Fence.Epoch)
		if getErr != nil {
			return credential.PrepareResult{}, mapReadError("read concurrent Runner credential revocation prepare", getErr)
		}
		if !samePrepare(existing, request, metadata, tokenDigest) {
			return credential.PrepareResult{}, credential.ErrIdempotencyConflict
		}
		if err := markActionCredentialExpected(ctx, tx, metadata, tokenDigest); err != nil {
			return credential.PrepareResult{}, err
		}
		if err := revalidateRunnerPrepareFence(ctx, tx, scope, request, metadata); err != nil {
			return credential.PrepareResult{}, err
		}
		return credential.PrepareResult{Revocation: publicRevocation(existing)}, nil
	}
	if isUniqueViolation(err) {
		return credential.PrepareResult{}, credential.ErrIdempotencyConflict
	}
	if err != nil {
		return credential.PrepareResult{}, databaseError("insert Runner credential revocation prepare", err)
	}

	record := &storedRevocation{revocation: credential.Revocation{
		ID: request.RevocationID, TenantID: metadata.TenantID, WorkspaceID: metadata.WorkspaceID,
		EnvironmentID: metadata.EnvironmentID, ActionID: metadata.ActionID, TargetKey: metadata.TargetKey,
		Production: metadata.Production, RunnerID: metadata.RunnerID, ActionLeaseEpoch: metadata.LeaseEpoch,
		Issuer: request.Issuer, IssuerRevision: request.IssuerRevision, ActionType: metadata.ActionType,
		ConnectorID: metadata.ConnectorID, Permission: metadata.Permission, Resource: metadata.Resource,
		CredentialTTLSeconds: metadata.CredentialTTLSeconds, CredentialExpiresAt: request.CredentialExpiresAt,
		Status: credential.RevocationStatus(status), AvailableAt: availableAt.UTC(), CreatedAt: createdAt.UTC(),
		UpdatedAt: updatedAt.UTC(), Version: version,
	}, actionTokenSHA256: tokenDigest, childCreatePermitSHA256: permitDigest}
	if err := markActionCredentialExpected(ctx, tx, metadata, tokenDigest); err != nil {
		return credential.PrepareResult{}, err
	}
	if err := writeStateChange(ctx, tx, record.revocation, "RUNNER", request.Fence.RunnerID,
		"credential.revocation.prepared", "credential.revocation.prepared.v1"); err != nil {
		return credential.PrepareResult{}, err
	}
	if err := revalidateRunnerPrepareFence(ctx, tx, scope, request, metadata); err != nil {
		return credential.PrepareResult{}, err
	}
	return credential.PrepareResult{
		Revocation: publicRevocation(record), Created: true,
		Permit: &credential.ChildCreatePermit{RevocationID: request.RevocationID, Token: permitToken},
	}, nil
}

// AuthorizeChildCreateRunnerTx consumes the one-use child-create permit under
// the action -> credential lock order. tx remains caller-owned. The caller must
// commit, then call FinalizeChildCreateAuthorizationAfterCommit before making
// the single Vault request.
func (repository *Repository) AuthorizeChildCreateRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	request credential.AuthorizeChildCreateRequest,
) (*RunnerChildCreateAuthorizationTicket, error) {
	if err := validateRunnerCredentialCall(ctx, tx, scope); err != nil {
		return nil, err
	}
	if !credential.ValidRevocationID(request.Permit.RevocationID) ||
		!credential.ValidOpaqueText(request.Permit.Token, 4096) || !credential.ValidActionFence(request.Fence) {
		return nil, credential.ErrInvalidRevocationRequest
	}
	metadata, err := resolveActionFenceWithWindow(ctx, tx, request.Fence, time.Time{}, 0, true)
	if err != nil {
		return nil, err
	}
	if metadata.Production {
		return nil, credential.ErrInvalidRevocationRequest
	}
	if !runnerScopeAuthorizesMetadata(scope, metadata) || metadata.Status != credential.ActionStatusRunning ||
		!metadata.CancelRequestedAt.IsZero() {
		return nil, credential.ErrStaleActionFence
	}
	record, err := selectStored(ctx, tx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE revocation_id = $1
		FOR UPDATE
	`, request.Permit.RevocationID)
	if err != nil {
		return nil, mapReadError("read Runner credential child creation authorization", err)
	}
	if !storedMatchesAction(record, request.Fence, metadata) ||
		record.revocation.CredentialExpiresAt.After(metadata.AuthorizationExpiresAt) {
		return nil, credential.ErrStaleActionFence
	}
	permitDigest := credential.SHA256Hex([]byte(request.Permit.Token))
	if subtle.ConstantTimeCompare([]byte(record.childCreatePermitSHA256), []byte(permitDigest)) != 1 {
		return nil, credential.ErrStaleChildCreatePermit
	}
	if record.revocation.Status != credential.StatusPrepared || len(record.protected.Ciphertext) != 0 {
		return nil, credential.ErrInvalidTransition
	}
	if !record.childCreateAuthorizedAt.IsZero() {
		return nil, credential.ErrChildCreateAlreadyAuthorized
	}

	commitWindowStarted := repository.monotonicNow()
	databaseNow, err := databaseClockTime(ctx, tx)
	if err != nil {
		return nil, err
	}
	minimumFenceExpiry := databaseNow.Add(credential.ChildCreateExpiryReserve + credential.MinPostChildFenceWindow)
	if metadata.LeaseExpiresAt.Before(minimumFenceExpiry) || metadata.AuthorizationExpiresAt.Before(minimumFenceExpiry) {
		return nil, credential.ErrStaleActionFence
	}
	remaining := record.revocation.CredentialExpiresAt.Sub(databaseNow) - credential.ChildCreateExpiryReserve
	ttl := remaining / credential.VaultTTLQuantum * credential.VaultTTLQuantum
	if ttl < credential.MinChildCreateTTL {
		return nil, credential.ErrChildCreateWindowExpired
	}
	record, err = selectStored(ctx, tx, `
		UPDATE credential_revocations
		SET child_create_authorized_at = $2, child_create_ttl_seconds = $3,
			updated_at = clock_timestamp(), version = version + 1
		WHERE revocation_id = $1 AND status = 'PREPARED'
		  AND child_create_authorized_at IS NULL
		  AND child_create_permit_sha256 = $4
		RETURNING `+revocationProjection,
		request.Permit.RevocationID, databaseNow, int32(ttl/time.Second), permitDigest)
	if err != nil {
		return nil, mapTransitionError("authorize Runner credential child creation", err)
	}
	if err := writeStateChange(ctx, tx, record.revocation, "RUNNER", request.Fence.RunnerID,
		"credential.revocation.child_create_authorized", "credential.revocation.child_create_authorized.v1"); err != nil {
		return nil, err
	}
	return &RunnerChildCreateAuthorizationTicket{
		owner: repository,
		authorization: credential.ChildCreateAuthorization{
			Revocation: publicRevocation(record), DatabaseAuthorizedAt: databaseNow,
			CredentialExpiresAt: record.revocation.CredentialExpiresAt, TTL: ttl,
			VaultCallBudget: credential.ChildCreateVaultCallBudget,
		},
		commitWindowStarted: commitWindowStarted,
	}, nil
}

// RecordAnchorRunnerTx durably protects the revoke-only accessor. The action
// row is inspected before the credential row is locked. If the exact frozen
// fence is no longer current, the anchor is still persisted and atomically
// moved to REVOCATION_PENDING so it cannot be orphaned. The Gateway must commit
// that cleanup transition before mapping the stale execution authorization to
// a protocol conflict; rolling it back would lose the revoke anchor.
func (repository *Repository) RecordAnchorRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	request credential.RecordAnchorRequest,
) (credential.Revocation, error) {
	if err := validateRunnerCredentialCall(ctx, tx, scope); err != nil {
		return credential.Revocation{}, err
	}
	if !credential.ValidRevocationID(request.RevocationID) || !credential.ValidActionFence(request.Fence) ||
		!credential.ValidSensitiveReference(request.Accessor) {
		return credential.Revocation{}, credential.ErrInvalidRevocationRequest
	}
	inspection, databaseNow, registrationCurrent, err := inspectAction(ctx, tx, request.Fence.ActionID, request.Fence.RunnerID)
	if err != nil {
		return credential.Revocation{}, err
	}
	if inspection.Metadata.Production {
		return credential.Revocation{}, credential.ErrInvalidRevocationRequest
	}
	// Once child creation was authorized, losing the current scope must not
	// prevent persistence of the only revoke accessor. A matching WRITE
	// runner/tenant may anchor the frozen action fence, but a narrowed revision
	// or exact pair makes registrationCurrent false below and therefore forces
	// the new anchor directly to REVOCATION_PENDING. This path grants no
	// execution authorization.
	if !runnerScopeIdentifiesMetadata(scope, inspection.Metadata) {
		return credential.Revocation{}, credential.ErrStaleActionFence
	}
	registrationCurrent = registrationCurrent && runnerScopeAuthorizesMetadata(scope, inspection.Metadata)
	record, err := selectStored(ctx, tx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE revocation_id = $1
		FOR UPDATE
	`, request.RevocationID)
	if err != nil {
		return credential.Revocation{}, mapReadError("read Runner credential revocation anchor", err)
	}
	if !storedFrozenFenceMatches(record, request.Fence) || !storedInspectionScopeMatches(record, inspection.Metadata) {
		return credential.Revocation{}, credential.ErrStaleActionFence
	}
	if record.childCreateAuthorizedAt.IsZero() {
		return credential.Revocation{}, credential.ErrInvalidTransition
	}
	current := storedInspectionFenceCurrent(record, inspection, databaseNow, 0, registrationCurrent)
	if record.revocation.Status != credential.StatusPrepared {
		if record.revocation.Status == credential.StatusNoCredential || record.revocation.Status == credential.StatusRevoked ||
			len(record.protected.Ciphertext) == 0 {
			return credential.Revocation{}, credential.ErrInvalidTransition
		}
		matches, matchErr := repository.protector.Matches(referenceContext(record.revocation), record.protected, request.Accessor)
		if matchErr != nil {
			return credential.Revocation{}, credential.ErrReferenceProtection
		}
		if !matches {
			return credential.Revocation{}, credential.ErrIdempotencyConflict
		}
		if record.revocation.Status == credential.StatusAnchored || record.revocation.Status == credential.StatusActive {
			if current {
				finalNow, timeErr := databaseTime(ctx, tx)
				if timeErr != nil {
					return credential.Revocation{}, timeErr
				}
				current = storedInspectionFenceCurrent(record, inspection, finalNow, credential.MinPostChildFenceWindow, registrationCurrent)
			}
			if !current {
				record, err = repository.requestInvalidatedAnchor(ctx, tx, record.revocation.ID, "RUNNER", request.Fence.RunnerID)
				if err != nil {
					return credential.Revocation{}, err
				}
			}
		}
		return publicRevocation(record), nil
	}
	protected, err := repository.protector.Protect(referenceContext(record.revocation), request.Accessor)
	if err != nil {
		return credential.Revocation{}, credential.ErrReferenceProtection
	}
	record, err = selectStored(ctx, tx, `
		UPDATE credential_revocations
		SET status = 'ANCHORED', accessor_ciphertext = $2, accessor_hmac = $3,
			encryption_key_id = $4, anchored_at = statement_timestamp(),
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1 AND status = 'PREPARED'
		  AND child_create_authorized_at IS NOT NULL
		RETURNING `+revocationProjection,
		request.RevocationID, protected.Ciphertext, protected.AccessorHMAC, protected.KeyID)
	if err != nil {
		return credential.Revocation{}, mapTransitionError("anchor Runner credential revocation", err)
	}
	if err := writeStateChange(ctx, tx, record.revocation, "RUNNER", request.Fence.RunnerID,
		"credential.revocation.anchored", "credential.revocation.anchored.v1"); err != nil {
		return credential.Revocation{}, err
	}
	if current {
		finalNow, timeErr := databaseTime(ctx, tx)
		if timeErr != nil {
			return credential.Revocation{}, timeErr
		}
		current = storedInspectionFenceCurrent(record, inspection, finalNow, credential.MinPostChildFenceWindow, registrationCurrent)
	}
	if !current {
		record, err = repository.requestInvalidatedAnchor(ctx, tx, record.revocation.ID, "RUNNER", request.Fence.RunnerID)
		if err != nil {
			return credential.Revocation{}, err
		}
	}
	return publicRevocation(record), nil
}

// ActivateRunnerTx advances an exact anchored credential to ACTIVE while the
// caller-owned action transaction still proves that the Runner may execute. A
// stale scope returns REVOCATION_PENDING without an error; the Gateway must
// commit that cleanup state before reporting the authorization conflict.
func (repository *Repository) ActivateRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	request credential.ActionTransitionRequest,
) (credential.Revocation, error) {
	if err := validateRunnerCredentialCall(ctx, tx, scope); err != nil {
		return credential.Revocation{}, err
	}
	if !credential.ValidRevocationID(request.RevocationID) || !credential.ValidActionFence(request.Fence) {
		return credential.Revocation{}, credential.ErrInvalidRevocationRequest
	}
	inspection, databaseNow, registrationCurrent, err := inspectAction(ctx, tx, request.Fence.ActionID, request.Fence.RunnerID)
	if err != nil {
		return credential.Revocation{}, err
	}
	if inspection.Metadata.Production {
		return credential.Revocation{}, credential.ErrInvalidRevocationRequest
	}
	// Activation reuses the safe late-anchor identity rule: a stale scope may
	// only move an already anchored record toward revocation, never ACTIVE.
	if !runnerScopeIdentifiesMetadata(scope, inspection.Metadata) {
		return credential.Revocation{}, credential.ErrStaleActionFence
	}
	registrationCurrent = registrationCurrent && runnerScopeAuthorizesMetadata(scope, inspection.Metadata)
	record, err := selectStored(ctx, tx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE revocation_id = $1
		FOR UPDATE
	`, request.RevocationID)
	if err != nil {
		return credential.Revocation{}, mapReadError("read Runner credential revocation activation", err)
	}
	if !storedFrozenFenceMatches(record, request.Fence) || !storedInspectionScopeMatches(record, inspection.Metadata) {
		return credential.Revocation{}, credential.ErrStaleActionFence
	}
	current := storedInspectionFenceCurrent(record, inspection, databaseNow, 0, registrationCurrent)
	switch record.revocation.Status {
	case credential.StatusAnchored:
		if current {
			record, err = selectStored(ctx, tx, `
				UPDATE credential_revocations
				SET status = 'ACTIVE', activated_at = statement_timestamp(),
					updated_at = statement_timestamp(), version = version + 1
				WHERE revocation_id = $1 AND status = 'ANCHORED'
				RETURNING `+revocationProjection,
				request.RevocationID)
			if err != nil {
				return credential.Revocation{}, mapTransitionError("activate Runner credential revocation", err)
			}
			if err := writeStateChange(ctx, tx, record.revocation, "RUNNER", request.Fence.RunnerID,
				"credential.revocation.active", "credential.revocation.active.v1"); err != nil {
				return credential.Revocation{}, err
			}
		} else {
			record, err = repository.requestInvalidatedAnchor(ctx, tx, record.revocation.ID, "RUNNER", request.Fence.RunnerID)
			if err != nil {
				return credential.Revocation{}, err
			}
		}
	case credential.StatusActive:
		if !current {
			record, err = repository.requestInvalidatedAnchor(ctx, tx, record.revocation.ID, "RUNNER", request.Fence.RunnerID)
			if err != nil {
				return credential.Revocation{}, err
			}
		}
	case credential.StatusRevocationPending, credential.StatusRevoking,
		credential.StatusManualRequired, credential.StatusRevoked:
	case credential.StatusPrepared, credential.StatusNoCredential:
		return credential.Revocation{}, credential.ErrInvalidTransition
	default:
		return credential.Revocation{}, credential.ErrInvalidTransition
	}
	if current && record.revocation.Status == credential.StatusActive {
		finalNow, timeErr := databaseTime(ctx, tx)
		if timeErr != nil {
			return credential.Revocation{}, timeErr
		}
		if !storedInspectionFenceCurrent(record, inspection, finalNow, credential.MinPostChildFenceWindow, registrationCurrent) {
			record, err = repository.requestInvalidatedAnchor(ctx, tx, record.revocation.ID, "RUNNER", request.Fence.RunnerID)
			if err != nil {
				return credential.Revocation{}, err
			}
		}
	}
	return publicRevocation(record), nil
}

// RecordNoCredentialRunnerTx proves that the PREPARED job never performed a
// child-create call. tx remains caller-owned.
func (repository *Repository) RecordNoCredentialRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	request credential.ActionTransitionRequest,
) (credential.Revocation, error) {
	return repository.runnerActionTransitionTx(ctx, tx, scope, request, transitionNoCredential)
}

// RequestRevocationRunnerTx atomically requests cleanup for an anchored or
// active credential under the current action bearer. Completion paths must use
// EnsureCompletionCleanupRunnerTx instead of trusting a Runner revocation ID.
func (repository *Repository) RequestRevocationRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	request credential.ActionTransitionRequest,
) (credential.Revocation, error) {
	return repository.runnerActionTransitionTx(ctx, tx, scope, request, transitionRequestRevocation)
}

// EnsureCompletionCleanupRunnerTx derives the credential solely from the
// trusted FINALIZING action_id + completed epoch/token fence. It never accepts
// a Runner-supplied revocation ID. PREPARED-without-authorization becomes
// NO_CREDENTIAL, ANCHORED/ACTIVE becomes REVOCATION_PENDING, and every other
// non-terminal state keeps Terminal=false so FinalizeRunnerTx cannot release
// the target lock. tx remains caller-owned.
func (repository *Repository) EnsureCompletionCleanupRunnerTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	fence executionlease.LeaseIdentity,
) (RunnerCompletionCleanup, error) {
	if err := validateRunnerCredentialCall(ctx, tx, scope); err != nil {
		return RunnerCompletionCleanup{}, err
	}
	if !validRunnerCompletionFence(fence) {
		return RunnerCompletionCleanup{}, credential.ErrInvalidRevocationRequest
	}
	action, err := lockRunnerCompletionAction(ctx, tx, fence.ExecutionID)
	if err != nil {
		return RunnerCompletionCleanup{}, err
	}
	if action.production {
		return RunnerCompletionCleanup{}, credential.ErrInvalidRevocationRequest
	}
	if action.status != "FINALIZING" || action.runnerID != fence.RunnerID || action.runnerID != scope.RunnerID() ||
		action.leaseEpoch != fence.Epoch || action.completedLeaseEpoch != fence.Epoch ||
		subtle.ConstantTimeCompare([]byte(action.completedTokenSHA256), []byte(credential.SHA256Hex([]byte(fence.Token)))) != 1 ||
		action.tenantID != scope.TenantID() || action.runnerPool != string(executionlease.PoolWrite) ||
		action.scopeRevision != scope.ScopeRevision() || !runnerScopeAllowsPair(scope, action.workspaceID, action.environmentID) ||
		!action.credentialExpected || action.credentialLeaseEpoch != fence.Epoch {
		return RunnerCompletionCleanup{}, credential.ErrStaleActionFence
	}
	record, err := selectStored(ctx, tx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE action_id = $1 AND action_lease_epoch = $2
		FOR UPDATE
	`, fence.ExecutionID, fence.Epoch)
	if err != nil {
		return RunnerCompletionCleanup{}, mapReadError("read Runner completion credential cleanup", err)
	}
	if !runnerCompletionRecordMatches(record, action, fence) {
		return RunnerCompletionCleanup{}, credential.ErrStaleActionFence
	}

	switch record.revocation.Status {
	case credential.StatusPrepared:
		if !record.childCreateAuthorizedAt.IsZero() {
			return RunnerCompletionCleanup{Revocation: publicRevocation(record)}, nil
		}
		record, err = selectStored(ctx, tx, `
			UPDATE credential_revocations
			SET status = 'NO_CREDENTIAL', updated_at = statement_timestamp(), version = version + 1
			WHERE revocation_id = $1 AND status = 'PREPARED'
			  AND child_create_authorized_at IS NULL
			RETURNING `+revocationProjection,
			record.revocation.ID)
		if err != nil {
			return RunnerCompletionCleanup{}, mapTransitionError("record Runner completion without credential", err)
		}
		if err := writeStateChange(ctx, tx, record.revocation, "RUNNER", fence.RunnerID,
			"credential.revocation.no_credential", "credential.revocation.no_credential.v1"); err != nil {
			return RunnerCompletionCleanup{}, err
		}
	case credential.StatusAnchored, credential.StatusActive:
		record, err = repository.requestInvalidatedAnchor(ctx, tx, record.revocation.ID, "RUNNER", fence.RunnerID)
		if err != nil {
			return RunnerCompletionCleanup{}, err
		}
	case credential.StatusNoCredential, credential.StatusRevoked:
		return RunnerCompletionCleanup{Revocation: publicRevocation(record), Terminal: true}, nil
	case credential.StatusRevocationPending, credential.StatusRevoking, credential.StatusManualRequired:
		return RunnerCompletionCleanup{Revocation: publicRevocation(record)}, nil
	default:
		return RunnerCompletionCleanup{}, credential.ErrInvalidTransition
	}
	terminal := record.revocation.Status == credential.StatusNoCredential || record.revocation.Status == credential.StatusRevoked
	return RunnerCompletionCleanup{Revocation: publicRevocation(record), Terminal: terminal}, nil
}

func (repository *Repository) runnerActionTransitionTx(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	request credential.ActionTransitionRequest,
	kind actionTransitionKind,
) (credential.Revocation, error) {
	if err := validateRunnerCredentialCall(ctx, tx, scope); err != nil {
		return credential.Revocation{}, err
	}
	if !credential.ValidRevocationID(request.RevocationID) || !credential.ValidActionFence(request.Fence) {
		return credential.Revocation{}, credential.ErrInvalidRevocationRequest
	}
	metadata, err := resolveActionFenceWithWindow(ctx, tx, request.Fence, time.Time{}, 0, true)
	if err != nil {
		return credential.Revocation{}, err
	}
	if metadata.Production {
		return credential.Revocation{}, credential.ErrInvalidRevocationRequest
	}
	if !runnerScopeAuthorizesMetadata(scope, metadata) || metadata.Status != credential.ActionStatusRunning ||
		!metadata.CancelRequestedAt.IsZero() {
		return credential.Revocation{}, credential.ErrStaleActionFence
	}
	record, err := selectStored(ctx, tx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE revocation_id = $1
		FOR UPDATE
	`, request.RevocationID)
	if err != nil {
		return credential.Revocation{}, mapReadError("read Runner credential revocation transition", err)
	}
	if !storedMatchesAction(record, request.Fence, metadata) {
		return credential.Revocation{}, credential.ErrStaleActionFence
	}
	var query, auditAction, eventType string
	var idempotent bool
	switch kind {
	case transitionNoCredential:
		switch record.revocation.Status {
		case credential.StatusPrepared:
			if !record.childCreateAuthorizedAt.IsZero() {
				return credential.Revocation{}, credential.ErrInvalidTransition
			}
			query = `
				UPDATE credential_revocations
				SET status = 'NO_CREDENTIAL', updated_at = statement_timestamp(), version = version + 1
				WHERE revocation_id = $1 AND child_create_authorized_at IS NULL
				RETURNING ` + revocationProjection
			auditAction, eventType = "credential.revocation.no_credential", "credential.revocation.no_credential.v1"
		case credential.StatusNoCredential:
			idempotent = true
		default:
			return credential.Revocation{}, credential.ErrInvalidTransition
		}
	case transitionRequestRevocation:
		switch record.revocation.Status {
		case credential.StatusAnchored, credential.StatusActive:
			query = `
				UPDATE credential_revocations
				SET status = 'REVOCATION_PENDING', available_at = statement_timestamp(),
					revocation_requested_at = statement_timestamp(), updated_at = statement_timestamp(),
					retry_cycle_attempt_base = attempt, retry_cycle_started_at = statement_timestamp(),
					version = version + 1
				WHERE revocation_id = $1
				RETURNING ` + revocationProjection
			auditAction, eventType = "credential.revocation.requested", "credential.revocation.requested.v1"
		case credential.StatusRevocationPending, credential.StatusRevoking,
			credential.StatusManualRequired, credential.StatusRevoked:
			idempotent = true
		default:
			return credential.Revocation{}, credential.ErrInvalidTransition
		}
	default:
		return credential.Revocation{}, credential.ErrInvalidRevocationRequest
	}
	if !idempotent {
		record, err = selectStored(ctx, tx, query, request.RevocationID)
		if err != nil {
			return credential.Revocation{}, mapTransitionError("update Runner credential revocation state", err)
		}
		if err := writeStateChange(ctx, tx, record.revocation, "RUNNER", request.Fence.RunnerID, auditAction, eventType); err != nil {
			return credential.Revocation{}, err
		}
	}
	return publicRevocation(record), nil
}

func revalidateRunnerPrepareFence(
	ctx context.Context,
	tx pgx.Tx,
	scope execution.RunnerScope,
	request credential.PrepareRequest,
	initial credential.ActionMetadata,
) error {
	current, err := resolvePrepareActionFence(ctx, tx, request.Fence, request.CredentialExpiresAt)
	if err != nil {
		if errors.Is(err, credential.ErrStaleActionFence) || errors.Is(err, credential.ErrInvalidRevocationRequest) {
			return credential.ErrStaleActionFence
		}
		return err
	}
	if !sameResolvedActionScope(initial, current) || !runnerScopeAuthorizesMetadata(scope, current) ||
		current.Status != credential.ActionStatusRunning || !current.CancelRequestedAt.IsZero() ||
		request.CredentialExpiresAt.After(current.AuthorizationExpiresAt) {
		return credential.ErrStaleActionFence
	}
	return nil
}

func validateRunnerCredentialCall(ctx context.Context, tx pgx.Tx, scope execution.RunnerScope) error {
	if ctx == nil || tx == nil {
		return credential.ErrInvalidRevocationRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if scope.Pool() != executionlease.PoolWrite || !credential.ValidIdentifier(scope.RunnerID(), 256) ||
		!credential.ValidRevocationID(scope.TenantID()) || scope.ScopeRevision() <= 0 ||
		scope.MaxConcurrency() < 1 || scope.MaxConcurrency() > 1024 {
		return credential.ErrInvalidRevocationRequest
	}
	bindings := scope.Bindings()
	if len(bindings) == 0 {
		return credential.ErrInvalidRevocationRequest
	}
	seen := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if !credential.ValidRevocationID(binding.WorkspaceID) || !credential.ValidRevocationID(binding.EnvironmentID) {
			return credential.ErrInvalidRevocationRequest
		}
		key := binding.WorkspaceID + "\x00" + binding.EnvironmentID
		if _, duplicate := seen[key]; duplicate {
			return credential.ErrInvalidRevocationRequest
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validRunnerChildCreateAuthorization(authorization credential.ChildCreateAuthorization) bool {
	return credential.ValidRevocationID(authorization.Revocation.ID) &&
		authorization.Revocation.Status == credential.StatusPrepared &&
		!authorization.DatabaseAuthorizedAt.IsZero() && !authorization.CredentialExpiresAt.IsZero() &&
		authorization.CredentialExpiresAt.Equal(authorization.Revocation.CredentialExpiresAt) &&
		authorization.TTL >= credential.MinChildCreateTTL &&
		authorization.TTL%credential.VaultTTLQuantum == 0 &&
		authorization.TTL <= credential.MaxCredentialTTL &&
		authorization.VaultCallBudget == credential.ChildCreateVaultCallBudget &&
		!authorization.DatabaseAuthorizedAt.Add(authorization.TTL+credential.ChildCreateExpiryReserve).
			After(authorization.CredentialExpiresAt)
}

func runnerScopeAuthorizesMetadata(scope execution.RunnerScope, metadata credential.ActionMetadata) bool {
	return runnerScopeIdentifiesMetadata(scope, metadata) &&
		metadata.ScopeRevision == scope.ScopeRevision() &&
		runnerScopeAllowsPair(scope, metadata.WorkspaceID, metadata.EnvironmentID)
}

func runnerScopeIdentifiesMetadata(scope execution.RunnerScope, metadata credential.ActionMetadata) bool {
	return !metadata.Production && metadata.RunnerPool == string(executionlease.PoolWrite) &&
		metadata.RunnerID == scope.RunnerID() && metadata.TenantID == scope.TenantID()
}

func runnerScopeAllowsPair(scope execution.RunnerScope, workspaceID, environmentID string) bool {
	for _, binding := range scope.Bindings() {
		if binding.WorkspaceID == workspaceID && binding.EnvironmentID == environmentID {
			return true
		}
	}
	return false
}

type runnerCompletionAction struct {
	actionID             string
	tenantID             string
	workspaceID          string
	environmentID        string
	targetKey            string
	production           bool
	runnerID             string
	runnerPool           string
	leaseEpoch           int64
	scopeRevision        int64
	status               string
	completedLeaseEpoch  int64
	completedTokenSHA256 string
	credentialExpected   bool
	credentialLeaseEpoch int64
}

func lockRunnerCompletionAction(ctx context.Context, tx pgx.Tx, actionID string) (runnerCompletionAction, error) {
	var action runnerCompletionAction
	err := tx.QueryRow(ctx, `
		SELECT action_id, runner_tenant_id::text, runner_workspace_id::text, runner_environment_id::text,
			target_key, production, runner_id, runner_pool, lease_epoch, scope_revision, status,
			completed_lease_epoch, completed_lease_token_sha256,
			credential_expected, credential_lease_epoch
		FROM action_queue
		WHERE action_id = $1
		FOR UPDATE
	`, actionID).Scan(
		&action.actionID, &action.tenantID, &action.workspaceID, &action.environmentID,
		&action.targetKey, &action.production, &action.runnerID, &action.runnerPool,
		&action.leaseEpoch, &action.scopeRevision, &action.status,
		&action.completedLeaseEpoch, &action.completedTokenSHA256,
		&action.credentialExpected, &action.credentialLeaseEpoch,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return runnerCompletionAction{}, credential.ErrStaleActionFence
	}
	if err != nil {
		return runnerCompletionAction{}, databaseError("lock Runner completion credential action", err)
	}
	return action, nil
}

func runnerCompletionRecordMatches(
	record *storedRevocation,
	action runnerCompletionAction,
	fence executionlease.LeaseIdentity,
) bool {
	revocation := record.revocation
	return revocation.ActionID == action.actionID && revocation.ActionID == fence.ExecutionID &&
		revocation.TenantID == action.tenantID && revocation.WorkspaceID == action.workspaceID &&
		revocation.EnvironmentID == action.environmentID && revocation.TargetKey == action.targetKey &&
		revocation.Production == action.production && revocation.RunnerID == action.runnerID &&
		revocation.ActionLeaseEpoch == action.leaseEpoch && revocation.ActionLeaseEpoch == fence.Epoch &&
		subtle.ConstantTimeCompare([]byte(record.actionTokenSHA256), []byte(action.completedTokenSHA256)) == 1
}

func validRunnerCompletionFence(fence executionlease.LeaseIdentity) bool {
	return credential.ValidIdentifier(fence.ExecutionID, 256) && credential.ValidIdentifier(fence.RunnerID, 256) &&
		credential.ValidOpaqueText(fence.Token, 4096) && fence.Epoch > 0
}
