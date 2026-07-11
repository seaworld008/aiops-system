package postgres

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/ids"
	"github.com/seaworld008/aiops-system/internal/requestmeta"
)

const revocationProjection = `
	revocation_id::text, tenant_id::text, workspace_id::text, environment_id::text,
	action_id, target_key, production, runner_id, action_lease_epoch, action_lease_token_sha256,
	issuer, issuer_revision, action_type, connector_id, scope_permission, scope_resource,
	credential_ttl_seconds, credential_expires_at,
	child_create_permit_sha256, child_create_authorized_at, child_create_ttl_seconds, status,
	accessor_ciphertext, accessor_hmac, encryption_key_id,
	claim_epoch, claimed_by, claim_token_sha256, claimed_at, claim_expires_at, last_heartbeat_at,
	completed_claim_epoch, completed_claim_token_sha256, completed_claimed_by,
	attempt, retry_cycle_attempt_base, retry_cycle_started_at,
	failure_count, failure_code, failure_detail_sha256, available_at, evidence_hash,
	anchored_at, activated_at, revocation_requested_at, manual_required_at, revoked_at,
	version, created_at, updated_at
`

type DB interface {
	Begin(context.Context) (pgx.Tx, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type Options struct {
	TokenSource  func() (string, error)
	PermitSource func() (string, error)
	MonotonicNow func() time.Time
}

type Repository struct {
	database     DB
	protector    credential.ReferenceProtector
	tokenSource  func() (string, error)
	permitSource func() (string, error)
	monotonicNow func() time.Time
}

var _ credential.Repository = (*Repository)(nil)
var _ credential.CleanupInspector = (*Repository)(nil)

type storedRevocation struct {
	revocation                credential.Revocation
	protected                 credential.ProtectedReference
	actionTokenSHA256         string
	childCreatePermitSHA256   string
	childCreateAuthorizedAt   time.Time
	childCreateTTL            time.Duration
	retryCycleAttemptBase     int
	retryCycleStartedAt       time.Time
	claimTokenSHA256          string
	completedClaimEpoch       int64
	completedClaimTokenSHA256 string
	completedClaimedBy        string
}

type lockedRunnerRegistration struct {
	tenantID      string
	pool          string
	enabled       bool
	scopeRevision int64
	found         bool
}

func New(database DB, protector credential.ReferenceProtector, options Options) (*Repository, error) {
	if database == nil || protector == nil {
		return nil, credential.ErrInvalidRevocationRequest
	}
	if options.TokenSource == nil {
		options.TokenSource = randomToken
	}
	if options.PermitSource == nil {
		options.PermitSource = randomToken
	}
	if options.MonotonicNow == nil {
		options.MonotonicNow = time.Now
	}
	return &Repository{
		database: database, protector: protector, tokenSource: options.TokenSource,
		permitSource: options.PermitSource, monotonicNow: options.MonotonicNow,
	}, nil
}

func (repository *Repository) Prepare(ctx context.Context, request credential.PrepareRequest) (credential.PrepareResult, error) {
	if err := validateContext(ctx); err != nil {
		return credential.PrepareResult{}, err
	}
	request.CredentialExpiresAt = credential.CanonicalCredentialExpiry(request.CredentialExpiresAt)
	if !credential.ValidRevocationID(request.RevocationID) || !credential.ValidActionFence(request.Fence) ||
		!credential.ValidOpaqueText(request.Issuer, 256) || !credential.ValidIdentifier(request.IssuerRevision, 256) ||
		request.CredentialExpiresAt.IsZero() {
		return credential.PrepareResult{}, credential.ErrInvalidRevocationRequest
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return credential.PrepareResult{}, databaseError("begin credential revocation prepare", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	metadata, err := resolvePrepareActionFence(ctx, tx, request.Fence, request.CredentialExpiresAt)
	if err != nil {
		return credential.PrepareResult{}, err
	}
	if metadata.Production {
		return credential.PrepareResult{}, credential.ErrInvalidRevocationRequest
	}
	tokenDigest := credential.SHA256Hex([]byte(request.Fence.Token))
	finishExisting := func(existing *storedRevocation) (credential.PrepareResult, error) {
		if !samePrepare(existing, request, metadata, tokenDigest) {
			return credential.PrepareResult{}, credential.ErrIdempotencyConflict
		}
		if existing.revocation.ID != request.RevocationID {
			var candidateOccupied bool
			if err := tx.QueryRow(ctx, `
				SELECT EXISTS (
					SELECT 1 FROM credential_revocations WHERE revocation_id = $1
				)
			`, request.RevocationID).Scan(&candidateOccupied); err != nil {
				return credential.PrepareResult{}, databaseError("check credential revocation candidate identifier", err)
			}
			if candidateOccupied {
				return credential.PrepareResult{}, credential.ErrIdempotencyConflict
			}
		}
		if err := markActionCredentialExpected(ctx, tx, metadata, tokenDigest); err != nil {
			return credential.PrepareResult{}, err
		}
		if err := revalidatePrepareFence(ctx, tx, request, metadata); err != nil {
			return credential.PrepareResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return credential.PrepareResult{}, databaseError("commit idempotent credential revocation prepare", err)
		}
		committed = true
		return credential.PrepareResult{Revocation: publicRevocation(existing)}, nil
	}

	existing, getErr := selectStored(ctx, tx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE action_id = $1 AND action_lease_epoch = $2
		FOR SHARE
	`, request.Fence.ActionID, request.Fence.Epoch)
	if getErr == nil {
		return finishExisting(existing)
	}
	if !errors.Is(getErr, pgx.ErrNoRows) {
		return credential.PrepareResult{}, mapReadError("read idempotent credential revocation prepare", getErr)
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
		existing, getErr := selectStored(ctx, tx, `
			SELECT `+revocationProjection+`
			FROM credential_revocations
			WHERE action_id = $1 AND action_lease_epoch = $2
			FOR SHARE
		`, request.Fence.ActionID, request.Fence.Epoch)
		if getErr != nil {
			return credential.PrepareResult{}, mapReadError("read idempotent credential revocation prepare", getErr)
		}
		return finishExisting(existing)
	}
	if isUniqueViolation(err) {
		return credential.PrepareResult{}, credential.ErrIdempotencyConflict
	}
	if err != nil {
		return credential.PrepareResult{}, databaseError("insert credential revocation prepare", err)
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
	if err := revalidatePrepareFence(ctx, tx, request, metadata); err != nil {
		return credential.PrepareResult{}, err
	}
	// A commit error is intentionally ambiguous and therefore never authorizes
	// child creation. If the server committed before the response was lost, a
	// retry takes the conflict path above and returns Created=false.
	if err := tx.Commit(ctx); err != nil {
		return credential.PrepareResult{}, databaseError("commit credential revocation prepare", err)
	}
	committed = true
	return credential.PrepareResult{
		Revocation: publicRevocation(record), Created: true,
		Permit: &credential.ChildCreatePermit{RevocationID: request.RevocationID, Token: permitToken},
	}, nil
}

func markActionCredentialExpected(
	ctx context.Context,
	tx pgx.Tx,
	metadata credential.ActionMetadata,
	tokenDigest string,
) error {
	result, err := tx.Exec(ctx, `
		UPDATE action_queue
		SET credential_expected = true,
			credential_lease_epoch = $8,
			updated_at = statement_timestamp()
		WHERE action_id = $1
		  AND runner_tenant_id = $2::uuid
		  AND runner_workspace_id = $3::uuid
		  AND runner_environment_id = $4::uuid
		  AND target_key = $5
		  AND production = $6
		  AND runner_id = $7
		  AND lease_epoch = $8
		  AND lease_token_sha256 = $9
		  AND runner_pool = 'WRITE'
		  AND status IN ('LEASED', 'RUNNING')
		  AND (
			(credential_expected = false AND credential_lease_epoch IS NULL) OR
			(credential_expected = true AND credential_lease_epoch = $8)
		  )
	`, metadata.ActionID, metadata.TenantID, metadata.WorkspaceID, metadata.EnvironmentID,
		metadata.TargetKey, metadata.Production, metadata.RunnerID, metadata.LeaseEpoch, tokenDigest)
	if err != nil {
		return databaseError("mark action credential expected", err)
	}
	if result.RowsAffected() != 1 {
		return credential.ErrStaleActionFence
	}
	return nil
}

func (repository *Repository) AuthorizeChildCreate(
	ctx context.Context,
	request credential.AuthorizeChildCreateRequest,
) (credential.ChildCreateAuthorization, error) {
	if err := validateContext(ctx); err != nil {
		return credential.ChildCreateAuthorization{}, err
	}
	if !credential.ValidRevocationID(request.Permit.RevocationID) ||
		!credential.ValidOpaqueText(request.Permit.Token, 4096) || !credential.ValidActionFence(request.Fence) {
		return credential.ChildCreateAuthorization{}, credential.ErrInvalidRevocationRequest
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return credential.ChildCreateAuthorization{}, databaseError("begin credential child creation authorization", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	// Child creation follows the execution repository's global lock prefix:
	// runner registration, action row, then credential revocation row. runner_id
	// is globally unique, so no action-row tenant hint is required before the
	// registration lock.
	metadata, err := resolveChildCreateActionFence(ctx, tx, request.Fence)
	if err != nil {
		return credential.ChildCreateAuthorization{}, err
	}
	record, err := selectStored(ctx, tx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE revocation_id = $1
		FOR UPDATE
	`, request.Permit.RevocationID)
	if err != nil {
		return credential.ChildCreateAuthorization{}, mapReadError("read credential child creation authorization", err)
	}
	if !storedMatchesAction(record, request.Fence, metadata) ||
		record.revocation.CredentialExpiresAt.After(metadata.AuthorizationExpiresAt) {
		return credential.ChildCreateAuthorization{}, credential.ErrStaleActionFence
	}
	permitDigest := credential.SHA256Hex([]byte(request.Permit.Token))
	if subtle.ConstantTimeCompare([]byte(record.childCreatePermitSHA256), []byte(permitDigest)) != 1 {
		return credential.ChildCreateAuthorization{}, credential.ErrStaleChildCreatePermit
	}
	if record.revocation.Status != credential.StatusPrepared || len(record.protected.Ciphertext) != 0 {
		return credential.ChildCreateAuthorization{}, credential.ErrInvalidTransition
	}
	if !record.childCreateAuthorizedAt.IsZero() {
		return credential.ChildCreateAuthorization{}, credential.ErrChildCreateAlreadyAuthorized
	}

	commitWindowStarted := repository.monotonicNow()
	databaseNow, err := databaseClockTime(ctx, tx)
	if err != nil {
		return credential.ChildCreateAuthorization{}, err
	}
	minimumFenceExpiry := databaseNow.Add(credential.ChildCreateExpiryReserve + credential.MinPostChildFenceWindow)
	if metadata.LeaseExpiresAt.Before(minimumFenceExpiry) || metadata.AuthorizationExpiresAt.Before(minimumFenceExpiry) {
		return credential.ChildCreateAuthorization{}, credential.ErrStaleActionFence
	}
	remaining := record.revocation.CredentialExpiresAt.Sub(databaseNow) - credential.ChildCreateExpiryReserve
	ttl := remaining / credential.VaultTTLQuantum * credential.VaultTTLQuantum
	if ttl < credential.MinChildCreateTTL {
		return credential.ChildCreateAuthorization{}, credential.ErrChildCreateWindowExpired
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
		return credential.ChildCreateAuthorization{}, mapTransitionError("authorize credential child creation", err)
	}
	if err := writeStateChange(ctx, tx, record.revocation, "RUNNER", request.Fence.RunnerID,
		"credential.revocation.child_create_authorized", "credential.revocation.child_create_authorized.v1"); err != nil {
		return credential.ChildCreateAuthorization{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return credential.ChildCreateAuthorization{}, databaseError("commit credential child creation authorization", err)
	}
	committed = true
	commitElapsed := repository.monotonicNow().Sub(commitWindowStarted)
	if commitElapsed < 0 || commitElapsed > credential.MaxChildCreateDBCommitLatency {
		return credential.ChildCreateAuthorization{}, credential.ErrChildCreateWindowExpired
	}
	return credential.ChildCreateAuthorization{
		Revocation: publicRevocation(record), DatabaseAuthorizedAt: databaseNow,
		CredentialExpiresAt: record.revocation.CredentialExpiresAt, TTL: ttl,
		VaultCallBudget: credential.ChildCreateVaultCallBudget,
	}, nil
}

func resolveActionFence(ctx context.Context, tx pgx.Tx, fence credential.ActionFence, credentialExpiry time.Time) (credential.ActionMetadata, error) {
	return resolveActionFenceWithWindow(ctx, tx, fence, credentialExpiry, 0, false)
}

func resolveChildCreateActionFence(
	ctx context.Context,
	tx pgx.Tx,
	fence credential.ActionFence,
) (credential.ActionMetadata, error) {
	registration, err := lockRunnerRegistration(ctx, tx, fence.RunnerID)
	if err != nil {
		return credential.ActionMetadata{}, err
	}
	metadata, err := resolveActionFence(ctx, tx, fence, time.Time{})
	if err != nil {
		return credential.ActionMetadata{}, err
	}
	if metadata.Status != credential.ActionStatusRunning || !metadata.CancelRequestedAt.IsZero() ||
		!registration.matches(metadata) {
		return credential.ActionMetadata{}, credential.ErrStaleActionFence
	}
	// Binding mutations synchronously bump this already share-locked
	// registration row. A committed mutation therefore changes the revision;
	// an uncommitted mutation remains invisible and linearizes after this check.
	bound, err := exactRunnerScopeBinding(ctx, tx, metadata)
	if err != nil {
		return credential.ActionMetadata{}, err
	}
	if !bound {
		return credential.ActionMetadata{}, credential.ErrStaleActionFence
	}
	return metadata, nil
}

func lockRunnerRegistration(
	ctx context.Context,
	tx pgx.Tx,
	runnerID string,
) (lockedRunnerRegistration, error) {
	var registration lockedRunnerRegistration
	err := tx.QueryRow(ctx, `
		SELECT tenant_id::text, runner_pool, enabled, scope_revision
		FROM runner_registrations
		WHERE runner_id = $1
		FOR SHARE
	`, runnerID).Scan(
		&registration.tenantID, &registration.pool, &registration.enabled, &registration.scopeRevision,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return registration, nil
	}
	if err != nil {
		return lockedRunnerRegistration{}, databaseError("lock credential runner registration", err)
	}
	registration.found = true
	return registration, nil
}

func (registration lockedRunnerRegistration) matches(metadata credential.ActionMetadata) bool {
	return registration.found && registration.enabled && registration.pool == "WRITE" &&
		metadata.RunnerPool == "WRITE" && registration.tenantID == metadata.TenantID &&
		registration.scopeRevision > 0 && registration.scopeRevision == metadata.ScopeRevision
}

func exactRunnerScopeBinding(
	ctx context.Context,
	tx pgx.Tx,
	metadata credential.ActionMetadata,
) (bool, error) {
	var bound bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM runner_scope_bindings
			WHERE runner_id = $1 AND tenant_id = $2 AND workspace_id = $3 AND environment_id = $4
		)
	`, metadata.RunnerID, metadata.TenantID, metadata.WorkspaceID, metadata.EnvironmentID).Scan(&bound)
	if err != nil {
		return false, databaseError("check credential runner scope binding", err)
	}
	return bound, nil
}

func resolvePrepareActionFence(ctx context.Context, tx pgx.Tx, fence credential.ActionFence, credentialExpiry time.Time) (credential.ActionMetadata, error) {
	return resolveActionFenceWithWindow(ctx, tx, fence, credentialExpiry, credential.MinPrepareFenceWindow, true)
}

func resolveActionFenceWithWindow(
	ctx context.Context,
	tx pgx.Tx,
	fence credential.ActionFence,
	credentialExpiry time.Time,
	minimumWindow time.Duration,
	lockForUpdate bool,
) (credential.ActionMetadata, error) {
	query := `
		SELECT action_id, runner_tenant_id::text, runner_workspace_id::text, runner_environment_id::text,
			target_key, production, runner_id, lease_epoch, status, lease_expires_at, authorization_expires_at,
			runner_pool, scope_revision, cancel_requested_at,
			envelope ->> 'action_type',
			envelope #>> '{credential_scope,connector_id}',
			envelope #>> '{credential_scope,permission}',
			envelope #>> '{credential_scope,resource}',
			CASE
				WHEN jsonb_typeof(envelope #> '{credential_scope,ttl_seconds}') = 'number'
				 AND (envelope #>> '{credential_scope,ttl_seconds}') COLLATE "C" ~ '^[1-9][0-9]{0,8}$'
				 AND pg_input_is_valid(envelope #>> '{credential_scope,ttl_seconds}', 'integer')
				THEN (envelope #>> '{credential_scope,ttl_seconds}')::integer
			END,
			statement_timestamp()
		FROM action_queue
		WHERE action_id = $1 AND runner_id = $2 AND lease_epoch = $3 AND lease_token_sha256 = $4
		  AND status IN ('LEASED', 'RUNNING') AND lease_expires_at > statement_timestamp()
		  AND authorization_expires_at > statement_timestamp()
	`
	args := []any{fence.ActionID, fence.RunnerID, fence.Epoch, credential.SHA256Hex([]byte(fence.Token))}
	if lockForUpdate {
		query += ` FOR UPDATE`
	} else {
		query += ` FOR SHARE`
	}
	var metadata credential.ActionMetadata
	var status string
	var databaseNow time.Time
	var cancelRequestedAt pgtype.Timestamptz
	var credentialTTLSeconds pgtype.Int4
	err := tx.QueryRow(ctx, query, args...).Scan(
		&metadata.ActionID, &metadata.TenantID, &metadata.WorkspaceID, &metadata.EnvironmentID,
		&metadata.TargetKey, &metadata.Production, &metadata.RunnerID, &metadata.LeaseEpoch, &status,
		&metadata.LeaseExpiresAt, &metadata.AuthorizationExpiresAt,
		&metadata.RunnerPool, &metadata.ScopeRevision, &cancelRequestedAt,
		&metadata.ActionType, &metadata.ConnectorID, &metadata.Permission, &metadata.Resource,
		&credentialTTLSeconds, &databaseNow,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.ActionMetadata{}, credential.ErrStaleActionFence
	}
	if err != nil {
		return credential.ActionMetadata{}, databaseError("resolve credential revocation action fence", err)
	}
	metadata.Status = credential.ActionStatus(status)
	metadata.LeaseExpiresAt = metadata.LeaseExpiresAt.UTC()
	metadata.AuthorizationExpiresAt = metadata.AuthorizationExpiresAt.UTC()
	metadata.CancelRequestedAt = timeValue(cancelRequestedAt)
	if !credentialTTLSeconds.Valid || !validTrustedCredentialBinding(metadata.ActionType, credentialTTLSeconds.Int32) {
		return credential.ActionMetadata{}, credential.ErrStaleActionFence
	}
	metadata.CredentialTTLSeconds = credentialTTLSeconds.Int32
	credentialExpiry = credential.CanonicalCredentialExpiry(credentialExpiry)
	if minimumWindow > 0 {
		minimumExpiry := databaseNow.Add(minimumWindow)
		if metadata.LeaseExpiresAt.Before(minimumExpiry) || metadata.AuthorizationExpiresAt.Before(minimumExpiry) {
			return credential.ActionMetadata{}, credential.ErrStaleActionFence
		}
	}
	if !credentialExpiry.IsZero() && (!credentialExpiry.After(databaseNow) || credentialExpiry.After(metadata.AuthorizationExpiresAt) ||
		credentialExpiry.After(credential.CanonicalCredentialExpiry(databaseNow.Add(credential.MaxCredentialTTL))) ||
		credentialExpiry.After(credential.CanonicalCredentialExpiry(databaseNow.Add(
			time.Duration(metadata.CredentialTTLSeconds)*time.Second)))) {
		return credential.ActionMetadata{}, credential.ErrInvalidRevocationRequest
	}
	return metadata, nil
}

func revalidatePrepareFence(
	ctx context.Context,
	tx pgx.Tx,
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
	if !sameResolvedActionScope(initial, current) || request.CredentialExpiresAt.After(current.AuthorizationExpiresAt) {
		return credential.ErrStaleActionFence
	}
	return nil
}

func sameResolvedActionScope(left, right credential.ActionMetadata) bool {
	return left.ActionID == right.ActionID && left.TenantID == right.TenantID && left.WorkspaceID == right.WorkspaceID &&
		left.EnvironmentID == right.EnvironmentID && left.TargetKey == right.TargetKey && left.Production == right.Production &&
		left.RunnerID == right.RunnerID && left.LeaseEpoch == right.LeaseEpoch && left.ActionType == right.ActionType &&
		left.ConnectorID == right.ConnectorID && left.Permission == right.Permission && left.Resource == right.Resource &&
		left.CredentialTTLSeconds == right.CredentialTTLSeconds
}

func validTrustedCredentialBinding(actionType string, ttlSeconds int32) bool {
	return credential.ValidIdentifier(actionType, 256) && ttlSeconds > 0 &&
		time.Duration(ttlSeconds)*time.Second <= credential.MaxCredentialTTL
}

func writeStateChange(ctx context.Context, tx pgx.Tx, revocation credential.Revocation, actorType, actorID, auditAction, eventType string) error {
	payload := map[string]any{
		"revocation_id":   revocation.ID,
		"action_id":       revocation.ActionID,
		"workspace_id":    revocation.WorkspaceID,
		"issuer":          revocation.Issuer,
		"issuer_revision": revocation.IssuerRevision,
		"attempt":         revocation.Attempt,
		"failure_count":   revocation.FailureCount,
	}
	if revocation.FailureCode != "" {
		payload["failure_code"] = revocation.FailureCode
	}
	if revocation.FailureDetailSHA256 != "" {
		payload["detail_hash"] = revocation.FailureDetailSHA256
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode credential revocation state change: %w", err)
	}
	metadata := requestmeta.From(ctx)
	if metadata.RequestID == "" {
		metadata.RequestID = ids.NewUUID()
	}
	if actorID == "" {
		actorID = "credential-repository"
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_records (
			id, tenant_id, workspace_id, actor_type, actor_id, action,
			resource_type, resource_id, request_id, trace_id, payload_hash, details
		) VALUES ($1, $2, $3, $4, $5, $6, 'CREDENTIAL_REVOCATION', $7, $8, $9, $10, $11)
	`, ids.NewUUID(), revocation.TenantID, revocation.WorkspaceID, actorType, actorID, auditAction,
		revocation.ID, metadata.RequestID, nullableText(metadata.TraceID), credential.SHA256Hex(encoded), string(encoded))
	if err != nil {
		return databaseError("insert credential revocation audit", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO outbox_events (
			id, tenant_id, workspace_id, aggregate_type, aggregate_id, aggregate_version,
			event_type, payload, created_at, available_at
		) VALUES ($1, $2, $3, 'CREDENTIAL_REVOCATION', $4, $5, $6, $7,
			statement_timestamp(), statement_timestamp())
	`, ids.NewUUID(), revocation.TenantID, revocation.WorkspaceID, revocation.ID, revocation.Version, eventType, string(encoded))
	if err != nil {
		return databaseError("insert credential revocation outbox event", err)
	}
	return nil
}

func (repository *Repository) RecordAnchor(ctx context.Context, request credential.RecordAnchorRequest) (credential.Revocation, error) {
	if err := validateContext(ctx); err != nil {
		return credential.Revocation{}, err
	}
	if !credential.ValidRevocationID(request.RevocationID) || !credential.ValidActionFence(request.Fence) ||
		!credential.ValidSensitiveReference(request.Accessor) {
		return credential.Revocation{}, credential.ErrInvalidRevocationRequest
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return credential.Revocation{}, databaseError("begin credential revocation anchor", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	inspection, databaseNow, registrationCurrent, err := inspectAction(ctx, tx, request.Fence.ActionID, request.Fence.RunnerID)
	if err != nil {
		return credential.Revocation{}, err
	}
	record, err := selectStored(ctx, tx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE revocation_id = $1
		FOR UPDATE
	`, request.RevocationID)
	if err != nil {
		return credential.Revocation{}, mapReadError("read credential revocation anchor", err)
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
		if err := tx.Commit(ctx); err != nil {
			return credential.Revocation{}, databaseError("commit idempotent credential revocation anchor", err)
		}
		committed = true
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
		return credential.Revocation{}, mapTransitionError("anchor credential revocation", err)
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
	if err := tx.Commit(ctx); err != nil {
		return credential.Revocation{}, databaseError("commit credential revocation anchor", err)
	}
	committed = true
	return publicRevocation(record), nil
}

func (repository *Repository) requestInvalidatedAnchor(
	ctx context.Context,
	tx pgx.Tx,
	revocationID, actorType, actorID string,
) (*storedRevocation, error) {
	record, err := selectStored(ctx, tx, `
		UPDATE credential_revocations
		SET status = 'REVOCATION_PENDING', available_at = statement_timestamp(),
			revocation_requested_at = statement_timestamp(), updated_at = statement_timestamp(),
			retry_cycle_attempt_base = attempt, retry_cycle_started_at = statement_timestamp(),
			version = version + 1
		WHERE revocation_id = $1 AND status IN ('ANCHORED', 'ACTIVE')
		RETURNING `+revocationProjection,
		revocationID)
	if err != nil {
		return nil, mapTransitionError("request invalidated anchored credential revocation", err)
	}
	if err := writeStateChange(ctx, tx, record.revocation, actorType, actorID,
		"credential.revocation.requested", "credential.revocation.requested.v1"); err != nil {
		return nil, err
	}
	return record, nil
}

func inspectAction(
	ctx context.Context,
	tx pgx.Tx,
	actionID, runnerHint string,
) (credential.ActionInspection, time.Time, bool, error) {
	registration, err := lockRunnerRegistration(ctx, tx, runnerHint)
	if err != nil {
		return credential.ActionInspection{}, time.Time{}, false, err
	}
	var inspection credential.ActionInspection
	var runnerID, leaseTokenSHA256 pgtype.Text
	var leaseExpiresAt pgtype.Timestamptz
	var scopeRevision pgtype.Int8
	var cancelRequestedAt pgtype.Timestamptz
	var credentialTTLSeconds pgtype.Int4
	var status string
	var databaseNow time.Time
	err = tx.QueryRow(ctx, `
		SELECT action.action_id, workspace.tenant_id::text, action.workspace_id, action.environment_id,
			action.target_key, action.production, action.runner_id, action.lease_epoch, action.status,
			action.lease_token_sha256, action.lease_expires_at, action.authorization_expires_at,
			action.runner_pool, action.scope_revision, action.cancel_requested_at,
			action.envelope ->> 'action_type',
			action.envelope #>> '{credential_scope,connector_id}',
			action.envelope #>> '{credential_scope,permission}',
			action.envelope #>> '{credential_scope,resource}',
			CASE
				WHEN jsonb_typeof(action.envelope #> '{credential_scope,ttl_seconds}') = 'number'
				 AND (action.envelope #>> '{credential_scope,ttl_seconds}') COLLATE "C" ~ '^[1-9][0-9]{0,8}$'
				 AND pg_input_is_valid(action.envelope #>> '{credential_scope,ttl_seconds}', 'integer')
				THEN (action.envelope #>> '{credential_scope,ttl_seconds}')::integer
			END,
			statement_timestamp()
		FROM action_queue AS action
		JOIN workspaces AS workspace ON workspace.id::text = action.workspace_id
		JOIN environments AS environment
		  ON environment.id::text = action.environment_id
		 AND environment.tenant_id = workspace.tenant_id
		 AND environment.workspace_id = workspace.id
		WHERE action.action_id = $1
		FOR SHARE OF action
	`, actionID).Scan(
		&inspection.Metadata.ActionID, &inspection.Metadata.TenantID, &inspection.Metadata.WorkspaceID,
		&inspection.Metadata.EnvironmentID, &inspection.Metadata.TargetKey, &inspection.Metadata.Production,
		&runnerID, &inspection.Metadata.LeaseEpoch, &status, &leaseTokenSHA256, &leaseExpiresAt,
		&inspection.Metadata.AuthorizationExpiresAt, &inspection.Metadata.RunnerPool, &scopeRevision, &cancelRequestedAt,
		&inspection.Metadata.ActionType, &inspection.Metadata.ConnectorID,
		&inspection.Metadata.Permission, &inspection.Metadata.Resource, &credentialTTLSeconds, &databaseNow,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.ActionInspection{}, time.Time{}, false, credential.ErrStaleActionFence
	}
	if err != nil {
		return credential.ActionInspection{}, time.Time{}, false, databaseError("inspect credential revocation action", err)
	}
	inspection.Metadata.RunnerID = textValue(runnerID)
	inspection.Metadata.Status = credential.ActionStatus(status)
	inspection.Metadata.LeaseExpiresAt = timeValue(leaseExpiresAt)
	inspection.Metadata.AuthorizationExpiresAt = inspection.Metadata.AuthorizationExpiresAt.UTC()
	inspection.Metadata.ScopeRevision = int64Value(scopeRevision)
	inspection.Metadata.CancelRequestedAt = timeValue(cancelRequestedAt)
	if !credentialTTLSeconds.Valid || !validTrustedCredentialBinding(inspection.Metadata.ActionType, credentialTTLSeconds.Int32) {
		return credential.ActionInspection{}, time.Time{}, false, credential.ErrStaleActionFence
	}
	inspection.Metadata.CredentialTTLSeconds = credentialTTLSeconds.Int32
	inspection.LeaseTokenSHA256 = textValue(leaseTokenSHA256)
	registrationCurrent := registration.matches(inspection.Metadata)
	if registrationCurrent {
		registrationCurrent, err = exactRunnerScopeBinding(ctx, tx, inspection.Metadata)
		if err != nil {
			return credential.ActionInspection{}, time.Time{}, false, err
		}
	}
	return inspection, databaseNow.UTC(), registrationCurrent, nil
}

type actionTransitionKind uint8

const (
	transitionNoCredential actionTransitionKind = iota + 1
	transitionRequestRevocation
)

func (repository *Repository) Activate(ctx context.Context, request credential.ActionTransitionRequest) (credential.Revocation, error) {
	if err := validateContext(ctx); err != nil {
		return credential.Revocation{}, err
	}
	if !credential.ValidRevocationID(request.RevocationID) || !credential.ValidActionFence(request.Fence) {
		return credential.Revocation{}, credential.ErrInvalidRevocationRequest
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return credential.Revocation{}, databaseError("begin credential revocation activation", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	inspection, databaseNow, registrationCurrent, err := inspectAction(ctx, tx, request.Fence.ActionID, request.Fence.RunnerID)
	if err != nil {
		return credential.Revocation{}, err
	}
	record, err := selectStored(ctx, tx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE revocation_id = $1
		FOR UPDATE
	`, request.RevocationID)
	if err != nil {
		return credential.Revocation{}, mapReadError("read credential revocation activation", err)
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
				return credential.Revocation{}, mapTransitionError("activate credential revocation", err)
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
	if err := tx.Commit(ctx); err != nil {
		return credential.Revocation{}, databaseError("commit credential revocation activation", err)
	}
	committed = true
	return publicRevocation(record), nil
}

func (repository *Repository) RecordNoCredential(ctx context.Context, request credential.ActionTransitionRequest) (credential.Revocation, error) {
	return repository.actionTransition(ctx, request, transitionNoCredential)
}

func (repository *Repository) RecoverPrepared(
	ctx context.Context,
	request credential.RecoverPreparedRequest,
) ([]credential.Revocation, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if request.Limit < 1 || request.Limit > credential.MaxRevocationClaimBatch {
		return nil, credential.ErrInvalidRevocationRequest
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return nil, databaseError("begin prepared credential recovery", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	rows, err := tx.Query(ctx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE status = 'PREPARED'
		  AND accessor_ciphertext IS NULL AND accessor_hmac IS NULL AND encryption_key_id IS NULL
		  AND credential_expires_at <= statement_timestamp() - interval '1 minute'
		ORDER BY credential_expires_at, revocation_id
		FOR UPDATE SKIP LOCKED
		LIMIT $1
	`, request.Limit)
	if err != nil {
		return nil, databaseError("select expired prepared credential revocations", err)
	}
	candidates := make([]*storedRevocation, 0, request.Limit)
	for rows.Next() {
		record, scanErr := scanStored(rows)
		if scanErr != nil {
			rows.Close()
			return nil, databaseError("scan expired prepared credential revocation", scanErr)
		}
		candidates = append(candidates, record)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, databaseError("read expired prepared credential revocations", err)
	}
	rows.Close()
	recovered := make([]credential.Revocation, 0, len(candidates))
	for _, candidate := range candidates {
		record, updateErr := selectStored(ctx, tx, `
			UPDATE credential_revocations
			SET status = 'NO_CREDENTIAL', updated_at = statement_timestamp(), version = version + 1
			WHERE revocation_id = $1 AND status = 'PREPARED'
			  AND accessor_ciphertext IS NULL AND accessor_hmac IS NULL AND encryption_key_id IS NULL
			  AND credential_expires_at <= statement_timestamp() - interval '1 minute'
			RETURNING `+revocationProjection,
			candidate.revocation.ID)
		if updateErr != nil {
			return nil, mapTransitionError("recover expired prepared credential revocation", updateErr)
		}
		if err := writeStateChange(ctx, tx, record.revocation, "SYSTEM", "credential-prepared-recovery",
			"credential.revocation.prepared_expired", "credential.revocation.prepared_expired.v1"); err != nil {
			return nil, err
		}
		recovered = append(recovered, publicRevocation(record))
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, databaseError("commit prepared credential recovery", err)
	}
	committed = true
	return recovered, nil
}

type managedRecoveryCandidate struct {
	revocationID string
	actionID     string
	runnerID     string
	managedAt    time.Time
}

// RecoverManaged deliberately scans candidates without taking credential row
// locks. Each candidate is then rechecked under the global authorization lock
// order: runner registration -> action -> exact scope -> credential.
func (repository *Repository) RecoverManaged(
	ctx context.Context,
	request credential.RecoverManagedRequest,
) ([]credential.Revocation, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if request.Limit < 1 || request.Limit > credential.MaxRevocationClaimBatch {
		return nil, credential.ErrInvalidRevocationRequest
	}
	rows, err := repository.database.Query(ctx, `
		SELECT credential.revocation_id::text, credential.action_id, credential.runner_id,
			COALESCE(credential.activated_at, credential.anchored_at) AS managed_at
		FROM credential_revocations AS credential
		WHERE credential.status IN ('ANCHORED', 'ACTIVE')
		  AND (
			(
				credential.status = 'ANCHORED' AND
				credential.anchored_at <= clock_timestamp() - make_interval(secs => $2::double precision)
			) OR NOT EXISTS (
				SELECT 1
				FROM action_queue AS action
				JOIN runner_registrations AS registration
				  ON registration.runner_id = credential.runner_id
				 AND registration.tenant_id = credential.tenant_id
				WHERE action.action_id = credential.action_id
				  AND action.status = 'RUNNING' AND action.cancel_requested_at IS NULL
				  AND action.runner_id = credential.runner_id
				  AND action.lease_epoch = credential.action_lease_epoch
				  AND action.lease_token_sha256 = credential.action_lease_token_sha256
				  AND action.runner_tenant_id = credential.tenant_id
				  AND action.runner_workspace_id = credential.workspace_id
				  AND action.runner_environment_id = credential.environment_id
				  AND action.target_key = credential.target_key
				  AND action.production = credential.production
				  AND action.runner_pool = 'WRITE'
				  AND action.scope_revision > 0
				  AND action.envelope ->> 'action_type' = credential.action_type
				  AND action.envelope #>> '{credential_scope,connector_id}' = credential.connector_id
				  AND action.envelope #>> '{credential_scope,permission}' = credential.scope_permission
				  AND action.envelope #>> '{credential_scope,resource}' = credential.scope_resource
				  AND action.envelope #>> '{credential_scope,ttl_seconds}' = credential.credential_ttl_seconds::text
				  AND action.lease_expires_at > clock_timestamp() + make_interval(secs => $3::double precision)
				  AND action.authorization_expires_at > clock_timestamp() + make_interval(secs => $3::double precision)
				  AND credential.credential_expires_at > clock_timestamp() + make_interval(secs => $3::double precision)
				  AND registration.enabled AND registration.runner_pool = 'WRITE'
				  AND registration.scope_revision = action.scope_revision
				  AND EXISTS (
					SELECT 1 FROM runner_scope_bindings AS binding
					WHERE binding.runner_id = credential.runner_id
					  AND binding.tenant_id = credential.tenant_id
					  AND binding.workspace_id = credential.workspace_id
					  AND binding.environment_id = credential.environment_id
				  )
			)
		  )
		ORDER BY managed_at, revocation_id
		LIMIT $1
	`, request.Limit, credential.ManagedAnchorRecoveryGrace.Seconds(), credential.MinPostChildFenceWindow.Seconds())
	if err != nil {
		return nil, databaseError("select managed credential recovery candidates", err)
	}
	candidates := make([]managedRecoveryCandidate, 0, request.Limit)
	for rows.Next() {
		var candidate managedRecoveryCandidate
		if scanErr := rows.Scan(&candidate.revocationID, &candidate.actionID, &candidate.runnerID, &candidate.managedAt); scanErr != nil {
			rows.Close()
			return nil, databaseError("scan managed credential recovery candidate", scanErr)
		}
		candidate.managedAt = candidate.managedAt.UTC()
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, databaseError("read managed credential recovery candidates", err)
	}
	rows.Close()

	recovered := make([]credential.Revocation, 0, len(candidates))
	for _, candidate := range candidates {
		revocation, transitioned, recoverErr := repository.recoverManagedCandidate(ctx, candidate)
		if recoverErr != nil {
			return recovered, recoverErr
		}
		if transitioned {
			recovered = append(recovered, revocation)
		}
	}
	return recovered, nil
}

func (repository *Repository) recoverManagedCandidate(
	ctx context.Context,
	candidate managedRecoveryCandidate,
) (credential.Revocation, bool, error) {
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return credential.Revocation{}, false, databaseError("begin managed credential recovery", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	inspection, _, registrationCurrent, err := inspectAction(ctx, tx, candidate.actionID, candidate.runnerID)
	if err != nil {
		return credential.Revocation{}, false, err
	}
	record, err := selectStored(ctx, tx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE revocation_id = $1
		FOR UPDATE
	`, candidate.revocationID)
	if err != nil {
		return credential.Revocation{}, false, mapReadError("lock managed credential recovery candidate", err)
	}
	if record.revocation.Status != credential.StatusAnchored && record.revocation.Status != credential.StatusActive {
		if err := tx.Commit(ctx); err != nil {
			return credential.Revocation{}, false, databaseError("commit idempotent managed credential recovery", err)
		}
		committed = true
		return credential.Revocation{}, false, nil
	}
	currentTime, err := databaseClockTime(ctx, tx)
	if err != nil {
		return credential.Revocation{}, false, err
	}
	current := storedInspectionScopeMatches(record, inspection.Metadata) &&
		storedInspectionFenceCurrent(record, inspection, currentTime, credential.MinPostChildFenceWindow, registrationCurrent)
	if record.revocation.Status == credential.StatusAnchored && current &&
		!record.revocation.AnchoredAt.Add(credential.ManagedAnchorRecoveryGrace).After(currentTime) {
		current = false
	}
	if current {
		if err := tx.Commit(ctx); err != nil {
			return credential.Revocation{}, false, databaseError("commit current managed credential recovery", err)
		}
		committed = true
		return credential.Revocation{}, false, nil
	}
	record, err = repository.requestInvalidatedAnchor(
		ctx, tx, record.revocation.ID, "SYSTEM", "credential-managed-recovery",
	)
	if err != nil {
		return credential.Revocation{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return credential.Revocation{}, false, databaseError("commit managed credential recovery", err)
	}
	committed = true
	return publicRevocation(record), true, nil
}

func (repository *Repository) RecoverExhausted(
	ctx context.Context,
	request credential.RecoverExhaustedRequest,
) ([]credential.Revocation, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if request.Limit < 1 || request.Limit > credential.MaxRevocationClaimBatch {
		return nil, credential.ErrInvalidRevocationRequest
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return nil, databaseError("begin exhausted credential recovery", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	rows, err := tx.Query(ctx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE (
			status = 'REVOCATION_PENDING'
			OR (status = 'REVOKING' AND claim_expires_at <= clock_timestamp())
		)
		  AND (
			attempt - retry_cycle_attempt_base >= $2
			OR retry_cycle_started_at <= clock_timestamp() - make_interval(secs => $3::double precision)
		  )
		ORDER BY retry_cycle_started_at, revocation_id
		FOR UPDATE SKIP LOCKED
		LIMIT $1
	`, request.Limit, credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds())
	if err != nil {
		return nil, databaseError("select exhausted credential revocations", err)
	}
	candidates := make([]*storedRevocation, 0, request.Limit)
	for rows.Next() {
		record, scanErr := scanStored(rows)
		if scanErr != nil {
			rows.Close()
			return nil, databaseError("scan exhausted credential revocation", scanErr)
		}
		candidates = append(candidates, record)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, databaseError("read exhausted credential revocations", err)
	}
	rows.Close()
	detailHash := credential.SHA256Hex([]byte(credential.FailureDetailExhaustedWithoutAck))
	recovered := make([]credential.Revocation, 0, len(candidates))
	for _, candidate := range candidates {
		record, updateErr := selectStored(ctx, tx, `
			UPDATE credential_revocations
			SET status = 'MANUAL_REQUIRED',
				claimed_by = NULL, claim_token_sha256 = NULL, claimed_at = NULL,
				claim_expires_at = NULL, last_heartbeat_at = NULL,
				failure_count = failure_count + 1, failure_code = $2, failure_detail_sha256 = $3,
				manual_required_at = statement_timestamp(), updated_at = statement_timestamp(), version = version + 1
			WHERE revocation_id = $1
			  AND (
				status = 'REVOCATION_PENDING'
				OR (status = 'REVOKING' AND claim_expires_at <= clock_timestamp())
			  )
			  AND (
				attempt - retry_cycle_attempt_base >= $4
				OR retry_cycle_started_at <= clock_timestamp() - make_interval(secs => $5::double precision)
			  )
			RETURNING `+revocationProjection,
			candidate.revocation.ID, string(credential.FailureUnknown), detailHash,
			credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds())
		if updateErr != nil {
			return nil, mapTransitionError("recover exhausted credential revocation", updateErr)
		}
		if err := writeStateChange(ctx, tx, record.revocation, "SYSTEM", "credential-revocation-recovery",
			"credential.revocation.manual_required", "credential.revocation.manual_required.v1"); err != nil {
			return nil, err
		}
		recovered = append(recovered, publicRevocation(record))
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, databaseError("commit exhausted credential recovery", err)
	}
	committed = true
	return recovered, nil
}

func (repository *Repository) RequestRevocation(ctx context.Context, request credential.ActionTransitionRequest) (credential.Revocation, error) {
	return repository.actionTransition(ctx, request, transitionRequestRevocation)
}

func (repository *Repository) actionTransition(ctx context.Context, request credential.ActionTransitionRequest, kind actionTransitionKind) (credential.Revocation, error) {
	if err := validateContext(ctx); err != nil {
		return credential.Revocation{}, err
	}
	recoveryRequest := kind == transitionRequestRevocation && request.Fence == (credential.ActionFence{})
	if !credential.ValidRevocationID(request.RevocationID) || (!recoveryRequest && !credential.ValidActionFence(request.Fence)) {
		return credential.Revocation{}, credential.ErrInvalidRevocationRequest
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return credential.Revocation{}, databaseError("begin credential revocation state transition", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	var metadata credential.ActionMetadata
	if !recoveryRequest {
		metadata, err = resolveActionFence(ctx, tx, request.Fence, time.Time{})
		if err != nil {
			return credential.Revocation{}, err
		}
	}
	record, err := selectStored(ctx, tx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE revocation_id = $1
		FOR UPDATE
	`, request.RevocationID)
	if err != nil {
		return credential.Revocation{}, mapReadError("read credential revocation transition", err)
	}
	if !recoveryRequest && !storedMatchesAction(record, request.Fence, metadata) {
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
		case credential.StatusRevocationPending, credential.StatusRevoking, credential.StatusManualRequired, credential.StatusRevoked:
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
			return credential.Revocation{}, mapTransitionError("update credential revocation state", err)
		}
		actorType, actorID := "RUNNER", request.Fence.RunnerID
		if recoveryRequest {
			actorType, actorID = "SYSTEM", ""
		}
		if err := writeStateChange(ctx, tx, record.revocation, actorType, actorID, auditAction, eventType); err != nil {
			return credential.Revocation{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return credential.Revocation{}, databaseError("commit credential revocation state transition", err)
	}
	committed = true
	return publicRevocation(record), nil
}

type preparedClaim struct {
	record   *storedRevocation
	token    string
	accessor *credential.SensitiveReference
}

func (repository *Repository) ClaimRevocations(ctx context.Context, request credential.ClaimRevocationsRequest) ([]credential.ClaimedRevocation, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if !credential.ValidIdentifier(request.WorkerID, 256) || request.Limit < 1 || request.Limit > credential.MaxRevocationClaimBatch ||
		!credential.ValidClaimDuration(request.LeaseDuration) {
		return nil, credential.ErrInvalidRevocationRequest
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return nil, databaseError("begin credential revocation claim", err)
	}
	committed := false
	prepared := make([]preparedClaim, 0, request.Limit)
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
			for _, claim := range prepared {
				claim.accessor.Destroy()
			}
		}
	}()
	rows, err := tx.Query(ctx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE (
			(status = 'REVOCATION_PENDING' AND available_at <= clock_timestamp())
			OR (status = 'REVOKING' AND claim_expires_at <= clock_timestamp())
		)
		  AND attempt - retry_cycle_attempt_base < $2
		  AND retry_cycle_started_at > clock_timestamp() - make_interval(secs => $3::double precision)
		ORDER BY available_at, created_at, revocation_id
		FOR UPDATE SKIP LOCKED
		LIMIT $1
	`, request.Limit, credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds())
	if err != nil {
		return nil, databaseError("select credential revocation claims", err)
	}
	candidates := make([]*storedRevocation, 0, request.Limit)
	for rows.Next() {
		record, scanErr := scanStored(rows)
		if scanErr != nil {
			rows.Close()
			return nil, databaseError("scan credential revocation claim", scanErr)
		}
		candidates = append(candidates, record)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, databaseError("read credential revocation claims", err)
	}
	rows.Close()
	for _, record := range candidates {
		if record.revocation.ClaimEpoch == math.MaxInt64 {
			return nil, credential.ErrInvalidTransition
		}
		token, tokenErr := repository.tokenSource()
		if tokenErr != nil || !credential.ValidOpaqueText(token, 4096) {
			return nil, fmt.Errorf("generate credential revocation claim token: %w", credential.ErrInvalidRevocationRequest)
		}
		digest := credential.SHA256Hex([]byte(token))
		updated, updateErr := selectStored(ctx, tx, `
			UPDATE credential_revocations
			SET status = 'REVOKING', claim_epoch = claim_epoch + 1,
				claimed_by = $2, claim_token_sha256 = $3,
				claimed_at = clock_timestamp(), last_heartbeat_at = clock_timestamp(),
				claim_expires_at = clock_timestamp() + make_interval(secs => $4::double precision),
				attempt = attempt + 1, updated_at = clock_timestamp(), version = version + 1
			WHERE revocation_id = $1 AND claim_epoch < 9223372036854775807
			  AND (
				(status = 'REVOCATION_PENDING' AND available_at <= clock_timestamp())
				OR (status = 'REVOKING' AND claim_expires_at <= clock_timestamp())
			  )
			  AND attempt - retry_cycle_attempt_base < $5
			  AND retry_cycle_started_at > clock_timestamp() - make_interval(secs => $6::double precision)
			RETURNING `+revocationProjection,
			record.revocation.ID, request.WorkerID, digest, request.LeaseDuration.Seconds(),
			credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds())
		if updateErr != nil {
			return nil, mapTransitionError("claim credential revocation", updateErr)
		}
		if err := writeStateChange(ctx, tx, updated.revocation, "SYSTEM", request.WorkerID,
			"credential.revocation.claimed", "credential.revocation.claimed.v1"); err != nil {
			return nil, err
		}
		accessor, openErr := repository.protector.Unprotect(referenceContext(updated.revocation), updated.protected)
		poison := openErr != nil || !credential.ValidSensitiveReference(accessor)
		if poison {
			if accessor != nil {
				accessor.Destroy()
			}
			detailHash := credential.SHA256Hex([]byte(credential.FailureDetailProtectedRefInvalid))
			quarantined, quarantineErr := selectStored(ctx, tx, `
				UPDATE credential_revocations
				SET status = 'MANUAL_REQUIRED',
					claimed_by = NULL, claim_token_sha256 = NULL, claimed_at = NULL,
					claim_expires_at = NULL, last_heartbeat_at = NULL,
					failure_count = failure_count + 1, failure_code = $5, failure_detail_sha256 = $6,
					manual_required_at = statement_timestamp(), updated_at = statement_timestamp(), version = version + 1
				WHERE revocation_id = $1 AND claimed_by = $2 AND claim_token_sha256 = $3
				  AND claim_epoch = $4 AND status = 'REVOKING'
				RETURNING `+revocationProjection,
				updated.revocation.ID, request.WorkerID, digest, updated.revocation.ClaimEpoch,
				string(credential.FailureInvalidReference), detailHash)
			if quarantineErr != nil {
				return nil, mapTransitionError("quarantine invalid credential reference", quarantineErr)
			}
			if err := writeStateChange(ctx, tx, quarantined.revocation, "SYSTEM", request.WorkerID,
				"credential.revocation.manual_required", "credential.revocation.manual_required.v1"); err != nil {
				return nil, err
			}
			continue
		}
		prepared = append(prepared, preparedClaim{record: updated, token: token, accessor: accessor})
	}

	claims := make([]credential.ClaimedRevocation, 0, len(prepared))
	for index := range prepared {
		item := &prepared[index]
		claims = append(claims, credential.ClaimedRevocation{
			Revocation: publicRevocation(item.record),
			Fence: credential.ClaimFence{
				RevocationID: item.record.revocation.ID, WorkerID: request.WorkerID,
				Token: item.token, Epoch: item.record.revocation.ClaimEpoch,
			},
			Accessor: item.accessor,
		})
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, databaseError("commit credential revocation claims", err)
	}
	committed = true
	return claims, nil
}

func (repository *Repository) Heartbeat(ctx context.Context, request credential.HeartbeatRequest) (credential.Revocation, error) {
	if err := validateContext(ctx); err != nil {
		return credential.Revocation{}, err
	}
	if !credential.ValidClaimFence(request.Fence) || !credential.ValidClaimDuration(request.Extension) {
		return credential.Revocation{}, credential.ErrInvalidRevocationRequest
	}
	record, err := selectStored(ctx, repository.database, `
		UPDATE credential_revocations
		SET last_heartbeat_at = statement_timestamp(),
			claim_expires_at = statement_timestamp() + make_interval(secs => $5::double precision),
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1 AND claimed_by = $2 AND claim_token_sha256 = $3 AND claim_epoch = $4
		  AND status = 'REVOKING' AND claim_expires_at > statement_timestamp()
		RETURNING `+revocationProjection,
		request.Fence.RevocationID, request.Fence.WorkerID, credential.SHA256Hex([]byte(request.Fence.Token)),
		request.Fence.Epoch, request.Extension.Seconds())
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.Revocation{}, repository.claimMiss(ctx, request.Fence)
	}
	if err != nil {
		return credential.Revocation{}, databaseError("heartbeat credential revocation", err)
	}
	return publicRevocation(record), nil
}

func (repository *Repository) CompleteRevocation(ctx context.Context, request credential.CompleteRevocationRequest) (credential.Revocation, error) {
	if err := validateContext(ctx); err != nil {
		return credential.Revocation{}, err
	}
	if !credential.ValidClaimFence(request.Fence) {
		return credential.Revocation{}, credential.ErrInvalidRevocationRequest
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return credential.Revocation{}, databaseError("begin credential revocation completion", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	digest := credential.SHA256Hex([]byte(request.Fence.Token))
	record, err := selectStored(ctx, tx, `
		UPDATE credential_revocations
		SET status = 'REVOKED',
			completed_claim_epoch = claim_epoch,
			completed_claim_token_sha256 = claim_token_sha256,
			completed_claimed_by = claimed_by,
			claimed_by = NULL, claim_token_sha256 = NULL, claimed_at = NULL,
			claim_expires_at = NULL, last_heartbeat_at = NULL,
			accessor_ciphertext = NULL, encryption_key_id = NULL,
			revoked_at = statement_timestamp(), updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1 AND claimed_by = $2 AND claim_token_sha256 = $3 AND claim_epoch = $4
		  AND status = 'REVOKING' AND claim_expires_at > statement_timestamp()
		RETURNING `+revocationProjection,
		request.Fence.RevocationID, request.Fence.WorkerID, digest, request.Fence.Epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		record, err = selectStored(ctx, tx, `
			SELECT `+revocationProjection+`
			FROM credential_revocations
			WHERE revocation_id = $1
			FOR SHARE
		`, request.Fence.RevocationID)
		if errors.Is(err, pgx.ErrNoRows) {
			return credential.Revocation{}, credential.ErrRevocationNotFound
		}
		if err != nil {
			return credential.Revocation{}, databaseError("read credential revocation completion", err)
		}
		if record.revocation.Status != credential.StatusRevoked || record.completedClaimTokenSHA256 != digest ||
			record.completedClaimEpoch != request.Fence.Epoch || record.completedClaimedBy != request.Fence.WorkerID {
			return credential.Revocation{}, credential.ErrStaleClaim
		}
		if err := tx.Commit(ctx); err != nil {
			return credential.Revocation{}, databaseError("commit idempotent credential revocation completion", err)
		}
		committed = true
		return publicRevocation(record), nil
	}
	if err != nil {
		return credential.Revocation{}, databaseError("complete credential revocation", err)
	}
	if err := writeStateChange(ctx, tx, record.revocation, "SYSTEM", request.Fence.WorkerID,
		"credential.revocation.completed", "credential.revocation.completed.v1"); err != nil {
		return credential.Revocation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return credential.Revocation{}, databaseError("commit credential revocation completion", err)
	}
	committed = true
	return publicRevocation(record), nil
}

func (repository *Repository) RetryRevocation(ctx context.Context, request credential.RetryRevocationRequest) (credential.Revocation, error) {
	if request.Delay < credential.MinRevocationRetryDelay || request.Delay > credential.MaxRevocationRetryDelay ||
		!credential.ValidFailure(request.FailureCode, request.FailureDetail) {
		return credential.Revocation{}, credential.ErrInvalidRevocationRequest
	}
	return repository.failClaim(ctx, request.Fence, request.FailureCode, request.FailureDetail, request.Delay, false)
}

func (repository *Repository) RequireManual(ctx context.Context, request credential.RequireManualRequest) (credential.Revocation, error) {
	if !credential.ValidFailure(request.FailureCode, request.FailureDetail) {
		return credential.Revocation{}, credential.ErrInvalidRevocationRequest
	}
	return repository.failClaim(ctx, request.Fence, request.FailureCode, request.FailureDetail, 0, true)
}

func (repository *Repository) failClaim(ctx context.Context, fence credential.ClaimFence, code credential.FailureCode, detail []byte, delay time.Duration, manual bool) (credential.Revocation, error) {
	if err := validateContext(ctx); err != nil {
		return credential.Revocation{}, err
	}
	if !credential.ValidClaimFence(fence) {
		return credential.Revocation{}, credential.ErrInvalidRevocationRequest
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return credential.Revocation{}, databaseError("begin failed credential revocation transition", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	digest := credential.SHA256Hex([]byte(fence.Token))
	detailHash := credential.SHA256Hex(detail)
	var lockedRevocationID string
	err = tx.QueryRow(ctx, `
		SELECT revocation_id::text
		FROM credential_revocations
		WHERE revocation_id = $1 AND claimed_by = $2 AND claim_token_sha256 = $3 AND claim_epoch = $4
		  AND status = 'REVOKING'
		FOR UPDATE
	`, fence.RevocationID, fence.WorkerID, digest, fence.Epoch).Scan(&lockedRevocationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.Revocation{}, repository.claimMissWith(ctx, tx, fence)
	}
	if err != nil {
		return credential.Revocation{}, databaseError("lock failed credential revocation transition", err)
	}
	if lockedRevocationID != fence.RevocationID {
		return credential.Revocation{}, credential.ErrRevocationPersistence
	}
	var transitionAt time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&transitionAt); err != nil {
		return credential.Revocation{}, databaseError("read failed credential revocation transition time", err)
	}
	transitionAt = transitionAt.UTC()
	var query, auditAction, eventType string
	if manual {
		query = `
			UPDATE credential_revocations
			SET status = 'MANUAL_REQUIRED',
				claimed_by = NULL, claim_token_sha256 = NULL, claimed_at = NULL,
				claim_expires_at = NULL, last_heartbeat_at = NULL,
				failure_count = failure_count + 1, failure_code = $5, failure_detail_sha256 = $6,
				manual_required_at = $7, updated_at = $7, version = version + 1
			WHERE revocation_id = $1 AND claimed_by = $2 AND claim_token_sha256 = $3 AND claim_epoch = $4
			  AND status = 'REVOKING' AND claim_expires_at > $7
			RETURNING ` + revocationProjection
		auditAction, eventType = "credential.revocation.manual_required", "credential.revocation.manual_required.v1"
	} else {
		query = `
			UPDATE credential_revocations
			SET status = CASE
					WHEN attempt - retry_cycle_attempt_base >= $8
					  OR retry_cycle_started_at <= $10 - make_interval(secs => $9::double precision)
					THEN 'MANUAL_REQUIRED'
					ELSE 'REVOCATION_PENDING'
				END,
				claimed_by = NULL, claim_token_sha256 = NULL, claimed_at = NULL,
				claim_expires_at = NULL, last_heartbeat_at = NULL,
				failure_count = failure_count + 1, failure_code = $5, failure_detail_sha256 = $6,
				available_at = CASE
					WHEN attempt - retry_cycle_attempt_base >= $8
					  OR retry_cycle_started_at <= $10 - make_interval(secs => $9::double precision)
					THEN available_at
					ELSE $10 + make_interval(secs => $7::double precision)
				END,
				manual_required_at = CASE
					WHEN attempt - retry_cycle_attempt_base >= $8
					  OR retry_cycle_started_at <= $10 - make_interval(secs => $9::double precision)
					THEN $10
					ELSE manual_required_at
				END,
				updated_at = $10, version = version + 1
			WHERE revocation_id = $1 AND claimed_by = $2 AND claim_token_sha256 = $3 AND claim_epoch = $4
			  AND status = 'REVOKING' AND claim_expires_at > $10
			RETURNING ` + revocationProjection
		auditAction, eventType = "credential.revocation.failed", "credential.revocation.failed.v1"
	}
	args := []any{fence.RevocationID, fence.WorkerID, digest, fence.Epoch, string(code), detailHash}
	if !manual {
		args = append(args, delay.Seconds(), credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds(), transitionAt)
	} else {
		args = append(args, transitionAt)
	}
	record, err := selectStored(ctx, tx, query, args...)
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.Revocation{}, repository.claimMissWith(ctx, tx, fence)
	}
	if err != nil {
		return credential.Revocation{}, databaseError("record failed credential revocation", err)
	}
	if !manual && record.revocation.Status == credential.StatusManualRequired {
		auditAction, eventType = "credential.revocation.manual_required", "credential.revocation.manual_required.v1"
	}
	if err := writeStateChange(ctx, tx, record.revocation, "SYSTEM", fence.WorkerID, auditAction, eventType); err != nil {
		return credential.Revocation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return credential.Revocation{}, databaseError("commit failed credential revocation transition", err)
	}
	committed = true
	return publicRevocation(record), nil
}

func (repository *Repository) RequeueManual(ctx context.Context, request credential.RequeueManualRequest) (credential.Revocation, error) {
	if err := validateContext(ctx); err != nil {
		return credential.Revocation{}, err
	}
	if !credential.ValidRevocationID(request.RevocationID) || !credential.ValidConfirmationSubject(request.ActorSubject) {
		return credential.Revocation{}, credential.ErrInvalidRevocationRequest
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return credential.Revocation{}, databaseError("begin manual credential revocation requeue", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	record, err := selectStored(ctx, tx, `
		UPDATE credential_revocations AS revocation
		SET status = 'REVOCATION_PENDING', available_at = statement_timestamp(),
			retry_cycle_attempt_base = attempt, retry_cycle_started_at = statement_timestamp(),
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation_id = $1 AND status = 'MANUAL_REQUIRED' AND evidence_hash IS NULL
		  AND NOT EXISTS (
			SELECT 1 FROM credential_revocation_confirmations AS confirmation
			WHERE confirmation.revocation_id = revocation.revocation_id
		  )
		RETURNING `+revocationProjection,
		request.RevocationID)
	if errors.Is(err, pgx.ErrNoRows) {
		record, err = selectStored(ctx, tx, `
			SELECT `+revocationProjection+`
			FROM credential_revocations
			WHERE revocation_id = $1
			FOR SHARE
		`, request.RevocationID)
		if errors.Is(err, pgx.ErrNoRows) {
			return credential.Revocation{}, credential.ErrRevocationNotFound
		}
		if err != nil {
			return credential.Revocation{}, databaseError("read manual credential revocation requeue", err)
		}
		if record.revocation.Status != credential.StatusRevocationPending {
			return credential.Revocation{}, credential.ErrInvalidTransition
		}
		if err := tx.Commit(ctx); err != nil {
			return credential.Revocation{}, databaseError("commit idempotent manual credential revocation requeue", err)
		}
		committed = true
		return publicRevocation(record), nil
	}
	if err != nil {
		return credential.Revocation{}, databaseError("requeue manual credential revocation", err)
	}
	if err := writeStateChange(ctx, tx, record.revocation, "USER", request.ActorSubject,
		"credential.revocation.requeued", "credential.revocation.requeued.v1"); err != nil {
		return credential.Revocation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return credential.Revocation{}, databaseError("commit manual credential revocation requeue", err)
	}
	committed = true
	return publicRevocation(record), nil
}

func (repository *Repository) SubmitExternalConfirmation(ctx context.Context, request credential.ExternalConfirmationRequest) (credential.ConfirmationResult, error) {
	if err := validateContext(ctx); err != nil {
		return credential.ConfirmationResult{}, err
	}
	if !credential.ValidRevocationID(request.RevocationID) || !credential.ValidConfirmationSubject(request.Subject) ||
		!credential.ValidSHA256(request.EvidenceHash) {
		return credential.ConfirmationResult{}, credential.ErrInvalidRevocationRequest
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return credential.ConfirmationResult{}, databaseError("begin credential revocation confirmation", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	record, err := selectStored(ctx, tx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE revocation_id = $1
		FOR UPDATE
	`, request.RevocationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.ConfirmationResult{}, credential.ErrRevocationNotFound
	}
	if err != nil {
		return credential.ConfirmationResult{}, databaseError("read credential revocation confirmation state", err)
	}
	if record.revocation.Status != credential.StatusManualRequired && record.revocation.Status != credential.StatusRevoked {
		return credential.ConfirmationResult{}, credential.ErrInvalidTransition
	}
	if record.revocation.EvidenceHash != "" && record.revocation.EvidenceHash != request.EvidenceHash {
		return credential.ConfirmationResult{}, credential.ErrEvidenceConflict
	}
	confirmations, err := readConfirmations(ctx, tx, request.RevocationID)
	if err != nil {
		return credential.ConfirmationResult{}, err
	}
	for _, confirmation := range confirmations {
		if confirmation.Subject != request.Subject {
			continue
		}
		if confirmation.EvidenceHash != request.EvidenceHash || confirmation.PlatformAdmin != request.PlatformAdmin {
			return credential.ConfirmationResult{}, credential.ErrEvidenceConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return credential.ConfirmationResult{}, databaseError("commit idempotent credential revocation confirmation", err)
		}
		committed = true
		return credential.ConfirmationResult{Revocation: publicRevocation(record), Confirmations: confirmations}, nil
	}
	if record.revocation.Status == credential.StatusRevoked || len(confirmations) >= 2 {
		return credential.ConfirmationResult{}, credential.ErrInvalidTransition
	}
	if len(confirmations) == 1 && !request.PlatformAdmin && !confirmations[0].PlatformAdmin {
		return credential.ConfirmationResult{}, credential.ErrPlatformAdminRequired
	}
	if len(confirmations) == 0 {
		if record.revocation.EvidenceHash != "" {
			return credential.ConfirmationResult{}, credential.ErrEvidenceConflict
		}
		record, err = selectStored(ctx, tx, `
			UPDATE credential_revocations
			SET evidence_hash = $2, updated_at = statement_timestamp(), version = version + 1
			WHERE revocation_id = $1 AND status = 'MANUAL_REQUIRED' AND evidence_hash IS NULL
			RETURNING `+revocationProjection,
			request.RevocationID, request.EvidenceHash)
		if err != nil {
			return credential.ConfirmationResult{}, mapTransitionError("record credential revocation evidence", err)
		}
	}
	var createdAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO credential_revocation_confirmations (
			revocation_id, subject, evidence_hash, platform_admin
		) VALUES ($1, $2, $3, $4)
		RETURNING created_at
	`, request.RevocationID, request.Subject, request.EvidenceHash, request.PlatformAdmin).Scan(&createdAt)
	if isUniqueViolation(err) {
		return credential.ConfirmationResult{}, credential.ErrEvidenceConflict
	}
	if err != nil {
		return credential.ConfirmationResult{}, databaseError("insert credential revocation confirmation", err)
	}
	confirmations = append(confirmations, credential.ExternalConfirmation{
		Subject: request.Subject, EvidenceHash: request.EvidenceHash,
		PlatformAdmin: request.PlatformAdmin, CreatedAt: createdAt.UTC(),
	})
	if len(confirmations) == 2 {
		record, err = selectStored(ctx, tx, `
			UPDATE credential_revocations
			SET status = 'REVOKED', accessor_ciphertext = NULL, encryption_key_id = NULL,
				revoked_at = statement_timestamp(), updated_at = statement_timestamp(), version = version + 1
			WHERE revocation_id = $1 AND status = 'MANUAL_REQUIRED' AND evidence_hash = $2
			RETURNING `+revocationProjection,
			request.RevocationID, request.EvidenceHash)
		if err != nil {
			return credential.ConfirmationResult{}, mapTransitionError("complete externally confirmed credential revocation", err)
		}
		if err := writeStateChange(ctx, tx, record.revocation, "USER", request.Subject,
			"credential.revocation.externally_confirmed", "credential.revocation.externally_confirmed.v1"); err != nil {
			return credential.ConfirmationResult{}, err
		}
	} else {
		if err := writeStateChange(ctx, tx, record.revocation, "USER", request.Subject,
			"credential.revocation.confirmation_recorded", "credential.revocation.confirmation_recorded.v1"); err != nil {
			return credential.ConfirmationResult{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return credential.ConfirmationResult{}, databaseError("commit credential revocation confirmation", err)
	}
	committed = true
	return credential.ConfirmationResult{Revocation: publicRevocation(record), Confirmations: confirmations}, nil
}

func (repository *Repository) Get(ctx context.Context, revocationID string) (credential.Revocation, error) {
	if err := validateContext(ctx); err != nil {
		return credential.Revocation{}, err
	}
	if !credential.ValidRevocationID(revocationID) {
		return credential.Revocation{}, credential.ErrInvalidRevocationRequest
	}
	record, err := selectStored(ctx, repository.database, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE revocation_id = $1
	`, revocationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.Revocation{}, credential.ErrRevocationNotFound
	}
	if err != nil {
		return credential.Revocation{}, databaseError("get credential revocation", err)
	}
	return publicRevocation(record), nil
}

func (repository *Repository) InspectCleanup(ctx context.Context, actionID string, epoch int64) (bool, bool, error) {
	if err := validateContext(ctx); err != nil {
		return false, false, err
	}
	if !credential.ValidIdentifier(actionID, 256) || epoch <= 0 {
		return false, false, credential.ErrInvalidRevocationRequest
	}
	var status credential.RevocationStatus
	err := repository.database.QueryRow(ctx, `
		SELECT status
		FROM credential_revocations
		WHERE action_id = $1 AND action_lease_epoch = $2
	`, actionID, epoch).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, databaseError("inspect credential cleanup", err)
	}
	return true, status == credential.StatusRevoked || status == credential.StatusNoCredential, nil
}

func (repository *Repository) List(ctx context.Context, filter credential.ListFilter) ([]credential.Revocation, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if (filter.WorkspaceID != "" && !credential.ValidIdentifier(filter.WorkspaceID, 256)) ||
		(filter.Status != "" && !credential.ValidRevocationStatus(filter.Status)) || filter.Limit < 1 || filter.Limit > 1000 {
		return nil, credential.ErrInvalidRevocationRequest
	}
	rows, err := repository.database.Query(ctx, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE ($1 = '' OR workspace_id::text = $1)
		  AND ($2 = '' OR status = $2)
		ORDER BY created_at, revocation_id
		LIMIT $3
	`, filter.WorkspaceID, string(filter.Status), filter.Limit)
	if err != nil {
		return nil, databaseError("list credential revocations", err)
	}
	defer rows.Close()
	items := make([]credential.Revocation, 0, filter.Limit)
	for rows.Next() {
		record, scanErr := scanStored(rows)
		if scanErr != nil {
			return nil, databaseError("scan credential revocation list", scanErr)
		}
		items = append(items, publicRevocation(record))
	}
	if err := rows.Err(); err != nil {
		return nil, databaseError("read credential revocation list", err)
	}
	return items, nil
}

func readConfirmations(ctx context.Context, tx pgx.Tx, revocationID string) ([]credential.ExternalConfirmation, error) {
	rows, err := tx.Query(ctx, `
		SELECT subject, evidence_hash, platform_admin, created_at
		FROM credential_revocation_confirmations
		WHERE revocation_id = $1
		ORDER BY created_at, subject
	`, revocationID)
	if err != nil {
		return nil, databaseError("read credential revocation confirmations", err)
	}
	defer rows.Close()
	confirmations := make([]credential.ExternalConfirmation, 0, 2)
	for rows.Next() {
		var confirmation credential.ExternalConfirmation
		if err := rows.Scan(&confirmation.Subject, &confirmation.EvidenceHash, &confirmation.PlatformAdmin, &confirmation.CreatedAt); err != nil {
			return nil, databaseError("scan credential revocation confirmation", err)
		}
		confirmation.CreatedAt = confirmation.CreatedAt.UTC()
		confirmations = append(confirmations, confirmation)
	}
	if err := rows.Err(); err != nil {
		return nil, databaseError("iterate credential revocation confirmations", err)
	}
	return confirmations, nil
}

type rowScanner interface {
	Scan(...any) error
}

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func selectStored(ctx context.Context, querier rowQuerier, query string, args ...any) (*storedRevocation, error) {
	return scanStored(querier.QueryRow(ctx, query, args...))
}

func scanStored(row rowScanner) (*storedRevocation, error) {
	var record storedRevocation
	var status string
	var ciphertext, accessorHMAC []byte
	var permitSHA256, encryptionKeyID, claimedBy, claimToken, completedToken, completedBy pgtype.Text
	var failureCode, failureDetail, evidenceHash pgtype.Text
	var childCreateAuthorizedAt, claimedAt, claimExpiresAt, heartbeatAt, retryCycleStartedAt pgtype.Timestamptz
	var anchoredAt, activatedAt, requestedAt, manualAt, revokedAt pgtype.Timestamptz
	var completedEpoch pgtype.Int8
	var childCreateTTLSeconds pgtype.Int4
	var attempt, retryCycleAttemptBase, failureCount int32
	err := row.Scan(
		&record.revocation.ID, &record.revocation.TenantID, &record.revocation.WorkspaceID, &record.revocation.EnvironmentID,
		&record.revocation.ActionID, &record.revocation.TargetKey, &record.revocation.Production,
		&record.revocation.RunnerID, &record.revocation.ActionLeaseEpoch, &record.actionTokenSHA256,
		&record.revocation.Issuer, &record.revocation.IssuerRevision, &record.revocation.ActionType,
		&record.revocation.ConnectorID, &record.revocation.Permission, &record.revocation.Resource,
		&record.revocation.CredentialTTLSeconds, &record.revocation.CredentialExpiresAt,
		&permitSHA256, &childCreateAuthorizedAt, &childCreateTTLSeconds, &status,
		&ciphertext, &accessorHMAC, &encryptionKeyID,
		&record.revocation.ClaimEpoch, &claimedBy, &claimToken, &claimedAt, &claimExpiresAt, &heartbeatAt,
		&completedEpoch, &completedToken, &completedBy,
		&attempt, &retryCycleAttemptBase, &retryCycleStartedAt,
		&failureCount, &failureCode, &failureDetail, &record.revocation.AvailableAt, &evidenceHash,
		&anchoredAt, &activatedAt, &requestedAt, &manualAt, &revokedAt,
		&record.revocation.Version, &record.revocation.CreatedAt, &record.revocation.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if !validTrustedCredentialBinding(record.revocation.ActionType, record.revocation.CredentialTTLSeconds) {
		return nil, credential.ErrRevocationPersistence
	}
	record.revocation.Status = credential.RevocationStatus(status)
	record.childCreatePermitSHA256 = textValue(permitSHA256)
	record.childCreateAuthorizedAt = timeValue(childCreateAuthorizedAt)
	if childCreateTTLSeconds.Valid {
		record.childCreateTTL = time.Duration(childCreateTTLSeconds.Int32) * time.Second
	}
	record.revocation.AccessorPresent = len(ciphertext) > 0
	if len(accessorHMAC) > 0 {
		record.revocation.AccessorHMAC = hex.EncodeToString(accessorHMAC)
	}
	record.revocation.EncryptionKeyID = textValue(encryptionKeyID)
	record.revocation.ClaimedBy = textValue(claimedBy)
	record.claimTokenSHA256 = textValue(claimToken)
	record.completedClaimEpoch = int64Value(completedEpoch)
	record.completedClaimTokenSHA256 = textValue(completedToken)
	record.completedClaimedBy = textValue(completedBy)
	record.revocation.ClaimedAt = timeValue(claimedAt)
	record.revocation.ClaimExpiresAt = timeValue(claimExpiresAt)
	record.revocation.LastHeartbeatAt = timeValue(heartbeatAt)
	record.revocation.Attempt = int(attempt)
	record.retryCycleAttemptBase = int(retryCycleAttemptBase)
	record.retryCycleStartedAt = timeValue(retryCycleStartedAt)
	record.revocation.FailureCount = int(failureCount)
	record.revocation.FailureCode = credential.FailureCode(textValue(failureCode))
	record.revocation.FailureDetailSHA256 = textValue(failureDetail)
	record.revocation.EvidenceHash = textValue(evidenceHash)
	record.revocation.AnchoredAt = timeValue(anchoredAt)
	record.revocation.ActivatedAt = timeValue(activatedAt)
	record.revocation.RevocationRequestedAt = timeValue(requestedAt)
	record.revocation.ManualRequiredAt = timeValue(manualAt)
	record.revocation.RevokedAt = timeValue(revokedAt)
	record.revocation.CredentialExpiresAt = record.revocation.CredentialExpiresAt.UTC()
	record.revocation.AvailableAt = record.revocation.AvailableAt.UTC()
	record.revocation.CreatedAt = record.revocation.CreatedAt.UTC()
	record.revocation.UpdatedAt = record.revocation.UpdatedAt.UTC()
	record.protected = credential.ProtectedReference{
		Ciphertext: bytes.Clone(ciphertext), AccessorHMAC: bytes.Clone(accessorHMAC), KeyID: textValue(encryptionKeyID),
	}
	return &record, nil
}

func (repository *Repository) claimMiss(ctx context.Context, fence credential.ClaimFence) error {
	return repository.claimMissWith(ctx, repository.database, fence)
}

func (repository *Repository) claimMissWith(ctx context.Context, querier rowQuerier, fence credential.ClaimFence) error {
	_, err := selectStored(ctx, querier, `
		SELECT `+revocationProjection+`
		FROM credential_revocations
		WHERE revocation_id = $1
	`, fence.RevocationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.ErrRevocationNotFound
	}
	if err != nil {
		return databaseError("read credential revocation claim state", err)
	}
	return credential.ErrStaleClaim
}

func samePrepare(record *storedRevocation, request credential.PrepareRequest, metadata credential.ActionMetadata, tokenDigest string) bool {
	revocation := record.revocation
	return revocation.ActionID == metadata.ActionID &&
		revocation.TenantID == metadata.TenantID && revocation.WorkspaceID == metadata.WorkspaceID &&
		revocation.EnvironmentID == metadata.EnvironmentID && revocation.TargetKey == metadata.TargetKey &&
		revocation.Production == metadata.Production && revocation.RunnerID == metadata.RunnerID &&
		revocation.ActionLeaseEpoch == metadata.LeaseEpoch && record.actionTokenSHA256 == tokenDigest &&
		revocation.Issuer == request.Issuer && revocation.IssuerRevision == request.IssuerRevision &&
		revocation.ActionType == metadata.ActionType && revocation.CredentialTTLSeconds == metadata.CredentialTTLSeconds &&
		revocation.ConnectorID == metadata.ConnectorID &&
		revocation.Permission == metadata.Permission && revocation.Resource == metadata.Resource &&
		revocation.CredentialExpiresAt.Equal(credential.CanonicalCredentialExpiry(request.CredentialExpiresAt))
}

func storedMatchesAction(record *storedRevocation, fence credential.ActionFence, metadata credential.ActionMetadata) bool {
	revocation := record.revocation
	return revocation.ActionID == fence.ActionID && revocation.RunnerID == fence.RunnerID &&
		revocation.ActionLeaseEpoch == fence.Epoch && record.actionTokenSHA256 == credential.SHA256Hex([]byte(fence.Token)) &&
		revocation.TenantID == metadata.TenantID && revocation.WorkspaceID == metadata.WorkspaceID &&
		revocation.EnvironmentID == metadata.EnvironmentID && revocation.TargetKey == metadata.TargetKey &&
		revocation.Production == metadata.Production && revocation.ActionType == metadata.ActionType &&
		revocation.CredentialTTLSeconds == metadata.CredentialTTLSeconds && revocation.ConnectorID == metadata.ConnectorID &&
		revocation.Permission == metadata.Permission && revocation.Resource == metadata.Resource
}

func storedFrozenFenceMatches(record *storedRevocation, fence credential.ActionFence) bool {
	return record.revocation.ActionID == fence.ActionID && record.revocation.RunnerID == fence.RunnerID &&
		record.revocation.ActionLeaseEpoch == fence.Epoch &&
		record.actionTokenSHA256 == credential.SHA256Hex([]byte(fence.Token))
}

func storedInspectionScopeMatches(record *storedRevocation, metadata credential.ActionMetadata) bool {
	revocation := record.revocation
	return revocation.ActionID == metadata.ActionID && revocation.TenantID == metadata.TenantID &&
		revocation.WorkspaceID == metadata.WorkspaceID && revocation.EnvironmentID == metadata.EnvironmentID &&
		revocation.TargetKey == metadata.TargetKey && revocation.Production == metadata.Production &&
		revocation.ActionType == metadata.ActionType && revocation.CredentialTTLSeconds == metadata.CredentialTTLSeconds &&
		revocation.ConnectorID == metadata.ConnectorID && revocation.Permission == metadata.Permission &&
		revocation.Resource == metadata.Resource
}

func storedInspectionFenceCurrent(
	record *storedRevocation,
	inspection credential.ActionInspection,
	now time.Time,
	minimumWindow time.Duration,
	runnerRegistrationCurrent bool,
) bool {
	metadata := inspection.Metadata
	minimumExpiry := now.Add(minimumWindow)
	return runnerRegistrationCurrent && metadata.Status == credential.ActionStatusRunning && metadata.CancelRequestedAt.IsZero() &&
		metadata.RunnerID == record.revocation.RunnerID && metadata.LeaseEpoch == record.revocation.ActionLeaseEpoch &&
		inspection.LeaseTokenSHA256 == record.actionTokenSHA256 && metadata.LeaseExpiresAt.After(minimumExpiry) &&
		metadata.AuthorizationExpiresAt.After(minimumExpiry) && record.revocation.CredentialExpiresAt.After(minimumExpiry)
}

func databaseTime(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT statement_timestamp()`).Scan(&now); err != nil {
		return time.Time{}, databaseError("read credential revocation database time", err)
	}
	return now.UTC(), nil
}

func databaseClockTime(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return time.Time{}, databaseError("read credential child creation database time", err)
	}
	return now.UTC(), nil
}

func referenceContext(revocation credential.Revocation) credential.ReferenceContext {
	return credential.ReferenceContext{
		RevocationID: revocation.ID, ActionID: revocation.ActionID,
		ActionEpoch: revocation.ActionLeaseEpoch, Issuer: revocation.Issuer,
		IssuerRevision: revocation.IssuerRevision,
	}
}

func publicRevocation(record *storedRevocation) credential.Revocation {
	return record.revocation
}

func mapReadError(operation string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.ErrRevocationNotFound
	}
	return databaseError(operation, err)
}

func mapTransitionError(operation string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.ErrInvalidTransition
	}
	return databaseError(operation, err)
}

func databaseError(operation string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%s: %w", operation, credential.ErrRevocationPersistence)
}

func textValue(value pgtype.Text) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func int64Value(value pgtype.Int8) int64 {
	if !value.Valid {
		return 0
	}
	return value.Int64
}

func timeValue(value pgtype.Timestamptz) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return value.Time.UTC()
}

func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func validateContext(ctx context.Context) error {
	if ctx == nil {
		return credential.ErrInvalidRevocationRequest
	}
	return ctx.Err()
}

func isUniqueViolation(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "23505"
}

func randomToken() (string, error) {
	value := make([]byte, 32)
	defer clear(value)
	if _, err := cryptorand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
