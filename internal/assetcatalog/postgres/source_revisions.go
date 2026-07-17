package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

const (
	sourceRevisionCreatedEvent     = "asset.source.revision.created.v1"
	sourceValidationRequestedEvent = "asset.source.validation.requested.v1"
	sourceRevisionPublishedEvent   = "asset.source.revision.published.v1"
	sourceDisabledEvent            = "asset.source.disabled.v1"
	sourceSyncRequestedEvent       = "asset.source.sync.requested.v1"
	sourceInitialCreateReason      = "INITIAL_CREATE"
)

const sourceCreateIdempotencyConstraint = "asset_sources_workspace_id_create_idempotency_key_key"

var lockSourceMutationSQL = `
SELECT ` + sourceProjectionSQL("source") + `
FROM asset_sources AS source
WHERE source.tenant_id=$1::uuid
  AND source.workspace_id=$2::uuid
  AND source.id=$3::uuid
FOR UPDATE OF source
`

const lockSourceRevisionMutationSQL = `
SELECT revision.id::text,revision.source_id::text,revision.tenant_id::text,
       revision.workspace_id::text,revision.revision,revision.state,
       revision.canonical_profile_manifest,revision.profile_manifest_sha256,
       revision.canonical_provider_schema,revision.canonical_provider_schema_sha256,
       revision.source_definition_digest,revision.canonical_revision_digest,
       revision.integration_id::text,revision.sync_mode,
       revision.credential_reference_id,revision.trust_reference_id,
       revision.network_policy_reference_id,revision.authority_scope_digest,
       revision.rate_limit_requests,revision.rate_limit_window_seconds,
       revision.backpressure_base_seconds,revision.backpressure_max_seconds,
       revision.profile_code,revision.schedule_expression,
       revision.typed_extension_code,revision.prepared_extension_digest,
       revision.validation_run_id::text,revision.validation_digest,
       revision.created_by,revision.change_reason_code,
       revision.expected_source_version,revision.version,
       revision.created_at,revision.updated_at
FROM asset_source_revisions AS revision
WHERE revision.tenant_id=$1::uuid
  AND revision.workspace_id=$2::uuid
  AND revision.source_id=$3::uuid
  AND revision.revision=$4
FOR UPDATE OF revision
`

var lockSourceRunMutationSQL = `
SELECT ` + sourceRunProjectionSQL("run") + `
FROM asset_source_runs AS run
WHERE run.tenant_id=$1::uuid
  AND run.workspace_id=$2::uuid
  AND run.source_id=$3::uuid
  AND run.id=$4::uuid
FOR UPDATE OF run
`

const sourceMutationAuditLookupSQL = `
SELECT id::text,actor_id,action,resource_type,resource_id,payload_hash,trace_id,details
FROM audit_records
WHERE tenant_id=$1::uuid
  AND workspace_id=$2::uuid
  AND request_id=$3
`

const insertSourceMutationAuditSQL = `
INSERT INTO audit_records (
    id,tenant_id,workspace_id,actor_type,actor_id,action,
    resource_type,resource_id,request_id,trace_id,payload_hash,details
) VALUES (
    $1::uuid,$2::uuid,$3::uuid,'USER',$4,$5,
    'ASSET_SOURCE',$6,$7,$8,$9,$10::jsonb
)
`

const insertSourceMutationOutboxSQL = `
INSERT INTO outbox_events (
    id,tenant_id,workspace_id,aggregate_type,aggregate_id,
    aggregate_version,event_type,payload
) VALUES (
    $1::uuid,$2::uuid,$3::uuid,$4,$5::uuid,
    $6,$7,$8::jsonb
)
`

type sourceMutationAuditDetails struct {
	CommandSHA256   string `json:"command_sha256"`
	SourceID        string `json:"source_id"`
	ReasonCode      string `json:"reason_code,omitempty"`
	Revision        int64  `json:"revision,omitempty"`
	RunID           string `json:"run_id,omitempty"`
	SourceVersion   int64  `json:"source_version"`
	RevisionVersion int64  `json:"revision_version,omitempty"`
	RunVersion      int64  `json:"run_version,omitempty"`
}

type sourceMutationAuditRecord struct {
	ID, ActorID, Action, ResourceType, ResourceID string
	PayloadHash, TraceID                          string
	Details                                       sourceMutationAuditDetails
}

type sourceOutboxPayload struct {
	SourceID        string `json:"source_id"`
	Revision        int64  `json:"revision,omitempty"`
	RunID           string `json:"run_id,omitempty"`
	SourceVersion   int64  `json:"source_version"`
	RevisionVersion int64  `json:"revision_version,omitempty"`
	RunVersion      int64  `json:"run_version,omitempty"`
	TraceID         string `json:"trace_id"`
}

type sourceCreationAuditDetails struct {
	CommandSHA256   string `json:"command_sha256"`
	SourceID        string `json:"source_id"`
	OutboxID        string `json:"outbox_id"`
	ReasonCode      string `json:"reason_code"`
	Revision        int64  `json:"revision"`
	RunID           string `json:"run_id,omitempty"`
	SourceVersion   int64  `json:"source_version"`
	RevisionVersion int64  `json:"revision_version"`
	RunVersion      int64  `json:"run_version,omitempty"`
}

type sourceCreationAuditRecord struct {
	ID, ActorID, Action, ResourceType, ResourceID string
	PayloadHash, TraceID                          string
	Details                                       sourceCreationAuditDetails
}

type sourceCreationOutboxPayload struct {
	AuditID         string `json:"audit_id"`
	SourceID        string `json:"source_id"`
	Revision        int64  `json:"revision"`
	RunID           string `json:"run_id,omitempty"`
	SourceVersion   int64  `json:"source_version"`
	RevisionVersion int64  `json:"revision_version"`
	RunVersion      int64  `json:"run_version,omitempty"`
	TraceID         string `json:"trace_id"`
}

func (repository *Repository) CreateSource(
	ctx context.Context,
	command assetcatalog.CreateSourceCommand,
) (assetcatalog.SourceRevisionMutation, error) {
	command = command.Clone()
	slices.Sort(command.AuthorityEnvironmentIDs)
	scope, commandHash, err := validateCreateSourceCommand(command)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	profile, err := assetcatalog.NewBuiltinSourceProfileRegistry().Resolve(command.SourceProfileID)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	ids, err := repository.allocateIDs(4)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	return withSourceCreationSerializable(ctx, repository, func(
		tx pgx.Tx,
		receiptRequired bool,
	) (assetcatalog.SourceRevisionMutation, error) {
		return repository.createSourceInTx(
			ctx, tx, scope, command, commandHash, profile, ids, receiptRequired,
		)
	})
}

func (repository *Repository) CreateRevision(
	ctx context.Context,
	command assetcatalog.CreateSourceRevisionCommand,
) (assetcatalog.SourceRevisionMutation, error) {
	command = command.Clone()
	slices.Sort(command.AuthorityEnvironmentIDs)
	scope, commandHash, err := validateCreateSourceRevisionCommand(command)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	profile, err := assetcatalog.NewBuiltinSourceProfileRegistry().Resolve(command.SourceProfileID)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	ids, err := repository.allocateIDs(3)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	return withSourceRevisionSerializable(ctx, repository, func(tx pgx.Tx) (assetcatalog.SourceRevisionMutation, error) {
		return repository.createRevisionInTx(ctx, tx, scope, command, commandHash, profile, ids)
	})
}

func (repository *Repository) RequestValidation(
	ctx context.Context,
	command assetcatalog.ValidateSourceRevisionCommand,
) (assetcatalog.SourceRunMutation, error) {
	scope, commandHash, err := validateSourceRevisionValidationCommand(command)
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	ids, err := repository.allocateIDs(5)
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	fenceTokenHash, err := randomFenceTokenHash()
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	return withSourceRevisionSerializable(ctx, repository, func(tx pgx.Tx) (assetcatalog.SourceRunMutation, error) {
		return repository.requestValidationInTx(ctx, tx, scope, command, commandHash, ids, fenceTokenHash)
	})
}

func (repository *Repository) Publish(
	ctx context.Context,
	command assetcatalog.PublishSourceRevisionCommand,
) (assetcatalog.SourceRevisionMutation, error) {
	scope, commandHash, err := validatePublishSourceRevisionCommand(command)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	ids, err := repository.allocateIDs(2)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	return withSourceRevisionSerializable(ctx, repository, func(tx pgx.Tx) (assetcatalog.SourceRevisionMutation, error) {
		return repository.publishRevisionInTx(ctx, tx, scope, command, commandHash, ids)
	})
}

func (repository *Repository) Disable(
	ctx context.Context,
	command assetcatalog.DisableSourceCommand,
) (assetcatalog.SourceMutation, error) {
	scope, commandHash, err := validateDisableSourceCommand(command)
	if err != nil {
		return assetcatalog.SourceMutation{}, err
	}
	ids, err := repository.allocateIDs(2)
	if err != nil {
		return assetcatalog.SourceMutation{}, err
	}
	return withSourceRevisionSerializable(ctx, repository, func(tx pgx.Tx) (assetcatalog.SourceMutation, error) {
		return repository.disableSourceInTx(ctx, tx, scope, command, commandHash, ids)
	})
}

func (repository *Repository) RequestSync(
	ctx context.Context,
	command assetcatalog.RequestSyncCommand,
) (assetcatalog.SourceRunMutation, error) {
	scope, commandHash, err := validateRequestSyncCommand(command)
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	ids, err := repository.allocateIDs(3)
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	return withSourceRevisionSerializable(ctx, repository, func(tx pgx.Tx) (assetcatalog.SourceRunMutation, error) {
		return repository.requestSyncInTx(ctx, tx, scope, command, commandHash, ids)
	})
}

func withSourceRevisionSerializable[T any](
	ctx context.Context,
	repository *Repository,
	operation func(pgx.Tx) (T, error),
) (T, error) {
	var zero T
	for attempt := 0; attempt < serializableAttempts; attempt++ {
		tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{
			IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite,
		})
		if err != nil {
			return zero, mapSourceRevisionError(err)
		}
		result, operationErr := operation(tx)
		if operationErr != nil {
			_ = tx.Rollback(ctx)
			if isRetryablePGError(operationErr) && attempt+1 < serializableAttempts {
				if err := waitForRetry(ctx, attempt); err != nil {
					return zero, err
				}
				continue
			}
			return zero, mapSourceRevisionError(operationErr)
		}
		if err := tx.Commit(ctx); err != nil {
			if isRetryablePGError(err) && attempt+1 < serializableAttempts {
				if waitErr := waitForRetry(ctx, attempt); waitErr != nil {
					return zero, waitErr
				}
				continue
			}
			return zero, mapSourceRevisionError(err)
		}
		return result, nil
	}
	return zero, assetcatalog.ErrStateConflict
}

func withSourceCreationSerializable[T any](
	ctx context.Context,
	repository *Repository,
	operation func(pgx.Tx, bool) (T, error),
) (T, error) {
	var zero T
	for attempt := 0; attempt < serializableAttempts; attempt++ {
		tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{
			IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite,
		})
		if err != nil {
			return zero, mapSourceRevisionError(err)
		}
		result, operationErr := operation(tx, false)
		if operationErr != nil {
			_ = tx.Rollback(ctx)
			if isSourceCreationReplayRace(operationErr) {
				if err := waitForRetry(ctx, attempt); err != nil {
					return zero, err
				}
				return withSourceCreationReceipt(ctx, repository, operation)
			}
			if isRetryablePGError(operationErr) && attempt+1 < serializableAttempts {
				if err := waitForRetry(ctx, attempt); err != nil {
					return zero, err
				}
				continue
			}
			return zero, mapSourceRevisionError(operationErr)
		}
		if err := tx.Commit(ctx); err != nil {
			if isSourceCreationReplayRace(err) {
				if waitErr := waitForRetry(ctx, attempt); waitErr != nil {
					return zero, waitErr
				}
				return withSourceCreationReceipt(ctx, repository, operation)
			}
			if isRetryablePGError(err) && attempt+1 < serializableAttempts {
				if waitErr := waitForRetry(ctx, attempt); waitErr != nil {
					return zero, waitErr
				}
				continue
			}
			return zero, mapSourceRevisionError(err)
		}
		return result, nil
	}
	return zero, assetcatalog.ErrStateConflict
}

func withSourceCreationReceipt[T any](
	ctx context.Context,
	repository *Repository,
	operation func(pgx.Tx, bool) (T, error),
) (T, error) {
	var zero T
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite,
	})
	if err != nil {
		return zero, mapSourceRevisionError(err)
	}
	result, operationErr := operation(tx, true)
	if operationErr != nil {
		_ = tx.Rollback(ctx)
		return zero, mapSourceRevisionError(operationErr)
	}
	if err := tx.Commit(ctx); err != nil {
		return zero, mapSourceRevisionError(err)
	}
	return result, nil
}

func isSourceCreationReplayRace(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) &&
		postgresError.Code == "23505" &&
		postgresError.ConstraintName == sourceCreateIdempotencyConstraint
}

func prepareSourceMutation(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	idempotencyKey string,
) error {
	var tenantID, workspaceID string
	err := tx.QueryRow(ctx, `
SELECT tenant_id::text,id::text
FROM workspaces
WHERE tenant_id=$1::uuid AND id=$2::uuid
`, scope.TenantID, scope.WorkspaceID).Scan(&tenantID, &workspaceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return assetcatalog.ErrScopeViolation
	}
	if err != nil {
		return err
	}
	if tenantID != scope.TenantID || workspaceID != scope.WorkspaceID {
		return assetcatalog.ErrScopeViolation
	}
	_, err = tx.Exec(ctx, lockIdempotencySQL, scope.TenantID, scope.WorkspaceID, idempotencyKey)
	return err
}

func lockSourceMutation(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	sourceID string,
) (assetcatalog.Source, error) {
	var projection []byte
	if err := tx.QueryRow(
		ctx, lockSourceMutationSQL, scope.TenantID, scope.WorkspaceID, sourceID,
	).Scan(&projection); err != nil {
		return assetcatalog.Source{}, err
	}
	var wire sourceProjectionWire
	if !decodeStrictProjection(projection, &wire) {
		return assetcatalog.Source{}, assetcatalog.ErrStateConflict
	}
	source, ok := wire.finish()
	if !ok {
		return assetcatalog.Source{}, assetcatalog.ErrStateConflict
	}
	return source.Clone(), nil
}

func lockSourceRevisionMutation(
	ctx context.Context,
	tx pgx.Tx,
	source assetcatalog.Source,
	revision int64,
) (assetcatalog.SourceRevision, error) {
	var (
		value                                           assetcatalog.SourceRevision
		integrationID, credentialID, trustID, networkID *string
		schedule, extensionCode, extensionDigest        *string
		validationRunID, validationDigest               *string
	)
	if err := tx.QueryRow(
		ctx, lockSourceRevisionMutationSQL,
		source.TenantID, source.WorkspaceID, source.ID, revision,
	).Scan(
		&value.ID, &value.SourceID, &value.TenantID, &value.WorkspaceID,
		&value.Revision, &value.Status,
		&value.CanonicalProfileManifest, &value.ProfileManifestSHA256,
		&value.CanonicalProviderSchema, &value.CanonicalProviderSchemaSHA256,
		&value.SourceDefinitionDigest, &value.CanonicalRevisionDigest,
		&integrationID, &value.SyncMode, &credentialID, &trustID, &networkID,
		&value.AuthorityScopeDigest, &value.RateLimitRequests, &value.RateLimitWindowSeconds,
		&value.BackpressureBaseSeconds, &value.BackpressureMaxSeconds,
		&value.ProfileCode, &schedule, &extensionCode, &extensionDigest,
		&validationRunID, &validationDigest, &value.CreatedBy, &value.ChangeReasonCode,
		&value.ExpectedSourceVersion, &value.Version, &value.CreatedAt, &value.UpdatedAt,
	); err != nil {
		return assetcatalog.SourceRevision{}, err
	}
	value.IntegrationID = optionalString(integrationID)
	value.CredentialReferenceID = assetcatalog.CredentialReferenceID(optionalString(credentialID))
	value.TrustReferenceID = assetcatalog.TrustReferenceID(optionalString(trustID))
	value.NetworkPolicyReferenceID = assetcatalog.NetworkPolicyReferenceID(optionalString(networkID))
	value.ScheduleExpression = optionalString(schedule)
	value.TypedExtensionCode = assetcatalog.ExtensionCode(optionalString(extensionCode))
	value.PreparedExtensionDigest = optionalString(extensionDigest)
	value.ValidationRunID = optionalString(validationRunID)
	value.ValidationDigest = optionalString(validationDigest)
	value.CreatedAt = canonicalDatabaseTime(value.CreatedAt)
	value.UpdatedAt = canonicalDatabaseTime(value.UpdatedAt)
	rows, err := tx.Query(ctx, readManualAuthoritiesSQL,
		source.TenantID, source.WorkspaceID, source.ID, value.Revision)
	if err != nil {
		return assetcatalog.SourceRevision{}, err
	}
	defer rows.Close()
	expectedOrdinal := 1
	for rows.Next() {
		var environmentID string
		var ordinal int
		if err := rows.Scan(&environmentID, &ordinal); err != nil {
			return assetcatalog.SourceRevision{}, err
		}
		if ordinal != expectedOrdinal {
			return assetcatalog.SourceRevision{}, assetcatalog.ErrStateConflict
		}
		value.AuthorityEnvironmentIDs = append(value.AuthorityEnvironmentIDs, environmentID)
		expectedOrdinal++
	}
	if err := rows.Err(); err != nil {
		return assetcatalog.SourceRevision{}, err
	}
	if value.SourceID != source.ID || value.TenantID != source.TenantID ||
		value.WorkspaceID != source.WorkspaceID || value.Validate() != nil {
		return assetcatalog.SourceRevision{}, assetcatalog.ErrStateConflict
	}
	return value.Clone(), nil
}

func lockSourceRunMutation(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	sourceID, runID string,
) (assetcatalog.SourceRun, error) {
	var projection []byte
	if err := tx.QueryRow(
		ctx, lockSourceRunMutationSQL, scope.TenantID, scope.WorkspaceID, sourceID, runID,
	).Scan(&projection); err != nil {
		return assetcatalog.SourceRun{}, err
	}
	var wire sourceRunProjectionWire
	if !decodeStrictProjection(projection, &wire) {
		return assetcatalog.SourceRun{}, assetcatalog.ErrStateConflict
	}
	run, ok := wire.finish()
	if !ok {
		return assetcatalog.SourceRun{}, assetcatalog.ErrStateConflict
	}
	return run.Clone(), nil
}

func validateSourceRunReplayIdentity(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	sourceID, runID string,
	commandContext assetcatalog.MutationContext,
) error {
	var idempotencyKey, requestHash string
	if err := tx.QueryRow(ctx, `
SELECT idempotency_key,request_hash
FROM asset_source_runs
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
  AND source_id=$3::uuid AND id=$4::uuid
`, scope.TenantID, scope.WorkspaceID, sourceID, runID).Scan(&idempotencyKey, &requestHash); err != nil {
		return err
	}
	if idempotencyKey != commandContext.IdempotencyKey() ||
		requestHash != commandContext.RequestHash() {
		return assetcatalog.ErrIdempotency
	}
	return nil
}

func findSourceMutationAudit(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	idempotencyKey string,
) (sourceMutationAuditRecord, bool, error) {
	var record sourceMutationAuditRecord
	var traceID *string
	var details []byte
	err := tx.QueryRow(
		ctx, sourceMutationAuditLookupSQL, scope.TenantID, scope.WorkspaceID, idempotencyKey,
	).Scan(
		&record.ID, &record.ActorID, &record.Action, &record.ResourceType, &record.ResourceID,
		&record.PayloadHash, &traceID, &details,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return sourceMutationAuditRecord{}, false, nil
	}
	if err != nil {
		return sourceMutationAuditRecord{}, false, err
	}
	if traceID == nil || !validUUID(record.ID) || decodeStrictJSON(details, &record.Details) != nil {
		return sourceMutationAuditRecord{}, false, assetcatalog.ErrStateConflict
	}
	record.TraceID = *traceID
	return record, true, nil
}

func validateSourceMutationAudit(
	commandContext assetcatalog.MutationContext,
	commandHash, action, sourceID, reasonCode string,
	record sourceMutationAuditRecord,
) error {
	if record.ActorID != commandContext.ActorID() || record.Action != action ||
		record.ResourceType != "ASSET_SOURCE" || record.ResourceID != sourceID ||
		record.PayloadHash != commandContext.RequestHash() ||
		record.Details.CommandSHA256 != commandHash || record.Details.SourceID != sourceID ||
		record.Details.ReasonCode != reasonCode {
		return assetcatalog.ErrIdempotency
	}
	return nil
}

func findSourceCreationAudit(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	idempotencyKey string,
) (sourceCreationAuditRecord, bool, error) {
	var record sourceCreationAuditRecord
	var traceID *string
	var details []byte
	err := tx.QueryRow(
		ctx, sourceMutationAuditLookupSQL, scope.TenantID, scope.WorkspaceID, idempotencyKey,
	).Scan(
		&record.ID, &record.ActorID, &record.Action, &record.ResourceType, &record.ResourceID,
		&record.PayloadHash, &traceID, &details,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return sourceCreationAuditRecord{}, false, nil
	}
	if err != nil {
		return sourceCreationAuditRecord{}, false, err
	}
	if traceID == nil || !validUUID(record.ID) || decodeStrictJSON(details, &record.Details) != nil {
		return sourceCreationAuditRecord{}, false, assetcatalog.ErrStateConflict
	}
	record.TraceID = *traceID
	return record, true, nil
}

func validateSourceCreationAudit(
	commandContext assetcatalog.MutationContext,
	commandHash, sourceID string,
	record sourceCreationAuditRecord,
) error {
	if record.ActorID != commandContext.ActorID() ||
		record.Action != sourceRevisionCreatedEvent ||
		record.ResourceType != "ASSET_SOURCE" || record.ResourceID != sourceID ||
		record.PayloadHash != commandContext.RequestHash() ||
		record.Details.CommandSHA256 != commandHash ||
		record.Details.SourceID != sourceID ||
		record.Details.ReasonCode != sourceInitialCreateReason {
		return assetcatalog.ErrIdempotency
	}
	return nil
}

func insertSourceCreationSideEffects(
	ctx context.Context,
	tx pgx.Tx,
	ids []string,
	commandContext assetcatalog.MutationContext,
	commandHash string,
	source assetcatalog.Source,
	revision assetcatalog.SourceRevision,
) (assetcatalog.MutationReceipt, error) {
	if len(ids) != 2 {
		return assetcatalog.MutationReceipt{}, assetcatalog.ErrStateConflict
	}
	detailsJSON, err := json.Marshal(sourceCreationAuditDetails{
		CommandSHA256: commandHash,
		SourceID:      source.ID,
		OutboxID:      ids[1],
		ReasonCode:    sourceInitialCreateReason,
		Revision:      revision.Revision,
		SourceVersion: source.Version, RevisionVersion: revision.Version,
	})
	if err != nil {
		return assetcatalog.MutationReceipt{}, assetcatalog.ErrStateConflict
	}
	if _, err := tx.Exec(
		ctx, insertSourceMutationAuditSQL,
		ids[0], source.TenantID, source.WorkspaceID, commandContext.ActorID(),
		sourceRevisionCreatedEvent, source.ID, commandContext.IdempotencyKey(),
		commandContext.TraceID(), commandContext.RequestHash(), string(detailsJSON),
	); err != nil {
		return assetcatalog.MutationReceipt{}, err
	}
	payloadJSON, err := json.Marshal(sourceCreationOutboxPayload{
		AuditID:       ids[0],
		SourceID:      source.ID,
		Revision:      revision.Revision,
		SourceVersion: source.Version, RevisionVersion: revision.Version,
		TraceID: commandContext.TraceID(),
	})
	if err != nil {
		return assetcatalog.MutationReceipt{}, assetcatalog.ErrStateConflict
	}
	if _, err := tx.Exec(
		ctx, insertSourceMutationOutboxSQL,
		ids[1], source.TenantID, source.WorkspaceID, "ASSET_SOURCE", source.ID,
		source.Version, sourceRevisionCreatedEvent, string(payloadJSON),
	); err != nil {
		return assetcatalog.MutationReceipt{}, err
	}
	return assetcatalog.MutationReceipt{
		AuditID: ids[0], TraceID: commandContext.TraceID(), IdempotentReplay: false,
	}, nil
}

func insertSourceMutationSideEffects(
	ctx context.Context,
	tx pgx.Tx,
	ids []string,
	commandContext assetcatalog.MutationContext,
	commandHash, action, reasonCode string,
	source assetcatalog.Source,
	revision *assetcatalog.SourceRevision,
	run *assetcatalog.SourceRun,
) (assetcatalog.MutationReceipt, error) {
	if len(ids) != 2 {
		return assetcatalog.MutationReceipt{}, assetcatalog.ErrStateConflict
	}
	details := sourceMutationAuditDetails{
		CommandSHA256: commandHash,
		SourceID:      source.ID, ReasonCode: reasonCode, SourceVersion: source.Version,
	}
	payload := sourceOutboxPayload{
		SourceID: source.ID, SourceVersion: source.Version, TraceID: commandContext.TraceID(),
	}
	if revision != nil {
		details.Revision = revision.Revision
		details.RevisionVersion = revision.Version
		payload.Revision = revision.Revision
		payload.RevisionVersion = revision.Version
	}
	if run != nil {
		details.RunID = run.ID
		details.RunVersion = run.Version
		payload.RunID = run.ID
		payload.RunVersion = run.Version
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return assetcatalog.MutationReceipt{}, assetcatalog.ErrStateConflict
	}
	if _, err := tx.Exec(
		ctx, insertSourceMutationAuditSQL,
		ids[0], source.TenantID, source.WorkspaceID, commandContext.ActorID(), action,
		source.ID, commandContext.IdempotencyKey(), commandContext.TraceID(),
		commandContext.RequestHash(), string(detailsJSON),
	); err != nil {
		return assetcatalog.MutationReceipt{}, err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return assetcatalog.MutationReceipt{}, assetcatalog.ErrStateConflict
	}
	aggregateType := "ASSET_SOURCE"
	aggregateID := source.ID
	aggregateVersion := source.Version
	if run != nil {
		aggregateType = "ASSET_SOURCE_RUN"
		aggregateID = run.ID
		aggregateVersion = run.Version
	}
	if _, err := tx.Exec(
		ctx, insertSourceMutationOutboxSQL,
		ids[1], source.TenantID, source.WorkspaceID, aggregateType, aggregateID,
		aggregateVersion, action, string(payloadJSON),
	); err != nil {
		return assetcatalog.MutationReceipt{}, err
	}
	return assetcatalog.MutationReceipt{
		AuditID: ids[0], TraceID: commandContext.TraceID(), IdempotentReplay: false,
	}, nil
}

func sourceReplayReceipt(record sourceMutationAuditRecord) assetcatalog.MutationReceipt {
	return assetcatalog.MutationReceipt{
		AuditID: record.ID, TraceID: record.TraceID, IdempotentReplay: true,
	}
}

func sourceCreationReplayReceipt(record sourceCreationAuditRecord) assetcatalog.MutationReceipt {
	return assetcatalog.MutationReceipt{
		AuditID: record.ID, TraceID: record.TraceID, IdempotentReplay: true,
	}
}

func nullableSourceString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (repository *Repository) createSourceInTx(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	command assetcatalog.CreateSourceCommand,
	commandHash string,
	profile assetcatalog.BuiltinSourceProfile,
	ids []string,
	receiptRequired bool,
) (assetcatalog.SourceRevisionMutation, error) {
	if len(ids) != 4 {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrStateConflict
	}
	if err := prepareSourceMutation(ctx, tx, scope, command.Context.IdempotencyKey()); err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	record, found, err := findSourceCreationAudit(ctx, tx, scope, command.Context.IdempotencyKey())
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	authorities := slices.Clone(command.AuthorityEnvironmentIDs)
	slices.Sort(authorities)
	if found {
		if !validUUID(record.ResourceID) {
			return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrIdempotency
		}
		if err := validateSourceCreationAudit(
			command.Context, commandHash, record.ResourceID, record,
		); err != nil {
			return assetcatalog.SourceRevisionMutation{}, err
		}
		source, err := lockSourceMutation(ctx, tx, scope, record.ResourceID)
		if err != nil {
			return assetcatalog.SourceRevisionMutation{}, err
		}
		if record.Details.Revision != 1 {
			return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrIdempotency
		}
		revision, err := lockSourceRevisionMutation(ctx, tx, source, record.Details.Revision)
		if err != nil {
			return assetcatalog.SourceRevisionMutation{}, err
		}
		replay, err := sourceCreationReplay(
			ctx, tx, command, source, revision, profile, authorities, record,
		)
		if err != nil {
			return assetcatalog.SourceRevisionMutation{}, err
		}
		replay.Receipt = sourceCreationReplayReceipt(record)
		return replay.Clone(), nil
	}
	if receiptRequired {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrStateConflict
	}
	if err := validateResolvedSourceAuthorities(ctx, tx, scope, profile, authorities); err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	source := assetcatalog.Source{
		ID: ids[0], TenantID: scope.TenantID, WorkspaceID: scope.WorkspaceID,
		ProviderKind: profile.ProviderKind, Name: command.Name, Kind: profile.SourceKind,
		Status: assetcatalog.SourceStatusActive, GateStatus: assetcatalog.SourceGateUnavailable,
		Version: 1,
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO asset_sources (
    id,tenant_id,workspace_id,source_kind,provider_kind,name,
    create_idempotency_key,create_request_hash
) VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8)
`, source.ID, source.TenantID, source.WorkspaceID, source.Kind, source.ProviderKind,
		source.Name, command.Context.IdempotencyKey(), command.Context.RequestHash(),
	); err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	revision, err := newSourceRevision(
		source, profile, authorities, ids[1], 1, 1,
		command.Context.ActorID(), sourceInitialCreateReason,
	)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	if err := insertSourceRevisionInTx(ctx, tx, revision); err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	source, err = lockSourceMutation(ctx, tx, scope, source.ID)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	revision, err = lockSourceRevisionMutation(ctx, tx, source, revision.Revision)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	if !sourceHasExactInitialCreateState(source, command.Name) ||
		!sourceRevisionMatchesResolvedProfile(source, revision, profile) ||
		revision.Revision != 1 || revision.Status != assetcatalog.SourceRevisionDraft ||
		revision.ExpectedSourceVersion != 1 || revision.Version != 1 ||
		revision.ChangeReasonCode != sourceInitialCreateReason ||
		!slices.Equal(revision.AuthorityEnvironmentIDs, authorities) {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrStateConflict
	}
	receipt, err := insertSourceCreationSideEffects(
		ctx, tx, ids[2:], command.Context, commandHash, source, revision,
	)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	return assetcatalog.SourceRevisionMutation{
		Source: source, Revision: revision, Receipt: receipt,
	}.Clone(), nil
}

func sourceCreationReplay(
	ctx context.Context,
	tx pgx.Tx,
	command assetcatalog.CreateSourceCommand,
	currentSource assetcatalog.Source,
	currentRevision assetcatalog.SourceRevision,
	profile assetcatalog.BuiltinSourceProfile,
	authorities []string,
	record sourceCreationAuditRecord,
) (assetcatalog.SourceRevisionMutation, error) {
	var idempotencyKey, requestHash string
	if err := tx.QueryRow(ctx, `
SELECT create_idempotency_key,create_request_hash
FROM asset_sources
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, currentSource.TenantID, currentSource.WorkspaceID, currentSource.ID).Scan(
		&idempotencyKey, &requestHash,
	); err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	if idempotencyKey != command.Context.IdempotencyKey() ||
		requestHash != command.Context.RequestHash() {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrIdempotency
	}
	if record.Details.SourceVersion != 2 || record.Details.Revision != 1 ||
		record.Details.RevisionVersion != 1 ||
		record.Details.RunID != "" || record.Details.RunVersion != 0 ||
		!validUUID(record.Details.OutboxID) ||
		currentSource.ID != record.ResourceID ||
		currentSource.Kind != profile.SourceKind ||
		currentSource.ProviderKind != profile.ProviderKind ||
		currentRevision.ID == "" || currentRevision.Revision != 1 ||
		currentRevision.ExpectedSourceVersion != 1 ||
		currentRevision.CreatedBy != command.Context.ActorID() ||
		currentRevision.ChangeReasonCode != sourceInitialCreateReason ||
		!slices.Equal(currentRevision.AuthorityEnvironmentIDs, authorities) ||
		!sourceRevisionMatchesResolvedProfile(currentSource, currentRevision, profile) {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrStateConflict
	}
	if err := validateSourceCreationOutbox(ctx, tx, currentSource, record); err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	source := assetcatalog.Source{
		ID: currentSource.ID, TenantID: currentSource.TenantID, WorkspaceID: currentSource.WorkspaceID,
		ProviderKind: profile.ProviderKind, Name: command.Name, Kind: profile.SourceKind,
		Status: assetcatalog.SourceStatusActive, GateStatus: assetcatalog.SourceGateUnavailable,
		Version:   record.Details.SourceVersion,
		CreatedAt: currentSource.CreatedAt, UpdatedAt: currentRevision.CreatedAt,
	}
	revision, err := newSourceRevision(
		source, profile, authorities, currentRevision.ID, 1, 1,
		command.Context.ActorID(), sourceInitialCreateReason,
	)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	revision.CreatedAt = currentRevision.CreatedAt
	revision.UpdatedAt = currentRevision.CreatedAt
	if !sourceHasExactInitialCreateState(source, command.Name) ||
		source.Validate() != nil || revision.Validate() != nil {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrStateConflict
	}
	return assetcatalog.SourceRevisionMutation{
		Source: source, Revision: revision,
	}.Clone(), nil
}

func validateSourceCreationOutbox(
	ctx context.Context,
	tx pgx.Tx,
	source assetcatalog.Source,
	record sourceCreationAuditRecord,
) error {
	var count int
	var outboxID string
	var encodedPayload string
	if err := tx.QueryRow(ctx, `
SELECT count(*),COALESCE(min(id::text),''),COALESCE(min(payload::text),'')
FROM outbox_events
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
  AND aggregate_type='ASSET_SOURCE' AND aggregate_id=$3::uuid
  AND aggregate_version=$4 AND event_type=$5
`, source.TenantID, source.WorkspaceID, source.ID,
		record.Details.SourceVersion, sourceRevisionCreatedEvent,
	).Scan(&count, &outboxID, &encodedPayload); err != nil {
		return err
	}
	var payload sourceCreationOutboxPayload
	if count != 1 || decodeStrictJSON([]byte(encodedPayload), &payload) != nil ||
		outboxID != record.Details.OutboxID ||
		payload.AuditID != record.ID ||
		payload.SourceID != source.ID ||
		payload.Revision != record.Details.Revision ||
		payload.RunID != "" ||
		payload.SourceVersion != record.Details.SourceVersion ||
		payload.RevisionVersion != record.Details.RevisionVersion ||
		payload.RunVersion != 0 ||
		payload.TraceID != record.TraceID {
		return assetcatalog.ErrStateConflict
	}
	return nil
}

func sourceHasExactInitialCreateState(source assetcatalog.Source, name string) bool {
	return source.Name == name &&
		source.Status == assetcatalog.SourceStatusActive &&
		source.GateStatus == assetcatalog.SourceGateUnavailable &&
		source.GateReasonCode == "" && source.GateRevision == 0 &&
		source.PublishedRevision == 0 && source.PublishedRevisionDigest == "" &&
		source.ValidatedRunID == "" && source.ValidationDigest == "" &&
		source.ValidatedBindingDigest == "" && source.CheckpointSHA256 == "" &&
		source.CheckpointVersion == 0 && source.CheckpointSourceRevision == 0 &&
		source.NextAllowedAt == nil && source.ConsecutiveFailures == 0 &&
		source.LastSuccessRunID == "" && source.LastSuccessAt == nil &&
		source.LastCompleteSnapshotRunID == "" && source.LastCompleteSnapshotAt == nil &&
		source.Version == 2
}

func validateResolvedSourceAuthorities(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	profile assetcatalog.BuiltinSourceProfile,
	authorities []string,
) error {
	var authorityCount int
	if err := tx.QueryRow(ctx, `
SELECT count(*)
FROM environments
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
  AND id=ANY($3::uuid[])
`, scope.TenantID, scope.WorkspaceID, authorities).Scan(&authorityCount); err != nil {
		return err
	}
	if authorityCount != len(authorities) {
		return assetcatalog.ErrScopeViolation
	}
	switch profile.EnvironmentMapping {
	case assetcatalog.EnvironmentMappingSingle:
		if len(authorities) != 1 {
			return assetcatalog.ErrScopeViolation
		}
	case assetcatalog.EnvironmentMappingExplicitItem:
		if len(authorities) == 0 || len(authorities) > 100 {
			return assetcatalog.ErrScopeViolation
		}
	default:
		return assetcatalog.ErrStateConflict
	}
	return nil
}

func newSourceRevision(
	source assetcatalog.Source,
	profile assetcatalog.BuiltinSourceProfile,
	authorities []string,
	id string,
	revisionNumber, expectedSourceVersion int64,
	createdBy, reasonCode string,
) (assetcatalog.SourceRevision, error) {
	authorityDigest, err := assetcatalog.AuthorityScopeDigest(authorities)
	if err != nil {
		return assetcatalog.SourceRevision{}, err
	}
	profile = profile.Clone()
	revision := assetcatalog.SourceRevision{
		ID: id, SourceID: source.ID, TenantID: source.TenantID, WorkspaceID: source.WorkspaceID,
		Revision: revisionNumber, Status: assetcatalog.SourceRevisionDraft,
		CanonicalProfileManifest:      profile.CanonicalProfileManifest,
		CanonicalProviderSchema:       profile.CanonicalProviderSchema,
		ProfileManifestSHA256:         profile.ProfileManifestSHA256,
		CanonicalProviderSchemaSHA256: profile.CanonicalProviderSchemaSHA256,
		IntegrationID:                 profile.IntegrationID,
		SyncMode:                      profile.SyncMode,
		CredentialReferenceID:         profile.CredentialReferenceID,
		TrustReferenceID:              profile.TrustReferenceID,
		NetworkPolicyReferenceID:      profile.NetworkPolicyReferenceID,
		AuthorityEnvironmentIDs:       slices.Clone(authorities),
		AuthorityScopeDigest:          authorityDigest,
		RateLimitRequests:             profile.RateLimitRequests,
		RateLimitWindowSeconds:        profile.RateLimitWindowSeconds,
		BackpressureBaseSeconds:       profile.BackpressureBaseSeconds,
		BackpressureMaxSeconds:        profile.BackpressureMaxSeconds,
		ProfileCode:                   profile.ProfileCode,
		ScheduleExpression:            profile.ScheduleExpression,
		TypedExtensionCode:            profile.TypedExtensionCode,
		PreparedExtensionDigest:       profile.PreparedExtensionDigest,
		CreatedBy:                     createdBy,
		ChangeReasonCode:              reasonCode,
		ExpectedSourceVersion:         expectedSourceVersion,
		Version:                       1,
	}
	revision.SourceDefinitionDigest, err = assetcatalog.SourceDefinitionDigest(source, revision)
	if err != nil {
		return assetcatalog.SourceRevision{}, err
	}
	revision.CanonicalRevisionDigest = revision.BindingDigest()
	if !validSHA256(revision.CanonicalRevisionDigest) {
		return assetcatalog.SourceRevision{}, assetcatalog.ErrStateConflict
	}
	return revision.Clone(), nil
}

func insertSourceRevisionInTx(
	ctx context.Context,
	tx pgx.Tx,
	revision assetcatalog.SourceRevision,
) error {
	if _, err := tx.Exec(ctx, `
INSERT INTO asset_source_revisions (
    id,tenant_id,workspace_id,source_id,revision,state,
    canonical_profile_manifest,profile_manifest_sha256,
    canonical_provider_schema,canonical_provider_schema_sha256,
    integration_id,sync_mode,authority_scope_digest,source_definition_digest,
    canonical_revision_digest,credential_reference_id,trust_reference_id,
    network_policy_reference_id,rate_limit_requests,rate_limit_window_seconds,
    backpressure_base_seconds,backpressure_max_seconds,profile_code,
    schedule_expression,typed_extension_code,prepared_extension_digest,
    created_by,change_reason_code,expected_source_version
) VALUES (
    $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,'DRAFT',
    $6,$7,$8,$9,$10::uuid,$11,$12,$13,$14,$15,$16,$17,
    $18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28
)
`, revision.ID, revision.TenantID, revision.WorkspaceID, revision.SourceID, revision.Revision,
		revision.CanonicalProfileManifest, revision.ProfileManifestSHA256,
		revision.CanonicalProviderSchema, revision.CanonicalProviderSchemaSHA256,
		nullableSourceString(revision.IntegrationID), revision.SyncMode,
		revision.AuthorityScopeDigest, revision.SourceDefinitionDigest, revision.CanonicalRevisionDigest,
		nullableSourceString(string(revision.CredentialReferenceID)),
		nullableSourceString(string(revision.TrustReferenceID)),
		nullableSourceString(string(revision.NetworkPolicyReferenceID)),
		revision.RateLimitRequests, revision.RateLimitWindowSeconds,
		revision.BackpressureBaseSeconds, revision.BackpressureMaxSeconds,
		revision.ProfileCode, nullableSourceString(revision.ScheduleExpression),
		nullableSourceString(string(revision.TypedExtensionCode)),
		nullableSourceString(revision.PreparedExtensionDigest),
		revision.CreatedBy, revision.ChangeReasonCode, revision.ExpectedSourceVersion,
	); err != nil {
		return err
	}
	for index, environmentID := range revision.AuthorityEnvironmentIDs {
		if _, err := tx.Exec(ctx, `
INSERT INTO asset_source_revision_authorities (
    tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
) VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5::uuid,$6)
`, revision.TenantID, revision.WorkspaceID, revision.SourceID,
			revision.Revision, environmentID, index+1,
		); err != nil {
			return err
		}
	}
	return nil
}

func sourceRevisionMatchesResolvedProfile(
	source assetcatalog.Source,
	revision assetcatalog.SourceRevision,
	profile assetcatalog.BuiltinSourceProfile,
) bool {
	definitionDigest, err := assetcatalog.SourceDefinitionDigest(source, revision)
	return err == nil &&
		source.Kind == profile.SourceKind &&
		source.ProviderKind == profile.ProviderKind &&
		revision.ProfileCode == profile.ProfileCode &&
		revision.SyncMode == profile.SyncMode &&
		revision.IntegrationID == profile.IntegrationID &&
		revision.CredentialReferenceID == profile.CredentialReferenceID &&
		revision.TrustReferenceID == profile.TrustReferenceID &&
		revision.NetworkPolicyReferenceID == profile.NetworkPolicyReferenceID &&
		revision.ScheduleExpression == profile.ScheduleExpression &&
		revision.TypedExtensionCode == profile.TypedExtensionCode &&
		revision.PreparedExtensionDigest == profile.PreparedExtensionDigest &&
		bytes.Equal(revision.CanonicalProfileManifest, profile.CanonicalProfileManifest) &&
		revision.ProfileManifestSHA256 == profile.ProfileManifestSHA256 &&
		bytes.Equal(revision.CanonicalProviderSchema, profile.CanonicalProviderSchema) &&
		revision.CanonicalProviderSchemaSHA256 == profile.CanonicalProviderSchemaSHA256 &&
		revision.RateLimitRequests == profile.RateLimitRequests &&
		revision.RateLimitWindowSeconds == profile.RateLimitWindowSeconds &&
		revision.BackpressureBaseSeconds == profile.BackpressureBaseSeconds &&
		revision.BackpressureMaxSeconds == profile.BackpressureMaxSeconds &&
		revision.SourceDefinitionDigest == definitionDigest &&
		revision.CanonicalRevisionDigest == revision.BindingDigest()
}

func (repository *Repository) createRevisionInTx(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	command assetcatalog.CreateSourceRevisionCommand,
	commandHash string,
	profile assetcatalog.BuiltinSourceProfile,
	ids []string,
) (assetcatalog.SourceRevisionMutation, error) {
	if len(ids) != 3 {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrStateConflict
	}
	if err := prepareSourceMutation(ctx, tx, scope, command.Context.IdempotencyKey()); err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	record, found, err := findSourceMutationAudit(ctx, tx, scope, command.Context.IdempotencyKey())
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	source, err := lockSourceMutation(ctx, tx, scope, command.SourceID)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	authorities := slices.Clone(command.AuthorityEnvironmentIDs)
	slices.Sort(authorities)
	if found {
		if err := validateSourceMutationAudit(
			command.Context, commandHash, sourceRevisionCreatedEvent, command.SourceID,
			command.ChangeReasonCode, record,
		); err != nil {
			return assetcatalog.SourceRevisionMutation{}, err
		}
		if record.Details.Revision <= 0 {
			return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrIdempotency
		}
		revision, err := lockSourceRevisionMutation(ctx, tx, source, record.Details.Revision)
		if err != nil {
			return assetcatalog.SourceRevisionMutation{}, err
		}
		if source.Version != record.Details.SourceVersion ||
			revision.Version != record.Details.RevisionVersion ||
			!sourceRevisionMatchesResolvedProfile(source, revision, profile) ||
			!slices.Equal(revision.AuthorityEnvironmentIDs, authorities) ||
			revision.ChangeReasonCode != command.ChangeReasonCode ||
			revision.ExpectedSourceVersion != command.ExpectedSourceVersion {
			return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrStateConflict
		}
		return assetcatalog.SourceRevisionMutation{
			Source: source, Revision: revision, Receipt: sourceReplayReceipt(record),
		}.Clone(), nil
	}
	if source.Version != command.ExpectedSourceVersion {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrVersionConflict
	}
	if source.Status == assetcatalog.SourceStatusDisabled {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrStateConflict
	}
	if profile.TypedExtensionCode != "" || profile.PreparedExtensionDigest != "" ||
		profile.SourceKind != source.Kind || profile.ProviderKind != source.ProviderKind {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrStateConflict
	}
	if err := validateResolvedSourceAuthorities(ctx, tx, scope, profile, authorities); err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	var nextRevision int64
	if err := tx.QueryRow(ctx, `
SELECT COALESCE(max(revision),0)+1
FROM asset_source_revisions
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
	`, scope.TenantID, scope.WorkspaceID, source.ID).Scan(&nextRevision); err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	revision, err := newSourceRevision(
		source, profile, authorities, ids[0], nextRevision, command.ExpectedSourceVersion,
		command.Context.ActorID(), command.ChangeReasonCode,
	)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	if err := insertSourceRevisionInTx(ctx, tx, revision); err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	source, err = lockSourceMutation(ctx, tx, scope, source.ID)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	revision, err = lockSourceRevisionMutation(ctx, tx, source, revision.Revision)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	receipt, err := insertSourceMutationSideEffects(
		ctx, tx, ids[1:], command.Context, commandHash, sourceRevisionCreatedEvent,
		command.ChangeReasonCode,
		source, &revision, nil,
	)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	return assetcatalog.SourceRevisionMutation{
		Source: source, Revision: revision, Receipt: receipt,
	}.Clone(), nil
}

type nonterminalSourceRun struct {
	ID, RequestHash, RevisionDigest string
	Revision                        int64
	Kind                            assetcatalog.RunKind
	Status                          assetcatalog.RunStatus
	CleanupStatus                   assetcatalog.CredentialCleanupStatus
	WorkResultKind, PendingDigest   *string
}

func prelockNonterminalSourceRun(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	sourceID string,
) (*nonterminalSourceRun, error) {
	var run nonterminalSourceRun
	err := tx.QueryRow(ctx, `
SELECT id::text,request_hash,source_revision,source_revision_digest,
       run_kind,status,cleanup_status,work_result_kind,pending_transition_digest
FROM asset_source_runs
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
  AND status IN ('QUEUED','DELAYED','RUNNING','FINALIZING')
FOR UPDATE
`, scope.TenantID, scope.WorkspaceID, sourceID).Scan(
		&run.ID, &run.RequestHash, &run.Revision, &run.RevisionDigest,
		&run.Kind, &run.Status, &run.CleanupStatus, &run.WorkResultKind, &run.PendingDigest,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &run, nil
}

func recheckPrelockedSourceRun(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	sourceID string,
	prelocked *nonterminalSourceRun,
) error {
	var runID string
	err := tx.QueryRow(ctx, `
SELECT id::text
FROM asset_source_runs
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
  AND status IN ('QUEUED','DELAYED','RUNNING','FINALIZING')
`, scope.TenantID, scope.WorkspaceID, sourceID).Scan(&runID)
	if errors.Is(err, pgx.ErrNoRows) {
		if prelocked != nil {
			return assetcatalog.ErrStateConflict
		}
		return nil
	}
	if err != nil {
		return err
	}
	if prelocked == nil || runID != prelocked.ID {
		return assetcatalog.ErrStateConflict
	}
	return nil
}

func cancelPrelockedSourceRun(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	sourceID string,
	run *nonterminalSourceRun,
) error {
	if run == nil {
		return nil
	}
	if run.Status == assetcatalog.RunStatusRunning || run.Status == assetcatalog.RunStatusFinalizing {
		return assetcatalog.ErrStateConflict
	}
	if run.Status == assetcatalog.RunStatusDelayed &&
		(run.CleanupStatus != assetcatalog.CredentialCleanupRevoked &&
			run.CleanupStatus != assetcatalog.CredentialCleanupNoCredential ||
			run.WorkResultKind != nil || run.PendingDigest != nil) {
		return assetcatalog.ErrStateConflict
	}
	if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET status='CANCELLED',stage_code='COMPLETED',version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
  AND id=$4::uuid AND status IN ('QUEUED','DELAYED')
`, scope.TenantID, scope.WorkspaceID, sourceID, run.ID); err != nil {
		return err
	}
	if run.Kind == assetcatalog.RunKindValidation {
		tag, err := tx.Exec(ctx, `
UPDATE asset_source_revisions
SET state='REJECTED',validation_digest=$6,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
  AND revision=$4 AND canonical_revision_digest=$5
  AND state='VALIDATING' AND validation_run_id=$7::uuid
`, scope.TenantID, scope.WorkspaceID, sourceID, run.Revision, run.RevisionDigest, run.RequestHash, run.ID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return assetcatalog.ErrStateConflict
		}
	}
	return nil
}

func manualValidationProof(
	source assetcatalog.Source,
	revision assetcatalog.SourceRevision,
	profile assetcatalog.BuiltinSourceProfile,
) (string, error) {
	request := discoverysource.ValidationRequest{
		Locator: assetcatalog.SourceLocator{
			Scope: assetcatalog.SourceScope{
				TenantID: source.TenantID, WorkspaceID: source.WorkspaceID,
			},
			SourceID: source.ID,
		},
		SourceRevision: revision.Revision, SourceRevisionDigest: revision.CanonicalRevisionDigest,
		Limits: discoverysource.Limits{
			MaxPageItems: profile.MaxPageItems, MaxPageRelations: profile.MaxPageRelations,
			MaxPageBytes: profile.MaxPageBytes, MaxDocumentBytes: profile.MaxDocumentBytes,
		},
	}
	proof := discoverysource.ValidationProof{
		Outcome: assetcatalog.ValidationOutcomeSucceeded,
		Code:    "VALIDATION_SUCCEEDED",
		Checks: []discoverysource.ValidationCheck{
			{Kind: discoverysource.ValidationCheckIdentity, Code: "IDENTITY_VERIFIED", Passed: true, Count: 1, DigestSHA256: revision.CanonicalRevisionDigest},
			{Kind: discoverysource.ValidationCheckTrustOrSignature, Code: "TRUST_OR_SIGNATURE_VERIFIED", Passed: true, Count: 0, DigestSHA256: revision.ProfileManifestSHA256},
			{Kind: discoverysource.ValidationCheckNetwork, Code: "NETWORK_VERIFIED", Passed: true, Count: 0, DigestSHA256: revision.AuthorityScopeDigest},
			{Kind: discoverysource.ValidationCheckCredentialOpen, Code: "CREDENTIAL_OPEN_VERIFIED", Passed: true, Count: 0},
			{Kind: discoverysource.ValidationCheckFixedProbe, Code: "FIXED_PROBE_VERIFIED", Passed: true, Count: 1, DigestSHA256: revision.SourceDefinitionDigest},
			{Kind: discoverysource.ValidationCheckSchema, Code: "SCHEMA_VERIFIED", Passed: true, Count: 1, DigestSHA256: revision.CanonicalProviderSchemaSHA256},
			{Kind: discoverysource.ValidationCheckDLP, Code: "DLP_VERIFIED", Passed: true, Count: 1, DigestSHA256: revision.ProfileManifestSHA256},
			{Kind: discoverysource.ValidationCheckBudget, Code: "BUDGET_VERIFIED", Passed: true, Count: 1, DigestSHA256: revision.CanonicalRevisionDigest},
		},
	}
	return proof.Digest(request)
}

func randomFenceTokenHash() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", assetcatalog.ErrStateConflict
	}
	digest := sha256.Sum256(raw[:])
	clear(raw[:])
	return hex.EncodeToString(digest[:]), nil
}

func insertSourceRunSystemReceipt(
	ctx context.Context,
	tx pgx.Tx,
	id string,
	scope assetcatalog.SourceScope,
	runID, actorID, action, requestID, traceID, payloadHash string,
) error {
	_, err := tx.Exec(ctx, `
INSERT INTO audit_records (
    id,tenant_id,workspace_id,actor_type,actor_id,action,
    resource_type,resource_id,request_id,trace_id,payload_hash,details
) VALUES (
    $1::uuid,$2::uuid,$3::uuid,'SYSTEM',$4,$5,
    'ASSET_SOURCE_RUN',$6,$7,$8,$9,'{}'::jsonb
)
`, id, scope.TenantID, scope.WorkspaceID, actorID, action, runID, requestID, traceID, payloadHash)
	return err
}

func (repository *Repository) requestValidationInTx(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	command assetcatalog.ValidateSourceRevisionCommand,
	commandHash string,
	ids []string,
	fenceTokenHash string,
) (assetcatalog.SourceRunMutation, error) {
	if len(ids) != 5 || !validSHA256(fenceTokenHash) {
		return assetcatalog.SourceRunMutation{}, assetcatalog.ErrStateConflict
	}
	if err := prepareSourceMutation(ctx, tx, scope, command.Context.IdempotencyKey()); err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	record, found, err := findSourceMutationAudit(ctx, tx, scope, command.Context.IdempotencyKey())
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	if found {
		if err := validateSourceMutationAudit(
			command.Context, commandHash, sourceValidationRequestedEvent, command.SourceID, "", record,
		); err != nil {
			return assetcatalog.SourceRunMutation{}, err
		}
		if record.Details.Revision != command.Revision || !validUUID(record.Details.RunID) {
			return assetcatalog.SourceRunMutation{}, assetcatalog.ErrIdempotency
		}
		run, err := lockSourceRunMutation(ctx, tx, scope, command.SourceID, record.Details.RunID)
		if err != nil {
			return assetcatalog.SourceRunMutation{}, err
		}
		if err := validateSourceRunReplayIdentity(
			ctx, tx, scope, command.SourceID, run.ID, command.Context,
		); err != nil {
			return assetcatalog.SourceRunMutation{}, err
		}
		source, err := lockSourceMutation(ctx, tx, scope, command.SourceID)
		if err != nil {
			return assetcatalog.SourceRunMutation{}, err
		}
		revision, err := lockSourceRevisionMutation(ctx, tx, source, record.Details.Revision)
		if err != nil {
			return assetcatalog.SourceRunMutation{}, err
		}
		if revision.CanonicalRevisionDigest != command.ExpectedRevisionDigest ||
			run.SourceRevision != revision.Revision ||
			run.SourceRevisionDigest != revision.CanonicalRevisionDigest {
			return assetcatalog.SourceRunMutation{}, assetcatalog.ErrStateConflict
		}
		return assetcatalog.SourceRunMutation{
			Source: source, Revision: revision, Run: run, Receipt: sourceReplayReceipt(record),
		}.Clone(), nil
	}
	prelockedRun, err := prelockNonterminalSourceRun(ctx, tx, scope, command.SourceID)
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	source, err := lockSourceMutation(ctx, tx, scope, command.SourceID)
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	if err := recheckPrelockedSourceRun(ctx, tx, scope, source.ID, prelockedRun); err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	if source.Version != command.ExpectedSourceVersion {
		return assetcatalog.SourceRunMutation{}, assetcatalog.ErrVersionConflict
	}
	if source.Status != assetcatalog.SourceStatusActive ||
		source.GateStatus == assetcatalog.SourceGateDegraded ||
		source.GateStatus == assetcatalog.SourceGateSuspended {
		return assetcatalog.SourceRunMutation{}, assetcatalog.ErrStateConflict
	}
	revision, err := lockSourceRevisionMutation(ctx, tx, source, command.Revision)
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	if revision.Version != command.ExpectedRevisionVersion {
		return assetcatalog.SourceRunMutation{}, assetcatalog.ErrVersionConflict
	}
	if revision.CanonicalRevisionDigest != command.ExpectedRevisionDigest {
		return assetcatalog.SourceRunMutation{}, assetcatalog.ErrStateConflict
	}
	if revision.Status != assetcatalog.SourceRevisionDraft &&
		revision.Status != assetcatalog.SourceRevisionRejected {
		return assetcatalog.SourceRunMutation{}, assetcatalog.ErrStateConflict
	}
	if source.GateStatus != assetcatalog.SourceGateUnavailable {
		if source.GateStatus != assetcatalog.SourceGateAvailable &&
			source.GateStatus != assetcatalog.SourceGateValidating {
			return assetcatalog.SourceRunMutation{}, assetcatalog.ErrStateConflict
		}
		var closedVersion int64
		if err := tx.QueryRow(ctx, `
UPDATE asset_sources
SET gate_status='UNAVAILABLE',gate_reason_code='VALIDATION_REQUESTED',
    gate_revision=gate_revision+1,validated_run_id=NULL,validation_digest=NULL,
    validated_binding_digest=NULL,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid AND version=$4
RETURNING version
`, scope.TenantID, scope.WorkspaceID, source.ID, source.Version).Scan(&closedVersion); err != nil {
			return assetcatalog.SourceRunMutation{}, err
		}
		source, err = lockSourceMutation(ctx, tx, scope, source.ID)
		if err != nil || source.Version != closedVersion {
			if err != nil {
				return assetcatalog.SourceRunMutation{}, err
			}
			return assetcatalog.SourceRunMutation{}, assetcatalog.ErrStateConflict
		}
	}
	if err := cancelPrelockedSourceRun(ctx, tx, scope, source.ID, prelockedRun); err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO asset_source_runs (
    id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
    run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
    cursor_before_sha256,checkpoint_version,trace_id
) VALUES (
    $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,
    'VALIDATION','HUMAN',$7,$8,$9,NULL,0,$10
)
`, ids[0], scope.TenantID, scope.WorkspaceID, source.ID, revision.Revision,
		revision.CanonicalRevisionDigest, source.GateRevision,
		command.Context.IdempotencyKey(), command.Context.RequestHash(), command.Context.TraceID(),
	); err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	tag, err := tx.Exec(ctx, `
UPDATE asset_source_revisions
SET state='VALIDATING',validation_run_id=$5::uuid,validation_digest=NULL,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
  AND revision=$4 AND version=$6 AND canonical_revision_digest=$7
  AND state IN ('DRAFT','REJECTED')
`, scope.TenantID, scope.WorkspaceID, source.ID, revision.Revision, ids[0],
		command.ExpectedRevisionVersion, command.ExpectedRevisionDigest)
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	if tag.RowsAffected() != 1 {
		return assetcatalog.SourceRunMutation{}, assetcatalog.ErrVersionConflict
	}
	var validatingSourceVersion int64
	if err := tx.QueryRow(ctx, `
UPDATE asset_sources
SET gate_status='VALIDATING',gate_revision=gate_revision+1,
    validated_run_id=$5::uuid,validation_digest=NULL,validated_binding_digest=NULL,
    version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
  AND version=$4 AND gate_status='UNAVAILABLE'
RETURNING version
`, scope.TenantID, scope.WorkspaceID, source.ID, source.Version, ids[0]).Scan(&validatingSourceVersion); err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	source, err = lockSourceMutation(ctx, tx, scope, source.ID)
	if err != nil || source.Version != validatingSourceVersion {
		if err != nil {
			return assetcatalog.SourceRunMutation{}, err
		}
		return assetcatalog.SourceRunMutation{}, assetcatalog.ErrStateConflict
	}
	revision, err = lockSourceRevisionMutation(ctx, tx, source, revision.Revision)
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	run, err := lockSourceRunMutation(ctx, tx, scope, source.ID, ids[0])
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}

	profile, profileErr := assetcatalog.NewBuiltinSourceProfileAdmissionResolver().
		ResolveProfileAdmission(ctx, revision.ProfileCode)
	isManual := profileErr == nil && exactManualRevisionProfile(source, revision, profile)
	if source.Kind == assetcatalog.SourceKindManual && !isManual {
		return assetcatalog.SourceRunMutation{}, assetcatalog.ErrStateConflict
	}
	if isManual {
		proofDigest, err := manualValidationProof(source, revision, profile)
		if err != nil {
			return assetcatalog.SourceRunMutation{}, err
		}
		run, revision, err = completeManualValidationInTx(
			ctx, tx, scope, source, revision, run, proofDigest,
			ids[3], ids[4], fenceTokenHash, command.Context.TraceID(),
		)
		if err != nil {
			return assetcatalog.SourceRunMutation{}, err
		}
		source, err = lockSourceMutation(ctx, tx, scope, source.ID)
		if err != nil {
			return assetcatalog.SourceRunMutation{}, err
		}
	}
	receipt, err := insertSourceMutationSideEffects(
		ctx, tx, ids[1:3], command.Context, commandHash, sourceValidationRequestedEvent, "",
		source, &revision, &run,
	)
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	return assetcatalog.SourceRunMutation{
		Source: source, Revision: revision, Run: run, Receipt: receipt,
	}.Clone(), nil
}

func completeManualValidationInTx(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	source assetcatalog.Source,
	revision assetcatalog.SourceRevision,
	run assetcatalog.SourceRun,
	proofDigest, cleanupAuditID, terminalAuditID, fenceTokenHash, traceID string,
) (assetcatalog.SourceRun, assetcatalog.SourceRevision, error) {
	const leaseOwner = "manual-validation"
	if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET status='RUNNING',stage_code='VALIDATING',lease_owner=$5,
    lease_expires_at=clock_timestamp()+interval '5 minutes',
    fence_epoch=1,fence_token_hash=$6,heartbeat_sequence=1,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
  AND id=$4::uuid AND status='QUEUED' AND stage_code='WAITING' AND version=1
`, scope.TenantID, scope.WorkspaceID, source.ID, run.ID, leaseOwner, fenceTokenHash); err != nil {
		return assetcatalog.SourceRun{}, assetcatalog.SourceRevision{}, err
	}
	var cleanupDigest string
	if err := tx.QueryRow(
		ctx, manualCleanupDigestSQL, scope.TenantID, scope.WorkspaceID, source.ID, run.ID,
	).Scan(&cleanupDigest); err != nil {
		return assetcatalog.SourceRun{}, assetcatalog.SourceRevision{}, err
	}
	if !validSHA256(cleanupDigest) {
		return assetcatalog.SourceRun{}, assetcatalog.SourceRevision{}, assetcatalog.ErrStateConflict
	}
	if err := insertSourceRunSystemReceipt(
		ctx, tx, cleanupAuditID, scope, run.ID, leaseOwner, "ATTEMPT_CLEANED",
		"source-attempt:"+run.ID+":0", traceID, cleanupDigest,
	); err != nil {
		return assetcatalog.SourceRun{}, assetcatalog.SourceRevision{}, err
	}
	if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET status='FINALIZING',stage_code='CLEANING_UP',
    work_result_kind='VALIDATION_PROOF',work_result_status='SUCCEEDED',
    work_result_digest=$5,work_result_recorded_at=statement_timestamp(),
    validation_outcome='SUCCEEDED',validation_digest=$5,validation_proof_digest=$5,
    cleanup_status='NO_CREDENTIAL',cleanup_digest=$6,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
  AND id=$4::uuid AND status='RUNNING' AND stage_code='VALIDATING'
  AND lease_owner=$7 AND fence_epoch=1 AND fence_token_hash=$8
`, scope.TenantID, scope.WorkspaceID, source.ID, run.ID, proofDigest, cleanupDigest,
		leaseOwner, fenceTokenHash); err != nil {
		return assetcatalog.SourceRun{}, assetcatalog.SourceRevision{}, err
	}
	var terminalDigest string
	if err := tx.QueryRow(
		ctx, manualTerminalDigestSQL, scope.TenantID, scope.WorkspaceID, source.ID, run.ID,
	).Scan(&terminalDigest); err != nil {
		return assetcatalog.SourceRun{}, assetcatalog.SourceRevision{}, err
	}
	if !validSHA256(terminalDigest) {
		return assetcatalog.SourceRun{}, assetcatalog.SourceRevision{}, assetcatalog.ErrStateConflict
	}
	if err := insertSourceRunSystemReceipt(
		ctx, tx, terminalAuditID, scope, run.ID, leaseOwner, "TERMINAL_COMMITTED",
		"source-terminal:"+run.ID, traceID, terminalDigest,
	); err != nil {
		return assetcatalog.SourceRun{}, assetcatalog.SourceRevision{}, err
	}
	if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET status='SUCCEEDED',stage_code='COMPLETED',
    terminal_command_sha256=$5,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
  AND id=$4::uuid AND status='FINALIZING' AND stage_code='CLEANING_UP'
  AND lease_owner=$6 AND fence_epoch=1 AND fence_token_hash=$7
`, scope.TenantID, scope.WorkspaceID, source.ID, run.ID, terminalDigest,
		leaseOwner, fenceTokenHash); err != nil {
		return assetcatalog.SourceRun{}, assetcatalog.SourceRevision{}, err
	}
	if _, err := tx.Exec(ctx, `
UPDATE asset_source_revisions
SET state='VALIDATED',validation_digest=$5,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
  AND revision=$4 AND state='VALIDATING' AND validation_run_id=$6::uuid
`, scope.TenantID, scope.WorkspaceID, source.ID, revision.Revision, proofDigest, run.ID); err != nil {
		return assetcatalog.SourceRun{}, assetcatalog.SourceRevision{}, err
	}
	updatedRun, err := lockSourceRunMutation(ctx, tx, scope, source.ID, run.ID)
	if err != nil {
		return assetcatalog.SourceRun{}, assetcatalog.SourceRevision{}, err
	}
	updatedRevision, err := lockSourceRevisionMutation(ctx, tx, source, revision.Revision)
	if err != nil {
		return assetcatalog.SourceRun{}, assetcatalog.SourceRevision{}, err
	}
	return updatedRun, updatedRevision, nil
}

func (repository *Repository) publishRevisionInTx(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	command assetcatalog.PublishSourceRevisionCommand,
	commandHash string,
	ids []string,
) (assetcatalog.SourceRevisionMutation, error) {
	if len(ids) != 2 {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrStateConflict
	}
	if err := prepareSourceMutation(ctx, tx, scope, command.Context.IdempotencyKey()); err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	record, found, err := findSourceMutationAudit(ctx, tx, scope, command.Context.IdempotencyKey())
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	if found {
		source, err := lockSourceMutation(ctx, tx, scope, command.SourceID)
		if err != nil {
			return assetcatalog.SourceRevisionMutation{}, err
		}
		if err := validateSourceMutationAudit(
			command.Context, commandHash, sourceRevisionPublishedEvent, command.SourceID,
			command.ReasonCode, record,
		); err != nil {
			return assetcatalog.SourceRevisionMutation{}, err
		}
		if record.Details.Revision != command.Revision {
			return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrIdempotency
		}
		revision, err := lockSourceRevisionMutation(ctx, tx, source, command.Revision)
		if err != nil {
			return assetcatalog.SourceRevisionMutation{}, err
		}
		if source.Version != record.Details.SourceVersion ||
			revision.Version != record.Details.RevisionVersion ||
			revision.Status != assetcatalog.SourceRevisionPublished ||
			revision.CanonicalRevisionDigest != command.ExpectedRevisionDigest ||
			revision.ValidationRunID != command.ExpectedValidationRunID ||
			revision.ValidationDigest != command.ExpectedValidationDigest {
			return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrStateConflict
		}
		if err := admitSourceRevisionPublication(ctx, source, revision); err != nil {
			return assetcatalog.SourceRevisionMutation{}, err
		}
		return assetcatalog.SourceRevisionMutation{
			Source: source, Revision: revision, Receipt: sourceReplayReceipt(record),
		}.Clone(), nil
	}
	prelockedRun, err := prelockNonterminalSourceRun(ctx, tx, scope, command.SourceID)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	if sourceRunBlocksPublication(prelockedRun) {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrStateConflict
	}
	source, err := lockSourceMutation(ctx, tx, scope, command.SourceID)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	if err := recheckPrelockedSourceRun(ctx, tx, scope, source.ID, prelockedRun); err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	if source.Version != command.ExpectedSourceVersion {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrVersionConflict
	}
	if source.Status != assetcatalog.SourceStatusActive {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrStateConflict
	}
	revision, err := lockSourceRevisionMutation(ctx, tx, source, command.Revision)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	if revision.Version != command.ExpectedRevisionVersion {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrVersionConflict
	}
	if revision.Status != assetcatalog.SourceRevisionValidated ||
		revision.CanonicalRevisionDigest != command.ExpectedRevisionDigest ||
		revision.ValidationRunID != command.ExpectedValidationRunID ||
		revision.ValidationDigest != command.ExpectedValidationDigest ||
		revision.TypedExtensionCode != "" || revision.PreparedExtensionDigest != "" {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrSourceRevisionNotValidated
	}
	if source.GateStatus != assetcatalog.SourceGateValidating ||
		source.GateReasonCode != "VALIDATION_IN_PROGRESS" ||
		source.ValidationDigest != "" ||
		source.ValidatedBindingDigest != "" ||
		source.ValidatedRunID != command.ExpectedValidationRunID {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrStateConflict
	}
	run, err := lockSourceRunMutation(ctx, tx, scope, source.ID, command.ExpectedValidationRunID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrSourceRevisionNotValidated
		}
		return assetcatalog.SourceRevisionMutation{}, err
	}
	if run.Kind != assetcatalog.RunKindValidation ||
		run.Status != assetcatalog.RunStatusSucceeded ||
		run.Stage != assetcatalog.RunStageCompleted ||
		run.SourceRevision != revision.Revision ||
		run.SourceRevisionDigest != revision.CanonicalRevisionDigest ||
		run.ValidationOutcome != assetcatalog.ValidationOutcomeSucceeded ||
		run.ValidationProofDigest != revision.ValidationDigest {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrSourceRevisionNotValidated
	}
	if err := admitSourceRevisionPublication(ctx, source, revision); err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	tag, err := tx.Exec(ctx, `
UPDATE asset_source_revisions
SET state='PUBLISHED',version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
  AND revision=$4 AND state='VALIDATED' AND version=$5
  AND canonical_revision_digest=$6 AND validation_run_id=$7::uuid
  AND validation_digest=$8
`, scope.TenantID, scope.WorkspaceID, source.ID, revision.Revision,
		command.ExpectedRevisionVersion, command.ExpectedRevisionDigest,
		command.ExpectedValidationRunID, command.ExpectedValidationDigest)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	if tag.RowsAffected() != 1 {
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrVersionConflict
	}
	if err := cancelPrelockedSourceRun(ctx, tx, scope, source.ID, prelockedRun); err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	source, err = lockSourceMutation(ctx, tx, scope, source.ID)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	revision, err = lockSourceRevisionMutation(ctx, tx, source, revision.Revision)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	var openedVersion int64
	if err := tx.QueryRow(ctx, `
UPDATE asset_sources
SET gate_status='AVAILABLE',gate_reason_code=NULL,gate_revision=gate_revision+1,
    validated_run_id=$5::uuid,validation_digest=$6,validated_binding_digest=$7,
    version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
  AND version=$4 AND status='ACTIVE' AND gate_status='UNAVAILABLE'
  AND published_revision=$8 AND published_revision_digest=$7
RETURNING version
`, scope.TenantID, scope.WorkspaceID, source.ID, source.Version,
		run.ID, revision.ValidationDigest, revision.CanonicalRevisionDigest,
		revision.Revision).Scan(&openedVersion); err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	source, err = lockSourceMutation(ctx, tx, scope, source.ID)
	if err != nil || source.Version != openedVersion {
		if err != nil {
			return assetcatalog.SourceRevisionMutation{}, err
		}
		return assetcatalog.SourceRevisionMutation{}, assetcatalog.ErrStateConflict
	}
	receipt, err := insertSourceMutationSideEffects(
		ctx, tx, ids, command.Context, commandHash, sourceRevisionPublishedEvent,
		command.ReasonCode,
		source, &revision, nil,
	)
	if err != nil {
		return assetcatalog.SourceRevisionMutation{}, err
	}
	return assetcatalog.SourceRevisionMutation{
		Source: source, Revision: revision, Receipt: receipt,
	}.Clone(), nil
}

func sourceRunBlocksPublication(run *nonterminalSourceRun) bool {
	return run != nil &&
		(run.Status == assetcatalog.RunStatusRunning ||
			run.Status == assetcatalog.RunStatusFinalizing)
}

func admitSourceRevisionPublication(
	ctx context.Context,
	source assetcatalog.Source,
	revision assetcatalog.SourceRevision,
) error {
	if source.Kind != assetcatalog.SourceKindManual ||
		revision.ProfileCode != assetcatalog.ProfileCode("MANUAL_V1") {
		return assetcatalog.ErrUnavailable
	}
	profile, err := assetcatalog.NewBuiltinSourceProfileAdmissionResolver().
		ResolveProfileAdmission(ctx, revision.ProfileCode)
	if err != nil {
		return assetcatalog.ErrUnavailable
	}
	if !exactManualRevisionProfile(source, revision, profile) {
		return assetcatalog.ErrStateConflict
	}
	return nil
}

func exactManualRevisionProfile(
	source assetcatalog.Source,
	revision assetcatalog.SourceRevision,
	profile assetcatalog.BuiltinSourceProfile,
) bool {
	expectedDefinition, err := manualSourceDefinitionDigest(profile)
	if err != nil {
		return false
	}
	expectedAuthority, err := assetcatalog.AuthorityScopeDigest(revision.AuthorityEnvironmentIDs)
	if err != nil {
		return false
	}
	return source.Kind == assetcatalog.SourceKindManual &&
		source.Kind == profile.SourceKind &&
		source.ProviderKind == "MANUAL_V1" &&
		source.ProviderKind == profile.ProviderKind &&
		source.Status == assetcatalog.SourceStatusActive &&
		revision.ProfileCode == "MANUAL_V1" &&
		revision.ProfileCode == profile.ProfileCode &&
		revision.SyncMode == assetcatalog.SyncModeManual &&
		revision.IntegrationID == "" &&
		revision.CredentialReferenceID == "" &&
		revision.TrustReferenceID == "" &&
		revision.NetworkPolicyReferenceID == "" &&
		revision.ScheduleExpression == "" &&
		revision.TypedExtensionCode == "" &&
		revision.PreparedExtensionDigest == "" &&
		bytes.Equal(revision.CanonicalProfileManifest, profile.CanonicalProfileManifest) &&
		revision.ProfileManifestSHA256 == profile.ProfileManifestSHA256 &&
		bytes.Equal(revision.CanonicalProviderSchema, profile.CanonicalProviderSchema) &&
		revision.CanonicalProviderSchemaSHA256 == profile.CanonicalProviderSchemaSHA256 &&
		revision.RateLimitRequests == profile.RateLimitRequests &&
		revision.RateLimitWindowSeconds == profile.RateLimitWindowSeconds &&
		revision.BackpressureBaseSeconds == profile.BackpressureBaseSeconds &&
		revision.BackpressureMaxSeconds == profile.BackpressureMaxSeconds &&
		len(revision.AuthorityEnvironmentIDs) == 1 &&
		revision.AuthorityScopeDigest == expectedAuthority &&
		revision.SourceDefinitionDigest == expectedDefinition
}

func (repository *Repository) disableSourceInTx(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	command assetcatalog.DisableSourceCommand,
	commandHash string,
	ids []string,
) (assetcatalog.SourceMutation, error) {
	if len(ids) != 2 {
		return assetcatalog.SourceMutation{}, assetcatalog.ErrStateConflict
	}
	if err := prepareSourceMutation(ctx, tx, scope, command.Context.IdempotencyKey()); err != nil {
		return assetcatalog.SourceMutation{}, err
	}
	record, found, err := findSourceMutationAudit(ctx, tx, scope, command.Context.IdempotencyKey())
	if err != nil {
		return assetcatalog.SourceMutation{}, err
	}
	if found {
		source, err := lockSourceMutation(ctx, tx, scope, command.SourceID)
		if err != nil {
			return assetcatalog.SourceMutation{}, err
		}
		if err := validateSourceMutationAudit(
			command.Context, commandHash, sourceDisabledEvent, command.SourceID, command.ReasonCode, record,
		); err != nil {
			return assetcatalog.SourceMutation{}, err
		}
		if source.Version != record.Details.SourceVersion ||
			source.Status != assetcatalog.SourceStatusDisabled ||
			source.GateStatus != assetcatalog.SourceGateUnavailable ||
			source.GateReasonCode != "SOURCE_NOT_ACTIVE" {
			return assetcatalog.SourceMutation{}, assetcatalog.ErrStateConflict
		}
		return assetcatalog.SourceMutation{
			Source: source, Receipt: sourceReplayReceipt(record),
		}.Clone(), nil
	}
	prelockedRun, err := prelockNonterminalSourceRun(ctx, tx, scope, command.SourceID)
	if err != nil {
		return assetcatalog.SourceMutation{}, err
	}
	source, err := lockSourceMutation(ctx, tx, scope, command.SourceID)
	if err != nil {
		return assetcatalog.SourceMutation{}, err
	}
	if err := recheckPrelockedSourceRun(ctx, tx, scope, source.ID, prelockedRun); err != nil {
		return assetcatalog.SourceMutation{}, err
	}
	if source.Version != command.ExpectedSourceVersion {
		return assetcatalog.SourceMutation{}, assetcatalog.ErrVersionConflict
	}
	if source.Status == assetcatalog.SourceStatusDisabled ||
		source.GateStatus == assetcatalog.SourceGateDegraded {
		return assetcatalog.SourceMutation{}, assetcatalog.ErrStateConflict
	}
	if prelockedRun != nil &&
		(prelockedRun.Status == assetcatalog.RunStatusRunning ||
			prelockedRun.Status == assetcatalog.RunStatusFinalizing) &&
		prelockedRun.Kind == assetcatalog.RunKindValidation {
		return assetcatalog.SourceMutation{}, assetcatalog.ErrStateConflict
	}
	var disabledVersion int64
	if err := tx.QueryRow(ctx, `
UPDATE asset_sources
SET status='DISABLED',gate_status='UNAVAILABLE',
    gate_reason_code='SOURCE_NOT_ACTIVE',validated_run_id=NULL,
    validation_digest=NULL,validated_binding_digest=NULL,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
  AND version=$4 AND gate_status<>'DEGRADED' AND status<>'DISABLED'
RETURNING version
`, scope.TenantID, scope.WorkspaceID, source.ID, source.Version).Scan(&disabledVersion); err != nil {
		return assetcatalog.SourceMutation{}, err
	}
	if prelockedRun != nil &&
		(prelockedRun.Status == assetcatalog.RunStatusQueued ||
			prelockedRun.Status == assetcatalog.RunStatusDelayed) {
		if err := cancelPrelockedSourceRun(ctx, tx, scope, source.ID, prelockedRun); err != nil {
			return assetcatalog.SourceMutation{}, err
		}
	}
	source, err = lockSourceMutation(ctx, tx, scope, source.ID)
	if err != nil || source.Version != disabledVersion {
		if err != nil {
			return assetcatalog.SourceMutation{}, err
		}
		return assetcatalog.SourceMutation{}, assetcatalog.ErrStateConflict
	}
	if source.Status != assetcatalog.SourceStatusDisabled ||
		source.GateStatus != assetcatalog.SourceGateUnavailable ||
		source.GateReasonCode != "SOURCE_NOT_ACTIVE" {
		return assetcatalog.SourceMutation{}, assetcatalog.ErrStateConflict
	}
	receipt, err := insertSourceMutationSideEffects(
		ctx, tx, ids, command.Context, commandHash, sourceDisabledEvent,
		command.ReasonCode, source, nil, nil,
	)
	if err != nil {
		return assetcatalog.SourceMutation{}, err
	}
	return assetcatalog.SourceMutation{Source: source, Receipt: receipt}.Clone(), nil
}

func (repository *Repository) requestSyncInTx(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	command assetcatalog.RequestSyncCommand,
	commandHash string,
	ids []string,
) (assetcatalog.SourceRunMutation, error) {
	if len(ids) != 3 {
		return assetcatalog.SourceRunMutation{}, assetcatalog.ErrStateConflict
	}
	if err := prepareSourceMutation(ctx, tx, scope, command.Context.IdempotencyKey()); err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	record, found, err := findSourceMutationAudit(ctx, tx, scope, command.Context.IdempotencyKey())
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	if found {
		if err := validateSourceMutationAudit(
			command.Context, commandHash, sourceSyncRequestedEvent, command.SourceID, "", record,
		); err != nil {
			return assetcatalog.SourceRunMutation{}, err
		}
		if record.Details.Revision != command.ExpectedRevision || !validUUID(record.Details.RunID) {
			return assetcatalog.SourceRunMutation{}, assetcatalog.ErrIdempotency
		}
		run, err := lockSourceRunMutation(ctx, tx, scope, command.SourceID, record.Details.RunID)
		if err != nil {
			return assetcatalog.SourceRunMutation{}, err
		}
		if err := validateSourceRunReplayIdentity(
			ctx, tx, scope, command.SourceID, run.ID, command.Context,
		); err != nil {
			return assetcatalog.SourceRunMutation{}, err
		}
		source, err := lockSourceMutation(ctx, tx, scope, command.SourceID)
		if err != nil {
			return assetcatalog.SourceRunMutation{}, err
		}
		revision, err := lockSourceRevisionMutation(ctx, tx, source, record.Details.Revision)
		if err != nil {
			return assetcatalog.SourceRunMutation{}, err
		}
		if revision.CanonicalRevisionDigest != command.ExpectedRevisionDigest ||
			run.SourceRevision != command.ExpectedRevision ||
			run.SourceRevisionDigest != command.ExpectedRevisionDigest ||
			run.CheckpointVersion != command.ExpectedCheckpointVersion ||
			run.CursorBeforeSHA256 != command.ExpectedCheckpointSHA256 {
			return assetcatalog.SourceRunMutation{}, assetcatalog.ErrStateConflict
		}
		return assetcatalog.SourceRunMutation{
			Source: source, Revision: revision, Run: run, Receipt: sourceReplayReceipt(record),
		}.Clone(), nil
	}
	prelockedRun, err := prelockNonterminalSourceRun(ctx, tx, scope, command.SourceID)
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	source, err := lockSourceMutation(ctx, tx, scope, command.SourceID)
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	if err := recheckPrelockedSourceRun(ctx, tx, scope, source.ID, prelockedRun); err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	if prelockedRun != nil {
		return assetcatalog.SourceRunMutation{}, assetcatalog.ErrStateConflict
	}
	if source.Version != command.ExpectedSourceVersion {
		return assetcatalog.SourceRunMutation{}, assetcatalog.ErrVersionConflict
	}
	if source.Status != assetcatalog.SourceStatusActive ||
		source.GateStatus != assetcatalog.SourceGateAvailable ||
		source.PublishedRevision != command.ExpectedRevision ||
		source.PublishedRevisionDigest != command.ExpectedRevisionDigest ||
		source.CheckpointVersion != command.ExpectedCheckpointVersion ||
		source.CheckpointSHA256 != command.ExpectedCheckpointSHA256 {
		return assetcatalog.SourceRunMutation{}, assetcatalog.ErrStateConflict
	}
	if !requestSyncSourceKindAllowed(source.Kind) {
		return assetcatalog.SourceRunMutation{}, assetcatalog.ErrStateConflict
	}
	revision, err := lockSourceRevisionMutation(ctx, tx, source, source.PublishedRevision)
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	if revision.Status != assetcatalog.SourceRevisionPublished ||
		revision.CanonicalRevisionDigest != source.PublishedRevisionDigest ||
		revision.TypedExtensionCode != "" || revision.PreparedExtensionDigest != "" {
		return assetcatalog.SourceRunMutation{}, assetcatalog.ErrStateConflict
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO asset_source_runs (
    id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
    run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
    cursor_before_sha256,checkpoint_version,trace_id
) VALUES (
    $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,
    'DISCOVERY','HUMAN',$7,$8,$9,$10,$11,$12
)
`, ids[0], scope.TenantID, scope.WorkspaceID, source.ID,
		revision.Revision, revision.CanonicalRevisionDigest, source.GateRevision,
		command.Context.IdempotencyKey(), command.Context.RequestHash(),
		nullableSourceString(source.CheckpointSHA256), source.CheckpointVersion,
		command.Context.TraceID(),
	); err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	run, err := lockSourceRunMutation(ctx, tx, scope, source.ID, ids[0])
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	receipt, err := insertSourceMutationSideEffects(
		ctx, tx, ids[1:], command.Context, commandHash, sourceSyncRequestedEvent, "",
		source, &revision, &run,
	)
	if err != nil {
		return assetcatalog.SourceRunMutation{}, err
	}
	return assetcatalog.SourceRunMutation{
		Source: source, Revision: revision, Run: run, Receipt: receipt,
	}.Clone(), nil
}

func mapSourceRevisionError(err error) error {
	if errors.Is(err, assetcatalog.ErrSourceRevisionNotValidated) {
		return assetcatalog.ErrSourceRevisionNotValidated
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.ConstraintName {
		case "asset_source_revisions_validation_guard":
			return assetcatalog.ErrSourceRevisionNotValidated
		case "asset_source_revisions_source_version_guard",
			"asset_source_revisions_version_guard",
			"asset_sources_version_guard":
			return assetcatalog.ErrVersionConflict
		case "asset_source_revisions_state_guard",
			"asset_source_revisions_sequence_guard",
			"asset_source_revisions_new_validation_run_guard",
			"asset_sources_gate_transition_guard",
			"asset_sources_validating_gate_guard",
			"asset_source_runs_cancel_guard",
			"asset_source_runs_nonterminal_uk":
			return assetcatalog.ErrStateConflict
		}
	}
	return mapPGError(err)
}

func createSourceCommandHash(
	scope assetcatalog.SourceScope,
	command assetcatalog.CreateSourceCommand,
) (string, error) {
	authorities := slices.Clone(command.AuthorityEnvironmentIDs)
	slices.Sort(authorities)
	return semanticCommandHash(struct {
		Operation               string                       `json:"operation"`
		Scope                   assetcatalog.SourceScope     `json:"scope"`
		Name                    string                       `json:"name"`
		SourceProfileID         assetcatalog.SourceProfileID `json:"source_profile_id"`
		AuthorityEnvironmentIDs []string                     `json:"authority_environment_ids"`
	}{
		Operation: sourceRevisionCreatedEvent, Scope: scope, Name: command.Name,
		SourceProfileID: command.SourceProfileID, AuthorityEnvironmentIDs: authorities,
	})
}

func validateCreateSourceCommand(
	command assetcatalog.CreateSourceCommand,
) (assetcatalog.SourceScope, string, error) {
	scope, ok := validSourceMutationContext(command.Context)
	authorities := slices.Clone(command.AuthorityEnvironmentIDs)
	slices.Sort(authorities)
	if !ok || !validAssetSafeText(command.Name, 1, 256) ||
		!command.SourceProfileID.Valid() || !validUniqueSourceAuthorityIDs(authorities) {
		return assetcatalog.SourceScope{}, "", assetcatalog.ErrInvalidRequest
	}
	command.AuthorityEnvironmentIDs = authorities
	hash, err := createSourceCommandHash(scope, command)
	return scope, hash, err
}

func createSourceRevisionCommandHash(
	scope assetcatalog.SourceScope,
	command assetcatalog.CreateSourceRevisionCommand,
) (string, error) {
	authorities := slices.Clone(command.AuthorityEnvironmentIDs)
	slices.Sort(authorities)
	return semanticCommandHash(struct {
		Operation               string                       `json:"operation"`
		Scope                   assetcatalog.SourceScope     `json:"scope"`
		SourceID                string                       `json:"source_id"`
		SourceProfileID         assetcatalog.SourceProfileID `json:"source_profile_id"`
		AuthorityEnvironmentIDs []string                     `json:"authority_environment_ids"`
		ChangeReasonCode        string                       `json:"change_reason_code"`
		ExpectedSourceVersion   int64                        `json:"expected_source_version"`
	}{
		Operation: sourceRevisionCreatedEvent, Scope: scope, SourceID: command.SourceID,
		SourceProfileID: command.SourceProfileID, AuthorityEnvironmentIDs: authorities,
		ChangeReasonCode: command.ChangeReasonCode, ExpectedSourceVersion: command.ExpectedSourceVersion,
	})
}

func validateCreateSourceRevisionCommand(
	command assetcatalog.CreateSourceRevisionCommand,
) (assetcatalog.SourceScope, string, error) {
	scope, ok := validSourceMutationContext(command.Context)
	authorities := slices.Clone(command.AuthorityEnvironmentIDs)
	slices.Sort(authorities)
	if !ok || !validUUID(command.SourceID) || !command.SourceProfileID.Valid() ||
		!validUniqueSourceAuthorityIDs(authorities) || !validAssetCode(command.ChangeReasonCode, 128) ||
		command.ExpectedSourceVersion <= 0 {
		return assetcatalog.SourceScope{}, "", assetcatalog.ErrInvalidRequest
	}
	command.AuthorityEnvironmentIDs = authorities
	hash, err := createSourceRevisionCommandHash(scope, command)
	return scope, hash, err
}

func validateSourceRevisionValidationCommand(
	command assetcatalog.ValidateSourceRevisionCommand,
) (assetcatalog.SourceScope, string, error) {
	scope, ok := validSourceMutationContext(command.Context)
	if !ok || !validUUID(command.SourceID) || command.Revision <= 0 ||
		command.ExpectedSourceVersion <= 0 || command.ExpectedRevisionVersion <= 0 ||
		!validSHA256(command.ExpectedRevisionDigest) {
		return assetcatalog.SourceScope{}, "", assetcatalog.ErrInvalidRequest
	}
	hash, err := semanticCommandHash(struct {
		Operation               string                   `json:"operation"`
		Scope                   assetcatalog.SourceScope `json:"scope"`
		SourceID                string                   `json:"source_id"`
		Revision                int64                    `json:"revision"`
		ExpectedSourceVersion   int64                    `json:"expected_source_version"`
		ExpectedRevisionVersion int64                    `json:"expected_revision_version"`
		ExpectedRevisionDigest  string                   `json:"expected_revision_digest"`
	}{
		sourceValidationRequestedEvent, scope, command.SourceID, command.Revision,
		command.ExpectedSourceVersion, command.ExpectedRevisionVersion, command.ExpectedRevisionDigest,
	})
	return scope, hash, err
}

func validatePublishSourceRevisionCommand(
	command assetcatalog.PublishSourceRevisionCommand,
) (assetcatalog.SourceScope, string, error) {
	scope, ok := validSourceMutationContext(command.Context)
	if !ok || !validUUID(command.SourceID) || command.Revision <= 0 ||
		!validAssetCode(command.ReasonCode, 128) || command.ExpectedSourceVersion <= 0 ||
		command.ExpectedRevisionVersion <= 0 || !validSHA256(command.ExpectedRevisionDigest) ||
		!validUUID(command.ExpectedValidationRunID) || !validSHA256(command.ExpectedValidationDigest) {
		return assetcatalog.SourceScope{}, "", assetcatalog.ErrInvalidRequest
	}
	hash, err := semanticCommandHash(struct {
		Operation                string                   `json:"operation"`
		Scope                    assetcatalog.SourceScope `json:"scope"`
		SourceID                 string                   `json:"source_id"`
		Revision                 int64                    `json:"revision"`
		ReasonCode               string                   `json:"reason_code"`
		ExpectedSourceVersion    int64                    `json:"expected_source_version"`
		ExpectedRevisionVersion  int64                    `json:"expected_revision_version"`
		ExpectedRevisionDigest   string                   `json:"expected_revision_digest"`
		ExpectedValidationRunID  string                   `json:"expected_validation_run_id"`
		ExpectedValidationDigest string                   `json:"expected_validation_digest"`
	}{
		sourceRevisionPublishedEvent, scope, command.SourceID, command.Revision, command.ReasonCode,
		command.ExpectedSourceVersion, command.ExpectedRevisionVersion, command.ExpectedRevisionDigest,
		command.ExpectedValidationRunID, command.ExpectedValidationDigest,
	})
	return scope, hash, err
}

func validateDisableSourceCommand(
	command assetcatalog.DisableSourceCommand,
) (assetcatalog.SourceScope, string, error) {
	scope, ok := validSourceMutationContext(command.Context)
	if !ok || !validUUID(command.SourceID) || !validAssetCode(command.ReasonCode, 128) ||
		command.ExpectedSourceVersion <= 0 {
		return assetcatalog.SourceScope{}, "", assetcatalog.ErrInvalidRequest
	}
	hash, err := semanticCommandHash(struct {
		Operation             string                   `json:"operation"`
		Scope                 assetcatalog.SourceScope `json:"scope"`
		SourceID              string                   `json:"source_id"`
		ReasonCode            string                   `json:"reason_code"`
		ExpectedSourceVersion int64                    `json:"expected_source_version"`
	}{sourceDisabledEvent, scope, command.SourceID, command.ReasonCode, command.ExpectedSourceVersion})
	return scope, hash, err
}

func validateRequestSyncCommand(
	command assetcatalog.RequestSyncCommand,
) (assetcatalog.SourceScope, string, error) {
	scope, ok := validSourceMutationContext(command.Context)
	checkpointValid := command.ExpectedCheckpointVersion >= 0 &&
		(command.ExpectedCheckpointVersion == 0 && command.ExpectedCheckpointSHA256 == "" ||
			command.ExpectedCheckpointVersion > 0 && validSHA256(command.ExpectedCheckpointSHA256))
	if !ok || !validUUID(command.SourceID) || command.ExpectedSourceVersion <= 0 ||
		command.ExpectedRevision <= 0 || !validSHA256(command.ExpectedRevisionDigest) || !checkpointValid {
		return assetcatalog.SourceScope{}, "", assetcatalog.ErrInvalidRequest
	}
	hash, err := semanticCommandHash(struct {
		Operation                 string                   `json:"operation"`
		Scope                     assetcatalog.SourceScope `json:"scope"`
		SourceID                  string                   `json:"source_id"`
		ExpectedSourceVersion     int64                    `json:"expected_source_version"`
		ExpectedRevision          int64                    `json:"expected_revision"`
		ExpectedRevisionDigest    string                   `json:"expected_revision_digest"`
		ExpectedCheckpointVersion int64                    `json:"expected_checkpoint_version"`
		ExpectedCheckpointSHA256  string                   `json:"expected_checkpoint_sha256"`
	}{
		sourceSyncRequestedEvent, scope, command.SourceID, command.ExpectedSourceVersion,
		command.ExpectedRevision, command.ExpectedRevisionDigest,
		command.ExpectedCheckpointVersion, command.ExpectedCheckpointSHA256,
	})
	return scope, hash, err
}

func validSourceMutationContext(value assetcatalog.MutationContext) (assetcatalog.SourceScope, bool) {
	if value.Validate() != nil {
		return assetcatalog.SourceScope{}, false
	}
	scope := value.SourceScope()
	_, environmentScoped := value.EnvironmentScope()
	return scope, scope.Valid() && !environmentScoped
}

func validUniqueSourceAuthorityIDs(values []string) bool {
	if len(values) == 0 || len(values) > 100 || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !validUUID(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func requestSyncSourceKindAllowed(kind assetcatalog.SourceKind) bool {
	switch kind {
	case assetcatalog.SourceKindManual, assetcatalog.SourceKindCSVImport,
		assetcatalog.SourceKindControlPlaneAPI:
		return false
	case assetcatalog.SourceKindExternalCMDB, assetcatalog.SourceKindVSphere,
		assetcatalog.SourceKindProxmox, assetcatalog.SourceKindOpenStack,
		assetcatalog.SourceKindCloudProvider, assetcatalog.SourceKindKubernetesOperator,
		assetcatalog.SourceKindAWXInventory:
		return true
	default:
		return false
	}
}
