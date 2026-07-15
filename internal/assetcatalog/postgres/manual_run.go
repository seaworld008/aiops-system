package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/jackc/pgx/v5"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/leasefence"
)

const (
	manualLeaseOwner          = "manual-api"
	manualFenceEpoch    int64 = 1
	manualPageSequence  int64 = 1
	manualSchemaVersion       = "manual-asset.v1"
)

const lockManualSourceSQL = `
SELECT source.id::text,
       source.tenant_id::text,
       source.workspace_id::text,
       source.provider_kind,
       source.name,
       source.source_kind,
       source.status,
       source.published_revision,
       source.published_revision_digest,
       source.gate_status,
       source.gate_reason_code,
       source.gate_revision,
       source.validated_run_id::text,
       source.validation_digest,
       source.validated_binding_digest,
       source.checkpoint_sha256,
       source.checkpoint_version,
       source.checkpoint_revision,
       source.next_allowed_at,
       source.consecutive_failures,
       source.last_success_run_id::text,
       source.last_success_at,
       source.last_complete_snapshot_run_id::text,
       source.last_complete_snapshot_at,
       source.version,
       source.created_at,
       source.updated_at,
       source.checkpoint_ciphertext,
       source.checkpoint_key_id
FROM asset_sources AS source
WHERE source.tenant_id = $1::uuid
  AND source.workspace_id = $2::uuid
  AND source.id = $3::uuid
FOR UPDATE
`

const lockManualRevisionSQL = `
SELECT revision.id::text,
       revision.source_id::text,
       revision.tenant_id::text,
       revision.workspace_id::text,
       revision.revision,
       revision.state,
       revision.canonical_profile_manifest,
       revision.profile_manifest_sha256,
       revision.canonical_provider_schema,
       revision.canonical_provider_schema_sha256,
       revision.source_definition_digest,
       revision.canonical_revision_digest,
       revision.integration_id::text,
       revision.sync_mode,
       revision.credential_reference_id,
       revision.trust_reference_id,
       revision.network_policy_reference_id,
       revision.authority_scope_digest,
       revision.rate_limit_requests,
       revision.rate_limit_window_seconds,
       revision.backpressure_base_seconds,
       revision.backpressure_max_seconds,
       revision.profile_code,
       revision.schedule_expression,
       revision.typed_extension_code,
       revision.prepared_extension_digest,
       revision.validation_run_id::text,
       revision.validation_digest,
       revision.created_by,
       revision.change_reason_code,
       revision.expected_source_version,
       revision.version,
       revision.created_at,
       revision.updated_at
FROM asset_source_revisions AS revision
WHERE revision.tenant_id = $1::uuid
  AND revision.workspace_id = $2::uuid
  AND revision.source_id = $3::uuid
  AND revision.revision = $4
FOR SHARE
`

const readManualAuthoritiesSQL = `
SELECT authority.environment_id::text, authority.canonical_ordinal
FROM asset_source_revision_authorities AS authority
WHERE authority.tenant_id = $1::uuid
  AND authority.workspace_id = $2::uuid
  AND authority.source_id = $3::uuid
  AND authority.source_revision = $4
ORDER BY authority.canonical_ordinal, authority.environment_id
`

const existingManualAssetSQL = `
SELECT id::text
FROM assets
WHERE tenant_id = $1::uuid
  AND workspace_id = $2::uuid
  AND source_id = $3::uuid
  AND provider_kind = $4
  AND external_id = $5
`

const insertManualRunSQL = `
INSERT INTO asset_source_runs (
    id, tenant_id, workspace_id, source_id, source_revision, source_revision_digest,
    run_kind, trigger_type, gate_revision, idempotency_key, request_hash,
    cursor_before_sha256, checkpoint_version, trace_id
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6,
    'MANUAL_MUTATION', 'HUMAN', $7, $8, $9,
    NULL, $10, $11
)
`

const claimManualRunSQL = `
UPDATE asset_source_runs
SET status = 'RUNNING',
    stage_code = 'READING',
    lease_owner = $5,
    lease_expires_at = clock_timestamp() + interval '5 minutes',
    fence_epoch = 1,
    fence_token_hash = $6,
    heartbeat_sequence = 1,
    version = version + 1
WHERE tenant_id = $1::uuid
  AND workspace_id = $2::uuid
  AND source_id = $3::uuid
  AND id = $4::uuid
  AND status = 'QUEUED'
  AND stage_code = 'WAITING'
  AND version = 1
  AND checkpoint_version = $7
RETURNING id::text, lease_owner, fence_epoch, fence_token_hash, version
`

const advanceManualRunStageSQL = `
UPDATE asset_source_runs
SET stage_code = $5,
    version = version + 1
WHERE tenant_id = $1::uuid
  AND workspace_id = $2::uuid
  AND source_id = $3::uuid
  AND id = $4::uuid
  AND status = 'RUNNING'
  AND stage_code = $6
  AND lease_owner = $7
  AND fence_epoch = 1
  AND fence_token_hash = $8
  AND lease_expires_at > clock_timestamp()
  AND version = $9
RETURNING version
`

const insertManualObservationSQL = `
INSERT INTO asset_observations (
    id, tenant_id, workspace_id, environment_id, source_id, run_id,
    provider_kind, external_id, source_revision, canonical_revision_digest,
    source_definition_digest, observed_at, freshness_kind, freshness_order_time,
    freshness_order_sequence, provider_version_sha256, provider_fact_sha256,
    fingerprint_sha256, provider_provenance_sha256, previous_observation_id,
    previous_chain_sha256, observation_chain_sha256, accepted_checkpoint_version,
    run_fence_epoch, run_page_sequence, schema_version, normalized_document,
    document_sha256, field_provenance, field_provenance_sha256, tombstone,
    tombstone_reason_code
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6::uuid,
    $7, $8, $9, $10, $11, $12, 'CATALOG_SEQUENCE', NULL,
    $13, $14, $15, $16, $17, NULL, NULL, $18, $19,
    1, 1, $20, $21::bytea, $22, $23::bytea, $24, false, NULL
)
`

const insertManualAssetSQL = `
INSERT INTO assets (
    id, tenant_id, workspace_id, environment_id, source_id, provider_kind,
    external_id, kind, display_name, owner_group, criticality,
    data_classification, labels, lifecycle, mapping_status,
    last_observation_id, last_observation_chain_sha256, last_observed_at,
    last_source_revision, create_idempotency_key, create_request_hash, version
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6,
    $7, $8, $9, $10, $11, $12, $13::jsonb, 'DISCOVERED', 'UNRESOLVED',
    $14::uuid, $15, $16, $17, $18, $19, 1
)
`

const insertManualTypeDetailSQL = `
INSERT INTO asset_type_details (
    id, tenant_id, workspace_id, environment_id, asset_id, source_id,
    provider_kind, external_id, source_revision, source_observed_at,
    source_observation_chain_sha256, revision, schema_version,
    source_observation_id, details_document, details_sha256, actor_id
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6::uuid,
    $7, $8, $9, $10, $11, 1, $12,
    $13::uuid, $14::bytea, $15, $16
)
`

const insertManualRunReceiptSQL = `
INSERT INTO audit_records (
    id, tenant_id, workspace_id, actor_type, actor_id, action,
    resource_type, resource_id, request_id, trace_id, payload_hash, details
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, 'SYSTEM', $4, $5,
    'ASSET_SOURCE_RUN', $6, $7, $8, $9, '{}'::jsonb
)
`

const manualCleanupDigestSQL = `
SELECT asset_catalog_source_run_no_credential_digest(run)
FROM asset_source_runs AS run
WHERE run.tenant_id = $1::uuid
  AND run.workspace_id = $2::uuid
  AND run.source_id = $3::uuid
  AND run.id = $4::uuid
`

const advanceManualCheckpointSQL = `
UPDATE asset_sources
SET checkpoint_version = $6,
    version = version + 1
WHERE tenant_id = $1::uuid
  AND workspace_id = $2::uuid
  AND id = $3::uuid
  AND version = $4
  AND checkpoint_version = $5
  AND checkpoint_revision = $7
  AND source_kind = 'MANUAL'
  AND provider_kind = 'MANUAL_V1'
  AND status = 'ACTIVE'
  AND gate_status = 'AVAILABLE'
  AND published_revision = $7
  AND checkpoint_ciphertext IS NULL
  AND checkpoint_key_id IS NULL
  AND checkpoint_sha256 IS NULL
RETURNING version
`

const finalizeManualRunSQL = `
UPDATE asset_source_runs
SET status = 'FINALIZING',
    stage_code = 'CLEANING_UP',
    page_sequence = 1,
    page_digest = $5,
    checkpoint_version = $6,
    final_page = true,
    complete_snapshot = false,
    effective_complete_snapshot = false,
    observed_count = 1,
    created_count = 1,
    work_result_kind = 'DATA_PROJECTION',
    work_result_status = 'SUCCEEDED',
    work_result_digest = $5,
    cleanup_status = 'NO_CREDENTIAL',
    cleanup_digest = $7,
    heartbeat_sequence = heartbeat_sequence + 1,
    version = version + 1
WHERE tenant_id = $1::uuid
  AND workspace_id = $2::uuid
  AND source_id = $3::uuid
  AND id = $4::uuid
  AND status = 'RUNNING'
  AND stage_code = 'APPLYING'
  AND page_sequence = 0
  AND relation_page_sequence = 0
  AND checkpoint_version = $8
  AND lease_owner = $9
  AND fence_epoch = 1
  AND fence_token_hash = $10
  AND lease_expires_at > clock_timestamp()
  AND version = $11
RETURNING id::text, lease_owner, fence_epoch, fence_token_hash, version
`

const manualTerminalDigestSQL = `
SELECT asset_catalog_source_run_terminal_digest(run, 'SUCCEEDED', NULL)
FROM asset_source_runs AS run
WHERE run.tenant_id = $1::uuid
  AND run.workspace_id = $2::uuid
  AND run.source_id = $3::uuid
  AND run.id = $4::uuid
  AND run.status = 'FINALIZING'
`

const completeManualRunSQL = `
UPDATE asset_source_runs
SET status = 'SUCCEEDED',
    stage_code = 'COMPLETED',
    terminal_command_sha256 = $5,
    version = version + 1
WHERE tenant_id = $1::uuid
  AND workspace_id = $2::uuid
  AND source_id = $3::uuid
  AND id = $4::uuid
  AND status = 'FINALIZING'
  AND stage_code = 'CLEANING_UP'
  AND lease_owner = $6
  AND fence_epoch = 1
  AND fence_token_hash = $7
  AND version = $8
RETURNING version, completed_at
`

const recordManualSuccessSQL = `
UPDATE asset_sources
SET last_success_run_id = $5::uuid,
    last_success_at = $6,
    version = version + 1
WHERE tenant_id = $1::uuid
  AND workspace_id = $2::uuid
  AND id = $3::uuid
  AND version = $4
  AND status = 'ACTIVE'
  AND gate_status = 'AVAILABLE'
  AND checkpoint_version = $7
  AND checkpoint_revision = $8
RETURNING version
`

const recheckManualFenceSQL = `
SELECT run.id::text, run.lease_owner, run.fence_epoch, run.fence_token_hash
FROM asset_source_runs AS run
JOIN asset_sources AS source
  ON source.tenant_id = run.tenant_id
 AND source.workspace_id = run.workspace_id
 AND source.id = run.source_id
WHERE run.tenant_id = $1::uuid
  AND run.workspace_id = $2::uuid
  AND run.source_id = $3::uuid
  AND run.id = $4::uuid
  AND run.status = 'SUCCEEDED'
  AND run.stage_code = 'COMPLETED'
  AND source.checkpoint_version = $5
  AND source.last_success_run_id = run.id
FOR UPDATE OF run, source
`

type manualRunIDs struct {
	asset, observation, detail, run                                 string
	managementAudit, pageAudit, cleanupAudit, terminalAudit, outbox string
}

type manualRunExecutor struct {
	ids          manualRunIDs
	fence        leasefence.Fence
	fenceHash    string
	fenceCreated bool
}

type manualSourceState struct {
	source   assetcatalog.Source
	revision assetcatalog.SourceRevision
}

type manualFacts struct {
	document, provenance, details                           []byte
	documentDigest, provenanceDigest, detailsDigest         string
	providerVersion, providerFact, fingerprint              string
	providerProvenance, chain, itemPage, relationPage, page string
	observedAt                                              time.Time
}

type persistedProvenanceValue struct {
	Confidence       int                         `json:"confidence"`
	ObservedAt       string                      `json:"observed_at"`
	Ownership        assetcatalog.FieldOwnership `json:"ownership"`
	ProviderKind     string                      `json:"provider_kind"`
	ProviderPathCode string                      `json:"provider_path_code"`
	SourceID         string                      `json:"source_id"`
	SourceRevision   int64                       `json:"source_revision"`
}

func newManualRunExecutor(ids []string) *manualRunExecutor {
	return &manualRunExecutor{ids: manualRunIDs{
		asset: ids[0], observation: ids[1], detail: ids[2], run: ids[3],
		managementAudit: ids[4], pageAudit: ids[5], cleanupAudit: ids[6], terminalAudit: ids[7], outbox: ids[8],
	}}
}

func (executor *manualRunExecutor) destroy() {
	if executor == nil || !executor.fenceCreated {
		return
	}
	executor.fence.Destroy()
	executor.fenceHash = ""
	executor.fenceCreated = false
}

func (executor *manualRunExecutor) ensureFence() error {
	if executor.fenceCreated {
		return nil
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return assetcatalog.ErrStateConflict
	}
	digest := sha256.Sum256(raw[:])
	fence, err := leasefence.FromManualRun(executor.ids.run, manualLeaseOwner, manualFenceEpoch, &raw)
	if err != nil {
		return assetcatalog.ErrStateConflict
	}
	executor.fence = fence
	executor.fenceHash = hex.EncodeToString(digest[:])
	executor.fenceCreated = true
	return nil
}

func lockEligibleManualSource(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	sourceID string,
) (manualSourceState, error) {
	var (
		source                                             assetcatalog.Source
		publishedRevision                                  *int64
		publishedDigest, gateReason                        *string
		validatedRunID, validationDigest, validatedBinding *string
		checkpointSHA, checkpointKey                       *string
		checkpointCiphertext                               []byte
		lastSuccessRunID, lastCompleteRunID                *string
	)
	if err := tx.QueryRow(ctx, lockManualSourceSQL, scope.TenantID, scope.WorkspaceID, sourceID).Scan(
		&source.ID,
		&source.TenantID,
		&source.WorkspaceID,
		&source.ProviderKind,
		&source.Name,
		&source.Kind,
		&source.Status,
		&publishedRevision,
		&publishedDigest,
		&source.GateStatus,
		&gateReason,
		&source.GateRevision,
		&validatedRunID,
		&validationDigest,
		&validatedBinding,
		&checkpointSHA,
		&source.CheckpointVersion,
		&source.CheckpointSourceRevision,
		&source.NextAllowedAt,
		&source.ConsecutiveFailures,
		&lastSuccessRunID,
		&source.LastSuccessAt,
		&lastCompleteRunID,
		&source.LastCompleteSnapshotAt,
		&source.Version,
		&source.CreatedAt,
		&source.UpdatedAt,
		&checkpointCiphertext,
		&checkpointKey,
	); err != nil {
		return manualSourceState{}, err
	}
	if publishedRevision == nil || publishedDigest == nil || validatedRunID == nil ||
		validationDigest == nil || validatedBinding == nil {
		return manualSourceState{}, assetcatalog.ErrStateConflict
	}
	source.PublishedRevision = *publishedRevision
	source.PublishedRevisionDigest = *publishedDigest
	source.GateReasonCode = optionalString(gateReason)
	source.ValidatedRunID = *validatedRunID
	source.ValidationDigest = *validationDigest
	source.ValidatedBindingDigest = *validatedBinding
	source.CheckpointSHA256 = optionalString(checkpointSHA)
	source.LastSuccessRunID = optionalString(lastSuccessRunID)
	source.LastCompleteSnapshotRunID = optionalString(lastCompleteRunID)
	canonicalizeSourceTimes(&source)
	if len(checkpointCiphertext) != 0 || checkpointKey != nil || checkpointSHA != nil {
		return manualSourceState{}, assetcatalog.ErrStateConflict
	}

	var (
		revision                                          assetcatalog.SourceRevision
		integrationID, credentialID, trustID, networkID   *string
		schedule, extensionCode, extensionDigest          *string
		revisionValidationRunID, revisionValidationDigest *string
	)
	if err := tx.QueryRow(
		ctx, lockManualRevisionSQL, scope.TenantID, scope.WorkspaceID, sourceID, source.PublishedRevision,
	).Scan(
		&revision.ID,
		&revision.SourceID,
		&revision.TenantID,
		&revision.WorkspaceID,
		&revision.Revision,
		&revision.Status,
		&revision.CanonicalProfileManifest,
		&revision.ProfileManifestSHA256,
		&revision.CanonicalProviderSchema,
		&revision.CanonicalProviderSchemaSHA256,
		&revision.SourceDefinitionDigest,
		&revision.CanonicalRevisionDigest,
		&integrationID,
		&revision.SyncMode,
		&credentialID,
		&trustID,
		&networkID,
		&revision.AuthorityScopeDigest,
		&revision.RateLimitRequests,
		&revision.RateLimitWindowSeconds,
		&revision.BackpressureBaseSeconds,
		&revision.BackpressureMaxSeconds,
		&revision.ProfileCode,
		&schedule,
		&extensionCode,
		&extensionDigest,
		&revisionValidationRunID,
		&revisionValidationDigest,
		&revision.CreatedBy,
		&revision.ChangeReasonCode,
		&revision.ExpectedSourceVersion,
		&revision.Version,
		&revision.CreatedAt,
		&revision.UpdatedAt,
	); err != nil {
		return manualSourceState{}, err
	}
	revision.IntegrationID = optionalString(integrationID)
	revision.CredentialReferenceID = assetcatalog.CredentialReferenceID(optionalString(credentialID))
	revision.TrustReferenceID = assetcatalog.TrustReferenceID(optionalString(trustID))
	revision.NetworkPolicyReferenceID = assetcatalog.NetworkPolicyReferenceID(optionalString(networkID))
	revision.ScheduleExpression = optionalString(schedule)
	revision.TypedExtensionCode = assetcatalog.ExtensionCode(optionalString(extensionCode))
	revision.PreparedExtensionDigest = optionalString(extensionDigest)
	revision.ValidationRunID = optionalString(revisionValidationRunID)
	revision.ValidationDigest = optionalString(revisionValidationDigest)
	revision.CreatedAt = canonicalDatabaseTime(revision.CreatedAt)
	revision.UpdatedAt = canonicalDatabaseTime(revision.UpdatedAt)

	rows, err := tx.Query(
		ctx, readManualAuthoritiesSQL, scope.TenantID, scope.WorkspaceID, sourceID, revision.Revision,
	)
	if err != nil {
		return manualSourceState{}, err
	}
	defer rows.Close()
	ordinals := make([]int, 0, 2)
	for rows.Next() {
		var environmentID string
		var ordinal int
		if err := rows.Scan(&environmentID, &ordinal); err != nil {
			return manualSourceState{}, err
		}
		revision.AuthorityEnvironmentIDs = append(revision.AuthorityEnvironmentIDs, environmentID)
		ordinals = append(ordinals, ordinal)
	}
	if err := rows.Err(); err != nil {
		return manualSourceState{}, err
	}
	if len(revision.AuthorityEnvironmentIDs) != 1 || len(ordinals) != 1 || ordinals[0] != 1 {
		return manualSourceState{}, assetcatalog.ErrStateConflict
	}
	if revision.AuthorityEnvironmentIDs[0] != scope.EnvironmentID {
		return manualSourceState{}, assetcatalog.ErrScopeViolation
	}
	profile := assetcatalog.ManualProfileV1()
	if !exactManualProfile(source, revision, profile) || source.Validate() != nil || revision.Validate() != nil ||
		!source.PublishedBindingEligible(revision) {
		return manualSourceState{}, assetcatalog.ErrStateConflict
	}
	return manualSourceState{source: source.Clone(), revision: revision.Clone()}, nil
}

func (executor *manualRunExecutor) execute(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	command assetcatalog.CreateAssetCommand,
	commandHash string,
	manual manualSourceState,
) (assetcatalog.AssetMutationResult, error) {
	var existingID string
	err := tx.QueryRow(
		ctx,
		existingManualAssetSQL,
		scope.TenantID,
		scope.WorkspaceID,
		manual.source.ID,
		manual.source.ProviderKind,
		command.ExternalID,
	).Scan(&existingID)
	if err == nil {
		return assetcatalog.AssetMutationResult{}, assetcatalog.ErrStateConflict
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return assetcatalog.AssetMutationResult{}, err
	}
	if err := executor.ensureFence(); err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	if err := insertMutationAuditRecord(
		ctx,
		tx,
		executor.ids.managementAudit,
		command.Context,
		assetCreatedAction,
		executor.ids.asset,
		scope,
		mutationAuditDetails{
			EnvironmentID: scope.EnvironmentID, ResultVersion: 1,
			Lifecycle: assetcatalog.LifecycleDiscovered, CommandSHA256: commandHash,
		},
	); err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	if _, err := tx.Exec(
		ctx,
		insertManualRunSQL,
		executor.ids.run,
		scope.TenantID,
		scope.WorkspaceID,
		manual.source.ID,
		manual.revision.Revision,
		manual.revision.CanonicalRevisionDigest,
		manual.source.GateRevision,
		command.Context.IdempotencyKey(),
		command.Context.RequestHash(),
		manual.source.CheckpointVersion,
		command.Context.TraceID(),
	); err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	claimedVersion, err := executor.claim(ctx, tx, scope, manual)
	if err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	normalizingVersion, err := executor.advanceStage(
		ctx, tx, scope, manual.source.ID, "NORMALIZING", "READING", claimedVersion,
	)
	if err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	applyingVersion, err := executor.advanceStage(
		ctx, tx, scope, manual.source.ID, "APPLYING", "NORMALIZING", normalizingVersion,
	)
	if err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}

	var observedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&observedAt); err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	observedAt = canonicalDatabaseTime(observedAt)
	nextCheckpoint := manual.source.CheckpointVersion + 1
	facts, err := buildManualFacts(scope, command, manual, executor.ids, observedAt, nextCheckpoint)
	if err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	if err := insertManualProjection(ctx, tx, scope, command, manual, executor.ids, facts, nextCheckpoint); err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	if err := insertManualRunReceipt(
		ctx,
		tx,
		executor.ids.pageAudit,
		scope,
		executor.ids.run,
		"PAGE_APPLIED",
		"source-page:"+executor.ids.run+":1",
		command.Context.TraceID(),
		facts.page,
	); err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	var cleanupDigest string
	if err := tx.QueryRow(
		ctx,
		manualCleanupDigestSQL,
		scope.TenantID,
		scope.WorkspaceID,
		manual.source.ID,
		executor.ids.run,
	).Scan(&cleanupDigest); err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	if !validSHA256(cleanupDigest) {
		return assetcatalog.AssetMutationResult{}, assetcatalog.ErrStateConflict
	}
	if err := insertManualRunReceipt(
		ctx,
		tx,
		executor.ids.cleanupAudit,
		scope,
		executor.ids.run,
		"ATTEMPT_CLEANED",
		"source-attempt:"+executor.ids.run+":0",
		command.Context.TraceID(),
		cleanupDigest,
	); err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	var checkpointSourceVersion int64
	if err := tx.QueryRow(
		ctx,
		advanceManualCheckpointSQL,
		scope.TenantID,
		scope.WorkspaceID,
		manual.source.ID,
		manual.source.Version,
		manual.source.CheckpointVersion,
		nextCheckpoint,
		manual.revision.Revision,
	).Scan(&checkpointSourceVersion); err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	finalizingVersion, err := executor.finalize(
		ctx, tx, scope, manual.source.ID, facts.page, nextCheckpoint, cleanupDigest,
		manual.source.CheckpointVersion, applyingVersion,
	)
	if err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	var terminalDigest string
	if err := tx.QueryRow(
		ctx,
		manualTerminalDigestSQL,
		scope.TenantID,
		scope.WorkspaceID,
		manual.source.ID,
		executor.ids.run,
	).Scan(&terminalDigest); err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	if !validSHA256(terminalDigest) {
		return assetcatalog.AssetMutationResult{}, assetcatalog.ErrStateConflict
	}
	if err := insertManualRunReceipt(
		ctx,
		tx,
		executor.ids.terminalAudit,
		scope,
		executor.ids.run,
		"TERMINAL_COMMITTED",
		"source-terminal:"+executor.ids.run,
		command.Context.TraceID(),
		terminalDigest,
	); err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	completedAt, err := executor.complete(
		ctx, tx, scope, manual.source.ID, terminalDigest, finalizingVersion,
	)
	if err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	var finalSourceVersion int64
	if err := tx.QueryRow(
		ctx,
		recordManualSuccessSQL,
		scope.TenantID,
		scope.WorkspaceID,
		manual.source.ID,
		checkpointSourceVersion,
		executor.ids.run,
		completedAt,
		nextCheckpoint,
		manual.revision.Revision,
	).Scan(&finalSourceVersion); err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	if finalSourceVersion != checkpointSourceVersion+1 {
		return assetcatalog.AssetMutationResult{}, assetcatalog.ErrStateConflict
	}
	model, err := loadAssetDetailInTx(ctx, tx, scope, executor.ids.asset)
	if err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	if err := insertAssetOutboxRecord(
		ctx, tx, executor.ids.outbox, command.Context.TraceID(), assetCreatedAction, model.Asset,
	); err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	if err := executor.recheckFence(ctx, tx, scope, manual.source.ID, nextCheckpoint); err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	return assetcatalog.AssetMutationResult{
		Asset: model,
		Receipt: assetcatalog.MutationReceipt{
			AuditID: executor.ids.managementAudit, TraceID: command.Context.TraceID(), IdempotentReplay: false,
		},
	}, nil
}

func (executor *manualRunExecutor) claim(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	manual manualSourceState,
) (int64, error) {
	var runID, owner, tokenHash string
	var epoch, version int64
	if err := tx.QueryRow(
		ctx,
		claimManualRunSQL,
		scope.TenantID,
		scope.WorkspaceID,
		manual.source.ID,
		executor.ids.run,
		manualLeaseOwner,
		executor.fenceHash,
		manual.source.CheckpointVersion,
	).Scan(&runID, &owner, &epoch, &tokenHash, &version); err != nil {
		return 0, err
	}
	if !executor.fence.Matches(runID, owner, epoch, tokenHash) || version != 2 {
		return 0, assetcatalog.ErrStateConflict
	}
	return version, nil
}

func (executor *manualRunExecutor) advanceStage(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	sourceID, nextStage, currentStage string,
	version int64,
) (int64, error) {
	var nextVersion int64
	if err := tx.QueryRow(
		ctx,
		advanceManualRunStageSQL,
		scope.TenantID,
		scope.WorkspaceID,
		sourceID,
		executor.ids.run,
		nextStage,
		currentStage,
		manualLeaseOwner,
		executor.fenceHash,
		version,
	).Scan(&nextVersion); err != nil {
		return 0, err
	}
	if nextVersion != version+1 {
		return 0, assetcatalog.ErrStateConflict
	}
	return nextVersion, nil
}

func (executor *manualRunExecutor) finalize(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	sourceID, pageDigest string,
	nextCheckpoint int64,
	cleanupDigest string,
	previousCheckpoint, version int64,
) (int64, error) {
	var runID, owner, tokenHash string
	var epoch, nextVersion int64
	if err := tx.QueryRow(
		ctx,
		finalizeManualRunSQL,
		scope.TenantID,
		scope.WorkspaceID,
		sourceID,
		executor.ids.run,
		pageDigest,
		nextCheckpoint,
		cleanupDigest,
		previousCheckpoint,
		manualLeaseOwner,
		executor.fenceHash,
		version,
	).Scan(&runID, &owner, &epoch, &tokenHash, &nextVersion); err != nil {
		return 0, err
	}
	if !executor.fence.Matches(runID, owner, epoch, tokenHash) || nextVersion != version+1 {
		return 0, assetcatalog.ErrStateConflict
	}
	return nextVersion, nil
}

func (executor *manualRunExecutor) complete(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	sourceID, terminalDigest string,
	version int64,
) (time.Time, error) {
	var nextVersion int64
	var completedAt time.Time
	if err := tx.QueryRow(
		ctx,
		completeManualRunSQL,
		scope.TenantID,
		scope.WorkspaceID,
		sourceID,
		executor.ids.run,
		terminalDigest,
		manualLeaseOwner,
		executor.fenceHash,
		version,
	).Scan(&nextVersion, &completedAt); err != nil {
		return time.Time{}, err
	}
	if nextVersion != version+1 {
		return time.Time{}, assetcatalog.ErrStateConflict
	}
	return canonicalDatabaseTime(completedAt), nil
}

func (executor *manualRunExecutor) recheckFence(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	sourceID string,
	checkpointVersion int64,
) error {
	var runID, owner, tokenHash string
	var epoch int64
	if err := tx.QueryRow(
		ctx,
		recheckManualFenceSQL,
		scope.TenantID,
		scope.WorkspaceID,
		sourceID,
		executor.ids.run,
		checkpointVersion,
	).Scan(&runID, &owner, &epoch, &tokenHash); err != nil {
		return err
	}
	if !executor.fence.Matches(runID, owner, epoch, tokenHash) {
		return assetcatalog.ErrStateConflict
	}
	return nil
}

func insertManualProjection(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	command assetcatalog.CreateAssetCommand,
	manual manualSourceState,
	ids manualRunIDs,
	facts manualFacts,
	checkpointVersion int64,
) error {
	if _, err := tx.Exec(
		ctx,
		insertManualObservationSQL,
		ids.observation,
		scope.TenantID,
		scope.WorkspaceID,
		scope.EnvironmentID,
		manual.source.ID,
		ids.run,
		manual.source.ProviderKind,
		command.ExternalID,
		manual.revision.Revision,
		manual.revision.CanonicalRevisionDigest,
		manual.revision.SourceDefinitionDigest,
		facts.observedAt,
		checkpointVersion,
		facts.providerVersion,
		facts.providerFact,
		facts.fingerprint,
		facts.providerProvenance,
		facts.chain,
		checkpointVersion,
		manualSchemaVersion,
		facts.document,
		facts.documentDigest,
		facts.provenance,
		facts.provenanceDigest,
	); err != nil {
		return err
	}
	labels, _ := json.Marshal(command.Labels)
	if _, err := tx.Exec(
		ctx,
		insertManualAssetSQL,
		ids.asset,
		scope.TenantID,
		scope.WorkspaceID,
		scope.EnvironmentID,
		manual.source.ID,
		manual.source.ProviderKind,
		command.ExternalID,
		command.Kind,
		command.DisplayName,
		command.OwnerGroup,
		command.Criticality,
		command.DataClassification,
		string(labels),
		ids.observation,
		facts.chain,
		facts.observedAt,
		manual.revision.Revision,
		command.Context.IdempotencyKey(),
		command.Context.RequestHash(),
	); err != nil {
		return err
	}
	_, err := tx.Exec(
		ctx,
		insertManualTypeDetailSQL,
		ids.detail,
		scope.TenantID,
		scope.WorkspaceID,
		scope.EnvironmentID,
		ids.asset,
		manual.source.ID,
		manual.source.ProviderKind,
		command.ExternalID,
		manual.revision.Revision,
		facts.observedAt,
		facts.chain,
		manualSchemaVersion,
		ids.observation,
		facts.details,
		facts.detailsDigest,
		command.Context.ActorID(),
	)
	return err
}

func insertManualRunReceipt(
	ctx context.Context,
	tx pgx.Tx,
	auditID string,
	scope assetcatalog.Scope,
	runID, action, requestID, traceID, payloadHash string,
) error {
	_, err := tx.Exec(
		ctx,
		insertManualRunReceiptSQL,
		auditID,
		scope.TenantID,
		scope.WorkspaceID,
		manualLeaseOwner,
		action,
		runID,
		requestID,
		traceID,
		payloadHash,
	)
	return err
}

func buildManualFacts(
	scope assetcatalog.Scope,
	command assetcatalog.CreateAssetCommand,
	manual manualSourceState,
	ids manualRunIDs,
	observedAt time.Time,
	checkpointVersion int64,
) (manualFacts, error) {
	document, err := canonicalJSON(map[string]any{
		"display_name": command.DisplayName,
		"external_id":  command.ExternalID,
		"kind":         command.Kind,
	})
	if err != nil {
		return manualFacts{}, assetcatalog.ErrStateConflict
	}
	const observedAtLayout = "2006-01-02T15:04:05.000000Z"
	observedAtText := observedAt.Format(observedAtLayout)
	provenanceValues := map[string]persistedProvenanceValue{
		"display_name": {
			Confidence: 100, ObservedAt: observedAtText, Ownership: assetcatalog.FieldOwnershipSource,
			ProviderKind: manual.source.ProviderKind, ProviderPathCode: "MANUAL_V1_DISPLAY_NAME",
			SourceID: manual.source.ID, SourceRevision: manual.revision.Revision,
		},
		"external_id": {
			Confidence: 100, ObservedAt: observedAtText, Ownership: assetcatalog.FieldOwnershipSource,
			ProviderKind: manual.source.ProviderKind, ProviderPathCode: "MANUAL_V1_EXTERNAL_ID",
			SourceID: manual.source.ID, SourceRevision: manual.revision.Revision,
		},
		"kind": {
			Confidence: 100, ObservedAt: observedAtText, Ownership: assetcatalog.FieldOwnershipSource,
			ProviderKind: manual.source.ProviderKind, ProviderPathCode: "MANUAL_V1_KIND",
			SourceID: manual.source.ID, SourceRevision: manual.revision.Revision,
		},
	}
	provenance, err := canonicalJSON(provenanceValues)
	if err != nil {
		return manualFacts{}, assetcatalog.ErrStateConflict
	}
	details := []byte(`{}`)
	documentDigest := sha256Hex(document)
	provenanceDigest := sha256Hex(provenance)
	detailsDigest := sha256Hex(details)

	providerVersion := framedDigest(
		[]byte("manual-catalog-version.v1"),
		[]byte(scope.TenantID),
		[]byte(scope.WorkspaceID),
		[]byte(manual.source.ID),
		[]byte(strconv.FormatInt(manual.revision.Revision, 10)),
		[]byte(strconv.FormatInt(checkpointVersion, 10)),
	)
	fingerprint := framedDigest([]byte("asset-fingerprints.v1"), []byte("0"))
	fieldCodes := []string{"display_name", "external_id", "kind"}
	sort.Strings(fieldCodes)
	providerProvenanceFrames := [][]byte{[]byte("asset-provider-provenance.v1"), []byte(strconv.Itoa(len(fieldCodes)))}
	for _, fieldCode := range fieldCodes {
		item := provenanceValues[fieldCode]
		providerProvenanceFrames = append(providerProvenanceFrames,
			[]byte(fieldCode), []byte(item.ProviderPathCode), []byte(item.Ownership), []byte(strconv.Itoa(item.Confidence)),
		)
	}
	providerProvenance := framedDigest(providerProvenanceFrames...)
	providerFact, err := framedDigestWithNamedHashes([]manualFrame{
		{value: []byte("asset-provider-fact.v1")},
		{value: []byte(scope.TenantID)},
		{value: []byte(scope.WorkspaceID)},
		{value: []byte(manual.source.ID)},
		{value: []byte(manual.source.ProviderKind)},
		{value: []byte(strconv.FormatInt(manual.revision.Revision, 10))},
		{digest: manual.revision.CanonicalRevisionDigest},
		{digest: manual.revision.SourceDefinitionDigest},
		{value: []byte(scope.EnvironmentID)},
		{value: []byte(command.ExternalID)},
		{value: []byte(command.Kind)},
		{value: []byte(command.DisplayName)},
		{value: []byte(manualSchemaVersion)},
		{value: []byte("0")},
		{null: true},
		{digest: documentDigest},
		{digest: fingerprint},
		{digest: providerProvenance},
	})
	if err != nil {
		return manualFacts{}, assetcatalog.ErrStateConflict
	}
	chain, err := framedDigestWithNamedHashes([]manualFrame{
		{value: []byte("asset-observation-chain.v1")},
		{value: []byte(scope.TenantID)},
		{value: []byte(scope.WorkspaceID)},
		{value: []byte(scope.EnvironmentID)},
		{value: []byte(manual.source.ID)},
		{value: []byte(ids.run)},
		{value: []byte(ids.observation)},
		{value: []byte(manual.source.ProviderKind)},
		{value: []byte(command.ExternalID)},
		{value: []byte(strconv.FormatInt(manual.revision.Revision, 10))},
		{digest: manual.revision.CanonicalRevisionDigest},
		{value: []byte(observedAtText)},
		{value: []byte(assetcatalog.FreshnessCatalogSequence)},
		{null: true},
		{value: []byte(strconv.FormatInt(checkpointVersion, 10))},
		{digest: providerVersion},
		{value: []byte(strconv.FormatInt(checkpointVersion, 10))},
		{value: []byte(strconv.FormatInt(manualFenceEpoch, 10))},
		{value: []byte(strconv.FormatInt(manualPageSequence, 10))},
		{digest: providerFact},
		{digest: provenanceDigest},
		{null: true},
		{null: true},
	})
	if err != nil {
		return manualFacts{}, assetcatalog.ErrStateConflict
	}
	itemPage, err := framedDigestWithNamedHashes([]manualFrame{
		{value: []byte("asset-item-page.v1")},
		{value: []byte("1")},
		{value: []byte(scope.EnvironmentID)},
		{value: []byte(manual.source.ProviderKind)},
		{value: []byte(command.ExternalID)},
		{value: []byte(assetcatalog.FreshnessCatalogSequence)},
		{null: true},
		{value: []byte(strconv.FormatInt(checkpointVersion, 10))},
		{digest: providerVersion},
		{digest: providerFact},
	})
	if err != nil {
		return manualFacts{}, assetcatalog.ErrStateConflict
	}
	relationPage := framedDigest([]byte("asset-relation-page.v1"), []byte("0"))
	page, err := framedDigestWithNamedHashes([]manualFrame{
		{value: []byte("asset-source-page.v2")},
		{value: []byte(scope.TenantID)},
		{value: []byte(scope.WorkspaceID)},
		{value: []byte(manual.source.ID)},
		{value: []byte(ids.run)},
		{value: []byte("1")},
		{null: true},
		{null: true},
		{value: []byte("1")},
		{value: []byte("0")},
		{value: []byte("1")},
		{digest: itemPage},
		{value: []byte("0")},
		{digest: relationPage},
	})
	if err != nil {
		return manualFacts{}, assetcatalog.ErrStateConflict
	}
	observation := assetcatalog.Observation{
		ID: ids.observation, SourceID: manual.source.ID, RunID: ids.run,
		ProviderKind: manual.source.ProviderKind, ExternalID: command.ExternalID, Scope: scope,
		SourceRevision:          manual.revision.Revision,
		CanonicalRevisionDigest: manual.revision.CanonicalRevisionDigest,
		SourceDefinitionDigest:  manual.revision.SourceDefinitionDigest,
		ObservedAt:              observedAt, FreshnessKind: assetcatalog.FreshnessCatalogSequence,
		FreshnessOrderSequence: checkpointVersion, ProviderVersionSHA256: providerVersion,
		ProviderFactSHA256: providerFact, FingerprintSHA256: fingerprint,
		ProviderProvenanceSHA256: providerProvenance, ObservationChainSHA256: chain,
		AcceptedCheckpointVersion: checkpointVersion, RunFenceEpoch: manualFenceEpoch,
		RunPageSequence: manualPageSequence, SchemaVersion: manualSchemaVersion,
		NormalizedDocument: document, DocumentSHA256: documentDigest,
		FieldProvenance: provenance, FieldProvenanceSHA256: provenanceDigest, CreatedAt: observedAt,
	}
	if err := observation.Validate(); err != nil {
		return manualFacts{}, assetcatalog.ErrStateConflict
	}
	return manualFacts{
		document: document, provenance: provenance, details: details,
		documentDigest: documentDigest, provenanceDigest: provenanceDigest, detailsDigest: detailsDigest,
		providerVersion: providerVersion, providerFact: providerFact, fingerprint: fingerprint,
		providerProvenance: providerProvenance, chain: chain, itemPage: itemPage,
		relationPage: relationPage, page: page, observedAt: observedAt,
	}, nil
}

type manualFrame struct {
	value  []byte
	digest string
	null   bool
}

func framedDigestWithNamedHashes(frames []manualFrame) (string, error) {
	values := make([][]byte, 0, len(frames))
	for _, frame := range frames {
		switch {
		case frame.null:
			values = append(values, nil)
		case frame.digest != "":
			value, err := hex.DecodeString(frame.digest)
			if err != nil || len(value) != sha256.Size {
				return "", assetcatalog.ErrStateConflict
			}
			values = append(values, value)
		default:
			values = append(values, frame.value)
		}
	}
	return framedDigest(values...), nil
}

func framedDigest(frames ...[]byte) string {
	hash := sha256.New()
	var length [4]byte
	for _, frame := range frames {
		if frame == nil {
			_, _ = hash.Write([]byte{0})
			continue
		}
		_, _ = hash.Write([]byte{1})
		binary.BigEndian.PutUint32(length[:], uint32(len(frame)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(frame)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func canonicalJSON(value any) ([]byte, error) {
	wire, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(wire)
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == hex.EncodeToString(decoded)
}

func exactManualProfile(
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
	return source.Kind == profile.SourceKind && source.ProviderKind == profile.ProviderKind &&
		source.Status == assetcatalog.SourceStatusActive && source.GateStatus == assetcatalog.SourceGateAvailable &&
		source.GateReasonCode == "" && source.CheckpointSourceRevision == revision.Revision &&
		source.PublishedRevision == revision.Revision && source.CheckpointVersion >= 0 && source.CheckpointSHA256 == "" &&
		revision.Status == assetcatalog.SourceRevisionPublished &&
		bytes.Equal(revision.CanonicalProfileManifest, profile.CanonicalProfileManifest) &&
		revision.ProfileManifestSHA256 == profile.ProfileManifestSHA256 &&
		bytes.Equal(revision.CanonicalProviderSchema, profile.CanonicalProviderSchema) &&
		revision.CanonicalProviderSchemaSHA256 == profile.CanonicalProviderSchemaSHA256 &&
		revision.IntegrationID == profile.IntegrationID && revision.SyncMode == profile.SyncMode &&
		revision.CredentialReferenceID == profile.CredentialReferenceID &&
		revision.TrustReferenceID == profile.TrustReferenceID &&
		revision.NetworkPolicyReferenceID == profile.NetworkPolicyReferenceID &&
		revision.RateLimitRequests == profile.RateLimitRequests &&
		revision.RateLimitWindowSeconds == profile.RateLimitWindowSeconds &&
		revision.BackpressureBaseSeconds == profile.BackpressureBaseSeconds &&
		revision.BackpressureMaxSeconds == profile.BackpressureMaxSeconds &&
		revision.ProfileCode == profile.ProfileCode && revision.ScheduleExpression == profile.ScheduleExpression &&
		revision.TypedExtensionCode == profile.TypedExtensionCode &&
		revision.PreparedExtensionDigest == profile.PreparedExtensionDigest &&
		revision.SourceDefinitionDigest == expectedDefinition && revision.AuthorityScopeDigest == expectedAuthority
}

func canonicalizeSourceTimes(source *assetcatalog.Source) {
	source.CreatedAt = canonicalDatabaseTime(source.CreatedAt)
	source.UpdatedAt = canonicalDatabaseTime(source.UpdatedAt)
	canonicalizeTimePointer(source.NextAllowedAt)
	canonicalizeTimePointer(source.LastSuccessAt)
	canonicalizeTimePointer(source.LastCompleteSnapshotAt)
}

func canonicalizeTimePointer(value *time.Time) {
	if value == nil {
		return
	}
	*value = canonicalDatabaseTime(*value)
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
