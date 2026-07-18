package discoveryruntime

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetsource/externalcmdb"
	"github.com/seaworld008/aiops-system/internal/discoverycheckpoint"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/seaworld008/aiops-system/internal/sourceprofile"
)

// Postgres resolves only immutable Source, Revision, run, lease, and opaque
// reference facts. It deliberately has no access path to integrations.config,
// integrations.secret_ref, or resolved runtime material.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres creates an exact-fact resolver. Every read independently proves
// the PostgreSQL 18.4 TLS application identity before returning safe facts.
func NewPostgres(pool *pgxpool.Pool) (*Postgres, error) {
	if pool == nil {
		return nil, ErrExternalCMDBRuntimeAuthority
	}
	return &Postgres{pool: pool}, nil
}

type postgresExternalCMDBRow struct {
	sourceID, revisionDigest                          string
	sourceRevision, runCheckpointVersion              int64
	runKind                                           assetcatalog.RunKind
	revisionStatus                                    assetcatalog.SourceRevisionStatus
	canonicalProfileManifest, canonicalProviderSchema []byte
	profileManifestSHA256, providerSchemaSHA256       string
	integrationID                                     string
	syncMode                                          assetcatalog.SyncMode
	authorityScopeSHA256, sourceDefinitionSHA256      string
	canonicalRevisionSHA256                           string
	credentialReferenceID, trustReferenceID           string
	networkPolicyReferenceID                          string
	rateLimitRequests, rateLimitWindowSeconds         int64
	backpressureBaseSeconds, backpressureMaxSeconds   int64
	profileCode                                       assetcatalog.ProfileCode
	scheduleExpression, typedExtensionCode            *string
	preparedExtensionSHA256                           *string
	validationRunID, validationSHA256                 *string
	authorityEnvironmentIDs                           []string
	checkpointEnvelope                                []byte
	checkpointKeyID, checkpointSHA256                 *string
	checkpointVersion, checkpointRevision             int64
	cursorBeforeSHA256, cursorAfterSHA256             *string
	initialAllowed                                    bool
	databaseNow, leaseExpiresAt                       time.Time
}

const resolveExternalCMDBAttemptSQL = `
SELECT
  run.source_id::text,
  run.source_revision,
  run.source_revision_digest,
  run.run_kind,
  revision.state,
  revision.canonical_profile_manifest,
  revision.profile_manifest_sha256,
  revision.canonical_provider_schema,
  revision.canonical_provider_schema_sha256,
  revision.integration_id::text,
  revision.sync_mode,
  revision.authority_scope_digest,
  revision.source_definition_digest,
  revision.canonical_revision_digest,
  revision.credential_reference_id,
  revision.trust_reference_id,
  revision.network_policy_reference_id,
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
  ARRAY(
    SELECT authority.environment_id::text
    FROM public.asset_source_revision_authorities AS authority
    WHERE authority.tenant_id=revision.tenant_id
      AND authority.workspace_id=revision.workspace_id
      AND authority.source_id=revision.source_id
      AND authority.source_revision=revision.revision
    ORDER BY authority.canonical_ordinal
  )::text[],
  source.checkpoint_ciphertext,
  source.checkpoint_key_id,
  source.checkpoint_sha256,
  source.checkpoint_version,
  source.checkpoint_revision,
  run.checkpoint_version,
  run.cursor_before_sha256,
  run.cursor_after_sha256,
  clock_timestamp(),
  run.lease_expires_at,
  (
    run.status='RUNNING'
    AND run.fence_epoch=run.cleanup_attempt_epoch
    AND run.work_result_kind IS NULL
    AND run.pending_transition_digest IS NULL
    AND source.status='ACTIVE'
    AND (source.next_allowed_at IS NULL OR source.next_allowed_at<=clock_timestamp())
    AND (
      (
        run.run_kind='VALIDATION'
        AND run.stage_code='VALIDATING'
        AND revision.state='VALIDATING'
        AND revision.validation_run_id=run.id
        AND run.checkpoint_version=0
        AND run.cursor_before_sha256 IS NULL
        AND run.cursor_after_sha256 IS NULL
        AND (
          (
            source.gate_status='UNAVAILABLE'
            AND source.gate_revision=run.gate_revision
          )
          OR (
            source.gate_status='VALIDATING'
            AND source.validated_run_id=run.id
            AND source.validation_digest IS NULL
            AND source.validated_binding_digest IS NULL
            AND source.gate_revision=run.gate_revision+1
          )
        )
      )
      OR (
        run.run_kind='DISCOVERY'
        AND run.stage_code='READING'
        AND revision.state='PUBLISHED'
        AND source.published_revision=run.source_revision
        AND source.published_revision_digest=run.source_revision_digest
        AND source.checkpoint_revision=run.source_revision
        AND source.checkpoint_version=run.checkpoint_version
        AND source.checkpoint_sha256 IS NOT DISTINCT FROM
            COALESCE(run.cursor_after_sha256,run.cursor_before_sha256)
        AND (
          (
            run.lineage_rollover_reason IS NULL
            AND source.gate_status='AVAILABLE'
            AND source.gate_revision=run.gate_revision
          )
          OR (
            run.lineage_rollover_reason IS NOT NULL
            AND source.gate_status='DEGRADED'
            AND source.gate_reason_code='CHECKPOINT_LINEAGE_ROLLOVER'
            AND source.gate_revision=run.gate_revision+1
          )
        )
      )
    )
  ) AS initial_allowed
FROM public.asset_source_runs AS run
JOIN public.asset_sources AS source
  ON source.tenant_id=run.tenant_id
 AND source.workspace_id=run.workspace_id
 AND source.id=run.source_id
JOIN public.asset_source_revisions AS revision
  ON revision.tenant_id=run.tenant_id
 AND revision.workspace_id=run.workspace_id
 AND revision.source_id=run.source_id
 AND revision.revision=run.source_revision
 AND revision.canonical_revision_digest=run.source_revision_digest
WHERE run.tenant_id=$1::uuid
  AND run.workspace_id=$2::uuid
  AND run.id=$3::uuid
  AND SESSION_USER='aiops_control_plane_workload'
  AND CURRENT_USER='aiops_control_plane_workload'
  AND current_setting('server_version_num')::integer BETWEEN 180004 AND 189999
  AND EXISTS (
    SELECT 1
    FROM pg_catalog.pg_stat_ssl AS transport
    WHERE transport.pid=pg_backend_pid()
      AND transport.ssl
      AND transport.version='TLSv1.3'
  )
  AND run.cleanup_attempt_id=$4::uuid
  AND run.cleanup_attempt_epoch=$5::bigint
  AND run.fence_epoch>=run.cleanup_attempt_epoch
  AND run.cleanup_status='PENDING'
  AND run.status IN ('RUNNING','FINALIZING')
  AND run.lease_owner IS NOT NULL
  AND run.fence_token_hash IS NOT NULL
  AND run.lease_expires_at>clock_timestamp()
  AND source.source_kind='EXTERNAL_CMDB'
  AND source.provider_kind='CMDB_CATALOG_V1'
FOR SHARE OF run,source,revision
`

func (postgres *Postgres) resolveExternalCMDBAttempt(
	ctx context.Context,
	key externalCMDBAttemptKey,
) (externalCMDBAttemptSnapshot, error) {
	if ctx == nil || !key.valid() || postgres == nil || postgres.pool == nil {
		return externalCMDBAttemptSnapshot{}, ErrExternalCMDBRuntimeAuthority
	}
	if err := ctx.Err(); err != nil {
		return externalCMDBAttemptSnapshot{}, err
	}
	tx, err := postgres.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.Serializable},
	)
	if err != nil {
		return externalCMDBAttemptSnapshot{}, boundedRuntimeAuthorityError(err)
	}
	defer func() {
		_ = tx.Rollback(context.Background())
	}()

	snapshot, err := postgres.loadExternalCMDBAttempt(ctx, tx, key)
	if err != nil {
		return externalCMDBAttemptSnapshot{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return externalCMDBAttemptSnapshot{}, boundedRuntimeAuthorityError(err)
	}
	return snapshot, nil
}

func (postgres *Postgres) admitExternalCMDBMaterial(
	ctx context.Context,
	key externalCMDBAttemptKey,
	expected externalCMDBAttemptSnapshot,
	use func(context.Context, externalCMDBAttemptSnapshot) error,
) error {
	if ctx == nil || !key.valid() || expected.key != key || use == nil ||
		postgres == nil || postgres.pool == nil {
		return ErrExternalCMDBRuntimeAuthority
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := postgres.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.Serializable},
	)
	if err != nil {
		return boundedRuntimeAuthorityError(err)
	}
	defer func() {
		_ = tx.Rollback(context.Background())
	}()

	confirmed, err := postgres.loadExternalCMDBAttempt(ctx, tx, key)
	if err != nil || !expected.same(confirmed) ||
		!expected.initialAllowed || !confirmed.initialAllowed ||
		confirmed.materialDeadline.IsZero() ||
		!time.Now().Before(confirmed.materialDeadline) {
		clear(confirmed.sealedCheckpoint.Envelope)
		return boundedRuntimeAuthorityError(err)
	}
	admissionContext, cancel := context.WithDeadline(
		ctx,
		confirmed.materialDeadline,
	)
	defer cancel()
	callbackSnapshot := confirmed.clone()
	err = use(admissionContext, callbackSnapshot)
	clear(callbackSnapshot.sealedCheckpoint.Envelope)
	if err != nil {
		clear(confirmed.sealedCheckpoint.Envelope)
		return boundedRuntimeAuthorityError(err)
	}
	if err := admissionContext.Err(); err != nil {
		clear(confirmed.sealedCheckpoint.Envelope)
		return err
	}
	rechecked, err := postgres.loadExternalCMDBAttempt(
		admissionContext,
		tx,
		key,
	)
	if err != nil || !confirmed.same(rechecked) {
		clear(confirmed.sealedCheckpoint.Envelope)
		clear(rechecked.sealedCheckpoint.Envelope)
		return boundedRuntimeAuthorityError(err)
	}
	clear(confirmed.sealedCheckpoint.Envelope)
	clear(rechecked.sealedCheckpoint.Envelope)
	if err := tx.Commit(admissionContext); err != nil {
		return boundedRuntimeAuthorityError(err)
	}
	return nil
}

func (postgres *Postgres) loadExternalCMDBAttempt(
	ctx context.Context,
	tx pgx.Tx,
	key externalCMDBAttemptKey,
) (externalCMDBAttemptSnapshot, error) {
	if ctx == nil || tx == nil || !key.valid() {
		return externalCMDBAttemptSnapshot{}, ErrExternalCMDBRuntimeAuthority
	}
	queryStarted := time.Now()
	var row postgresExternalCMDBRow
	err := tx.QueryRow(
		ctx,
		resolveExternalCMDBAttemptSQL,
		key.coordinates.Scope.TenantID,
		key.coordinates.Scope.WorkspaceID,
		key.coordinates.RunID,
		key.attempt.AttemptID,
		key.attempt.AttemptEpoch,
	).Scan(
		&row.sourceID,
		&row.sourceRevision,
		&row.revisionDigest,
		&row.runKind,
		&row.revisionStatus,
		&row.canonicalProfileManifest,
		&row.profileManifestSHA256,
		&row.canonicalProviderSchema,
		&row.providerSchemaSHA256,
		&row.integrationID,
		&row.syncMode,
		&row.authorityScopeSHA256,
		&row.sourceDefinitionSHA256,
		&row.canonicalRevisionSHA256,
		&row.credentialReferenceID,
		&row.trustReferenceID,
		&row.networkPolicyReferenceID,
		&row.rateLimitRequests,
		&row.rateLimitWindowSeconds,
		&row.backpressureBaseSeconds,
		&row.backpressureMaxSeconds,
		&row.profileCode,
		&row.scheduleExpression,
		&row.typedExtensionCode,
		&row.preparedExtensionSHA256,
		&row.validationRunID,
		&row.validationSHA256,
		&row.authorityEnvironmentIDs,
		&row.checkpointEnvelope,
		&row.checkpointKeyID,
		&row.checkpointSHA256,
		&row.checkpointVersion,
		&row.checkpointRevision,
		&row.runCheckpointVersion,
		&row.cursorBeforeSHA256,
		&row.cursorAfterSHA256,
		&row.databaseNow,
		&row.leaseExpiresAt,
		&row.initialAllowed,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return externalCMDBAttemptSnapshot{}, ErrExternalCMDBRuntimeAuthority
		}
		return externalCMDBAttemptSnapshot{}, boundedRuntimeAuthorityError(err)
	}
	snapshot, err := row.snapshot(key, queryStarted)
	if err != nil {
		return externalCMDBAttemptSnapshot{}, err
	}
	return snapshot, nil
}

func (row postgresExternalCMDBRow) snapshot(
	key externalCMDBAttemptKey,
	queryStarted time.Time,
) (externalCMDBAttemptSnapshot, error) {
	defer clear(row.checkpointEnvelope)
	descriptor := sourceprofile.ExternalCMDBV1()
	reconciliation, err := externalcmdb.NewReconciliationDescriptor(descriptor)
	if err != nil {
		return externalCMDBAttemptSnapshot{}, ErrExternalCMDBRuntimeAuthority
	}
	references := sourceprofile.ExternalCMDBProfileReferences{
		IntegrationID: row.integrationID,
		CredentialReferenceID: assetcatalog.CredentialReferenceID(
			row.credentialReferenceID,
		),
		TrustReferenceID: assetcatalog.TrustReferenceID(
			row.trustReferenceID,
		),
		NetworkPolicyReferenceID: assetcatalog.NetworkPolicyReferenceID(
			row.networkPolicyReferenceID,
		),
	}
	registration, err := descriptor.Registration(references)
	if err != nil {
		return externalCMDBAttemptSnapshot{}, ErrExternalCMDBRuntimeAuthority
	}
	profile := registration.Profile
	if !row.matchesProfile(profile) ||
		!canonicalUUID(row.sourceID) ||
		row.sourceRevision <= 0 ||
		row.revisionDigest != row.canonicalRevisionSHA256 ||
		len(row.authorityEnvironmentIDs) != 1 ||
		!canonicalUUID(row.authorityEnvironmentIDs[0]) {
		return externalCMDBAttemptSnapshot{}, ErrExternalCMDBRuntimeAuthority
	}

	revision := assetcatalog.SourceRevision{
		TenantID:                      key.coordinates.Scope.TenantID,
		WorkspaceID:                   key.coordinates.Scope.WorkspaceID,
		SourceID:                      row.sourceID,
		Revision:                      row.sourceRevision,
		CanonicalProfileManifest:      bytes.Clone(row.canonicalProfileManifest),
		ProfileManifestSHA256:         row.profileManifestSHA256,
		CanonicalProviderSchema:       bytes.Clone(row.canonicalProviderSchema),
		CanonicalProviderSchemaSHA256: row.providerSchemaSHA256,
		SourceDefinitionDigest:        row.sourceDefinitionSHA256,
		CanonicalRevisionDigest:       row.canonicalRevisionSHA256,
		IntegrationID:                 row.integrationID,
		SyncMode:                      row.syncMode,
		CredentialReferenceID:         references.CredentialReferenceID,
		TrustReferenceID:              references.TrustReferenceID,
		NetworkPolicyReferenceID:      references.NetworkPolicyReferenceID,
		AuthorityEnvironmentIDs: append(
			[]string(nil),
			row.authorityEnvironmentIDs...,
		),
		AuthorityScopeDigest:    row.authorityScopeSHA256,
		RateLimitRequests:       row.rateLimitRequests,
		RateLimitWindowSeconds:  row.rateLimitWindowSeconds,
		BackpressureBaseSeconds: row.backpressureBaseSeconds,
		BackpressureMaxSeconds:  row.backpressureMaxSeconds,
		ProfileCode:             row.profileCode,
	}
	definitionSHA256, err := assetcatalog.SourceDefinitionDigest(
		assetcatalog.Source{
			Kind:         assetcatalog.SourceKindExternalCMDB,
			ProviderKind: descriptor.ProviderKind(),
		},
		revision,
	)
	if err != nil ||
		definitionSHA256 != row.sourceDefinitionSHA256 ||
		revision.BindingDigest() != row.canonicalRevisionSHA256 {
		return externalCMDBAttemptSnapshot{}, ErrExternalCMDBRuntimeAuthority
	}
	authoritySHA256, err := assetcatalog.AuthorityScopeDigest(
		row.authorityEnvironmentIDs,
	)
	if err != nil || authoritySHA256 != row.authorityScopeSHA256 {
		return externalCMDBAttemptSnapshot{}, ErrExternalCMDBRuntimeAuthority
	}

	var revisionStatus assetcatalog.SourceRevisionStatus
	switch row.runKind {
	case assetcatalog.RunKindValidation:
		revisionStatus = assetcatalog.SourceRevisionValidating
	case assetcatalog.RunKindDiscovery:
		revisionStatus = assetcatalog.SourceRevisionPublished
	default:
		return externalCMDBAttemptSnapshot{}, ErrExternalCMDBRuntimeAuthority
	}
	binding := discoverysource.RuntimeBinding{
		Locator: assetcatalog.SourceLocator{
			Scope:    key.coordinates.Scope,
			SourceID: row.sourceID,
		},
		SourceRevision:       row.sourceRevision,
		SourceRevisionDigest: row.revisionDigest,
		RevisionStatus:       revisionStatus,
		ProviderKind:         descriptor.ProviderKind(),
		ProfileCode:          descriptor.ProfileCode(),
	}
	snapshot := externalCMDBAttemptSnapshot{
		key:     key,
		binding: binding,
		runKind: row.runKind,
		references: externalCMDBReferences{
			integrationID:            row.integrationID,
			credentialReferenceID:    row.credentialReferenceID,
			trustReferenceID:         row.trustReferenceID,
			networkPolicyReferenceID: row.networkPolicyReferenceID,
		},
		environmentID:          row.authorityEnvironmentIDs[0],
		sourceDefinitionSHA256: row.sourceDefinitionSHA256,
		descriptorSHA256:       reconciliation.DescriptorDigestSHA256(),
		limits:                 reconciliation.Limits(),
		checkpointVersion:      row.runCheckpointVersion,
		initialAllowed:         row.initialAllowed,
		materialDeadline: queryStarted.Add(
			row.leaseExpiresAt.Sub(row.databaseNow),
		),
	}
	if err := row.bindRunState(&snapshot); err != nil ||
		!snapshot.valid(reconciliation) {
		clear(snapshot.sealedCheckpoint.Envelope)
		return externalCMDBAttemptSnapshot{}, ErrExternalCMDBRuntimeAuthority
	}
	return snapshot, nil
}

func (row postgresExternalCMDBRow) matchesProfile(
	profile assetcatalog.BuiltinSourceProfile,
) bool {
	return profile.SourceKind == assetcatalog.SourceKindExternalCMDB &&
		profile.ProviderKind == sourceprofile.ExternalCMDBV1().ProviderKind() &&
		profile.ProfileCode == row.profileCode &&
		profile.SyncMode == row.syncMode &&
		bytes.Equal(
			profile.CanonicalProfileManifest,
			row.canonicalProfileManifest,
		) &&
		profile.ProfileManifestSHA256 == row.profileManifestSHA256 &&
		bytes.Equal(
			profile.CanonicalProviderSchema,
			row.canonicalProviderSchema,
		) &&
		profile.CanonicalProviderSchemaSHA256 == row.providerSchemaSHA256 &&
		profile.IntegrationID == row.integrationID &&
		string(profile.CredentialReferenceID) == row.credentialReferenceID &&
		string(profile.TrustReferenceID) == row.trustReferenceID &&
		string(profile.NetworkPolicyReferenceID) ==
			row.networkPolicyReferenceID &&
		profile.RateLimitRequests == row.rateLimitRequests &&
		profile.RateLimitWindowSeconds == row.rateLimitWindowSeconds &&
		profile.BackpressureBaseSeconds == row.backpressureBaseSeconds &&
		profile.BackpressureMaxSeconds == row.backpressureMaxSeconds &&
		profile.ScheduleExpression == stringValue(row.scheduleExpression) &&
		string(profile.TypedExtensionCode) == stringValue(row.typedExtensionCode) &&
		profile.PreparedExtensionDigest ==
			stringValue(row.preparedExtensionSHA256)
}

func (row postgresExternalCMDBRow) bindRunState(
	snapshot *externalCMDBAttemptSnapshot,
) error {
	if snapshot == nil {
		return ErrExternalCMDBRuntimeAuthority
	}
	switch row.runKind {
	case assetcatalog.RunKindValidation:
		if row.runCheckpointVersion != 0 ||
			row.cursorBeforeSHA256 != nil ||
			row.cursorAfterSHA256 != nil {
			return ErrExternalCMDBRuntimeAuthority
		}
		if !snapshot.initialAllowed {
			return nil
		}
		if row.revisionStatus != assetcatalog.SourceRevisionValidating ||
			stringValue(row.validationRunID) != snapshot.key.coordinates.RunID ||
			row.validationSHA256 != nil {
			return ErrExternalCMDBRuntimeAuthority
		}
	case assetcatalog.RunKindDiscovery:
		if row.runCheckpointVersion < 0 {
			return ErrExternalCMDBRuntimeAuthority
		}
		if !snapshot.initialAllowed {
			return nil
		}
		if row.revisionStatus != assetcatalog.SourceRevisionPublished ||
			!canonicalUUID(stringValue(row.validationRunID)) ||
			!validDigest(stringValue(row.validationSHA256)) ||
			row.checkpointVersion != row.runCheckpointVersion ||
			row.checkpointRevision != row.sourceRevision {
			return ErrExternalCMDBRuntimeAuthority
		}
		if row.runCheckpointVersion == 0 {
			if row.checkpointEnvelope != nil ||
				row.checkpointKeyID != nil ||
				row.checkpointSHA256 != nil ||
				row.cursorBeforeSHA256 != nil ||
				row.cursorAfterSHA256 != nil {
				return ErrExternalCMDBRuntimeAuthority
			}
			return nil
		}
		cursorSHA256 := stringValue(row.cursorAfterSHA256)
		if cursorSHA256 == "" {
			cursorSHA256 = stringValue(row.cursorBeforeSHA256)
		}
		if !validDigest(cursorSHA256) ||
			cursorSHA256 != stringValue(row.checkpointSHA256) ||
			stringValue(row.checkpointKeyID) == "" ||
			len(row.checkpointEnvelope) == 0 {
			return ErrExternalCMDBRuntimeAuthority
		}
		snapshot.checkpointSHA256 = cursorSHA256
		snapshot.sealedCheckpoint = discoverycheckpoint.SealedCheckpoint{
			Envelope:          bytes.Clone(row.checkpointEnvelope),
			CheckpointKeyID:   stringValue(row.checkpointKeyID),
			CheckpointSHA256:  cursorSHA256,
			CheckpointVersion: row.runCheckpointVersion,
		}
	default:
		return ErrExternalCMDBRuntimeAuthority
	}
	return nil
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
