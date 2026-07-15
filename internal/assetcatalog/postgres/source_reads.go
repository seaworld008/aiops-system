package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

const resolveSourceScopeSQL = `
SELECT workspace.tenant_id::text, workspace.id::text
FROM workspaces AS workspace
WHERE workspace.id = $1::uuid
`

const sourceReadJoinsSQL = `
FROM asset_sources AS source
LEFT JOIN LATERAL (
    SELECT revision.*
    FROM asset_source_revisions AS revision
    WHERE revision.tenant_id = source.tenant_id
      AND revision.workspace_id = source.workspace_id
      AND revision.source_id = source.id
    ORDER BY revision.revision DESC
    LIMIT 1
) AS latest_revision ON true
LEFT JOIN LATERAL (
    SELECT array_agg(authority.environment_id::text ORDER BY authority.canonical_ordinal) AS environment_ids,
           array_agg(authority.canonical_ordinal ORDER BY authority.canonical_ordinal) AS ordinals
    FROM asset_source_revision_authorities AS authority
    WHERE authority.tenant_id = latest_revision.tenant_id
      AND authority.workspace_id = latest_revision.workspace_id
      AND authority.source_id = latest_revision.source_id
      AND authority.source_revision = latest_revision.revision
) AS latest_authority ON latest_revision.id IS NOT NULL
LEFT JOIN asset_source_revisions AS published_revision
  ON source.published_revision IS NOT NULL
 AND published_revision.tenant_id = source.tenant_id
 AND published_revision.workspace_id = source.workspace_id
 AND published_revision.source_id = source.id
 AND published_revision.revision = source.published_revision
 AND published_revision.canonical_revision_digest = source.published_revision_digest
 AND published_revision.state = 'PUBLISHED'
LEFT JOIN LATERAL (
    SELECT array_agg(authority.environment_id::text ORDER BY authority.canonical_ordinal) AS environment_ids,
           array_agg(authority.canonical_ordinal ORDER BY authority.canonical_ordinal) AS ordinals
    FROM asset_source_revision_authorities AS authority
    WHERE authority.tenant_id = published_revision.tenant_id
      AND authority.workspace_id = published_revision.workspace_id
      AND authority.source_id = published_revision.source_id
      AND authority.source_revision = published_revision.revision
) AS published_authority ON published_revision.id IS NOT NULL
LEFT JOIN asset_source_runs AS current_run
  ON current_run.tenant_id = source.tenant_id
 AND current_run.workspace_id = source.workspace_id
 AND current_run.source_id = source.id
 AND current_run.status IN ('QUEUED', 'DELAYED', 'RUNNING', 'FINALIZING')
LEFT JOIN asset_source_revisions AS current_run_revision
  ON current_run_revision.tenant_id = current_run.tenant_id
 AND current_run_revision.workspace_id = current_run.workspace_id
 AND current_run_revision.source_id = current_run.source_id
 AND current_run_revision.revision = current_run.source_revision
 AND current_run_revision.canonical_revision_digest = current_run.source_revision_digest
LEFT JOIN asset_source_runs AS last_success_run
  ON source.last_success_run_id IS NOT NULL
 AND last_success_run.tenant_id = source.tenant_id
 AND last_success_run.workspace_id = source.workspace_id
 AND last_success_run.source_id = source.id
 AND last_success_run.id = source.last_success_run_id
 AND last_success_run.run_kind <> 'VALIDATION'
 AND last_success_run.status = 'SUCCEEDED'
 AND last_success_run.source_revision = source.published_revision
 AND last_success_run.source_revision_digest = source.published_revision_digest
 AND last_success_run.completed_at = source.last_success_at
`

const getSourceAccessSQL = `
  AND cardinality($4::uuid[]) > 0
  AND (latest_revision.id IS NULL OR NOT EXISTS (
      SELECT 1
      FROM asset_source_revision_authorities AS denied_latest
      WHERE denied_latest.tenant_id = latest_revision.tenant_id
        AND denied_latest.workspace_id = latest_revision.workspace_id
        AND denied_latest.source_id = latest_revision.source_id
        AND denied_latest.source_revision = latest_revision.revision
        AND NOT (denied_latest.environment_id = ANY($4::uuid[]))
  ))
  AND (published_revision.id IS NULL OR NOT EXISTS (
      SELECT 1
      FROM asset_source_revision_authorities AS denied_published
      WHERE denied_published.tenant_id = published_revision.tenant_id
        AND denied_published.workspace_id = published_revision.workspace_id
        AND denied_published.source_id = published_revision.source_id
        AND denied_published.source_revision = published_revision.revision
        AND NOT (denied_published.environment_id = ANY($4::uuid[]))
  ))
  AND (current_run.id IS NULL OR current_run_revision.id IS NULL OR NOT EXISTS (
      SELECT 1
      FROM asset_source_revision_authorities AS denied_current
      WHERE denied_current.tenant_id = current_run_revision.tenant_id
        AND denied_current.workspace_id = current_run_revision.workspace_id
        AND denied_current.source_id = current_run_revision.source_id
        AND denied_current.source_revision = current_run_revision.revision
        AND NOT (denied_current.environment_id = ANY($4::uuid[]))
  ))
`

const listSourceAccessSQL = `
  AND cardinality($3::uuid[]) > 0
  AND (latest_revision.id IS NULL OR NOT EXISTS (
      SELECT 1
      FROM asset_source_revision_authorities AS denied_latest
      WHERE denied_latest.tenant_id = latest_revision.tenant_id
        AND denied_latest.workspace_id = latest_revision.workspace_id
        AND denied_latest.source_id = latest_revision.source_id
        AND denied_latest.source_revision = latest_revision.revision
        AND NOT (denied_latest.environment_id = ANY($3::uuid[]))
  ))
  AND (published_revision.id IS NULL OR NOT EXISTS (
      SELECT 1
      FROM asset_source_revision_authorities AS denied_published
      WHERE denied_published.tenant_id = published_revision.tenant_id
        AND denied_published.workspace_id = published_revision.workspace_id
        AND denied_published.source_id = published_revision.source_id
        AND denied_published.source_revision = published_revision.revision
        AND NOT (denied_published.environment_id = ANY($3::uuid[]))
  ))
  AND (current_run.id IS NULL OR current_run_revision.id IS NULL OR NOT EXISTS (
      SELECT 1
      FROM asset_source_revision_authorities AS denied_current
      WHERE denied_current.tenant_id = current_run_revision.tenant_id
        AND denied_current.workspace_id = current_run_revision.workspace_id
        AND denied_current.source_id = current_run_revision.source_id
        AND denied_current.source_revision = current_run_revision.revision
        AND NOT (denied_current.environment_id = ANY($3::uuid[]))
  ))
`

const listSourceFiltersSQL = `
  AND ($4::text[] IS NULL OR source.source_kind = ANY($4::text[]))
  AND ($5::text[] IS NULL OR source.status = ANY($5::text[]))
  AND ($6::text[] IS NULL OR source.gate_status = ANY($6::text[]))
  AND (
      ($7::text = '' AND ($8::uuid IS NULL OR EXISTS (
          SELECT 1
          FROM asset_source_revision_authorities AS environment_filter
          WHERE environment_filter.tenant_id = latest_revision.tenant_id
            AND environment_filter.workspace_id = latest_revision.workspace_id
            AND environment_filter.source_id = latest_revision.source_id
            AND environment_filter.source_revision = latest_revision.revision
            AND environment_filter.environment_id = $8::uuid
      )))
      OR
      ($7::text = 'manual_asset_create'
       AND source.source_kind = 'MANUAL'
       AND source.provider_kind = 'MANUAL_V1'
       AND source.status = 'ACTIVE'
       AND source.gate_status = 'AVAILABLE'
       AND source.gate_reason_code IS NULL
       AND source.gate_revision > 0
       AND source.published_revision IS NOT NULL
       AND published_revision.id IS NOT NULL
       AND source.validated_run_id = published_revision.validation_run_id
       AND source.validation_digest = published_revision.validation_digest
       AND source.validated_binding_digest = published_revision.canonical_revision_digest
       AND source.checkpoint_revision = source.published_revision
       AND source.checkpoint_ciphertext IS NULL
       AND source.checkpoint_key_id IS NULL
       AND source.checkpoint_sha256 IS NULL
       AND published_revision.state = 'PUBLISHED'
       AND published_revision.canonical_profile_manifest = $11::bytea
       AND published_revision.profile_manifest_sha256 = $12::text
       AND published_revision.canonical_provider_schema = $13::bytea
       AND published_revision.canonical_provider_schema_sha256 = $14::text
       AND published_revision.integration_id IS NULL
       AND published_revision.sync_mode = 'MANUAL'
       AND published_revision.credential_reference_id IS NULL
       AND published_revision.trust_reference_id IS NULL
       AND published_revision.network_policy_reference_id IS NULL
       AND published_revision.rate_limit_requests = 1
       AND published_revision.rate_limit_window_seconds = 1
       AND published_revision.backpressure_base_seconds = 1
       AND published_revision.backpressure_max_seconds = 1
       AND published_revision.profile_code = 'MANUAL_V1'
       AND published_revision.schedule_expression IS NULL
       AND published_revision.typed_extension_code IS NULL
       AND published_revision.prepared_extension_digest IS NULL
       AND published_revision.source_definition_digest = $15::text
       AND published_revision.canonical_revision_digest = asset_catalog_source_revision_binding_digest(
           ROW(published_revision.*)::asset_source_revisions
       )
       AND cardinality(published_authority.environment_ids) = 1
       AND published_authority.environment_ids[1] = $8::text
       AND published_authority.ordinals[1] = 1)
  )
  AND ($9::uuid IS NULL OR source.id > $9::uuid)
ORDER BY source.id ASC
LIMIT $10::integer
`

const getSourceRunJoinsSQL = `
FROM asset_source_runs AS source_run
JOIN asset_sources AS source
  ON source.tenant_id = source_run.tenant_id
 AND source.workspace_id = source_run.workspace_id
 AND source.id = source_run.source_id
LEFT JOIN asset_source_revisions AS run_revision
  ON run_revision.tenant_id = source_run.tenant_id
 AND run_revision.workspace_id = source_run.workspace_id
 AND run_revision.source_id = source_run.source_id
 AND run_revision.revision = source_run.source_revision
 AND run_revision.canonical_revision_digest = source_run.source_revision_digest
LEFT JOIN LATERAL (
    SELECT array_agg(authority.environment_id::text ORDER BY authority.canonical_ordinal) AS environment_ids,
           array_agg(authority.canonical_ordinal ORDER BY authority.canonical_ordinal) AS ordinals
    FROM asset_source_revision_authorities AS authority
    WHERE authority.tenant_id = run_revision.tenant_id
      AND authority.workspace_id = run_revision.workspace_id
      AND authority.source_id = run_revision.source_id
      AND authority.source_revision = run_revision.revision
) AS run_authority ON run_revision.id IS NOT NULL
`

const getSourceRunAccessSQL = `
  AND cardinality($4::uuid[]) > 0
  AND (run_revision.id IS NULL OR NOT EXISTS (
      SELECT 1
      FROM asset_source_revision_authorities AS denied_run
      WHERE denied_run.tenant_id = run_revision.tenant_id
        AND denied_run.workspace_id = run_revision.workspace_id
        AND denied_run.source_id = run_revision.source_id
        AND denied_run.source_revision = run_revision.revision
        AND NOT (denied_run.environment_id = ANY($4::uuid[]))
  ))
`

var (
	getSourceSQL = `SELECT ` + sourceReadModelProjectionSQL() + sourceReadJoinsSQL + `
WHERE source.tenant_id = $1::uuid
  AND source.workspace_id = $2::uuid
  AND source.id = $3::uuid
` + getSourceAccessSQL
	listSourcesSQL = `SELECT ` + sourceReadModelProjectionSQL() + sourceReadJoinsSQL + `
WHERE source.tenant_id = $1::uuid
  AND source.workspace_id = $2::uuid
` + listSourceAccessSQL + listSourceFiltersSQL
	getSourceRunSQL = `SELECT ` + sourceRunReadProjectionSQL() + getSourceRunJoinsSQL + `
WHERE source_run.tenant_id = $1::uuid
  AND source_run.workspace_id = $2::uuid
  AND source_run.id = $3::uuid
` + getSourceRunAccessSQL
)

func (repository *Repository) ResolveSourceScope(
	ctx context.Context,
	workspaceID string,
) (assetcatalog.SourceScope, error) {
	if !validUUID(workspaceID) {
		return assetcatalog.SourceScope{}, assetcatalog.ErrInvalidRequest
	}
	var scope assetcatalog.SourceScope
	if err := repository.pool.QueryRow(ctx, resolveSourceScopeSQL, workspaceID).Scan(
		&scope.TenantID,
		&scope.WorkspaceID,
	); err != nil {
		return assetcatalog.SourceScope{}, mapPGError(err)
	}
	if !scope.Valid() {
		return assetcatalog.SourceScope{}, assetcatalog.ErrStateConflict
	}
	return scope, nil
}

func (repository *Repository) GetSource(
	ctx context.Context,
	locator assetcatalog.SourceLocator,
	access assetcatalog.SourceReadConstraint,
) (assetcatalog.SourceReadModel, error) {
	if !locator.Scope.Valid() || !validUUID(locator.SourceID) || access.Validate() != nil {
		return assetcatalog.SourceReadModel{}, assetcatalog.ErrInvalidRequest
	}
	environmentIDs := access.EnvironmentIDs()
	if len(environmentIDs) == 0 {
		return assetcatalog.SourceReadModel{}, assetcatalog.ErrNotFound
	}
	var projection []byte
	if err := repository.pool.QueryRow(
		ctx,
		getSourceSQL,
		locator.Scope.TenantID,
		locator.Scope.WorkspaceID,
		locator.SourceID,
		environmentIDs,
	).Scan(&projection); err != nil {
		return assetcatalog.SourceReadModel{}, mapPGError(err)
	}
	model, err := decodeSourceReadModel(projection)
	if err != nil {
		return assetcatalog.SourceReadModel{}, err
	}
	return model.Clone(), nil
}

func (repository *Repository) ListSources(
	ctx context.Context,
	request assetcatalog.ListSourcesRequest,
) (assetcatalog.SourcePage, error) {
	request = request.Clone()
	digest, err := request.QueryDigest()
	if err != nil {
		return assetcatalog.SourcePage{}, assetcatalog.ErrInvalidRequest
	}
	environmentIDs := request.Access.EnvironmentIDs()
	if len(environmentIDs) == 0 {
		return assetcatalog.SourcePage{Items: []assetcatalog.SourceReadModel{}}, nil
	}
	cursorID := ""
	if request.Cursor != nil {
		cursorID = request.Cursor.SourceID
	}
	profile := assetcatalog.ManualProfileV1()
	expectedDefinition, err := manualSourceDefinitionDigest(profile)
	if err != nil {
		return assetcatalog.SourcePage{}, assetcatalog.ErrStateConflict
	}
	rows, err := repository.pool.Query(
		ctx,
		listSourcesSQL,
		request.Scope.TenantID,
		request.Scope.WorkspaceID,
		environmentIDs,
		stringsOrNil(request.Kinds),
		stringsOrNil(request.Statuses),
		stringsOrNil(request.GateStatuses),
		string(request.Usage),
		uuidOrNil(request.EnvironmentID),
		uuidOrNil(cursorID),
		request.Limit+1,
		profile.CanonicalProfileManifest,
		profile.ProfileManifestSHA256,
		profile.CanonicalProviderSchema,
		profile.CanonicalProviderSchemaSHA256,
		expectedDefinition,
	)
	if err != nil {
		return assetcatalog.SourcePage{}, mapPGError(err)
	}
	defer rows.Close()
	items := make([]assetcatalog.SourceReadModel, 0, request.Limit+1)
	for rows.Next() {
		var projection []byte
		if err := rows.Scan(&projection); err != nil {
			return assetcatalog.SourcePage{}, mapPGError(err)
		}
		model, err := decodeSourceReadModel(projection)
		if err != nil {
			return assetcatalog.SourcePage{}, err
		}
		items = append(items, model)
	}
	if err := rows.Err(); err != nil {
		return assetcatalog.SourcePage{}, mapPGError(err)
	}
	page := assetcatalog.SourcePage{Items: items}
	if len(items) > request.Limit {
		page.Items = items[:request.Limit]
		page.Next = &assetcatalog.SourceCursor{
			QueryDigest: digest,
			SourceID:    page.Items[len(page.Items)-1].Source.ID,
		}
	}
	return page.Clone(), nil
}

func (repository *Repository) GetSourceRun(
	ctx context.Context,
	locator assetcatalog.SourceRunLocator,
	access assetcatalog.SourceReadConstraint,
) (assetcatalog.SourceRun, error) {
	if !locator.Scope.Valid() || !validUUID(locator.RunID) || access.Validate() != nil {
		return assetcatalog.SourceRun{}, assetcatalog.ErrInvalidRequest
	}
	environmentIDs := access.EnvironmentIDs()
	if len(environmentIDs) == 0 {
		return assetcatalog.SourceRun{}, assetcatalog.ErrNotFound
	}
	var projection []byte
	if err := repository.pool.QueryRow(
		ctx,
		getSourceRunSQL,
		locator.Scope.TenantID,
		locator.Scope.WorkspaceID,
		locator.RunID,
		environmentIDs,
	).Scan(&projection); err != nil {
		return assetcatalog.SourceRun{}, mapPGError(err)
	}
	run, err := decodeSourceRunReadProjection(projection)
	if err != nil {
		return assetcatalog.SourceRun{}, err
	}
	return run.Clone(), nil
}

var _ assetcatalog.SourceReadRepository = (*Repository)(nil)

func sourceReadModelProjectionSQL() string {
	return `jsonb_build_object(
    'source', ` + sourceProjectionSQL("source") + `,
    'latest_revision', CASE WHEN latest_revision.id IS NULL THEN NULL ELSE ` +
		sourceRevisionProjectionSQL("latest_revision", "latest_authority") + ` END,
    'published_revision', CASE WHEN published_revision.id IS NULL THEN NULL ELSE ` +
		sourceRevisionProjectionSQL("published_revision", "published_authority") + ` END,
    'current_run', CASE WHEN current_run.id IS NULL THEN NULL ELSE ` + sourceRunProjectionSQL("current_run") + ` END,
    'current_revision_matches', current_run.id IS NULL OR current_run_revision.id IS NOT NULL,
    'last_successful_run', CASE WHEN last_success_run.id IS NULL THEN NULL ELSE ` + sourceRunProjectionSQL("last_success_run") + ` END
)`
}

func sourceRunReadProjectionSQL() string {
	return `jsonb_build_object(
    'source_kind', source.source_kind,
    'provider_kind', source.provider_kind,
    'run', ` + sourceRunProjectionSQL("source_run") + `,
    'revision', CASE WHEN run_revision.id IS NULL THEN NULL ELSE ` +
		sourceRevisionProjectionSQL("run_revision", "run_authority") + ` END
)`
}

func sourceProjectionSQL(alias string) string {
	return fmt.Sprintf(`jsonb_build_object(
    'id', %[1]s.id::text,
    'tenant_id', %[1]s.tenant_id::text,
    'workspace_id', %[1]s.workspace_id::text,
    'provider_kind', %[1]s.provider_kind,
    'name', %[1]s.name,
    'kind', %[1]s.source_kind,
    'status', %[1]s.status,
    'published_revision', %[1]s.published_revision,
    'published_revision_digest', %[1]s.published_revision_digest,
    'gate_status', %[1]s.gate_status,
    'gate_reason_code', %[1]s.gate_reason_code,
    'gate_revision', %[1]s.gate_revision,
    'validated_run_id', %[1]s.validated_run_id::text,
    'validation_digest', %[1]s.validation_digest,
    'validated_binding_digest', %[1]s.validated_binding_digest,
    'checkpoint_sha256', %[1]s.checkpoint_sha256,
    'checkpoint_version', %[1]s.checkpoint_version,
    'checkpoint_source_revision', %[1]s.checkpoint_revision,
    'next_allowed_at', %[1]s.next_allowed_at,
    'consecutive_failures', %[1]s.consecutive_failures,
    'last_success_run_id', %[1]s.last_success_run_id::text,
    'last_success_at', %[1]s.last_success_at,
    'last_complete_snapshot_run_id', %[1]s.last_complete_snapshot_run_id::text,
    'last_complete_snapshot_at', %[1]s.last_complete_snapshot_at,
    'version', %[1]s.version,
    'created_at', %[1]s.created_at,
    'updated_at', %[1]s.updated_at
)`, alias)
}

func sourceRevisionProjectionSQL(alias, authorityAlias string) string {
	manifest := "convert_from(" + alias + ".canonical_profile_manifest, 'UTF8')::jsonb"
	return fmt.Sprintf(`jsonb_build_object(
    'id', %[1]s.id::text,
    'source_id', %[1]s.source_id::text,
    'tenant_id', %[1]s.tenant_id::text,
    'workspace_id', %[1]s.workspace_id::text,
    'revision', %[1]s.revision,
    'status', %[1]s.state,
    'profile_manifest_sha256', %[1]s.profile_manifest_sha256,
    'canonical_provider_schema_sha256', %[1]s.canonical_provider_schema_sha256,
    'source_definition_digest', %[1]s.source_definition_digest,
    'canonical_revision_digest', %[1]s.canonical_revision_digest,
    'sync_mode', %[1]s.sync_mode,
    'authority_environment_ids', COALESCE(%[2]s.environment_ids, ARRAY[]::text[]),
    'authority_ordinals', COALESCE(%[2]s.ordinals, ARRAY[]::integer[]),
    'authority_scope_digest', %[1]s.authority_scope_digest,
    'rate_limit_requests', %[1]s.rate_limit_requests,
    'rate_limit_window_seconds', %[1]s.rate_limit_window_seconds,
    'backpressure_base_seconds', %[1]s.backpressure_base_seconds,
    'backpressure_max_seconds', %[1]s.backpressure_max_seconds,
    'profile_code', %[1]s.profile_code,
    'schedule_expression', %[1]s.schedule_expression,
    'typed_extension_code', %[1]s.typed_extension_code,
    'prepared_extension_digest', %[1]s.prepared_extension_digest,
    'validation_run_id', %[1]s.validation_run_id::text,
    'validation_digest', %[1]s.validation_digest,
    'created_by', %[1]s.created_by,
    'change_reason_code', %[1]s.change_reason_code,
    'expected_source_version', %[1]s.expected_source_version,
    'version', %[1]s.version,
    'created_at', %[1]s.created_at,
    'updated_at', %[1]s.updated_at,
    'manifest_source_kind', (%[3]s)->>'source_kind',
    'manifest_provider_kind', (%[3]s)->>'provider_kind',
    'manifest_profile_code', (%[3]s)->>'profile_code',
    'manifest_sync_mode', (%[3]s)->>'sync_mode',
    'environment_mapping_mode', (%[3]s)->>'environment_mapping_mode',
    'binding_valid', asset_catalog_source_revision_binding_digest(
        ROW(%[1]s.*)::asset_source_revisions
    ) = %[1]s.canonical_revision_digest
)`, alias, authorityAlias, manifest)
}

func sourceRunProjectionSQL(alias string) string {
	return fmt.Sprintf(`(
jsonb_build_object(
    'id', %[1]s.id::text,
    'source_id', %[1]s.source_id::text,
    'tenant_id', %[1]s.tenant_id::text,
    'workspace_id', %[1]s.workspace_id::text,
    'source_revision', %[1]s.source_revision,
    'source_revision_digest', %[1]s.source_revision_digest,
    'kind', %[1]s.run_kind,
    'status', %[1]s.status,
    'stage', %[1]s.stage_code,
    'stage_changed_at', %[1]s.stage_changed_at,
    'trigger_type', %[1]s.trigger_type,
    'gate_revision', %[1]s.gate_revision,
    'page_sequence', %[1]s.page_sequence,
    'page_digest', %[1]s.page_digest,
    'relation_page_sequence', %[1]s.relation_page_sequence,
    'relation_page_digest', %[1]s.relation_page_digest,
    'cursor_before_sha256', %[1]s.cursor_before_sha256,
    'cursor_after_sha256', %[1]s.cursor_after_sha256,
    'checkpoint_version', %[1]s.checkpoint_version,
    'not_before', %[1]s.not_before,
    'heartbeat_sequence', %[1]s.heartbeat_sequence,
    'final_page', %[1]s.final_page,
    'complete_snapshot', %[1]s.complete_snapshot,
    'effective_complete_snapshot', %[1]s.effective_complete_snapshot,
    'work_result_kind', %[1]s.work_result_kind,
    'work_result_status', %[1]s.work_result_status,
    'work_result_digest', %[1]s.work_result_digest,
    'work_result_recorded_at', %[1]s.work_result_recorded_at
)
|| jsonb_build_object(
    'validation_outcome', %[1]s.validation_outcome,
    'validation_proof_digest', %[1]s.validation_proof_digest,
    'credential_cleanup_status', %[1]s.cleanup_status,
    'observed', %[1]s.observed_count,
    'created', %[1]s.created_count,
    'changed', %[1]s.changed_count,
    'unchanged', %[1]s.unchanged_count,
    'conflicts', %[1]s.conflict_count,
    'missing', %[1]s.missing_count,
    'stale', %[1]s.stale_count,
    'restored', %[1]s.restored_count,
    'tombstoned', %[1]s.tombstoned_count,
    'rejected', %[1]s.rejected_count,
    'failure_code', %[1]s.failure_code,
    'trace_id', %[1]s.trace_id,
    'version', %[1]s.version,
    'created_at', %[1]s.created_at,
    'started_at', %[1]s.started_at,
    'heartbeat_at', %[1]s.heartbeat_at,
    'completed_at', %[1]s.completed_at
))`, alias)
}

var (
	projectionDigestPattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	projectionProviderKindPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

type databaseJSONTime struct{ time.Time }

func (value *databaseJSONTime) UnmarshalJSON(data []byte) error {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return err
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05.999999999Z07",
		"2006-01-02 15:04:05Z07:00",
		"2006-01-02 15:04:05Z07",
	} {
		parsed, err := time.Parse(layout, encoded)
		if err == nil {
			value.Time = canonicalDatabaseTime(parsed)
			return nil
		}
	}
	return fmt.Errorf("invalid database timestamp")
}

type sourceProjectionWire struct {
	ID                        string                        `json:"id"`
	TenantID                  string                        `json:"tenant_id"`
	WorkspaceID               string                        `json:"workspace_id"`
	ProviderKind              string                        `json:"provider_kind"`
	Name                      string                        `json:"name"`
	Kind                      assetcatalog.SourceKind       `json:"kind"`
	Status                    assetcatalog.SourceStatus     `json:"status"`
	PublishedRevision         *int64                        `json:"published_revision"`
	PublishedRevisionDigest   *string                       `json:"published_revision_digest"`
	GateStatus                assetcatalog.SourceGateStatus `json:"gate_status"`
	GateReasonCode            *string                       `json:"gate_reason_code"`
	GateRevision              int64                         `json:"gate_revision"`
	ValidatedRunID            *string                       `json:"validated_run_id"`
	ValidationDigest          *string                       `json:"validation_digest"`
	ValidatedBindingDigest    *string                       `json:"validated_binding_digest"`
	CheckpointSHA256          *string                       `json:"checkpoint_sha256"`
	CheckpointVersion         int64                         `json:"checkpoint_version"`
	CheckpointSourceRevision  int64                         `json:"checkpoint_source_revision"`
	NextAllowedAt             *databaseJSONTime             `json:"next_allowed_at"`
	ConsecutiveFailures       int                           `json:"consecutive_failures"`
	LastSuccessRunID          *string                       `json:"last_success_run_id"`
	LastSuccessAt             *databaseJSONTime             `json:"last_success_at"`
	LastCompleteSnapshotRunID *string                       `json:"last_complete_snapshot_run_id"`
	LastCompleteSnapshotAt    *databaseJSONTime             `json:"last_complete_snapshot_at"`
	Version                   int64                         `json:"version"`
	CreatedAt                 databaseJSONTime              `json:"created_at"`
	UpdatedAt                 databaseJSONTime              `json:"updated_at"`
}

type sourceRevisionProjectionWire struct {
	ID                      string                              `json:"id"`
	SourceID                string                              `json:"source_id"`
	TenantID                string                              `json:"tenant_id"`
	WorkspaceID             string                              `json:"workspace_id"`
	Revision                int64                               `json:"revision"`
	Status                  assetcatalog.SourceRevisionStatus   `json:"status"`
	ProfileManifestSHA256   string                              `json:"profile_manifest_sha256"`
	ProviderSchemaSHA256    string                              `json:"canonical_provider_schema_sha256"`
	SourceDefinitionDigest  string                              `json:"source_definition_digest"`
	CanonicalRevisionDigest string                              `json:"canonical_revision_digest"`
	SyncMode                assetcatalog.SyncMode               `json:"sync_mode"`
	AuthorityEnvironmentIDs []string                            `json:"authority_environment_ids"`
	AuthorityOrdinals       []int                               `json:"authority_ordinals"`
	AuthorityScopeDigest    string                              `json:"authority_scope_digest"`
	RateLimitRequests       int64                               `json:"rate_limit_requests"`
	RateLimitWindowSeconds  int64                               `json:"rate_limit_window_seconds"`
	BackpressureBaseSeconds int64                               `json:"backpressure_base_seconds"`
	BackpressureMaxSeconds  int64                               `json:"backpressure_max_seconds"`
	ProfileCode             assetcatalog.ProfileCode            `json:"profile_code"`
	ScheduleExpression      *string                             `json:"schedule_expression"`
	TypedExtensionCode      *string                             `json:"typed_extension_code"`
	PreparedExtensionDigest *string                             `json:"prepared_extension_digest"`
	ValidationRunID         *string                             `json:"validation_run_id"`
	ValidationDigest        *string                             `json:"validation_digest"`
	CreatedBy               string                              `json:"created_by"`
	ChangeReasonCode        string                              `json:"change_reason_code"`
	ExpectedSourceVersion   int64                               `json:"expected_source_version"`
	Version                 int64                               `json:"version"`
	CreatedAt               databaseJSONTime                    `json:"created_at"`
	UpdatedAt               databaseJSONTime                    `json:"updated_at"`
	ManifestSourceKind      assetcatalog.SourceKind             `json:"manifest_source_kind"`
	ManifestProviderKind    string                              `json:"manifest_provider_kind"`
	ManifestProfileCode     assetcatalog.ProfileCode            `json:"manifest_profile_code"`
	ManifestSyncMode        assetcatalog.SyncMode               `json:"manifest_sync_mode"`
	EnvironmentMappingMode  assetcatalog.EnvironmentMappingMode `json:"environment_mapping_mode"`
	BindingValid            bool                                `json:"binding_valid"`
}

type sourceRunProjectionWire struct {
	ID                        string                               `json:"id"`
	SourceID                  string                               `json:"source_id"`
	TenantID                  string                               `json:"tenant_id"`
	WorkspaceID               string                               `json:"workspace_id"`
	SourceRevision            int64                                `json:"source_revision"`
	SourceRevisionDigest      string                               `json:"source_revision_digest"`
	Kind                      assetcatalog.RunKind                 `json:"kind"`
	Status                    assetcatalog.RunStatus               `json:"status"`
	Stage                     assetcatalog.RunStage                `json:"stage"`
	StageChangedAt            databaseJSONTime                     `json:"stage_changed_at"`
	TriggerType               assetcatalog.TriggerType             `json:"trigger_type"`
	GateRevision              int64                                `json:"gate_revision"`
	PageSequence              int64                                `json:"page_sequence"`
	PageDigest                *string                              `json:"page_digest"`
	RelationPageSequence      int64                                `json:"relation_page_sequence"`
	RelationPageDigest        *string                              `json:"relation_page_digest"`
	CursorBeforeSHA256        *string                              `json:"cursor_before_sha256"`
	CursorAfterSHA256         *string                              `json:"cursor_after_sha256"`
	CheckpointVersion         int64                                `json:"checkpoint_version"`
	NotBefore                 databaseJSONTime                     `json:"not_before"`
	HeartbeatSequence         int64                                `json:"heartbeat_sequence"`
	FinalPage                 bool                                 `json:"final_page"`
	CompleteSnapshot          bool                                 `json:"complete_snapshot"`
	EffectiveCompleteSnapshot bool                                 `json:"effective_complete_snapshot"`
	WorkResultKind            *string                              `json:"work_result_kind"`
	WorkResultStatus          *string                              `json:"work_result_status"`
	WorkResultDigest          *string                              `json:"work_result_digest"`
	WorkResultRecordedAt      *databaseJSONTime                    `json:"work_result_recorded_at"`
	ValidationOutcome         *string                              `json:"validation_outcome"`
	ValidationProofDigest     *string                              `json:"validation_proof_digest"`
	CredentialCleanupStatus   assetcatalog.CredentialCleanupStatus `json:"credential_cleanup_status"`
	Observed                  int64                                `json:"observed"`
	Created                   int64                                `json:"created"`
	Changed                   int64                                `json:"changed"`
	Unchanged                 int64                                `json:"unchanged"`
	Conflicts                 int64                                `json:"conflicts"`
	Missing                   int64                                `json:"missing"`
	Stale                     int64                                `json:"stale"`
	Restored                  int64                                `json:"restored"`
	Tombstoned                int64                                `json:"tombstoned"`
	Rejected                  int64                                `json:"rejected"`
	FailureCode               *string                              `json:"failure_code"`
	TraceID                   *string                              `json:"trace_id"`
	Version                   int64                                `json:"version"`
	CreatedAt                 databaseJSONTime                     `json:"created_at"`
	StartedAt                 *databaseJSONTime                    `json:"started_at"`
	HeartbeatAt               *databaseJSONTime                    `json:"heartbeat_at"`
	CompletedAt               *databaseJSONTime                    `json:"completed_at"`
}

type sourceReadModelProjectionWire struct {
	Source                 sourceProjectionWire          `json:"source"`
	LatestRevision         *sourceRevisionProjectionWire `json:"latest_revision"`
	PublishedRevision      *sourceRevisionProjectionWire `json:"published_revision"`
	CurrentRun             *sourceRunProjectionWire      `json:"current_run"`
	CurrentRevisionMatches bool                          `json:"current_revision_matches"`
	LastSuccessfulRun      *sourceRunProjectionWire      `json:"last_successful_run"`
}

type sourceRunReadProjectionWire struct {
	SourceKind   assetcatalog.SourceKind       `json:"source_kind"`
	ProviderKind string                        `json:"provider_kind"`
	Run          sourceRunProjectionWire       `json:"run"`
	Revision     *sourceRevisionProjectionWire `json:"revision"`
}

func decodeSourceReadModel(projection []byte) (assetcatalog.SourceReadModel, error) {
	var wire sourceReadModelProjectionWire
	if !decodeStrictProjection(projection, &wire) {
		return assetcatalog.SourceReadModel{}, assetcatalog.ErrStateConflict
	}
	source, ok := wire.Source.finish()
	if !ok || wire.LatestRevision == nil {
		return assetcatalog.SourceReadModel{}, assetcatalog.ErrStateConflict
	}
	latest, ok := wire.LatestRevision.finish(&source)
	if !ok || latest.SourceID != source.ID || latest.TenantID != source.TenantID || latest.WorkspaceID != source.WorkspaceID {
		return assetcatalog.SourceReadModel{}, assetcatalog.ErrStateConflict
	}
	model := assetcatalog.SourceReadModel{Source: source, LatestRevision: latest}
	if (source.PublishedRevision == 0) != (wire.PublishedRevision == nil) {
		return assetcatalog.SourceReadModel{}, assetcatalog.ErrStateConflict
	}
	if wire.PublishedRevision != nil {
		published, valid := wire.PublishedRevision.finish(&source)
		if !valid || published.Status != assetcatalog.SourceRevisionPublished ||
			published.Revision != source.PublishedRevision ||
			published.CanonicalRevisionDigest != source.PublishedRevisionDigest {
			return assetcatalog.SourceReadModel{}, assetcatalog.ErrStateConflict
		}
		model.PublishedRevision = &published
	}
	if wire.CurrentRun == nil {
		if !wire.CurrentRevisionMatches {
			return assetcatalog.SourceReadModel{}, assetcatalog.ErrStateConflict
		}
	} else {
		current, valid := wire.CurrentRun.finish()
		if !valid || !wire.CurrentRevisionMatches || current.SourceID != source.ID || current.Scope != (assetcatalog.SourceScope{
			TenantID: source.TenantID, WorkspaceID: source.WorkspaceID,
		}) || !slices.Contains([]assetcatalog.RunStatus{
			assetcatalog.RunStatusQueued,
			assetcatalog.RunStatusDelayed,
			assetcatalog.RunStatusRunning,
			assetcatalog.RunStatusFinalizing,
		}, current.Status) {
			return assetcatalog.SourceReadModel{}, assetcatalog.ErrStateConflict
		}
		model.CurrentRun = &current
	}
	if (source.LastSuccessRunID == "") != (wire.LastSuccessfulRun == nil) {
		return assetcatalog.SourceReadModel{}, assetcatalog.ErrStateConflict
	}
	if wire.LastSuccessfulRun != nil {
		last, valid := wire.LastSuccessfulRun.finish()
		if !valid || last.ID != source.LastSuccessRunID || last.SourceID != source.ID ||
			last.Scope != (assetcatalog.SourceScope{TenantID: source.TenantID, WorkspaceID: source.WorkspaceID}) ||
			last.Kind == assetcatalog.RunKindValidation || last.Status != assetcatalog.RunStatusSucceeded ||
			last.SourceRevision != source.PublishedRevision || last.SourceRevisionDigest != source.PublishedRevisionDigest ||
			last.CompletedAt == nil || source.LastSuccessAt == nil || *last.CompletedAt != *source.LastSuccessAt {
			return assetcatalog.SourceReadModel{}, assetcatalog.ErrStateConflict
		}
		model.LastSuccessfulRun = &last
	}
	return model.Clone(), nil
}

func decodeSourceRunReadProjection(projection []byte) (assetcatalog.SourceRun, error) {
	var wire sourceRunReadProjectionWire
	if !decodeStrictProjection(projection, &wire) || wire.Revision == nil ||
		!wire.SourceKind.Valid() || !projectionProviderKindPattern.MatchString(wire.ProviderKind) {
		return assetcatalog.SourceRun{}, assetcatalog.ErrStateConflict
	}
	run, ok := wire.Run.finish()
	if !ok {
		return assetcatalog.SourceRun{}, assetcatalog.ErrStateConflict
	}
	expectedSource := assetcatalog.Source{
		ID: run.SourceID, TenantID: run.Scope.TenantID, WorkspaceID: run.Scope.WorkspaceID,
		Kind: wire.SourceKind, ProviderKind: wire.ProviderKind,
	}
	revision, ok := wire.Revision.finish(&expectedSource)
	if !ok || revision.SourceID != run.SourceID || revision.TenantID != run.Scope.TenantID ||
		revision.WorkspaceID != run.Scope.WorkspaceID || revision.Revision != run.SourceRevision ||
		revision.CanonicalRevisionDigest != run.SourceRevisionDigest {
		return assetcatalog.SourceRun{}, assetcatalog.ErrStateConflict
	}
	return run.Clone(), nil
}

func decodeStrictProjection[T any](projection []byte, target *T) bool {
	if len(projection) == 0 {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(projection))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	var trailing any
	return decoder.Decode(&trailing) == io.EOF
}

func (wire sourceProjectionWire) finish() (assetcatalog.Source, bool) {
	source := assetcatalog.Source{
		ID:                        wire.ID,
		TenantID:                  wire.TenantID,
		WorkspaceID:               wire.WorkspaceID,
		ProviderKind:              wire.ProviderKind,
		Name:                      wire.Name,
		Kind:                      wire.Kind,
		Status:                    wire.Status,
		PublishedRevision:         projectionInt64(wire.PublishedRevision),
		PublishedRevisionDigest:   projectionString(wire.PublishedRevisionDigest),
		GateStatus:                wire.GateStatus,
		GateReasonCode:            projectionString(wire.GateReasonCode),
		GateRevision:              wire.GateRevision,
		ValidatedRunID:            projectionString(wire.ValidatedRunID),
		ValidationDigest:          projectionString(wire.ValidationDigest),
		ValidatedBindingDigest:    projectionString(wire.ValidatedBindingDigest),
		CheckpointSHA256:          projectionString(wire.CheckpointSHA256),
		CheckpointVersion:         wire.CheckpointVersion,
		CheckpointSourceRevision:  wire.CheckpointSourceRevision,
		NextAllowedAt:             projectionTime(wire.NextAllowedAt),
		ConsecutiveFailures:       wire.ConsecutiveFailures,
		LastSuccessRunID:          projectionString(wire.LastSuccessRunID),
		LastSuccessAt:             projectionTime(wire.LastSuccessAt),
		LastCompleteSnapshotRunID: projectionString(wire.LastCompleteSnapshotRunID),
		LastCompleteSnapshotAt:    projectionTime(wire.LastCompleteSnapshotAt),
		Version:                   wire.Version,
		CreatedAt:                 wire.CreatedAt.Time,
		UpdatedAt:                 wire.UpdatedAt.Time,
	}
	if source.Validate() != nil {
		return assetcatalog.Source{}, false
	}
	return source.Clone(), true
}

func (wire sourceRevisionProjectionWire) finish(expectedSource *assetcatalog.Source) (assetcatalog.SourceRevision, bool) {
	revision := assetcatalog.SourceRevision{
		ID:                            wire.ID,
		SourceID:                      wire.SourceID,
		TenantID:                      wire.TenantID,
		WorkspaceID:                   wire.WorkspaceID,
		Revision:                      wire.Revision,
		Status:                        wire.Status,
		ProfileManifestSHA256:         wire.ProfileManifestSHA256,
		CanonicalProviderSchemaSHA256: wire.ProviderSchemaSHA256,
		SourceDefinitionDigest:        wire.SourceDefinitionDigest,
		CanonicalRevisionDigest:       wire.CanonicalRevisionDigest,
		SyncMode:                      wire.SyncMode,
		AuthorityEnvironmentIDs:       slices.Clone(wire.AuthorityEnvironmentIDs),
		AuthorityScopeDigest:          wire.AuthorityScopeDigest,
		RateLimitRequests:             wire.RateLimitRequests,
		RateLimitWindowSeconds:        wire.RateLimitWindowSeconds,
		BackpressureBaseSeconds:       wire.BackpressureBaseSeconds,
		BackpressureMaxSeconds:        wire.BackpressureMaxSeconds,
		ProfileCode:                   wire.ProfileCode,
		ScheduleExpression:            projectionString(wire.ScheduleExpression),
		TypedExtensionCode:            assetcatalog.ExtensionCode(projectionString(wire.TypedExtensionCode)),
		PreparedExtensionDigest:       projectionString(wire.PreparedExtensionDigest),
		ValidationRunID:               projectionString(wire.ValidationRunID),
		ValidationDigest:              projectionString(wire.ValidationDigest),
		CreatedBy:                     wire.CreatedBy,
		ChangeReasonCode:              wire.ChangeReasonCode,
		ExpectedSourceVersion:         wire.ExpectedSourceVersion,
		Version:                       wire.Version,
		CreatedAt:                     wire.CreatedAt.Time,
		UpdatedAt:                     wire.UpdatedAt.Time,
	}
	if !wire.BindingValid || !validUUID(revision.ID) || !validUUID(revision.SourceID) ||
		!validUUID(revision.TenantID) || !validUUID(revision.WorkspaceID) || revision.Revision <= 0 ||
		!revision.Status.Valid() || !projectionDigestPattern.MatchString(revision.ProfileManifestSHA256) ||
		!projectionDigestPattern.MatchString(revision.CanonicalProviderSchemaSHA256) ||
		!projectionDigestPattern.MatchString(revision.SourceDefinitionDigest) ||
		!projectionDigestPattern.MatchString(revision.CanonicalRevisionDigest) || !revision.SyncMode.Valid() ||
		revision.RateLimitRequests < 1 || revision.RateLimitRequests > 1_000_000 ||
		revision.RateLimitWindowSeconds < 1 || revision.RateLimitWindowSeconds > 86_400 ||
		revision.BackpressureBaseSeconds < 1 || revision.BackpressureBaseSeconds > 86_400 ||
		revision.BackpressureMaxSeconds < revision.BackpressureBaseSeconds || revision.BackpressureMaxSeconds > 604_800 ||
		!revision.ProfileCode.Valid() || revision.ScheduleExpression != "" && !validProjectionText(revision.ScheduleExpression, 1, 256) ||
		(revision.TypedExtensionCode == "") != (revision.PreparedExtensionDigest == "") ||
		revision.TypedExtensionCode != "" && (!revision.TypedExtensionCode.Valid() ||
			!projectionDigestPattern.MatchString(revision.PreparedExtensionDigest)) ||
		!validProjectionText(revision.CreatedBy, 1, 256) ||
		!assetcatalog.ExtensionCode(revision.ChangeReasonCode).Valid() ||
		revision.ExpectedSourceVersion <= 0 || revision.Version <= 0 ||
		!validProjectionTime(revision.CreatedAt) || !validProjectionTime(revision.UpdatedAt) ||
		revision.CreatedAt.After(revision.UpdatedAt) || !validRevisionAuthority(wire, revision) ||
		!validRevisionStateClosure(revision) || !wire.ManifestSourceKind.Valid() ||
		!projectionProviderKindPattern.MatchString(wire.ManifestProviderKind) ||
		!wire.ManifestProfileCode.Valid() || !wire.ManifestSyncMode.Valid() ||
		wire.ManifestProfileCode != revision.ProfileCode || wire.ManifestSyncMode != revision.SyncMode ||
		!wire.EnvironmentMappingMode.Valid() {
		return assetcatalog.SourceRevision{}, false
	}
	switch wire.EnvironmentMappingMode {
	case assetcatalog.EnvironmentMappingSingle:
		if len(revision.AuthorityEnvironmentIDs) != 1 {
			return assetcatalog.SourceRevision{}, false
		}
	case assetcatalog.EnvironmentMappingExplicitItem:
		if len(revision.AuthorityEnvironmentIDs) < 1 || len(revision.AuthorityEnvironmentIDs) > 100 {
			return assetcatalog.SourceRevision{}, false
		}
	default:
		return assetcatalog.SourceRevision{}, false
	}
	if wire.ManifestSourceKind == assetcatalog.SourceKindKubernetesOperator {
		if revision.TypedExtensionCode == "" || revision.TypedExtensionCode != assetcatalog.ExtensionCode(wire.ManifestProfileCode) {
			return assetcatalog.SourceRevision{}, false
		}
	} else if revision.TypedExtensionCode != "" || revision.PreparedExtensionDigest != "" {
		return assetcatalog.SourceRevision{}, false
	}
	if expectedSource != nil && (revision.SourceID != expectedSource.ID || revision.TenantID != expectedSource.TenantID ||
		revision.WorkspaceID != expectedSource.WorkspaceID || wire.ManifestSourceKind != expectedSource.Kind ||
		wire.ManifestProviderKind != expectedSource.ProviderKind) {
		return assetcatalog.SourceRevision{}, false
	}
	if revision.CanonicalProfileManifest != nil || revision.CanonicalProviderSchema != nil || revision.IntegrationID != "" ||
		revision.CredentialReferenceID != "" || revision.TrustReferenceID != "" || revision.NetworkPolicyReferenceID != "" {
		return assetcatalog.SourceRevision{}, false
	}
	return revision.Clone(), true
}

func validRevisionAuthority(wire sourceRevisionProjectionWire, revision assetcatalog.SourceRevision) bool {
	if len(wire.AuthorityEnvironmentIDs) < 1 || len(wire.AuthorityEnvironmentIDs) > 100 ||
		len(wire.AuthorityEnvironmentIDs) != len(wire.AuthorityOrdinals) ||
		!slices.IsSorted(wire.AuthorityEnvironmentIDs) || !projectionDigestPattern.MatchString(wire.AuthorityScopeDigest) {
		return false
	}
	for index, environmentID := range wire.AuthorityEnvironmentIDs {
		if !validUUID(environmentID) || wire.AuthorityOrdinals[index] != index+1 ||
			index > 0 && wire.AuthorityEnvironmentIDs[index-1] == environmentID {
			return false
		}
	}
	digest, err := assetcatalog.AuthorityScopeDigest(revision.AuthorityEnvironmentIDs)
	return err == nil && digest == revision.AuthorityScopeDigest
}

func validRevisionStateClosure(revision assetcatalog.SourceRevision) bool {
	switch revision.Status {
	case assetcatalog.SourceRevisionDraft:
		return revision.ValidationRunID == "" && revision.ValidationDigest == ""
	case assetcatalog.SourceRevisionValidating:
		return validUUID(revision.ValidationRunID) && revision.ValidationDigest == ""
	case assetcatalog.SourceRevisionValidated, assetcatalog.SourceRevisionRejected,
		assetcatalog.SourceRevisionPublished, assetcatalog.SourceRevisionSuperseded:
		return validUUID(revision.ValidationRunID) && projectionDigestPattern.MatchString(revision.ValidationDigest)
	}
	return false
}

func (wire sourceRunProjectionWire) finish() (assetcatalog.SourceRun, bool) {
	run := assetcatalog.SourceRun{
		ID:                        wire.ID,
		SourceID:                  wire.SourceID,
		Scope:                     assetcatalog.SourceScope{TenantID: wire.TenantID, WorkspaceID: wire.WorkspaceID},
		SourceRevision:            wire.SourceRevision,
		SourceRevisionDigest:      wire.SourceRevisionDigest,
		Kind:                      wire.Kind,
		Status:                    wire.Status,
		Stage:                     wire.Stage,
		StageChangedAt:            wire.StageChangedAt.Time,
		TriggerType:               wire.TriggerType,
		GateRevision:              wire.GateRevision,
		PageSequence:              wire.PageSequence,
		PageDigest:                projectionString(wire.PageDigest),
		RelationPageSequence:      wire.RelationPageSequence,
		RelationPageDigest:        projectionString(wire.RelationPageDigest),
		CursorBeforeSHA256:        projectionString(wire.CursorBeforeSHA256),
		CursorAfterSHA256:         projectionString(wire.CursorAfterSHA256),
		CheckpointVersion:         wire.CheckpointVersion,
		NotBefore:                 wire.NotBefore.Time,
		HeartbeatSequence:         wire.HeartbeatSequence,
		FinalPage:                 wire.FinalPage,
		CompleteSnapshot:          wire.CompleteSnapshot,
		EffectiveCompleteSnapshot: wire.EffectiveCompleteSnapshot,
		WorkResultKind:            assetcatalog.WorkResultKind(projectionString(wire.WorkResultKind)),
		WorkResultStatus:          assetcatalog.WorkResultStatus(projectionString(wire.WorkResultStatus)),
		WorkResultDigest:          projectionString(wire.WorkResultDigest),
		WorkResultRecordedAt:      projectionTime(wire.WorkResultRecordedAt),
		ValidationOutcome:         assetcatalog.ValidationOutcome(projectionString(wire.ValidationOutcome)),
		ValidationProofDigest:     projectionString(wire.ValidationProofDigest),
		CredentialCleanupStatus:   wire.CredentialCleanupStatus,
		Observed:                  wire.Observed,
		Created:                   wire.Created,
		Changed:                   wire.Changed,
		Unchanged:                 wire.Unchanged,
		Conflicts:                 wire.Conflicts,
		Missing:                   wire.Missing,
		Stale:                     wire.Stale,
		Restored:                  wire.Restored,
		Tombstoned:                wire.Tombstoned,
		Rejected:                  wire.Rejected,
		FailureCode:               projectionString(wire.FailureCode),
		TraceID:                   projectionString(wire.TraceID),
		Version:                   wire.Version,
		CreatedAt:                 wire.CreatedAt.Time,
		StartedAt:                 projectionTime(wire.StartedAt),
		HeartbeatAt:               projectionTime(wire.HeartbeatAt),
		CompletedAt:               projectionTime(wire.CompletedAt),
	}
	validationRun := run.Clone()
	switch run.Status {
	case assetcatalog.RunStatusDelayed:
		validationRun.FenceEpoch = 1
	case assetcatalog.RunStatusRunning, assetcatalog.RunStatusFinalizing:
		leaseExpiry := run.StageChangedAt
		validationRun.LeaseExpiresAt = &leaseExpiry
		validationRun.FenceEpoch = 1
	case assetcatalog.RunStatusSucceeded, assetcatalog.RunStatusPartial, assetcatalog.RunStatusFailed:
		validationRun.FenceEpoch = 1
	case assetcatalog.RunStatusCancelled:
		if run.StartedAt != nil {
			validationRun.FenceEpoch = 1
		}
	}
	if validationRun.Validate() != nil || run.LeaseExpiresAt != nil || run.FenceEpoch != 0 {
		return assetcatalog.SourceRun{}, false
	}
	return run.Clone(), true
}

func projectionString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func projectionInt64(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

func projectionTime(value *databaseJSONTime) *time.Time {
	if value == nil {
		return nil
	}
	canonical := canonicalDatabaseTime(value.Time)
	return &canonical
}

func validProjectionTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 2000 && value.Year() <= 9999 &&
		value.Nanosecond()%1000 == 0 && value == value.Round(0)
}

func validProjectionText(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character == utf8.RuneError || character == 0 || character == '\r' || character == '\n' ||
			unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return false
		}
	}
	return true
}
