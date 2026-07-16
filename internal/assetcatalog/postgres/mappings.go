package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/domain"
)

const (
	conflictResolvedAction = "asset.conflict.resolved.v1"
	bindingCreatedAction   = "service.asset.binding.created.v1"
	bindingRemovedAction   = "service.asset.binding.removed.v1"
)

const resolveConflictScopeSQL = `
SELECT conflict.tenant_id::text, conflict.workspace_id::text, conflict.environment_id::text
FROM asset_conflicts AS conflict
JOIN workspaces AS workspace
  ON workspace.tenant_id = conflict.tenant_id
 AND workspace.id = conflict.workspace_id
JOIN environments AS environment
  ON environment.tenant_id = conflict.tenant_id
 AND environment.workspace_id = conflict.workspace_id
 AND environment.id = conflict.environment_id
WHERE conflict.workspace_id = $1::uuid
  AND conflict.id = $2::uuid
`

const relationshipColumns = `
relationship.id::text,
relationship.source_id::text,
relationship.canonical_revision_digest,
relationship.last_run_id::text,
relationship.tenant_id::text,
relationship.workspace_id::text,
relationship.source_revision,
relationship.last_page_sequence,
relationship.accepted_checkpoint_version,
relationship.run_fence_epoch,
relationship.relation_page_sha256,
relationship.source_environment_id::text,
relationship.target_environment_id::text,
relationship.source_asset_id::text,
relationship.target_asset_id::text,
relationship.from_external_id,
relationship.to_external_id,
relationship.relationship_type,
relationship.provider_path_code,
relationship.confidence,
relationship.freshness_kind,
relationship.freshness_order_time,
relationship.freshness_order_sequence,
relationship.provider_version_sha256,
relationship.relation_fact_sha256,
relationship.provenance,
COALESCE(relationship.provenance_source_id::text, ''),
COALESCE(relationship.cross_environment_policy_reference_id, ''),
relationship.status,
relationship.version,
relationship.created_at,
relationship.updated_at`

const listRelationshipsSQL = `
SELECT ` + relationshipColumns + `
FROM asset_relationships AS relationship
WHERE relationship.tenant_id = $1::uuid
  AND relationship.workspace_id = $2::uuid
  AND relationship.source_environment_id = $3::uuid
  AND relationship.target_environment_id = $3::uuid
  AND ($4::uuid IS NULL OR relationship.source_asset_id = $4::uuid OR relationship.target_asset_id = $4::uuid)
  AND ($5::uuid IS NULL OR relationship.source_id = $5::uuid)
  AND ($6::text[] IS NULL OR relationship.relationship_type = ANY($6::text[]))
  AND ($7::text[] IS NULL OR relationship.status = ANY($7::text[]))
  AND (
      $8::boolean OR (
          EXISTS (
              SELECT 1
              FROM service_asset_bindings AS source_access
              WHERE source_access.tenant_id = relationship.tenant_id
                AND source_access.workspace_id = relationship.workspace_id
                AND source_access.environment_id = relationship.source_environment_id
                AND source_access.asset_id = relationship.source_asset_id
                AND source_access.service_id = ANY($9::uuid[])
                AND source_access.status = 'ACTIVE'
          )
          AND EXISTS (
              SELECT 1
              FROM service_asset_bindings AS target_access
              WHERE target_access.tenant_id = relationship.tenant_id
                AND target_access.workspace_id = relationship.workspace_id
                AND target_access.environment_id = relationship.target_environment_id
                AND target_access.asset_id = relationship.target_asset_id
                AND target_access.service_id = ANY($9::uuid[])
                AND target_access.status = 'ACTIVE'
          )
      )
  )
  AND (
      $10::text IS NULL OR
      (relationship.relationship_type, relationship.source_asset_id, relationship.target_asset_id, relationship.id) >
      ($10::text, $11::uuid, $12::uuid, $13::uuid)
  )
ORDER BY relationship.relationship_type, relationship.source_asset_id, relationship.target_asset_id, relationship.id
LIMIT $14
`

const bindingColumns = `
binding.id::text,
binding.tenant_id::text,
binding.workspace_id::text,
binding.environment_id::text,
binding.service_id::text,
binding.asset_id::text,
binding.binding_role,
binding.mapping_status,
binding.provenance,
COALESCE(binding.provenance_source_id::text, ''),
binding.status,
binding.version,
binding.created_at,
binding.updated_at`

const listBindingsSQL = `
SELECT ` + bindingColumns + `
FROM service_asset_bindings AS binding
WHERE binding.tenant_id = $1::uuid
  AND binding.workspace_id = $2::uuid
  AND binding.environment_id = $3::uuid
  AND ($4::uuid IS NULL OR binding.service_id = $4::uuid)
  AND ($5::uuid IS NULL OR binding.asset_id = $5::uuid)
  AND ($6::text[] IS NULL OR binding.binding_role = ANY($6::text[]))
  AND ($7::text[] IS NULL OR binding.status = ANY($7::text[]))
  AND (
      $8::boolean OR (
          binding.service_id = ANY($9::uuid[])
          AND EXISTS (
              SELECT 1
              FROM service_asset_bindings AS asset_access
              WHERE asset_access.tenant_id = binding.tenant_id
                AND asset_access.workspace_id = binding.workspace_id
                AND asset_access.environment_id = binding.environment_id
                AND asset_access.asset_id = binding.asset_id
                AND asset_access.service_id = ANY($9::uuid[])
                AND asset_access.status = 'ACTIVE'
          )
      )
  )
  AND (
      $10::uuid IS NULL OR
      (binding.service_id, binding.binding_role, binding.asset_id, binding.id) >
      ($10::uuid, $11::text, $12::uuid, $13::uuid)
  )
ORDER BY binding.service_id, binding.binding_role, binding.asset_id, binding.id
LIMIT $14
`

const conflictColumns = `
conflict.id::text,
conflict.tenant_id::text,
conflict.workspace_id::text,
conflict.environment_id::text,
conflict.asset_id::text,
COALESCE(conflict.candidate_asset_id::text, ''),
COALESCE(conflict.candidate_service_id::text, ''),
conflict.source_id::text,
conflict.observation_id::text,
conflict.conflict_type,
COALESCE(conflict.field_name, ''),
COALESCE(conflict.existing_value_sha256, ''),
COALESCE(conflict.candidate_value_sha256, ''),
conflict.status,
COALESCE(conflict.resolution, ''),
COALESCE(conflict.resolution_reason_code, ''),
COALESCE(conflict.resolved_by, ''),
conflict.resolved_at,
conflict.version,
conflict.created_at,
conflict.updated_at`

const conflictReadModelColumns = conflictColumns + `,
observation.id::text,
observation.source_id::text,
observation.source_revision,
observation.observed_at,
asset.id::text,
asset.display_name,
asset.kind,
asset.lifecycle,
COALESCE(candidate_asset.id::text, ''),
COALESCE(candidate_asset.display_name, ''),
COALESCE(candidate_asset.kind, ''),
COALESCE(candidate_asset.lifecycle, ''),
COALESCE(candidate_service.id::text, ''),
COALESCE(candidate_service.name, ''),
(
    SELECT count(*)::bigint
    FROM service_asset_bindings AS impact_binding
    WHERE impact_binding.tenant_id = conflict.tenant_id
      AND impact_binding.workspace_id = conflict.workspace_id
      AND impact_binding.environment_id = conflict.environment_id
      AND impact_binding.asset_id = conflict.asset_id
      AND impact_binding.status = 'ACTIVE'
),
(
    SELECT count(*)::bigint
    FROM asset_relationships AS impact_relationship
    WHERE impact_relationship.tenant_id = conflict.tenant_id
      AND impact_relationship.workspace_id = conflict.workspace_id
      AND impact_relationship.status = 'ACTIVE'
      AND (
          impact_relationship.source_asset_id = conflict.asset_id OR
          impact_relationship.target_asset_id = conflict.asset_id
      )
),
(
    SELECT count(*)::bigint
    FROM service_asset_bindings AS candidate_binding
    WHERE conflict.candidate_asset_id IS NOT NULL
      AND candidate_binding.tenant_id = conflict.tenant_id
      AND candidate_binding.workspace_id = conflict.workspace_id
      AND candidate_binding.environment_id = conflict.environment_id
      AND candidate_binding.asset_id = conflict.candidate_asset_id
      AND candidate_binding.status = 'ACTIVE'
),
(
    SELECT count(*)::bigint
    FROM asset_relationships AS candidate_relationship
    WHERE conflict.candidate_asset_id IS NOT NULL
      AND candidate_relationship.tenant_id = conflict.tenant_id
      AND candidate_relationship.workspace_id = conflict.workspace_id
      AND candidate_relationship.status = 'ACTIVE'
      AND (
          candidate_relationship.source_asset_id = conflict.candidate_asset_id OR
          candidate_relationship.target_asset_id = conflict.candidate_asset_id
      )
),
(
    SELECT count(*)::bigint
    FROM service_asset_bindings AS candidate_service_binding
    WHERE conflict.candidate_service_id IS NOT NULL
      AND candidate_service_binding.tenant_id = conflict.tenant_id
      AND candidate_service_binding.workspace_id = conflict.workspace_id
      AND candidate_service_binding.environment_id = conflict.environment_id
      AND candidate_service_binding.service_id = conflict.candidate_service_id
      AND candidate_service_binding.status = 'ACTIVE'
)`

const conflictReadModelJoinsSQL = `
FROM asset_conflicts AS conflict
JOIN asset_observations AS observation
  ON observation.tenant_id = conflict.tenant_id
 AND observation.workspace_id = conflict.workspace_id
 AND observation.environment_id = conflict.environment_id
 AND observation.source_id = conflict.source_id
 AND observation.id = conflict.observation_id
JOIN assets AS asset
  ON asset.tenant_id = conflict.tenant_id
 AND asset.workspace_id = conflict.workspace_id
 AND asset.environment_id = conflict.environment_id
 AND asset.id = conflict.asset_id
LEFT JOIN assets AS candidate_asset
  ON candidate_asset.tenant_id = conflict.tenant_id
 AND candidate_asset.workspace_id = conflict.workspace_id
 AND candidate_asset.environment_id = conflict.environment_id
 AND candidate_asset.id = conflict.candidate_asset_id
LEFT JOIN services AS candidate_service
  ON candidate_service.tenant_id = conflict.tenant_id
 AND candidate_service.workspace_id = conflict.workspace_id
 AND candidate_service.id = conflict.candidate_service_id
`

const listConflictsSQL = `
SELECT ` + conflictReadModelColumns + conflictReadModelJoinsSQL + `
WHERE conflict.tenant_id = $1::uuid
  AND conflict.workspace_id = $2::uuid
  AND conflict.environment_id = $3::uuid
  AND ($4::uuid IS NULL OR conflict.asset_id = $4::uuid)
  AND ($5::uuid IS NULL OR conflict.source_id = $5::uuid)
  AND ($6::text[] IS NULL OR conflict.status = ANY($6::text[]))
  AND (
      $7::boolean OR (
          EXISTS (
              SELECT 1
              FROM service_asset_bindings AS primary_access
              WHERE primary_access.tenant_id = conflict.tenant_id
                AND primary_access.workspace_id = conflict.workspace_id
                AND primary_access.environment_id = conflict.environment_id
                AND primary_access.asset_id = conflict.asset_id
                AND primary_access.service_id = ANY($8::uuid[])
                AND primary_access.status = 'ACTIVE'
          )
          AND (
              conflict.candidate_asset_id IS NULL OR EXISTS (
                  SELECT 1
                  FROM service_asset_bindings AS candidate_access
                  WHERE candidate_access.tenant_id = conflict.tenant_id
                    AND candidate_access.workspace_id = conflict.workspace_id
                    AND candidate_access.environment_id = conflict.environment_id
                    AND candidate_access.asset_id = conflict.candidate_asset_id
                    AND candidate_access.service_id = ANY($8::uuid[])
                    AND candidate_access.status = 'ACTIVE'
              )
          )
          AND (
              conflict.candidate_service_id IS NULL OR
              conflict.candidate_service_id = ANY($8::uuid[])
          )
      )
  )
  AND (
      $9::timestamptz IS NULL OR
      (conflict.created_at, conflict.id) < ($9::timestamptz, $10::uuid)
  )
ORDER BY conflict.created_at DESC, conflict.id DESC
LIMIT $11
`

const getConflictReadModelSQL = `
SELECT ` + conflictReadModelColumns + conflictReadModelJoinsSQL + `
WHERE conflict.tenant_id = $1::uuid
  AND conflict.workspace_id = $2::uuid
  AND conflict.environment_id = $3::uuid
  AND conflict.id = $4::uuid
`

const getConflictForUpdateSQL = `
SELECT ` + conflictColumns + `
FROM asset_conflicts AS conflict
WHERE conflict.tenant_id = $1::uuid
  AND conflict.workspace_id = $2::uuid
  AND conflict.environment_id = $3::uuid
  AND conflict.id = $4::uuid
FOR UPDATE
`

const lockMappingAssetsSQL = `
SELECT ` + assetColumns + `
FROM assets AS a
WHERE a.tenant_id = $1::uuid
  AND a.workspace_id = $2::uuid
  AND a.environment_id = $3::uuid
  AND a.id = ANY($4::uuid[])
ORDER BY a.id::text COLLATE "C"
FOR UPDATE OF a
`

const lockExactServiceBindingSQL = `
SELECT public.asset_catalog_lock_exact_service_binding($1::uuid, $2::uuid, $3::uuid, $4::uuid)
`

const insertBindingSQL = `
INSERT INTO service_asset_bindings AS binding (
    id, tenant_id, workspace_id, environment_id, service_id, asset_id,
    binding_role, mapping_status, provenance, provenance_source_id, status,
    idempotency_key, request_hash, version
)
SELECT $1::uuid, asset.tenant_id, asset.workspace_id, asset.environment_id,
       service.id, asset.id, $7::text, 'EXACT', $8::text, NULL, 'ACTIVE',
       $9::text, $10::text, 1
FROM assets AS asset
JOIN services AS service
  ON service.tenant_id = asset.tenant_id
 AND service.workspace_id = asset.workspace_id
JOIN service_bindings AS legacy_binding
  ON legacy_binding.tenant_id = service.tenant_id
 AND legacy_binding.workspace_id = service.workspace_id
 AND legacy_binding.service_id = service.id
 AND legacy_binding.environment_id = asset.environment_id
 AND legacy_binding.mapping_status = 'EXACT'
WHERE asset.tenant_id = $2::uuid
  AND asset.workspace_id = $3::uuid
  AND asset.environment_id = $4::uuid
  AND asset.id = $5::uuid
  AND service.id = $6::uuid
  AND asset.mapping_status = 'EXACT'
RETURNING ` + bindingColumns + `
`

const getBindingForUpdateSQL = `
SELECT ` + bindingColumns + `
FROM service_asset_bindings AS binding
WHERE binding.tenant_id = $1::uuid
  AND binding.workspace_id = $2::uuid
  AND binding.environment_id = $3::uuid
  AND binding.id = $4::uuid
FOR UPDATE
`

const updateBindingInactiveSQL = `
UPDATE service_asset_bindings AS binding
SET status = 'INACTIVE',
    version = version + 1
WHERE binding.tenant_id = $1::uuid
  AND binding.workspace_id = $2::uuid
  AND binding.environment_id = $3::uuid
  AND binding.id = $4::uuid
  AND binding.version = $5
  AND binding.status = 'ACTIVE'
RETURNING ` + bindingColumns + `
`

const updateConflictDecisionSQL = `
UPDATE asset_conflicts AS conflict
SET status = $5::text,
    resolution = $6::text,
    resolution_reason_code = $7::text,
    resolved_by = $8::text,
    resolved_at = transaction_timestamp(),
    resolution_idempotency_key = $9::text,
    resolution_request_hash = $10::text,
    version = version + 1
WHERE conflict.tenant_id = $1::uuid
  AND conflict.workspace_id = $2::uuid
  AND conflict.environment_id = $3::uuid
  AND conflict.id = $4::uuid
  AND conflict.version = $11
  AND conflict.status = 'OPEN'
RETURNING ` + conflictColumns + `
`

const updateAssetMappingSQL = `
UPDATE assets AS a
SET mapping_status = $5::text,
    version = version + 1
WHERE a.tenant_id = $1::uuid
  AND a.workspace_id = $2::uuid
  AND a.environment_id = $3::uuid
  AND a.id = $4::uuid
  AND a.version = $6
RETURNING ` + assetColumns + `
`

const updateAssetQuarantineSQL = `
UPDATE assets AS a
SET lifecycle = 'QUARANTINED',
    version = version + 1
WHERE a.tenant_id = $1::uuid
  AND a.workspace_id = $2::uuid
  AND a.environment_id = $3::uuid
  AND a.id = $4::uuid
  AND a.version = $5
RETURNING ` + assetColumns + `
`

const otherOpenConflictSQL = `
SELECT EXISTS (
    SELECT 1
    FROM asset_conflicts AS other
    WHERE other.tenant_id = $1::uuid
      AND other.workspace_id = $2::uuid
      AND other.environment_id = $3::uuid
      AND other.asset_id = $4::uuid
      AND other.id <> $5::uuid
      AND other.status = 'OPEN'
)
`

const insertMappingAuditSQL = `
INSERT INTO audit_records (
    id, tenant_id, workspace_id, actor_type, actor_id, action,
    resource_type, resource_id, request_id, trace_id, payload_hash, details
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, 'USER', $4::text, $5::text,
    $6::text, $7::text, $8::text, $9::text, $10::text, $11::jsonb
)
`

const insertMappingOutboxSQL = `
INSERT INTO outbox_events (
    id, tenant_id, workspace_id, aggregate_type, aggregate_id,
    aggregate_version, event_type, payload
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, $4::text, $5::uuid,
    $6::bigint, $7::text, $8::jsonb
)
`

type mappingAuditDetails struct {
	EnvironmentID      string                          `json:"environment_id"`
	CommandSHA256      string                          `json:"command_sha256"`
	ResultVersion      int64                           `json:"result_version"`
	AssetID            string                          `json:"asset_id"`
	AssetVersion       int64                           `json:"asset_version,omitempty"`
	AssetLifecycle     assetcatalog.Lifecycle          `json:"asset_lifecycle,omitempty"`
	AssetMapping       domain.MappingStatus            `json:"asset_mapping_status,omitempty"`
	ServiceID          string                          `json:"service_id,omitempty"`
	BindingID          string                          `json:"binding_id,omitempty"`
	BindingRole        assetcatalog.BindingRole        `json:"binding_role,omitempty"`
	BindingStatus      assetcatalog.BindingStatus      `json:"binding_status,omitempty"`
	BindingVersion     int64                           `json:"binding_version,omitempty"`
	ConflictStatus     assetcatalog.ConflictStatus     `json:"conflict_status,omitempty"`
	ConflictResolution assetcatalog.ConflictResolution `json:"conflict_resolution,omitempty"`
	ReasonCode         string                          `json:"reason_code"`
}

type mappingAuditRecord struct {
	ID, ActorID, Action, ResourceType, ResourceID string
	PayloadHash, TraceID                          string
	Details                                       mappingAuditDetails
}

type conflictOutboxPayload struct {
	ConflictID      string                          `json:"conflict_id"`
	AssetID         string                          `json:"asset_id"`
	BindingID       string                          `json:"binding_id,omitempty"`
	Resolution      assetcatalog.ConflictResolution `json:"resolution"`
	ConflictVersion int64                           `json:"conflict_version"`
	AssetVersion    int64                           `json:"asset_version"`
}

type bindingOutboxPayload struct {
	BindingID string                     `json:"binding_id"`
	ServiceID string                     `json:"service_id"`
	AssetID   string                     `json:"asset_id"`
	Status    assetcatalog.BindingStatus `json:"status"`
	Version   int64                      `json:"version"`
}

func (repository *Repository) ResolveConflictScope(
	ctx context.Context,
	workspaceID string,
	conflictID string,
) (assetcatalog.Scope, error) {
	if !validUUID(workspaceID) || !validUUID(conflictID) {
		return assetcatalog.Scope{}, assetcatalog.ErrInvalidRequest
	}
	var scope assetcatalog.Scope
	err := repository.pool.QueryRow(ctx, resolveConflictScopeSQL, workspaceID, conflictID).Scan(
		&scope.TenantID,
		&scope.WorkspaceID,
		&scope.EnvironmentID,
	)
	if err != nil {
		return assetcatalog.Scope{}, mapMappingError(err)
	}
	if !scope.Valid() || scope.WorkspaceID != workspaceID {
		return assetcatalog.Scope{}, assetcatalog.ErrStateConflict
	}
	return scope, nil
}

func (repository *Repository) ListRelationships(
	ctx context.Context,
	request assetcatalog.ListRelationshipsRequest,
) (assetcatalog.RelationshipPage, error) {
	request = request.Clone()
	digest, err := request.QueryDigest()
	if err != nil {
		return assetcatalog.RelationshipPage{}, assetcatalog.ErrInvalidRequest
	}
	var cursorType, cursorSource, cursorTarget, cursorID any
	if request.Cursor != nil {
		cursorType = string(request.Cursor.Type)
		cursorSource = request.Cursor.SourceAssetID
		cursorTarget = request.Cursor.TargetAssetID
		cursorID = request.Cursor.RelationshipID
	}
	rows, err := repository.pool.Query(
		ctx,
		listRelationshipsSQL,
		request.Scope.TenantID,
		request.Scope.WorkspaceID,
		request.Scope.EnvironmentID,
		uuidOrNil(request.AssetID),
		uuidOrNil(request.SourceID),
		stringsOrNil(request.Types),
		stringsOrNil(request.Statuses),
		request.Access.Unrestricted(),
		request.Access.ServiceIDs(),
		cursorType,
		cursorSource,
		cursorTarget,
		cursorID,
		request.Limit+1,
	)
	if err != nil {
		return assetcatalog.RelationshipPage{}, mapMappingError(err)
	}
	defer rows.Close()
	items := make([]assetcatalog.Relationship, 0, request.Limit+1)
	for rows.Next() {
		item, scanErr := scanRelationship(rows)
		if scanErr != nil {
			return assetcatalog.RelationshipPage{}, mapMappingError(scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return assetcatalog.RelationshipPage{}, mapMappingError(err)
	}
	page := assetcatalog.RelationshipPage{Items: items}
	if len(page.Items) > request.Limit {
		page.Items = page.Items[:request.Limit]
		last := page.Items[len(page.Items)-1]
		page.Next = &assetcatalog.RelationshipCursor{
			QueryDigest: digest, Type: last.Type, SourceAssetID: last.SourceAssetID,
			TargetAssetID: last.TargetAssetID, RelationshipID: last.ID,
		}
	}
	return page.Clone(), nil
}

func (repository *Repository) ListBindings(
	ctx context.Context,
	request assetcatalog.ListBindingsRequest,
) (assetcatalog.BindingPage, error) {
	request = request.Clone()
	digest, err := request.QueryDigest()
	if err != nil {
		return assetcatalog.BindingPage{}, assetcatalog.ErrInvalidRequest
	}
	var cursorService, cursorRole, cursorAsset, cursorID any
	if request.Cursor != nil {
		cursorService = request.Cursor.ServiceID
		cursorRole = string(request.Cursor.Role)
		cursorAsset = request.Cursor.AssetID
		cursorID = request.Cursor.BindingID
	}
	rows, err := repository.pool.Query(
		ctx,
		listBindingsSQL,
		request.Scope.TenantID,
		request.Scope.WorkspaceID,
		request.Scope.EnvironmentID,
		uuidOrNil(request.ServiceID),
		uuidOrNil(request.AssetID),
		stringsOrNil(request.Roles),
		stringsOrNil(request.Statuses),
		request.Access.Unrestricted(),
		request.Access.ServiceIDs(),
		cursorService,
		cursorRole,
		cursorAsset,
		cursorID,
		request.Limit+1,
	)
	if err != nil {
		return assetcatalog.BindingPage{}, mapMappingError(err)
	}
	defer rows.Close()
	items := make([]assetcatalog.ServiceAssetBinding, 0, request.Limit+1)
	for rows.Next() {
		item, scanErr := scanBinding(rows)
		if scanErr != nil {
			return assetcatalog.BindingPage{}, mapMappingError(scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return assetcatalog.BindingPage{}, mapMappingError(err)
	}
	page := assetcatalog.BindingPage{Items: items}
	if len(page.Items) > request.Limit {
		page.Items = page.Items[:request.Limit]
		last := page.Items[len(page.Items)-1]
		page.Next = &assetcatalog.BindingCursor{
			QueryDigest: digest, ServiceID: last.ServiceID, Role: last.Role,
			AssetID: last.AssetID, BindingID: last.ID,
		}
	}
	return page.Clone(), nil
}

func (repository *Repository) ListConflicts(
	ctx context.Context,
	request assetcatalog.ListConflictsRequest,
) (assetcatalog.ConflictPage, error) {
	request = request.Clone()
	digest, err := request.QueryDigest()
	if err != nil {
		return assetcatalog.ConflictPage{}, assetcatalog.ErrInvalidRequest
	}
	var cursorTime, cursorID any
	if request.Cursor != nil {
		cursorTime = request.Cursor.CreatedAt
		cursorID = request.Cursor.ConflictID
	}
	rows, err := repository.pool.Query(
		ctx,
		listConflictsSQL,
		request.Scope.TenantID,
		request.Scope.WorkspaceID,
		request.Scope.EnvironmentID,
		uuidOrNil(request.AssetID),
		uuidOrNil(request.SourceID),
		stringsOrNil(request.Statuses),
		request.Access.Unrestricted(),
		request.Access.ServiceIDs(),
		cursorTime,
		cursorID,
		request.Limit+1,
	)
	if err != nil {
		return assetcatalog.ConflictPage{}, mapMappingError(err)
	}
	defer rows.Close()
	items := make([]assetcatalog.ConflictReadModel, 0, request.Limit+1)
	for rows.Next() {
		item, scanErr := scanConflictReadModel(rows)
		if scanErr != nil {
			return assetcatalog.ConflictPage{}, mapMappingError(scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return assetcatalog.ConflictPage{}, mapMappingError(err)
	}
	page := assetcatalog.ConflictPage{Items: items}
	if len(page.Items) > request.Limit {
		page.Items = page.Items[:request.Limit]
		last := page.Items[len(page.Items)-1]
		page.Next = &assetcatalog.ConflictCursor{
			QueryDigest: digest, CreatedAt: last.CreatedAt, ConflictID: last.ID,
		}
	}
	return page.Clone(), nil
}

func (repository *Repository) CreateBinding(
	ctx context.Context,
	command assetcatalog.CreateBindingCommand,
) (assetcatalog.BindingMutationResult, error) {
	scope, commandHash, err := validateCreateBindingCommand(command)
	if err != nil {
		return assetcatalog.BindingMutationResult{}, err
	}
	ids, err := repository.allocateIDs(3)
	if err != nil {
		return assetcatalog.BindingMutationResult{}, err
	}
	result, err := withMappingSerializable(repository, ctx, func(tx pgx.Tx) (assetcatalog.BindingMutationResult, error) {
		if err := prepareMutation(ctx, tx, scope, command.Context.IdempotencyKey()); err != nil {
			return assetcatalog.BindingMutationResult{}, err
		}
		record, found, err := findMappingAudit(ctx, tx, scope, command.Context.IdempotencyKey())
		if err != nil {
			return assetcatalog.BindingMutationResult{}, err
		}
		if found {
			if record.ResourceType != "SERVICE_ASSET_BINDING" || !validUUID(record.ResourceID) {
				return assetcatalog.BindingMutationResult{}, assetcatalog.ErrIdempotency
			}
			if err := validateMappingAudit(
				record, command.Context, scope, commandHash, bindingCreatedAction,
				"SERVICE_ASSET_BINDING", record.ResourceID,
			); err != nil {
				return assetcatalog.BindingMutationResult{}, err
			}
			if record.Details.ServiceID != command.ServiceID || record.Details.AssetID != command.AssetID ||
				record.Details.BindingRole != command.Role || record.Details.BindingID != record.ResourceID {
				return assetcatalog.BindingMutationResult{}, assetcatalog.ErrIdempotency
			}
			assets, err := lockMappingAssets(ctx, tx, scope, []string{record.Details.AssetID})
			if err != nil {
				return assetcatalog.BindingMutationResult{}, err
			}
			asset := assets[record.Details.AssetID]
			if asset.MappingStatus != domain.MappingExact ||
				asset.Lifecycle == assetcatalog.LifecycleRetired ||
				asset.Lifecycle == assetcatalog.LifecycleQuarantined {
				return assetcatalog.BindingMutationResult{}, assetcatalog.ErrStateConflict
			}
			if err := lockExactServiceBinding(ctx, tx, scope, record.Details.ServiceID); err != nil {
				return assetcatalog.BindingMutationResult{}, err
			}
			binding, err := lockBinding(ctx, tx, scope, record.ResourceID)
			if err != nil {
				return assetcatalog.BindingMutationResult{}, err
			}
			if !bindingMatchesAudit(binding, record.Details) {
				return assetcatalog.BindingMutationResult{}, assetcatalog.ErrStateConflict
			}
			return assetcatalog.BindingMutationResult{
				Binding: binding,
				Receipt: replayReceipt(record),
			}, nil
		}
		assets, err := lockMappingAssets(ctx, tx, scope, []string{command.AssetID})
		if err != nil {
			return assetcatalog.BindingMutationResult{}, err
		}
		asset := assets[command.AssetID]
		if asset.MappingStatus != domain.MappingExact ||
			asset.Lifecycle == assetcatalog.LifecycleRetired ||
			asset.Lifecycle == assetcatalog.LifecycleQuarantined {
			return assetcatalog.BindingMutationResult{}, assetcatalog.ErrStateConflict
		}
		if err := lockExactServiceBinding(ctx, tx, scope, command.ServiceID); err != nil {
			return assetcatalog.BindingMutationResult{}, err
		}
		binding, err := scanBinding(tx.QueryRow(
			ctx,
			insertBindingSQL,
			ids[0],
			scope.TenantID,
			scope.WorkspaceID,
			scope.EnvironmentID,
			command.AssetID,
			command.ServiceID,
			command.Role,
			assetcatalog.ProvenanceManual,
			command.Context.IdempotencyKey(),
			command.Context.RequestHash(),
		))
		if err != nil {
			return assetcatalog.BindingMutationResult{}, err
		}
		details := bindingAuditDetails(binding, commandHash, command.ReasonCode)
		if err := insertMappingSideEffects(
			ctx, tx, ids[1], ids[2], command.Context, bindingCreatedAction,
			"SERVICE_ASSET_BINDING", binding.ID, binding.Version, details,
			bindingOutboxPayload{
				BindingID: binding.ID, ServiceID: binding.ServiceID, AssetID: binding.AssetID,
				Status: binding.Status, Version: binding.Version,
			},
		); err != nil {
			return assetcatalog.BindingMutationResult{}, err
		}
		return assetcatalog.BindingMutationResult{
			Binding: binding,
			Receipt: assetcatalog.MutationReceipt{
				AuditID: ids[1], TraceID: command.Context.TraceID(),
			},
		}, nil
	})
	if err != nil {
		return assetcatalog.BindingMutationResult{}, err
	}
	return result.Clone(), nil
}

func (repository *Repository) DeleteBinding(
	ctx context.Context,
	command assetcatalog.DeleteBindingCommand,
) (assetcatalog.MutationReceipt, error) {
	scope, commandHash, err := validateDeleteBindingCommand(command)
	if err != nil {
		return assetcatalog.MutationReceipt{}, err
	}
	ids, err := repository.allocateIDs(2)
	if err != nil {
		return assetcatalog.MutationReceipt{}, err
	}
	return withMappingSerializable(repository, ctx, func(tx pgx.Tx) (assetcatalog.MutationReceipt, error) {
		if err := prepareMutation(ctx, tx, scope, command.Context.IdempotencyKey()); err != nil {
			return assetcatalog.MutationReceipt{}, err
		}
		record, found, err := findMappingAudit(ctx, tx, scope, command.Context.IdempotencyKey())
		if err != nil {
			return assetcatalog.MutationReceipt{}, err
		}
		if found {
			if err := validateMappingAudit(
				record, command.Context, scope, commandHash, bindingRemovedAction,
				"SERVICE_ASSET_BINDING", command.BindingID,
			); err != nil {
				return assetcatalog.MutationReceipt{}, err
			}
			binding, err := lockBinding(ctx, tx, scope, record.ResourceID)
			if err != nil {
				return assetcatalog.MutationReceipt{}, err
			}
			if !bindingMatchesAudit(binding, record.Details) {
				return assetcatalog.MutationReceipt{}, assetcatalog.ErrStateConflict
			}
			return replayReceipt(record), nil
		}
		binding, err := lockBinding(ctx, tx, scope, command.BindingID)
		if err != nil {
			return assetcatalog.MutationReceipt{}, err
		}
		if binding.Version != command.ExpectedVersion {
			return assetcatalog.MutationReceipt{}, assetcatalog.ErrVersionConflict
		}
		if binding.Status != assetcatalog.BindingStatusActive {
			return assetcatalog.MutationReceipt{}, assetcatalog.ErrStateConflict
		}
		binding, err = scanBinding(tx.QueryRow(
			ctx,
			updateBindingInactiveSQL,
			scope.TenantID,
			scope.WorkspaceID,
			scope.EnvironmentID,
			command.BindingID,
			command.ExpectedVersion,
		))
		if err != nil {
			return assetcatalog.MutationReceipt{}, err
		}
		details := bindingAuditDetails(binding, commandHash, command.ReasonCode)
		if err := insertMappingSideEffects(
			ctx, tx, ids[0], ids[1], command.Context, bindingRemovedAction,
			"SERVICE_ASSET_BINDING", binding.ID, binding.Version, details,
			bindingOutboxPayload{
				BindingID: binding.ID, ServiceID: binding.ServiceID, AssetID: binding.AssetID,
				Status: binding.Status, Version: binding.Version,
			},
		); err != nil {
			return assetcatalog.MutationReceipt{}, err
		}
		return assetcatalog.MutationReceipt{
			AuditID: ids[0], TraceID: command.Context.TraceID(),
		}, nil
	})
}

func (repository *Repository) ResolveConflict(
	ctx context.Context,
	decision assetcatalog.MappingDecision,
) (assetcatalog.MappingDecisionResult, error) {
	scope, commandHash, err := validateMappingDecision(decision)
	if err != nil {
		return assetcatalog.MappingDecisionResult{}, err
	}
	ids, err := repository.allocateIDs(3)
	if err != nil {
		return assetcatalog.MappingDecisionResult{}, err
	}
	result, err := withMappingSerializable(repository, ctx, func(tx pgx.Tx) (assetcatalog.MappingDecisionResult, error) {
		if err := prepareMutation(ctx, tx, scope, decision.Context.IdempotencyKey()); err != nil {
			return assetcatalog.MappingDecisionResult{}, err
		}
		record, found, err := findMappingAudit(ctx, tx, scope, decision.Context.IdempotencyKey())
		if err != nil {
			return assetcatalog.MappingDecisionResult{}, err
		}
		if found {
			if err := validateMappingAudit(
				record, decision.Context, scope, commandHash, conflictResolvedAction,
				"ASSET_CONFLICT", decision.ConflictID,
			); err != nil {
				return assetcatalog.MappingDecisionResult{}, err
			}
		}
		conflict, err := lockConflict(ctx, tx, scope, decision.ConflictID)
		if err != nil {
			return assetcatalog.MappingDecisionResult{}, err
		}
		assetIDs := []string{conflict.AssetID}
		if conflict.CandidateAssetID != "" {
			assetIDs = append(assetIDs, conflict.CandidateAssetID)
		}
		assets, err := lockMappingAssets(ctx, tx, scope, assetIDs)
		if err != nil {
			return assetcatalog.MappingDecisionResult{}, err
		}
		asset := assets[conflict.AssetID]
		if found {
			return replayConflictDecision(
				ctx, tx, scope, decision, commandHash, conflict, asset, record,
			)
		}
		if conflict.Version != decision.ExpectedVersion {
			return assetcatalog.MappingDecisionResult{}, assetcatalog.ErrVersionConflict
		}
		if conflict.Status != assetcatalog.ConflictStatusOpen ||
			asset.Lifecycle == assetcatalog.LifecycleRetired {
			return assetcatalog.MappingDecisionResult{}, assetcatalog.ErrStateConflict
		}
		if conflict.CandidateServiceID != "" &&
			decision.Resolution == assetcatalog.ConflictResolutionConfirmExact &&
			conflict.CandidateServiceID != decision.ServiceID {
			return assetcatalog.MappingDecisionResult{}, assetcatalog.ErrStateConflict
		}

		var (
			binding       *assetcatalog.ServiceAssetBinding
			conflictState = assetcatalog.ConflictStatusResolved
		)
		switch decision.Resolution {
		case assetcatalog.ConflictResolutionConfirmExact:
			if asset.Lifecycle == assetcatalog.LifecycleQuarantined {
				return assetcatalog.MappingDecisionResult{}, assetcatalog.ErrStateConflict
			}
			if err := lockExactServiceBinding(ctx, tx, scope, decision.ServiceID); err != nil {
				return assetcatalog.MappingDecisionResult{}, err
			}
			asset, err = updateMappingAsset(ctx, tx, asset, domain.MappingExact)
			if err != nil {
				return assetcatalog.MappingDecisionResult{}, err
			}
			created, err := scanBinding(tx.QueryRow(
				ctx,
				insertBindingSQL,
				ids[0],
				scope.TenantID,
				scope.WorkspaceID,
				scope.EnvironmentID,
				asset.ID,
				decision.ServiceID,
				decision.BindingRole,
				assetcatalog.ProvenanceMergeDecision,
				decision.Context.IdempotencyKey(),
				decision.Context.RequestHash(),
			))
			if err != nil {
				return assetcatalog.MappingDecisionResult{}, err
			}
			binding = &created
		case assetcatalog.ConflictResolutionRejectCandidate:
			conflictState = assetcatalog.ConflictStatusRejected
			var otherOpen bool
			if err := tx.QueryRow(
				ctx,
				otherOpenConflictSQL,
				scope.TenantID,
				scope.WorkspaceID,
				scope.EnvironmentID,
				asset.ID,
				conflict.ID,
			).Scan(&otherOpen); err != nil {
				return assetcatalog.MappingDecisionResult{}, err
			}
			mapping := domain.MappingUnresolved
			if otherOpen {
				mapping = domain.MappingAmbiguous
			}
			asset, err = updateMappingAsset(ctx, tx, asset, mapping)
			if err != nil {
				return assetcatalog.MappingDecisionResult{}, err
			}
		case assetcatalog.ConflictResolutionKeepUnresolved:
			asset, err = updateMappingAsset(ctx, tx, asset, domain.MappingUnresolved)
			if err != nil {
				return assetcatalog.MappingDecisionResult{}, err
			}
		case assetcatalog.ConflictResolutionQuarantineAsset:
			if asset.Lifecycle == assetcatalog.LifecycleQuarantined {
				return assetcatalog.MappingDecisionResult{}, assetcatalog.ErrStateConflict
			}
			asset, err = scanAsset(tx.QueryRow(
				ctx,
				updateAssetQuarantineSQL,
				scope.TenantID,
				scope.WorkspaceID,
				scope.EnvironmentID,
				asset.ID,
				asset.Version,
			))
			if err != nil {
				return assetcatalog.MappingDecisionResult{}, err
			}
		default:
			return assetcatalog.MappingDecisionResult{}, assetcatalog.ErrInvalidRequest
		}
		conflict, err = scanConflict(tx.QueryRow(
			ctx,
			updateConflictDecisionSQL,
			scope.TenantID,
			scope.WorkspaceID,
			scope.EnvironmentID,
			conflict.ID,
			conflictState,
			decision.Resolution,
			decision.ReasonCode,
			decision.Context.ActorID(),
			decision.Context.IdempotencyKey(),
			decision.Context.RequestHash(),
			decision.ExpectedVersion,
		))
		if err != nil {
			return assetcatalog.MappingDecisionResult{}, err
		}
		model, err := loadConflictReadModel(ctx, tx, scope, conflict.ID)
		if err != nil {
			return assetcatalog.MappingDecisionResult{}, err
		}
		details := mappingAuditDetails{
			EnvironmentID: scope.EnvironmentID, CommandSHA256: commandHash,
			ResultVersion: conflict.Version, AssetID: asset.ID, AssetVersion: asset.Version,
			AssetLifecycle: asset.Lifecycle, AssetMapping: asset.MappingStatus,
			ConflictStatus: conflict.Status, ConflictResolution: conflict.Resolution,
			ReasonCode: decision.ReasonCode,
		}
		if binding != nil {
			details.ServiceID = binding.ServiceID
			details.BindingID = binding.ID
			details.BindingRole = binding.Role
			details.BindingStatus = binding.Status
			details.BindingVersion = binding.Version
		}
		if err := insertMappingSideEffects(
			ctx, tx, ids[1], ids[2], decision.Context, conflictResolvedAction,
			"ASSET_CONFLICT", conflict.ID, conflict.Version, details,
			conflictOutboxPayload{
				ConflictID: conflict.ID, AssetID: asset.ID, BindingID: details.BindingID,
				Resolution: conflict.Resolution, ConflictVersion: conflict.Version, AssetVersion: asset.Version,
			},
		); err != nil {
			return assetcatalog.MappingDecisionResult{}, err
		}
		return assetcatalog.MappingDecisionResult{
			Conflict: model, Binding: binding,
			Receipt: assetcatalog.MutationReceipt{
				AuditID: ids[1], TraceID: decision.Context.TraceID(),
			},
		}, nil
	})
	if err != nil {
		return assetcatalog.MappingDecisionResult{}, err
	}
	return result.Clone(), nil
}

func replayConflictDecision(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	decision assetcatalog.MappingDecision,
	commandHash string,
	conflict assetcatalog.Conflict,
	asset assetcatalog.Asset,
	record mappingAuditRecord,
) (assetcatalog.MappingDecisionResult, error) {
	if err := validateMappingAudit(
		record, decision.Context, scope, commandHash, conflictResolvedAction,
		"ASSET_CONFLICT", decision.ConflictID,
	); err != nil {
		return assetcatalog.MappingDecisionResult{}, err
	}
	details := record.Details
	if conflict.Version != details.ResultVersion || conflict.Status != details.ConflictStatus ||
		conflict.Resolution != details.ConflictResolution || asset.ID != details.AssetID ||
		asset.Version != details.AssetVersion || asset.Lifecycle != details.AssetLifecycle ||
		asset.MappingStatus != details.AssetMapping {
		return assetcatalog.MappingDecisionResult{}, assetcatalog.ErrStateConflict
	}
	var binding *assetcatalog.ServiceAssetBinding
	if decision.Resolution == assetcatalog.ConflictResolutionConfirmExact {
		if details.ServiceID != decision.ServiceID || details.BindingRole != decision.BindingRole ||
			!validUUID(details.BindingID) {
			return assetcatalog.MappingDecisionResult{}, assetcatalog.ErrIdempotency
		}
		if err := lockExactServiceBinding(ctx, tx, scope, decision.ServiceID); err != nil {
			return assetcatalog.MappingDecisionResult{}, err
		}
		locked, err := lockBinding(ctx, tx, scope, details.BindingID)
		if err != nil {
			return assetcatalog.MappingDecisionResult{}, err
		}
		if !bindingMatchesAudit(locked, details) {
			return assetcatalog.MappingDecisionResult{}, assetcatalog.ErrStateConflict
		}
		binding = &locked
	} else if details.ServiceID != "" || details.BindingID != "" || details.BindingRole != "" {
		return assetcatalog.MappingDecisionResult{}, assetcatalog.ErrStateConflict
	}
	model, err := loadConflictReadModel(ctx, tx, scope, conflict.ID)
	if err != nil {
		return assetcatalog.MappingDecisionResult{}, err
	}
	return assetcatalog.MappingDecisionResult{
		Conflict: model, Binding: binding, Receipt: replayReceipt(record),
	}, nil
}

func withMappingSerializable[T any](
	repository *Repository,
	ctx context.Context,
	operation func(pgx.Tx) (T, error),
) (T, error) {
	var zero T
	for attempt := 0; attempt < serializableAttempts; attempt++ {
		tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{
			IsoLevel:   pgx.Serializable,
			AccessMode: pgx.ReadWrite,
		})
		if err != nil {
			return zero, mapMappingError(err)
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
			return zero, mapMappingError(operationErr)
		}
		if err := tx.Commit(ctx); err != nil {
			if isRetryablePGError(err) && attempt+1 < serializableAttempts {
				if waitErr := waitForRetry(ctx, attempt); waitErr != nil {
					return zero, waitErr
				}
				continue
			}
			return zero, mapMappingError(err)
		}
		return result, nil
	}
	return zero, assetcatalog.ErrStateConflict
}

func lockConflict(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	conflictID string,
) (assetcatalog.Conflict, error) {
	conflict, err := scanConflict(tx.QueryRow(
		ctx,
		getConflictForUpdateSQL,
		scope.TenantID,
		scope.WorkspaceID,
		scope.EnvironmentID,
		conflictID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return assetcatalog.Conflict{}, assetcatalog.ErrNotFound
	}
	return conflict, err
}

func lockMappingAssets(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	assetIDs []string,
) (map[string]assetcatalog.Asset, error) {
	ids := slices.Clone(assetIDs)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if len(ids) == 0 {
		return nil, assetcatalog.ErrInvalidRequest
	}
	for _, id := range ids {
		if !validUUID(id) {
			return nil, assetcatalog.ErrInvalidRequest
		}
	}
	rows, err := tx.Query(
		ctx,
		lockMappingAssetsSQL,
		scope.TenantID,
		scope.WorkspaceID,
		scope.EnvironmentID,
		ids,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]assetcatalog.Asset, len(ids))
	for rows.Next() {
		asset, scanErr := scanAsset(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result[asset.ID] = asset
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(result) != len(ids) {
		return nil, assetcatalog.ErrScopeViolation
	}
	return result, nil
}

func lockExactServiceBinding(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	serviceID string,
) error {
	var locked bool
	err := tx.QueryRow(
		ctx,
		lockExactServiceBindingSQL,
		scope.TenantID,
		scope.WorkspaceID,
		scope.EnvironmentID,
		serviceID,
	).Scan(&locked)
	if err != nil {
		return err
	}
	if !locked {
		return assetcatalog.ErrScopeViolation
	}
	return nil
}

func lockBinding(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	bindingID string,
) (assetcatalog.ServiceAssetBinding, error) {
	binding, err := scanBinding(tx.QueryRow(
		ctx,
		getBindingForUpdateSQL,
		scope.TenantID,
		scope.WorkspaceID,
		scope.EnvironmentID,
		bindingID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return assetcatalog.ServiceAssetBinding{}, assetcatalog.ErrNotFound
	}
	return binding, err
}

func updateMappingAsset(
	ctx context.Context,
	tx pgx.Tx,
	asset assetcatalog.Asset,
	mapping domain.MappingStatus,
) (assetcatalog.Asset, error) {
	updated, err := scanAsset(tx.QueryRow(
		ctx,
		updateAssetMappingSQL,
		asset.Scope.TenantID,
		asset.Scope.WorkspaceID,
		asset.Scope.EnvironmentID,
		asset.ID,
		mapping,
		asset.Version,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return assetcatalog.Asset{}, assetcatalog.ErrVersionConflict
	}
	return updated, err
}

func findMappingAudit(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	idempotencyKey string,
) (mappingAuditRecord, bool, error) {
	var (
		record  mappingAuditRecord
		traceID *string
		details []byte
	)
	err := tx.QueryRow(
		ctx,
		mutationAuditLookupSQL,
		scope.TenantID,
		scope.WorkspaceID,
		idempotencyKey,
	).Scan(
		&record.ID,
		&record.ActorID,
		&record.Action,
		&record.ResourceType,
		&record.ResourceID,
		&record.PayloadHash,
		&traceID,
		&details,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return mappingAuditRecord{}, false, nil
	}
	if err != nil {
		return mappingAuditRecord{}, false, err
	}
	if traceID == nil || !validUUID(record.ID) ||
		decodeStrictJSON(details, &record.Details) != nil {
		return mappingAuditRecord{}, false, assetcatalog.ErrStateConflict
	}
	record.TraceID = *traceID
	return record, true, nil
}

func validateMappingAudit(
	record mappingAuditRecord,
	mutationContext assetcatalog.MutationContext,
	scope assetcatalog.Scope,
	commandHash string,
	action string,
	resourceType string,
	resourceID string,
) error {
	if record.Action != action || record.ResourceType != resourceType || record.ResourceID != resourceID ||
		record.PayloadHash != mutationContext.RequestHash() || record.ActorID != mutationContext.ActorID() ||
		record.Details.EnvironmentID != scope.EnvironmentID ||
		record.Details.CommandSHA256 != commandHash || record.Details.ResultVersion <= 0 {
		return assetcatalog.ErrIdempotency
	}
	return nil
}

func insertMappingSideEffects(
	ctx context.Context,
	tx pgx.Tx,
	auditID string,
	outboxID string,
	mutationContext assetcatalog.MutationContext,
	action string,
	resourceType string,
	resourceID string,
	version int64,
	details mappingAuditDetails,
	payload any,
) error {
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return assetcatalog.ErrStateConflict
	}
	if _, err := tx.Exec(
		ctx,
		insertMappingAuditSQL,
		auditID,
		mutationContext.SourceScope().TenantID,
		mutationContext.SourceScope().WorkspaceID,
		mutationContext.ActorID(),
		action,
		resourceType,
		resourceID,
		mutationContext.IdempotencyKey(),
		mutationContext.TraceID(),
		mutationContext.RequestHash(),
		string(detailsJSON),
	); err != nil {
		return err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return assetcatalog.ErrStateConflict
	}
	_, err = tx.Exec(
		ctx,
		insertMappingOutboxSQL,
		outboxID,
		mutationContext.SourceScope().TenantID,
		mutationContext.SourceScope().WorkspaceID,
		resourceType,
		resourceID,
		version,
		action,
		string(payloadJSON),
	)
	return err
}

func bindingAuditDetails(
	binding assetcatalog.ServiceAssetBinding,
	commandHash string,
	reasonCode string,
) mappingAuditDetails {
	return mappingAuditDetails{
		EnvironmentID: binding.Scope.EnvironmentID, CommandSHA256: commandHash,
		ResultVersion: binding.Version, AssetID: binding.AssetID, ServiceID: binding.ServiceID,
		BindingID: binding.ID, BindingRole: binding.Role, BindingStatus: binding.Status,
		BindingVersion: binding.Version,
		ReasonCode:     reasonCode,
	}
}

func bindingMatchesAudit(
	binding assetcatalog.ServiceAssetBinding,
	details mappingAuditDetails,
) bool {
	return binding.ID == details.BindingID && binding.AssetID == details.AssetID &&
		binding.ServiceID == details.ServiceID && binding.Role == details.BindingRole &&
		binding.Status == details.BindingStatus && binding.Version == details.BindingVersion
}

func replayReceipt(record mappingAuditRecord) assetcatalog.MutationReceipt {
	return assetcatalog.MutationReceipt{
		AuditID: record.ID, TraceID: record.TraceID, IdempotentReplay: true,
	}
}

func loadConflictReadModel(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	conflictID string,
) (assetcatalog.ConflictReadModel, error) {
	return scanConflictReadModel(tx.QueryRow(
		ctx,
		getConflictReadModelSQL,
		scope.TenantID,
		scope.WorkspaceID,
		scope.EnvironmentID,
		conflictID,
	))
}

func scanRelationship(row rowScanner) (assetcatalog.Relationship, error) {
	var relationship assetcatalog.Relationship
	if err := row.Scan(
		&relationship.ID,
		&relationship.SourceID,
		&relationship.CanonicalRevisionDigest,
		&relationship.LastRunID,
		&relationship.SourceScope.TenantID,
		&relationship.SourceScope.WorkspaceID,
		&relationship.SourceRevision,
		&relationship.LastPageSequence,
		&relationship.AcceptedCheckpointVersion,
		&relationship.RunFenceEpoch,
		&relationship.RelationPageSHA256,
		&relationship.SourceEnvironmentID,
		&relationship.TargetEnvironmentID,
		&relationship.SourceAssetID,
		&relationship.TargetAssetID,
		&relationship.FromExternalID,
		&relationship.ToExternalID,
		&relationship.Type,
		&relationship.ProviderPathCode,
		&relationship.Confidence,
		&relationship.FreshnessKind,
		&relationship.FreshnessOrderTime,
		&relationship.FreshnessOrderSequence,
		&relationship.ProviderVersionSHA256,
		&relationship.RelationFactSHA256,
		&relationship.Provenance,
		&relationship.ProvenanceSourceID,
		&relationship.CrossEnvironmentPolicyReferenceID,
		&relationship.Status,
		&relationship.Version,
		&relationship.CreatedAt,
		&relationship.UpdatedAt,
	); err != nil {
		return assetcatalog.Relationship{}, err
	}
	if relationship.FreshnessOrderTime != nil {
		value := canonicalDatabaseTime(*relationship.FreshnessOrderTime)
		relationship.FreshnessOrderTime = &value
	}
	relationship.CreatedAt = canonicalDatabaseTime(relationship.CreatedAt)
	relationship.UpdatedAt = canonicalDatabaseTime(relationship.UpdatedAt)
	if err := relationship.Validate(); err != nil {
		return assetcatalog.Relationship{}, assetcatalog.ErrStateConflict
	}
	return relationship.Clone(), nil
}

func scanBinding(row rowScanner) (assetcatalog.ServiceAssetBinding, error) {
	var binding assetcatalog.ServiceAssetBinding
	if err := row.Scan(
		&binding.ID,
		&binding.Scope.TenantID,
		&binding.Scope.WorkspaceID,
		&binding.Scope.EnvironmentID,
		&binding.ServiceID,
		&binding.AssetID,
		&binding.Role,
		&binding.MappingStatus,
		&binding.Provenance,
		&binding.ProvenanceSourceID,
		&binding.Status,
		&binding.Version,
		&binding.CreatedAt,
		&binding.UpdatedAt,
	); err != nil {
		return assetcatalog.ServiceAssetBinding{}, err
	}
	binding.CreatedAt = canonicalDatabaseTime(binding.CreatedAt)
	binding.UpdatedAt = canonicalDatabaseTime(binding.UpdatedAt)
	if err := binding.Validate(); err != nil {
		return assetcatalog.ServiceAssetBinding{}, assetcatalog.ErrStateConflict
	}
	return binding, nil
}

func scanConflict(row rowScanner) (assetcatalog.Conflict, error) {
	var conflict assetcatalog.Conflict
	if err := row.Scan(
		&conflict.ID,
		&conflict.Scope.TenantID,
		&conflict.Scope.WorkspaceID,
		&conflict.Scope.EnvironmentID,
		&conflict.AssetID,
		&conflict.CandidateAssetID,
		&conflict.CandidateServiceID,
		&conflict.SourceID,
		&conflict.ObservationID,
		&conflict.Type,
		&conflict.FieldName,
		&conflict.ExistingValueSHA256,
		&conflict.CandidateValueSHA256,
		&conflict.Status,
		&conflict.Resolution,
		&conflict.ResolutionReasonCode,
		&conflict.ResolvedBy,
		&conflict.ResolvedAt,
		&conflict.Version,
		&conflict.CreatedAt,
		&conflict.UpdatedAt,
	); err != nil {
		return assetcatalog.Conflict{}, err
	}
	if conflict.ResolvedAt != nil {
		value := canonicalDatabaseTime(*conflict.ResolvedAt)
		conflict.ResolvedAt = &value
	}
	conflict.CreatedAt = canonicalDatabaseTime(conflict.CreatedAt)
	conflict.UpdatedAt = canonicalDatabaseTime(conflict.UpdatedAt)
	if err := conflict.Validate(); err != nil {
		return assetcatalog.Conflict{}, assetcatalog.ErrStateConflict
	}
	return conflict.Clone(), nil
}

func scanConflictReadModel(row rowScanner) (assetcatalog.ConflictReadModel, error) {
	var (
		model                   assetcatalog.ConflictReadModel
		candidateAssetID        string
		candidateAssetName      string
		candidateAssetKind      string
		candidateAssetLifecycle string
		candidateServiceID      string
		candidateServiceName    string
	)
	conflictDestinations := []any{
		&model.ID,
		&model.Scope.TenantID,
		&model.Scope.WorkspaceID,
		&model.Scope.EnvironmentID,
		&model.AssetID,
		&model.CandidateAssetID,
		&model.CandidateServiceID,
		&model.SourceID,
		&model.ObservationID,
		&model.Type,
		&model.FieldName,
		&model.ExistingValueSHA256,
		&model.CandidateValueSHA256,
		&model.Status,
		&model.Resolution,
		&model.ResolutionReasonCode,
		&model.ResolvedBy,
		&model.ResolvedAt,
		&model.Version,
		&model.CreatedAt,
		&model.UpdatedAt,
	}
	destinations := append(conflictDestinations,
		&model.Observation.ID,
		&model.Observation.SourceID,
		&model.Observation.SourceRevision,
		&model.Observation.ObservedAt,
		&model.Asset.ID,
		&model.Asset.DisplayName,
		&model.Asset.Kind,
		&model.Asset.Lifecycle,
		&candidateAssetID,
		&candidateAssetName,
		&candidateAssetKind,
		&candidateAssetLifecycle,
		&candidateServiceID,
		&candidateServiceName,
		&model.Impact.AssetActiveBindings,
		&model.Impact.AssetActiveRelationships,
		&model.Impact.CandidateAssetActiveBindings,
		&model.Impact.CandidateAssetActiveRelationships,
		&model.Impact.CandidateServiceActiveBindings,
	)
	if err := row.Scan(destinations...); err != nil {
		return assetcatalog.ConflictReadModel{}, err
	}
	if model.ResolvedAt != nil {
		value := canonicalDatabaseTime(*model.ResolvedAt)
		model.ResolvedAt = &value
	}
	model.CreatedAt = canonicalDatabaseTime(model.CreatedAt)
	model.UpdatedAt = canonicalDatabaseTime(model.UpdatedAt)
	model.Observation.ObservedAt = canonicalDatabaseTime(model.Observation.ObservedAt)
	if err := model.Conflict.Validate(); err != nil ||
		model.Observation.ID != model.ObservationID ||
		model.Observation.SourceID != model.SourceID ||
		model.Observation.SourceRevision <= 0 ||
		!validUUID(model.Asset.ID) || model.Asset.ID != model.AssetID ||
		model.Asset.DisplayName == "" || !model.Asset.Kind.Valid() || !model.Asset.Lifecycle.Valid() ||
		model.Impact.AssetActiveBindings < 0 || model.Impact.AssetActiveRelationships < 0 ||
		model.Impact.CandidateAssetActiveBindings < 0 ||
		model.Impact.CandidateAssetActiveRelationships < 0 ||
		model.Impact.CandidateServiceActiveBindings < 0 {
		return assetcatalog.ConflictReadModel{}, assetcatalog.ErrStateConflict
	}
	if model.CandidateAssetID == "" {
		if candidateAssetID != "" || candidateAssetName != "" || candidateAssetKind != "" || candidateAssetLifecycle != "" {
			return assetcatalog.ConflictReadModel{}, assetcatalog.ErrStateConflict
		}
	} else {
		candidate := assetcatalog.ConflictAssetReference{
			ID: candidateAssetID, DisplayName: candidateAssetName,
			Kind:      assetcatalog.Kind(candidateAssetKind),
			Lifecycle: assetcatalog.Lifecycle(candidateAssetLifecycle),
		}
		if candidate.ID != model.CandidateAssetID || candidate.DisplayName == "" ||
			!candidate.Kind.Valid() || !candidate.Lifecycle.Valid() {
			return assetcatalog.ConflictReadModel{}, assetcatalog.ErrStateConflict
		}
		model.CandidateAsset = &candidate
	}
	if model.CandidateServiceID == "" {
		if candidateServiceID != "" || candidateServiceName != "" {
			return assetcatalog.ConflictReadModel{}, assetcatalog.ErrStateConflict
		}
	} else {
		candidate := assetcatalog.ConflictServiceReference{
			ID: candidateServiceID, Name: candidateServiceName,
		}
		if candidate.ID != model.CandidateServiceID || candidate.Name == "" {
			return assetcatalog.ConflictReadModel{}, assetcatalog.ErrStateConflict
		}
		model.CandidateService = &candidate
	}
	return model.Clone(), nil
}

func validateCreateBindingCommand(
	command assetcatalog.CreateBindingCommand,
) (assetcatalog.Scope, string, error) {
	scope, ok := validEnvironmentMutationContext(command.Context)
	if !ok || !validUUID(command.ServiceID) || !validUUID(command.AssetID) ||
		!command.Role.Valid() || !validAssetCode(command.ReasonCode, 128) {
		return assetcatalog.Scope{}, "", assetcatalog.ErrInvalidRequest
	}
	hash, err := semanticCommandHash(struct {
		Operation  string                   `json:"operation"`
		Scope      assetcatalog.Scope       `json:"scope"`
		ServiceID  string                   `json:"service_id"`
		AssetID    string                   `json:"asset_id"`
		Role       assetcatalog.BindingRole `json:"role"`
		ReasonCode string                   `json:"reason_code"`
	}{
		Operation: bindingCreatedAction, Scope: scope, ServiceID: command.ServiceID,
		AssetID: command.AssetID, Role: command.Role, ReasonCode: command.ReasonCode,
	})
	return scope, hash, err
}

func validateDeleteBindingCommand(
	command assetcatalog.DeleteBindingCommand,
) (assetcatalog.Scope, string, error) {
	scope, ok := validEnvironmentMutationContext(command.Context)
	if !ok || !validUUID(command.BindingID) || !validAssetCode(command.ReasonCode, 128) ||
		command.ExpectedVersion <= 0 {
		return assetcatalog.Scope{}, "", assetcatalog.ErrInvalidRequest
	}
	hash, err := semanticCommandHash(struct {
		Operation       string             `json:"operation"`
		Scope           assetcatalog.Scope `json:"scope"`
		BindingID       string             `json:"binding_id"`
		ReasonCode      string             `json:"reason_code"`
		ExpectedVersion int64              `json:"expected_version"`
	}{
		Operation: bindingRemovedAction, Scope: scope, BindingID: command.BindingID,
		ReasonCode: command.ReasonCode, ExpectedVersion: command.ExpectedVersion,
	})
	return scope, hash, err
}

func validateMappingDecision(
	decision assetcatalog.MappingDecision,
) (assetcatalog.Scope, string, error) {
	scope, ok := validEnvironmentMutationContext(decision.Context)
	if !ok || !validUUID(decision.ConflictID) || !decision.Resolution.Valid() ||
		!validAssetCode(decision.ReasonCode, 128) || decision.ExpectedVersion <= 0 {
		return assetcatalog.Scope{}, "", assetcatalog.ErrInvalidRequest
	}
	if decision.Resolution == assetcatalog.ConflictResolutionConfirmExact {
		if !validUUID(decision.ServiceID) || !decision.BindingRole.Valid() {
			return assetcatalog.Scope{}, "", assetcatalog.ErrInvalidRequest
		}
	} else if decision.ServiceID != "" || decision.BindingRole != "" {
		return assetcatalog.Scope{}, "", assetcatalog.ErrInvalidRequest
	}
	hash, err := semanticCommandHash(struct {
		Operation       string                          `json:"operation"`
		Scope           assetcatalog.Scope              `json:"scope"`
		ConflictID      string                          `json:"conflict_id"`
		ServiceID       string                          `json:"service_id"`
		Resolution      assetcatalog.ConflictResolution `json:"resolution"`
		BindingRole     assetcatalog.BindingRole        `json:"binding_role"`
		ReasonCode      string                          `json:"reason_code"`
		ExpectedVersion int64                           `json:"expected_version"`
	}{
		Operation: conflictResolvedAction, Scope: scope, ConflictID: decision.ConflictID,
		ServiceID: decision.ServiceID, Resolution: decision.Resolution,
		BindingRole: decision.BindingRole, ReasonCode: decision.ReasonCode,
		ExpectedVersion: decision.ExpectedVersion,
	})
	return scope, hash, err
}

func mapMappingError(err error) error {
	if err == nil {
		return nil
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.ConstraintName {
		case "asset_catalog_exact_service_binding_service_scope_guard",
			"asset_catalog_exact_service_binding_environment_guard",
			"asset_catalog_exact_service_binding_mapping_guard":
			return assetcatalog.ErrScopeViolation
		case "service_asset_bindings_active_uk":
			return assetcatalog.ErrStateConflict
		}
	}
	return mapPGError(err)
}

var _ assetcatalog.MappingRepository = (*Repository)(nil)
