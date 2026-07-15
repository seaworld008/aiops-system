package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/domain"
)

const activeServiceReferencesSQL = `
SELECT COALESCE(
    jsonb_agg(
        jsonb_build_object('id', service_row.id, 'name', service_row.name, 'role', service_row.binding_role)
        ORDER BY lower(service_row.name), service_row.id, service_row.binding_role
    ),
    '[]'::jsonb
) AS services
FROM (
    SELECT DISTINCT service.id::text AS id, service.name, binding.binding_role
    FROM service_asset_bindings AS binding
    JOIN services AS service
      ON service.tenant_id = binding.tenant_id
     AND service.workspace_id = binding.workspace_id
     AND service.id = binding.service_id
    WHERE binding.tenant_id = a.tenant_id
      AND binding.workspace_id = a.workspace_id
      AND binding.environment_id = a.environment_id
      AND binding.asset_id = a.id
      AND binding.status = 'ACTIVE'
) AS service_row`

const getAssetReadModelSQL = `
SELECT ` + assetColumns + `,
       source.id::text,
       source.name,
       source.source_kind,
       service_refs.services,
       observation.field_provenance,
       (
           SELECT count(*)::bigint
           FROM asset_relationships AS relationship
           WHERE relationship.tenant_id = a.tenant_id
             AND relationship.workspace_id = a.workspace_id
             AND relationship.target_environment_id = a.environment_id
             AND relationship.target_asset_id = a.id
             AND relationship.status = 'ACTIVE'
       ) AS incoming_relations,
       (
           SELECT count(*)::bigint
           FROM asset_relationships AS relationship
           WHERE relationship.tenant_id = a.tenant_id
             AND relationship.workspace_id = a.workspace_id
             AND relationship.source_environment_id = a.environment_id
             AND relationship.source_asset_id = a.id
             AND relationship.status = 'ACTIVE'
       ) AS outgoing_relations
FROM assets AS a
JOIN asset_sources AS source
  ON source.tenant_id = a.tenant_id
 AND source.workspace_id = a.workspace_id
 AND source.id = a.source_id
JOIN asset_observations AS observation
  ON observation.tenant_id = a.tenant_id
 AND observation.workspace_id = a.workspace_id
 AND observation.environment_id = a.environment_id
 AND observation.id = a.last_observation_id
LEFT JOIN LATERAL (` + activeServiceReferencesSQL + `) AS service_refs ON true
WHERE a.tenant_id = $1::uuid
  AND a.workspace_id = $2::uuid
  AND a.environment_id = $3::uuid
  AND a.id = $4::uuid
  AND (
      $5::boolean OR EXISTS (
          SELECT 1
          FROM service_asset_bindings AS access_binding
          WHERE access_binding.tenant_id = a.tenant_id
            AND access_binding.workspace_id = a.workspace_id
            AND access_binding.environment_id = a.environment_id
            AND access_binding.asset_id = a.id
            AND access_binding.service_id = ANY($6::uuid[])
            AND access_binding.status = 'ACTIVE'
      )
  )
`

const manualCreateEligibilitySQL = `
SELECT EXISTS (
    SELECT 1
    FROM asset_sources AS eligible_source
    JOIN asset_source_revisions AS eligible_revision
      ON eligible_revision.tenant_id = eligible_source.tenant_id
     AND eligible_revision.workspace_id = eligible_source.workspace_id
     AND eligible_revision.source_id = eligible_source.id
     AND eligible_revision.revision = eligible_source.published_revision
    WHERE eligible_source.tenant_id = $1::uuid
      AND eligible_source.workspace_id = $2::uuid
      AND eligible_source.source_kind = 'MANUAL'
      AND eligible_source.provider_kind = 'MANUAL_V1'
      AND eligible_source.status = 'ACTIVE'
      AND eligible_source.gate_status = 'AVAILABLE'
      AND eligible_source.gate_reason_code IS NULL
      AND eligible_source.gate_revision > 0
      AND eligible_source.published_revision > 0
      AND eligible_source.published_revision_digest = eligible_revision.canonical_revision_digest
      AND eligible_source.validated_run_id = eligible_revision.validation_run_id
      AND eligible_source.validation_digest = eligible_revision.validation_digest
      AND eligible_source.validated_binding_digest = eligible_revision.canonical_revision_digest
      AND eligible_source.checkpoint_revision = eligible_source.published_revision
      AND eligible_source.checkpoint_ciphertext IS NULL
      AND eligible_source.checkpoint_key_id IS NULL
      AND eligible_source.checkpoint_sha256 IS NULL
      AND eligible_revision.state = 'PUBLISHED'
      AND eligible_revision.canonical_profile_manifest = $17::bytea
      AND eligible_revision.profile_manifest_sha256 = $18::text
      AND eligible_revision.canonical_provider_schema = $19::bytea
      AND eligible_revision.canonical_provider_schema_sha256 = $20::text
      AND eligible_revision.integration_id IS NULL
      AND eligible_revision.sync_mode = 'MANUAL'
      AND eligible_revision.credential_reference_id IS NULL
      AND eligible_revision.trust_reference_id IS NULL
      AND eligible_revision.network_policy_reference_id IS NULL
      AND eligible_revision.rate_limit_requests = 1
      AND eligible_revision.rate_limit_window_seconds = 1
      AND eligible_revision.backpressure_base_seconds = 1
      AND eligible_revision.backpressure_max_seconds = 1
      AND eligible_revision.profile_code = 'MANUAL_V1'
      AND eligible_revision.schedule_expression IS NULL
      AND eligible_revision.typed_extension_code IS NULL
      AND eligible_revision.prepared_extension_digest IS NULL
      AND eligible_revision.source_definition_digest = $21::text
      AND eligible_revision.canonical_revision_digest = asset_catalog_source_revision_binding_digest(eligible_revision)
      AND eligible_revision.authority_scope_digest = encode(sha256(
            asset_catalog_framed_value_v1(convert_to('asset-source-authority-scope.v1', 'UTF8')) ||
            asset_catalog_framed_value_v1(convert_to('1', 'UTF8')) ||
            asset_catalog_framed_value_v1(convert_to($3::text, 'UTF8'))
          ), 'hex')
      AND (
          SELECT count(*)
          FROM asset_source_revision_authorities AS authority
          WHERE authority.tenant_id = eligible_revision.tenant_id
            AND authority.workspace_id = eligible_revision.workspace_id
            AND authority.source_id = eligible_revision.source_id
            AND authority.source_revision = eligible_revision.revision
      ) = 1
      AND EXISTS (
          SELECT 1
          FROM asset_source_revision_authorities AS authority
          WHERE authority.tenant_id = eligible_revision.tenant_id
            AND authority.workspace_id = eligible_revision.workspace_id
            AND authority.source_id = eligible_revision.source_id
            AND authority.source_revision = eligible_revision.revision
            AND authority.environment_id = $3::uuid
            AND authority.canonical_ordinal = 1
      )
) AS manual_create_eligible`

const listAssetReadModelsPrefixSQL = `
WITH manual_eligibility AS (` + manualCreateEligibilitySQL + `),
page_rows AS (
    SELECT a.id::text AS id,
           a.tenant_id::text AS tenant_id,
           a.workspace_id::text AS workspace_id,
           a.environment_id::text AS environment_id,
           a.source_id::text AS source_id,
           a.kind,
           a.provider_kind,
           a.external_id,
           a.display_name,
           a.lifecycle,
           a.mapping_status,
           a.owner_group,
           a.criticality,
           a.data_classification,
           a.labels,
           a.last_observation_id::text AS last_observation_id,
           a.last_observation_chain_sha256,
           a.last_observed_at,
           a.last_source_revision,
           a.version,
           a.created_at,
           a.updated_at,
           source.name AS source_name,
           source.source_kind,
           service_refs.services
    FROM assets AS a
    JOIN asset_sources AS source
      ON source.tenant_id = a.tenant_id
     AND source.workspace_id = a.workspace_id
     AND source.id = a.source_id
    LEFT JOIN LATERAL (` + activeServiceReferencesSQL + `) AS service_refs ON true
    WHERE a.tenant_id = $1::uuid
      AND a.workspace_id = $2::uuid
      AND a.environment_id = $3::uuid
      AND ($4::text = '' OR lower(a.display_name) LIKE $4::text ESCAPE '\')
      AND ($5::text[] IS NULL OR a.kind = ANY($5::text[]))
      AND ($6::uuid[] IS NULL OR a.source_id = ANY($6::uuid[]))
      AND ($7::text[] IS NULL OR a.lifecycle = ANY($7::text[]))
      AND ($8::text[] IS NULL OR a.mapping_status = ANY($8::text[]))
      AND ($9::uuid IS NULL OR EXISTS (
          SELECT 1
          FROM service_asset_bindings AS filter_binding
          WHERE filter_binding.tenant_id = a.tenant_id
            AND filter_binding.workspace_id = a.workspace_id
            AND filter_binding.environment_id = a.environment_id
            AND filter_binding.asset_id = a.id
            AND filter_binding.service_id = $9::uuid
            AND filter_binding.status = 'ACTIVE'
      ))
      AND ($10::text[] IS NULL OR a.criticality = ANY($10::text[]))
      AND ($11::text[] IS NULL OR a.data_classification = ANY($11::text[]))
      AND ($12::boolean OR EXISTS (
          SELECT 1
          FROM service_asset_bindings AS access_binding
          WHERE access_binding.tenant_id = a.tenant_id
            AND access_binding.workspace_id = a.workspace_id
            AND access_binding.environment_id = a.environment_id
            AND access_binding.asset_id = a.id
            AND access_binding.service_id = ANY($13::uuid[])
            AND access_binding.status = 'ACTIVE'
      ))
`

const listAssetReadModelsSuffixSQL = `
)
SELECT eligibility.manual_create_eligible,
       COALESCE(jsonb_agg(to_jsonb(page_rows) ORDER BY `

const listAssetReadModelsEndSQL = `) FILTER (WHERE page_rows.id IS NOT NULL), '[]'::jsonb)
FROM manual_eligibility AS eligibility
LEFT JOIN page_rows ON true
GROUP BY eligibility.manual_create_eligible
`

const listAssetReadModelsSQL = listAssetReadModelsPrefixSQL + `
      AND ($14::text IS NULL OR (lower(a.display_name), a.id) > ($14::text, $15::uuid))
    ORDER BY lower(a.display_name), a.id
    LIMIT $16
` + listAssetReadModelsSuffixSQL + `lower(page_rows.display_name), page_rows.id` + listAssetReadModelsEndSQL

const listAssetReadModelsLastObservedSQL = listAssetReadModelsPrefixSQL + `
      AND ($14::timestamptz IS NULL OR (a.last_observed_at, a.id) < ($14::timestamptz, $15::uuid))
    ORDER BY a.last_observed_at DESC, a.id DESC
    LIMIT $16
` + listAssetReadModelsSuffixSQL + `page_rows.last_observed_at DESC, page_rows.id DESC` + listAssetReadModelsEndSQL

type serviceReferenceJSON struct {
	ID   string                   `json:"id"`
	Name string                   `json:"name"`
	Role assetcatalog.BindingRole `json:"role"`
}

type provenanceJSON struct {
	Confidence       int                         `json:"confidence"`
	ObservedAt       string                      `json:"observed_at"`
	Ownership        assetcatalog.FieldOwnership `json:"ownership"`
	ProviderKind     string                      `json:"provider_kind"`
	ProviderPathCode string                      `json:"provider_path_code"`
	SourceID         string                      `json:"source_id"`
	SourceRevision   int64                       `json:"source_revision"`
}

var safeProvenanceFieldCodes = map[string]struct{}{
	"provider_kind": {}, "external_id": {}, "kind": {}, "display_name": {}, "owner_group": {},
	"criticality": {}, "data_classification": {}, "labels": {}, "environment_id": {},
	"lifecycle": {}, "mapping_status": {}, "type_details": {},
}

type assetPageProjection struct {
	ID                         string                          `json:"id"`
	TenantID                   string                          `json:"tenant_id"`
	WorkspaceID                string                          `json:"workspace_id"`
	EnvironmentID              string                          `json:"environment_id"`
	SourceID                   string                          `json:"source_id"`
	Kind                       assetcatalog.Kind               `json:"kind"`
	ProviderKind               string                          `json:"provider_kind"`
	ExternalID                 string                          `json:"external_id"`
	DisplayName                string                          `json:"display_name"`
	Lifecycle                  assetcatalog.Lifecycle          `json:"lifecycle"`
	MappingStatus              string                          `json:"mapping_status"`
	OwnerGroup                 *string                         `json:"owner_group"`
	Criticality                assetcatalog.Criticality        `json:"criticality"`
	DataClassification         assetcatalog.DataClassification `json:"data_classification"`
	Labels                     map[string]string               `json:"labels"`
	LastObservationID          string                          `json:"last_observation_id"`
	LastObservationChainSHA256 string                          `json:"last_observation_chain_sha256"`
	LastObservedAt             time.Time                       `json:"last_observed_at"`
	LastSourceRevision         int64                           `json:"last_source_revision"`
	Version                    int64                           `json:"version"`
	CreatedAt                  time.Time                       `json:"created_at"`
	UpdatedAt                  time.Time                       `json:"updated_at"`
	SourceName                 string                          `json:"source_name"`
	SourceKind                 assetcatalog.SourceKind         `json:"source_kind"`
	Services                   []serviceReferenceJSON          `json:"services"`
}

func (repository *Repository) GetReadModel(
	ctx context.Context,
	locator assetcatalog.AssetLocator,
	access assetcatalog.AssetReadConstraint,
) (assetcatalog.AssetDetailReadModel, error) {
	if !locator.Scope.Valid() || !validUUID(locator.AssetID) || access.Validate() != nil {
		return assetcatalog.AssetDetailReadModel{}, assetcatalog.ErrInvalidRequest
	}
	model, err := scanAssetDetailReadModel(repository.pool.QueryRow(
		ctx,
		getAssetReadModelSQL,
		locator.Scope.TenantID,
		locator.Scope.WorkspaceID,
		locator.Scope.EnvironmentID,
		locator.AssetID,
		access.Unrestricted(),
		access.ServiceIDs(),
	))
	if err != nil {
		return assetcatalog.AssetDetailReadModel{}, mapPGError(err)
	}
	return model.Clone(), nil
}

func (repository *Repository) List(
	ctx context.Context,
	request assetcatalog.ListAssetsRequest,
) (assetcatalog.AssetPage, error) {
	request = request.Clone()
	digest, err := request.QueryDigest()
	if err != nil {
		return assetcatalog.AssetPage{}, assetcatalog.ErrInvalidRequest
	}
	profile := assetcatalog.ManualProfileV1()
	expectedDefinition, err := manualSourceDefinitionDigest(profile)
	if err != nil {
		return assetcatalog.AssetPage{}, assetcatalog.ErrStateConflict
	}
	query, cursorValue, cursorID, err := listQueryAndCursor(request)
	if err != nil {
		return assetcatalog.AssetPage{}, err
	}
	arguments := []any{
		request.Scope.TenantID,
		request.Scope.WorkspaceID,
		request.Scope.EnvironmentID,
		escapedSearch(request.Filter.Search),
		stringsOrNil(request.Filter.Kinds),
		stringsOrNil(request.Filter.SourceIDs),
		stringsOrNil(request.Filter.Lifecycles),
		stringsOrNil(request.Filter.MappingStatuses),
		uuidOrNil(request.Filter.ServiceID),
		stringsOrNil(request.Filter.Criticalities),
		stringsOrNil(request.Filter.DataClassifications),
		request.Access.Unrestricted(),
		request.Access.ServiceIDs(),
		cursorValue,
		cursorID,
		request.Limit + 1,
		profile.CanonicalProfileManifest,
		profile.ProfileManifestSHA256,
		profile.CanonicalProviderSchema,
		profile.CanonicalProviderSchemaSHA256,
		expectedDefinition,
	}
	var (
		eligible bool
		pageJSON []byte
	)
	if err := repository.pool.QueryRow(ctx, query, arguments...).Scan(&eligible, &pageJSON); err != nil {
		return assetcatalog.AssetPage{}, mapPGError(err)
	}
	items, err := decodeAssetPage(pageJSON)
	if err != nil {
		return assetcatalog.AssetPage{}, assetcatalog.ErrStateConflict
	}
	page := assetcatalog.AssetPage{Items: items, ManualCreateEligible: eligible}
	if len(page.Items) > request.Limit {
		page.Items = page.Items[:request.Limit]
		last := page.Items[len(page.Items)-1]
		cursor := assetcatalog.AssetCursor{Sort: request.Sort, QueryDigest: digest, AssetID: last.ID}
		switch request.Sort {
		case assetcatalog.AssetSortDisplayNameAsc:
			cursor.Value = strings.ToLower(last.DisplayName)
		case assetcatalog.AssetSortLastObservedDesc:
			cursor.Value = last.LastObservedAt.UTC().Format(time.RFC3339Nano)
		default:
			return assetcatalog.AssetPage{}, assetcatalog.ErrInvalidRequest
		}
		page.Next = &cursor
	}
	return page.Clone(), nil
}

func scanAssetDetailReadModel(row rowScanner) (assetcatalog.AssetDetailReadModel, error) {
	var (
		target         assetScanTarget
		source         assetcatalog.AssetSourceReference
		servicesJSON   []byte
		provenanceJSON []byte
		relations      assetcatalog.AssetRelationCounts
	)
	destinations := target.destinations()
	destinations = append(destinations,
		&source.ID,
		&source.Name,
		&source.Kind,
		&servicesJSON,
		&provenanceJSON,
		&relations.Incoming,
		&relations.Outgoing,
	)
	if err := row.Scan(destinations...); err != nil {
		return assetcatalog.AssetDetailReadModel{}, err
	}
	asset, err := target.finish()
	if err != nil || source.ID != asset.SourceID || !source.Kind.Valid() {
		return assetcatalog.AssetDetailReadModel{}, assetcatalog.ErrStateConflict
	}
	services, err := decodeServiceReferences(servicesJSON)
	if err != nil {
		return assetcatalog.AssetDetailReadModel{}, assetcatalog.ErrStateConflict
	}
	provenance, err := decodeFieldProvenance(provenanceJSON, asset)
	if err != nil || relations.Incoming < 0 || relations.Outgoing < 0 {
		return assetcatalog.AssetDetailReadModel{}, assetcatalog.ErrStateConflict
	}
	return assetcatalog.AssetDetailReadModel{
		AssetReadModel: assetcatalog.AssetReadModel{
			Asset:      asset,
			Source:     source,
			Services:   services,
			Connection: assetcatalog.ConnectionSummary{Status: assetcatalog.OperationalSummaryNotConfigured},
			Capability: assetcatalog.CapabilitySummary{Status: assetcatalog.OperationalSummaryNotConfigured, Count: 0},
		},
		FieldProvenance: provenance,
		Relations:       relations,
	}, nil
}

func decodeServiceReferences(value []byte) ([]assetcatalog.AssetServiceReference, error) {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	var wire []serviceReferenceJSON
	if err := decoder.Decode(&wire); err != nil {
		return nil, err
	}
	result := make([]assetcatalog.AssetServiceReference, 0, len(wire))
	for _, item := range wire {
		if !validUUID(item.ID) || item.Name == "" || !item.Role.Valid() {
			return nil, assetcatalog.ErrStateConflict
		}
		result = append(result, assetcatalog.AssetServiceReference{ID: item.ID, Name: item.Name, Role: item.Role})
	}
	return result, nil
}

func decodeFieldProvenance(value []byte, asset assetcatalog.Asset) ([]assetcatalog.FieldProvenanceSummary, error) {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	var wire map[string]provenanceJSON
	if err := decoder.Decode(&wire); err != nil {
		return nil, err
	}
	fieldCodes := make([]string, 0, len(wire))
	for fieldCode := range wire {
		fieldCodes = append(fieldCodes, fieldCode)
	}
	sort.Strings(fieldCodes)
	result := make([]assetcatalog.FieldProvenanceSummary, 0, len(fieldCodes))
	for _, fieldCode := range fieldCodes {
		item := wire[fieldCode]
		observedAt, err := time.Parse("2006-01-02T15:04:05.000000Z", item.ObservedAt)
		_, fieldAllowed := safeProvenanceFieldCodes[fieldCode]
		if err != nil || !fieldAllowed || !validProjectionCode(item.ProviderPathCode) ||
			item.SourceID != asset.SourceID || item.ProviderKind != asset.ProviderKind ||
			item.SourceRevision != asset.LastSourceRevision || observedAt != asset.LastObservedAt ||
			item.Confidence < 0 || item.Confidence > 100 || !item.Ownership.Valid() {
			return nil, assetcatalog.ErrStateConflict
		}
		result = append(result, assetcatalog.FieldProvenanceSummary{
			FieldCode: fieldCode, SourceID: item.SourceID, ProviderKind: item.ProviderKind,
			SourceRevision: item.SourceRevision, ObservedAt: observedAt,
			ProviderPathCode: item.ProviderPathCode, Confidence: item.Confidence, Ownership: item.Ownership,
		})
	}
	return result, nil
}

func decodeAssetPage(value []byte) ([]assetcatalog.AssetReadModel, error) {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	var projections []assetPageProjection
	if err := decoder.Decode(&projections); err != nil {
		return nil, err
	}
	items := make([]assetcatalog.AssetReadModel, 0, len(projections))
	for _, projection := range projections {
		asset := assetcatalog.Asset{
			ID: projection.ID,
			Scope: assetcatalog.Scope{
				TenantID: projection.TenantID, WorkspaceID: projection.WorkspaceID, EnvironmentID: projection.EnvironmentID,
			},
			SourceID: projection.SourceID, Kind: projection.Kind, ProviderKind: projection.ProviderKind,
			ExternalID: projection.ExternalID, DisplayName: projection.DisplayName,
			Lifecycle: projection.Lifecycle, MappingStatus: domainMappingStatus(projection.MappingStatus),
			OwnerGroup: projection.OwnerGroup, Criticality: projection.Criticality,
			DataClassification: projection.DataClassification, Labels: projection.Labels,
			LastObservationID:          projection.LastObservationID,
			LastObservationChainSHA256: projection.LastObservationChainSHA256,
			LastObservedAt:             canonicalDatabaseTime(projection.LastObservedAt),
			LastSourceRevision:         projection.LastSourceRevision, Version: projection.Version,
			CreatedAt: canonicalDatabaseTime(projection.CreatedAt), UpdatedAt: canonicalDatabaseTime(projection.UpdatedAt),
		}
		if err := asset.Validate(); err != nil || !projection.SourceKind.Valid() {
			return nil, assetcatalog.ErrStateConflict
		}
		services := make([]assetcatalog.AssetServiceReference, 0, len(projection.Services))
		for _, item := range projection.Services {
			if !validUUID(item.ID) || item.Name == "" || !item.Role.Valid() {
				return nil, assetcatalog.ErrStateConflict
			}
			services = append(services, assetcatalog.AssetServiceReference{ID: item.ID, Name: item.Name, Role: item.Role})
		}
		items = append(items, assetcatalog.AssetReadModel{
			Asset: asset,
			Source: assetcatalog.AssetSourceReference{
				ID: asset.SourceID, Name: projection.SourceName, Kind: projection.SourceKind,
			},
			Services:   services,
			Connection: assetcatalog.ConnectionSummary{Status: assetcatalog.OperationalSummaryNotConfigured},
			Capability: assetcatalog.CapabilitySummary{Status: assetcatalog.OperationalSummaryNotConfigured, Count: 0},
		})
	}
	return items, nil
}

func manualSourceDefinitionDigest(profile assetcatalog.BuiltinSourceProfile) (string, error) {
	return assetcatalog.SourceDefinitionDigest(
		assetcatalog.Source{Kind: profile.SourceKind, ProviderKind: profile.ProviderKind},
		assetcatalog.SourceRevision{
			CanonicalProfileManifest: profile.CanonicalProfileManifest,
			CanonicalProviderSchema:  profile.CanonicalProviderSchema,
			ProfileCode:              profile.ProfileCode,
			IntegrationID:            profile.IntegrationID,
			SyncMode:                 profile.SyncMode,
			RateLimitRequests:        profile.RateLimitRequests,
			RateLimitWindowSeconds:   profile.RateLimitWindowSeconds,
			BackpressureBaseSeconds:  profile.BackpressureBaseSeconds,
			BackpressureMaxSeconds:   profile.BackpressureMaxSeconds,
			CredentialReferenceID:    profile.CredentialReferenceID,
			TrustReferenceID:         profile.TrustReferenceID,
			NetworkPolicyReferenceID: profile.NetworkPolicyReferenceID,
			ScheduleExpression:       profile.ScheduleExpression,
			TypedExtensionCode:       profile.TypedExtensionCode,
			PreparedExtensionDigest:  profile.PreparedExtensionDigest,
		},
	)
}

func listQueryAndCursor(request assetcatalog.ListAssetsRequest) (string, any, any, error) {
	var cursorID any
	if request.Cursor != nil {
		cursorID = request.Cursor.AssetID
	}
	switch request.Sort {
	case assetcatalog.AssetSortDisplayNameAsc:
		if request.Cursor == nil {
			return listAssetReadModelsSQL, nil, nil, nil
		}
		return listAssetReadModelsSQL, request.Cursor.Value, cursorID, nil
	case assetcatalog.AssetSortLastObservedDesc:
		if request.Cursor == nil {
			return listAssetReadModelsLastObservedSQL, nil, nil, nil
		}
		cursorTime, err := time.Parse(time.RFC3339Nano, request.Cursor.Value)
		if err != nil {
			return "", nil, nil, assetcatalog.ErrInvalidRequest
		}
		return listAssetReadModelsLastObservedSQL, cursorTime, cursorID, nil
	default:
		return "", nil, nil, assetcatalog.ErrInvalidRequest
	}
}

func escapedSearch(value string) string {
	if value == "" {
		return ""
	}
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + replacer.Replace(strings.ToLower(value)) + "%"
}

func stringsOrNil[T ~string](values []T) any {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

func uuidOrNil(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func validProjectionCode(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._:/@-", character) {
			continue
		}
		return false
	}
	return true
}

func domainMappingStatus(value string) domain.MappingStatus { return domain.MappingStatus(value) }
