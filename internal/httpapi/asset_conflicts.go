package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/requestmeta"
)

type conflictAssetReferenceDTO struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Kind        string `json:"kind"`
	Lifecycle   string `json:"lifecycle"`
}

type conflictServiceReferenceDTO struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type conflictObservationReferenceDTO struct {
	ID             string    `json:"id"`
	SourceID       string    `json:"source_id"`
	SourceRevision int64     `json:"source_revision"`
	ObservedAt     time.Time `json:"observed_at"`
}

type conflictImpactCountsDTO struct {
	AssetActiveBindings               int64 `json:"asset_active_bindings"`
	AssetActiveRelationships          int64 `json:"asset_active_relationships"`
	CandidateAssetActiveBindings      int64 `json:"candidate_asset_active_bindings"`
	CandidateAssetActiveRelationships int64 `json:"candidate_asset_active_relationships"`
	CandidateServiceActiveBindings    int64 `json:"candidate_service_active_bindings"`
}

type assetConflictDTO struct {
	ID                   string                          `json:"id"`
	EnvironmentID        string                          `json:"environment_id"`
	Asset                conflictAssetReferenceDTO       `json:"asset"`
	CandidateAsset       *conflictAssetReferenceDTO      `json:"candidate_asset"`
	CandidateService     *conflictServiceReferenceDTO    `json:"candidate_service"`
	SourceID             string                          `json:"source_id"`
	Observation          conflictObservationReferenceDTO `json:"observation"`
	Type                 string                          `json:"type"`
	FieldName            string                          `json:"field_name"`
	ExistingValueSHA256  string                          `json:"existing_value_sha256"`
	CandidateValueSHA256 string                          `json:"candidate_value_sha256"`
	Status               string                          `json:"status"`
	Resolution           *string                         `json:"resolution"`
	ResolutionReasonCode *string                         `json:"resolution_reason_code"`
	ResolvedAt           *time.Time                      `json:"resolved_at"`
	ImpactCounts         conflictImpactCountsDTO         `json:"impact_counts"`
	Version              int64                           `json:"version"`
	ETag                 string                          `json:"etag"`
	CreatedAt            time.Time                       `json:"created_at"`
	UpdatedAt            time.Time                       `json:"updated_at"`
	EffectiveActions     []string                        `json:"effective_actions"`
}

type assetConflictPageDTO struct {
	Items []assetConflictDTO `json:"items"`
	Page  pageMetaDTO        `json:"page"`
}

type resolveAssetConflictRequest struct {
	Resolution  string              `json:"resolution"`
	ServiceID   nullableStringInput `json:"service_id"`
	BindingRole nullableStringInput `json:"binding_role"`
	ReasonCode  string              `json:"reason_code"`
}

type assetConflictMutationResultDTO struct {
	Conflict        assetConflictDTO               `json:"conflict"`
	Binding         *serviceAssetBindingSummaryDTO `json:"binding"`
	MutationReceipt mutationReceiptDTO             `json:"mutation_receipt"`
}

func listAssetConflictsHandler(
	manager assetcatalog.ConflictManager,
	codec *ControlPlaneCursorCodec,
) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if nilHTTPDependency(manager) || codec == nil {
			writeAssetCatalogError(writer, request, errAssetCatalogUnavailable, "asset_conflict_not_found")
			return
		}
		collection, input, err := parseConflictListRequest(request, codec)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_conflict_not_found")
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeAssetCatalogError(writer, request, authn.ErrUnauthenticated, "asset_conflict_not_found")
			return
		}
		page, err := manager.ListConflicts(request.Context(), principal, collection, input)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_conflict_not_found")
			return
		}
		response := assetConflictPageDTO{
			Items: make([]assetConflictDTO, len(page.Items)), Page: pageMetaDTO{},
		}
		for index := range page.Items {
			response.Items[index] = toAssetConflictDTO(page.Items[index])
		}
		if page.Next != nil {
			encoded, err := codec.encode(controlPlaneCursor{
				Kind: "asset-conflicts", QueryDigest: page.Next.QueryDigest,
				Sort: "created_at_desc", Value: page.Next.CreatedAt.UTC().Format(time.RFC3339Nano),
				ID: page.Next.ConflictID,
			})
			if err != nil {
				writeAssetCatalogError(writer, request, err, "asset_conflict_not_found")
				return
			}
			response.Page.NextCursor = &encoded
		}
		writeJSON(writer, http.StatusOK, response)
	}
}

func resolveAssetConflictHandler(manager assetcatalog.ConflictManager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if nilHTTPDependency(manager) {
			writeAssetCatalogError(writer, request, errAssetCatalogUnavailable, "asset_conflict_not_found")
			return
		}
		path, err := conflictPathFromRequest(request)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_conflict_not_found")
			return
		}
		idempotencyKey, err := parseIdempotencyKey(request)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_conflict_not_found")
			return
		}
		version, err := parseVersionETag(request, "asset-conflict", path.ConflictID)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_conflict_not_found")
			return
		}
		var body resolveAssetConflictRequest
		if err := decodeStrictJSON(writer, request, &body, 64<<10); err != nil {
			writeAssetCatalogError(writer, request, err, "asset_conflict_not_found")
			return
		}
		input, err := body.input()
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_conflict_not_found")
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeAssetCatalogError(writer, request, authn.ErrUnauthenticated, "asset_conflict_not_found")
			return
		}
		traceID := requestmeta.From(request.Context()).TraceID
		result, err := manager.ResolveConflict(
			request.Context(), principal, path, input,
			assetcatalog.ServerRequestMetadata{
				TraceID: traceID, IdempotencyKey: idempotencyKey, ExpectedVersion: version,
			},
		)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_conflict_not_found")
			return
		}
		receipt, err := mutationReceiptFrom(result.Receipt, traceID)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_conflict_not_found")
			return
		}
		response := assetConflictMutationResultDTO{
			Conflict: toAssetConflictDTO(result.View), MutationReceipt: receipt,
		}
		if result.Binding != nil {
			binding := toServiceAssetBindingDTO(assetcatalog.BindingView{
				Binding: *result.Binding, EffectiveActions: []assetcatalog.EffectiveAction{},
			})
			response.Binding = &binding
		}
		writeVersionETag(writer, "asset-conflict", result.View.ReadModel.ID, result.View.ReadModel.Version)
		writeJSON(writer, http.StatusOK, response)
	}
}

func parseConflictListRequest(
	request *http.Request,
	codec *ControlPlaneCursorCodec,
) (assetcatalog.ConflictCollectionRequest, assetcatalog.ConflictListInput, error) {
	workspaceID := chi.URLParam(request, "workspaceID")
	if !validControlPlaneUUID(workspaceID) {
		return assetcatalog.ConflictCollectionRequest{}, assetcatalog.ConflictListInput{}, errInvalidControlPlaneRequest
	}
	values, err := parseControlPlaneQuery(
		request, "environment_id", "asset_id", "source_id", "statuses", "limit", "cursor",
	)
	if err != nil {
		return assetcatalog.ConflictCollectionRequest{}, assetcatalog.ConflictListInput{}, err
	}
	environmentID := values.Get("environment_id")
	if !validControlPlaneUUID(environmentID) {
		return assetcatalog.ConflictCollectionRequest{}, assetcatalog.ConflictListInput{}, errInvalidControlPlaneRequest
	}
	assetID, sourceID := values.Get("asset_id"), values.Get("source_id")
	if assetID != "" && !validControlPlaneUUID(assetID) ||
		sourceID != "" && !validControlPlaneUUID(sourceID) {
		return assetcatalog.ConflictCollectionRequest{}, assetcatalog.ConflictListInput{}, errInvalidControlPlaneRequest
	}
	statuses, err := parseControlPlaneStringSet(values.Get("statuses"), 3, func(value assetcatalog.ConflictStatus) bool { return value.Valid() })
	if err != nil {
		return assetcatalog.ConflictCollectionRequest{}, assetcatalog.ConflictListInput{}, err
	}
	limit, err := parseControlPlaneLimit(values)
	if err != nil {
		return assetcatalog.ConflictCollectionRequest{}, assetcatalog.ConflictListInput{}, err
	}
	input := assetcatalog.ConflictListInput{
		AssetID: assetID, SourceID: sourceID, Statuses: statuses, Limit: limit,
	}
	if encoded := values.Get("cursor"); encoded != "" {
		cursor, err := codec.decode(encoded, "asset-conflicts")
		createdAt, timeErr := time.Parse(time.RFC3339Nano, cursor.Value)
		if err != nil || cursor.Sort != "created_at_desc" || timeErr != nil ||
			createdAt.Location() != time.UTC || createdAt.Format(time.RFC3339Nano) != cursor.Value {
			return assetcatalog.ConflictCollectionRequest{}, assetcatalog.ConflictListInput{}, errInvalidControlPlaneRequest
		}
		input.Cursor = &assetcatalog.ConflictCursor{
			QueryDigest: cursor.QueryDigest, CreatedAt: createdAt, ConflictID: cursor.ID,
		}
	}
	return assetcatalog.ConflictCollectionRequest{
		WorkspaceID: workspaceID, EnvironmentID: environmentID,
	}, input, nil
}

func conflictPathFromRequest(request *http.Request) (assetcatalog.ConflictPathRequest, error) {
	workspaceID, conflictID := chi.URLParam(request, "workspaceID"), chi.URLParam(request, "conflictID")
	if !validControlPlaneUUID(workspaceID) || !validControlPlaneUUID(conflictID) {
		return assetcatalog.ConflictPathRequest{}, errInvalidControlPlaneRequest
	}
	return assetcatalog.ConflictPathRequest{WorkspaceID: workspaceID, ConflictID: conflictID}, nil
}

func (request resolveAssetConflictRequest) input() (assetcatalog.ResolveConflictInput, error) {
	resolution := assetcatalog.ConflictResolution(request.Resolution)
	if !resolution.Valid() || !validControlPlaneReasonCode(request.ReasonCode) {
		return assetcatalog.ResolveConflictInput{}, errInvalidControlPlaneRequest
	}
	result := assetcatalog.ResolveConflictInput{
		Resolution: resolution, ReasonCode: request.ReasonCode,
	}
	if resolution == assetcatalog.ConflictResolutionConfirmExact {
		if !request.ServiceID.Present || request.ServiceID.Value == nil ||
			!request.BindingRole.Present || request.BindingRole.Value == nil ||
			!validControlPlaneUUID(*request.ServiceID.Value) {
			return assetcatalog.ResolveConflictInput{}, errInvalidControlPlaneRequest
		}
		role := assetcatalog.BindingRole(*request.BindingRole.Value)
		if !role.Valid() {
			return assetcatalog.ResolveConflictInput{}, errInvalidControlPlaneRequest
		}
		result.ServiceID, result.BindingRole = *request.ServiceID.Value, role
	} else if request.ServiceID.Present || request.BindingRole.Present {
		return assetcatalog.ResolveConflictInput{}, errInvalidControlPlaneRequest
	}
	return result, nil
}

func toAssetConflictDTO(view assetcatalog.ConflictView) assetConflictDTO {
	model := view.ReadModel
	result := assetConflictDTO{
		ID: model.ID, EnvironmentID: model.Scope.EnvironmentID,
		Asset: conflictAssetReferenceDTO{
			ID: model.Asset.ID, DisplayName: model.Asset.DisplayName,
			Kind: string(model.Asset.Kind), Lifecycle: string(model.Asset.Lifecycle),
		},
		SourceID: model.SourceID,
		Observation: conflictObservationReferenceDTO{
			ID: model.Observation.ID, SourceID: model.Observation.SourceID,
			SourceRevision: model.Observation.SourceRevision, ObservedAt: model.Observation.ObservedAt.UTC(),
		},
		Type: model.Type, FieldName: model.FieldName,
		ExistingValueSHA256:  model.ExistingValueSHA256,
		CandidateValueSHA256: model.CandidateValueSHA256,
		Status:               string(model.Status), Resolution: optionalString(string(model.Resolution)),
		ResolutionReasonCode: optionalString(model.ResolutionReasonCode),
		ResolvedAt:           cloneTimePointer(model.ResolvedAt),
		ImpactCounts: conflictImpactCountsDTO{
			AssetActiveBindings:               model.Impact.AssetActiveBindings,
			AssetActiveRelationships:          model.Impact.AssetActiveRelationships,
			CandidateAssetActiveBindings:      model.Impact.CandidateAssetActiveBindings,
			CandidateAssetActiveRelationships: model.Impact.CandidateAssetActiveRelationships,
			CandidateServiceActiveBindings:    model.Impact.CandidateServiceActiveBindings,
		},
		Version:   model.Version,
		ETag:      `"asset-conflict:` + model.ID + `:v` + formatPositiveVersion(model.Version) + `"`,
		CreatedAt: model.CreatedAt.UTC(), UpdatedAt: model.UpdatedAt.UTC(),
		EffectiveActions: effectiveActionStrings(view.EffectiveActions),
	}
	if model.CandidateAsset != nil {
		result.CandidateAsset = &conflictAssetReferenceDTO{
			ID: model.CandidateAsset.ID, DisplayName: model.CandidateAsset.DisplayName,
			Kind: string(model.CandidateAsset.Kind), Lifecycle: string(model.CandidateAsset.Lifecycle),
		}
	}
	if model.CandidateService != nil {
		result.CandidateService = &conflictServiceReferenceDTO{
			ID: model.CandidateService.ID, Name: model.CandidateService.Name,
		}
	}
	return result
}
