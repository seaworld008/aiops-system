package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/authz"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/requestmeta"
)

var errAssetCatalogUnavailable = errors.New("asset catalog unavailable")

type pageMetaDTO struct {
	NextCursor *string `json:"next_cursor"`
}

type labelDTO struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type sourceReferenceDTO struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type serviceReferenceDTO struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
}

type connectionSummaryDTO struct {
	Status string `json:"status"`
}

type capabilitySummaryDTO struct {
	Status string `json:"status"`
	Count  int64  `json:"count"`
}

type assetSummaryDTO struct {
	ID                 string                `json:"id"`
	EnvironmentID      string                `json:"environment_id"`
	DisplayName        string                `json:"display_name"`
	ExternalID         string                `json:"external_id"`
	Kind               string                `json:"kind"`
	ProviderKind       string                `json:"provider_kind"`
	Source             sourceReferenceDTO    `json:"source"`
	Services           []serviceReferenceDTO `json:"service_summaries"`
	MappingStatus      string                `json:"mapping_status"`
	Lifecycle          string                `json:"lifecycle"`
	OwnerGroup         *string               `json:"owner_group"`
	Criticality        string                `json:"criticality"`
	DataClassification string                `json:"data_classification"`
	Labels             []labelDTO            `json:"labels"`
	ConnectionSummary  connectionSummaryDTO  `json:"connection_summary"`
	CapabilitySummary  capabilitySummaryDTO  `json:"capability_summary"`
	LastObservedAt     time.Time             `json:"last_observed_at"`
	Version            int64                 `json:"version"`
	EffectiveActions   []string              `json:"effective_actions"`
}

type fieldProvenanceDTO struct {
	FieldCode        string    `json:"field_code"`
	SourceID         string    `json:"source_id"`
	ProviderKind     string    `json:"provider_kind"`
	SourceRevision   int64     `json:"source_revision"`
	ObservedAt       time.Time `json:"observed_at"`
	ProviderPathCode string    `json:"provider_path_code"`
	Confidence       int       `json:"confidence"`
	Ownership        string    `json:"ownership"`
}

type relationCountsDTO struct {
	Incoming int64 `json:"incoming"`
	Outgoing int64 `json:"outgoing"`
}

type assetDetailDTO struct {
	assetSummaryDTO
	FieldProvenance []fieldProvenanceDTO `json:"field_provenance"`
	RelationCounts  relationCountsDTO    `json:"relation_counts"`
}

type assetPageDTO struct {
	Items            []assetSummaryDTO `json:"items"`
	Page             pageMetaDTO       `json:"page"`
	EffectiveActions []string          `json:"effective_actions"`
}

type mutationReceiptDTO struct {
	AuditID          string `json:"audit_id"`
	TraceID          string `json:"trace_id"`
	IdempotentReplay bool   `json:"idempotent_replay"`
}

type assetMutationResultDTO struct {
	Asset           assetDetailDTO     `json:"asset"`
	MutationReceipt mutationReceiptDTO `json:"mutation_receipt"`
}

type nullableStringInput struct {
	Present bool
	Value   *string
}

func (value *nullableStringInput) UnmarshalJSON(raw []byte) error {
	value.Present = true
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		value.Value = nil
		return nil
	}
	var decoded string
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	value.Value = &decoded
	return nil
}

type createAssetRequest struct {
	SourceID           string              `json:"source_id"`
	Kind               string              `json:"kind"`
	ExternalID         string              `json:"external_id"`
	DisplayName        string              `json:"display_name"`
	OwnerGroup         nullableStringInput `json:"owner_group"`
	Criticality        string              `json:"criticality"`
	DataClassification string              `json:"data_classification"`
	Labels             []labelDTO          `json:"labels"`
}

type patchAssetRequest struct {
	DisplayName        string              `json:"display_name"`
	OwnerGroup         nullableStringInput `json:"owner_group"`
	Criticality        string              `json:"criticality"`
	DataClassification string              `json:"data_classification"`
	Labels             []labelDTO          `json:"labels"`
}

type transitionAssetRequest struct {
	ReasonCode string `json:"reason_code"`
}

func listAssetsHandler(
	manager assetcatalog.AssetManager,
	codec *ControlPlaneCursorCodec,
) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if nilHTTPDependency(manager) || codec == nil {
			writeAssetCatalogError(writer, request, errAssetCatalogUnavailable, "asset_not_found")
			return
		}
		collection, err := assetCollectionFromRequest(request)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_not_found")
			return
		}
		input, err := parseAssetListInput(request, codec)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_not_found")
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeAssetCatalogError(writer, request, authn.ErrUnauthenticated, "asset_not_found")
			return
		}
		page, err := manager.ListAssets(request.Context(), principal, collection, input)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_not_found")
			return
		}
		response := assetPageDTO{
			Items:            make([]assetSummaryDTO, len(page.Items)),
			Page:             pageMetaDTO{},
			EffectiveActions: effectiveActionStrings(page.EffectiveActions),
		}
		for index := range page.Items {
			response.Items[index] = toAssetSummaryDTO(page.Items[index])
		}
		if page.Next != nil {
			encoded, err := encodeAssetCursor(codec, *page.Next)
			if err != nil {
				writeAssetCatalogError(writer, request, err, "asset_not_found")
				return
			}
			response.Page.NextCursor = &encoded
		}
		writeJSON(writer, http.StatusOK, response)
	}
}

func getAssetHandler(manager assetcatalog.AssetManager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if nilHTTPDependency(manager) {
			writeAssetCatalogError(writer, request, errAssetCatalogUnavailable, "asset_not_found")
			return
		}
		path, err := assetPathFromRequest(request)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_not_found")
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeAssetCatalogError(writer, request, authn.ErrUnauthenticated, "asset_not_found")
			return
		}
		view, err := manager.GetAsset(request.Context(), principal, path)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_not_found")
			return
		}
		writeVersionETag(writer, "asset", view.ReadModel.ID, view.ReadModel.Version)
		writeJSON(writer, http.StatusOK, toAssetDetailDTO(view))
	}
}

func createAssetHandler(manager assetcatalog.AssetManager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if nilHTTPDependency(manager) {
			writeAssetCatalogError(writer, request, errAssetCatalogUnavailable, "asset_not_found")
			return
		}
		collection, err := assetCollectionFromRequest(request)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_not_found")
			return
		}
		idempotencyKey, err := parseIdempotencyKey(request)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_not_found")
			return
		}
		var body createAssetRequest
		if err := decodeStrictJSON(writer, request, &body, 64<<10); err != nil {
			writeAssetCatalogError(writer, request, err, "asset_not_found")
			return
		}
		input, err := body.input()
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_not_found")
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeAssetCatalogError(writer, request, authn.ErrUnauthenticated, "asset_not_found")
			return
		}
		metadata := assetcatalog.ServerRequestMetadata{
			TraceID: requestmeta.From(request.Context()).TraceID, IdempotencyKey: idempotencyKey,
		}
		result, err := manager.CreateAsset(request.Context(), principal, collection, input, metadata)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_not_found")
			return
		}
		response, err := assetMutationDTO(result, metadata.TraceID)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_not_found")
			return
		}
		writer.Header().Set("Location", request.URL.Path+"/"+result.View.ReadModel.ID)
		writeVersionETag(writer, "asset", result.View.ReadModel.ID, result.View.ReadModel.Version)
		writeJSON(writer, http.StatusCreated, response)
	}
}

func patchAssetHandler(manager assetcatalog.AssetManager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		path, metadata, principal, ok := prepareAssetVersionedMutation(writer, request, manager)
		if !ok {
			return
		}
		var body patchAssetRequest
		if err := decodeStrictJSON(writer, request, &body, 64<<10); err != nil {
			writeAssetCatalogError(writer, request, err, "asset_not_found")
			return
		}
		input, err := body.input()
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_not_found")
			return
		}
		result, err := manager.UpdateAsset(request.Context(), principal, path, input, metadata)
		writeAssetMutationResponse(writer, request, result, err)
	}
}

func quarantineAssetHandler(manager assetcatalog.AssetManager) http.HandlerFunc {
	return transitionAssetHandler(manager, func(
		ctx context.Context,
		principal authn.Principal,
		path assetcatalog.AssetPathRequest,
		input assetcatalog.TransitionInput,
		metadata assetcatalog.ServerRequestMetadata,
	) (assetcatalog.AssetMutationView, error) {
		return manager.QuarantineAsset(ctx, principal, path, input, metadata)
	})
}

func retireAssetHandler(manager assetcatalog.AssetManager) http.HandlerFunc {
	return transitionAssetHandler(manager, func(
		ctx context.Context,
		principal authn.Principal,
		path assetcatalog.AssetPathRequest,
		input assetcatalog.TransitionInput,
		metadata assetcatalog.ServerRequestMetadata,
	) (assetcatalog.AssetMutationView, error) {
		return manager.RetireAsset(ctx, principal, path, input, metadata)
	})
}

func transitionAssetHandler(
	manager assetcatalog.AssetManager,
	transition func(
		context.Context,
		authn.Principal,
		assetcatalog.AssetPathRequest,
		assetcatalog.TransitionInput,
		assetcatalog.ServerRequestMetadata,
	) (assetcatalog.AssetMutationView, error),
) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		path, metadata, principal, ok := prepareAssetVersionedMutation(writer, request, manager)
		if !ok {
			return
		}
		var body transitionAssetRequest
		if err := decodeStrictJSON(writer, request, &body, 64<<10); err != nil {
			writeAssetCatalogError(writer, request, err, "asset_not_found")
			return
		}
		if !validControlPlaneReasonCode(body.ReasonCode) {
			writeAssetCatalogError(writer, request, errInvalidControlPlaneRequest, "asset_not_found")
			return
		}
		result, err := transition(
			request.Context(), principal, path,
			assetcatalog.TransitionInput{ReasonCode: body.ReasonCode}, metadata,
		)
		writeAssetMutationResponse(writer, request, result, err)
	}
}

func prepareAssetVersionedMutation(
	writer http.ResponseWriter,
	request *http.Request,
	manager assetcatalog.AssetManager,
) (assetcatalog.AssetPathRequest, assetcatalog.ServerRequestMetadata, authn.Principal, bool) {
	if nilHTTPDependency(manager) {
		writeAssetCatalogError(writer, request, errAssetCatalogUnavailable, "asset_not_found")
		return assetcatalog.AssetPathRequest{}, assetcatalog.ServerRequestMetadata{}, authn.Principal{}, false
	}
	path, err := assetPathFromRequest(request)
	if err != nil {
		writeAssetCatalogError(writer, request, err, "asset_not_found")
		return assetcatalog.AssetPathRequest{}, assetcatalog.ServerRequestMetadata{}, authn.Principal{}, false
	}
	idempotencyKey, err := parseIdempotencyKey(request)
	if err != nil {
		writeAssetCatalogError(writer, request, err, "asset_not_found")
		return assetcatalog.AssetPathRequest{}, assetcatalog.ServerRequestMetadata{}, authn.Principal{}, false
	}
	version, err := parseVersionETag(request, "asset", path.AssetID)
	if err != nil {
		writeAssetCatalogError(writer, request, err, "asset_not_found")
		return assetcatalog.AssetPathRequest{}, assetcatalog.ServerRequestMetadata{}, authn.Principal{}, false
	}
	principal, ok := authn.PrincipalFromContext(request.Context())
	if !ok {
		writeAssetCatalogError(writer, request, authn.ErrUnauthenticated, "asset_not_found")
		return assetcatalog.AssetPathRequest{}, assetcatalog.ServerRequestMetadata{}, authn.Principal{}, false
	}
	return path, assetcatalog.ServerRequestMetadata{
		TraceID:        requestmeta.From(request.Context()).TraceID,
		IdempotencyKey: idempotencyKey, ExpectedVersion: version,
	}, principal, true
}

func writeAssetMutationResponse(
	writer http.ResponseWriter,
	request *http.Request,
	result assetcatalog.AssetMutationView,
	err error,
) {
	if err != nil {
		writeAssetCatalogError(writer, request, err, "asset_not_found")
		return
	}
	response, err := assetMutationDTO(result, requestmeta.From(request.Context()).TraceID)
	if err != nil {
		writeAssetCatalogError(writer, request, err, "asset_not_found")
		return
	}
	writeVersionETag(writer, "asset", result.View.ReadModel.ID, result.View.ReadModel.Version)
	writeJSON(writer, http.StatusOK, response)
}

func assetCollectionFromRequest(request *http.Request) (assetcatalog.AssetCollectionRequest, error) {
	result := assetcatalog.AssetCollectionRequest{
		WorkspaceID:   chi.URLParam(request, "workspaceID"),
		EnvironmentID: chi.URLParam(request, "environmentID"),
	}
	if !validControlPlaneUUID(result.WorkspaceID) || !validControlPlaneUUID(result.EnvironmentID) {
		return assetcatalog.AssetCollectionRequest{}, errInvalidControlPlaneRequest
	}
	return result, nil
}

func assetPathFromRequest(request *http.Request) (assetcatalog.AssetPathRequest, error) {
	collection, err := assetCollectionFromRequest(request)
	if err != nil {
		return assetcatalog.AssetPathRequest{}, err
	}
	assetID := chi.URLParam(request, "assetID")
	if !validControlPlaneUUID(assetID) {
		return assetcatalog.AssetPathRequest{}, errInvalidControlPlaneRequest
	}
	return assetcatalog.AssetPathRequest{
		WorkspaceID: collection.WorkspaceID, EnvironmentID: collection.EnvironmentID, AssetID: assetID,
	}, nil
}

func parseAssetListInput(
	request *http.Request,
	codec *ControlPlaneCursorCodec,
) (assetcatalog.AssetListInput, error) {
	values, err := parseControlPlaneQuery(
		request, "search", "service_id", "kinds", "source_ids", "lifecycles",
		"mapping_statuses", "criticalities", "data_classifications", "sort", "limit", "cursor",
	)
	if err != nil {
		return assetcatalog.AssetListInput{}, err
	}
	limit, err := parseControlPlaneLimit(values)
	if err != nil {
		return assetcatalog.AssetListInput{}, err
	}
	search := values.Get("search")
	if len(search) > 256 || strings.TrimSpace(search) != search {
		return assetcatalog.AssetListInput{}, errInvalidControlPlaneRequest
	}
	serviceID := values.Get("service_id")
	if serviceID != "" && !validControlPlaneUUID(serviceID) {
		return assetcatalog.AssetListInput{}, errInvalidControlPlaneRequest
	}
	kinds, err := parseControlPlaneStringSet(values.Get("kinds"), 17, func(value assetcatalog.Kind) bool { return value.Valid() })
	if err != nil {
		return assetcatalog.AssetListInput{}, err
	}
	sourceIDs, err := parseControlPlaneUUIDSet(values.Get("source_ids"), 100)
	if err != nil {
		return assetcatalog.AssetListInput{}, err
	}
	lifecycles, err := parseControlPlaneStringSet(values.Get("lifecycles"), 5, func(value assetcatalog.Lifecycle) bool { return value.Valid() })
	if err != nil {
		return assetcatalog.AssetListInput{}, err
	}
	mappings, err := parseControlPlaneStringSet(values.Get("mapping_statuses"), 3, func(value domain.MappingStatus) bool {
		return value == domain.MappingExact || value == domain.MappingAmbiguous || value == domain.MappingUnresolved
	})
	if err != nil {
		return assetcatalog.AssetListInput{}, err
	}
	criticalities, err := parseControlPlaneStringSet(values.Get("criticalities"), 4, func(value assetcatalog.Criticality) bool { return value.Valid() })
	if err != nil {
		return assetcatalog.AssetListInput{}, err
	}
	classifications, err := parseControlPlaneStringSet(values.Get("data_classifications"), 4, func(value assetcatalog.DataClassification) bool { return value.Valid() })
	if err != nil {
		return assetcatalog.AssetListInput{}, err
	}
	sortValue := assetcatalog.AssetSort(values.Get("sort"))
	if sortValue == "" {
		sortValue = assetcatalog.AssetSortDisplayNameAsc
	}
	if !sortValue.Valid() {
		return assetcatalog.AssetListInput{}, errInvalidControlPlaneRequest
	}
	input := assetcatalog.AssetListInput{
		Filter: assetcatalog.AssetFilter{
			Search: search, ServiceID: serviceID, Kinds: kinds, SourceIDs: sourceIDs,
			Lifecycles: lifecycles, MappingStatuses: mappings,
			Criticalities: criticalities, DataClassifications: classifications,
		},
		Sort: sortValue, Limit: limit,
	}
	if encoded := values.Get("cursor"); encoded != "" {
		cursor, err := codec.decode(encoded, "assets")
		if err != nil || cursor.Sort != string(sortValue) {
			return assetcatalog.AssetListInput{}, errInvalidControlPlaneRequest
		}
		input.Cursor = &assetcatalog.AssetCursor{
			Sort: sortValue, QueryDigest: cursor.QueryDigest, Value: cursor.Value, AssetID: cursor.ID,
		}
	}
	return input, nil
}

func encodeAssetCursor(codec *ControlPlaneCursorCodec, cursor assetcatalog.AssetCursor) (string, error) {
	return codec.encode(controlPlaneCursor{
		Kind: "assets", QueryDigest: cursor.QueryDigest, Sort: string(cursor.Sort),
		Value: cursor.Value, ID: cursor.AssetID,
	})
}

func (request createAssetRequest) input() (assetcatalog.CreateAssetInput, error) {
	labels, err := labelMap(request.Labels)
	kind := assetcatalog.Kind(request.Kind)
	criticality := assetcatalog.Criticality(request.Criticality)
	classification := assetcatalog.DataClassification(request.DataClassification)
	if err != nil || !request.OwnerGroup.Present || !validControlPlaneUUID(request.SourceID) ||
		!kind.Valid() ||
		!validControlPlaneSafeText(request.ExternalID, 1, 512) ||
		!validControlPlaneSafeText(request.DisplayName, 1, 256) ||
		request.OwnerGroup.Value != nil && !validControlPlaneSafeText(*request.OwnerGroup.Value, 1, 256) ||
		!criticality.Valid() || !classification.Valid() {
		return assetcatalog.CreateAssetInput{}, errInvalidControlPlaneRequest
	}
	return assetcatalog.CreateAssetInput{
		SourceID: request.SourceID, Kind: kind,
		ExternalID: request.ExternalID, DisplayName: request.DisplayName,
		OwnerGroup: request.OwnerGroup.Value, Criticality: criticality,
		DataClassification: classification, Labels: labels,
	}, nil
}

func (request patchAssetRequest) input() (assetcatalog.UpdateGovernanceInput, error) {
	labels, err := labelMap(request.Labels)
	criticality := assetcatalog.Criticality(request.Criticality)
	classification := assetcatalog.DataClassification(request.DataClassification)
	if err != nil || !request.OwnerGroup.Present ||
		!validControlPlaneSafeText(request.DisplayName, 1, 256) ||
		request.OwnerGroup.Value != nil && !validControlPlaneSafeText(*request.OwnerGroup.Value, 1, 256) ||
		!criticality.Valid() || !classification.Valid() {
		return assetcatalog.UpdateGovernanceInput{}, errInvalidControlPlaneRequest
	}
	return assetcatalog.UpdateGovernanceInput{
		DisplayName: request.DisplayName, OwnerGroup: request.OwnerGroup.Value,
		Criticality:        criticality,
		DataClassification: classification, Labels: labels,
	}, nil
}

func labelMap(labels []labelDTO) (map[string]string, error) {
	if labels == nil || len(labels) > 64 {
		return nil, errInvalidControlPlaneRequest
	}
	result := make(map[string]string, len(labels))
	for _, label := range labels {
		if !validControlPlaneLabelKey(label.Key) ||
			!validControlPlaneSafeText(label.Value, 0, 1024) {
			return nil, errInvalidControlPlaneRequest
		}
		if _, duplicate := result[label.Key]; duplicate {
			return nil, errInvalidControlPlaneRequest
		}
		result[label.Key] = label.Value
	}
	return result, nil
}

func validControlPlaneLabelKey(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			index > 0 && (character == '_' || character == '.' || character == '-') {
			continue
		}
		return false
	}
	normalized := strings.ToLower(value)
	normalized = strings.NewReplacer("-", "", "_", "", ".", "").Replace(normalized)
	for _, unsafe := range []string{"secret", "token", "password", "credential", "dsn", "endpoint"} {
		if strings.Contains(normalized, unsafe) {
			return false
		}
	}
	return true
}

func toAssetSummaryDTO(view assetcatalog.AssetSummaryView) assetSummaryDTO {
	model := view.ReadModel
	services := make([]serviceReferenceDTO, len(model.Services))
	for index := range model.Services {
		services[index] = serviceReferenceDTO{
			ID: model.Services[index].ID, Name: model.Services[index].Name, Role: string(model.Services[index].Role),
		}
	}
	return assetSummaryDTO{
		ID: model.ID, EnvironmentID: model.Scope.EnvironmentID,
		DisplayName: model.DisplayName, ExternalID: model.ExternalID,
		Kind: string(model.Kind), ProviderKind: model.ProviderKind,
		Source: sourceReferenceDTO{
			ID: model.Source.ID, Name: model.Source.Name, Kind: string(model.Source.Kind),
		},
		Services: services, MappingStatus: string(model.MappingStatus), Lifecycle: string(model.Lifecycle),
		OwnerGroup: cloneStringPointer(model.OwnerGroup), Criticality: string(model.Criticality),
		DataClassification: string(model.DataClassification), Labels: labelList(model.Labels),
		ConnectionSummary: connectionSummaryDTO{Status: string(model.Connection.Status)},
		CapabilitySummary: capabilitySummaryDTO{
			Status: string(model.Capability.Status), Count: model.Capability.Count,
		},
		LastObservedAt: model.LastObservedAt.UTC(), Version: model.Version,
		EffectiveActions: effectiveActionStrings(view.EffectiveActions),
	}
}

func toAssetDetailDTO(view assetcatalog.AssetView) assetDetailDTO {
	summary := toAssetSummaryDTO(assetcatalog.AssetSummaryView{
		ReadModel: view.ReadModel.AssetReadModel, EffectiveActions: view.EffectiveActions,
	})
	provenance := make([]fieldProvenanceDTO, len(view.ReadModel.FieldProvenance))
	for index := range view.ReadModel.FieldProvenance {
		value := view.ReadModel.FieldProvenance[index]
		provenance[index] = fieldProvenanceDTO{
			FieldCode: value.FieldCode, SourceID: value.SourceID, ProviderKind: value.ProviderKind,
			SourceRevision: value.SourceRevision, ObservedAt: value.ObservedAt.UTC(),
			ProviderPathCode: value.ProviderPathCode, Confidence: value.Confidence,
			Ownership: string(value.Ownership),
		}
	}
	return assetDetailDTO{
		assetSummaryDTO: summary, FieldProvenance: provenance,
		RelationCounts: relationCountsDTO{
			Incoming: view.ReadModel.Relations.Incoming, Outgoing: view.ReadModel.Relations.Outgoing,
		},
	}
}

func assetMutationDTO(
	result assetcatalog.AssetMutationView,
	traceID string,
) (assetMutationResultDTO, error) {
	receipt, err := mutationReceiptFrom(result.Receipt, traceID)
	if err != nil {
		return assetMutationResultDTO{}, err
	}
	return assetMutationResultDTO{
		Asset: toAssetDetailDTO(result.View), MutationReceipt: receipt,
	}, nil
}

func mutationReceiptFrom(
	receipt assetcatalog.MutationReceipt,
	traceID string,
) (mutationReceiptDTO, error) {
	if !validControlPlaneUUID(receipt.AuditID) || !validTraceID(traceID) || receipt.TraceID != traceID {
		return mutationReceiptDTO{}, errors.New("unsafe mutation receipt")
	}
	return mutationReceiptDTO{
		AuditID: receipt.AuditID, TraceID: receipt.TraceID,
		IdempotentReplay: receipt.IdempotentReplay,
	}, nil
}

func labelList(labels map[string]string) []labelDTO {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]labelDTO, 0, len(keys))
	for _, key := range keys {
		result = append(result, labelDTO{Key: key, Value: labels[key]})
	}
	return result
}

func effectiveActionStrings(actions []assetcatalog.EffectiveAction) []string {
	result := make([]string, len(actions))
	for index := range actions {
		result[index] = string(actions[index])
	}
	if result == nil {
		return []string{}
	}
	return result
}

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func writeAssetCatalogError(
	writer http.ResponseWriter,
	request *http.Request,
	err error,
	notFoundCode string,
) {
	switch {
	case errors.Is(err, errUnsupportedControlPlaneMediaType):
		writeRequestProblem(writer, request, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
	case errors.Is(err, errControlPlaneBodyTooLarge):
		writeRequestProblem(writer, request, http.StatusRequestEntityTooLarge, "payload_too_large", "Request body exceeds 64 KiB")
	case errors.Is(err, errInvalidControlPlaneRequest), errors.Is(err, assetcatalog.ErrInvalidRequest):
		writeRequestProblem(writer, request, http.StatusBadRequest, "invalid_request", "The request is invalid")
	case errors.Is(err, authn.ErrUnauthenticated):
		writeRequestProblem(writer, request, http.StatusUnauthorized, "authentication_required", "A valid OIDC bearer token is required")
	case errors.Is(err, authz.ErrReauthenticationRequired):
		writer.Header().Set("WWW-Authenticate", `Bearer error="insufficient_user_authentication"`)
		writeRequestProblem(writer, request, http.StatusUnauthorized, "reauthentication_required", "Recent OIDC authentication is required")
	case errors.Is(err, authz.ErrForbidden), errors.Is(err, assetcatalog.ErrScopeViolation):
		writeRequestProblem(writer, request, http.StatusForbidden, "asset_scope_forbidden", "The asset catalog operation is forbidden")
	case errors.Is(err, assetcatalog.ErrNotFound):
		writeRequestProblem(writer, request, http.StatusNotFound, notFoundCode, "The requested asset catalog resource was not found")
	case errors.Is(err, assetcatalog.ErrVersionConflict):
		writeRequestProblem(writer, request, http.StatusConflict, "version_conflict", "The resource version changed")
	case errors.Is(err, assetcatalog.ErrIdempotency):
		writeRequestProblem(writer, request, http.StatusConflict, "idempotency_conflict", "Idempotency-Key was reused with a different request")
	case errors.Is(err, assetcatalog.ErrStateConflict):
		writeRequestProblem(writer, request, http.StatusConflict, "invalid_asset_state", "The asset catalog state conflicts with this operation")
	case errors.Is(err, errAssetCatalogUnavailable), errors.Is(err, context.DeadlineExceeded):
		writeRequestProblem(writer, request, http.StatusServiceUnavailable, "asset_catalog_unavailable", "Asset catalog is unavailable")
	default:
		metadata := requestmeta.From(request.Context())
		slog.Error("asset catalog request failed", "trace_id", metadata.TraceID, "error", err)
		writeRequestProblem(writer, request, http.StatusInternalServerError, "asset_catalog_failed", "Asset catalog request failed")
	}
}
