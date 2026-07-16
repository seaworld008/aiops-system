package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/requestmeta"
)

type serviceAssetBindingSummaryDTO struct {
	ID               string    `json:"id"`
	EnvironmentID    string    `json:"environment_id"`
	ServiceID        string    `json:"service_id"`
	AssetID          string    `json:"asset_id"`
	Role             string    `json:"role"`
	MappingStatus    string    `json:"mapping_status"`
	Provenance       string    `json:"provenance"`
	Status           string    `json:"status"`
	Version          int64     `json:"version"`
	ETag             string    `json:"etag"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	EffectiveActions []string  `json:"effective_actions"`
}

type serviceAssetBindingPageDTO struct {
	Items []serviceAssetBindingSummaryDTO `json:"items"`
	Page  pageMetaDTO                     `json:"page"`
}

type createServiceAssetBindingRequest struct {
	ServiceID  string `json:"service_id"`
	AssetID    string `json:"asset_id"`
	Role       string `json:"role"`
	ReasonCode string `json:"reason_code"`
}

type deleteServiceAssetBindingRequest struct {
	ReasonCode string `json:"reason_code"`
}

type serviceAssetBindingMutationResultDTO struct {
	Binding         serviceAssetBindingSummaryDTO `json:"binding"`
	MutationReceipt mutationReceiptDTO            `json:"mutation_receipt"`
}

func listServiceAssetBindingsHandler(
	manager assetcatalog.BindingManager,
	codec *ControlPlaneCursorCodec,
) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if nilHTTPDependency(manager) || codec == nil {
			writeAssetCatalogError(writer, request, errAssetCatalogUnavailable, "service_asset_binding_not_found")
			return
		}
		collection, err := assetCollectionFromRequest(request)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "service_asset_binding_not_found")
			return
		}
		input, err := parseBindingListInput(request, codec)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "service_asset_binding_not_found")
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeAssetCatalogError(writer, request, authn.ErrUnauthenticated, "service_asset_binding_not_found")
			return
		}
		page, err := manager.ListBindings(request.Context(), principal, collection, input)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "service_asset_binding_not_found")
			return
		}
		response := serviceAssetBindingPageDTO{
			Items: make([]serviceAssetBindingSummaryDTO, len(page.Items)), Page: pageMetaDTO{},
		}
		for index := range page.Items {
			response.Items[index] = toServiceAssetBindingDTO(page.Items[index])
		}
		if page.Next != nil {
			encoded, err := codec.encode(controlPlaneCursor{
				Kind: "service-asset-bindings", QueryDigest: page.Next.QueryDigest,
				Sort:  "service_id_asc",
				Value: page.Next.ServiceID + "|" + string(page.Next.Role) + "|" + page.Next.AssetID,
				ID:    page.Next.BindingID,
			})
			if err != nil {
				writeAssetCatalogError(writer, request, err, "service_asset_binding_not_found")
				return
			}
			response.Page.NextCursor = &encoded
		}
		writeJSON(writer, http.StatusOK, response)
	}
}

func createServiceAssetBindingHandler(manager assetcatalog.BindingManager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if nilHTTPDependency(manager) {
			writeAssetCatalogError(writer, request, errAssetCatalogUnavailable, "service_asset_binding_not_found")
			return
		}
		collection, err := assetCollectionFromRequest(request)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "service_asset_binding_not_found")
			return
		}
		idempotencyKey, err := parseIdempotencyKey(request)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "service_asset_binding_not_found")
			return
		}
		var body createServiceAssetBindingRequest
		if err := decodeStrictJSON(writer, request, &body, 64<<10); err != nil {
			writeAssetCatalogError(writer, request, err, "service_asset_binding_not_found")
			return
		}
		role := assetcatalog.BindingRole(body.Role)
		if !validControlPlaneUUID(body.ServiceID) || !validControlPlaneUUID(body.AssetID) ||
			!role.Valid() || !validControlPlaneReasonCode(body.ReasonCode) {
			writeAssetCatalogError(writer, request, errInvalidControlPlaneRequest, "service_asset_binding_not_found")
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeAssetCatalogError(writer, request, authn.ErrUnauthenticated, "service_asset_binding_not_found")
			return
		}
		traceID := requestmeta.From(request.Context()).TraceID
		result, err := manager.CreateBinding(
			request.Context(), principal, collection,
			assetcatalog.CreateBindingInput{
				ServiceID: body.ServiceID, AssetID: body.AssetID, Role: role, ReasonCode: body.ReasonCode,
			},
			assetcatalog.ServerRequestMetadata{TraceID: traceID, IdempotencyKey: idempotencyKey},
		)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "service_asset_binding_not_found")
			return
		}
		receipt, err := mutationReceiptFrom(result.Receipt, traceID)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "service_asset_binding_not_found")
			return
		}
		response := serviceAssetBindingMutationResultDTO{
			Binding: toServiceAssetBindingDTO(result.View), MutationReceipt: receipt,
		}
		writer.Header().Set("Location", request.URL.Path+"/"+result.View.Binding.ID)
		writeVersionETag(
			writer, "service-asset-binding", result.View.Binding.ID, result.View.Binding.Version,
		)
		writeJSON(writer, http.StatusCreated, response)
	}
}

func deleteServiceAssetBindingHandler(manager assetcatalog.BindingManager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if nilHTTPDependency(manager) {
			writeAssetCatalogError(writer, request, errAssetCatalogUnavailable, "service_asset_binding_not_found")
			return
		}
		path, err := bindingPathFromRequest(request)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "service_asset_binding_not_found")
			return
		}
		idempotencyKey, err := parseIdempotencyKey(request)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "service_asset_binding_not_found")
			return
		}
		version, err := parseVersionETag(request, "service-asset-binding", path.BindingID)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "service_asset_binding_not_found")
			return
		}
		var body deleteServiceAssetBindingRequest
		if err := decodeStrictJSON(writer, request, &body, 64<<10); err != nil {
			writeAssetCatalogError(writer, request, err, "service_asset_binding_not_found")
			return
		}
		if !validControlPlaneReasonCode(body.ReasonCode) {
			writeAssetCatalogError(writer, request, errInvalidControlPlaneRequest, "service_asset_binding_not_found")
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeAssetCatalogError(writer, request, authn.ErrUnauthenticated, "service_asset_binding_not_found")
			return
		}
		traceID := requestmeta.From(request.Context()).TraceID
		receipt, err := manager.DeleteBinding(
			request.Context(), principal, path,
			assetcatalog.DeleteBindingInput{ReasonCode: body.ReasonCode},
			assetcatalog.ServerRequestMetadata{
				TraceID: traceID, IdempotencyKey: idempotencyKey, ExpectedVersion: version,
			},
		)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "service_asset_binding_not_found")
			return
		}
		persisted, err := mutationReceiptFrom(receipt, traceID)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "service_asset_binding_not_found")
			return
		}
		writer.Header().Set("X-Audit-ID", persisted.AuditID)
		writer.Header().Set("X-Idempotent-Replay", strconv.FormatBool(persisted.IdempotentReplay))
		writer.WriteHeader(http.StatusNoContent)
	}
}

func bindingPathFromRequest(request *http.Request) (assetcatalog.BindingPathRequest, error) {
	collection, err := assetCollectionFromRequest(request)
	if err != nil {
		return assetcatalog.BindingPathRequest{}, err
	}
	bindingID := chi.URLParam(request, "bindingID")
	if !validControlPlaneUUID(bindingID) {
		return assetcatalog.BindingPathRequest{}, errInvalidControlPlaneRequest
	}
	return assetcatalog.BindingPathRequest{
		WorkspaceID: collection.WorkspaceID, EnvironmentID: collection.EnvironmentID,
		BindingID: bindingID,
	}, nil
}

func parseBindingListInput(
	request *http.Request,
	codec *ControlPlaneCursorCodec,
) (assetcatalog.BindingListInput, error) {
	values, err := parseControlPlaneQuery(
		request, "service_id", "asset_id", "roles", "statuses", "limit", "cursor",
	)
	if err != nil {
		return assetcatalog.BindingListInput{}, err
	}
	serviceID, assetID := values.Get("service_id"), values.Get("asset_id")
	if serviceID != "" && !validControlPlaneUUID(serviceID) ||
		assetID != "" && !validControlPlaneUUID(assetID) {
		return assetcatalog.BindingListInput{}, errInvalidControlPlaneRequest
	}
	roles, err := parseControlPlaneStringSet(values.Get("roles"), 5, func(value assetcatalog.BindingRole) bool { return value.Valid() })
	if err != nil {
		return assetcatalog.BindingListInput{}, err
	}
	statuses, err := parseControlPlaneStringSet(values.Get("statuses"), 2, func(value assetcatalog.BindingStatus) bool { return value.Valid() })
	if err != nil {
		return assetcatalog.BindingListInput{}, err
	}
	limit, err := parseControlPlaneLimit(values)
	if err != nil {
		return assetcatalog.BindingListInput{}, err
	}
	input := assetcatalog.BindingListInput{
		ServiceID: serviceID, AssetID: assetID, Roles: roles, Statuses: statuses, Limit: limit,
	}
	if encoded := values.Get("cursor"); encoded != "" {
		cursor, err := codec.decode(encoded, "service-asset-bindings")
		parts := strings.Split(cursor.Value, "|")
		if err != nil || cursor.Sort != "service_id_asc" || len(parts) != 3 ||
			!validControlPlaneUUID(parts[0]) || !validControlPlaneUUID(parts[2]) {
			return assetcatalog.BindingListInput{}, errInvalidControlPlaneRequest
		}
		role := assetcatalog.BindingRole(parts[1])
		if !role.Valid() {
			return assetcatalog.BindingListInput{}, errInvalidControlPlaneRequest
		}
		input.Cursor = &assetcatalog.BindingCursor{
			QueryDigest: cursor.QueryDigest, ServiceID: parts[0], Role: role,
			AssetID: parts[2], BindingID: cursor.ID,
		}
	}
	return input, nil
}

func toServiceAssetBindingDTO(view assetcatalog.BindingView) serviceAssetBindingSummaryDTO {
	binding := view.Binding
	return serviceAssetBindingSummaryDTO{
		ID: binding.ID, EnvironmentID: binding.Scope.EnvironmentID,
		ServiceID: binding.ServiceID, AssetID: binding.AssetID, Role: string(binding.Role),
		MappingStatus: string(binding.MappingStatus), Provenance: string(binding.Provenance),
		Status: string(binding.Status), Version: binding.Version,
		ETag:      `"service-asset-binding:` + binding.ID + `:v` + formatPositiveVersion(binding.Version) + `"`,
		CreatedAt: binding.CreatedAt.UTC(), UpdatedAt: binding.UpdatedAt.UTC(),
		EffectiveActions: effectiveActionStrings(view.EffectiveActions),
	}
}

func formatPositiveVersion(version int64) string {
	if version <= 0 {
		return "0"
	}
	return strconv.FormatInt(version, 10)
}
