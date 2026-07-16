package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/authn"
)

type assetRelationSummaryDTO struct {
	ID                        string    `json:"id"`
	SourceEnvironmentID       string    `json:"source_environment_id"`
	TargetEnvironmentID       string    `json:"target_environment_id"`
	SourceAssetID             string    `json:"source_asset_id"`
	TargetAssetID             string    `json:"target_asset_id"`
	Type                      string    `json:"type"`
	Status                    string    `json:"status"`
	Provenance                string    `json:"provenance"`
	SourceID                  string    `json:"source_id"`
	SourceRevision            int64     `json:"source_revision"`
	LastRunID                 string    `json:"last_run_id"`
	LastPageSequence          int64     `json:"last_page_sequence"`
	AcceptedCheckpointVersion int64     `json:"accepted_checkpoint_version"`
	RunFenceEpoch             int64     `json:"run_fence_epoch"`
	ProviderVersionSHA256     string    `json:"provider_version_sha256"`
	RelationFactSHA256        string    `json:"relation_fact_sha256"`
	Version                   int64     `json:"version"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

type assetRelationPageDTO struct {
	Items []assetRelationSummaryDTO `json:"items"`
	Page  pageMetaDTO               `json:"page"`
}

func listAssetRelationsHandler(
	manager assetcatalog.RelationshipManager,
	codec *ControlPlaneCursorCodec,
) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if nilHTTPDependency(manager) || codec == nil {
			writeAssetCatalogError(writer, request, errAssetCatalogUnavailable, "asset_relation_not_found")
			return
		}
		collection, err := assetCollectionFromRequest(request)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_relation_not_found")
			return
		}
		input, err := parseRelationshipListInput(request, codec)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_relation_not_found")
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeAssetCatalogError(writer, request, authn.ErrUnauthenticated, "asset_relation_not_found")
			return
		}
		page, err := manager.ListRelationships(request.Context(), principal, collection, input)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_relation_not_found")
			return
		}
		response := assetRelationPageDTO{
			Items: make([]assetRelationSummaryDTO, len(page.Items)), Page: pageMetaDTO{},
		}
		for index := range page.Items {
			response.Items[index] = toAssetRelationDTO(page.Items[index])
		}
		if page.Next != nil {
			encoded, err := encodeRelationshipCursor(codec, *page.Next)
			if err != nil {
				writeAssetCatalogError(writer, request, err, "asset_relation_not_found")
				return
			}
			response.Page.NextCursor = &encoded
		}
		writeJSON(writer, http.StatusOK, response)
	}
}

func parseRelationshipListInput(
	request *http.Request,
	codec *ControlPlaneCursorCodec,
) (assetcatalog.RelationshipListInput, error) {
	values, err := parseControlPlaneQuery(
		request, "asset_id", "source_id", "types", "statuses", "limit", "cursor",
	)
	if err != nil {
		return assetcatalog.RelationshipListInput{}, err
	}
	limit, err := parseControlPlaneLimit(values)
	if err != nil {
		return assetcatalog.RelationshipListInput{}, err
	}
	assetID, sourceID := values.Get("asset_id"), values.Get("source_id")
	if assetID != "" && !validControlPlaneUUID(assetID) ||
		sourceID != "" && !validControlPlaneUUID(sourceID) {
		return assetcatalog.RelationshipListInput{}, errInvalidControlPlaneRequest
	}
	types, err := parseControlPlaneStringSet(values.Get("types"), 9, func(value assetcatalog.RelationshipType) bool { return value.Valid() })
	if err != nil {
		return assetcatalog.RelationshipListInput{}, err
	}
	statuses, err := parseControlPlaneStringSet(values.Get("statuses"), 2, func(value assetcatalog.RelationshipStatus) bool { return value.Valid() })
	if err != nil {
		return assetcatalog.RelationshipListInput{}, err
	}
	input := assetcatalog.RelationshipListInput{
		AssetID: assetID, SourceID: sourceID, Types: types, Statuses: statuses, Limit: limit,
	}
	if encoded := values.Get("cursor"); encoded != "" {
		cursor, err := codec.decode(encoded, "asset-relations")
		parts := strings.Split(cursor.Value, "|")
		if err != nil || cursor.Sort != "relationship_type_asc" || len(parts) != 3 {
			return assetcatalog.RelationshipListInput{}, errInvalidControlPlaneRequest
		}
		relationshipType := assetcatalog.RelationshipType(parts[0])
		if !relationshipType.Valid() || !validControlPlaneUUID(parts[1]) ||
			!validControlPlaneUUID(parts[2]) {
			return assetcatalog.RelationshipListInput{}, errInvalidControlPlaneRequest
		}
		input.Cursor = &assetcatalog.RelationshipCursor{
			QueryDigest: cursor.QueryDigest, Type: relationshipType,
			SourceAssetID: parts[1], TargetAssetID: parts[2], RelationshipID: cursor.ID,
		}
	}
	return input, nil
}

func encodeRelationshipCursor(
	codec *ControlPlaneCursorCodec,
	cursor assetcatalog.RelationshipCursor,
) (string, error) {
	return codec.encode(controlPlaneCursor{
		Kind: "asset-relations", QueryDigest: cursor.QueryDigest,
		Sort:  "relationship_type_asc",
		Value: string(cursor.Type) + "|" + cursor.SourceAssetID + "|" + cursor.TargetAssetID,
		ID:    cursor.RelationshipID,
	})
}

func toAssetRelationDTO(value assetcatalog.Relationship) assetRelationSummaryDTO {
	return assetRelationSummaryDTO{
		ID: value.ID, SourceEnvironmentID: value.SourceEnvironmentID,
		TargetEnvironmentID: value.TargetEnvironmentID,
		SourceAssetID:       value.SourceAssetID, TargetAssetID: value.TargetAssetID,
		Type: string(value.Type), Status: string(value.Status), Provenance: string(value.Provenance),
		SourceID: value.SourceID, SourceRevision: value.SourceRevision, LastRunID: value.LastRunID,
		LastPageSequence:          value.LastPageSequence,
		AcceptedCheckpointVersion: value.AcceptedCheckpointVersion,
		RunFenceEpoch:             value.RunFenceEpoch, ProviderVersionSHA256: value.ProviderVersionSHA256,
		RelationFactSHA256: value.RelationFactSHA256, Version: value.Version,
		UpdatedAt: value.UpdatedAt.UTC(),
	}
}
