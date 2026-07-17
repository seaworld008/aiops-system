package httpapi

import (
	"errors"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/authz"
	"github.com/seaworld008/aiops-system/internal/requestmeta"
)

var errSourceBackpressure = errors.New("source backpressure")

type sourceRunCountsDTO struct {
	Observed   int64 `json:"observed"`
	Created    int64 `json:"created"`
	Changed    int64 `json:"changed"`
	Unchanged  int64 `json:"unchanged"`
	Conflicts  int64 `json:"conflicts"`
	Missing    int64 `json:"missing"`
	Stale      int64 `json:"stale"`
	Restored   int64 `json:"restored"`
	Tombstoned int64 `json:"tombstoned"`
	Rejected   int64 `json:"rejected"`
}

type assetSourceSummaryDTO struct {
	ID                        string              `json:"id"`
	Name                      string              `json:"name"`
	Kind                      string              `json:"kind"`
	ProviderKind              string              `json:"provider_kind"`
	Status                    string              `json:"status"`
	GateStatus                string              `json:"gate_status"`
	GateReasonCode            *string             `json:"gate_reason_code"`
	GateRevision              int64               `json:"gate_revision"`
	PublishedRevision         *int64              `json:"published_revision"`
	PublishedRevisionDigest   *string             `json:"published_revision_digest"`
	CheckpointSHA256          *string             `json:"checkpoint_sha256"`
	CheckpointVersion         int64               `json:"checkpoint_version"`
	LastSuccessRunID          *string             `json:"last_success_run_id"`
	LastSuccessAt             *time.Time          `json:"last_success_at"`
	LastCompleteSnapshotRunID *string             `json:"last_complete_snapshot_run_id"`
	LastCompleteSnapshotAt    *time.Time          `json:"last_complete_snapshot_at"`
	CurrentRunCounts          *sourceRunCountsDTO `json:"current_run_counts"`
	LastRunCounts             *sourceRunCountsDTO `json:"last_run_counts"`
	Version                   int64               `json:"version"`
	CreatedAt                 time.Time           `json:"created_at"`
	UpdatedAt                 time.Time           `json:"updated_at"`
	EffectiveActions          []string            `json:"effective_actions"`
}

type sourceRevisionSummaryDTO struct {
	Revision                 int64     `json:"revision"`
	Status                   string    `json:"status"`
	ProfileCode              string    `json:"profile_code"`
	IntegrationID            *string   `json:"integration_id"`
	SyncMode                 string    `json:"sync_mode"`
	CredentialReferenceID    *string   `json:"credential_reference_id"`
	TrustReferenceID         *string   `json:"trust_reference_id"`
	NetworkPolicyReferenceID *string   `json:"network_policy_reference_id"`
	AuthorityEnvironmentIDs  []string  `json:"authority_environment_ids"`
	BindingDigest            string    `json:"binding_digest"`
	SourceDefinitionDigest   string    `json:"source_definition_digest"`
	Version                  int64     `json:"version"`
	CreatedAt                time.Time `json:"created_at"`
	UpdatedAt                time.Time `json:"updated_at"`
	EffectiveActions         []string  `json:"effective_actions"`
}

type assetSourceDetailDTO struct {
	Summary           assetSourceSummaryDTO     `json:"summary"`
	LatestRevision    sourceRevisionSummaryDTO  `json:"latest_revision"`
	PublishedRevision *sourceRevisionSummaryDTO `json:"published_revision"`
}

type assetSourcePageDTO struct {
	Items            []assetSourceSummaryDTO `json:"items"`
	Page             pageMetaDTO             `json:"page"`
	EffectiveActions []string                `json:"effective_actions"`
}

type assetSourceRunDTO struct {
	ID                        string             `json:"id"`
	SourceID                  string             `json:"source_id"`
	SourceRevision            int64              `json:"source_revision"`
	SourceRevisionDigest      string             `json:"source_revision_digest"`
	Kind                      string             `json:"kind"`
	Status                    string             `json:"status"`
	Stage                     string             `json:"stage"`
	StageChangedAt            time.Time          `json:"stage_changed_at"`
	TriggerType               string             `json:"trigger_type"`
	GateRevision              int64              `json:"gate_revision"`
	PageSequence              int64              `json:"page_sequence"`
	RelationPageSequence      int64              `json:"relation_page_sequence"`
	CursorBeforeSHA256        *string            `json:"cursor_before_sha256"`
	CursorAfterSHA256         *string            `json:"cursor_after_sha256"`
	CheckpointVersion         int64              `json:"checkpoint_version"`
	NotBefore                 time.Time          `json:"not_before"`
	FinalPage                 bool               `json:"final_page"`
	CompleteSnapshot          bool               `json:"complete_snapshot"`
	EffectiveCompleteSnapshot bool               `json:"effective_complete_snapshot"`
	WorkResultKind            *string            `json:"work_result_kind"`
	WorkResultStatus          *string            `json:"work_result_status"`
	WorkResultDigest          *string            `json:"work_result_digest"`
	WorkResultRecordedAt      *time.Time         `json:"work_result_recorded_at"`
	ValidationOutcome         *string            `json:"validation_outcome"`
	ValidationProofDigest     *string            `json:"validation_proof_digest"`
	CredentialCleanupStatus   string             `json:"credential_cleanup_status"`
	Counts                    sourceRunCountsDTO `json:"counts"`
	FailureCode               *string            `json:"failure_code"`
	TraceID                   *string            `json:"trace_id"`
	Version                   int64              `json:"version"`
	CreatedAt                 time.Time          `json:"created_at"`
	StartedAt                 *time.Time         `json:"started_at"`
	HeartbeatAt               *time.Time         `json:"heartbeat_at"`
	CompletedAt               *time.Time         `json:"completed_at"`
	EffectiveActions          []string           `json:"effective_actions"`
}

type createAssetSourceRequest struct {
	Name                    string   `json:"name"`
	SourceProfileID         string   `json:"source_profile_id"`
	AuthorityEnvironmentIDs []string `json:"authority_environment_ids"`
}

type createAssetSourceRevisionRequest struct {
	SourceProfileID         string   `json:"source_profile_id"`
	AuthorityEnvironmentIDs []string `json:"authority_environment_ids"`
	ChangeReasonCode        string   `json:"change_reason_code"`
}

type sourceReasonRequest struct {
	ReasonCode string `json:"reason_code"`
}

type emptySourceRequest struct{}

type sourceRevisionMutationDTO struct {
	Source          assetSourceSummaryDTO    `json:"source"`
	Revision        sourceRevisionSummaryDTO `json:"revision"`
	MutationReceipt mutationReceiptDTO       `json:"mutation_receipt"`
}

type sourceMutationDTO struct {
	Source          assetSourceSummaryDTO `json:"source"`
	MutationReceipt mutationReceiptDTO    `json:"mutation_receipt"`
}

type sourceRunMutationDTO struct {
	Source          assetSourceSummaryDTO    `json:"source"`
	Revision        sourceRevisionSummaryDTO `json:"revision"`
	Run             assetSourceRunDTO        `json:"run"`
	OperationID     string                   `json:"operation_id"`
	MutationReceipt mutationReceiptDTO       `json:"mutation_receipt"`
}

func listAssetSourcesHandler(
	manager assetcatalog.SourceManager,
	codec *ControlPlaneCursorCodec,
) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if nilHTTPDependency(manager) || codec == nil {
			writeAssetCatalogError(writer, request, errAssetCatalogUnavailable, "asset_source_not_found")
			return
		}
		collection, err := sourceCollectionFromRequest(request)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_source_not_found")
			return
		}
		input, err := parseSourceListInput(request, codec)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_source_not_found")
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeAssetCatalogError(writer, request, authn.ErrUnauthenticated, "asset_source_not_found")
			return
		}
		page, err := manager.ListSources(request.Context(), principal, collection, input)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_source_not_found")
			return
		}
		response := assetSourcePageDTO{
			Items: make([]assetSourceSummaryDTO, len(page.Items)),
			Page:  pageMetaDTO{}, EffectiveActions: effectiveActionStrings(page.EffectiveActions),
		}
		for index := range page.Items {
			response.Items[index] = toAssetSourceSummaryDTO(page.Items[index])
		}
		if page.Next != nil {
			encoded, err := codec.encode(controlPlaneCursor{
				Kind: "asset-sources", QueryDigest: page.Next.QueryDigest,
				Sort: "source_id_asc", Value: "", ID: page.Next.SourceID,
			})
			if err != nil {
				writeAssetCatalogError(writer, request, err, "asset_source_not_found")
				return
			}
			response.Page.NextCursor = &encoded
		}
		writeJSON(writer, http.StatusOK, response)
	}
}

func createAssetSourceHandler(manager assetcatalog.SourceManager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if nilHTTPDependency(manager) {
			writeSourceError(writer, request, errAssetCatalogUnavailable, "asset_source_not_found")
			return
		}
		collection, err := sourceCollectionFromRequest(request)
		if err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		idempotencyKey, err := parseIdempotencyKey(request)
		if err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		var body createAssetSourceRequest
		if err := decodeStrictJSON(writer, request, &body, 64<<10); err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		input, err := body.input()
		if err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeSourceError(writer, request, authn.ErrUnauthenticated, "asset_source_not_found")
			return
		}
		metadata := assetcatalog.ServerRequestMetadata{
			TraceID: requestmeta.From(request.Context()).TraceID, IdempotencyKey: idempotencyKey,
		}
		result, err := manager.CreateSource(request.Context(), principal, collection, input, metadata)
		if err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		response, err := sourceRevisionMutationDTOFrom(result, metadata.TraceID)
		if err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		writer.Header().Set(
			"Location",
			request.URL.Path+"/"+result.Source.ID,
		)
		writeSourceRevisionETag(
			writer, result.Source.ID, result.Revision.Revision,
			result.Source.Version, result.Revision.Version,
		)
		writeJSON(writer, http.StatusCreated, response)
	}
}

func getAssetSourceHandler(manager assetcatalog.SourceManager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if nilHTTPDependency(manager) {
			writeAssetCatalogError(writer, request, errAssetCatalogUnavailable, "asset_source_not_found")
			return
		}
		path, err := sourcePathFromRequest(request)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_source_not_found")
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeAssetCatalogError(writer, request, authn.ErrUnauthenticated, "asset_source_not_found")
			return
		}
		view, err := manager.GetSource(request.Context(), principal, path)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_source_not_found")
			return
		}
		writeVersionETag(writer, "asset-source", view.ReadModel.Source.ID, view.ReadModel.Source.Version)
		writeJSON(writer, http.StatusOK, toAssetSourceDetailDTO(view))
	}
}

func getAssetSourceRunHandler(manager assetcatalog.SourceManager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if nilHTTPDependency(manager) {
			writeAssetCatalogError(writer, request, errAssetCatalogUnavailable, "asset_source_run_not_found")
			return
		}
		path, err := sourceRunPathFromRequest(request)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_source_run_not_found")
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeAssetCatalogError(writer, request, authn.ErrUnauthenticated, "asset_source_run_not_found")
			return
		}
		view, err := manager.GetSourceRun(request.Context(), principal, path)
		if err != nil {
			writeAssetCatalogError(writer, request, err, "asset_source_run_not_found")
			return
		}
		writeVersionETag(writer, "asset-source-run", view.Run.ID, view.Run.Version)
		writeJSON(writer, http.StatusOK, toAssetSourceRunDTO(view))
	}
}

func createAssetSourceRevisionHandler(manager assetcatalog.SourceManager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		path, metadata, principal, ok := prepareSourceVersionedMutation(writer, request, manager)
		if !ok {
			return
		}
		var body createAssetSourceRevisionRequest
		if err := decodeStrictJSON(writer, request, &body, 64<<10); err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		input, err := body.input()
		if err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		result, err := manager.CreateSourceRevision(
			request.Context(), principal, path, input, metadata,
		)
		writeSourceRevisionMutationResponse(writer, request, result, err, http.StatusCreated)
	}
}

func validateAssetSourceRevisionHandler(manager assetcatalog.SourceManager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		path, metadata, principal, ok := prepareSourceRevisionMutation(writer, request, manager)
		if !ok {
			return
		}
		var body emptySourceRequest
		if err := decodeStrictJSON(writer, request, &body, 64<<10); err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		result, err := manager.ValidateSourceRevision(
			request.Context(), principal, path, metadata,
		)
		if err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		response, err := sourceRunMutationDTOFrom(result, requestmeta.From(request.Context()).TraceID)
		if err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		writeSourceRevisionETag(
			writer, result.Source.ID, result.Revision.Revision,
			result.Source.Version, result.Revision.Version,
		)
		status := http.StatusAccepted
		if result.Revision.ProfileCode == assetcatalog.ProfileCode("MANUAL_V1") &&
			terminalSourceRun(result.Run.Status) {
			status = http.StatusOK
		}
		writeJSON(writer, status, response)
	}
}

func publishAssetSourceRevisionHandler(manager assetcatalog.SourceManager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		path, metadata, principal, ok := prepareSourceRevisionMutation(writer, request, manager)
		if !ok {
			return
		}
		var body sourceReasonRequest
		if err := decodeStrictJSON(writer, request, &body, 64<<10); err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		if !validControlPlaneReasonCode(body.ReasonCode) {
			writeSourceError(writer, request, errInvalidControlPlaneRequest, "asset_source_not_found")
			return
		}
		result, err := manager.PublishSourceRevision(
			request.Context(), principal, path,
			assetcatalog.SourceReasonInput{ReasonCode: body.ReasonCode}, metadata,
		)
		writeSourceRevisionMutationResponse(writer, request, result, err, http.StatusOK)
	}
}

func disableAssetSourceHandler(manager assetcatalog.SourceManager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		path, metadata, principal, ok := prepareSourceVersionedMutation(writer, request, manager)
		if !ok {
			return
		}
		var body sourceReasonRequest
		if err := decodeStrictJSON(writer, request, &body, 64<<10); err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		if !validControlPlaneReasonCode(body.ReasonCode) {
			writeSourceError(writer, request, errInvalidControlPlaneRequest, "asset_source_not_found")
			return
		}
		result, err := manager.DisableSource(
			request.Context(), principal, path,
			assetcatalog.SourceReasonInput{ReasonCode: body.ReasonCode}, metadata,
		)
		if err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		response, err := sourceMutationDTOFrom(result, metadata.TraceID)
		if err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		writeVersionETag(writer, "asset-source", result.Source.ID, result.Source.Version)
		writeJSON(writer, http.StatusOK, response)
	}
}

func syncAssetSourceHandler(manager assetcatalog.SourceManager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		path, metadata, principal, ok := prepareSourceVersionedMutation(writer, request, manager)
		if !ok {
			return
		}
		var body emptySourceRequest
		if err := decodeStrictJSON(writer, request, &body, 64<<10); err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		result, err := manager.SyncSource(request.Context(), principal, path, metadata)
		if err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		response, err := sourceRunMutationDTOFrom(result, metadata.TraceID)
		if err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		writeVersionETag(writer, "asset-source", result.Source.ID, result.Source.Version)
		writeJSON(writer, http.StatusAccepted, response)
	}
}

func unavailableAssetSourceImportHandler(manager assetcatalog.SourceManager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if nilHTTPDependency(manager) {
			writeSourceError(writer, request, errAssetCatalogUnavailable, "asset_source_not_found")
			return
		}
		if _, err := sourcePathFromRequest(request); err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		if _, err := parseIdempotencyKey(request); err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		if _, err := parseVersionETag(
			request, "asset-source", chi.URLParam(request, "sourceID"),
		); err != nil {
			writeSourceError(writer, request, err, "asset_source_not_found")
			return
		}
		contentTypes := request.Header.Values("Content-Type")
		if len(contentTypes) != 1 {
			writeSourceError(writer, request, errUnsupportedControlPlaneMediaType, "asset_source_not_found")
			return
		}
		contentType, parameters, err := mime.ParseMediaType(contentTypes[0])
		if err != nil || contentType != "multipart/form-data" ||
			len(parameters) != 1 || parameters["boundary"] == "" {
			writeSourceError(writer, request, errUnsupportedControlPlaneMediaType, "asset_source_not_found")
			return
		}
		if _, ok := authn.PrincipalFromContext(request.Context()); !ok {
			writeSourceError(writer, request, authn.ErrUnauthenticated, "asset_source_not_found")
			return
		}
		writeRequestProblem(
			writer, request, http.StatusServiceUnavailable,
			"source_import_unavailable", "Source import runtime is unavailable",
		)
	}
}

func unavailableAssetSourceIngestionHandler() http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if values := request.Header.Values("Authorization"); len(values) != 0 {
			writeRequestProblem(
				writer, request, http.StatusUnauthorized,
				"source_workload_identity_mismatch", "A matching mutual TLS workload identity is required",
			)
			return
		}
		if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 ||
			len(request.TLS.VerifiedChains) == 0 {
			writeRequestProblem(
				writer, request, http.StatusUnauthorized,
				"source_workload_identity_mismatch", "A matching mutual TLS workload identity is required",
			)
			return
		}
		// Task 16 owns the exact SAN tuple parser and durable identity binding.
		// Until it is installed, no certificate is treated as an authorized Source identity.
		writeRequestProblem(
			writer, request, http.StatusServiceUnavailable,
			"source_ingestion_unavailable", "Source ingestion runtime is unavailable",
		)
	}
}

func sourceCollectionFromRequest(request *http.Request) (assetcatalog.SourceCollectionRequest, error) {
	workspaceID := chi.URLParam(request, "workspaceID")
	if !validControlPlaneUUID(workspaceID) {
		return assetcatalog.SourceCollectionRequest{}, errInvalidControlPlaneRequest
	}
	return assetcatalog.SourceCollectionRequest{WorkspaceID: workspaceID}, nil
}

func sourcePathFromRequest(request *http.Request) (assetcatalog.SourcePathRequest, error) {
	collection, err := sourceCollectionFromRequest(request)
	if err != nil {
		return assetcatalog.SourcePathRequest{}, err
	}
	sourceID := chi.URLParam(request, "sourceID")
	if !validControlPlaneUUID(sourceID) {
		return assetcatalog.SourcePathRequest{}, errInvalidControlPlaneRequest
	}
	return assetcatalog.SourcePathRequest{WorkspaceID: collection.WorkspaceID, SourceID: sourceID}, nil
}

func sourceRevisionPathFromRequest(request *http.Request) (assetcatalog.SourceRevisionPathRequest, error) {
	path, err := sourcePathFromRequest(request)
	if err != nil {
		return assetcatalog.SourceRevisionPathRequest{}, err
	}
	rawRevision := chi.URLParam(request, "revision")
	revision, err := strconv.ParseInt(rawRevision, 10, 64)
	if err != nil || revision <= 0 || strconv.FormatInt(revision, 10) != rawRevision {
		return assetcatalog.SourceRevisionPathRequest{}, errInvalidControlPlaneRequest
	}
	return assetcatalog.SourceRevisionPathRequest{
		WorkspaceID: path.WorkspaceID, SourceID: path.SourceID, Revision: revision,
	}, nil
}

func sourceRunPathFromRequest(request *http.Request) (assetcatalog.SourceRunPathRequest, error) {
	collection, err := sourceCollectionFromRequest(request)
	if err != nil {
		return assetcatalog.SourceRunPathRequest{}, err
	}
	runID := chi.URLParam(request, "runID")
	if !validControlPlaneUUID(runID) {
		return assetcatalog.SourceRunPathRequest{}, errInvalidControlPlaneRequest
	}
	return assetcatalog.SourceRunPathRequest{WorkspaceID: collection.WorkspaceID, RunID: runID}, nil
}

func prepareSourceVersionedMutation(
	writer http.ResponseWriter,
	request *http.Request,
	manager assetcatalog.SourceManager,
) (assetcatalog.SourcePathRequest, assetcatalog.ServerRequestMetadata, authn.Principal, bool) {
	if nilHTTPDependency(manager) {
		writeSourceError(writer, request, errAssetCatalogUnavailable, "asset_source_not_found")
		return assetcatalog.SourcePathRequest{}, assetcatalog.ServerRequestMetadata{}, authn.Principal{}, false
	}
	path, err := sourcePathFromRequest(request)
	if err != nil {
		writeSourceError(writer, request, err, "asset_source_not_found")
		return assetcatalog.SourcePathRequest{}, assetcatalog.ServerRequestMetadata{}, authn.Principal{}, false
	}
	idempotencyKey, err := parseIdempotencyKey(request)
	if err != nil {
		writeSourceError(writer, request, err, "asset_source_not_found")
		return assetcatalog.SourcePathRequest{}, assetcatalog.ServerRequestMetadata{}, authn.Principal{}, false
	}
	sourceVersion, err := parseVersionETag(request, "asset-source", path.SourceID)
	if err != nil {
		writeSourceError(writer, request, err, "asset_source_not_found")
		return assetcatalog.SourcePathRequest{}, assetcatalog.ServerRequestMetadata{}, authn.Principal{}, false
	}
	principal, ok := authn.PrincipalFromContext(request.Context())
	if !ok {
		writeSourceError(writer, request, authn.ErrUnauthenticated, "asset_source_not_found")
		return assetcatalog.SourcePathRequest{}, assetcatalog.ServerRequestMetadata{}, authn.Principal{}, false
	}
	return path, assetcatalog.ServerRequestMetadata{
		TraceID:        requestmeta.From(request.Context()).TraceID,
		IdempotencyKey: idempotencyKey, ExpectedVersion: sourceVersion,
	}, principal, true
}

func prepareSourceRevisionMutation(
	writer http.ResponseWriter,
	request *http.Request,
	manager assetcatalog.SourceManager,
) (assetcatalog.SourceRevisionPathRequest, assetcatalog.ServerRequestMetadata, authn.Principal, bool) {
	if nilHTTPDependency(manager) {
		writeSourceError(writer, request, errAssetCatalogUnavailable, "asset_source_not_found")
		return assetcatalog.SourceRevisionPathRequest{}, assetcatalog.ServerRequestMetadata{}, authn.Principal{}, false
	}
	path, err := sourceRevisionPathFromRequest(request)
	if err != nil {
		writeSourceError(writer, request, err, "asset_source_not_found")
		return assetcatalog.SourceRevisionPathRequest{}, assetcatalog.ServerRequestMetadata{}, authn.Principal{}, false
	}
	idempotencyKey, err := parseIdempotencyKey(request)
	if err != nil {
		writeSourceError(writer, request, err, "asset_source_not_found")
		return assetcatalog.SourceRevisionPathRequest{}, assetcatalog.ServerRequestMetadata{}, authn.Principal{}, false
	}
	sourceVersion, revisionVersion, err := parseSourceRevisionETag(request, path.SourceID, path.Revision)
	if err != nil {
		writeSourceError(writer, request, err, "asset_source_not_found")
		return assetcatalog.SourceRevisionPathRequest{}, assetcatalog.ServerRequestMetadata{}, authn.Principal{}, false
	}
	principal, ok := authn.PrincipalFromContext(request.Context())
	if !ok {
		writeSourceError(writer, request, authn.ErrUnauthenticated, "asset_source_not_found")
		return assetcatalog.SourceRevisionPathRequest{}, assetcatalog.ServerRequestMetadata{}, authn.Principal{}, false
	}
	return path, assetcatalog.ServerRequestMetadata{
		TraceID: requestmeta.From(request.Context()).TraceID, IdempotencyKey: idempotencyKey,
		ExpectedVersion: sourceVersion, ExpectedRevisionVersion: revisionVersion,
	}, principal, true
}

func parseSourceListInput(
	request *http.Request,
	codec *ControlPlaneCursorCodec,
) (assetcatalog.SourceListInput, error) {
	values, err := parseControlPlaneQuery(
		request, "kinds", "statuses", "gate_statuses", "usage", "environment_id", "limit", "cursor",
	)
	if err != nil {
		return assetcatalog.SourceListInput{}, err
	}
	limit, err := parseControlPlaneLimit(values)
	if err != nil {
		return assetcatalog.SourceListInput{}, err
	}
	kinds, err := parseControlPlaneStringSet(values.Get("kinds"), 10, func(value assetcatalog.SourceKind) bool { return value.Valid() })
	if err != nil {
		return assetcatalog.SourceListInput{}, err
	}
	statuses, err := parseControlPlaneStringSet(values.Get("statuses"), 4, func(value assetcatalog.SourceStatus) bool { return value.Valid() })
	if err != nil {
		return assetcatalog.SourceListInput{}, err
	}
	gates, err := parseControlPlaneStringSet(values.Get("gate_statuses"), 5, func(value assetcatalog.SourceGateStatus) bool { return value.Valid() })
	if err != nil {
		return assetcatalog.SourceListInput{}, err
	}
	usage := assetcatalog.SourceUsage(values.Get("usage"))
	if usage != "" && !usage.Valid() {
		return assetcatalog.SourceListInput{}, errInvalidControlPlaneRequest
	}
	environmentID := values.Get("environment_id")
	if environmentID != "" && !validControlPlaneUUID(environmentID) ||
		(usage == assetcatalog.SourceUsageManualAssetCreate) != (environmentID != "") {
		return assetcatalog.SourceListInput{}, errInvalidControlPlaneRequest
	}
	input := assetcatalog.SourceListInput{
		Kinds: kinds, Statuses: statuses, GateStatuses: gates,
		Usage: usage, EnvironmentID: environmentID, Limit: limit,
	}
	if encoded := values.Get("cursor"); encoded != "" {
		cursor, err := codec.decode(encoded, "asset-sources")
		if err != nil || cursor.Sort != "source_id_asc" || cursor.Value != "" {
			return assetcatalog.SourceListInput{}, errInvalidControlPlaneRequest
		}
		input.Cursor = &assetcatalog.SourceCursor{
			QueryDigest: cursor.QueryDigest, SourceID: cursor.ID,
		}
	}
	return input, nil
}

func (request createAssetSourceRequest) input() (assetcatalog.CreateSourceInput, error) {
	authorities, err := sourceAuthorityEnvironmentIDs(request.AuthorityEnvironmentIDs)
	profileID := assetcatalog.SourceProfileID(request.SourceProfileID)
	if err != nil || !validControlPlaneSafeText(request.Name, 1, 256) || !profileID.Valid() {
		return assetcatalog.CreateSourceInput{}, errInvalidControlPlaneRequest
	}
	return assetcatalog.CreateSourceInput{
		Name: request.Name, SourceProfileID: profileID,
		AuthorityEnvironmentIDs: authorities,
	}, nil
}

func (request createAssetSourceRevisionRequest) input() (assetcatalog.CreateSourceRevisionInput, error) {
	authorities, err := sourceAuthorityEnvironmentIDs(request.AuthorityEnvironmentIDs)
	profileID := assetcatalog.SourceProfileID(request.SourceProfileID)
	if err != nil || !profileID.Valid() || !validControlPlaneReasonCode(request.ChangeReasonCode) {
		return assetcatalog.CreateSourceRevisionInput{}, errInvalidControlPlaneRequest
	}
	return assetcatalog.CreateSourceRevisionInput{
		SourceProfileID: profileID, AuthorityEnvironmentIDs: authorities,
		ChangeReasonCode: request.ChangeReasonCode,
	}, nil
}

func sourceAuthorityEnvironmentIDs(values []string) ([]string, error) {
	result := slices.Clone(values)
	slices.Sort(result)
	if len(result) == 0 || len(result) > 100 {
		return nil, errInvalidControlPlaneRequest
	}
	for index, value := range result {
		if !validControlPlaneUUID(value) || index > 0 && result[index-1] == value {
			return nil, errInvalidControlPlaneRequest
		}
	}
	return result, nil
}

func toAssetSourceSummaryDTO(view assetcatalog.SourceView) assetSourceSummaryDTO {
	source := view.ReadModel.Source
	return assetSourceSummaryDTO{
		ID: source.ID, Name: source.Name, Kind: string(source.Kind), ProviderKind: source.ProviderKind,
		Status: string(source.Status), GateStatus: string(source.GateStatus),
		GateReasonCode: optionalString(source.GateReasonCode), GateRevision: source.GateRevision,
		PublishedRevision:         optionalPositiveInt64(source.PublishedRevision),
		PublishedRevisionDigest:   optionalString(source.PublishedRevisionDigest),
		CheckpointSHA256:          optionalString(source.CheckpointSHA256),
		CheckpointVersion:         source.CheckpointVersion,
		LastSuccessRunID:          optionalString(source.LastSuccessRunID),
		LastSuccessAt:             cloneTimePointer(source.LastSuccessAt),
		LastCompleteSnapshotRunID: optionalString(source.LastCompleteSnapshotRunID),
		LastCompleteSnapshotAt:    cloneTimePointer(source.LastCompleteSnapshotAt),
		CurrentRunCounts:          sourceRunCounts(view.ReadModel.CurrentRun),
		LastRunCounts:             sourceRunCounts(view.ReadModel.LastSuccessfulRun),
		Version:                   source.Version, CreatedAt: source.CreatedAt.UTC(), UpdatedAt: source.UpdatedAt.UTC(),
		EffectiveActions: sourceEffectiveActionStrings(view.EffectiveActions),
	}
}

func toAssetSourceDetailDTO(view assetcatalog.SourceView) assetSourceDetailDTO {
	result := assetSourceDetailDTO{
		Summary: toAssetSourceSummaryDTO(view),
		LatestRevision: toSourceRevisionSummaryDTO(
			view.ReadModel.LatestRevision, view.EffectiveActions,
		),
	}
	if view.ReadModel.PublishedRevision != nil {
		published := toSourceRevisionSummaryDTO(
			*view.ReadModel.PublishedRevision, []assetcatalog.EffectiveAction{},
		)
		result.PublishedRevision = &published
	}
	return result
}

func toSourceRevisionSummaryDTO(
	value assetcatalog.SourceRevision,
	actions []assetcatalog.EffectiveAction,
) sourceRevisionSummaryDTO {
	return sourceRevisionSummaryDTO{
		Revision: value.Revision, Status: string(value.Status), ProfileCode: string(value.ProfileCode),
		IntegrationID: optionalString(value.IntegrationID), SyncMode: string(value.SyncMode),
		CredentialReferenceID:    optionalString(string(value.CredentialReferenceID)),
		TrustReferenceID:         optionalString(string(value.TrustReferenceID)),
		NetworkPolicyReferenceID: optionalString(string(value.NetworkPolicyReferenceID)),
		AuthorityEnvironmentIDs:  slices.Clone(value.AuthorityEnvironmentIDs),
		BindingDigest:            value.CanonicalRevisionDigest,
		SourceDefinitionDigest:   value.SourceDefinitionDigest,
		Version:                  value.Version,
		CreatedAt:                value.CreatedAt.UTC(), UpdatedAt: value.UpdatedAt.UTC(),
		EffectiveActions: revisionEffectiveActionStrings(actions),
	}
}

func sourceEffectiveActionStrings(actions []assetcatalog.EffectiveAction) []string {
	filtered := make([]assetcatalog.EffectiveAction, 0, len(actions))
	for _, action := range actions {
		switch action {
		case assetcatalog.ActionCreateAsset,
			assetcatalog.ActionCreateSourceRevision,
			assetcatalog.ActionDisableSource,
			assetcatalog.ActionSyncSource,
			assetcatalog.ActionImportCSV:
			filtered = append(filtered, action)
		}
	}
	return effectiveActionStrings(filtered)
}

func revisionEffectiveActionStrings(actions []assetcatalog.EffectiveAction) []string {
	filtered := make([]assetcatalog.EffectiveAction, 0, len(actions))
	for _, action := range actions {
		switch action {
		case assetcatalog.ActionValidateSourceRevision,
			assetcatalog.ActionPublishSourceRevision:
			filtered = append(filtered, action)
		}
	}
	return effectiveActionStrings(filtered)
}

func toAssetSourceRunDTO(view assetcatalog.SourceRunView) assetSourceRunDTO {
	run := view.Run
	return assetSourceRunDTO{
		ID: run.ID, SourceID: run.SourceID, SourceRevision: run.SourceRevision,
		SourceRevisionDigest: run.SourceRevisionDigest, Kind: string(run.Kind),
		Status: string(run.Status), Stage: string(run.Stage), StageChangedAt: run.StageChangedAt.UTC(),
		TriggerType: string(run.TriggerType), GateRevision: run.GateRevision,
		PageSequence: run.PageSequence, RelationPageSequence: run.RelationPageSequence,
		CursorBeforeSHA256: optionalString(run.CursorBeforeSHA256),
		CursorAfterSHA256:  optionalString(run.CursorAfterSHA256),
		CheckpointVersion:  run.CheckpointVersion, NotBefore: run.NotBefore.UTC(),
		FinalPage: run.FinalPage, CompleteSnapshot: run.CompleteSnapshot,
		EffectiveCompleteSnapshot: run.EffectiveCompleteSnapshot,
		WorkResultKind:            optionalString(string(run.WorkResultKind)),
		WorkResultStatus:          optionalString(string(run.WorkResultStatus)),
		WorkResultDigest:          optionalString(run.WorkResultDigest),
		WorkResultRecordedAt:      cloneTimePointer(run.WorkResultRecordedAt),
		ValidationOutcome:         optionalString(string(run.ValidationOutcome)),
		ValidationProofDigest:     optionalString(run.ValidationProofDigest),
		CredentialCleanupStatus:   string(run.CredentialCleanupStatus),
		Counts: sourceRunCountsDTO{
			Observed: run.Observed, Created: run.Created, Changed: run.Changed,
			Unchanged: run.Unchanged, Conflicts: run.Conflicts, Missing: run.Missing,
			Stale: run.Stale, Restored: run.Restored, Tombstoned: run.Tombstoned, Rejected: run.Rejected,
		},
		FailureCode: optionalString(run.FailureCode), TraceID: optionalString(run.TraceID),
		Version: run.Version, CreatedAt: run.CreatedAt.UTC(),
		StartedAt: cloneTimePointer(run.StartedAt), HeartbeatAt: cloneTimePointer(run.HeartbeatAt),
		CompletedAt:      cloneTimePointer(run.CompletedAt),
		EffectiveActions: effectiveActionStrings(view.EffectiveActions),
	}
}

func sourceRunCounts(run *assetcatalog.SourceRun) *sourceRunCountsDTO {
	if run == nil {
		return nil
	}
	return &sourceRunCountsDTO{
		Observed: run.Observed, Created: run.Created, Changed: run.Changed,
		Unchanged: run.Unchanged, Conflicts: run.Conflicts, Missing: run.Missing,
		Stale: run.Stale, Restored: run.Restored, Tombstoned: run.Tombstoned, Rejected: run.Rejected,
	}
}

func sourceRevisionMutationDTOFrom(
	result assetcatalog.SourceRevisionMutationView,
	traceID string,
) (sourceRevisionMutationDTO, error) {
	receipt, err := mutationReceiptFrom(result.Receipt, traceID)
	if err != nil {
		return sourceRevisionMutationDTO{}, err
	}
	view := assetcatalog.SourceView{
		ReadModel: assetcatalog.SourceReadModel{
			Source: result.Source.Clone(), LatestRevision: result.Revision.Clone(),
		},
		EffectiveActions: slices.Clone(result.EffectiveActions),
	}
	return sourceRevisionMutationDTO{
		Source: toAssetSourceSummaryDTO(view),
		Revision: toSourceRevisionSummaryDTO(
			result.Revision, result.EffectiveActions,
		),
		MutationReceipt: receipt,
	}, nil
}

func sourceMutationDTOFrom(
	result assetcatalog.SourceMutationView,
	traceID string,
) (sourceMutationDTO, error) {
	receipt, err := mutationReceiptFrom(result.Receipt, traceID)
	if err != nil {
		return sourceMutationDTO{}, err
	}
	return sourceMutationDTO{
		Source: toAssetSourceSummaryDTO(assetcatalog.SourceView{
			ReadModel:        assetcatalog.SourceReadModel{Source: result.Source.Clone()},
			EffectiveActions: slices.Clone(result.EffectiveActions),
		}),
		MutationReceipt: receipt,
	}, nil
}

func sourceRunMutationDTOFrom(
	result assetcatalog.SourceRunMutationView,
	traceID string,
) (sourceRunMutationDTO, error) {
	receipt, err := mutationReceiptFrom(result.Receipt, traceID)
	if err != nil {
		return sourceRunMutationDTO{}, err
	}
	currentRun := result.Run.Clone()
	view := assetcatalog.SourceView{
		ReadModel: assetcatalog.SourceReadModel{
			Source: result.Source.Clone(), LatestRevision: result.Revision.Clone(),
			CurrentRun: &currentRun,
		},
		EffectiveActions: slices.Clone(result.EffectiveActions),
	}
	return sourceRunMutationDTO{
		Source: toAssetSourceSummaryDTO(view),
		Revision: toSourceRevisionSummaryDTO(
			result.Revision, result.EffectiveActions,
		),
		Run: toAssetSourceRunDTO(assetcatalog.SourceRunView{
			Run: result.Run.Clone(), EffectiveActions: []assetcatalog.EffectiveAction{},
		}),
		OperationID: result.Run.ID, MutationReceipt: receipt,
	}, nil
}

func writeSourceRevisionMutationResponse(
	writer http.ResponseWriter,
	request *http.Request,
	result assetcatalog.SourceRevisionMutationView,
	err error,
	status int,
) {
	if err != nil {
		writeSourceError(writer, request, err, "asset_source_not_found")
		return
	}
	response, err := sourceRevisionMutationDTOFrom(
		result, requestmeta.From(request.Context()).TraceID,
	)
	if err != nil {
		writeSourceError(writer, request, err, "asset_source_not_found")
		return
	}
	writeSourceRevisionETag(
		writer, result.Source.ID, result.Revision.Revision,
		result.Source.Version, result.Revision.Version,
	)
	if status == http.StatusCreated {
		writer.Header().Set(
			"Location",
			"/api/v1/workspaces/"+result.Source.WorkspaceID+
				"/asset-sources/"+result.Source.ID,
		)
	}
	writeJSON(writer, status, response)
}

func terminalSourceRun(status assetcatalog.RunStatus) bool {
	switch status {
	case assetcatalog.RunStatusSucceeded, assetcatalog.RunStatusPartial,
		assetcatalog.RunStatusFailed, assetcatalog.RunStatusCancelled:
		return true
	default:
		return false
	}
}

func writeSourceError(
	writer http.ResponseWriter,
	request *http.Request,
	err error,
	notFoundCode string,
) {
	switch {
	case errors.Is(err, errUnsupportedControlPlaneMediaType):
		writeRequestProblem(
			writer, request, http.StatusUnsupportedMediaType,
			"unsupported_media_type", "Content-Type is not supported for this Source operation",
		)
	case errors.Is(err, errControlPlaneBodyTooLarge):
		writeRequestProblem(
			writer, request, http.StatusRequestEntityTooLarge,
			"source_payload_rejected", "The Source request exceeds 64 KiB",
		)
	case errors.Is(err, errInvalidControlPlaneRequest), errors.Is(err, assetcatalog.ErrInvalidRequest):
		writeRequestProblem(
			writer, request, http.StatusBadRequest,
			"source_payload_rejected", "The Source request is invalid",
		)
	case errors.Is(err, assetcatalog.ErrSourceRevisionNotValidated):
		writeRequestProblem(
			writer, request, http.StatusConflict,
			"source_revision_not_validated", "The Source revision is not validated",
		)
	case errors.Is(err, assetcatalog.ErrVersionConflict):
		writeRequestProblem(
			writer, request, http.StatusConflict,
			"source_binding_drift", "The Source binding changed",
		)
	case errors.Is(err, assetcatalog.ErrStateConflict):
		writeRequestProblem(
			writer, request, http.StatusConflict,
			"source_gate_unavailable", "The Source gate does not admit this operation",
		)
	case errors.Is(err, errSourceBackpressure):
		writer.Header().Set("Retry-After", "1")
		writeRequestProblem(
			writer, request, http.StatusTooManyRequests,
			"source_backpressure", "The Source is temporarily backpressured",
		)
	case errors.Is(err, authz.ErrReauthenticationRequired):
		writer.Header().Set("WWW-Authenticate", `Bearer error="insufficient_user_authentication"`)
		writeRequestProblem(
			writer, request, http.StatusUnauthorized,
			"reauthentication_required", "Recent OIDC authentication is required",
		)
	default:
		writeAssetCatalogError(writer, request, err, notFoundCode)
	}
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	cloned := value
	return &cloned
}

func optionalPositiveInt64(value int64) *int64 {
	if value <= 0 {
		return nil
	}
	cloned := value
	return &cloned
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}
