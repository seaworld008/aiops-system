package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/authn"
)

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
	Revision               int64     `json:"revision"`
	Status                 string    `json:"status"`
	BindingDigest          string    `json:"binding_digest"`
	SourceDefinitionDigest string    `json:"source_definition_digest"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
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
			Page:  pageMetaDTO{}, EffectiveActions: []string{},
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
		EffectiveActions: effectiveActionStrings(view.EffectiveActions),
	}
}

func toAssetSourceDetailDTO(view assetcatalog.SourceView) assetSourceDetailDTO {
	result := assetSourceDetailDTO{
		Summary:        toAssetSourceSummaryDTO(view),
		LatestRevision: toSourceRevisionSummaryDTO(view.ReadModel.LatestRevision),
	}
	if view.ReadModel.PublishedRevision != nil {
		published := toSourceRevisionSummaryDTO(*view.ReadModel.PublishedRevision)
		result.PublishedRevision = &published
	}
	return result
}

func toSourceRevisionSummaryDTO(value assetcatalog.SourceRevision) sourceRevisionSummaryDTO {
	return sourceRevisionSummaryDTO{
		Revision: value.Revision, Status: string(value.Status),
		BindingDigest:          value.CanonicalRevisionDigest,
		SourceDefinitionDigest: value.SourceDefinitionDigest,
		CreatedAt:              value.CreatedAt.UTC(), UpdatedAt: value.UpdatedAt.UTC(),
	}
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
