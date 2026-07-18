package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/overview"
)

type overviewScopeDTO struct {
	WorkspaceID   string `json:"workspace_id"`
	EnvironmentID string `json:"environment_id"`
}

type overviewStateCountDTO struct {
	State string `json:"state"`
	Count int64  `json:"count"`
}

type overviewProviderGateDTO struct {
	ProviderKind string     `json:"provider_kind"`
	GateStatus   string     `json:"gate_status"`
	SourceCount  int64      `json:"source_count"`
	EvidenceAt   *time.Time `json:"evidence_at"`
}

type overviewAssetFactsDTO struct {
	Total             int64                   `json:"total"`
	Lifecycles        []overviewStateCountDTO `json:"lifecycles"`
	MappingStatuses   []overviewStateCountDTO `json:"mapping_statuses"`
	StaleCount        int64                   `json:"stale_count"`
	OldestStaleAt     *time.Time              `json:"oldest_stale_at"`
	OpenConflictCount int64                   `json:"open_conflict_count"`
}

type overviewSourceFactsDTO struct {
	Total              int64                     `json:"total"`
	Statuses           []overviewStateCountDTO   `json:"statuses"`
	RevisionStatuses   []overviewStateCountDTO   `json:"revision_statuses"`
	GateStatuses       []overviewStateCountDTO   `json:"gate_statuses"`
	RunStatuses        []overviewStateCountDTO   `json:"run_statuses"`
	BackpressuredCount int64                     `json:"backpressured_count"`
	ProviderGates      []overviewProviderGateDTO `json:"provider_gates"`
}

type overviewSectionDTO struct {
	State       string                  `json:"state"`
	Code        string                  `json:"code"`
	ObservedAt  time.Time               `json:"observed_at"`
	AssetFacts  *overviewAssetFactsDTO  `json:"asset_facts"`
	SourceFacts *overviewSourceFactsDTO `json:"source_facts"`
}

type overviewSectionsDTO struct {
	Assets         overviewSectionDTO `json:"ASSETS"`
	Sources        overviewSectionDTO `json:"SOURCES"`
	Connections    overviewSectionDTO `json:"CONNECTIONS"`
	Investigations overviewSectionDTO `json:"INVESTIGATIONS"`
	Actions        overviewSectionDTO `json:"ACTIONS"`
	Releases       overviewSectionDTO `json:"RELEASES"`
}

type overviewWorkQueueDTO struct {
	Key     string `json:"key"`
	Section string `json:"section"`
	State   string `json:"state"`
	Count   *int64 `json:"count"`
}

type overviewSnapshotDTO struct {
	Scope            overviewScopeDTO       `json:"scope"`
	GeneratedAt      time.Time              `json:"generated_at"`
	Sections         overviewSectionsDTO    `json:"sections"`
	WorkQueues       []overviewWorkQueueDTO `json:"work_queues"`
	EffectiveActions []string               `json:"effective_actions"`
}

func overviewHandler(manager overview.Manager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if nilHTTPDependency(manager) {
			writeOverviewError(writer, request, overview.ErrUnavailable)
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeRequestProblem(
				writer,
				request,
				http.StatusUnauthorized,
				"authentication_required",
				"A valid OIDC bearer token is required",
			)
			return
		}
		snapshot, err := manager.Get(
			request.Context(),
			principal,
			chi.URLParam(request, "workspaceID"),
			chi.URLParam(request, "environmentID"),
		)
		if err != nil {
			writeOverviewError(writer, request, err)
			return
		}
		if !snapshot.Valid() {
			writeOverviewError(writer, request, errors.New("invalid overview snapshot"))
			return
		}
		body, err := json.Marshal(projectOverviewSnapshot(snapshot))
		if err != nil {
			writeOverviewError(writer, request, errors.New("overview projection failed"))
			return
		}
		body = append(body, '\n')
		digest := sha256.Sum256(body)
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("ETag", `"overview:`+hex.EncodeToString(digest[:])+`"`)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(body)
	}
}

func projectOverviewSnapshot(snapshot overview.Snapshot) overviewSnapshotDTO {
	actions := make([]string, len(snapshot.EffectiveActions))
	for index, action := range snapshot.EffectiveActions {
		actions[index] = string(action)
	}
	queues := make([]overviewWorkQueueDTO, len(snapshot.WorkQueues))
	for index, queue := range snapshot.WorkQueues {
		queues[index] = overviewWorkQueueDTO{
			Key: string(queue.Key), Section: string(queue.Section),
			State: string(queue.State), Count: queue.Count,
		}
	}
	return overviewSnapshotDTO{
		Scope: overviewScopeDTO{
			WorkspaceID: snapshot.Scope.WorkspaceID, EnvironmentID: snapshot.Scope.EnvironmentID,
		},
		GeneratedAt: snapshot.GeneratedAt.UTC(),
		Sections: overviewSectionsDTO{
			Assets:         projectOverviewSection(snapshot.Sections[overview.FeatureAssets]),
			Sources:        projectOverviewSection(snapshot.Sections[overview.FeatureSources]),
			Connections:    projectOverviewSection(snapshot.Sections[overview.FeatureConnections]),
			Investigations: projectOverviewSection(snapshot.Sections[overview.FeatureInvestigations]),
			Actions:        projectOverviewSection(snapshot.Sections[overview.FeatureActions]),
			Releases:       projectOverviewSection(snapshot.Sections[overview.FeatureReleases]),
		},
		WorkQueues:       queues,
		EffectiveActions: actions,
	}
}

func projectOverviewSection(section overview.Section) overviewSectionDTO {
	dto := overviewSectionDTO{
		State: string(section.State), Code: string(section.Code), ObservedAt: section.ObservedAt.UTC(),
	}
	if section.AssetFacts != nil {
		dto.AssetFacts = &overviewAssetFactsDTO{
			Total:             section.AssetFacts.Total,
			Lifecycles:        projectOverviewCounts(section.AssetFacts.Lifecycles),
			MappingStatuses:   projectOverviewCounts(section.AssetFacts.MappingStatuses),
			StaleCount:        section.AssetFacts.StaleCount,
			OldestStaleAt:     utcTimePointer(section.AssetFacts.OldestStaleAt),
			OpenConflictCount: section.AssetFacts.OpenConflictCount,
		}
	}
	if section.SourceFacts != nil {
		providerGates := make([]overviewProviderGateDTO, len(section.SourceFacts.ProviderGates))
		for index, summary := range section.SourceFacts.ProviderGates {
			providerGates[index] = overviewProviderGateDTO{
				ProviderKind: summary.ProviderKind, GateStatus: string(summary.GateStatus),
				SourceCount: summary.SourceCount, EvidenceAt: utcTimePointer(summary.EvidenceAt),
			}
		}
		dto.SourceFacts = &overviewSourceFactsDTO{
			Total:              section.SourceFacts.Total,
			Statuses:           projectOverviewCounts(section.SourceFacts.Statuses),
			RevisionStatuses:   projectOverviewCounts(section.SourceFacts.RevisionStatuses),
			GateStatuses:       projectOverviewCounts(section.SourceFacts.GateStatuses),
			RunStatuses:        projectOverviewCounts(section.SourceFacts.RunStatuses),
			BackpressuredCount: section.SourceFacts.BackpressuredCount,
			ProviderGates:      providerGates,
		}
	}
	return dto
}

func projectOverviewCounts(values []overview.StateCount) []overviewStateCountDTO {
	counts := make([]overviewStateCountDTO, len(values))
	for index, value := range values {
		counts[index] = overviewStateCountDTO{State: value.State, Count: value.Count}
	}
	return counts
}

func utcTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	utc := value.UTC()
	return &utc
}

func writeOverviewError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, overview.ErrInvalidRequest):
		writeRequestProblem(
			writer, request, http.StatusBadRequest,
			"invalid_overview_request", "The overview request is invalid",
		)
	case errors.Is(err, overview.ErrNotFound):
		writeRequestProblem(
			writer, request, http.StatusNotFound,
			"overview_not_found", "The requested overview was not found",
		)
	case errors.Is(err, overview.ErrForbidden):
		writeRequestProblem(
			writer, request, http.StatusForbidden,
			"overview_forbidden", "The overview is not authorized for this scope",
		)
	case errors.Is(err, overview.ErrUnavailable):
		writeRequestProblem(
			writer, request, http.StatusServiceUnavailable,
			"overview_unavailable", "The overview is unavailable",
		)
	default:
		writeRequestProblem(
			writer, request, http.StatusInternalServerError,
			"overview_failed", "The overview could not be generated",
		)
	}
}
