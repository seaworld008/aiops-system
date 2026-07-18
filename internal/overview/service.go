package overview

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/authz"
)

const (
	defaultQueryTimeout = 500 * time.Millisecond
	defaultStaleAfter   = 2 * time.Minute
)

type ScopeResolver interface {
	ResolveScope(context.Context, string, string) (assetcatalog.Scope, error)
}

type FactsRepository interface {
	FeatureReadiness
	ReadAssetFacts(context.Context, assetcatalog.Scope) (AssetFacts, error)
	ReadSourceFacts(context.Context, assetcatalog.Scope) (SourceFacts, error)
}

type Authorizer interface {
	Authorize(authn.Principal, authz.Request) error
}

type Options struct {
	Clock        func() time.Time
	QueryTimeout time.Duration
	StaleAfter   time.Duration
}

type Service struct {
	scopes       ScopeResolver
	facts        FactsRepository
	authorizer   Authorizer
	clock        func() time.Time
	queryTimeout time.Duration
	staleAfter   time.Duration
}

func NewService(
	scopes ScopeResolver,
	facts FactsRepository,
	authorizer Authorizer,
	options Options,
) (*Service, error) {
	if nilDependency(scopes) || nilDependency(facts) || nilDependency(authorizer) {
		return nil, errors.New("overview scope resolver, facts repository, and authorizer are required")
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.QueryTimeout == 0 {
		options.QueryTimeout = defaultQueryTimeout
	}
	if options.StaleAfter == 0 {
		options.StaleAfter = defaultStaleAfter
	}
	if options.QueryTimeout <= 0 || options.QueryTimeout > defaultQueryTimeout ||
		options.StaleAfter < time.Minute || options.StaleAfter > 15*time.Minute {
		return nil, errors.New("overview query timeout and stale threshold are outside closed bounds")
	}
	return &Service{
		scopes:       scopes,
		facts:        facts,
		authorizer:   authorizer,
		clock:        options.Clock,
		queryTimeout: options.QueryTimeout,
		staleAfter:   options.StaleAfter,
	}, nil
}

func (service *Service) Get(
	ctx context.Context,
	principal authn.Principal,
	workspaceID string,
	environmentID string,
) (Snapshot, error) {
	if service == nil || nilDependency(service.scopes) || nilDependency(service.facts) ||
		nilDependency(service.authorizer) {
		return Snapshot{}, ErrUnavailable
	}
	requested := assetcatalog.Scope{
		TenantID: principal.TenantID, WorkspaceID: workspaceID, EnvironmentID: environmentID,
	}
	if !requested.Valid() {
		return Snapshot{}, ErrInvalidRequest
	}
	if !slices.Contains(principal.WorkspaceIDs, workspaceID) ||
		!slices.Contains(principal.EnvironmentIDs, environmentID) {
		return Snapshot{}, ErrNotFound
	}

	resolveContext, cancelResolve := context.WithTimeout(ctx, service.queryTimeout)
	resolved, err := service.scopes.ResolveScope(resolveContext, workspaceID, environmentID)
	cancelResolve()
	if err != nil {
		return Snapshot{}, mapScopeError(err)
	}
	if !resolved.Valid() || resolved != requested {
		return Snapshot{}, ErrNotFound
	}
	if err := service.authorizer.Authorize(principal, authz.Request{
		Permission:    authz.PermissionAssetRead,
		WorkspaceID:   resolved.WorkspaceID,
		EnvironmentID: resolved.EnvironmentID,
	}); err != nil {
		return Snapshot{}, ErrForbidden
	}

	generatedAt := service.clock().UTC()
	if !validObservedTime(generatedAt) {
		return Snapshot{}, ErrUnavailable
	}
	sections := map[Feature]Section{
		FeatureConnections:    notStartedSection(generatedAt),
		FeatureInvestigations: notStartedSection(generatedAt),
		FeatureActions:        notStartedSection(generatedAt),
		FeatureReleases:       notStartedSection(generatedAt),
	}

	type result struct {
		feature Feature
		section Section
	}
	results := make(chan result, 2)
	for _, feature := range []Feature{FeatureAssets, FeatureSources} {
		feature := feature
		go func() {
			results <- result{
				feature: feature,
				section: service.projectImplementedSection(ctx, resolved, feature, generatedAt),
			}
		}()
	}
	for range 2 {
		projected := <-results
		sections[projected.feature] = projected.section
	}

	snapshot := Snapshot{
		Scope:            resolved,
		GeneratedAt:      generatedAt,
		Sections:         sections,
		WorkQueues:       buildWorkQueues(sections),
		EffectiveActions: service.effectiveActions(principal, resolved, sections),
	}
	if !snapshot.Valid() {
		return Snapshot{}, ErrUnavailable
	}
	return snapshot.Clone(), nil
}

func (service *Service) projectImplementedSection(
	parent context.Context,
	scope assetcatalog.Scope,
	feature Feature,
	generatedAt time.Time,
) Section {
	queryContext, cancel := context.WithTimeout(parent, service.queryTimeout)
	defer cancel()

	state, err := service.facts.State(queryContext, scope, feature)
	if err != nil || !state.Valid() {
		return partialSection(generatedAt)
	}
	switch state {
	case StateNotStarted:
		return notStartedSection(generatedAt)
	case StateUnavailable:
		return unavailableSection(generatedAt)
	case StatePartial:
		return partialSection(generatedAt)
	case StateSuspended:
		return Section{State: StateSuspended, Code: CodeSuspended, ObservedAt: generatedAt}
	}

	switch feature {
	case FeatureAssets:
		facts, readErr := service.facts.ReadAssetFacts(queryContext, scope)
		facts = normalizedAssetFacts(facts)
		if readErr != nil || !facts.Valid() {
			return partialSection(generatedAt)
		}
		projectedState, code := service.evidenceState(state, facts.ObservedAt, generatedAt)
		return Section{
			State: projectedState, Code: code, ObservedAt: facts.ObservedAt, AssetFacts: &facts,
		}
	case FeatureSources:
		facts, readErr := service.facts.ReadSourceFacts(queryContext, scope)
		facts = normalizedSourceFacts(facts)
		if readErr != nil || !facts.Valid() {
			return partialSection(generatedAt)
		}
		projectedState, code := service.evidenceState(state, facts.ObservedAt, generatedAt)
		return Section{
			State: projectedState, Code: code, ObservedAt: facts.ObservedAt, SourceFacts: &facts,
		}
	default:
		return notStartedSection(generatedAt)
	}
}

func (service *Service) evidenceState(
	readiness ImplementationState,
	observedAt time.Time,
	generatedAt time.Time,
) (ImplementationState, SectionCode) {
	if readiness == StateDegraded ||
		observedAt.After(generatedAt.Add(30*time.Second)) ||
		generatedAt.Sub(observedAt) > service.staleAfter {
		return StateDegraded, CodeStaleEvidence
	}
	return StateAvailable, CodeReady
}

func (service *Service) effectiveActions(
	principal authn.Principal,
	scope assetcatalog.Scope,
	sections map[Feature]Section,
) []EffectiveAction {
	actions := make([]EffectiveAction, 0, 2)
	if sectionFactsTrusted(sections[FeatureAssets].State) {
		actions = append(actions, ActionViewAssets)
	}
	if sectionFactsTrusted(sections[FeatureSources].State) &&
		service.authorizer.Authorize(principal, authz.Request{
			Permission:    authz.PermissionAssetSourceRead,
			WorkspaceID:   scope.WorkspaceID,
			EnvironmentID: scope.EnvironmentID,
		}) == nil {
		actions = append(actions, ActionViewSources)
	}
	return actions
}

func buildWorkQueues(sections map[Feature]Section) []WorkQueue {
	assets := sections[FeatureAssets]
	sources := sections[FeatureSources]
	queues := []WorkQueue{
		{Key: QueueOpenConflicts, Section: FeatureAssets, State: assets.State},
		{Key: QueueStaleAssets, Section: FeatureAssets, State: assets.State},
		{Key: QueueUnavailableSources, Section: FeatureSources, State: sources.State},
		{Key: QueueDegradedSources, Section: FeatureSources, State: sources.State},
	}
	if sectionFactsTrusted(assets.State) && assets.AssetFacts != nil {
		queues[0].Count = countPointer(assets.AssetFacts.OpenConflictCount)
		queues[1].Count = countPointer(assets.AssetFacts.StaleCount)
	}
	if sectionFactsTrusted(sources.State) && sources.SourceFacts != nil {
		queues[2].Count = countPointer(stateCount(
			sources.SourceFacts.GateStatuses,
			string(assetcatalog.SourceGateUnavailable),
		))
		queues[3].Count = countPointer(stateCount(
			sources.SourceFacts.Statuses,
			string(assetcatalog.SourceStatusDegraded),
		))
	}
	return queues
}

func notStartedSection(observedAt time.Time) Section {
	return Section{State: StateNotStarted, Code: CodeNotImplemented, ObservedAt: observedAt}
}

func unavailableSection(observedAt time.Time) Section {
	return Section{State: StateUnavailable, Code: CodeModuleUnavailable, ObservedAt: observedAt}
}

func partialSection(observedAt time.Time) Section {
	return Section{State: StatePartial, Code: CodeAggregatePartial, ObservedAt: observedAt}
}

func normalizedAssetFacts(facts AssetFacts) AssetFacts {
	facts = facts.Clone()
	facts.ObservedAt = facts.ObservedAt.UTC()
	if facts.OldestStaleAt != nil {
		value := facts.OldestStaleAt.UTC()
		facts.OldestStaleAt = &value
	}
	sort.Slice(facts.Lifecycles, func(left, right int) bool {
		return facts.Lifecycles[left].State < facts.Lifecycles[right].State
	})
	sort.Slice(facts.MappingStatuses, func(left, right int) bool {
		return facts.MappingStatuses[left].State < facts.MappingStatuses[right].State
	})
	return facts
}

func normalizedSourceFacts(facts SourceFacts) SourceFacts {
	facts = facts.Clone()
	facts.ObservedAt = facts.ObservedAt.UTC()
	for _, counts := range [][]StateCount{
		facts.Statuses,
		facts.RevisionStatuses,
		facts.GateStatuses,
		facts.RunStatuses,
	} {
		sort.Slice(counts, func(left, right int) bool {
			return counts[left].State < counts[right].State
		})
	}
	for index := range facts.ProviderGates {
		if facts.ProviderGates[index].EvidenceAt != nil {
			value := facts.ProviderGates[index].EvidenceAt.UTC()
			facts.ProviderGates[index].EvidenceAt = &value
		}
	}
	sort.Slice(facts.ProviderGates, func(left, right int) bool {
		if facts.ProviderGates[left].ProviderKind == facts.ProviderGates[right].ProviderKind {
			return facts.ProviderGates[left].GateStatus < facts.ProviderGates[right].GateStatus
		}
		return facts.ProviderGates[left].ProviderKind < facts.ProviderGates[right].ProviderKind
	})
	return facts
}

func mapScopeError(err error) error {
	switch {
	case errors.Is(err, assetcatalog.ErrInvalidRequest):
		return ErrInvalidRequest
	case errors.Is(err, assetcatalog.ErrNotFound),
		errors.Is(err, assetcatalog.ErrScopeViolation):
		return ErrNotFound
	default:
		return ErrUnavailable
	}
}

func countPointer(value int64) *int64 { return &value }

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
