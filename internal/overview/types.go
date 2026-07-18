package overview

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/domain"
)

var (
	ErrInvalidRequest = errors.New("invalid overview request")
	ErrNotFound       = errors.New("overview not found")
	ErrForbidden      = errors.New("overview forbidden")
	ErrUnavailable    = errors.New("overview unavailable")
)

const maxSafeCount int64 = 9_007_199_254_740_991

type Feature string

const (
	FeatureAssets         Feature = "ASSETS"
	FeatureSources        Feature = "SOURCES"
	FeatureConnections    Feature = "CONNECTIONS"
	FeatureInvestigations Feature = "INVESTIGATIONS"
	FeatureActions        Feature = "ACTIONS"
	FeatureReleases       Feature = "RELEASES"
)

var allFeatures = []Feature{
	FeatureAssets,
	FeatureSources,
	FeatureConnections,
	FeatureInvestigations,
	FeatureActions,
	FeatureReleases,
}

func AllFeatures() []Feature { return slices.Clone(allFeatures) }

func (feature Feature) Valid() bool { return slices.Contains(allFeatures, feature) }

type ImplementationState string

const (
	StateNotStarted  ImplementationState = "NOT_STARTED"
	StateUnavailable ImplementationState = "UNAVAILABLE"
	StatePartial     ImplementationState = "PARTIAL"
	StateAvailable   ImplementationState = "AVAILABLE"
	StateDegraded    ImplementationState = "DEGRADED"
	StateSuspended   ImplementationState = "SUSPENDED"
)

var allImplementationStates = []ImplementationState{
	StateNotStarted,
	StateUnavailable,
	StatePartial,
	StateAvailable,
	StateDegraded,
	StateSuspended,
}

func (state ImplementationState) Valid() bool {
	return slices.Contains(allImplementationStates, state)
}

type SectionCode string

const (
	CodeNotImplemented    SectionCode = "NOT_IMPLEMENTED"
	CodeModuleUnavailable SectionCode = "MODULE_UNAVAILABLE"
	CodeAggregatePartial  SectionCode = "AGGREGATE_PARTIAL"
	CodeReady             SectionCode = "READY"
	CodeStaleEvidence     SectionCode = "STALE_EVIDENCE"
	CodeSuspended         SectionCode = "SUSPENDED"
)

func (code SectionCode) Valid() bool {
	switch code {
	case CodeNotImplemented, CodeModuleUnavailable, CodeAggregatePartial,
		CodeReady, CodeStaleEvidence, CodeSuspended:
		return true
	default:
		return false
	}
}

type StateCount struct {
	State string
	Count int64
}

type ProviderGateSummary struct {
	ProviderKind string                        `json:"provider_kind"`
	GateStatus   assetcatalog.SourceGateStatus `json:"gate_status"`
	SourceCount  int64                         `json:"source_count"`
	EvidenceAt   *time.Time                    `json:"evidence_at"`
}

type AssetFacts struct {
	ObservedAt        time.Time
	Total             int64
	Lifecycles        []StateCount
	MappingStatuses   []StateCount
	StaleCount        int64
	OldestStaleAt     *time.Time
	OpenConflictCount int64
}

func (facts AssetFacts) Clone() AssetFacts {
	facts.Lifecycles = slices.Clone(facts.Lifecycles)
	facts.MappingStatuses = slices.Clone(facts.MappingStatuses)
	facts.OldestStaleAt = cloneTime(facts.OldestStaleAt)
	return facts
}

func (facts AssetFacts) Valid() bool {
	lifecycles := []string{
		string(assetcatalog.LifecycleDiscovered),
		string(assetcatalog.LifecycleActive),
		string(assetcatalog.LifecycleStale),
		string(assetcatalog.LifecycleQuarantined),
		string(assetcatalog.LifecycleRetired),
	}
	mappings := []string{
		string(domain.MappingExact),
		string(domain.MappingAmbiguous),
		string(domain.MappingUnresolved),
	}
	return validObservedTime(facts.ObservedAt) &&
		validCount(facts.Total) &&
		validStateCounts(facts.Lifecycles, lifecycles, facts.Total) &&
		validStateCounts(facts.MappingStatuses, mappings, facts.Total) &&
		validCount(facts.StaleCount) &&
		facts.StaleCount == stateCount(facts.Lifecycles, string(assetcatalog.LifecycleStale)) &&
		validOptionalObservedTime(facts.OldestStaleAt) &&
		(facts.StaleCount > 0) == (facts.OldestStaleAt != nil) &&
		validCount(facts.OpenConflictCount)
}

type SourceFacts struct {
	ObservedAt         time.Time
	Total              int64
	Statuses           []StateCount
	RevisionStatuses   []StateCount
	GateStatuses       []StateCount
	RunStatuses        []StateCount
	BackpressuredCount int64
	ProviderGates      []ProviderGateSummary
}

func (facts SourceFacts) Clone() SourceFacts {
	facts.Statuses = slices.Clone(facts.Statuses)
	facts.RevisionStatuses = slices.Clone(facts.RevisionStatuses)
	facts.GateStatuses = slices.Clone(facts.GateStatuses)
	facts.RunStatuses = slices.Clone(facts.RunStatuses)
	facts.ProviderGates = slices.Clone(facts.ProviderGates)
	for index := range facts.ProviderGates {
		facts.ProviderGates[index].EvidenceAt = cloneTime(facts.ProviderGates[index].EvidenceAt)
	}
	return facts
}

func (facts SourceFacts) Valid() bool {
	statuses := []string{
		string(assetcatalog.SourceStatusActive),
		string(assetcatalog.SourceStatusPaused),
		string(assetcatalog.SourceStatusDegraded),
		string(assetcatalog.SourceStatusDisabled),
	}
	revisions := []string{
		string(assetcatalog.SourceRevisionDraft),
		string(assetcatalog.SourceRevisionValidating),
		string(assetcatalog.SourceRevisionValidated),
		string(assetcatalog.SourceRevisionRejected),
		string(assetcatalog.SourceRevisionPublished),
		string(assetcatalog.SourceRevisionSuperseded),
	}
	gates := []string{
		string(assetcatalog.SourceGateUnavailable),
		string(assetcatalog.SourceGateValidating),
		string(assetcatalog.SourceGateAvailable),
		string(assetcatalog.SourceGateDegraded),
		string(assetcatalog.SourceGateSuspended),
	}
	runs := []string{
		string(assetcatalog.RunStatusQueued),
		string(assetcatalog.RunStatusDelayed),
		string(assetcatalog.RunStatusRunning),
		string(assetcatalog.RunStatusFinalizing),
		string(assetcatalog.RunStatusSucceeded),
		string(assetcatalog.RunStatusPartial),
		string(assetcatalog.RunStatusFailed),
		string(assetcatalog.RunStatusCancelled),
	}
	if !validObservedTime(facts.ObservedAt) ||
		!validCount(facts.Total) ||
		!validStateCounts(facts.Statuses, statuses, facts.Total) ||
		!validStateCounts(facts.RevisionStatuses, revisions, -1) ||
		!validStateCounts(facts.GateStatuses, gates, facts.Total) ||
		!validStateCounts(facts.RunStatuses, runs, -1) ||
		!validCount(facts.BackpressuredCount) ||
		facts.BackpressuredCount > facts.Total ||
		len(facts.ProviderGates) > 128 {
		return false
	}
	var providerTotal int64
	seen := make(map[string]struct{}, len(facts.ProviderGates))
	for _, summary := range facts.ProviderGates {
		key := summary.ProviderKind + "\x00" + string(summary.GateStatus)
		if !safeProviderKindPattern.MatchString(summary.ProviderKind) ||
			!summary.GateStatus.Valid() ||
			!validCount(summary.SourceCount) ||
			summary.SourceCount == 0 ||
			!validOptionalObservedTime(summary.EvidenceAt) {
			return false
		}
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
		if providerTotal > maxSafeCount-summary.SourceCount {
			return false
		}
		providerTotal += summary.SourceCount
	}
	return providerTotal == facts.Total
}

type Section struct {
	State       ImplementationState
	Code        SectionCode
	ObservedAt  time.Time
	AssetFacts  *AssetFacts
	SourceFacts *SourceFacts
}

func (section Section) Clone() Section {
	if section.AssetFacts != nil {
		value := section.AssetFacts.Clone()
		section.AssetFacts = &value
	}
	if section.SourceFacts != nil {
		value := section.SourceFacts.Clone()
		section.SourceFacts = &value
	}
	return section
}

type WorkQueueKey string

const (
	QueueOpenConflicts      WorkQueueKey = "OPEN_CONFLICTS"
	QueueStaleAssets        WorkQueueKey = "STALE_ASSETS"
	QueueUnavailableSources WorkQueueKey = "UNAVAILABLE_SOURCES"
	QueueDegradedSources    WorkQueueKey = "DEGRADED_SOURCES"
)

var allWorkQueues = []WorkQueueKey{
	QueueOpenConflicts,
	QueueStaleAssets,
	QueueUnavailableSources,
	QueueDegradedSources,
}

type WorkQueue struct {
	Key     WorkQueueKey
	Section Feature
	State   ImplementationState
	Count   *int64
}

func (queue WorkQueue) Clone() WorkQueue {
	if queue.Count != nil {
		value := *queue.Count
		queue.Count = &value
	}
	return queue
}

type EffectiveAction string

const (
	ActionViewAssets         EffectiveAction = "VIEW_ASSETS"
	ActionViewSources        EffectiveAction = "VIEW_SOURCES"
	ActionViewConnections    EffectiveAction = "VIEW_CONNECTIONS"
	ActionViewInvestigations EffectiveAction = "VIEW_INVESTIGATIONS"
	ActionViewActions        EffectiveAction = "VIEW_ACTIONS"
	ActionViewReleases       EffectiveAction = "VIEW_RELEASES"
)

var allEffectiveActions = []EffectiveAction{
	ActionViewAssets,
	ActionViewSources,
	ActionViewConnections,
	ActionViewInvestigations,
	ActionViewActions,
	ActionViewReleases,
}

type Snapshot struct {
	Scope            assetcatalog.Scope
	GeneratedAt      time.Time
	Sections         map[Feature]Section
	WorkQueues       []WorkQueue
	EffectiveActions []EffectiveAction
}

func (snapshot Snapshot) Clone() Snapshot {
	sections := snapshot.Sections
	snapshot.Sections = make(map[Feature]Section, len(snapshot.Sections))
	for feature, section := range sections {
		snapshot.Sections[feature] = section.Clone()
	}
	snapshot.WorkQueues = slices.Clone(snapshot.WorkQueues)
	for index := range snapshot.WorkQueues {
		snapshot.WorkQueues[index] = snapshot.WorkQueues[index].Clone()
	}
	snapshot.EffectiveActions = slices.Clone(snapshot.EffectiveActions)
	return snapshot
}

func (snapshot Snapshot) Valid() bool {
	if !snapshot.Scope.Valid() || !validObservedTime(snapshot.GeneratedAt) ||
		len(snapshot.Sections) != len(allFeatures) ||
		len(snapshot.WorkQueues) != len(allWorkQueues) ||
		!validEffectiveActions(snapshot.EffectiveActions) {
		return false
	}
	for _, feature := range allFeatures {
		section, ok := snapshot.Sections[feature]
		if !ok || !validSection(feature, section) {
			return false
		}
	}
	for index, key := range allWorkQueues {
		queue := snapshot.WorkQueues[index]
		if queue.Key != key || !queue.Section.Valid() || !queue.State.Valid() {
			return false
		}
		section := snapshot.Sections[queue.Section]
		if queue.State != section.State ||
			(queue.Count != nil && !validCount(*queue.Count)) ||
			(queue.Count != nil) != sectionFactsTrusted(section.State) {
			return false
		}
	}
	return true
}

type Manager interface {
	Get(context.Context, authn.Principal, string, string) (Snapshot, error)
}

type FeatureReadiness interface {
	State(context.Context, assetcatalog.Scope, Feature) (ImplementationState, error)
}

var safeProviderKindPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

func validSection(feature Feature, section Section) bool {
	if !section.State.Valid() || !section.Code.Valid() || !validObservedTime(section.ObservedAt) {
		return false
	}
	switch section.State {
	case StateNotStarted:
		if section.Code != CodeNotImplemented {
			return false
		}
	case StateUnavailable:
		if section.Code != CodeModuleUnavailable {
			return false
		}
	case StatePartial:
		if section.Code != CodeAggregatePartial {
			return false
		}
	case StateAvailable:
		if section.Code != CodeReady {
			return false
		}
	case StateDegraded:
		if section.Code != CodeStaleEvidence {
			return false
		}
	case StateSuspended:
		if section.Code != CodeSuspended {
			return false
		}
	}
	switch feature {
	case FeatureAssets:
		if sectionFactsTrusted(section.State) {
			return section.AssetFacts != nil && section.AssetFacts.Valid() && section.SourceFacts == nil
		}
	case FeatureSources:
		if sectionFactsTrusted(section.State) {
			return section.SourceFacts != nil && section.SourceFacts.Valid() && section.AssetFacts == nil
		}
	default:
		return section.AssetFacts == nil && section.SourceFacts == nil
	}
	return section.AssetFacts == nil && section.SourceFacts == nil
}

func sectionFactsTrusted(state ImplementationState) bool {
	return state == StateAvailable || state == StateDegraded
}

func validEffectiveActions(actions []EffectiveAction) bool {
	if len(actions) > len(allEffectiveActions) {
		return false
	}
	lastIndex := -1
	for _, action := range actions {
		index := slices.Index(allEffectiveActions, action)
		if index <= lastIndex {
			return false
		}
		lastIndex = index
	}
	return true
}

func validStateCounts(values []StateCount, allowed []string, wantTotal int64) bool {
	if len(values) != len(allowed) {
		return false
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, state := range allowed {
		allowedSet[state] = struct{}{}
	}
	var total int64
	for _, value := range values {
		if _, ok := allowedSet[value.State]; !ok || !validCount(value.Count) {
			return false
		}
		delete(allowedSet, value.State)
		if total > maxSafeCount-value.Count {
			return false
		}
		total += value.Count
	}
	return len(allowedSet) == 0 && (wantTotal < 0 || total == wantTotal)
}

func stateCount(values []StateCount, state string) int64 {
	for _, value := range values {
		if value.State == state {
			return value.Count
		}
	}
	return -1
}

func validCount(value int64) bool { return value >= 0 && value <= maxSafeCount }

func validObservedTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 2000 && value.Year() <= 9999
}

func validOptionalObservedTime(value *time.Time) bool {
	return value == nil || validObservedTime(*value)
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
