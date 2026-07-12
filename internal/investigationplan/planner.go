package investigationplan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/readconnector"
)

const (
	minimumProfiles = 1
	maximumProfiles = 1000
	minimumLabels   = 1
	maximumLabels   = 16
	minimumTasks    = 1
	maximumTasks    = 12
)

var (
	persistentUUIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
	providerPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	labelKeyPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,127}$`)
)

type compiledProfile struct {
	scope          investigation.TaskSpecScope
	registryDigest string
	integrationID  string
	provider       string
	labels         []LabelMatch
	tasks          []investigation.TaskSpec
	tasksHash      string
	profileDigest  string
}

// Planner is immutable after construction and safe for concurrent use.
type Planner struct {
	manifestDigest string
	registryDigest string
	profiles       []compiledProfile
	scopeMarker    *scopeAuthorityState
}

func New(
	ctx context.Context,
	authority *ScopeAuthority,
	registry *readconnector.Registry,
	definition Definition,
) (*Planner, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if authority == nil || authority.marker == nil {
		return nil, ErrInvalidRequest
	}
	if registry == nil || !registry.Ready() || !domain.ValidSHA256Hex(definition.RegistryDigest) ||
		definition.RegistryDigest != registry.Digest() {
		return nil, ErrRegistryMismatch
	}
	if len(definition.Profiles) < minimumProfiles || len(definition.Profiles) > maximumProfiles {
		return nil, ErrInvalidDefinition
	}
	for _, profile := range definition.Profiles {
		if len(profile.Match.Labels) < minimumLabels || len(profile.Match.Labels) > maximumLabels ||
			len(profile.Tasks) < minimumTasks || len(profile.Tasks) > maximumTasks {
			return nil, ErrInvalidDefinition
		}
	}
	withinBudget, err := definitionWithinBudget(definition)
	if err != nil {
		return nil, ErrInvalidDefinition
	}
	if !withinBudget {
		return nil, errors.Join(ErrInvalidDefinition, ErrDefinitionTooLarge)
	}

	compiled := make([]compiledProfile, 0, len(definition.Profiles))
	for _, profile := range definition.Profiles {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		item, err := compileProfile(profile, definition.RegistryDigest)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, item)
	}
	if profilesOverlap(compiled) {
		return nil, ErrProfileOverlap
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	for index := range compiled {
		if err := investigation.AuthorizeTaskSpecs(ctx, registry.AuthorizeTaskSpec, compiled[index].scope, compiled[index].tasks); err != nil {
			if contextErr := contextError(ctx); contextErr != nil {
				return nil, contextErr
			}
			return nil, ErrInvalidDefinition
		}
	}
	manifestDigest, err := digestManifest(definition.RegistryDigest, compiled)
	if err != nil {
		return nil, ErrInvalidDefinition
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	sort.Slice(compiled, func(left, right int) bool {
		return compiled[left].profileDigest < compiled[right].profileDigest
	})
	return &Planner{
		manifestDigest: manifestDigest,
		registryDigest: strings.Clone(definition.RegistryDigest),
		profiles:       compiled,
		scopeMarker:    authority.marker,
	}, nil
}

func compileProfile(definition ProfileDefinition, registryDigest string) (compiledProfile, error) {
	if !validScope(definition.Scope) || !persistentUUIDPattern.MatchString(definition.Match.IntegrationID) ||
		!providerPattern.MatchString(definition.Match.Provider) || !domain.ValidSafeText(definition.Match.Provider) {
		return compiledProfile{}, ErrInvalidDefinition
	}
	labels := make([]LabelMatch, len(definition.Match.Labels))
	for index, label := range definition.Match.Labels {
		labels[index] = LabelMatch{Key: strings.Clone(label.Key), Value: strings.Clone(label.Value)}
	}
	sort.Slice(labels, func(left, right int) bool {
		if labels[left].Key != labels[right].Key {
			return labels[left].Key < labels[right].Key
		}
		return labels[left].Value < labels[right].Value
	})
	for index, label := range labels {
		if !labelKeyPattern.MatchString(label.Key) || label.Value == "" || len(label.Value) > 512 ||
			!domain.ValidSafeMetadata(label.Key, label.Value) || index > 0 && labels[index-1].Key == label.Key {
			return compiledProfile{}, ErrInvalidDefinition
		}
	}
	tasks := make([]investigation.TaskSpec, len(definition.Tasks))
	for index, task := range definition.Tasks {
		tasks[index] = investigation.TaskSpec{
			Key: strings.Clone(task.Key), ConnectorID: strings.Clone(task.ConnectorID),
			Operation: strings.Clone(task.Operation), Input: bytes.Clone(task.Input),
		}
	}
	canonicalTasks, tasksHash, err := investigation.CanonicalTaskSpecs(tasks)
	if err != nil {
		return compiledProfile{}, ErrInvalidDefinition
	}
	scope := investigation.TaskSpecScope{
		TenantID: strings.Clone(definition.Scope.TenantID), WorkspaceID: strings.Clone(definition.Scope.WorkspaceID),
		EnvironmentID: strings.Clone(definition.Scope.EnvironmentID), ServiceID: strings.Clone(definition.Scope.ServiceID),
		MappingStatus: domain.MappingExact,
	}
	item := compiledProfile{
		scope: scope, registryDigest: strings.Clone(registryDigest), integrationID: strings.Clone(definition.Match.IntegrationID),
		provider: strings.Clone(definition.Match.Provider), labels: labels,
		tasks: canonicalTasks, tasksHash: tasksHash,
	}
	item.profileDigest, err = digestProfile(item)
	if err != nil {
		return compiledProfile{}, ErrInvalidDefinition
	}
	return item, nil
}

func validScope(scope Scope) bool {
	return persistentUUIDPattern.MatchString(scope.TenantID) &&
		persistentUUIDPattern.MatchString(scope.WorkspaceID) &&
		persistentUUIDPattern.MatchString(scope.EnvironmentID) &&
		persistentUUIDPattern.MatchString(scope.ServiceID)
}

func profilesOverlap(profiles []compiledProfile) bool {
	for left := 0; left < len(profiles); left++ {
		for right := left + 1; right < len(profiles); right++ {
			if profilesCanMatchSameSignal(profiles[left], profiles[right]) {
				return true
			}
		}
	}
	return false
}

func profilesCanMatchSameSignal(left, right compiledProfile) bool {
	if left.scope.TenantID != right.scope.TenantID || left.scope.WorkspaceID != right.scope.WorkspaceID ||
		left.integrationID != right.integrationID || left.provider != right.provider {
		return false
	}
	for leftIndex, rightIndex := 0, 0; leftIndex < len(left.labels) && rightIndex < len(right.labels); {
		switch {
		case left.labels[leftIndex].Key < right.labels[rightIndex].Key:
			leftIndex++
		case left.labels[leftIndex].Key > right.labels[rightIndex].Key:
			rightIndex++
		default:
			if left.labels[leftIndex].Value != right.labels[rightIndex].Value {
				return false
			}
			leftIndex++
			rightIndex++
		}
	}
	return true
}

func (planner *Planner) ManifestDigest() string {
	if planner == nil {
		return ""
	}
	return planner.manifestDigest
}

func (planner *Planner) Ready() bool {
	return planner != nil && domain.ValidSHA256Hex(planner.manifestDigest) &&
		domain.ValidSHA256Hex(planner.registryDigest) && len(planner.profiles) > 0 &&
		planner.scopeMarker != nil
}

func (planner *Planner) RegistryDigest() string {
	if planner == nil {
		return ""
	}
	return planner.registryDigest
}

func (planner *Planner) Resolve(ctx context.Context, request ResolveRequest) (Plan, error) {
	if err := contextError(ctx); err != nil {
		return Plan{}, err
	}
	if !planner.Ready() ||
		request.ExpectedPlanDigest == "" || request.ExpectedPlanDigest != planner.manifestDigest {
		return Plan{}, ErrPlanDigestMismatch
	}
	if !persistentUUIDPattern.MatchString(request.TrustedScope.tenantID) ||
		!persistentUUIDPattern.MatchString(request.TrustedScope.workspaceID) ||
		request.TrustedScope.marker == nil || request.TrustedScope.marker != planner.scopeMarker {
		return Plan{}, ErrInvalidRequest
	}
	signal, err := investigation.NormalizeSignalForReplay(request.Signal)
	if err != nil || !persistentUUIDPattern.MatchString(signal.ID) ||
		!persistentUUIDPattern.MatchString(signal.WorkspaceID) ||
		!persistentUUIDPattern.MatchString(signal.IntegrationID) ||
		signal.WorkspaceID != request.TrustedScope.workspaceID {
		return Plan{}, ErrInvalidRequest
	}
	matches := make([]compiledProfile, 0, 1)
	for _, profile := range planner.profiles {
		if err := contextError(ctx); err != nil {
			return Plan{}, err
		}
		if profileMatches(profile, request.TrustedScope, signal) {
			matches = append(matches, profile)
		}
	}
	if len(matches) == 0 {
		return Plan{}, ErrMappingUnresolved
	}
	if len(matches) != 1 {
		return Plan{}, ErrPlannerIntegrity
	}
	matched := matches[0]
	correlationKey, err := correlationKey(matched, signal)
	if err != nil {
		return Plan{}, ErrPlannerIntegrity
	}
	if err := contextError(ctx); err != nil {
		return Plan{}, err
	}
	return Plan{
		manifestDigest: planner.manifestDigest,
		profileDigest:  matched.profileDigest,
		registryDigest: planner.registryDigest,
		tasksHash:      matched.tasksHash,
		scope:          matched.scope,
		tasks:          cloneTaskSpecs(matched.tasks),
		correlation: investigation.CorrelateSignalRequest{
			WorkspaceID: strings.Clone(signal.WorkspaceID), SignalID: strings.Clone(signal.ID), CorrelationKey: correlationKey,
			ServiceID: matched.scope.ServiceID, EnvironmentID: matched.scope.EnvironmentID,
			MappingStatus: domain.MappingExact,
		},
	}, nil
}

func profileMatches(profile compiledProfile, trusted TrustedSignalScope, signal domain.Signal) bool {
	if profile.scope.TenantID != trusted.tenantID || profile.scope.WorkspaceID != trusted.workspaceID ||
		profile.integrationID != signal.IntegrationID || profile.provider != signal.Provider {
		return false
	}
	for _, label := range profile.labels {
		if signal.Labels[label.Key] != label.Value {
			return false
		}
	}
	return true
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidRequest
	}
	return ctx.Err()
}

func (Planner) String() string   { return "InvestigationPlanner{[REDACTED]}" }
func (Planner) GoString() string { return "InvestigationPlanner{[REDACTED]}" }
func (planner Planner) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, planner.String())
}
func (Planner) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Planner) UnmarshalJSON([]byte) error {
	return errors.Join(ErrInvalidDefinition, ErrManifestDefinition)
}
