package catalog

import (
	"sort"

	"github.com/aiops-system/control-plane/internal/domain"
)

type MappingStatus = domain.MappingStatus

const (
	MappingExact      = domain.MappingExact
	MappingAmbiguous  = domain.MappingAmbiguous
	MappingUnresolved = domain.MappingUnresolved
)

type ResolutionReason string

const (
	ReasonUniqueExplicitMatch     ResolutionReason = "exactly one explicit binding matched"
	ReasonMultipleExplicitMatches ResolutionReason = "multiple explicit bindings matched"
	ReasonNoExplicitMatch         ResolutionReason = "no explicit binding matched"
)

// ServiceBinding is an explicit rule for mapping alert labels to a service in
// one workspace and environment.
type ServiceBinding struct {
	ID            string
	WorkspaceID   string
	EnvironmentID string
	ServiceID     string
	MatchLabels   map[string]string
}

type ResolveInput struct {
	WorkspaceID   string
	EnvironmentID string
	AlertLabels   map[string]string
}

type Resolution struct {
	Status              MappingStatus
	CandidateServiceIDs []string
	Reason              ResolutionReason
}

type Resolver struct {
	bindings []ServiceBinding
}

func NewResolver(bindings []ServiceBinding) *Resolver {
	snapshot := make([]ServiceBinding, len(bindings))
	for index, binding := range bindings {
		binding.MatchLabels = cloneLabels(binding.MatchLabels)
		snapshot[index] = binding
	}
	return &Resolver{bindings: snapshot}
}

func (resolver *Resolver) Resolve(input ResolveInput) Resolution {
	if input.WorkspaceID == "" || input.EnvironmentID == "" {
		return Resolution{Status: MappingUnresolved, Reason: ReasonNoExplicitMatch}
	}
	candidates := make(map[string]struct{})
	matchedBindings := 0
	if resolver != nil {
		for _, binding := range resolver.bindings {
			if binding.WorkspaceID != input.WorkspaceID ||
				binding.EnvironmentID != input.EnvironmentID ||
				binding.ServiceID == "" ||
				!matchesExplicitLabels(binding.MatchLabels, input.AlertLabels) {
				continue
			}
			matchedBindings++
			candidates[binding.ServiceID] = struct{}{}
		}
	}

	serviceIDs := make([]string, 0, len(candidates))
	for serviceID := range candidates {
		serviceIDs = append(serviceIDs, serviceID)
	}
	sort.Strings(serviceIDs)

	switch matchedBindings {
	case 0:
		return Resolution{
			Status:              MappingUnresolved,
			CandidateServiceIDs: serviceIDs,
			Reason:              ReasonNoExplicitMatch,
		}
	case 1:
		return Resolution{
			Status:              MappingExact,
			CandidateServiceIDs: serviceIDs,
			Reason:              ReasonUniqueExplicitMatch,
		}
	default:
		return Resolution{
			Status:              MappingAmbiguous,
			CandidateServiceIDs: serviceIDs,
			Reason:              ReasonMultipleExplicitMatches,
		}
	}
}

func cloneLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	clone := make(map[string]string, len(labels))
	for key, value := range labels {
		clone[key] = value
	}
	return clone
}

func matchesExplicitLabels(matchLabels, alertLabels map[string]string) bool {
	if len(matchLabels) == 0 {
		return false
	}
	for key, expected := range matchLabels {
		actual, exists := alertLabels[key]
		if !exists || actual != expected {
			return false
		}
	}
	return true
}
