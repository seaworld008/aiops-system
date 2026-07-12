// Package investigationplan compiles immutable, digest-bound investigation
// plans from a process-owned manifest and an admitted READ connector registry.
package investigationplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

const (
	ManifestSchemaVersion  = "investigation-plan-manifest.v1"
	MaximumDefinitionBytes = 1 << 20
)

var (
	ErrManifestPath       = errors.New("investigation plan manifest path rejected")
	ErrManifestFile       = errors.New("investigation plan manifest file rejected")
	ErrManifestJSON       = errors.New("investigation plan manifest JSON rejected")
	ErrManifestDefinition = errors.New("investigation plan manifest definition rejected")
	ErrInvalidDefinition  = errors.New("invalid investigation plan definition")
	ErrDefinitionTooLarge = errors.New("investigation plan definition size rejected")
	ErrRegistryMismatch   = errors.New("investigation plan registry rejected")
	ErrProfileOverlap     = errors.New("investigation plan profile overlap rejected")
	ErrInvalidRequest     = errors.New("invalid investigation plan request")
	ErrPlanDigestMismatch = errors.New("investigation plan digest mismatch")
	ErrMappingUnresolved  = errors.New("investigation plan mapping unresolved")
	ErrPlannerIntegrity   = errors.New("investigation planner integrity rejected")
)

type Definition struct {
	RegistryDigest string              `json:"registry_digest"`
	Profiles       []ProfileDefinition `json:"profiles"`
}

type ProfileDefinition struct {
	Scope Scope            `json:"scope"`
	Match MatchDefinition  `json:"match"`
	Tasks []TaskDefinition `json:"tasks"`
}

type Scope struct {
	TenantID      string `json:"tenant_id"`
	WorkspaceID   string `json:"workspace_id"`
	EnvironmentID string `json:"environment_id"`
	ServiceID     string `json:"service_id"`
}

type MatchDefinition struct {
	IntegrationID string       `json:"integration_id"`
	Provider      string       `json:"provider"`
	Labels        []LabelMatch `json:"labels"`
}

type LabelMatch struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type TaskDefinition struct {
	Key         string          `json:"key"`
	ConnectorID string          `json:"connector_id"`
	Operation   string          `json:"operation"`
	Input       json.RawMessage `json:"input"`
}

// TrustedSignalRegistration is populated only by trusted server-side
// persistence state. It has no direct promotion method: ScopeAuthority.Attest
// is the only boundary that can produce a scope accepted by its Planner.
type TrustedSignalRegistration struct {
	TenantID    string
	WorkspaceID string
}

func (TrustedSignalRegistration) String() string   { return "TrustedSignalRegistration{[REDACTED]}" }
func (TrustedSignalRegistration) GoString() string { return "TrustedSignalRegistration{[REDACTED]}" }
func (registration TrustedSignalRegistration) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, registration.String())
}
func (TrustedSignalRegistration) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}
func (*TrustedSignalRegistration) UnmarshalJSON([]byte) error { return ErrInvalidRequest }

// scopeAuthorityState is deliberately non-zero-sized. Go does not guarantee
// distinct pointer identity for separate zero-sized allocations.
type scopeAuthorityState struct {
	guard byte
}

// ScopeAuthority is a process-local capability. Only the persistence/activity
// boundary that owns an authority may attest trusted signal registrations for
// a Planner built with that same authority.
type ScopeAuthority struct {
	marker *scopeAuthorityState
}

func NewScopeAuthority() *ScopeAuthority {
	return &ScopeAuthority{marker: &scopeAuthorityState{guard: 1}}
}

func (ScopeAuthority) String() string   { return "ScopeAuthority{[REDACTED]}" }
func (ScopeAuthority) GoString() string { return "ScopeAuthority{[REDACTED]}" }
func (authority ScopeAuthority) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, authority.String())
}
func (ScopeAuthority) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*ScopeAuthority) UnmarshalJSON([]byte) error  { return ErrInvalidRequest }

func (authority *ScopeAuthority) Attest(registration TrustedSignalRegistration) (TrustedSignalScope, error) {
	if authority == nil || authority.marker == nil ||
		!persistentUUIDPattern.MatchString(registration.TenantID) ||
		!persistentUUIDPattern.MatchString(registration.WorkspaceID) {
		return TrustedSignalScope{}, ErrInvalidRequest
	}
	return TrustedSignalScope{
		tenantID: strings.Clone(registration.TenantID), workspaceID: strings.Clone(registration.WorkspaceID),
		marker: authority.marker,
	}, nil
}

type TrustedSignalScope struct {
	tenantID    string
	workspaceID string
	marker      *scopeAuthorityState
}

func (TrustedSignalScope) String() string   { return "TrustedSignalScope{[REDACTED]}" }
func (TrustedSignalScope) GoString() string { return "TrustedSignalScope{[REDACTED]}" }
func (scope TrustedSignalScope) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, scope.String())
}
func (TrustedSignalScope) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*TrustedSignalScope) UnmarshalJSON([]byte) error  { return ErrInvalidRequest }

type ResolveRequest struct {
	ExpectedPlanDigest string
	TrustedScope       TrustedSignalScope
	Signal             domain.Signal
}

// Plan owns detached copies and exposes only immutable snapshots.
type Plan struct {
	manifestDigest string
	profileDigest  string
	registryDigest string
	tasksHash      string
	scope          investigation.TaskSpecScope
	tasks          []investigation.TaskSpec
	correlation    investigation.CorrelateSignalRequest
}

func (plan Plan) ManifestDigest() string             { return plan.manifestDigest }
func (plan Plan) ProfileDigest() string              { return plan.profileDigest }
func (plan Plan) RegistryDigest() string             { return plan.registryDigest }
func (plan Plan) TasksHash() string                  { return plan.tasksHash }
func (plan Plan) Scope() investigation.TaskSpecScope { return plan.scope }
func (plan Plan) CorrelateSignalRequest() investigation.CorrelateSignalRequest {
	return plan.correlation
}
func (plan Plan) TaskSpecs() []investigation.TaskSpec { return cloneTaskSpecs(plan.tasks) }
func (Plan) String() string                           { return "InvestigationPlan{[REDACTED]}" }
func (Plan) GoString() string                         { return "InvestigationPlan{[REDACTED]}" }
func (plan Plan) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, plan.String())
}
func (Plan) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Plan) UnmarshalJSON([]byte) error  { return ErrInvalidRequest }

func cloneTaskSpecs(source []investigation.TaskSpec) []investigation.TaskSpec {
	if source == nil {
		return nil
	}
	cloned := make([]investigation.TaskSpec, len(source))
	for index, spec := range source {
		cloned[index] = spec
		cloned[index].Input = bytes.Clone(spec.Input)
	}
	return cloned
}
