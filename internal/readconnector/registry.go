package readconnector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

const maxDefinitions = 1000

const entryContractSchemaV1 = "read-connector-entry-contract.v1"

var (
	ErrInvalidDefinition = errors.New("invalid read connector definition")
	ErrContractRejected  = errors.New("read connector contract rejected")

	contentAddressedIDPattern = regexp.MustCompile(`^([a-z0-9][a-z0-9_.-]{0,59})-v1-([a-f0-9]{64})$`)
	connectorBasePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,59}$`)
	persistentScopePattern    = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
)

type registryKey struct {
	tenantID      string
	workspaceID   string
	environmentID string
	connectorID   string
	operation     string
}

type connectorScopeKey struct {
	tenantID    string
	workspaceID string
	connectorID string
}

type contractScopeKey struct {
	tenantID       string
	workspaceID    string
	environmentID  string
	contractDigest string
}

type entry struct {
	scope          Scope
	connectorID    string
	targetRef      string
	kind           Kind
	operation      string
	contractDigest string
	prometheus     *PrometheusRangeQueryV1
	victoria       *VictoriaLogsSearchV1
}

// RuntimeDependency is a detached, secret-free graph edge used only while a
// READ runtime bundle validates that every connector has one exact target and
// egress policy. Query and projection material are intentionally absent.
type RuntimeDependency struct {
	scope          Scope
	connectorID    string
	targetRef      string
	kind           Kind
	operation      string
	contractDigest string
}

func (dependency RuntimeDependency) Scope() Scope {
	return Scope{
		TenantID: strings.Clone(dependency.scope.TenantID), WorkspaceID: strings.Clone(dependency.scope.WorkspaceID),
		EnvironmentID: strings.Clone(dependency.scope.EnvironmentID), ServiceID: strings.Clone(dependency.scope.ServiceID),
	}
}
func (dependency RuntimeDependency) ConnectorID() string {
	return strings.Clone(dependency.connectorID)
}
func (dependency RuntimeDependency) TargetRef() string { return strings.Clone(dependency.targetRef) }
func (dependency RuntimeDependency) Kind() Kind        { return dependency.kind }
func (dependency RuntimeDependency) Operation() string { return strings.Clone(dependency.operation) }
func (dependency RuntimeDependency) ContractDigest() string {
	return strings.Clone(dependency.contractDigest)
}
func (RuntimeDependency) String() string   { return "<aiops-read-runtime-dependency>" }
func (RuntimeDependency) GoString() string { return "<aiops-read-runtime-dependency>" }
func (RuntimeDependency) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-read-runtime-dependency>")
}
func (RuntimeDependency) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*RuntimeDependency) UnmarshalJSON([]byte) error  { return ErrContractRejected }

// Registry is constructed once, owns detached copies, and supports read-only
// concurrent use. It intentionally has no mutation or hot-reload method.
type Registry struct {
	entries map[registryKey]entry
	digest  string
}

func New(definitions []Definition) (*Registry, error) {
	if len(definitions) == 0 || len(definitions) > maxDefinitions {
		return nil, ErrInvalidDefinition
	}
	registry := &Registry{entries: make(map[registryKey]entry, len(definitions))}
	connectorEnvironments := make(map[connectorScopeKey]string, len(definitions))
	contractAliases := make(map[contractScopeKey]struct{}, len(definitions))
	digestEntries := make([]entry, 0, len(definitions))
	for _, definition := range definitions {
		item, err := buildEntry(definition)
		if err != nil {
			return nil, ErrInvalidDefinition
		}
		key := item.key()
		if _, duplicate := registry.entries[key]; duplicate {
			return nil, ErrInvalidDefinition
		}
		connectorKey := connectorScopeKey{item.scope.TenantID, item.scope.WorkspaceID, item.connectorID}
		if environment, found := connectorEnvironments[connectorKey]; found && environment != item.scope.EnvironmentID {
			return nil, ErrInvalidDefinition
		}
		connectorEnvironments[connectorKey] = item.scope.EnvironmentID
		contractKey := contractScopeKey{item.scope.TenantID, item.scope.WorkspaceID, item.scope.EnvironmentID, item.contractDigest}
		if _, duplicate := contractAliases[contractKey]; duplicate {
			return nil, ErrInvalidDefinition
		}
		contractAliases[contractKey] = struct{}{}
		registry.entries[key] = item
		digestEntries = append(digestEntries, item)
	}
	digest, err := registryDigest(digestEntries)
	if err != nil {
		return nil, ErrInvalidDefinition
	}
	registry.digest = digest
	return registry, nil
}

// BuildConnectorID derives the only ConnectorID accepted for a normalized
// definition. The full SHA-256 suffix binds every persisted task reference to
// one exact scope, target reference, query, projection, budget and validator
// profile without adding mutable registry state to the task row.
func BuildConnectorID(base string, definition Definition) (string, error) {
	if !connectorBasePattern.MatchString(base) || sensitiveReference(base) || definition.ConnectorID != "" {
		return "", ErrInvalidDefinition
	}
	item, err := buildEntryContract(definition)
	if err != nil {
		return "", ErrInvalidDefinition
	}
	connectorID := base + "-v1-" + item.contractDigest
	if !domain.ValidConnectorID(connectorID) || !contentAddressedIDPattern.MatchString(connectorID) {
		return "", ErrInvalidDefinition
	}
	return connectorID, nil
}

func (registry *Registry) Ready() bool {
	return registry != nil && len(registry.entries) > 0 && domain.ValidSHA256Hex(registry.digest)
}

func (registry *Registry) Digest() string {
	if registry == nil {
		return ""
	}
	return registry.digest
}

// RuntimeDependencies returns a deterministic detached view containing only
// the facts required to validate the runtime dependency graph. It does not
// expose fixed queries, evidence projections, target URLs, or credentials.
func (registry *Registry) RuntimeDependencies() ([]RuntimeDependency, error) {
	if registry == nil || !registry.Ready() {
		return nil, ErrContractRejected
	}
	dependencies := make([]RuntimeDependency, 0, len(registry.entries))
	for _, item := range registry.entries {
		dependencies = append(dependencies, RuntimeDependency{
			scope: Scope{
				TenantID: strings.Clone(item.scope.TenantID), WorkspaceID: strings.Clone(item.scope.WorkspaceID),
				EnvironmentID: strings.Clone(item.scope.EnvironmentID), ServiceID: strings.Clone(item.scope.ServiceID),
			},
			connectorID: strings.Clone(item.connectorID), targetRef: strings.Clone(item.targetRef),
			kind: item.kind, operation: strings.Clone(item.operation), contractDigest: strings.Clone(item.contractDigest),
		})
	}
	sort.Slice(dependencies, func(left, right int) bool {
		leftScope, rightScope := dependencies[left].scope, dependencies[right].scope
		leftKey := leftScope.TenantID + "\x00" + leftScope.WorkspaceID + "\x00" + leftScope.EnvironmentID + "\x00" +
			dependencies[left].connectorID + "\x00" + dependencies[left].operation
		rightKey := rightScope.TenantID + "\x00" + rightScope.WorkspaceID + "\x00" + rightScope.EnvironmentID + "\x00" +
			dependencies[right].connectorID + "\x00" + dependencies[right].operation
		return leftKey < rightKey
	})
	return dependencies, nil
}

func (registry *Registry) AuthorizeTaskSpec(
	ctx context.Context,
	scope investigation.TaskSpecScope,
	spec investigation.TaskSpec,
) error {
	_, err := registry.ResolveTaskSpec(ctx, scope, spec)
	return err
}

// ResolveTaskSpec is the trusted construction-time counterpart to
// ResolveExecution. It resolves only a canonical TaskSpec under the exact
// server-owned scope and never accepts a TargetRef, query, or digest from the
// caller. The detached result is suitable for a TaskRuntimeBinder.
func (registry *Registry) ResolveTaskSpec(
	ctx context.Context,
	scope investigation.TaskSpecScope,
	spec investigation.TaskSpec,
) (ExecutionSpec, error) {
	if err := contextError(ctx); err != nil {
		return ExecutionSpec{}, err
	}
	if registry == nil || !registry.Ready() || scope.Validate() != nil || scope.MappingStatus != domain.MappingExact ||
		!canonicalTaskSpec(spec) {
		return ExecutionSpec{}, ErrContractRejected
	}
	item, found := registry.entries[registryKey{
		tenantID: scope.TenantID, workspaceID: scope.WorkspaceID, environmentID: scope.EnvironmentID,
		connectorID: spec.ConnectorID, operation: spec.Operation,
	}]
	if !found || item.scope.ServiceID != "" && item.scope.ServiceID != scope.ServiceID ||
		validateInput(item, spec.Input) != nil {
		return ExecutionSpec{}, ErrContractRejected
	}
	if err := contextError(ctx); err != nil {
		return ExecutionSpec{}, err
	}
	lookback, err := parseLookback(item, spec.Input)
	if err != nil {
		return ExecutionSpec{}, ErrContractRejected
	}
	inputDigest := sha256.Sum256(spec.Input)
	return resolvedExecutionSpec(item, lookback, hex.EncodeToString(inputDigest[:])), nil
}

func (registry *Registry) AuthorizeStart(ctx context.Context, descriptor readtask.Descriptor) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if descriptor.Validate() != nil {
		return readtask.ErrIntegrity
	}
	item, found := registry.lookupDescriptor(descriptor)
	if !found {
		return readtask.ErrClaimsDisabled
	}
	if validateInput(item, descriptor.Input) != nil {
		return readtask.ErrIntegrity
	}
	return contextError(ctx)
}

func (registry *Registry) AuthorizeCompletion(
	ctx context.Context,
	descriptor readtask.Descriptor,
	evidence readtask.EvidenceCompletion,
) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if descriptor.Validate() != nil {
		return readtask.ErrIntegrity
	}
	item, found := registry.lookupDescriptor(descriptor)
	if !found {
		return readtask.ErrClaimsDisabled
	}
	lookback, err := parseLookback(item, descriptor.Input)
	if err != nil {
		return readtask.ErrIntegrity
	}
	if err := validateEvidence(item, evidence, lookback); err != nil {
		return ErrContractRejected
	}
	return contextError(ctx)
}

func (registry *Registry) ResolveExecution(descriptor readtask.Descriptor) (ExecutionSpec, error) {
	if descriptor.Validate() != nil {
		return ExecutionSpec{}, readtask.ErrIntegrity
	}
	item, found := registry.lookupDescriptor(descriptor)
	if !found {
		return ExecutionSpec{}, readtask.ErrClaimsDisabled
	}
	lookback, err := parseLookback(item, descriptor.Input)
	if err != nil {
		return ExecutionSpec{}, readtask.ErrIntegrity
	}
	return resolvedExecutionSpec(item, lookback, descriptor.InputHash), nil
}

func resolvedExecutionSpec(item entry, lookback time.Duration, inputHash string) ExecutionSpec {
	resolved := ExecutionSpec{
		kind: item.kind, operation: item.operation, targetRef: item.targetRef,
		contractDigest: item.contractDigest, inputHash: inputHash, lookback: lookback,
	}
	if item.prometheus != nil {
		resolved.prometheus = &prometheusExecution{
			expression: item.prometheus.Expression, step: time.Duration(item.prometheus.StepSeconds) * time.Second,
			maxItems: item.prometheus.MaxItems, maxSamples: item.prometheus.MaxSamples,
		}
	}
	if item.victoria != nil {
		resolved.victoria = &victoriaExecution{
			query: item.victoria.Query, fields: append([]FieldSpec(nil), item.victoria.Fields...), limit: item.victoria.Limit,
		}
	}
	return resolved
}

func (registry *Registry) lookupDescriptor(descriptor readtask.Descriptor) (entry, bool) {
	if registry == nil || !registry.Ready() {
		return entry{}, false
	}
	item, found := registry.entries[registryKey{
		tenantID: descriptor.TenantID, workspaceID: descriptor.WorkspaceID,
		environmentID: descriptor.EnvironmentID, connectorID: descriptor.ConnectorID,
		operation: descriptor.Operation,
	}]
	if found && item.scope.ServiceID != "" && item.scope.ServiceID != descriptor.ServiceID {
		return entry{}, false
	}
	return item, found
}

func buildEntry(definition Definition) (entry, error) {
	item, err := buildEntryContract(definition)
	if err != nil || !domain.ValidConnectorID(definition.ConnectorID) {
		return entry{}, ErrInvalidDefinition
	}
	matches := contentAddressedIDPattern.FindStringSubmatch(definition.ConnectorID)
	if len(matches) != 3 || sensitiveReference(matches[1]) || matches[2] != item.contractDigest {
		return entry{}, ErrInvalidDefinition
	}
	item.connectorID = definition.ConnectorID
	return item, nil
}

func buildEntryContract(definition Definition) (entry, error) {
	if !validScope(definition.Scope) || !contentAddressedIDPattern.MatchString(definition.TargetRef) ||
		sensitiveReference(definition.TargetRef) {
		return entry{}, ErrInvalidDefinition
	}
	operationCount := 0
	item := entry{
		scope: definition.Scope, targetRef: definition.TargetRef,
	}
	if definition.PrometheusRangeQuery != nil {
		operationCount++
		value := *definition.PrometheusRangeQuery
		if validatePrometheusDefinition(value) != nil {
			return entry{}, ErrInvalidDefinition
		}
		item.kind, item.operation, item.prometheus = KindPrometheus, OperationPrometheusRangeQuery, &value
	}
	if definition.VictoriaLogsSearch != nil {
		operationCount++
		value := *definition.VictoriaLogsSearch
		value.Fields = append([]FieldSpec(nil), definition.VictoriaLogsSearch.Fields...)
		if validateVictoriaDefinition(value) != nil {
			return entry{}, ErrInvalidDefinition
		}
		sort.Slice(value.Fields, func(left, right int) bool { return value.Fields[left].Name < value.Fields[right].Name })
		item.kind, item.operation, item.victoria = KindVictoriaLogs, OperationVictoriaLogsSearch, &value
	}
	if operationCount != 1 {
		return entry{}, ErrInvalidDefinition
	}
	digest, err := entryContractDigest(item)
	if err != nil {
		return entry{}, ErrInvalidDefinition
	}
	item.contractDigest = digest
	return item, nil
}

func (item entry) key() registryKey {
	return registryKey{
		item.scope.TenantID, item.scope.WorkspaceID, item.scope.EnvironmentID,
		item.connectorID, item.operation,
	}
}

func validScope(scope Scope) bool {
	return persistentScopePattern.MatchString(scope.TenantID) && persistentScopePattern.MatchString(scope.WorkspaceID) &&
		persistentScopePattern.MatchString(scope.EnvironmentID) &&
		(scope.ServiceID == "" || persistentScopePattern.MatchString(scope.ServiceID))
}

func sensitiveReference(value string) bool {
	var skeleton strings.Builder
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			skeleton.WriteRune(character)
		}
	}
	normalized := skeleton.String()
	for _, token := range []string{
		"authorization", "authentication", "auth", "apikey", "accessor", "secret", "token",
		"password", "credential", "cookie", "privatekey", "endpoint", "url", "host", "dsn",
	} {
		if strings.Contains(normalized, token) {
			return true
		}
	}
	return false
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return ErrContractRejected
	}
	value := reflect.ValueOf(ctx)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return ErrContractRejected
		}
	}
	return ctx.Err()
}

func canonicalTaskSpec(spec investigation.TaskSpec) bool {
	canonical, _, err := investigation.CanonicalTaskSpecs([]investigation.TaskSpec{spec})
	return err == nil && len(canonical) == 1 && canonical[0].Key == spec.Key &&
		canonical[0].ConnectorID == spec.ConnectorID && canonical[0].Operation == spec.Operation &&
		bytes.Equal(canonical[0].Input, spec.Input)
}

func registryDigest(entries []entry) (string, error) {
	sort.Slice(entries, func(left, right int) bool {
		leftKey, rightKey := entries[left].key(), entries[right].key()
		return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s", leftKey.tenantID, leftKey.workspaceID, leftKey.environmentID, leftKey.connectorID, leftKey.operation) <
			fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s", rightKey.tenantID, rightKey.workspaceID, rightKey.environmentID, rightKey.connectorID, rightKey.operation)
	})
	type digestDefinition struct {
		Scope                Scope                   `json:"scope"`
		ConnectorID          string                  `json:"connector_id"`
		TargetRef            string                  `json:"target_ref"`
		Kind                 Kind                    `json:"kind"`
		Operation            string                  `json:"operation"`
		ContractDigest       string                  `json:"contract_digest"`
		PrometheusRangeQuery *PrometheusRangeQueryV1 `json:"prometheus_range_query,omitempty"`
		VictoriaLogsSearch   *VictoriaLogsSearchV1   `json:"victorialogs_search,omitempty"`
	}
	document := struct {
		SchemaVersion string             `json:"schema_version"`
		Definitions   []digestDefinition `json:"definitions"`
	}{SchemaVersion: "read-connector-registry.v1", Definitions: make([]digestDefinition, len(entries))}
	for index, item := range entries {
		document.Definitions[index] = digestDefinition{
			Scope: item.scope, ConnectorID: item.connectorID, TargetRef: item.targetRef,
			Kind: item.kind, Operation: item.operation,
			ContractDigest:       item.contractDigest,
			PrometheusRangeQuery: item.prometheus, VictoriaLogsSearch: item.victoria,
		}
	}
	wire, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	canonical, err := jsoncanonicalizer.Transform(wire)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func entryContractDigest(item entry) (string, error) {
	document := struct {
		SchemaVersion                string                  `json:"schema_version"`
		ValidatorProfile             string                  `json:"validator_profile"`
		JSONFieldProfile             string                  `json:"json_field_profile"`
		NumericProfile               string                  `json:"numeric_profile"`
		EvidenceFieldsProfile        string                  `json:"evidence_fields_profile"`
		Scope                        Scope                   `json:"scope"`
		TargetRef                    string                  `json:"target_ref"`
		Kind                         Kind                    `json:"kind"`
		Operation                    string                  `json:"operation"`
		PrometheusRangeQuery         *PrometheusRangeQueryV1 `json:"prometheus_range_query,omitempty"`
		VictoriaLogsSearch           *VictoriaLogsSearchV1   `json:"victorialogs_search,omitempty"`
		MaxEvidenceBytes             int                     `json:"max_evidence_bytes"`
		MaxEvidenceDepth             int                     `json:"max_evidence_depth"`
		ClockToleranceNanos          int64                   `json:"clock_tolerance_nanos"`
		PrometheusStepToleranceNanos int64                   `json:"prometheus_step_tolerance_nanos"`
		MaxLabels                    int                     `json:"max_labels"`
		MaxLabelValueBytes           int                     `json:"max_label_value_bytes"`
		MaxVictoriaFields            int                     `json:"max_victorialogs_fields"`
		MaxVictoriaStringBytes       int                     `json:"max_victorialogs_string_bytes"`
	}{
		SchemaVersion: entryContractSchemaV1, ValidatorProfile: "read-connector-validator.v2",
		JSONFieldProfile: "exact-case-no-folded-alias.v1",
		NumericProfile:   "jcs-ijson-safe-integer.v1", EvidenceFieldsProfile: "readtask-evidence-fields.v2",
		Scope: item.scope, TargetRef: item.targetRef, Kind: item.kind, Operation: item.operation,
		PrometheusRangeQuery: item.prometheus, VictoriaLogsSearch: item.victoria,
		MaxEvidenceBytes: readtask.MaxEvidencePayloadBytes, MaxEvidenceDepth: readtask.MaxEvidenceJSONDepth,
		ClockToleranceNanos: int64(evidenceClockTolerance), MaxLabels: maximumLabels,
		PrometheusStepToleranceNanos: int64(prometheusStepTolerance),
		MaxLabelValueBytes:           maximumLabelValueBytes, MaxVictoriaFields: maximumVictoriaFields,
		MaxVictoriaStringBytes: maximumVictoriaStringBytes,
	}
	wire, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	canonical, err := jsoncanonicalizer.Transform(wire)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func (registry Registry) String() string {
	return fmt.Sprintf("ReadConnectorRegistry{Ready:%t Definitions:%d Digest:%q Security:[REDACTED]}",
		(&registry).Ready(), len(registry.entries), registry.digest)
}
func (registry Registry) GoString() string { return registry.String() }
func (registry Registry) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, registry.String())
}
func (Registry) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Registry) UnmarshalJSON([]byte) error  { return ErrInvalidDefinition }
