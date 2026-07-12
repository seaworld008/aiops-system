// Package readconnector defines the immutable, server-owned contracts for
// READ-only investigation connectors. It deliberately contains no network,
// credential, persistence, or process-global mutable state.
package readconnector

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

const (
	OperationPrometheusRangeQuery = "range_query"
	OperationVictoriaLogsSearch   = "search"
)

type Kind string

const (
	KindPrometheus   Kind = "prometheus"
	KindVictoriaLogs Kind = "victorialogs"
)

type FieldType string

const (
	FieldString  FieldType = "string"
	FieldNumber  FieldType = "number"
	FieldBoolean FieldType = "boolean"
	FieldNull    FieldType = "null"
)

// Scope is copied from trusted server configuration. TargetRef is not part of
// Scope because it must never be accepted from a Task or Runner payload.
type Scope struct {
	TenantID      string `json:"tenant_id"`
	WorkspaceID   string `json:"workspace_id"`
	EnvironmentID string `json:"environment_id"`
	ServiceID     string `json:"service_id,omitempty"`
}

// Definition is the construction/manifest shape. Exactly one typed operation
// must be present. Query text, projection fields and budgets are server-owned.
type Definition struct {
	Scope       Scope  `json:"scope"`
	ConnectorID string `json:"connector_id"`
	TargetRef   string `json:"target_ref"`

	PrometheusRangeQuery *PrometheusRangeQueryV1 `json:"prometheus_range_query,omitempty"`
	VictoriaLogsSearch   *VictoriaLogsSearchV1   `json:"victorialogs_search,omitempty"`
}

type PrometheusRangeQueryV1 struct {
	Expression         string `json:"expression"`
	StepSeconds        int    `json:"step_seconds"`
	MaxLookbackMinutes int    `json:"max_lookback_minutes"`
	MaxItems           int    `json:"max_items"`
	MaxSamples         int    `json:"max_samples"`
}

type VictoriaLogsSearchV1 struct {
	Query              string      `json:"query"`
	Fields             []FieldSpec `json:"fields"`
	Limit              int         `json:"limit"`
	MaxLookbackMinutes int         `json:"max_lookback_minutes"`
}

type FieldSpec struct {
	Name     string    `json:"name"`
	Type     FieldType `json:"type"`
	Required bool      `json:"required"`
	MaxBytes int       `json:"max_bytes,omitempty"`
}

// ExecutionSpec is a non-serializable detached resolution. Its fields remain
// private so fixed queries and target references cannot be logged by accident.
type ExecutionSpec struct {
	kind           Kind
	operation      string
	targetRef      string
	contractDigest string
	inputHash      string
	lookback       time.Duration
	prometheus     *prometheusExecution
	victoria       *victoriaExecution
}

type prometheusExecution struct {
	expression string
	step       time.Duration
	maxItems   int
	maxSamples int
}

type victoriaExecution struct {
	query  string
	fields []FieldSpec
	limit  int
}

type PrometheusRangeExecution struct{ value prometheusExecution }
type VictoriaLogsExecution struct{ value victoriaExecution }

func (spec ExecutionSpec) Kind() Kind              { return spec.kind }
func (spec ExecutionSpec) Operation() string       { return spec.operation }
func (spec ExecutionSpec) TargetRef() string       { return spec.targetRef }
func (spec ExecutionSpec) ContractDigest() string  { return spec.contractDigest }
func (spec ExecutionSpec) Lookback() time.Duration { return spec.lookback }

// MatchesDescriptor proves that this process-owned resolution was derived
// from the exact persisted task input and runtime component fences. It keeps
// callers from pairing a valid descriptor with a different resolution from
// the same connector.
func (spec ExecutionSpec) MatchesDescriptor(descriptor readtask.Descriptor) bool {
	return descriptor.Validate() == nil && spec.operation == descriptor.Operation &&
		domain.ValidSHA256Hex(spec.contractDigest) && spec.contractDigest == descriptor.RuntimeBinding.ConnectorDigest &&
		domain.ValidSHA256Hex(spec.inputHash) && spec.inputHash == descriptor.InputHash &&
		domain.ConnectorDigestMatchesID(descriptor.ConnectorID, spec.contractDigest) &&
		domain.ValidSHA256Hex(descriptor.RuntimeBinding.TargetDigest) &&
		strings.HasSuffix(spec.targetRef, "-v1-"+descriptor.RuntimeBinding.TargetDigest)
}

// ValidateEvidence applies the same immutable connector contract inside the
// READ executor before the Gateway independently validates the completion.
// It accepts no caller-supplied scope, query, target, digest, or budget.
func (spec ExecutionSpec) ValidateEvidence(evidence readtask.EvidenceCompletion) error {
	if spec.lookback <= 0 || !domain.ValidSHA256Hex(spec.contractDigest) || !domain.ValidSHA256Hex(spec.inputHash) {
		return ErrContractRejected
	}
	switch {
	case spec.kind == KindPrometheus && spec.operation == OperationPrometheusRangeQuery &&
		spec.prometheus != nil && spec.victoria == nil && spec.prometheus.step > 0 &&
		spec.prometheus.step%time.Second == 0:
		return validatePrometheusEvidence(PrometheusRangeQueryV1{
			StepSeconds: int(spec.prometheus.step / time.Second), MaxItems: spec.prometheus.maxItems,
			MaxSamples: spec.prometheus.maxSamples,
		}, evidence, spec.lookback)
	case spec.kind == KindVictoriaLogs && spec.operation == OperationVictoriaLogsSearch &&
		spec.prometheus == nil && spec.victoria != nil:
		return validateVictoriaEvidence(VictoriaLogsSearchV1{
			Fields: append([]FieldSpec(nil), spec.victoria.fields...), Limit: spec.victoria.limit,
		}, evidence, spec.lookback)
	default:
		return ErrContractRejected
	}
}

func (spec ExecutionSpec) PrometheusRangeQuery() (PrometheusRangeExecution, bool) {
	if spec.prometheus == nil {
		return PrometheusRangeExecution{}, false
	}
	return PrometheusRangeExecution{value: *spec.prometheus}, true
}

func (spec ExecutionSpec) VictoriaLogsSearch() (VictoriaLogsExecution, bool) {
	if spec.victoria == nil {
		return VictoriaLogsExecution{}, false
	}
	copy := *spec.victoria
	copy.fields = append([]FieldSpec(nil), spec.victoria.fields...)
	return VictoriaLogsExecution{value: copy}, true
}

func (execution PrometheusRangeExecution) Expression() string  { return execution.value.expression }
func (execution PrometheusRangeExecution) Step() time.Duration { return execution.value.step }
func (execution PrometheusRangeExecution) MaxItems() int       { return execution.value.maxItems }
func (execution PrometheusRangeExecution) MaxSamples() int     { return execution.value.maxSamples }

func (execution VictoriaLogsExecution) Query() string { return execution.value.query }
func (execution VictoriaLogsExecution) Fields() []FieldSpec {
	return append([]FieldSpec(nil), execution.value.fields...)
}
func (execution VictoriaLogsExecution) Limit() int { return execution.value.limit }

func (ExecutionSpec) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*ExecutionSpec) UnmarshalJSON([]byte) error  { return ErrContractRejected }
func (PrometheusRangeExecution) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}
func (*PrometheusRangeExecution) UnmarshalJSON([]byte) error { return ErrContractRejected }
func (VictoriaLogsExecution) MarshalJSON() ([]byte, error)   { return []byte(`{"redacted":true}`), nil }
func (*VictoriaLogsExecution) UnmarshalJSON([]byte) error    { return ErrContractRejected }

func (spec ExecutionSpec) String() string {
	return fmt.Sprintf("ReadConnectorExecution{Kind:%q Operation:%q Security:[REDACTED]}", spec.kind, spec.operation)
}
func (spec ExecutionSpec) GoString() string { return spec.String() }
func (spec ExecutionSpec) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, spec.String())
}

func (PrometheusRangeExecution) String() string {
	return "PrometheusRangeExecution{Security:[REDACTED]}"
}
func (execution PrometheusRangeExecution) GoString() string { return execution.String() }
func (execution PrometheusRangeExecution) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, execution.String())
}

func (VictoriaLogsExecution) String() string             { return "VictoriaLogsExecution{Security:[REDACTED]}" }
func (execution VictoriaLogsExecution) GoString() string { return execution.String() }
func (execution VictoriaLogsExecution) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, execution.String())
}

// Compile-time checks keep the redacted wire behavior explicit.
var (
	_ json.Marshaler = ExecutionSpec{}
	_ json.Marshaler = PrometheusRangeExecution{}
	_ json.Marshaler = VictoriaLogsExecution{}
)
