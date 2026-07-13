package readtask

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/domain"
)

const (
	MaxEvidenceItems        = 256
	MaxEvidenceJSONDepth    = 16
	MaxEvidencePayloadBytes = 64 << 10
	// MaxEvidenceClockSkew bounds the untrusted connector timestamp against
	// server-owned attempt and receipt times. Larger drift is an unhealthy
	// Runner and fails closed; database received/created times stay authoritative.
	MaxEvidenceClockSkew = 2 * time.Second

	CompletionRequestHashVersionV3 = "read-task-completion-request.v3"
	CompletionReceiptHashVersionV3 = "read-task-completion-receipt.v3"
	RunnerEvidenceSchemaVersionV3  = "runner-evidence.v3"
)

// Receipt is the secret-free, server-derived completion binding. ReceivedAt
// is database evidence and intentionally excluded from ReceiptHash.
type Receipt struct {
	SchemaVersion      string
	TenantID           string
	WorkspaceID        string
	EnvironmentID      string
	ServiceID          string
	IncidentID         string
	InvestigationID    string
	TaskID             string
	RunnerID           string
	ScopeRevision      int64
	CertificateSHA256  string
	LeaseEpoch         int64
	ConnectorID        string
	Operation          string
	Outcome            CompletionOutcome
	ContentHash        string
	FailureCode        FailureCode
	IdempotencyKey     string
	PlanBinding        domain.InvestigationPlanBinding
	RuntimeBinding     domain.ReadTaskRuntimeBinding
	RequestHash        string
	ReceiptHash        string
	RequestHashVersion string
	ReceiptHashVersion string
	ReceivedAt         time.Time
}

func (receipt Receipt) ValidateAgainst(descriptor Descriptor, attempt Attempt) error {
	if descriptor.Validate() != nil || attempt.ValidateAgainst(descriptor) != nil ||
		receipt.SchemaVersion != RunnerEvidenceSchemaVersionV3 || receipt.TenantID != descriptor.TenantID ||
		receipt.WorkspaceID != descriptor.WorkspaceID || receipt.EnvironmentID != descriptor.EnvironmentID ||
		receipt.ServiceID != descriptor.ServiceID ||
		receipt.IncidentID != descriptor.IncidentID || receipt.InvestigationID != descriptor.InvestigationID ||
		receipt.TaskID != descriptor.TaskID || receipt.RunnerID != attempt.RunnerID ||
		receipt.ScopeRevision != attempt.ScopeRevision || receipt.CertificateSHA256 != attempt.Certificate.SHA256 ||
		receipt.LeaseEpoch != attempt.Epoch || receipt.ConnectorID != descriptor.ConnectorID ||
		receipt.Operation != descriptor.Operation || receipt.IdempotencyKey != derivedIdempotencyKey(descriptor.TaskID, attempt.Epoch) ||
		!receipt.PlanBinding.Equal(descriptor.PlanBinding) || !receipt.RuntimeBinding.Equal(descriptor.RuntimeBinding) ||
		receipt.RequestHashVersion != CompletionRequestHashVersionV3 ||
		receipt.ReceiptHashVersion != CompletionReceiptHashVersionV3 ||
		!validSHA256(receipt.RequestHash) || !validSHA256(receipt.ReceiptHash) ||
		!validReceivedAtForAttempt(receipt.ReceivedAt, attempt) {
		return ErrInvalidRequest
	}
	switch receipt.Outcome {
	case CompletionEvidence:
		if !validSHA256(receipt.ContentHash) || receipt.FailureCode != "" {
			return ErrInvalidRequest
		}
	case CompletionFailed:
		if receipt.ContentHash != "" || !validFailureCode(receipt.FailureCode) || receipt.FailureCode == FailureCancelled {
			return ErrInvalidRequest
		}
	case CompletionCancelled:
		if receipt.ContentHash != "" || receipt.FailureCode != FailureCancelled {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	requestHash, err := completionRequestHash(descriptor, attempt, receipt.Outcome, receipt.ContentHash, receipt.FailureCode)
	if err != nil || !equalHash(requestHash, receipt.RequestHash) {
		return ErrInvalidRequest
	}
	receiptHash, err := completionReceiptHash(receipt)
	if err != nil || !equalHash(receiptHash, receipt.ReceiptHash) {
		return ErrInvalidRequest
	}
	if attempt.Status == AttemptCompleted &&
		(receipt.ReceivedAt.Before(attempt.TerminalAt) || !equalHash(attempt.RequestHash, receipt.RequestHash) ||
			!equalHash(attempt.ReceiptHash, receipt.ReceiptHash)) {
		return ErrInvalidRequest
	}
	return nil
}

// MarshalJSON preserves bigint fences as canonical decimal strings.
func (receipt Receipt) MarshalJSON() ([]byte, error) {
	if receipt.ScopeRevision <= 0 || receipt.LeaseEpoch <= 0 {
		return nil, ErrInvalidRequest
	}
	return json.Marshal(receiptHashWire(receipt))
}

// ProjectedCompletion is the only completion representation suitable for the
// PostgreSQL adapter. All mutable values are private and returned as copies.
type ProjectedCompletion struct {
	outcome        CompletionOutcome
	payload        json.RawMessage
	attributes     map[string]string
	collectedAt    time.Time
	contentHash    string
	failureCode    FailureCode
	idempotencyKey string
	requestHash    string
	receiptHash    string
	receipt        Receipt
}

func (projection ProjectedCompletion) Outcome() CompletionOutcome { return projection.outcome }
func (projection ProjectedCompletion) Payload() json.RawMessage {
	return bytes.Clone(projection.payload)
}
func (projection ProjectedCompletion) ContentHash() string      { return projection.contentHash }
func (projection ProjectedCompletion) CollectedAt() time.Time   { return projection.collectedAt }
func (projection ProjectedCompletion) FailureCode() FailureCode { return projection.failureCode }
func (projection ProjectedCompletion) IdempotencyKey() string   { return projection.idempotencyKey }
func (projection ProjectedCompletion) RequestHash() string      { return projection.requestHash }
func (projection ProjectedCompletion) ReceiptHash() string      { return projection.receiptHash }
func (projection ProjectedCompletion) Receipt() Receipt         { return projection.receipt }
func (projection ProjectedCompletion) ReceivedAt() time.Time    { return projection.receipt.ReceivedAt }
func (projection ProjectedCompletion) Attributes() map[string]string {
	if projection.attributes == nil {
		return nil
	}
	cloned := make(map[string]string, len(projection.attributes))
	for key, value := range projection.attributes {
		cloned[key] = value
	}
	return cloned
}

func (projection ProjectedCompletion) String() string {
	return fmt.Sprintf("ProjectedReadTaskCompletion{Outcome:%q ReceiptHash:%q Security:[REDACTED]}",
		projection.outcome, projection.receiptHash)
}
func (projection ProjectedCompletion) GoString() string { return projection.String() }
func (projection ProjectedCompletion) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, projection.String())
}
func (ProjectedCompletion) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*ProjectedCompletion) UnmarshalJSON([]byte) error  { return ErrInvalidRequest }

// WithReceivedAt binds the database-returned receipt time without changing
// either semantic hash. The returned copy is revalidated against the same
// persisted descriptor and attempt.
func (projection ProjectedCompletion) WithReceivedAt(
	receivedAt time.Time,
	descriptor Descriptor,
	attempt Attempt,
) (ProjectedCompletion, error) {
	receivedAt = normalizeTime(receivedAt)
	if !validReceivedAtForAttempt(receivedAt, attempt) {
		return ProjectedCompletion{}, ErrInvalidRequest
	}
	bound := projection
	bound.receipt.ReceivedAt = receivedAt
	if bound.ValidateAgainst(descriptor, attempt) != nil || bound.requestHash != projection.requestHash ||
		bound.receiptHash != projection.receiptHash {
		return ProjectedCompletion{}, ErrInvalidRequest
	}
	return bound, nil
}

func (projection ProjectedCompletion) ValidateAgainst(descriptor Descriptor, attempt Attempt) error {
	if projection.receipt.ValidateAgainst(descriptor, attempt) != nil ||
		projection.outcome != projection.receipt.Outcome || projection.contentHash != projection.receipt.ContentHash ||
		projection.failureCode != projection.receipt.FailureCode || projection.idempotencyKey != projection.receipt.IdempotencyKey ||
		!equalHash(projection.requestHash, projection.receipt.RequestHash) ||
		!equalHash(projection.receiptHash, projection.receipt.ReceiptHash) {
		return ErrInvalidRequest
	}
	if projection.outcome == CompletionEvidence {
		if !validTime(projection.collectedAt) || len(projection.payload) == 0 ||
			projection.collectedAt.Before(normalizeTime(attempt.StartedAt).Add(-MaxEvidenceClockSkew)) ||
			projection.collectedAt.After(projection.receipt.ReceivedAt.Add(MaxEvidenceClockSkew)) ||
			domain.ValidateSafeJSONObject(projection.payload) != nil || domain.ValidateSafeAttributes(projection.attributes) != nil {
			return ErrInvalidRequest
		}
		digest := sha256.Sum256(projection.payload)
		if !equalHash(hex.EncodeToString(digest[:]), projection.contentHash) {
			return ErrInvalidRequest
		}
	} else if len(projection.payload) != 0 || projection.attributes != nil || !projection.collectedAt.IsZero() || projection.contentHash != "" {
		return ErrInvalidRequest
	}
	return nil
}

// ProjectCompletion validates untrusted Runner output and returns only a
// server-owned canonical projection. Connector/source, item count, identity,
// certificate and idempotency are all derived from persisted facts.
func ProjectCompletion(
	descriptor Descriptor,
	attempt Attempt,
	completion Completion,
	receivedAt time.Time,
) (ProjectedCompletion, error) {
	receivedAt = normalizeTime(receivedAt)
	if !validReceivedAtForAttempt(receivedAt, attempt) ||
		completion.ValidateAgainst(descriptor, attempt) != nil {
		return ProjectedCompletion{}, ErrProjectionRejected
	}

	projection := ProjectedCompletion{outcome: completion.Outcome, failureCode: completion.FailureCode}
	if completion.Outcome == CompletionEvidence {
		payload, attributes, collectedAt, contentHash, err := projectEvidence(descriptor, attempt, completion.Evidence, receivedAt)
		if err != nil {
			return ProjectedCompletion{}, ErrProjectionRejected
		}
		projection.payload = payload
		projection.attributes = attributes
		projection.collectedAt = collectedAt
		projection.contentHash = contentHash
	}

	projection.idempotencyKey = derivedIdempotencyKey(descriptor.TaskID, attempt.Epoch)
	if !idempotencyKeyPattern.MatchString(projection.idempotencyKey) {
		return ProjectedCompletion{}, ErrProjectionRejected
	}
	requestHash, err := completionRequestHash(
		descriptor, attempt, projection.outcome, projection.contentHash, projection.failureCode,
	)
	if err != nil {
		return ProjectedCompletion{}, ErrProjectionRejected
	}
	projection.requestHash = requestHash
	projection.receipt = Receipt{
		SchemaVersion: RunnerEvidenceSchemaVersionV3,
		TenantID:      descriptor.TenantID, WorkspaceID: descriptor.WorkspaceID, EnvironmentID: descriptor.EnvironmentID,
		ServiceID:  descriptor.ServiceID,
		IncidentID: descriptor.IncidentID, InvestigationID: descriptor.InvestigationID, TaskID: descriptor.TaskID,
		RunnerID: attempt.RunnerID, ScopeRevision: attempt.ScopeRevision,
		CertificateSHA256: attempt.Certificate.SHA256, LeaseEpoch: attempt.Epoch,
		ConnectorID: descriptor.ConnectorID, Operation: descriptor.Operation, Outcome: projection.outcome,
		ContentHash: projection.contentHash, FailureCode: projection.failureCode,
		IdempotencyKey: projection.idempotencyKey, PlanBinding: descriptor.PlanBinding,
		RuntimeBinding: descriptor.RuntimeBinding, RequestHash: requestHash,
		RequestHashVersion: CompletionRequestHashVersionV3,
		ReceiptHashVersion: CompletionReceiptHashVersionV3, ReceivedAt: receivedAt,
	}
	receiptHash, err := completionReceiptHash(projection.receipt)
	if err != nil {
		return ProjectedCompletion{}, ErrProjectionRejected
	}
	projection.receiptHash = receiptHash
	projection.receipt.ReceiptHash = receiptHash
	if projection.ValidateAgainst(descriptor, attempt) != nil {
		return ProjectedCompletion{}, ErrProjectionRejected
	}
	return projection, nil
}

func projectEvidence(
	descriptor Descriptor,
	attempt Attempt,
	evidence *EvidenceCompletion,
	receivedAt time.Time,
) (json.RawMessage, map[string]string, time.Time, string, error) {
	// There is deliberately no Runner-controlled truncation flag. A bounded
	// connector must fail its task when it cannot produce its complete contract;
	// PARTIAL investigations are derived from separate task outcomes.
	if evidence == nil || evidence.Items == nil || len(evidence.Items) > MaxEvidenceItems {
		return nil, nil, time.Time{}, "", ErrProjectionRejected
	}
	collectedAt := normalizeTime(evidence.CollectedAt)
	startedAt := normalizeTime(attempt.StartedAt)
	if !validTime(collectedAt) || collectedAt.Before(startedAt.Add(-MaxEvidenceClockSkew)) ||
		collectedAt.After(receivedAt.Add(MaxEvidenceClockSkew)) {
		return nil, nil, time.Time{}, "", ErrProjectionRejected
	}
	items := make([]json.RawMessage, len(evidence.Items))
	total := 0
	for index, item := range evidence.Items {
		total += len(item)
		if total > MaxEvidencePayloadBytes || domain.ValidateSafeJSONObject(item) != nil || jsonDepth(item) > MaxEvidenceJSONDepth {
			return nil, nil, time.Time{}, "", ErrProjectionRejected
		}
		items[index] = bytes.Clone(item)
	}
	wire, err := json.Marshal(struct {
		Source      string            `json:"source"`
		CollectedAt time.Time         `json:"collected_at"`
		ItemCount   int               `json:"item_count"`
		Truncated   bool              `json:"truncated"`
		Items       []json.RawMessage `json:"items"`
	}{descriptor.ConnectorID, collectedAt, len(items), false, items})
	if err != nil || len(wire) > MaxEvidencePayloadBytes {
		return nil, nil, time.Time{}, "", ErrProjectionRejected
	}
	canonical, err := jsoncanonicalizer.Transform(wire)
	if err != nil || len(canonical) > MaxEvidencePayloadBytes || domain.ValidateSafeJSONObject(canonical) != nil {
		return nil, nil, time.Time{}, "", ErrProjectionRejected
	}
	attributes := map[string]string{
		"source": descriptor.ConnectorID, "operation": descriptor.Operation,
		"item_count": strconv.Itoa(len(items)), "truncated": "false",
	}
	if domain.ValidateSafeAttributes(attributes) != nil {
		return nil, nil, time.Time{}, "", ErrProjectionRejected
	}
	digest := sha256.Sum256(canonical)
	return bytes.Clone(canonical), attributes, collectedAt, hex.EncodeToString(digest[:]), nil
}

func completionRequestHash(
	descriptor Descriptor,
	attempt Attempt,
	outcome CompletionOutcome,
	contentHash string,
	failureCode FailureCode,
) (string, error) {
	return canonicalHash(CompletionRequestHashVersionV3, struct {
		TaskID            string                          `json:"task_id"`
		TaskKey           string                          `json:"task_key"`
		TaskPosition      int                             `json:"task_position"`
		InputHash         string                          `json:"input_hash"`
		TenantID          string                          `json:"tenant_id"`
		WorkspaceID       string                          `json:"workspace_id"`
		EnvironmentID     string                          `json:"environment_id"`
		ServiceID         string                          `json:"service_id"`
		IncidentID        string                          `json:"incident_id"`
		InvestigationID   string                          `json:"investigation_id"`
		RunnerID          string                          `json:"runner_id"`
		ScopeRevision     string                          `json:"scope_revision"`
		CertificateSHA256 string                          `json:"certificate_sha256"`
		LeaseEpoch        string                          `json:"lease_epoch"`
		ConnectorID       string                          `json:"connector_id"`
		Operation         string                          `json:"operation"`
		PlanBinding       domain.InvestigationPlanBinding `json:"plan_binding"`
		RuntimeBinding    domain.ReadTaskRuntimeBinding   `json:"runtime_binding"`
		Outcome           CompletionOutcome               `json:"outcome"`
		ContentHash       string                          `json:"content_hash,omitempty"`
		FailureCode       FailureCode                     `json:"failure_code,omitempty"`
	}{
		descriptor.TaskID, descriptor.TaskKey, descriptor.Position, descriptor.InputHash,
		descriptor.TenantID, descriptor.WorkspaceID, descriptor.EnvironmentID, descriptor.ServiceID, descriptor.IncidentID,
		descriptor.InvestigationID, attempt.RunnerID, strconv.FormatInt(attempt.ScopeRevision, 10),
		attempt.Certificate.SHA256, strconv.FormatInt(attempt.Epoch, 10), descriptor.ConnectorID,
		descriptor.Operation, descriptor.PlanBinding, descriptor.RuntimeBinding, outcome, contentHash, failureCode,
	})
}

type receiptWire struct {
	SchemaVersion      string                          `json:"schema_version"`
	TenantID           string                          `json:"tenant_id"`
	WorkspaceID        string                          `json:"workspace_id"`
	EnvironmentID      string                          `json:"environment_id"`
	ServiceID          string                          `json:"service_id"`
	IncidentID         string                          `json:"incident_id"`
	InvestigationID    string                          `json:"investigation_id"`
	TaskID             string                          `json:"task_id"`
	RunnerID           string                          `json:"runner_id"`
	ScopeRevision      string                          `json:"scope_revision"`
	CertificateSHA256  string                          `json:"certificate_sha256"`
	LeaseEpoch         string                          `json:"lease_epoch"`
	ConnectorID        string                          `json:"connector_id"`
	Operation          string                          `json:"operation"`
	Outcome            CompletionOutcome               `json:"outcome"`
	ContentHash        string                          `json:"content_hash,omitempty"`
	FailureCode        FailureCode                     `json:"failure_code,omitempty"`
	IdempotencyKey     string                          `json:"idempotency_key"`
	PlanBinding        domain.InvestigationPlanBinding `json:"plan_binding"`
	RuntimeBinding     domain.ReadTaskRuntimeBinding   `json:"runtime_binding"`
	RequestHash        string                          `json:"request_hash"`
	RequestHashVersion string                          `json:"request_hash_version"`
	ReceiptHashVersion string                          `json:"receipt_hash_version"`
	ReceiptHash        string                          `json:"receipt_hash,omitempty"`
	ReceivedAt         *time.Time                      `json:"received_at,omitempty"`
}

func receiptHashWire(receipt Receipt) receiptWire {
	return receiptWire{
		SchemaVersion: receipt.SchemaVersion, TenantID: receipt.TenantID, WorkspaceID: receipt.WorkspaceID,
		EnvironmentID: receipt.EnvironmentID, ServiceID: receipt.ServiceID, IncidentID: receipt.IncidentID,
		InvestigationID: receipt.InvestigationID, TaskID: receipt.TaskID, RunnerID: receipt.RunnerID,
		ScopeRevision: strconv.FormatInt(receipt.ScopeRevision, 10), CertificateSHA256: receipt.CertificateSHA256,
		LeaseEpoch: strconv.FormatInt(receipt.LeaseEpoch, 10), ConnectorID: receipt.ConnectorID,
		Operation: receipt.Operation, Outcome: receipt.Outcome, ContentHash: receipt.ContentHash,
		FailureCode: receipt.FailureCode, IdempotencyKey: receipt.IdempotencyKey,
		PlanBinding: receipt.PlanBinding, RuntimeBinding: receipt.RuntimeBinding,
		RequestHash: receipt.RequestHash, RequestHashVersion: receipt.RequestHashVersion,
		ReceiptHashVersion: receipt.ReceiptHashVersion,
		ReceiptHash:        receipt.ReceiptHash, ReceivedAt: &receipt.ReceivedAt,
	}
}

func completionReceiptHash(receipt Receipt) (string, error) {
	wire := receiptHashWire(receipt)
	wire.ReceiptHash = ""
	wire.ReceivedAt = nil
	return canonicalHash(CompletionReceiptHashVersionV3, wire)
}

func canonicalHash(schema string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > MaxEvidencePayloadBytes {
		return "", ErrProjectionRejected
	}
	canonical, err := jsoncanonicalizer.Transform(encoded)
	if err != nil {
		return "", ErrProjectionRejected
	}
	input := make([]byte, 0, len(schema)+1+len(canonical))
	input = append(input, schema...)
	input = append(input, 0)
	input = append(input, canonical...)
	digest := sha256.Sum256(input)
	return hex.EncodeToString(digest[:]), nil
}

func derivedIdempotencyKey(taskID string, epoch int64) string {
	return "read-task:" + taskID + ":" + strconv.FormatInt(epoch, 10)
}

func normalizeTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return time.UnixMicro(value.UnixMicro()).UTC()
}

func validReceivedAtForAttempt(receivedAt time.Time, attempt Attempt) bool {
	receivedAt = normalizeTime(receivedAt)
	if !validTime(receivedAt) || !receivedAt.Before(attempt.Certificate.NotAfter) {
		return false
	}
	switch attempt.Status {
	case AttemptRunning:
		return !receivedAt.Before(normalizeTime(attempt.StartedAt)) && receivedAt.Before(attempt.LeaseExpiresAt)
	case AttemptCompleted:
		return !receivedAt.Before(normalizeTime(attempt.TerminalAt))
	default:
		return false
	}
}

func equalHash(left, right string) bool {
	return validSHA256(left) && validSHA256(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func jsonDepth(document []byte) int {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return MaxEvidenceJSONDepth + 1
	}
	return valueDepth(value, 1)
}

func valueDepth(value any, depth int) int {
	maximum := depth
	switch typed := value.(type) {
	case map[string]any:
		for _, child := range typed {
			if childDepth := valueDepth(child, depth+1); childDepth > maximum {
				maximum = childDepth
			}
		}
	case []any:
		for _, child := range typed {
			if childDepth := valueDepth(child, depth+1); childDepth > maximum {
				maximum = childDepth
			}
		}
	}
	return maximum
}

var _ json.Marshaler = Receipt{}
