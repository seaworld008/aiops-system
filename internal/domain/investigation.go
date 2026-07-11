package domain

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const MaxInvestigationJSONBytes = 64 * 1024
const MaxResourceIDBytes = 256

var (
	sha256HexPattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	identifierPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]*$`)
	idempotencyKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,127}$`)
	lowCardinalityPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)
)

type InvestigationStatus string

const (
	InvestigationQueued    InvestigationStatus = "QUEUED"
	InvestigationRunning   InvestigationStatus = "RUNNING"
	InvestigationPartial   InvestigationStatus = "PARTIAL"
	InvestigationCompleted InvestigationStatus = "COMPLETED"
	InvestigationFailed    InvestigationStatus = "FAILED"
	InvestigationCancelled InvestigationStatus = "CANCELLED"
)

type ModelStatus string

const (
	ModelPending   ModelStatus = "PENDING"
	ModelRunning   ModelStatus = "RUNNING"
	ModelCompleted ModelStatus = "COMPLETED"
	ModelFailed    ModelStatus = "FAILED"
	ModelSkipped   ModelStatus = "SKIPPED"
	ModelCancelled ModelStatus = "CANCELLED"
)

type Investigation struct {
	ID               string
	WorkspaceID      string
	IncidentID       string
	Status           InvestigationStatus
	ModelStatus      ModelStatus
	IdempotencyKey   string
	RequestHash      string
	FailureCode      string
	ModelFailureCode string
	CreatedAt        time.Time
	StartedAt        time.Time
	CompletedAt      time.Time
	UpdatedAt        time.Time
}

type ReadTaskStatus string

const (
	ReadTaskQueued    ReadTaskStatus = "QUEUED"
	ReadTaskRunning   ReadTaskStatus = "RUNNING"
	ReadTaskEvidence  ReadTaskStatus = "EVIDENCE"
	ReadTaskFailed    ReadTaskStatus = "FAILED"
	ReadTaskCancelled ReadTaskStatus = "CANCELLED"
)

type ReadTask struct {
	ID              string
	WorkspaceID     string
	IncidentID      string
	InvestigationID string
	Key             string
	Position        int
	ConnectorID     string
	Operation       string
	Input           json.RawMessage
	InputHash       string
	Status          ReadTaskStatus
	EvidenceID      string
	FailureCode     string
	CreatedAt       time.Time
	StartedAt       time.Time
	CompletedAt     time.Time
	UpdatedAt       time.Time
}

func (task ReadTask) Validate() error {
	if !validIdentifier(task.ID, 256) || !validIdentifier(task.WorkspaceID, 256) ||
		!validIdentifier(task.IncidentID, 256) || !validIdentifier(task.InvestigationID, 256) {
		return fmt.Errorf("read task identifiers are invalid")
	}
	if task.Position <= 0 || task.Position > 12 {
		return fmt.Errorf("read task position must be between 1 and 12")
	}
	if !lowCardinalityPattern.MatchString(task.Key) || len(task.Key) > 64 {
		return fmt.Errorf("read task key is invalid")
	}
	if !ValidConnectorID(task.ConnectorID) || !ValidOperation(task.Operation) {
		return fmt.Errorf("read task connector or operation is invalid")
	}
	if err := validateHashedJSONObject(task.Input, task.InputHash); err != nil {
		return fmt.Errorf("read task input: %w", err)
	}
	switch task.Status {
	case ReadTaskQueued, ReadTaskRunning, ReadTaskEvidence, ReadTaskFailed, ReadTaskCancelled:
	default:
		return fmt.Errorf("invalid read task status %q", task.Status)
	}
	if task.FailureCode != "" && !ValidFailureCode(task.FailureCode) {
		return fmt.Errorf("read task failure code is invalid")
	}
	if task.CreatedAt.IsZero() || task.UpdatedAt.IsZero() || task.UpdatedAt.Before(task.CreatedAt) ||
		!timeWithin(task.StartedAt, task.CreatedAt, task.UpdatedAt) ||
		!timeWithin(task.CompletedAt, task.CreatedAt, task.UpdatedAt) {
		return fmt.Errorf("read task timestamps are invalid")
	}
	switch task.Status {
	case ReadTaskQueued:
		if !task.StartedAt.IsZero() || !task.CompletedAt.IsZero() || task.EvidenceID != "" || task.FailureCode != "" {
			return fmt.Errorf("queued read task lifecycle is inconsistent")
		}
	case ReadTaskRunning:
		if task.StartedAt.IsZero() || !task.CompletedAt.IsZero() || task.EvidenceID != "" || task.FailureCode != "" {
			return fmt.Errorf("running read task lifecycle is inconsistent")
		}
	case ReadTaskEvidence:
		if task.StartedAt.IsZero() || task.CompletedAt.IsZero() || !validIdentifier(task.EvidenceID, 256) || task.FailureCode != "" {
			return fmt.Errorf("evidence read task lifecycle is inconsistent")
		}
	case ReadTaskFailed, ReadTaskCancelled:
		if task.StartedAt.IsZero() || task.CompletedAt.IsZero() || task.EvidenceID != "" || !ValidFailureCode(task.FailureCode) {
			return fmt.Errorf("failed read task lifecycle is inconsistent")
		}
	}
	return nil
}

type Evidence struct {
	ID              string
	WorkspaceID     string
	IncidentID      string
	InvestigationID string
	TaskID          string
	ConnectorID     string
	ContentHash     string
	Payload         json.RawMessage
	Attributes      map[string]string
	CollectedAt     time.Time
	CreatedAt       time.Time
}

type FeedbackVerdict string

const (
	FeedbackConfirmed    FeedbackVerdict = "CONFIRMED"
	FeedbackRejected     FeedbackVerdict = "REJECTED"
	FeedbackInconclusive FeedbackVerdict = "INCONCLUSIVE"
)

type Feedback struct {
	ID              string
	WorkspaceID     string
	IncidentID      string
	InvestigationID string
	HypothesisID    string
	Actor           Actor
	Verdict         FeedbackVerdict
	Details         json.RawMessage
	CreatedAt       time.Time
}

func (feedback Feedback) Validate() error {
	if !validIdentifier(feedback.ID, 256) || !validIdentifier(feedback.WorkspaceID, 256) ||
		!validIdentifier(feedback.IncidentID, 256) || !validIdentifier(feedback.InvestigationID, 256) ||
		!validIdentifier(feedback.HypothesisID, 256) {
		return fmt.Errorf("feedback identifiers are invalid")
	}
	if feedback.Actor.Type != ActorHuman || !validIdentifier(feedback.Actor.ID, 256) {
		return fmt.Errorf("feedback requires an authenticated human")
	}
	switch feedback.Verdict {
	case FeedbackConfirmed, FeedbackRejected, FeedbackInconclusive:
	default:
		return fmt.Errorf("invalid feedback verdict %q", feedback.Verdict)
	}
	if err := ValidateSafeJSONObject(feedback.Details); err != nil {
		return fmt.Errorf("feedback details: %w", err)
	}
	if feedback.CreatedAt.IsZero() {
		return fmt.Errorf("feedback creation time is required")
	}
	return nil
}

type RunnerEvidenceReceipt struct {
	ID              string
	WorkspaceID     string
	InvestigationID string
	TaskID          string
	RunnerID        string
	ConnectorID     string
	EvidenceID      string
	ContentHash     string
	FailureCode     string
	IdempotencyKey  string
	ReceivedAt      time.Time
}

func (receipt RunnerEvidenceReceipt) Validate() error {
	if !validIdentifier(receipt.ID, 256) || !validIdentifier(receipt.WorkspaceID, 256) ||
		!validIdentifier(receipt.InvestigationID, 256) || !validIdentifier(receipt.TaskID, 256) ||
		!validIdentifier(receipt.RunnerID, 256) || !ValidConnectorID(receipt.ConnectorID) ||
		!ValidIdempotencyKey(receipt.IdempotencyKey) {
		return fmt.Errorf("runner evidence receipt identifiers are invalid")
	}
	success := validIdentifier(receipt.EvidenceID, 256) && ValidSHA256Hex(receipt.ContentHash) && receipt.FailureCode == ""
	failure := receipt.EvidenceID == "" && receipt.ContentHash == "" && ValidFailureCode(receipt.FailureCode)
	if success == failure {
		return fmt.Errorf("runner evidence receipt must contain exactly one bounded result")
	}
	if receipt.ReceivedAt.IsZero() {
		return fmt.Errorf("runner evidence receipt time is required")
	}
	return nil
}

func (evidence Evidence) Validate() error {
	if !validIdentifier(evidence.ID, 256) || !validIdentifier(evidence.WorkspaceID, 256) ||
		!validIdentifier(evidence.IncidentID, 256) || !validIdentifier(evidence.InvestigationID, 256) ||
		!validIdentifier(evidence.TaskID, 256) || !ValidConnectorID(evidence.ConnectorID) {
		return fmt.Errorf("evidence identifiers are invalid")
	}
	if err := validateHashedJSONObject(evidence.Payload, evidence.ContentHash); err != nil {
		return fmt.Errorf("evidence payload: %w", err)
	}
	if err := ValidateSafeAttributes(evidence.Attributes); err != nil {
		return err
	}
	if evidence.CollectedAt.IsZero() || evidence.CreatedAt.IsZero() || evidence.CollectedAt.After(evidence.CreatedAt) {
		return fmt.Errorf("evidence timestamps are invalid")
	}
	return nil
}

func (investigation Investigation) Validate() error {
	if !validIdentifier(investigation.ID, 256) || !validIdentifier(investigation.WorkspaceID, 256) ||
		!validIdentifier(investigation.IncidentID, 256) {
		return fmt.Errorf("investigation identifiers are invalid")
	}
	switch investigation.Status {
	case InvestigationQueued, InvestigationRunning, InvestigationPartial, InvestigationCompleted,
		InvestigationFailed, InvestigationCancelled:
	default:
		return fmt.Errorf("invalid investigation status %q", investigation.Status)
	}
	switch investigation.ModelStatus {
	case ModelPending, ModelRunning, ModelCompleted, ModelFailed, ModelSkipped, ModelCancelled:
	default:
		return fmt.Errorf("invalid model status %q", investigation.ModelStatus)
	}
	if !ValidIdempotencyKey(investigation.IdempotencyKey) {
		return fmt.Errorf("investigation idempotency key is invalid")
	}
	if !ValidSHA256Hex(investigation.RequestHash) {
		return fmt.Errorf("investigation request hash is invalid")
	}
	switch investigation.Status {
	case InvestigationFailed, InvestigationCancelled:
		if !ValidFailureCode(investigation.FailureCode) {
			return fmt.Errorf("failed or cancelled investigation requires a bounded failure code")
		}
	default:
		if investigation.FailureCode != "" {
			return fmt.Errorf("investigation failure code requires FAILED or CANCELLED status")
		}
	}
	if investigation.ModelStatus == ModelFailed {
		if !ValidFailureCode(investigation.ModelFailureCode) {
			return fmt.Errorf("failed model requires a bounded failure code")
		}
	} else if investigation.ModelFailureCode != "" {
		return fmt.Errorf("model failure code requires FAILED model status")
	}
	if investigation.CreatedAt.IsZero() || investigation.UpdatedAt.IsZero() || investigation.UpdatedAt.Before(investigation.CreatedAt) {
		return fmt.Errorf("investigation timestamps are invalid")
	}
	if !timeWithin(investigation.StartedAt, investigation.CreatedAt, investigation.UpdatedAt) ||
		!timeWithin(investigation.CompletedAt, investigation.CreatedAt, investigation.UpdatedAt) {
		return fmt.Errorf("investigation lifecycle timestamps are invalid")
	}
	switch investigation.Status {
	case InvestigationQueued:
		if !investigation.StartedAt.IsZero() || !investigation.CompletedAt.IsZero() || investigation.ModelStatus != ModelPending {
			return fmt.Errorf("queued investigation lifecycle is inconsistent")
		}
	case InvestigationRunning:
		if investigation.StartedAt.IsZero() || !investigation.CompletedAt.IsZero() {
			return fmt.Errorf("running investigation lifecycle is inconsistent")
		}
	case InvestigationPartial, InvestigationCompleted:
		if investigation.StartedAt.IsZero() || investigation.CompletedAt.IsZero() ||
			(investigation.ModelStatus != ModelCompleted && investigation.ModelStatus != ModelFailed && investigation.ModelStatus != ModelSkipped) {
			return fmt.Errorf("completed investigation lifecycle is inconsistent")
		}
	case InvestigationFailed:
		if investigation.CompletedAt.IsZero() || investigation.ModelStatus != ModelFailed {
			return fmt.Errorf("terminal investigation lifecycle is inconsistent")
		}
	case InvestigationCancelled:
		if investigation.CompletedAt.IsZero() || investigation.ModelStatus != ModelCancelled {
			return fmt.Errorf("cancelled investigation lifecycle is inconsistent")
		}
	}
	return nil
}

func ValidSHA256Hex(value string) bool {
	return sha256HexPattern.MatchString(value)
}

func ValidResourceID(value string) bool {
	return validIdentifier(value, MaxResourceIDBytes)
}

func ValidIdempotencyKey(value string) bool {
	return idempotencyKeyPattern.MatchString(value)
}

func ValidFailureCode(value string) bool {
	return len(value) <= 128 && lowCardinalityPattern.MatchString(value)
}

func ValidConnectorID(value string) bool {
	return len(value) <= 128 && lowCardinalityPattern.MatchString(value)
}

func ValidOperation(value string) bool {
	return len(value) <= 64 && lowCardinalityPattern.MatchString(value)
}

func ValidateSafeJSONObject(value json.RawMessage) error {
	if len(value) == 0 || len(value) > MaxInvestigationJSONBytes || !json.Valid(value) {
		return fmt.Errorf("JSON must be a valid object of at most %d bytes", MaxInvestigationJSONBytes)
	}
	var object map[string]any
	if err := json.Unmarshal(value, &object); err != nil || object == nil {
		return fmt.Errorf("JSON must be an object")
	}
	if err := rejectSensitiveJSON(object, nil); err != nil {
		return err
	}
	return nil
}

func ValidateSafeAttributes(attributes map[string]string) error {
	if len(attributes) > 32 {
		return fmt.Errorf("evidence attributes exceed limit")
	}
	for key, value := range attributes {
		if !lowCardinalityPattern.MatchString(key) || len(key) > 64 || len(value) > 512 ||
			!ValidSafeMetadata(key, value) {
			return fmt.Errorf("evidence attributes contain invalid or sensitive metadata")
		}
	}
	return nil
}

func ValidSafeMetadata(name, value string) bool {
	return !unsafeSecurityName(name) && !unsafeSecurityValue(value) &&
		(normalizeSecurityName(name) != "name" || !unsafeSecurityName(value))
}

func validateHashedJSONObject(value json.RawMessage, hash string) error {
	if err := ValidateSafeJSONObject(value); err != nil {
		return err
	}
	if !ValidSHA256Hex(hash) {
		return fmt.Errorf("SHA-256 hash must be lowercase hexadecimal")
	}
	digest := sha256.Sum256(value)
	if fmt.Sprintf("%x", digest[:]) != hash {
		return fmt.Errorf("SHA-256 hash does not match JSON")
	}
	return nil
}

func validIdentifier(value string, maxBytes int) bool {
	return len(value) > 0 && len(value) <= maxBytes && identifierPattern.MatchString(value)
}

func timeWithin(value, notBefore, notAfter time.Time) bool {
	return value.IsZero() || (!value.Before(notBefore) && !value.After(notAfter))
}

func rejectSensitiveJSON(value any, path []string) error {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			if normalizeSecurityName(key) == "name" {
				if name, ok := child.(string); ok && unsafeSecurityName(name) {
					return fmt.Errorf("JSON contains forbidden sensitive metadata")
				}
			}
		}
		for key, child := range item {
			nextPath := append(append([]string(nil), path...), key)
			if unsafeSecurityName(key) || unsafeSecurityName(strings.Join(nextPath, ".")) {
				return fmt.Errorf("JSON contains forbidden sensitive metadata")
			}
			if err := rejectSensitiveJSON(child, nextPath); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range item {
			if err := rejectSensitiveJSON(child, path); err != nil {
				return err
			}
		}
	case string:
		if unsafeSecurityValue(item) {
			return fmt.Errorf("JSON contains forbidden sensitive metadata")
		}
	}
	return nil
}

func normalizeSecurityName(value string) string {
	return strings.NewReplacer("_", "", "-", "", ".", "", " ", "", "/", "").Replace(strings.ToLower(value))
}

func unsafeSecurityName(value string) bool {
	normalized := normalizeSecurityName(value)
	for _, marker := range []string{
		"authorization", "credential", "rawerror", "errorbody", "secret", "token", "password", "cookie", "privatekey",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func unsafeSecurityValue(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	for _, marker := range []string{
		"bearer ", "authorization:", "cookie:", "set-cookie", "begin private key", "begin rsa private key",
		"private-key", "private_key",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}
