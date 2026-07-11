package investigation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/domain"
)

var (
	ErrInvalidRequest    = errors.New("invalid investigation repository request")
	ErrInvalidTransition = errors.New("invalid investigation state transition")
)

var taskKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

var (
	targetURISchemePattern        = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://`)
	targetSchemeRelativePattern   = regexp.MustCompile(`(?i)(?:^|[\s"\x27(=])//(?:[a-z0-9._~%!$&()*+,;=:-]+@)?(?:[a-z0-9.-]+|\[[0-9a-f:]+\])(?::[0-9]{1,5})?(?:[/#?]|$)`)
	targetHostPortPattern         = regexp.MustCompile(`(?i)^(?:[a-z0-9.-]+|\[[0-9a-f:]+\]):[0-9]{1,5}(?:[/#?][^\s]*)?$`)
	targetAssignmentPattern       = regexp.MustCompile(`(?i)(^|[^a-z0-9])(host(?:[\s_.-]*name)?|port|dsn|endpoint|url|uri|address|server|target|cluster)[\s_.-]*[:=][\s]*`)
	targetMetricIdentifierPattern = regexp.MustCompile(`^[A-Za-z_:][A-Za-z0-9_:]*$`)
)

type TaskSpec struct {
	Key         string
	ConnectorID string
	Operation   string
	Input       json.RawMessage
}

type CorrelateSignalRequest struct {
	WorkspaceID    string
	SignalID       string
	CorrelationKey string
	ServiceID      string
	EnvironmentID  string
	MappingStatus  domain.MappingStatus
}

type CorrelateSignalResult struct {
	Incident   domain.Incident
	Created    bool
	Associated bool
	Counted    bool
}

type CreateOrGetInvestigationRequest struct {
	WorkspaceID    string
	IncidentID     string
	IdempotencyKey string
	Tasks          []TaskSpec
}

type CreateOrGetInvestigationResult struct {
	Investigation domain.Investigation
	Tasks         []domain.ReadTask
	Created       bool
}

type ListIncidentsRequest struct {
	WorkspaceID string
	Statuses    []domain.IncidentStatus
}

type ListInvestigationsRequest struct {
	WorkspaceID string
	IncidentID  string
	Statuses    []domain.InvestigationStatus
}

type ListTasksRequest struct {
	WorkspaceID     string
	InvestigationID string
	Statuses        []domain.ReadTaskStatus
}

type ListEvidenceRequest struct {
	WorkspaceID     string
	InvestigationID string
	TaskID          string
}

type ListHypothesesRequest struct {
	WorkspaceID     string
	InvestigationID string
}

type EvidenceInput struct {
	Payload     json.RawMessage
	ContentHash string
	Attributes  map[string]string
	CollectedAt time.Time
}

type CompleteTaskRequest struct {
	WorkspaceID     string
	InvestigationID string
	TaskID          string
	RunnerID        string
	IdempotencyKey  string
	Status          domain.ReadTaskStatus
	Evidence        *EvidenceInput
	FailureCode     string
}

type CompleteTaskResult struct {
	Task     domain.ReadTask
	Evidence *domain.Evidence
	Receipt  domain.RunnerEvidenceReceipt
	Replayed bool
}

type HypothesisSpec struct {
	Rank         int
	Confidence   float64
	Summary      string
	Proposal     json.RawMessage
	ProposalHash string
	Unknowns     []string
	EvidenceIDs  []string
}

type FinalizeInvestigationRequest struct {
	WorkspaceID      string
	InvestigationID  string
	IdempotencyKey   string
	Status           domain.InvestigationStatus
	ModelStatus      domain.ModelStatus
	FailureCode      string
	ModelFailureCode string
	Hypotheses       []HypothesisSpec
}

type FinalizeInvestigationResult struct {
	Investigation domain.Investigation
	Hypotheses    []domain.Hypothesis
	Replayed      bool
}

type StartModelRequest struct {
	WorkspaceID     string
	InvestigationID string
	IdempotencyKey  string
}

type StartModelResult struct {
	Investigation domain.Investigation
	Replayed      bool
}

type RecordFeedbackRequest struct {
	WorkspaceID     string
	IncidentID      string
	InvestigationID string
	HypothesisID    string
	Actor           domain.Actor
	Verdict         domain.FeedbackVerdict
	Details         json.RawMessage
	IdempotencyKey  string
}

type RecordFeedbackResult struct {
	Feedback domain.Feedback
	Created  bool
}

type Repository interface {
	RegisterSignal(context.Context, domain.Signal) (bool, error)
	CorrelateSignal(context.Context, CorrelateSignalRequest) (CorrelateSignalResult, error)
	CreateOrGetInvestigation(context.Context, CreateOrGetInvestigationRequest) (CreateOrGetInvestigationResult, error)

	GetIncident(context.Context, string, string) (domain.Incident, error)
	ListIncidents(context.Context, ListIncidentsRequest) ([]domain.Incident, error)
	GetInvestigation(context.Context, string, string) (domain.Investigation, error)
	ListInvestigations(context.Context, ListInvestigationsRequest) ([]domain.Investigation, error)
	GetTask(context.Context, string, string) (domain.ReadTask, error)
	ListTasks(context.Context, ListTasksRequest) ([]domain.ReadTask, error)
	GetEvidence(context.Context, string, string) (domain.Evidence, error)
	ListEvidence(context.Context, ListEvidenceRequest) ([]domain.Evidence, error)
	GetHypothesis(context.Context, string, string) (domain.Hypothesis, error)
	ListHypotheses(context.Context, ListHypothesesRequest) ([]domain.Hypothesis, error)

	CompleteTask(context.Context, CompleteTaskRequest) (CompleteTaskResult, error)
	StartModel(context.Context, StartModelRequest) (StartModelResult, error)
	FinalizeInvestigation(context.Context, FinalizeInvestigationRequest) (FinalizeInvestigationResult, error)
	RecordFeedback(context.Context, RecordFeedbackRequest) (RecordFeedbackResult, error)
}

func CanonicalTaskSpecs(specs []TaskSpec) ([]TaskSpec, string, error) {
	if len(specs) == 0 || len(specs) > 12 {
		return nil, "", fmt.Errorf("%w: task count must be between 1 and 12", ErrInvalidRequest)
	}
	canonical := make([]TaskSpec, len(specs))
	seen := make(map[string]struct{}, len(specs))
	for index, spec := range specs {
		if !taskKeyPattern.MatchString(spec.Key) || !domain.ValidConnectorID(spec.ConnectorID) ||
			!domain.ValidOperation(spec.Operation) {
			return nil, "", fmt.Errorf("%w: task key, connector and operation must be canonical", ErrInvalidRequest)
		}
		if _, duplicate := seen[spec.Key]; duplicate {
			return nil, "", fmt.Errorf("%w: duplicate task key", ErrInvalidRequest)
		}
		seen[spec.Key] = struct{}{}
		if err := domain.ValidateSafeJSONObject(spec.Input); err != nil {
			return nil, "", fmt.Errorf("%w: unsafe task input: %v", ErrInvalidRequest, err)
		}
		var object map[string]any
		if err := json.Unmarshal(spec.Input, &object); err != nil {
			return nil, "", fmt.Errorf("%w: invalid task input", ErrInvalidRequest)
		}
		if containsTaskTargetMaterial(object) {
			return nil, "", fmt.Errorf("%w: task input contains connection or credential material", ErrInvalidRequest)
		}
		encoded, err := jsoncanonicalizer.Transform(spec.Input)
		if err != nil {
			return nil, "", fmt.Errorf("%w: task input cannot be canonicalized", ErrInvalidRequest)
		}
		canonical[index] = TaskSpec{
			Key: spec.Key, ConnectorID: spec.ConnectorID, Operation: spec.Operation,
			Input: bytes.Clone(encoded),
		}
	}
	sort.Slice(canonical, func(left, right int) bool {
		if canonical[left].Key != canonical[right].Key {
			return canonical[left].Key < canonical[right].Key
		}
		if canonical[left].ConnectorID != canonical[right].ConnectorID {
			return canonical[left].ConnectorID < canonical[right].ConnectorID
		}
		if canonical[left].Operation != canonical[right].Operation {
			return canonical[left].Operation < canonical[right].Operation
		}
		return bytes.Compare(canonical[left].Input, canonical[right].Input) < 0
	})
	wire, err := json.Marshal(canonical)
	if err != nil {
		return nil, "", fmt.Errorf("%w: encode canonical tasks", ErrInvalidRequest)
	}
	digest := sha256.Sum256(wire)
	return canonical, fmt.Sprintf("%x", digest[:]), nil
}

func containsTaskTargetMaterial(value any) bool {
	return containsTaskTargetMaterialAt(value, "")
}

func containsTaskTargetMaterialAt(value any, parentKey string) bool {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			if normalized := normalizeTaskFieldName(key); normalized == "name" || normalized == "key" {
				if name, ok := child.(string); ok && forbiddenTaskFieldName(name) {
					return true
				}
			}
		}
		for key, child := range item {
			if forbiddenTaskFieldName(key) {
				return true
			}
			if containsTaskTargetMaterialAt(child, key) {
				return true
			}
		}
	case []any:
		for _, child := range item {
			if containsTaskTargetMaterialAt(child, parentKey) {
				return true
			}
		}
	case string:
		if unsafeTaskTargetValue(item) {
			return true
		}
	}
	return false
}

func normalizeTaskFieldName(value string) string {
	return strings.NewReplacer("_", "", "-", "", ".", "", " ", "", "/", "").Replace(strings.ToLower(value))
}

func forbiddenTaskFieldName(value string) bool {
	normalized := normalizeTaskFieldName(value)
	for _, forbidden := range []string{
		"url", "endpoint", "header", "auth", "secret", "token", "password", "credential",
		"host", "hostname", "port", "dsn", "uri", "address", "socket", "proxy", "server", "target", "cluster",
	} {
		if strings.Contains(normalized, forbidden) {
			return true
		}
	}
	return false
}

func unsafeTaskTargetValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	return targetURISchemePattern.MatchString(trimmed) || targetSchemeRelativePattern.MatchString(trimmed) ||
		targetHostPortPattern.MatchString(trimmed) || containsTaskTargetAssignment(trimmed)
}

func containsTaskTargetAssignment(value string) bool {
	for _, match := range targetAssignmentPattern.FindAllStringSubmatchIndex(value, -1) {
		valueStart := match[1]
		if valueStart >= len(value) {
			continue
		}
		remaining := value[valueStart:]
		if insideAllowedTaskSelector(value, match[4]) &&
			(strings.HasPrefix(remaining, `"`) || strings.HasPrefix(remaining, `~"`)) {
			continue
		}
		return true
	}
	return false
}

func insideAllowedTaskSelector(value string, position int) bool {
	selectorStarts := make([]int, 0, 1)
	quoted := false
	escaped := false
	for index := 0; index < position; index++ {
		switch current := value[index]; {
		case escaped:
			escaped = false
		case quoted && current == '\\':
			escaped = true
		case current == '"':
			quoted = !quoted
		case !quoted && current == '{':
			selectorStarts = append(selectorStarts, index)
		case !quoted && current == '}' && len(selectorStarts) > 0:
			selectorStarts = selectorStarts[:len(selectorStarts)-1]
		}
	}
	if len(selectorStarts) == 0 {
		return false
	}
	selectorStart := selectorStarts[len(selectorStarts)-1]
	if selectorStart == 0 {
		return true
	}
	previous := selectorStart - 1
	for previous >= 0 && strings.ContainsRune(" \t\r\n", rune(value[previous])) {
		previous--
	}
	identifierEnd := previous + 1
	for previous >= 0 && isTaskMetricIdentifierByte(value[previous]) {
		previous--
	}
	return targetMetricIdentifierPattern.MatchString(value[previous+1 : identifierEnd])
}

func isTaskMetricIdentifierByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || value == '_' || value == ':'
}
