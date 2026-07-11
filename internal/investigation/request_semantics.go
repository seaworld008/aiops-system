package investigation

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/domain"
)

const (
	createInvestigationRequestSemanticsV1   = "investigation.create.v1"
	completeTaskRequestSemanticsV1          = "investigation.complete-task.v1"
	finalizeInvestigationRequestSemanticsV1 = "investigation.finalize.v1"
	recordFeedbackRequestSemanticsV1        = "investigation.feedback.v1"
	startModelRequestSemanticsV1            = "investigation.start-model.v1"
	failInvestigationRequestSemanticsV1     = "investigation.fail.v1"
)

// CreateOrGetInvestigationRequestHash returns the stable semantic hash for a
// create operation after its task specifications have been canonicalized.
func CreateOrGetInvestigationRequestHash(request CreateOrGetInvestigationRequest, taskSpecsHash string) (string, error) {
	if !domain.ValidSHA256Hex(taskSpecsHash) {
		return "", fmt.Errorf("%w: invalid canonical task specification hash", ErrInvalidRequest)
	}
	return semanticRequestHash(createInvestigationRequestSemanticsV1, struct {
		IncidentID    string `json:"incident_id"`
		TaskSpecsHash string `json:"task_specs_hash"`
	}{IncidentID: request.IncidentID, TaskSpecsHash: taskSpecsHash})
}

// NormalizeCompleteTaskRequest validates the task-completion body, detaches all
// caller-owned data and returns a stable hash of the operation semantics.
// Workspace, resource and idempotency identity remain repository concerns.
func NormalizeCompleteTaskRequest(request CompleteTaskRequest) (CompleteTaskRequest, string, error) {
	switch request.Status {
	case domain.ReadTaskEvidence:
		if request.Evidence == nil || request.FailureCode != "" || !validEvidenceInput(request.Evidence) {
			return CompleteTaskRequest{}, "", fmt.Errorf("%w: invalid evidence completion body", ErrInvalidRequest)
		}
	case domain.ReadTaskFailed, domain.ReadTaskCancelled:
		if request.Evidence != nil || !domain.ValidFailureCode(request.FailureCode) {
			return CompleteTaskRequest{}, "", fmt.Errorf("%w: invalid failed task completion body", ErrInvalidRequest)
		}
	default:
		return CompleteTaskRequest{}, "", fmt.Errorf("%w: invalid task completion status", ErrInvalidRequest)
	}

	normalized := request
	if request.Evidence != nil {
		normalized.Evidence = &EvidenceInput{
			Payload:     bytes.Clone(request.Evidence.Payload),
			ContentHash: request.Evidence.ContentHash,
			Attributes:  cloneSemanticStringMap(request.Evidence.Attributes),
			CollectedAt: request.Evidence.CollectedAt.UTC(),
		}
	}
	requestHash, err := semanticRequestHash(completeTaskRequestSemanticsV1, struct {
		InvestigationID string                `json:"investigation_id"`
		TaskID          string                `json:"task_id"`
		RunnerID        string                `json:"runner_id"`
		Status          domain.ReadTaskStatus `json:"status"`
		Evidence        *EvidenceInput        `json:"evidence,omitempty"`
		FailureCode     string                `json:"failure_code,omitempty"`
	}{
		InvestigationID: normalized.InvestigationID,
		TaskID:          normalized.TaskID,
		RunnerID:        normalized.RunnerID,
		Status:          normalized.Status,
		Evidence:        normalized.Evidence,
		FailureCode:     normalized.FailureCode,
	})
	if err != nil {
		return CompleteTaskRequest{}, "", err
	}
	return normalized, requestHash, nil
}

// NormalizeFinalizeInvestigationRequest validates and rank-orders hypothesis
// specifications, detaches nested data and returns a stable semantic hash.
func NormalizeFinalizeInvestigationRequest(request FinalizeInvestigationRequest) (FinalizeInvestigationRequest, string, error) {
	if !validFinalizationSemantics(
		request.Status,
		request.ModelStatus,
		request.FailureCode,
		request.ModelFailureCode,
		len(request.Hypotheses),
	) {
		return FinalizeInvestigationRequest{}, "", fmt.Errorf("%w: invalid investigation finalization body", ErrInvalidRequest)
	}
	hypotheses, err := normalizeHypothesisSpecs(request.Hypotheses)
	if err != nil {
		return FinalizeInvestigationRequest{}, "", err
	}
	normalized := request
	normalized.Hypotheses = hypotheses
	requestHash, err := semanticRequestHash(finalizeInvestigationRequestSemanticsV1, struct {
		InvestigationID  string                     `json:"investigation_id"`
		Status           domain.InvestigationStatus `json:"status"`
		ModelStatus      domain.ModelStatus         `json:"model_status"`
		FailureCode      string                     `json:"failure_code,omitempty"`
		ModelFailureCode string                     `json:"model_failure_code,omitempty"`
		Hypotheses       []HypothesisSpec           `json:"hypotheses"`
	}{
		InvestigationID:  normalized.InvestigationID,
		Status:           normalized.Status,
		ModelStatus:      normalized.ModelStatus,
		FailureCode:      normalized.FailureCode,
		ModelFailureCode: normalized.ModelFailureCode,
		Hypotheses:       normalized.Hypotheses,
	})
	if err != nil {
		return FinalizeInvestigationRequest{}, "", err
	}
	return normalized, requestHash, nil
}

// NormalizeRecordFeedbackRequest validates feedback semantics and canonicalizes
// Details with JCS so insignificant JSON formatting cannot cause replay conflicts.
func NormalizeRecordFeedbackRequest(request RecordFeedbackRequest) (RecordFeedbackRequest, string, error) {
	if request.Actor.Type != domain.ActorHuman {
		return RecordFeedbackRequest{}, "", fmt.Errorf("%w: feedback requires a human actor", ErrInvalidRequest)
	}
	switch request.Verdict {
	case domain.FeedbackConfirmed, domain.FeedbackRejected, domain.FeedbackInconclusive:
	default:
		return RecordFeedbackRequest{}, "", fmt.Errorf("%w: invalid feedback verdict", ErrInvalidRequest)
	}
	if err := domain.ValidateSafeJSONObject(request.Details); err != nil {
		return RecordFeedbackRequest{}, "", fmt.Errorf("%w: invalid feedback details", ErrInvalidRequest)
	}
	canonicalDetails, err := jsoncanonicalizer.Transform(request.Details)
	if err != nil {
		return RecordFeedbackRequest{}, "", fmt.Errorf("%w: feedback details cannot be canonicalized", ErrInvalidRequest)
	}
	normalized := request
	normalized.Details = bytes.Clone(canonicalDetails)
	requestHash, err := semanticRequestHash(recordFeedbackRequestSemanticsV1, struct {
		IncidentID      string                 `json:"incident_id"`
		InvestigationID string                 `json:"investigation_id"`
		HypothesisID    string                 `json:"hypothesis_id"`
		Actor           domain.Actor           `json:"actor"`
		Verdict         domain.FeedbackVerdict `json:"verdict"`
		Details         json.RawMessage        `json:"details"`
	}{
		IncidentID:      normalized.IncidentID,
		InvestigationID: normalized.InvestigationID,
		HypothesisID:    normalized.HypothesisID,
		Actor:           normalized.Actor,
		Verdict:         normalized.Verdict,
		Details:         normalized.Details,
	})
	if err != nil {
		return RecordFeedbackRequest{}, "", err
	}
	return normalized, requestHash, nil
}

// StartModelRequestHash returns the stable semantic hash used for StartModel
// idempotency records. Repository-scoped identity is validated by the caller.
func StartModelRequestHash(request StartModelRequest) (string, error) {
	return semanticRequestHash(startModelRequestSemanticsV1, struct {
		InvestigationID string `json:"investigation_id"`
	}{InvestigationID: request.InvestigationID})
}

// FailInvestigationRequestHash validates failure semantics and returns the
// stable hash used for FailInvestigation idempotency records.
func FailInvestigationRequestHash(request FailInvestigationRequest) (string, error) {
	if !domain.ValidFailureCode(request.FailureCode) {
		return "", fmt.Errorf("%w: invalid investigation failure body", ErrInvalidRequest)
	}
	return semanticRequestHash(failInvestigationRequestSemanticsV1, struct {
		InvestigationID string `json:"investigation_id"`
		FailureCode     string `json:"failure_code"`
	}{InvestigationID: request.InvestigationID, FailureCode: request.FailureCode})
}

func validEvidenceInput(evidence *EvidenceInput) bool {
	if evidence == nil || evidence.CollectedAt.IsZero() || !domain.ValidSHA256Hex(evidence.ContentHash) {
		return false
	}
	if err := domain.ValidateSafeJSONObject(evidence.Payload); err != nil {
		return false
	}
	digest := sha256.Sum256(evidence.Payload)
	if fmt.Sprintf("%x", digest[:]) != evidence.ContentHash {
		return false
	}
	return domain.ValidateSafeAttributes(evidence.Attributes) == nil
}

func normalizeHypothesisSpecs(specs []HypothesisSpec) ([]HypothesisSpec, error) {
	if len(specs) > 20 {
		return nil, fmt.Errorf("%w: hypothesis count exceeds limit", ErrInvalidRequest)
	}
	normalized := make([]HypothesisSpec, len(specs))
	for index, spec := range specs {
		normalized[index] = HypothesisSpec{
			Rank:         spec.Rank,
			Confidence:   spec.Confidence,
			Summary:      spec.Summary,
			Proposal:     bytes.Clone(spec.Proposal),
			ProposalHash: spec.ProposalHash,
			Unknowns:     append([]string(nil), spec.Unknowns...),
			EvidenceIDs:  append([]string(nil), spec.EvidenceIDs...),
		}
		candidate := domain.Hypothesis{
			ID:              "validation",
			WorkspaceID:     "validation",
			IncidentID:      "validation",
			InvestigationID: "validation",
			Status:          domain.HypothesisProposed,
			Rank:            normalized[index].Rank,
			Confidence:      normalized[index].Confidence,
			Summary:         normalized[index].Summary,
			Proposal:        bytes.Clone(normalized[index].Proposal),
			ProposalHash:    normalized[index].ProposalHash,
			Unknowns:        append([]string(nil), normalized[index].Unknowns...),
			EvidenceIDs:     append([]string(nil), normalized[index].EvidenceIDs...),
			CreatedAt:       time.Unix(1, 0).UTC(),
		}
		if err := candidate.Validate(); err != nil {
			return nil, fmt.Errorf("%w: invalid hypothesis body", ErrInvalidRequest)
		}
	}
	sort.SliceStable(normalized, func(left, right int) bool {
		return normalized[left].Rank < normalized[right].Rank
	})
	for index := 1; index < len(normalized); index++ {
		if normalized[index-1].Rank == normalized[index].Rank {
			return nil, fmt.Errorf("%w: hypothesis ranks must be unique", ErrInvalidRequest)
		}
	}
	return normalized, nil
}

func validFinalizationSemantics(
	status domain.InvestigationStatus,
	modelStatus domain.ModelStatus,
	failureCode string,
	modelFailureCode string,
	hypothesisCount int,
) bool {
	switch status {
	case domain.InvestigationCompleted, domain.InvestigationPartial:
		switch modelStatus {
		case domain.ModelCompleted:
			return failureCode == "" && modelFailureCode == "" && hypothesisCount > 0
		case domain.ModelFailed:
			return failureCode == "" && domain.ValidFailureCode(modelFailureCode) && hypothesisCount == 0
		case domain.ModelSkipped:
			return failureCode == "" && modelFailureCode == "" && hypothesisCount == 0
		default:
			return false
		}
	case domain.InvestigationCancelled:
		return modelStatus == domain.ModelCancelled && domain.ValidFailureCode(failureCode) &&
			modelFailureCode == "" && hypothesisCount == 0
	default:
		return false
	}
}

func semanticRequestHash(schema string, value any) (string, error) {
	wire, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("%w: request semantics cannot be encoded", ErrInvalidRequest)
	}
	canonicalWire, err := jsoncanonicalizer.Transform(wire)
	if err != nil {
		return "", fmt.Errorf("%w: request semantics cannot be canonicalized", ErrInvalidRequest)
	}
	preimage := make([]byte, 0, len(schema)+1+len(canonicalWire))
	preimage = append(preimage, schema...)
	preimage = append(preimage, 0)
	preimage = append(preimage, canonicalWire...)
	digest := sha256.Sum256(preimage)
	return fmt.Sprintf("%x", digest[:]), nil
}

func cloneSemanticStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}
