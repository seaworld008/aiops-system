package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func (repository *Repository) FinalizeInvestigation(ctx context.Context, request investigation.FinalizeInvestigationRequest) (investigation.FinalizeInvestigationResult, error) {
	if err := ctx.Err(); err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	if !validResourceScope(request.WorkspaceID, request.InvestigationID) || !domain.ValidIdempotencyKey(request.IdempotencyKey) ||
		!validFinalization(request.Status, request.ModelStatus, request.FailureCode, request.ModelFailureCode, len(request.Hypotheses)) {
		return investigation.FinalizeInvestigationResult{}, fmt.Errorf("%w: invalid investigation finalization", investigation.ErrInvalidRequest)
	}
	canonical, err := canonicalHypothesisSpecs(request.Hypotheses)
	if err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	wire, err := json.Marshal(struct {
		InvestigationID  string
		Status           domain.InvestigationStatus
		ModelStatus      domain.ModelStatus
		FailureCode      string
		ModelFailureCode string
		Hypotheses       []investigation.HypothesisSpec
	}{request.InvestigationID, request.Status, request.ModelStatus, request.FailureCode, request.ModelFailureCode, canonical})
	if err != nil {
		return investigation.FinalizeInvestigationResult{}, fmt.Errorf("%w: encode finalization", investigation.ErrInvalidRequest)
	}
	digest := sha256.Sum256(wire)
	requestHash := fmt.Sprintf("%x", digest[:])
	now := repository.clock().UTC()
	if now.IsZero() {
		return investigation.FinalizeInvestigationResult{}, fmt.Errorf("%w: clock returned zero time", investigation.ErrInvalidRequest)
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	idempotencyKey := scoped(request.WorkspaceID, request.IdempotencyKey)
	if !repository.idempotencyOwnerMatches(idempotencyKey, "finalize_investigation") {
		return investigation.FinalizeInvestigationResult{}, store.ErrIdempotencyConflict
	}
	if record, exists := repository.finalizeIdempotency[idempotencyKey]; exists {
		if record.requestHash != requestHash {
			return investigation.FinalizeInvestigationResult{}, store.ErrIdempotencyConflict
		}
		return repository.finalizationResult(request.WorkspaceID, record.investigationID, true)
	}
	item, exists := repository.investigations[scoped(request.WorkspaceID, request.InvestigationID)]
	if !exists {
		return investigation.FinalizeInvestigationResult{}, store.ErrNotFound
	}
	if item.Status != domain.InvestigationQueued && item.Status != domain.InvestigationRunning {
		return investigation.FinalizeInvestigationResult{}, investigation.ErrInvalidTransition
	}
	if !validModelFinalizationTransition(item.ModelStatus, request.ModelStatus) {
		return investigation.FinalizeInvestigationResult{}, investigation.ErrInvalidTransition
	}
	if request.Status == domain.InvestigationCompleted || request.Status == domain.InvestigationPartial {
		derivedStatus := domain.InvestigationCompleted
		for _, taskID := range repository.taskIDsByInvestigation[scoped(request.WorkspaceID, item.ID)] {
			task, found := repository.tasks[scoped(request.WorkspaceID, taskID)]
			if !found {
				return investigation.FinalizeInvestigationResult{}, store.ErrNotFound
			}
			if task.Status == domain.ReadTaskQueued || task.Status == domain.ReadTaskRunning {
				return investigation.FinalizeInvestigationResult{}, investigation.ErrInvalidTransition
			}
			if task.Status != domain.ReadTaskEvidence {
				derivedStatus = domain.InvestigationPartial
			}
		}
		if request.Status != derivedStatus {
			return investigation.FinalizeInvestigationResult{}, investigation.ErrInvalidTransition
		}
	}
	createdHypotheses := make([]domain.Hypothesis, 0, len(canonical))
	createdIDs := make(map[string]struct{}, len(canonical))
	for _, spec := range canonical {
		hypothesisID, idErr := repository.newID()
		if idErr != nil {
			return investigation.FinalizeInvestigationResult{}, idErr
		}
		if _, duplicate := repository.hypotheses[scoped(request.WorkspaceID, hypothesisID)]; duplicate {
			return investigation.FinalizeInvestigationResult{}, fmt.Errorf("%w: ID factory returned duplicate hypothesis ID", investigation.ErrInvalidRequest)
		}
		if _, duplicate := createdIDs[hypothesisID]; duplicate {
			return investigation.FinalizeInvestigationResult{}, fmt.Errorf("%w: ID factory returned duplicate hypothesis ID", investigation.ErrInvalidRequest)
		}
		createdIDs[hypothesisID] = struct{}{}
		hypothesis := domain.Hypothesis{
			ID: hypothesisID, WorkspaceID: request.WorkspaceID, IncidentID: item.IncidentID, InvestigationID: item.ID,
			Status: domain.HypothesisProposed, Rank: spec.Rank, Confidence: spec.Confidence, Summary: spec.Summary,
			Proposal: bytes.Clone(spec.Proposal), ProposalHash: spec.ProposalHash,
			Unknowns: append([]string(nil), spec.Unknowns...), EvidenceIDs: append([]string(nil), spec.EvidenceIDs...), CreatedAt: now,
		}
		if validateErr := hypothesis.Validate(); validateErr != nil {
			return investigation.FinalizeInvestigationResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, validateErr)
		}
		for _, evidenceID := range hypothesis.EvidenceIDs {
			evidence, found := repository.evidence[scoped(request.WorkspaceID, evidenceID)]
			if !found {
				return investigation.FinalizeInvestigationResult{}, store.ErrNotFound
			}
			if evidence.InvestigationID != item.ID {
				return investigation.FinalizeInvestigationResult{}, store.ErrScopeViolation
			}
		}
		createdHypotheses = append(createdHypotheses, hypothesis)
	}
	item.Status = request.Status
	item.ModelStatus = request.ModelStatus
	item.FailureCode = request.FailureCode
	item.ModelFailureCode = request.ModelFailureCode
	item.CompletedAt = now
	item.UpdatedAt = now
	if validateErr := item.Validate(); validateErr != nil {
		return investigation.FinalizeInvestigationResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, validateErr)
	}
	repository.investigations[scoped(request.WorkspaceID, item.ID)] = item
	ids := make([]string, 0, len(createdHypotheses))
	for _, hypothesis := range createdHypotheses {
		repository.hypotheses[scoped(request.WorkspaceID, hypothesis.ID)] = cloneHypothesis(hypothesis)
		ids = append(ids, hypothesis.ID)
	}
	repository.hypothesisIDsByInvestigation[scoped(request.WorkspaceID, item.ID)] = append([]string(nil), ids...)
	incidentKey := scoped(request.WorkspaceID, item.IncidentID)
	if repository.activeInvestigation[incidentKey] == item.ID {
		delete(repository.activeInvestigation, incidentKey)
	}
	repository.finalizeIdempotency[idempotencyKey] = finalizeRecord{requestHash: requestHash, investigationID: item.ID}
	repository.bindIdempotencyOwner(idempotencyKey, "finalize_investigation")
	return investigation.FinalizeInvestigationResult{
		Investigation: cloneInvestigation(item), Hypotheses: cloneHypotheses(createdHypotheses),
	}, nil
}

func (repository *Repository) finalizationResult(workspaceID, investigationID string, replayed bool) (investigation.FinalizeInvestigationResult, error) {
	item, exists := repository.investigations[scoped(workspaceID, investigationID)]
	if !exists {
		return investigation.FinalizeInvestigationResult{}, store.ErrNotFound
	}
	ids := repository.hypothesisIDsByInvestigation[scoped(workspaceID, investigationID)]
	hypotheses := make([]domain.Hypothesis, 0, len(ids))
	for _, hypothesisID := range ids {
		hypothesis, found := repository.hypotheses[scoped(workspaceID, hypothesisID)]
		if !found {
			return investigation.FinalizeInvestigationResult{}, store.ErrNotFound
		}
		hypotheses = append(hypotheses, cloneHypothesis(hypothesis))
	}
	return investigation.FinalizeInvestigationResult{
		Investigation: cloneInvestigation(item), Hypotheses: hypotheses, Replayed: replayed,
	}, nil
}

func canonicalHypothesisSpecs(specs []investigation.HypothesisSpec) ([]investigation.HypothesisSpec, error) {
	if len(specs) > 20 {
		return nil, fmt.Errorf("%w: hypothesis count exceeds 20", investigation.ErrInvalidRequest)
	}
	canonical := make([]investigation.HypothesisSpec, len(specs))
	for index, spec := range specs {
		canonical[index] = investigation.HypothesisSpec{
			Rank: spec.Rank, Confidence: spec.Confidence, Summary: spec.Summary,
			Proposal: bytes.Clone(spec.Proposal), ProposalHash: spec.ProposalHash,
			Unknowns: append([]string(nil), spec.Unknowns...), EvidenceIDs: append([]string(nil), spec.EvidenceIDs...),
		}
		candidate := domain.Hypothesis{
			ID: "validation", WorkspaceID: "validation", IncidentID: "validation", InvestigationID: "validation",
			Status: domain.HypothesisProposed, Rank: spec.Rank, Confidence: spec.Confidence, Summary: spec.Summary,
			Proposal: bytes.Clone(spec.Proposal), ProposalHash: spec.ProposalHash,
			Unknowns: append([]string(nil), spec.Unknowns...), EvidenceIDs: append([]string(nil), spec.EvidenceIDs...), CreatedAt: time.Unix(1, 0).UTC(),
		}
		if err := candidate.Validate(); err != nil {
			return nil, fmt.Errorf("%w: invalid hypothesis body", investigation.ErrInvalidRequest)
		}
	}
	sort.SliceStable(canonical, func(left, right int) bool { return canonical[left].Rank < canonical[right].Rank })
	for index := 1; index < len(canonical); index++ {
		if canonical[index-1].Rank == canonical[index].Rank {
			return nil, fmt.Errorf("%w: hypothesis ranks must be unique", investigation.ErrInvalidRequest)
		}
	}
	return canonical, nil
}

func validFinalization(status domain.InvestigationStatus, modelStatus domain.ModelStatus, failureCode, modelFailureCode string, hypothesisCount int) bool {
	switch status {
	case domain.InvestigationCompleted, domain.InvestigationPartial:
		if modelStatus == domain.ModelCompleted {
			return failureCode == "" && modelFailureCode == "" && hypothesisCount > 0
		}
		if modelStatus == domain.ModelFailed {
			return failureCode == "" && domain.ValidFailureCode(modelFailureCode) && hypothesisCount == 0
		}
		return modelStatus == domain.ModelSkipped && failureCode == "" && modelFailureCode == "" && hypothesisCount == 0
	case domain.InvestigationCancelled:
		return modelStatus == domain.ModelCancelled && domain.ValidFailureCode(failureCode) && modelFailureCode == "" && hypothesisCount == 0
	default:
		return false
	}
}

func validModelFinalizationTransition(current, terminal domain.ModelStatus) bool {
	switch terminal {
	case domain.ModelCompleted, domain.ModelFailed:
		return current == domain.ModelRunning
	case domain.ModelSkipped:
		return current == domain.ModelPending
	case domain.ModelCancelled:
		return current == domain.ModelPending || current == domain.ModelRunning
	default:
		return false
	}
}
