package memory

import (
	"bytes"
	"context"
	"fmt"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func (repository *Repository) FinalizeInvestigation(ctx context.Context, request investigation.FinalizeInvestigationRequest) (investigation.FinalizeInvestigationResult, error) {
	if err := ctx.Err(); err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	if !validResourceScope(request.WorkspaceID, request.InvestigationID) || !domain.ValidIdempotencyKey(request.IdempotencyKey) {
		return investigation.FinalizeInvestigationResult{}, fmt.Errorf("%w: invalid investigation finalization", investigation.ErrInvalidRequest)
	}
	normalizedRequest, requestHash, err := investigation.NormalizeFinalizeInvestigationRequest(request)
	if err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	request = normalizedRequest
	canonical := request.Hypotheses

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
		result := cloneFinalizeResult(record.result)
		result.Replayed = true
		return result, nil
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
	hypothesisIDs := make([]string, len(canonical))
	createdIDs := make(map[string]struct{}, len(canonical))
	for index, spec := range canonical {
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
		hypothesisIDs[index] = hypothesisID
		for _, evidenceID := range spec.EvidenceIDs {
			evidence, found := repository.evidence[scoped(request.WorkspaceID, evidenceID)]
			if !found {
				return investigation.FinalizeInvestigationResult{}, store.ErrNotFound
			}
			if evidence.InvestigationID != item.ID {
				return investigation.FinalizeInvestigationResult{}, store.ErrScopeViolation
			}
		}
	}
	commitAt, err := repository.investigationCommitTime(request.WorkspaceID, item)
	if err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	var taskCandidates []domain.ReadTask
	if request.Status == domain.InvestigationCancelled {
		taskCandidates, err = repository.cancelledTaskCandidates(request.WorkspaceID, item.ID, request.FailureCode, commitAt)
		if err != nil {
			return investigation.FinalizeInvestigationResult{}, err
		}
	}
	createdHypotheses := make([]domain.Hypothesis, 0, len(canonical))
	for index, spec := range canonical {
		hypothesis := domain.Hypothesis{
			ID: hypothesisIDs[index], WorkspaceID: request.WorkspaceID, IncidentID: item.IncidentID, InvestigationID: item.ID,
			Status: domain.HypothesisProposed, Rank: spec.Rank, Confidence: spec.Confidence, Summary: spec.Summary,
			Proposal: bytes.Clone(spec.Proposal), ProposalHash: spec.ProposalHash,
			Unknowns: append([]string{}, spec.Unknowns...), EvidenceIDs: append([]string(nil), spec.EvidenceIDs...), CreatedAt: commitAt,
		}
		if validateErr := hypothesis.Validate(); validateErr != nil {
			return investigation.FinalizeInvestigationResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, validateErr)
		}
		createdHypotheses = append(createdHypotheses, hypothesis)
	}
	item.Status = request.Status
	item.ModelStatus = request.ModelStatus
	item.FailureCode = request.FailureCode
	item.ModelFailureCode = request.ModelFailureCode
	item.CompletedAt = commitAt
	item.UpdatedAt = commitAt
	if validateErr := item.Validate(); validateErr != nil {
		return investigation.FinalizeInvestigationResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, validateErr)
	}
	repository.investigations[scoped(request.WorkspaceID, item.ID)] = item
	repository.storeTaskCandidates(request.WorkspaceID, taskCandidates)
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
	result := investigation.FinalizeInvestigationResult{
		Investigation: cloneInvestigation(item), Hypotheses: cloneHypotheses(createdHypotheses),
	}
	repository.finalizeIdempotency[idempotencyKey] = finalizeRecord{
		requestHash: requestHash,
		result:      cloneFinalizeResult(result),
	}
	repository.bindIdempotencyOwner(idempotencyKey, "finalize_investigation")
	return cloneFinalizeResult(result), nil
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
