package memory

import (
	"context"
	"fmt"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func (repository *Repository) FailInvestigation(ctx context.Context, request investigation.FailInvestigationRequest) (investigation.FailInvestigationResult, error) {
	if err := ctx.Err(); err != nil {
		return investigation.FailInvestigationResult{}, err
	}
	if !validResourceScope(request.WorkspaceID, request.InvestigationID) ||
		!domain.ValidIdempotencyKey(request.IdempotencyKey) {
		return investigation.FailInvestigationResult{}, fmt.Errorf("%w: invalid investigation failure", investigation.ErrInvalidRequest)
	}
	requestHash, err := investigation.FailInvestigationRequestHash(request)
	if err != nil {
		return investigation.FailInvestigationResult{}, err
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	idempotencyKey := scoped(request.WorkspaceID, request.IdempotencyKey)
	if !repository.idempotencyOwnerMatches(idempotencyKey, "fail_investigation") {
		return investigation.FailInvestigationResult{}, store.ErrIdempotencyConflict
	}
	if record, exists := repository.failureIdempotency[idempotencyKey]; exists {
		if record.requestHash != requestHash {
			return investigation.FailInvestigationResult{}, store.ErrIdempotencyConflict
		}
		item, found := repository.investigations[scoped(request.WorkspaceID, record.resourceID)]
		if !found {
			return investigation.FailInvestigationResult{}, store.ErrNotFound
		}
		return investigation.FailInvestigationResult{Investigation: cloneInvestigation(item), Replayed: true}, nil
	}
	itemKey := scoped(request.WorkspaceID, request.InvestigationID)
	item, exists := repository.investigations[itemKey]
	if !exists {
		return investigation.FailInvestigationResult{}, store.ErrNotFound
	}
	if item.Status != domain.InvestigationQueued && item.Status != domain.InvestigationRunning {
		return investigation.FailInvestigationResult{}, investigation.ErrInvalidTransition
	}
	commitAt, err := repository.investigationCommitTime(request.WorkspaceID, item)
	if err != nil {
		return investigation.FailInvestigationResult{}, err
	}
	taskCandidates, err := repository.cancelledTaskCandidates(request.WorkspaceID, item.ID, request.FailureCode, commitAt)
	if err != nil {
		return investigation.FailInvestigationResult{}, err
	}
	item.Status = domain.InvestigationFailed
	item.ModelStatus = domain.ModelCancelled
	item.FailureCode = request.FailureCode
	item.ModelFailureCode = ""
	item.CompletedAt = commitAt
	item.UpdatedAt = commitAt
	if err := item.Validate(); err != nil {
		return investigation.FailInvestigationResult{}, fmt.Errorf("%w: invalid failed investigation", investigation.ErrInvalidTransition)
	}
	repository.investigations[itemKey] = item
	repository.storeTaskCandidates(request.WorkspaceID, taskCandidates)
	incidentKey := scoped(request.WorkspaceID, item.IncidentID)
	if repository.activeInvestigation[incidentKey] == item.ID {
		delete(repository.activeInvestigation, incidentKey)
	}
	repository.failureIdempotency[idempotencyKey] = idempotencyRecord{requestHash: requestHash, resourceID: item.ID}
	repository.bindIdempotencyOwner(idempotencyKey, "fail_investigation")
	return investigation.FailInvestigationResult{Investigation: cloneInvestigation(item)}, nil
}
