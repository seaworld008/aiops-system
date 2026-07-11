package memory

import (
	"context"
	"fmt"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func (repository *Repository) StartModel(ctx context.Context, request investigation.StartModelRequest) (investigation.StartModelResult, error) {
	if err := ctx.Err(); err != nil {
		return investigation.StartModelResult{}, err
	}
	if !validResourceScope(request.WorkspaceID, request.InvestigationID) || !domain.ValidIdempotencyKey(request.IdempotencyKey) {
		return investigation.StartModelResult{}, fmt.Errorf("%w: invalid model start request", investigation.ErrInvalidRequest)
	}
	requestHash, err := investigation.StartModelRequestHash(request)
	if err != nil {
		return investigation.StartModelResult{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	idempotencyKey := scoped(request.WorkspaceID, request.IdempotencyKey)
	if !repository.idempotencyOwnerMatches(idempotencyKey, "start_model") {
		return investigation.StartModelResult{}, store.ErrIdempotencyConflict
	}
	if record, exists := repository.modelStartIdempotency[idempotencyKey]; exists {
		if record.requestHash != requestHash {
			return investigation.StartModelResult{}, store.ErrIdempotencyConflict
		}
		result := cloneStartModelResult(record.result)
		result.Replayed = true
		return result, nil
	}
	itemKey := scoped(request.WorkspaceID, request.InvestigationID)
	item, exists := repository.investigations[itemKey]
	if !exists {
		return investigation.StartModelResult{}, store.ErrNotFound
	}
	if item.Status != domain.InvestigationRunning || item.ModelStatus != domain.ModelPending {
		return investigation.StartModelResult{}, investigation.ErrInvalidTransition
	}
	for _, taskID := range repository.taskIDsByInvestigation[scoped(request.WorkspaceID, item.ID)] {
		task, found := repository.tasks[scoped(request.WorkspaceID, taskID)]
		if !found {
			return investigation.StartModelResult{}, store.ErrNotFound
		}
		switch task.Status {
		case domain.ReadTaskEvidence, domain.ReadTaskFailed, domain.ReadTaskCancelled:
		default:
			return investigation.StartModelResult{}, investigation.ErrInvalidTransition
		}
	}
	commitAt, err := repository.investigationCommitTime(request.WorkspaceID, item)
	if err != nil {
		return investigation.StartModelResult{}, err
	}
	item.ModelStatus = domain.ModelRunning
	item.UpdatedAt = commitAt
	if err := item.Validate(); err != nil {
		return investigation.StartModelResult{}, fmt.Errorf("%w: invalid model transition", investigation.ErrInvalidTransition)
	}
	repository.investigations[itemKey] = item
	result := investigation.StartModelResult{Investigation: cloneInvestigation(item)}
	repository.modelStartIdempotency[idempotencyKey] = modelStartRecord{
		requestHash: requestHash,
		result:      cloneStartModelResult(result),
	}
	repository.bindIdempotencyOwner(idempotencyKey, "start_model")
	return cloneStartModelResult(result), nil
}
