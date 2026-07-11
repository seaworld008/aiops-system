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
	now := repository.clock().UTC()
	if now.IsZero() {
		return investigation.StartModelResult{}, fmt.Errorf("%w: clock returned zero time", investigation.ErrInvalidRequest)
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
		item, found := repository.investigations[scoped(request.WorkspaceID, record.resourceID)]
		if !found {
			return investigation.StartModelResult{}, store.ErrNotFound
		}
		return investigation.StartModelResult{Investigation: cloneInvestigation(item), Replayed: true}, nil
	}
	itemKey := scoped(request.WorkspaceID, request.InvestigationID)
	item, exists := repository.investigations[itemKey]
	if !exists {
		return investigation.StartModelResult{}, store.ErrNotFound
	}
	if item.Status != domain.InvestigationRunning || item.ModelStatus != domain.ModelPending {
		return investigation.StartModelResult{}, investigation.ErrInvalidTransition
	}
	item.ModelStatus = domain.ModelRunning
	item.UpdatedAt = laterTime(now, item.UpdatedAt)
	if err := item.Validate(); err != nil {
		return investigation.StartModelResult{}, fmt.Errorf("%w: invalid model transition", investigation.ErrInvalidTransition)
	}
	repository.investigations[itemKey] = item
	repository.modelStartIdempotency[idempotencyKey] = idempotencyRecord{requestHash: requestHash, resourceID: item.ID}
	repository.bindIdempotencyOwner(idempotencyKey, "start_model")
	return investigation.StartModelResult{Investigation: cloneInvestigation(item)}, nil
}
