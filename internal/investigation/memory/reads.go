package memory

import (
	"context"
	"fmt"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func (repository *Repository) GetEvidence(ctx context.Context, workspaceID, evidenceID string) (domain.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return domain.Evidence{}, err
	}
	if !validResourceScope(workspaceID, evidenceID) {
		return domain.Evidence{}, fmt.Errorf("%w: workspace and evidence IDs are required", investigation.ErrInvalidRequest)
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	evidence, exists := repository.evidence[scoped(workspaceID, evidenceID)]
	if !exists {
		return domain.Evidence{}, store.ErrNotFound
	}
	return cloneEvidence(evidence), nil
}

func (repository *Repository) ListEvidence(ctx context.Context, request investigation.ListEvidenceRequest) ([]domain.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validResourceScope(request.WorkspaceID, request.InvestigationID) ||
		(request.TaskID != "" && !domain.ValidResourceID(request.TaskID)) {
		return nil, fmt.Errorf("%w: workspace and investigation IDs are required", investigation.ErrInvalidRequest)
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	if _, exists := repository.investigations[scoped(request.WorkspaceID, request.InvestigationID)]; !exists {
		return nil, store.ErrNotFound
	}
	ids := repository.evidenceIDsByInvestigation[scoped(request.WorkspaceID, request.InvestigationID)]
	items := make([]domain.Evidence, 0, len(ids))
	for _, evidenceID := range ids {
		evidence, exists := repository.evidence[scoped(request.WorkspaceID, evidenceID)]
		if !exists {
			return nil, store.ErrNotFound
		}
		if request.TaskID != "" && evidence.TaskID != request.TaskID {
			continue
		}
		items = append(items, cloneEvidence(evidence))
	}
	return items, nil
}

func (repository *Repository) GetHypothesis(ctx context.Context, workspaceID, hypothesisID string) (domain.Hypothesis, error) {
	if err := ctx.Err(); err != nil {
		return domain.Hypothesis{}, err
	}
	if !validResourceScope(workspaceID, hypothesisID) {
		return domain.Hypothesis{}, fmt.Errorf("%w: workspace and hypothesis IDs are required", investigation.ErrInvalidRequest)
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	hypothesis, exists := repository.hypotheses[scoped(workspaceID, hypothesisID)]
	if !exists {
		return domain.Hypothesis{}, store.ErrNotFound
	}
	return cloneHypothesis(hypothesis), nil
}

func (repository *Repository) ListHypotheses(ctx context.Context, request investigation.ListHypothesesRequest) ([]domain.Hypothesis, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validResourceScope(request.WorkspaceID, request.InvestigationID) {
		return nil, fmt.Errorf("%w: workspace and investigation IDs are required", investigation.ErrInvalidRequest)
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	if _, exists := repository.investigations[scoped(request.WorkspaceID, request.InvestigationID)]; !exists {
		return nil, store.ErrNotFound
	}
	ids := repository.hypothesisIDsByInvestigation[scoped(request.WorkspaceID, request.InvestigationID)]
	items := make([]domain.Hypothesis, 0, len(ids))
	for _, hypothesisID := range ids {
		hypothesis, exists := repository.hypotheses[scoped(request.WorkspaceID, hypothesisID)]
		if !exists {
			return nil, store.ErrNotFound
		}
		items = append(items, cloneHypothesis(hypothesis))
	}
	return items, nil
}
