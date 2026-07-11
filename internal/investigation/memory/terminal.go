package memory

import (
	"fmt"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func (repository *Repository) investigationCommitTime(workspaceID string, item domain.Investigation, extra ...time.Time) (time.Time, error) {
	times := append([]time.Time{item.UpdatedAt, item.CompletedAt}, extra...)
	for _, taskID := range repository.taskIDsByInvestigation[scoped(workspaceID, item.ID)] {
		task, exists := repository.tasks[scoped(workspaceID, taskID)]
		if !exists {
			return time.Time{}, store.ErrNotFound
		}
		times = append(times, task.UpdatedAt, task.CompletedAt)
	}
	for _, evidenceID := range repository.evidenceIDsByInvestigation[scoped(workspaceID, item.ID)] {
		evidence, exists := repository.evidence[scoped(workspaceID, evidenceID)]
		if !exists {
			return time.Time{}, store.ErrNotFound
		}
		times = append(times, evidence.CollectedAt, evidence.CreatedAt)
	}
	now := repository.clock().UTC()
	if now.IsZero() {
		return time.Time{}, fmt.Errorf("%w: clock returned zero time", investigation.ErrInvalidRequest)
	}
	return latestTime(append(times, now)...), nil
}

func latestTime(times ...time.Time) time.Time {
	var latest time.Time
	for _, candidate := range times {
		if candidate.After(latest) {
			latest = candidate.UTC()
		}
	}
	return latest
}

func (repository *Repository) cancelledTaskCandidates(workspaceID, investigationID, failureCode string, commitAt time.Time) ([]domain.ReadTask, error) {
	taskIDs := repository.taskIDsByInvestigation[scoped(workspaceID, investigationID)]
	candidates := make([]domain.ReadTask, 0, len(taskIDs))
	for _, taskID := range taskIDs {
		task, exists := repository.tasks[scoped(workspaceID, taskID)]
		if !exists {
			return nil, store.ErrNotFound
		}
		if task.Status == domain.ReadTaskQueued || task.Status == domain.ReadTaskRunning {
			task.Status = domain.ReadTaskCancelled
			task.FailureCode = failureCode
			task.CompletedAt = commitAt
			task.UpdatedAt = commitAt
			if err := task.Validate(); err != nil {
				return nil, fmt.Errorf("%w: invalid task cancellation", investigation.ErrInvalidTransition)
			}
		}
		candidates = append(candidates, task)
	}
	return candidates, nil
}

func (repository *Repository) storeTaskCandidates(workspaceID string, candidates []domain.ReadTask) {
	for _, task := range candidates {
		repository.tasks[scoped(workspaceID, task.ID)] = task
	}
}
