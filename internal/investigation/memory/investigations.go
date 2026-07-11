package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func (repository *Repository) CreateOrGetInvestigation(ctx context.Context, request investigation.CreateOrGetInvestigationRequest) (investigation.CreateOrGetInvestigationResult, error) {
	if err := ctx.Err(); err != nil {
		return investigation.CreateOrGetInvestigationResult{}, err
	}
	if request.WorkspaceID == "" || request.IncidentID == "" || !domain.ValidIdempotencyKey(request.IdempotencyKey) {
		return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf("%w: invalid investigation identity", investigation.ErrInvalidRequest)
	}
	canonicalTasks, taskHash, err := investigation.CanonicalTaskSpecs(request.Tasks)
	if err != nil {
		return investigation.CreateOrGetInvestigationResult{}, err
	}
	requestDigest := sha256.Sum256([]byte(request.IncidentID + "\x00" + taskHash))
	requestHash := fmt.Sprintf("%x", requestDigest[:])
	now := repository.clock().UTC()
	if now.IsZero() {
		return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf("%w: clock returned zero time", investigation.ErrInvalidRequest)
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	idempotencyKey := scoped(request.WorkspaceID, request.IdempotencyKey)
	if record, exists := repository.investigationIdempotency[idempotencyKey]; exists {
		if record.requestHash != requestHash {
			return investigation.CreateOrGetInvestigationResult{}, store.ErrIdempotencyConflict
		}
		return repository.investigationResult(request.WorkspaceID, record.resourceID, false)
	}
	incidentKey := scoped(request.WorkspaceID, request.IncidentID)
	incident, exists := repository.incidents[incidentKey]
	if !exists {
		return investigation.CreateOrGetInvestigationResult{}, store.ErrNotFound
	}
	if activeID := repository.activeInvestigation[incidentKey]; activeID != "" {
		active, found := repository.investigations[scoped(request.WorkspaceID, activeID)]
		if found && (active.Status == domain.InvestigationQueued || active.Status == domain.InvestigationRunning) {
			repository.investigationIdempotency[idempotencyKey] = idempotencyRecord{requestHash: requestHash, resourceID: active.ID}
			return repository.investigationResult(request.WorkspaceID, active.ID, false)
		}
		delete(repository.activeInvestigation, incidentKey)
	}

	investigationID, err := repository.newID()
	if err != nil {
		return investigation.CreateOrGetInvestigationResult{}, err
	}
	if _, duplicate := repository.investigations[scoped(request.WorkspaceID, investigationID)]; duplicate {
		return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf("%w: ID factory returned duplicate investigation ID", investigation.ErrInvalidRequest)
	}
	item := domain.Investigation{
		ID: investigationID, WorkspaceID: request.WorkspaceID, IncidentID: request.IncidentID,
		Status: domain.InvestigationQueued, ModelStatus: domain.ModelPending,
		IdempotencyKey: request.IdempotencyKey, RequestHash: requestHash, CreatedAt: now, UpdatedAt: now,
	}
	if err := item.Validate(); err != nil {
		return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, err)
	}
	taskIDs := make([]string, 0, len(canonicalTasks))
	createdTasks := make([]domain.ReadTask, 0, len(canonicalTasks))
	createdTaskIDs := make(map[string]struct{}, len(canonicalTasks))
	for index, spec := range canonicalTasks {
		taskID, idErr := repository.newID()
		if idErr != nil {
			return investigation.CreateOrGetInvestigationResult{}, idErr
		}
		if _, duplicate := repository.tasks[scoped(request.WorkspaceID, taskID)]; duplicate {
			return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf("%w: ID factory returned duplicate task ID", investigation.ErrInvalidRequest)
		}
		if _, duplicate := createdTaskIDs[taskID]; duplicate {
			return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf("%w: ID factory returned duplicate task ID", investigation.ErrInvalidRequest)
		}
		createdTaskIDs[taskID] = struct{}{}
		inputDigest := sha256.Sum256(spec.Input)
		task := domain.ReadTask{
			ID: taskID, WorkspaceID: request.WorkspaceID, IncidentID: request.IncidentID, InvestigationID: item.ID,
			Key: spec.Key, Position: index + 1, ConnectorID: spec.ConnectorID, Operation: spec.Operation,
			Input: bytes.Clone(spec.Input), InputHash: fmt.Sprintf("%x", inputDigest[:]), Status: domain.ReadTaskQueued,
			CreatedAt: now, UpdatedAt: now,
		}
		if validateErr := task.Validate(); validateErr != nil {
			return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, validateErr)
		}
		taskIDs = append(taskIDs, task.ID)
		createdTasks = append(createdTasks, task)
	}
	if incident.Status == domain.IncidentOpen {
		if err := incident.TransitionAt(domain.IncidentInvestigating, laterTime(now, incident.UpdatedAt)); err != nil {
			return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidTransition, err)
		}
		repository.incidents[incidentKey] = incident
	}
	repository.investigations[scoped(request.WorkspaceID, item.ID)] = item
	for _, task := range createdTasks {
		repository.tasks[scoped(request.WorkspaceID, task.ID)] = task
	}
	repository.taskIDsByInvestigation[scoped(request.WorkspaceID, item.ID)] = append([]string(nil), taskIDs...)
	repository.activeInvestigation[incidentKey] = item.ID
	repository.investigationIdempotency[idempotencyKey] = idempotencyRecord{requestHash: requestHash, resourceID: item.ID}
	return investigation.CreateOrGetInvestigationResult{
		Investigation: cloneInvestigation(item), Tasks: cloneTasks(createdTasks), Created: true,
	}, nil
}

func (repository *Repository) investigationResult(workspaceID, investigationID string, created bool) (investigation.CreateOrGetInvestigationResult, error) {
	item, exists := repository.investigations[scoped(workspaceID, investigationID)]
	if !exists {
		return investigation.CreateOrGetInvestigationResult{}, store.ErrNotFound
	}
	taskIDs := repository.taskIDsByInvestigation[scoped(workspaceID, investigationID)]
	tasks := make([]domain.ReadTask, 0, len(taskIDs))
	for _, taskID := range taskIDs {
		task, found := repository.tasks[scoped(workspaceID, taskID)]
		if !found {
			return investigation.CreateOrGetInvestigationResult{}, store.ErrNotFound
		}
		tasks = append(tasks, cloneTask(task))
	}
	return investigation.CreateOrGetInvestigationResult{
		Investigation: cloneInvestigation(item), Tasks: tasks, Created: created,
	}, nil
}

func (repository *Repository) GetInvestigation(ctx context.Context, workspaceID, investigationID string) (domain.Investigation, error) {
	if err := ctx.Err(); err != nil {
		return domain.Investigation{}, err
	}
	if workspaceID == "" || investigationID == "" {
		return domain.Investigation{}, fmt.Errorf("%w: workspace and investigation IDs are required", investigation.ErrInvalidRequest)
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	item, exists := repository.investigations[scoped(workspaceID, investigationID)]
	if !exists {
		return domain.Investigation{}, store.ErrNotFound
	}
	return cloneInvestigation(item), nil
}

func (repository *Repository) ListInvestigations(ctx context.Context, request investigation.ListInvestigationsRequest) ([]domain.Investigation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if request.WorkspaceID == "" {
		return nil, fmt.Errorf("%w: workspace ID is required", investigation.ErrInvalidRequest)
	}
	statuses := make(map[domain.InvestigationStatus]struct{}, len(request.Statuses))
	for _, status := range request.Statuses {
		if !validInvestigationStatus(status) {
			return nil, fmt.Errorf("%w: invalid investigation status filter", investigation.ErrInvalidRequest)
		}
		statuses[status] = struct{}{}
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	if request.IncidentID != "" {
		if _, exists := repository.incidents[scoped(request.WorkspaceID, request.IncidentID)]; !exists {
			return nil, store.ErrNotFound
		}
	}
	items := make([]domain.Investigation, 0)
	for _, item := range repository.investigations {
		if item.WorkspaceID != request.WorkspaceID || (request.IncidentID != "" && item.IncidentID != request.IncidentID) {
			continue
		}
		if len(statuses) > 0 {
			if _, wanted := statuses[item.Status]; !wanted {
				continue
			}
		}
		items = append(items, cloneInvestigation(item))
	}
	sort.Slice(items, func(left, right int) bool {
		if !items[left].CreatedAt.Equal(items[right].CreatedAt) {
			return items[left].CreatedAt.Before(items[right].CreatedAt)
		}
		return items[left].ID < items[right].ID
	})
	return items, nil
}

func (repository *Repository) GetTask(ctx context.Context, workspaceID, taskID string) (domain.ReadTask, error) {
	if err := ctx.Err(); err != nil {
		return domain.ReadTask{}, err
	}
	if workspaceID == "" || taskID == "" {
		return domain.ReadTask{}, fmt.Errorf("%w: workspace and task IDs are required", investigation.ErrInvalidRequest)
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	task, exists := repository.tasks[scoped(workspaceID, taskID)]
	if !exists {
		return domain.ReadTask{}, store.ErrNotFound
	}
	return cloneTask(task), nil
}

func (repository *Repository) ListTasks(ctx context.Context, request investigation.ListTasksRequest) ([]domain.ReadTask, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if request.WorkspaceID == "" || request.InvestigationID == "" {
		return nil, fmt.Errorf("%w: workspace and investigation IDs are required", investigation.ErrInvalidRequest)
	}
	statuses := make(map[domain.ReadTaskStatus]struct{}, len(request.Statuses))
	for _, status := range request.Statuses {
		if !validReadTaskStatus(status) {
			return nil, fmt.Errorf("%w: invalid read task status filter", investigation.ErrInvalidRequest)
		}
		statuses[status] = struct{}{}
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	if _, exists := repository.investigations[scoped(request.WorkspaceID, request.InvestigationID)]; !exists {
		return nil, store.ErrNotFound
	}
	ids := repository.taskIDsByInvestigation[scoped(request.WorkspaceID, request.InvestigationID)]
	items := make([]domain.ReadTask, 0, len(ids))
	for _, taskID := range ids {
		task, exists := repository.tasks[scoped(request.WorkspaceID, taskID)]
		if !exists {
			return nil, store.ErrNotFound
		}
		if len(statuses) > 0 {
			if _, wanted := statuses[task.Status]; !wanted {
				continue
			}
		}
		items = append(items, cloneTask(task))
	}
	return items, nil
}

func validInvestigationStatus(status domain.InvestigationStatus) bool {
	switch status {
	case domain.InvestigationQueued, domain.InvestigationRunning, domain.InvestigationPartial,
		domain.InvestigationCompleted, domain.InvestigationFailed, domain.InvestigationCancelled:
		return true
	default:
		return false
	}
}

func validReadTaskStatus(status domain.ReadTaskStatus) bool {
	switch status {
	case domain.ReadTaskQueued, domain.ReadTaskRunning, domain.ReadTaskEvidence,
		domain.ReadTaskFailed, domain.ReadTaskCancelled:
		return true
	default:
		return false
	}
}
