package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func (repository *Repository) CreateOrGetInvestigation(ctx context.Context, request investigation.CreateOrGetInvestigationRequest) (investigation.CreateOrGetInvestigationResult, error) {
	if err := ctx.Err(); err != nil {
		return investigation.CreateOrGetInvestigationResult{}, err
	}
	if !validResourceScope(request.WorkspaceID, request.IncidentID) || !domain.ValidIdempotencyKey(request.IdempotencyKey) {
		return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf("%w: invalid investigation identity", investigation.ErrInvalidRequest)
	}
	canonicalTasks, taskHash, err := investigation.CanonicalTaskSpecs(request.Tasks)
	if err != nil {
		return investigation.CreateOrGetInvestigationResult{}, err
	}
	requestHash, err := investigation.CreateOrGetInvestigationRequestHash(request, taskHash)
	if err != nil {
		return investigation.CreateOrGetInvestigationResult{}, err
	}
	idempotencyKey := scoped(request.WorkspaceID, request.IdempotencyKey)
	repository.mu.RLock()
	replay, replayErr, handled := repository.createInvestigationReplayLocked(request.WorkspaceID, idempotencyKey, requestHash)
	repository.mu.RUnlock()
	if handled {
		return replay, replayErr
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if replay, replayErr, handled = repository.createInvestigationReplayLocked(request.WorkspaceID, idempotencyKey, requestHash); handled {
		return replay, replayErr
	}
	incidentKey := scoped(request.WorkspaceID, request.IncidentID)
	incident, exists := repository.incidents[incidentKey]
	if !exists {
		return investigation.CreateOrGetInvestigationResult{}, store.ErrNotFound
	}
	var active domain.Investigation
	activeFound := false
	if activeID := repository.activeInvestigation[incidentKey]; activeID != "" {
		candidate, found := repository.investigations[scoped(request.WorkspaceID, activeID)]
		if found && (candidate.Status == domain.InvestigationQueued || candidate.Status == domain.InvestigationRunning) {
			active = candidate
			activeFound = true
		} else {
			delete(repository.activeInvestigation, incidentKey)
		}
	}
	if !activeFound && incident.Status != domain.IncidentOpen && incident.Status != domain.IncidentInvestigating &&
		incident.Status != domain.IncidentMitigating {
		return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf(
			"%w: terminal incident cannot start a new investigation", investigation.ErrInvalidTransition,
		)
	}
	scope := investigation.TaskSpecScope{
		TenantID:      incident.TenantID,
		WorkspaceID:   incident.WorkspaceID,
		EnvironmentID: incident.EnvironmentID,
		ServiceID:     incident.ServiceID,
		MappingStatus: incident.MappingStatus,
	}
	if err := investigation.AuthorizeTaskSpecs(ctx, repository.taskSpecAuthorizer, scope, canonicalTasks); err != nil {
		return investigation.CreateOrGetInvestigationResult{}, err
	}
	runtimeComponents, err := investigation.ResolveTaskRuntimeComponents(
		ctx, repository.taskRuntimeBinder, scope, request.PlanBinding, canonicalTasks,
	)
	if err != nil {
		return investigation.CreateOrGetInvestigationResult{}, err
	}
	if activeFound {
		if active.RequestHashVersion != domain.InvestigationCreateRequestVersionV2 ||
			active.RequestHash != requestHash || !active.PlanBinding.Equal(request.PlanBinding) ||
			!repository.activeRuntimeBindingsMatch(request.WorkspaceID, active.ID, scope, canonicalTasks, runtimeComponents) {
			return investigation.CreateOrGetInvestigationResult{}, store.ErrIdempotencyConflict
		}
		repository.investigationIdempotency[idempotencyKey] = idempotencyRecord{requestHash: requestHash, resourceID: active.ID}
		repository.bindIdempotencyOwner(idempotencyKey, "create_investigation")
		return repository.investigationResult(request.WorkspaceID, active.ID, false)
	}

	investigationID, err := repository.newID()
	if err != nil {
		return investigation.CreateOrGetInvestigationResult{}, err
	}
	if _, duplicate := repository.investigations[scoped(request.WorkspaceID, investigationID)]; duplicate {
		return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf("%w: ID factory returned duplicate investigation ID", investigation.ErrInvalidRequest)
	}
	taskIDs := make([]string, len(canonicalTasks))
	createdTaskIDs := make(map[string]struct{}, len(canonicalTasks))
	for index := range canonicalTasks {
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
		taskIDs[index] = taskID
	}
	now := repository.clock().UTC()
	if now.IsZero() {
		return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf("%w: clock returned zero time", investigation.ErrInvalidRequest)
	}
	commitBoundary := latestTime(now, incident.OpenedAt, incident.LastSignalAt, incident.UpdatedAt).UTC()
	commitAt := commitBoundary.Truncate(time.Microsecond)
	if commitAt.Before(commitBoundary) {
		commitAt = commitAt.Add(time.Microsecond)
	}
	item := domain.Investigation{
		ID: investigationID, WorkspaceID: request.WorkspaceID, IncidentID: request.IncidentID,
		Status: domain.InvestigationQueued, ModelStatus: domain.ModelPending,
		IdempotencyKey: request.IdempotencyKey, RequestHash: requestHash,
		RequestHashVersion: domain.InvestigationCreateRequestVersionV2, PlanBinding: request.PlanBinding,
		CreatedAt: commitAt, UpdatedAt: commitAt,
	}
	if err := item.Validate(); err != nil {
		return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, err)
	}
	createdTasks := make([]domain.ReadTask, 0, len(canonicalTasks))
	for index, spec := range canonicalTasks {
		inputDigest := sha256.Sum256(spec.Input)
		runtimeBinding, bindingErr := investigation.BuildReadTaskRuntimeBinding(
			scope, request.PlanBinding, spec, index+1, runtimeComponents[index], commitAt,
		)
		if bindingErr != nil {
			return investigation.CreateOrGetInvestigationResult{}, bindingErr
		}
		task := domain.ReadTask{
			ID: taskIDs[index], WorkspaceID: request.WorkspaceID, IncidentID: request.IncidentID, InvestigationID: item.ID,
			Key: spec.Key, Position: index + 1, ConnectorID: spec.ConnectorID, Operation: spec.Operation,
			Input: bytes.Clone(spec.Input), InputHash: fmt.Sprintf("%x", inputDigest[:]), Status: domain.ReadTaskQueued,
			RuntimeBinding: runtimeBinding,
			CreatedAt:      commitAt, UpdatedAt: commitAt,
		}
		if validateErr := task.Validate(); validateErr != nil {
			return investigation.CreateOrGetInvestigationResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, validateErr)
		}
		createdTasks = append(createdTasks, task)
	}
	if incident.Status == domain.IncidentOpen {
		if err := incident.TransitionAt(domain.IncidentInvestigating, commitAt); err != nil {
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
	repository.bindIdempotencyOwner(idempotencyKey, "create_investigation")
	return investigation.CreateOrGetInvestigationResult{
		Investigation: cloneInvestigation(item), Tasks: cloneTasks(createdTasks), Created: true,
	}, nil
}

// activeRuntimeBindingsMatch verifies the locked active resource against the
// current trusted plan and binder output. A new idempotency key may bind to an
// existing active v2 Investigation only when every immutable task and runtime
// digest still matches; legacy or drifted state is never upgraded in place.
func (repository *Repository) activeRuntimeBindingsMatch(
	workspaceID, investigationID string,
	scope investigation.TaskSpecScope,
	specs []investigation.TaskSpec,
	components []investigation.TaskRuntimeComponents,
) bool {
	taskIDs := repository.taskIDsByInvestigation[scoped(workspaceID, investigationID)]
	if len(taskIDs) != len(specs) || len(components) != len(specs) {
		return false
	}
	for index, taskID := range taskIDs {
		task, found := repository.tasks[scoped(workspaceID, taskID)]
		if !found || task.Position != index+1 || task.Key != specs[index].Key ||
			task.ConnectorID != specs[index].ConnectorID || task.Operation != specs[index].Operation ||
			!bytes.Equal(task.Input, specs[index].Input) || task.RuntimeBinding.IsZero() {
			return false
		}
		expected, err := investigation.BuildReadTaskRuntimeBinding(
			scope, repository.investigations[scoped(workspaceID, investigationID)].PlanBinding,
			specs[index], index+1, components[index], task.RuntimeBinding.BoundAt,
		)
		if err != nil || !task.RuntimeBinding.Equal(expected) {
			return false
		}
	}
	return true
}

// createInvestigationReplayLocked checks the immutable workspace-scoped
// idempotency owner before any mutable server-side authorization. The caller
// must hold repository.mu for reading or writing.
func (repository *Repository) createInvestigationReplayLocked(
	workspaceID string,
	idempotencyKey scopeKey,
	requestHash string,
) (investigation.CreateOrGetInvestigationResult, error, bool) {
	if !repository.idempotencyOwnerMatches(idempotencyKey, "create_investigation") {
		return investigation.CreateOrGetInvestigationResult{}, store.ErrIdempotencyConflict, true
	}
	record, exists := repository.investigationIdempotency[idempotencyKey]
	if !exists {
		return investigation.CreateOrGetInvestigationResult{}, nil, false
	}
	if record.requestHash != requestHash {
		return investigation.CreateOrGetInvestigationResult{}, store.ErrIdempotencyConflict, true
	}
	result, err := repository.investigationResult(workspaceID, record.resourceID, false)
	return result, err, true
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
	if !validResourceScope(workspaceID, investigationID) {
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
	if !domain.ValidResourceID(request.WorkspaceID) || (request.IncidentID != "" && !domain.ValidResourceID(request.IncidentID)) {
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
	if !validResourceScope(workspaceID, taskID) {
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
	if !validResourceScope(request.WorkspaceID, request.InvestigationID) {
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
