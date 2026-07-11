package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func (repository *Repository) CompleteTask(ctx context.Context, request investigation.CompleteTaskRequest) (investigation.CompleteTaskResult, error) {
	if err := ctx.Err(); err != nil {
		return investigation.CompleteTaskResult{}, err
	}
	if !validResourceScope(request.WorkspaceID, request.InvestigationID, request.TaskID, request.RunnerID) ||
		!domain.ValidIdempotencyKey(request.IdempotencyKey) {
		return investigation.CompleteTaskResult{}, fmt.Errorf("%w: invalid task completion identity", investigation.ErrInvalidRequest)
	}
	switch request.Status {
	case domain.ReadTaskEvidence:
		if request.Evidence == nil || request.FailureCode != "" {
			return investigation.CompleteTaskResult{}, fmt.Errorf("%w: evidence completion requires evidence only", investigation.ErrInvalidRequest)
		}
	case domain.ReadTaskFailed, domain.ReadTaskCancelled:
		if request.Evidence != nil || !domain.ValidFailureCode(request.FailureCode) {
			return investigation.CompleteTaskResult{}, fmt.Errorf("%w: failed completion requires a bounded failure code", investigation.ErrInvalidRequest)
		}
	default:
		return investigation.CompleteTaskResult{}, fmt.Errorf("%w: invalid task completion status", investigation.ErrInvalidRequest)
	}
	if err := validateCompleteTaskBody(request); err != nil {
		return investigation.CompleteTaskResult{}, err
	}
	requestWire, err := json.Marshal(request)
	if err != nil {
		return investigation.CompleteTaskResult{}, fmt.Errorf("%w: encode task completion", investigation.ErrInvalidRequest)
	}
	requestDigest := sha256.Sum256(requestWire)
	requestHash := fmt.Sprintf("%x", requestDigest[:])

	repository.mu.Lock()
	defer repository.mu.Unlock()
	idempotencyKey := scoped(request.WorkspaceID, request.IdempotencyKey)
	if !repository.idempotencyOwnerMatches(idempotencyKey, "complete_task") {
		return investigation.CompleteTaskResult{}, store.ErrIdempotencyConflict
	}
	if record, exists := repository.taskCompletionIdempotency[idempotencyKey]; exists {
		if record.requestHash != requestHash {
			return investigation.CompleteTaskResult{}, store.ErrIdempotencyConflict
		}
		return repository.taskCompletionResult(request.WorkspaceID, record, true)
	}
	item, exists := repository.investigations[scoped(request.WorkspaceID, request.InvestigationID)]
	if !exists {
		return investigation.CompleteTaskResult{}, store.ErrNotFound
	}
	task, exists := repository.tasks[scoped(request.WorkspaceID, request.TaskID)]
	if !exists {
		return investigation.CompleteTaskResult{}, store.ErrNotFound
	}
	if task.InvestigationID != item.ID {
		return investigation.CompleteTaskResult{}, store.ErrScopeViolation
	}
	if task.Status != domain.ReadTaskQueued && task.Status != domain.ReadTaskRunning {
		return investigation.CompleteTaskResult{}, investigation.ErrInvalidTransition
	}
	if item.Status != domain.InvestigationQueued && item.Status != domain.InvestigationRunning {
		return investigation.CompleteTaskResult{}, investigation.ErrInvalidTransition
	}

	var storedEvidence *domain.Evidence
	evidenceID := ""
	if request.Status == domain.ReadTaskEvidence {
		evidenceID, err = repository.newID()
		if err != nil {
			return investigation.CompleteTaskResult{}, err
		}
		if _, duplicate := repository.evidence[scoped(request.WorkspaceID, evidenceID)]; duplicate {
			return investigation.CompleteTaskResult{}, fmt.Errorf("%w: ID factory returned duplicate evidence ID", investigation.ErrInvalidRequest)
		}
	}
	receiptID, err := repository.newID()
	if err != nil {
		return investigation.CompleteTaskResult{}, err
	}
	if _, duplicate := repository.receipts[scoped(request.WorkspaceID, receiptID)]; duplicate {
		return investigation.CompleteTaskResult{}, fmt.Errorf("%w: ID factory returned duplicate receipt ID", investigation.ErrInvalidRequest)
	}
	commitAt, err := repository.investigationCommitTime(request.WorkspaceID, item)
	if err != nil {
		return investigation.CompleteTaskResult{}, err
	}
	if request.Evidence != nil && request.Evidence.CollectedAt.After(commitAt) {
		return investigation.CompleteTaskResult{}, fmt.Errorf("%w: evidence collection time is in the future", investigation.ErrInvalidRequest)
	}
	if request.Status == domain.ReadTaskEvidence {
		evidence := domain.Evidence{
			ID: evidenceID, WorkspaceID: request.WorkspaceID, IncidentID: task.IncidentID,
			InvestigationID: item.ID, TaskID: task.ID, ConnectorID: task.ConnectorID,
			ContentHash: request.Evidence.ContentHash, Payload: bytes.Clone(request.Evidence.Payload),
			Attributes: cloneStringMap(request.Evidence.Attributes), CollectedAt: request.Evidence.CollectedAt.UTC(), CreatedAt: commitAt,
		}
		if validateErr := evidence.Validate(); validateErr != nil {
			return investigation.CompleteTaskResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, validateErr)
		}
		storedEvidence = &evidence
	}
	receipt := domain.RunnerEvidenceReceipt{
		ID: receiptID, WorkspaceID: request.WorkspaceID, InvestigationID: item.ID, TaskID: task.ID,
		RunnerID: request.RunnerID, ConnectorID: task.ConnectorID, EvidenceID: evidenceID,
		FailureCode: request.FailureCode, IdempotencyKey: request.IdempotencyKey, ReceivedAt: commitAt,
	}
	if storedEvidence != nil {
		receipt.ContentHash = storedEvidence.ContentHash
	}
	if validateErr := receipt.Validate(); validateErr != nil {
		return investigation.CompleteTaskResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, validateErr)
	}
	if task.StartedAt.IsZero() {
		task.StartedAt = commitAt
	}
	task.Status = request.Status
	task.EvidenceID = evidenceID
	task.FailureCode = request.FailureCode
	task.CompletedAt = commitAt
	task.UpdatedAt = commitAt
	if validateErr := task.Validate(); validateErr != nil {
		return investigation.CompleteTaskResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, validateErr)
	}
	if item.Status == domain.InvestigationQueued {
		item.Status = domain.InvestigationRunning
		item.StartedAt = commitAt
	}
	item.UpdatedAt = commitAt
	if validateErr := item.Validate(); validateErr != nil {
		return investigation.CompleteTaskResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, validateErr)
	}
	repository.tasks[scoped(request.WorkspaceID, task.ID)] = task
	repository.investigations[scoped(request.WorkspaceID, item.ID)] = item
	if storedEvidence != nil {
		repository.evidence[scoped(request.WorkspaceID, storedEvidence.ID)] = cloneEvidence(*storedEvidence)
		repository.evidenceIDsByInvestigation[scoped(request.WorkspaceID, item.ID)] = append(
			repository.evidenceIDsByInvestigation[scoped(request.WorkspaceID, item.ID)], storedEvidence.ID,
		)
	}
	repository.receipts[scoped(request.WorkspaceID, receipt.ID)] = receipt
	record := taskCompletionRecord{requestHash: requestHash, taskID: task.ID, evidenceID: evidenceID, receiptID: receipt.ID}
	repository.taskCompletionIdempotency[idempotencyKey] = record
	repository.bindIdempotencyOwner(idempotencyKey, "complete_task")
	return repository.taskCompletionResult(request.WorkspaceID, record, false)
}

func validateCompleteTaskBody(request investigation.CompleteTaskRequest) error {
	if request.Status != domain.ReadTaskEvidence {
		return nil
	}
	if err := domain.ValidateSafeJSONObject(request.Evidence.Payload); err != nil ||
		!domain.ValidSHA256Hex(request.Evidence.ContentHash) ||
		!hashMatches(request.Evidence.Payload, request.Evidence.ContentHash) ||
		domain.ValidateSafeAttributes(request.Evidence.Attributes) != nil ||
		request.Evidence.CollectedAt.IsZero() {
		return fmt.Errorf("%w: invalid evidence body", investigation.ErrInvalidRequest)
	}
	return nil
}

func hashMatches(value []byte, expected string) bool {
	digest := sha256.Sum256(value)
	return fmt.Sprintf("%x", digest[:]) == expected
}

func (repository *Repository) taskCompletionResult(workspaceID string, record taskCompletionRecord, replayed bool) (investigation.CompleteTaskResult, error) {
	task, exists := repository.tasks[scoped(workspaceID, record.taskID)]
	if !exists {
		return investigation.CompleteTaskResult{}, store.ErrNotFound
	}
	receipt, exists := repository.receipts[scoped(workspaceID, record.receiptID)]
	if !exists {
		return investigation.CompleteTaskResult{}, store.ErrNotFound
	}
	result := investigation.CompleteTaskResult{Task: cloneTask(task), Receipt: receipt, Replayed: replayed}
	if record.evidenceID != "" {
		evidence, found := repository.evidence[scoped(workspaceID, record.evidenceID)]
		if !found {
			return investigation.CompleteTaskResult{}, store.ErrNotFound
		}
		cloned := cloneEvidence(evidence)
		result.Evidence = &cloned
	}
	return result, nil
}
