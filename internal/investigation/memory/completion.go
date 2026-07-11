package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func (repository *Repository) CompleteTask(ctx context.Context, request investigation.CompleteTaskRequest) (investigation.CompleteTaskResult, error) {
	if err := ctx.Err(); err != nil {
		return investigation.CompleteTaskResult{}, err
	}
	if request.WorkspaceID == "" || request.InvestigationID == "" || request.TaskID == "" || request.RunnerID == "" ||
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
	requestWire, err := json.Marshal(request)
	if err != nil {
		return investigation.CompleteTaskResult{}, fmt.Errorf("%w: encode task completion", investigation.ErrInvalidRequest)
	}
	requestDigest := sha256.Sum256(requestWire)
	requestHash := fmt.Sprintf("%x", requestDigest[:])
	now := repository.clock().UTC()
	if now.IsZero() {
		return investigation.CompleteTaskResult{}, fmt.Errorf("%w: clock returned zero time", investigation.ErrInvalidRequest)
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	idempotencyKey := scoped(request.WorkspaceID, request.IdempotencyKey)
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
		evidence := domain.Evidence{
			ID: evidenceID, WorkspaceID: request.WorkspaceID, IncidentID: task.IncidentID,
			InvestigationID: item.ID, TaskID: task.ID, ConnectorID: task.ConnectorID,
			ContentHash: request.Evidence.ContentHash, Payload: bytes.Clone(request.Evidence.Payload),
			Attributes: cloneStringMap(request.Evidence.Attributes), CollectedAt: request.Evidence.CollectedAt.UTC(), CreatedAt: now,
		}
		if validateErr := evidence.Validate(); validateErr != nil {
			return investigation.CompleteTaskResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, validateErr)
		}
		storedEvidence = &evidence
	}
	receiptID, err := repository.newID()
	if err != nil {
		return investigation.CompleteTaskResult{}, err
	}
	if _, duplicate := repository.receipts[scoped(request.WorkspaceID, receiptID)]; duplicate {
		return investigation.CompleteTaskResult{}, fmt.Errorf("%w: ID factory returned duplicate receipt ID", investigation.ErrInvalidRequest)
	}
	receipt := domain.RunnerEvidenceReceipt{
		ID: receiptID, WorkspaceID: request.WorkspaceID, InvestigationID: item.ID, TaskID: task.ID,
		RunnerID: request.RunnerID, ConnectorID: task.ConnectorID, EvidenceID: evidenceID,
		FailureCode: request.FailureCode, IdempotencyKey: request.IdempotencyKey, ReceivedAt: now,
	}
	if storedEvidence != nil {
		receipt.ContentHash = storedEvidence.ContentHash
	}
	if validateErr := receipt.Validate(); validateErr != nil {
		return investigation.CompleteTaskResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, validateErr)
	}
	if task.StartedAt.IsZero() {
		task.StartedAt = now
	}
	task.Status = request.Status
	task.EvidenceID = evidenceID
	task.FailureCode = request.FailureCode
	task.CompletedAt = now
	task.UpdatedAt = now
	if validateErr := task.Validate(); validateErr != nil {
		return investigation.CompleteTaskResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, validateErr)
	}
	if item.Status == domain.InvestigationQueued {
		item.Status = domain.InvestigationRunning
		item.StartedAt = now
	}
	item.UpdatedAt = now
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
	return repository.taskCompletionResult(request.WorkspaceID, record, false)
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

func (repository *Repository) FinalizeInvestigation(ctx context.Context, request investigation.FinalizeInvestigationRequest) (investigation.FinalizeInvestigationResult, error) {
	if err := ctx.Err(); err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	if request.WorkspaceID == "" || request.InvestigationID == "" || !domain.ValidIdempotencyKey(request.IdempotencyKey) ||
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
	case domain.InvestigationFailed:
		return domain.ValidFailureCode(failureCode) && hypothesisCount == 0 &&
			((modelStatus == domain.ModelFailed && domain.ValidFailureCode(modelFailureCode)) ||
				(modelStatus == domain.ModelSkipped && modelFailureCode == ""))
	case domain.InvestigationCancelled:
		return modelStatus == domain.ModelSkipped && domain.ValidFailureCode(failureCode) && modelFailureCode == "" && hypothesisCount == 0
	default:
		return false
	}
}

func (repository *Repository) RecordFeedback(ctx context.Context, request investigation.RecordFeedbackRequest) (investigation.RecordFeedbackResult, error) {
	if err := ctx.Err(); err != nil {
		return investigation.RecordFeedbackResult{}, err
	}
	if request.WorkspaceID == "" || request.IncidentID == "" || request.InvestigationID == "" || request.HypothesisID == "" ||
		request.Actor.Type != domain.ActorHuman || request.Actor.ID == "" || !domain.ValidIdempotencyKey(request.IdempotencyKey) {
		return investigation.RecordFeedbackResult{}, fmt.Errorf("%w: invalid feedback identity", investigation.ErrInvalidRequest)
	}
	switch request.Verdict {
	case domain.FeedbackConfirmed, domain.FeedbackRejected, domain.FeedbackInconclusive:
	default:
		return investigation.RecordFeedbackResult{}, fmt.Errorf("%w: invalid feedback verdict", investigation.ErrInvalidRequest)
	}
	if err := domain.ValidateSafeJSONObject(request.Details); err != nil {
		return investigation.RecordFeedbackResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, err)
	}
	wire, err := json.Marshal(request)
	if err != nil {
		return investigation.RecordFeedbackResult{}, fmt.Errorf("%w: encode feedback", investigation.ErrInvalidRequest)
	}
	digest := sha256.Sum256(wire)
	requestHash := fmt.Sprintf("%x", digest[:])
	now := repository.clock().UTC()
	if now.IsZero() {
		return investigation.RecordFeedbackResult{}, fmt.Errorf("%w: clock returned zero time", investigation.ErrInvalidRequest)
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	idempotencyKey := scoped(request.WorkspaceID, request.IdempotencyKey)
	if record, exists := repository.feedbackIdempotency[idempotencyKey]; exists {
		if record.requestHash != requestHash {
			return investigation.RecordFeedbackResult{}, store.ErrIdempotencyConflict
		}
		feedback, found := repository.feedback[scoped(request.WorkspaceID, record.resourceID)]
		if !found {
			return investigation.RecordFeedbackResult{}, store.ErrNotFound
		}
		return investigation.RecordFeedbackResult{Feedback: cloneFeedback(feedback)}, nil
	}
	incidentKey := scoped(request.WorkspaceID, request.IncidentID)
	incident, exists := repository.incidents[incidentKey]
	if !exists {
		return investigation.RecordFeedbackResult{}, store.ErrNotFound
	}
	item, exists := repository.investigations[scoped(request.WorkspaceID, request.InvestigationID)]
	if !exists {
		return investigation.RecordFeedbackResult{}, store.ErrNotFound
	}
	hypothesisKey := scoped(request.WorkspaceID, request.HypothesisID)
	hypothesis, exists := repository.hypotheses[hypothesisKey]
	if !exists {
		return investigation.RecordFeedbackResult{}, store.ErrNotFound
	}
	if item.IncidentID != incident.ID || hypothesis.IncidentID != incident.ID || hypothesis.InvestigationID != item.ID {
		return investigation.RecordFeedbackResult{}, store.ErrScopeViolation
	}
	feedbackID, err := repository.newID()
	if err != nil {
		return investigation.RecordFeedbackResult{}, err
	}
	if _, duplicate := repository.feedback[scoped(request.WorkspaceID, feedbackID)]; duplicate {
		return investigation.RecordFeedbackResult{}, fmt.Errorf("%w: ID factory returned duplicate feedback ID", investigation.ErrInvalidRequest)
	}
	feedback := domain.Feedback{
		ID: feedbackID, WorkspaceID: request.WorkspaceID, IncidentID: incident.ID,
		InvestigationID: item.ID, HypothesisID: hypothesis.ID, Actor: request.Actor,
		Verdict: request.Verdict, Details: bytes.Clone(request.Details), CreatedAt: now,
	}
	if validateErr := feedback.Validate(); validateErr != nil {
		return investigation.RecordFeedbackResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, validateErr)
	}
	switch request.Verdict {
	case domain.FeedbackConfirmed:
		if err := incident.ConfirmRootCauseAt(&hypothesis, request.Actor, now); err != nil {
			return investigation.RecordFeedbackResult{}, investigation.ErrInvalidTransition
		}
		repository.incidents[incidentKey] = incident
		repository.hypotheses[hypothesisKey] = cloneHypothesis(hypothesis)
	case domain.FeedbackRejected:
		if hypothesis.Status != domain.HypothesisProposed {
			return investigation.RecordFeedbackResult{}, investigation.ErrInvalidTransition
		}
		hypothesis.Status = domain.HypothesisRejected
		repository.hypotheses[hypothesisKey] = cloneHypothesis(hypothesis)
	case domain.FeedbackInconclusive:
	}
	repository.feedback[scoped(request.WorkspaceID, feedback.ID)] = cloneFeedback(feedback)
	repository.feedbackIdempotency[idempotencyKey] = idempotencyRecord{requestHash: requestHash, resourceID: feedback.ID}
	return investigation.RecordFeedbackResult{Feedback: cloneFeedback(feedback), Created: true}, nil
}

func (repository *Repository) GetEvidence(ctx context.Context, workspaceID, evidenceID string) (domain.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return domain.Evidence{}, err
	}
	if workspaceID == "" || evidenceID == "" {
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
	if request.WorkspaceID == "" || request.InvestigationID == "" {
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
	if workspaceID == "" || hypothesisID == "" {
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
	if request.WorkspaceID == "" || request.InvestigationID == "" {
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
