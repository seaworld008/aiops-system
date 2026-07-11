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

func (repository *Repository) RecordFeedback(ctx context.Context, request investigation.RecordFeedbackRequest) (investigation.RecordFeedbackResult, error) {
	if err := ctx.Err(); err != nil {
		return investigation.RecordFeedbackResult{}, err
	}
	if !validResourceScope(request.WorkspaceID, request.IncidentID, request.InvestigationID, request.HypothesisID, request.Actor.ID) ||
		request.Actor.Type != domain.ActorHuman || !domain.ValidIdempotencyKey(request.IdempotencyKey) {
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

	repository.mu.Lock()
	defer repository.mu.Unlock()
	idempotencyKey := scoped(request.WorkspaceID, request.IdempotencyKey)
	if !repository.idempotencyOwnerMatches(idempotencyKey, "record_feedback") {
		return investigation.RecordFeedbackResult{}, store.ErrIdempotencyConflict
	}
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
	commitAt, err := repository.investigationCommitTime(request.WorkspaceID, item, incident.UpdatedAt, hypothesis.CreatedAt)
	if err != nil {
		return investigation.RecordFeedbackResult{}, err
	}
	feedback := domain.Feedback{
		ID: feedbackID, WorkspaceID: request.WorkspaceID, IncidentID: incident.ID,
		InvestigationID: item.ID, HypothesisID: hypothesis.ID, Actor: request.Actor,
		Verdict: request.Verdict, Details: bytes.Clone(request.Details), CreatedAt: commitAt,
	}
	if validateErr := feedback.Validate(); validateErr != nil {
		return investigation.RecordFeedbackResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, validateErr)
	}
	switch request.Verdict {
	case domain.FeedbackConfirmed:
		if err := incident.ConfirmRootCauseAt(&hypothesis, request.Actor, commitAt); err != nil {
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
	repository.bindIdempotencyOwner(idempotencyKey, "record_feedback")
	return investigation.RecordFeedbackResult{Feedback: cloneFeedback(feedback), Created: true}, nil
}
