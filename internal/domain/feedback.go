package domain

import (
	"encoding/json"
	"fmt"
	"time"
)

type FeedbackVerdict string

const (
	FeedbackConfirmed    FeedbackVerdict = "CONFIRMED"
	FeedbackRejected     FeedbackVerdict = "REJECTED"
	FeedbackInconclusive FeedbackVerdict = "INCONCLUSIVE"
)

type Feedback struct {
	ID              string
	WorkspaceID     string
	IncidentID      string
	InvestigationID string
	HypothesisID    string
	Actor           Actor
	Verdict         FeedbackVerdict
	Details         json.RawMessage
	CreatedAt       time.Time
}

func (feedback Feedback) Validate() error {
	if !validIdentifier(feedback.ID, 256) || !validIdentifier(feedback.WorkspaceID, 256) ||
		!validIdentifier(feedback.IncidentID, 256) || !validIdentifier(feedback.InvestigationID, 256) ||
		!validIdentifier(feedback.HypothesisID, 256) {
		return fmt.Errorf("feedback identifiers are invalid")
	}
	if feedback.Actor.Type != ActorHuman || !validIdentifier(feedback.Actor.ID, 256) {
		return fmt.Errorf("feedback requires an authenticated human")
	}
	switch feedback.Verdict {
	case FeedbackConfirmed, FeedbackRejected, FeedbackInconclusive:
	default:
		return fmt.Errorf("invalid feedback verdict %q", feedback.Verdict)
	}
	if err := ValidateSafeJSONObject(feedback.Details); err != nil {
		return fmt.Errorf("feedback details: %w", err)
	}
	if feedback.CreatedAt.IsZero() {
		return fmt.Errorf("feedback creation time is required")
	}
	return nil
}
