package domain

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
)

type HypothesisStatus string

const (
	HypothesisProposed  HypothesisStatus = "PROPOSED"
	HypothesisConfirmed HypothesisStatus = "CONFIRMED"
	HypothesisRejected  HypothesisStatus = "REJECTED"
)

type Hypothesis struct {
	ID              string
	WorkspaceID     string
	IncidentID      string
	InvestigationID string
	Status          HypothesisStatus
	Rank            int
	Confidence      float64
	Summary         string
	Proposal        json.RawMessage
	ProposalHash    string
	Unknowns        []string
	EvidenceIDs     []string
	CreatedAt       time.Time
}

func (hypothesis Hypothesis) Validate() error {
	if !validIdentifier(hypothesis.ID, 256) || !validIdentifier(hypothesis.WorkspaceID, 256) ||
		!validIdentifier(hypothesis.IncidentID, 256) || !validIdentifier(hypothesis.InvestigationID, 256) {
		return fmt.Errorf("hypothesis identifiers are invalid")
	}
	switch hypothesis.Status {
	case HypothesisProposed, HypothesisConfirmed, HypothesisRejected:
	default:
		return fmt.Errorf("invalid hypothesis status %q", hypothesis.Status)
	}
	if hypothesis.Rank <= 0 || hypothesis.Rank > 100 {
		return fmt.Errorf("hypothesis rank must be between 1 and 100")
	}
	if math.IsNaN(hypothesis.Confidence) || math.IsInf(hypothesis.Confidence, 0) ||
		hypothesis.Confidence < 0 || hypothesis.Confidence > 1 {
		return fmt.Errorf("hypothesis confidence must be between 0 and 1")
	}
	if hypothesis.Summary == "" || hypothesis.Summary != strings.TrimSpace(hypothesis.Summary) ||
		len(hypothesis.Summary) > 4096 || !ValidSafeText(hypothesis.Summary) {
		return fmt.Errorf("hypothesis summary is invalid")
	}
	if err := validateHashedJSONObject(hypothesis.Proposal, hypothesis.ProposalHash); err != nil {
		return fmt.Errorf("hypothesis proposal: %w", err)
	}
	if len(hypothesis.Unknowns) > 32 {
		return fmt.Errorf("hypothesis unknowns exceed limit")
	}
	for _, unknown := range hypothesis.Unknowns {
		if unknown == "" || unknown != strings.TrimSpace(unknown) || len(unknown) > 512 || !ValidSafeText(unknown) {
			return fmt.Errorf("hypothesis unknown is invalid")
		}
	}
	if len(hypothesis.EvidenceIDs) == 0 || len(hypothesis.EvidenceIDs) > 64 {
		return fmt.Errorf("hypothesis evidence IDs exceed limits")
	}
	seen := make(map[string]struct{}, len(hypothesis.EvidenceIDs))
	for _, evidenceID := range hypothesis.EvidenceIDs {
		if !validIdentifier(evidenceID, 256) {
			return fmt.Errorf("hypothesis evidence ID is invalid")
		}
		if _, duplicate := seen[evidenceID]; duplicate {
			return fmt.Errorf("hypothesis evidence IDs must be unique")
		}
		seen[evidenceID] = struct{}{}
	}
	if hypothesis.CreatedAt.IsZero() {
		return fmt.Errorf("hypothesis creation time is required")
	}
	return nil
}
