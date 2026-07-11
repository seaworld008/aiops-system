package domain_test

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
)

func TestHypothesisValidateEnforcesRankedEvidenceBackedProposal(t *testing.T) {
	now := time.Date(2026, 7, 11, 11, 0, 0, 0, time.UTC)
	proposal := json.RawMessage(`{"summary":"latency follows a saturated connection pool"}`)
	valid := domain.Hypothesis{
		ID: "hypothesis-1", WorkspaceID: "workspace-1", IncidentID: "incident-1", InvestigationID: "investigation-1",
		Status: domain.HypothesisProposed, Rank: 1, Confidence: 0.82,
		Summary: "Database connection pool saturation", Proposal: proposal, ProposalHash: sha256Hex(proposal),
		Unknowns: []string{"Whether retries amplified the queue"}, EvidenceIDs: []string{"evidence-1"}, CreatedAt: now,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want valid hypothesis", err)
	}

	for name, mutate := range map[string]func(*domain.Hypothesis){
		"rank zero":       func(value *domain.Hypothesis) { value.Rank = 0 },
		"confidence high": func(value *domain.Hypothesis) { value.Confidence = 1.01 },
		"confidence nan":  func(value *domain.Hypothesis) { value.Confidence = math.NaN() },
		"hash mismatch":   func(value *domain.Hypothesis) { value.ProposalHash = strings.Repeat("0", 64) },
		"no evidence":     func(value *domain.Hypothesis) { value.EvidenceIDs = nil },
		"duplicate evidence": func(value *domain.Hypothesis) {
			value.EvidenceIDs = []string{"evidence-1", "evidence-1"}
		},
		"blank unknown": func(value *domain.Hypothesis) { value.Unknowns = []string{" "} },
	} {
		t.Run(name, func(t *testing.T) {
			item := valid
			item.Unknowns = append([]string(nil), valid.Unknowns...)
			item.EvidenceIDs = append([]string(nil), valid.EvidenceIDs...)
			mutate(&item)
			if err := item.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want hypothesis contract rejection")
			}
		})
	}
}
