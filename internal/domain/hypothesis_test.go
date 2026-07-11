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

func TestHypothesisRejectsSensitiveSummaryAndUnknownTextWithoutEcho(t *testing.T) {
	now := time.Date(2026, 7, 12, 15, 30, 0, 0, time.UTC)
	proposal := json.RawMessage(`{"summary":"safe proposal"}`)
	base := domain.Hypothesis{
		ID: "hypothesis-1", WorkspaceID: "workspace-1", IncidentID: "incident-1", InvestigationID: "investigation-1",
		Status: domain.HypothesisProposed, Rank: 1, Confidence: 0.8, Summary: "Safe summary",
		Proposal: proposal, ProposalHash: sha256Hex(proposal), EvidenceIDs: []string{"evidence-1"}, CreatedAt: now,
	}
	readableUnicode := base
	readableUnicode.Summary = "数据库连接池已恢复"
	readableUnicode.Unknowns = []string{"是否仍有重试流量"}
	if err := readableUnicode.Validate(); err != nil {
		t.Fatalf("Validate(readable Unicode) error = %v", err)
	}
	const canary = "hypothesis-sensitive-canary"
	for name, mutate := range map[string]func(*domain.Hypothesis){
		"bearer summary":              func(value *domain.Hypothesis) { value.Summary = "Bearer " + canary },
		"invalid UTF-8 summary":       func(value *domain.Hypothesis) { value.Summary = canary + string([]byte{0xff}) },
		"authorization summary":       func(value *domain.Hypothesis) { value.Summary = "Authorization " + canary },
		"password assignment summary": func(value *domain.Hypothesis) { value.Summary = "PASSWORD = " + canary },
		"prefixed password summary":   func(value *domain.Hypothesis) { value.Summary = "dbPassword=" + canary },
		"NUL summary":                 func(value *domain.Hypothesis) { value.Summary = canary + "\x00text" },
		"cookie unknown":              func(value *domain.Hypothesis) { value.Unknowns = []string{"Cookie " + canary} },
		"invalid UTF-8 unknown":       func(value *domain.Hypothesis) { value.Unknowns = []string{canary + string([]byte{0xff})} },
		"Unicode control unknown":     func(value *domain.Hypothesis) { value.Unknowns = []string{canary + "\u0085text"} },
		"replacement rune unknown":    func(value *domain.Hypothesis) { value.Unknowns = []string{canary + "�"} },
		"token assignment unknown":    func(value *domain.Hypothesis) { value.Unknowns = []string{"token: " + canary} },
		"prefixed token unknown":      func(value *domain.Hypothesis) { value.Unknowns = []string{"accessToken=" + canary} },
		"private key unknown":         func(value *domain.Hypothesis) { value.Unknowns = []string{"BEGIN PRIVATE KEY " + canary} },
		"raw error unknown":           func(value *domain.Hypothesis) { value.Unknowns = []string{"raw error body " + canary} },
	} {
		t.Run(name, func(t *testing.T) {
			item := base
			mutate(&item)
			err := item.Validate()
			if err == nil {
				t.Fatal("Validate() error = nil, want sensitive text rejection")
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatalf("Validate() echoed sensitive text: %v", err)
			}
		})
	}
}
