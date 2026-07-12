package postgres

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

func TestStartModelSnapshotRoundTripExcludesReplayFlag(t *testing.T) {
	result := investigation.StartModelResult{Investigation: snapshotInvestigation(), Replayed: true}
	document, digest, err := encodeStartModelSnapshot(result)
	if err != nil || len(document) < 2 || !domain.ValidSHA256Hex(digest) {
		t.Fatalf("encodeStartModelSnapshot() = %q, %q, %v", document, digest, err)
	}
	if bytes.Contains(document, []byte("replayed")) {
		t.Fatalf("snapshot persisted transport replay flag: %s", document)
	}
	decoded, err := decodeStartModelSnapshot(document)
	if err != nil || decoded.Replayed || decoded.Investigation != result.Investigation {
		t.Fatalf("decodeStartModelSnapshot() = %#v, %v", decoded, err)
	}
}

func TestFinalizeSnapshotPreservesRawProposalAndDetachesSlices(t *testing.T) {
	proposal := []byte(` { "cause": "pool" } `)
	result := investigation.FinalizeInvestigationResult{
		Investigation: snapshotFinalizedInvestigation(),
		Hypotheses: []domain.Hypothesis{{
			ID: "70000000-0000-4000-8000-000000000001", WorkspaceID: snapshotWorkspaceID,
			IncidentID:      "50000000-0000-4000-8000-000000000001",
			InvestigationID: snapshotInvestigationID, Status: domain.HypothesisProposed,
			Rank: 1, Confidence: 0.9, Summary: "Pool saturation", Proposal: proposal,
			ProposalHash: snapshotSHA256Hex(proposal), Unknowns: []string{"trigger"},
			EvidenceIDs: []string{"68000000-0000-4000-8000-000000000001"},
			CreatedAt:   snapshotFinalizedInvestigation().CompletedAt,
		}},
		Replayed: true,
	}
	document, _, err := encodeFinalizeSnapshot(result)
	if err != nil {
		t.Fatalf("encodeFinalizeSnapshot() error = %v", err)
	}
	first, err := decodeFinalizeSnapshot(document)
	if err != nil || first.Replayed || string(first.Hypotheses[0].Proposal) != string(proposal) {
		t.Fatalf("decodeFinalizeSnapshot() = %#v, %v", first, err)
	}
	first.Hypotheses[0].Proposal[1] = 'X'
	first.Hypotheses[0].Unknowns[0] = "mutated"
	second, err := decodeFinalizeSnapshot(document)
	if err != nil || string(second.Hypotheses[0].Proposal) != string(proposal) || second.Hypotheses[0].Unknowns[0] != "trigger" {
		t.Fatalf("snapshot aliases decoded result: %#v, %v", second, err)
	}
}

func TestSnapshotGraphRejectsCrossScopeNonUUIDAndUnstableRanks(t *testing.T) {
	proposal := []byte(`{"cause":"pool"}`)
	item := snapshotFinalizedInvestigation()
	hypothesis := domain.Hypothesis{
		ID: "70000000-0000-4000-8000-000000000001", WorkspaceID: item.WorkspaceID,
		IncidentID: item.IncidentID, InvestigationID: item.ID, Status: domain.HypothesisProposed,
		Rank: 1, Confidence: 0.9, Summary: "Pool saturation", Proposal: proposal,
		ProposalHash: snapshotSHA256Hex(proposal), Unknowns: []string{},
		EvidenceIDs: []string{"68000000-0000-4000-8000-000000000001"}, CreatedAt: item.CompletedAt,
	}
	valid := investigation.FinalizeInvestigationResult{Investigation: item, Hypotheses: []domain.Hypothesis{hypothesis}}

	wrongScope := valid
	wrongScope.Hypotheses = append([]domain.Hypothesis(nil), valid.Hypotheses...)
	wrongScope.Hypotheses[0].WorkspaceID = "20000000-0000-4000-8000-000000000099"
	if _, _, err := encodeFinalizeSnapshot(wrongScope); err == nil {
		t.Fatal("encodeFinalizeSnapshot(cross-scope hypothesis) error = nil")
	}
	wrongStart := snapshotInvestigation()
	wrongStart.ModelStatus = domain.ModelPending
	if _, _, err := encodeStartModelSnapshot(investigation.StartModelResult{Investigation: wrongStart}); err == nil {
		t.Fatal("encodeStartModelSnapshot(RUNNING/PENDING) error = nil")
	}

	base := finalizeSnapshotDTO{
		Investigation: investigationToSnapshot(item),
		Hypotheses:    []hypothesisSnapshotDTO{hypothesisToSnapshot(hypothesis)},
	}
	for name, mutate := range map[string]func(*finalizeSnapshotDTO){
		"cross scope": func(snapshot *finalizeSnapshotDTO) {
			snapshot.Hypotheses[0].IncidentID = "50000000-0000-4000-8000-000000000099"
		},
		"non UUID evidence": func(snapshot *finalizeSnapshotDTO) {
			snapshot.Hypotheses[0].EvidenceIDs = []string{"evidence-readable-but-not-persistent"}
		},
		"duplicate rank": func(snapshot *finalizeSnapshotDTO) {
			duplicate := snapshot.Hypotheses[0]
			duplicate.ID = "70000000-0000-4000-8000-000000000002"
			snapshot.Hypotheses = append(snapshot.Hypotheses, duplicate)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Hypotheses = append([]hypothesisSnapshotDTO(nil), base.Hypotheses...)
			mutate(&candidate)
			document, _, err := encodeSnapshot(candidate)
			if err != nil {
				t.Fatalf("encodeSnapshot(malformed fixture) error = %v", err)
			}
			if _, err := decodeFinalizeSnapshot(document); err == nil {
				t.Fatal("decodeFinalizeSnapshot(malformed graph) error = nil")
			}
		})
	}
}

func TestFinalizeSnapshotFitsMaximumAcceptedHypothesisEnvelope(t *testing.T) {
	item := snapshotFinalizedInvestigation()
	prefix := []byte(`{"data":"`)
	suffix := []byte(`"}`)
	proposal := append(append(append([]byte{}, prefix...), bytes.Repeat([]byte("p"), domain.MaxInvestigationJSONBytes-len(prefix)-len(suffix))...), suffix...)
	unknowns := make([]string, 32)
	for index := range unknowns {
		unknowns[index] = strings.Repeat("u", 512)
	}
	hypotheses := make([]domain.Hypothesis, 20)
	for index := range hypotheses {
		hypotheses[index] = domain.Hypothesis{
			ID:          fmt.Sprintf("70000000-0000-4000-8000-%012x", index+1),
			WorkspaceID: item.WorkspaceID, IncidentID: item.IncidentID, InvestigationID: item.ID,
			Status: domain.HypothesisProposed, Rank: index + 1, Confidence: 0.9,
			Summary: strings.Repeat("s", 4096), Proposal: append([]byte(nil), proposal...),
			ProposalHash: snapshotSHA256Hex(proposal), Unknowns: append([]string{}, unknowns...),
			EvidenceIDs: []string{fmt.Sprintf("68000000-0000-4000-8000-%012x", index+1)},
			CreatedAt:   item.CompletedAt,
		}
	}
	document, _, err := encodeFinalizeSnapshot(investigation.FinalizeInvestigationResult{
		Investigation: item, Hypotheses: hypotheses,
	})
	if err != nil {
		t.Fatalf("encodeFinalizeSnapshot(maximum accepted envelope) error = %v", err)
	}
	if len(document) <= 2*1024*1024 || len(document) > maxSnapshotBytes {
		t.Fatalf("maximum accepted snapshot bytes = %d, want (2 MiB, %d]", len(document), maxSnapshotBytes)
	}
}

func TestSnapshotDecodeRejectsUnknownTrailingAndOversizedDocuments(t *testing.T) {
	for _, document := range [][]byte{
		[]byte(`{"investigation":{},"unknown":true}`),
		[]byte(`{} {}`),
		bytes.Repeat([]byte("x"), maxSnapshotBytes+1),
	} {
		if _, err := decodeStartModelSnapshot(document); err == nil {
			t.Fatalf("decodeStartModelSnapshot(%q) error = nil", document[:min(len(document), 64)])
		}
	}
}

const (
	snapshotWorkspaceID     = "20000000-0000-4000-8000-000000000001"
	snapshotInvestigationID = "60000000-0000-4000-8000-000000000001"
)

func snapshotInvestigation() domain.Investigation {
	createdAt := snapshotTime()
	return domain.Investigation{
		ID: snapshotInvestigationID, WorkspaceID: snapshotWorkspaceID,
		IncidentID: "50000000-0000-4000-8000-000000000001",
		Status:     domain.InvestigationRunning, ModelStatus: domain.ModelRunning,
		IdempotencyKey: "investigate:snapshot", RequestHash: strings.Repeat("a", 64),
		RequestHashVersion: domain.InvestigationCreateRequestVersionV1,
		CreatedAt:          createdAt, StartedAt: createdAt.Add(time.Minute), UpdatedAt: createdAt.Add(time.Minute),
	}
}

func snapshotFinalizedInvestigation() domain.Investigation {
	item := snapshotInvestigation()
	item.Status = domain.InvestigationCompleted
	item.ModelStatus = domain.ModelCompleted
	item.CompletedAt = item.UpdatedAt.Add(time.Minute)
	item.UpdatedAt = item.CompletedAt
	return item
}

func snapshotTime() time.Time {
	return time.Date(2026, 7, 14, 8, 0, 0, 123000, time.UTC)
}
