package investigation_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

func TestNormalizeCompleteTaskRequestPreservesRawEvidenceAndDetachesInput(t *testing.T) {
	payload := []byte(` { "value": 1 } `)
	expectedPayload := string(payload)
	request := investigation.CompleteTaskRequest{
		WorkspaceID: "workspace-1", InvestigationID: "investigation-1", TaskID: "task-1",
		RunnerID: "runner-1", IdempotencyKey: "complete-1", Status: domain.ReadTaskEvidence,
		Evidence: &investigation.EvidenceInput{
			Payload: payload, ContentHash: testSHA256Hex(payload), Attributes: map[string]string{"source": "runner"},
			CollectedAt: time.Date(2026, 7, 12, 8, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60)),
		},
	}
	normalized, requestHash, err := investigation.NormalizeCompleteTaskRequest(request)
	if err != nil {
		t.Fatalf("NormalizeCompleteTaskRequest() error = %v", err)
	}
	if string(normalized.Evidence.Payload) != expectedPayload {
		t.Fatalf("normalized payload = %q, want raw %q", normalized.Evidence.Payload, payload)
	}
	if normalized.Evidence.CollectedAt.Location() != time.UTC {
		t.Fatalf("normalized CollectedAt location = %v, want UTC", normalized.Evidence.CollectedAt.Location())
	}
	const goldenRequestHash = "28083700df7cbfc7f520685c1881231b9fa3259865b43bb9cb53c16b88a7c1d1"
	if requestHash != goldenRequestHash {
		t.Fatalf("request hash = %q, want versioned golden %q", requestHash, goldenRequestHash)
	}

	request.Evidence.Payload[2] = 'X'
	request.Evidence.Attributes["source"] = "mutated"
	if string(normalized.Evidence.Payload) != expectedPayload || normalized.Evidence.Attributes["source"] != "runner" {
		t.Fatalf("normalized evidence aliases caller input: payload=%q attributes=%v", normalized.Evidence.Payload, normalized.Evidence.Attributes)
	}

	equivalent := normalized
	equivalent.WorkspaceID = "different-workspace-scope"
	equivalent.IdempotencyKey = "different-idempotency-key"
	equivalent.Evidence = &investigation.EvidenceInput{
		Payload: append([]byte(nil), normalized.Evidence.Payload...), ContentHash: normalized.Evidence.ContentHash,
		Attributes: map[string]string{"source": "runner"}, CollectedAt: normalized.Evidence.CollectedAt.In(time.FixedZone("UTC-4", -4*60*60)),
	}
	_, equivalentHash, err := investigation.NormalizeCompleteTaskRequest(equivalent)
	if err != nil {
		t.Fatalf("NormalizeCompleteTaskRequest(equivalent) error = %v", err)
	}
	if equivalentHash != requestHash {
		t.Fatalf("equivalent request hash = %q, want %q", equivalentHash, requestHash)
	}

	semanticallyEqualJSON := []byte(`{"value":1}`)
	equivalent.Evidence.Payload = semanticallyEqualJSON
	equivalent.Evidence.ContentHash = testSHA256Hex(semanticallyEqualJSON)
	_, differentRawHash, err := investigation.NormalizeCompleteTaskRequest(equivalent)
	if err != nil {
		t.Fatalf("NormalizeCompleteTaskRequest(different raw JSON) error = %v", err)
	}
	if differentRawHash == requestHash {
		t.Fatal("raw evidence byte/hash change produced the same semantic request hash")
	}
}

func TestNormalizeCompleteTaskRequestValidatesTerminalBodyWithoutEcho(t *testing.T) {
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	validPayload := []byte(`{"value":1}`)
	validEvidence := &investigation.EvidenceInput{
		Payload: validPayload, ContentHash: testSHA256Hex(validPayload), Attributes: map[string]string{"source": "runner"}, CollectedAt: now,
	}
	for name, mutate := range map[string]func(*investigation.CompleteTaskRequest){
		"unsupported status":    func(request *investigation.CompleteTaskRequest) { request.Status = domain.ReadTaskRunning },
		"evidence plus failure": func(request *investigation.CompleteTaskRequest) { request.FailureCode = "runner_failed" },
		"failure without code": func(request *investigation.CompleteTaskRequest) {
			request.Status, request.Evidence = domain.ReadTaskFailed, nil
		},
		"mismatched hash": func(request *investigation.CompleteTaskRequest) {
			request.Evidence.ContentHash = strings.Repeat("0", 64)
		},
		"zero collected at": func(request *investigation.CompleteTaskRequest) { request.Evidence.CollectedAt = time.Time{} },
		"unsafe attributes": func(request *investigation.CompleteTaskRequest) {
			request.Evidence.Attributes = map[string]string{"authorization": "complete-semantics-canary"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := investigation.CompleteTaskRequest{Status: domain.ReadTaskEvidence, Evidence: &investigation.EvidenceInput{
				Payload: append([]byte(nil), validEvidence.Payload...), ContentHash: validEvidence.ContentHash,
				Attributes: map[string]string{"source": "runner"}, CollectedAt: validEvidence.CollectedAt,
			}}
			mutate(&request)
			if _, _, err := investigation.NormalizeCompleteTaskRequest(request); !errors.Is(err, investigation.ErrInvalidRequest) {
				t.Fatalf("NormalizeCompleteTaskRequest() error = %v, want ErrInvalidRequest", err)
			} else if strings.Contains(err.Error(), "complete-semantics-canary") {
				t.Fatalf("NormalizeCompleteTaskRequest() echoed request body: %v", err)
			}
		})
	}
}

func TestNormalizeFinalizeInvestigationRequestSortsValidatesAndDetachesHypotheses(t *testing.T) {
	proposalOne := []byte(` { "cause": "queue" } `)
	expectedProposalOne := string(proposalOne)
	proposalTwo := []byte(`{"cause":"database"}`)
	request := investigation.FinalizeInvestigationRequest{
		WorkspaceID: "workspace-1", InvestigationID: "investigation-1", IdempotencyKey: "finalize-1",
		Status: domain.InvestigationCompleted, ModelStatus: domain.ModelCompleted,
		Hypotheses: []investigation.HypothesisSpec{
			{Rank: 2, Confidence: 0.7, Summary: "Database contention", Proposal: proposalTwo, ProposalHash: testSHA256Hex(proposalTwo), Unknowns: []string{"lock owner"}, EvidenceIDs: []string{"evidence-2"}},
			{Rank: 1, Confidence: 0.9, Summary: "Queue saturation", Proposal: proposalOne, ProposalHash: testSHA256Hex(proposalOne), Unknowns: []string{"trigger"}, EvidenceIDs: []string{"evidence-1"}},
		},
	}
	normalized, requestHash, err := investigation.NormalizeFinalizeInvestigationRequest(request)
	if err != nil {
		t.Fatalf("NormalizeFinalizeInvestigationRequest() error = %v", err)
	}
	if len(normalized.Hypotheses) != 2 || normalized.Hypotheses[0].Rank != 1 || normalized.Hypotheses[1].Rank != 2 {
		t.Fatalf("normalized ranks = %#v, want 1,2", normalized.Hypotheses)
	}
	const goldenRequestHash = "13e5d6ffc406ada47b2ac1c4b6c9dfb7356f25186ff08a0142d2c8021afa2082"
	if string(normalized.Hypotheses[0].Proposal) != expectedProposalOne || requestHash != goldenRequestHash {
		t.Fatalf("normalized proposal/hash = %q/%q", normalized.Hypotheses[0].Proposal, requestHash)
	}

	request.Hypotheses[1].Proposal[2] = 'X'
	request.Hypotheses[1].Unknowns[0] = "mutated"
	request.Hypotheses[1].EvidenceIDs[0] = "evidence-mutated"
	if string(normalized.Hypotheses[0].Proposal) != expectedProposalOne || normalized.Hypotheses[0].Unknowns[0] != "trigger" || normalized.Hypotheses[0].EvidenceIDs[0] != "evidence-1" {
		t.Fatalf("normalized hypotheses alias caller input: %#v", normalized.Hypotheses[0])
	}

	reversed := normalized
	reversed.WorkspaceID = "different-workspace-scope"
	reversed.IdempotencyKey = "different-idempotency-key"
	reversed.Hypotheses = []investigation.HypothesisSpec{normalized.Hypotheses[1], normalized.Hypotheses[0]}
	_, reversedHash, err := investigation.NormalizeFinalizeInvestigationRequest(reversed)
	if err != nil {
		t.Fatalf("NormalizeFinalizeInvestigationRequest(reversed) error = %v", err)
	}
	if reversedHash != requestHash {
		t.Fatalf("reordered request hash = %q, want %q", reversedHash, requestHash)
	}
	differentRaw := normalized
	differentRaw.Hypotheses = append([]investigation.HypothesisSpec(nil), normalized.Hypotheses...)
	differentRawProposal := []byte(`{"cause":"queue"}`)
	differentRaw.Hypotheses[0].Proposal = differentRawProposal
	differentRaw.Hypotheses[0].ProposalHash = testSHA256Hex(differentRawProposal)
	_, differentRawHash, err := investigation.NormalizeFinalizeInvestigationRequest(differentRaw)
	if err != nil {
		t.Fatalf("NormalizeFinalizeInvestigationRequest(different raw proposal) error = %v", err)
	}
	if differentRawHash == requestHash {
		t.Fatal("raw proposal byte/hash change produced the same semantic request hash")
	}

	duplicateRank := normalized
	duplicateRank.Hypotheses = append(duplicateRank.Hypotheses, normalized.Hypotheses[0])
	if _, _, err := investigation.NormalizeFinalizeInvestigationRequest(duplicateRank); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("duplicate rank error = %v, want ErrInvalidRequest", err)
	}
	unsafeProposal := normalized
	unsafeProposal.Hypotheses = append([]investigation.HypothesisSpec(nil), normalized.Hypotheses...)
	canaryProposal := []byte(`{"authorization":"finalize-semantics-canary"}`)
	unsafeProposal.Hypotheses[0].Proposal = canaryProposal
	unsafeProposal.Hypotheses[0].ProposalHash = testSHA256Hex(canaryProposal)
	if _, _, err := investigation.NormalizeFinalizeInvestigationRequest(unsafeProposal); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("unsafe proposal error = %v, want ErrInvalidRequest", err)
	} else if strings.Contains(err.Error(), "finalize-semantics-canary") {
		t.Fatalf("NormalizeFinalizeInvestigationRequest() echoed proposal: %v", err)
	}
}

func TestNormalizeRecordFeedbackRequestUsesJCSAndDetachesDetails(t *testing.T) {
	first := investigation.RecordFeedbackRequest{
		IncidentID: "incident-1", InvestigationID: "investigation-1", HypothesisID: "hypothesis-1",
		Actor: domain.Actor{Type: domain.ActorHuman, ID: "user-1"}, Verdict: domain.FeedbackConfirmed,
		Details: []byte(` { "b": 2, "a": 1 } `),
	}
	second := first
	second.WorkspaceID = "different-workspace-scope"
	second.IdempotencyKey = "different-idempotency-key"
	second.Details = []byte(`{"a":1,"b":2}`)
	normalizedFirst, firstHash, err := investigation.NormalizeRecordFeedbackRequest(first)
	if err != nil {
		t.Fatalf("NormalizeRecordFeedbackRequest(first) error = %v", err)
	}
	normalizedSecond, secondHash, err := investigation.NormalizeRecordFeedbackRequest(second)
	if err != nil {
		t.Fatalf("NormalizeRecordFeedbackRequest(second) error = %v", err)
	}
	const goldenRequestHash = "7d6008116bd81a97c2354ddcc5cec12d9df20df5de8a5f1a865d1110e8b2e3cb"
	if string(normalizedFirst.Details) != `{"a":1,"b":2}` || string(normalizedSecond.Details) != string(normalizedFirst.Details) ||
		firstHash != secondHash || firstHash != goldenRequestHash {
		t.Fatalf("canonical details/hash = %q/%q %q/%q", normalizedFirst.Details, firstHash, normalizedSecond.Details, secondHash)
	}
	first.Details[3] = 'X'
	if string(normalizedFirst.Details) != `{"a":1,"b":2}` {
		t.Fatalf("normalized details alias caller input: %q", normalizedFirst.Details)
	}

	unsafe := first
	unsafe.Details = []byte(`{"authorization":"feedback-semantics-canary"}`)
	if _, _, err := investigation.NormalizeRecordFeedbackRequest(unsafe); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("unsafe details error = %v, want ErrInvalidRequest", err)
	} else if strings.Contains(err.Error(), "feedback-semantics-canary") {
		t.Fatalf("NormalizeRecordFeedbackRequest() echoed details: %v", err)
	}
	modelFeedback := second
	modelFeedback.Actor.Type = domain.ActorModel
	if _, _, err := investigation.NormalizeRecordFeedbackRequest(modelFeedback); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("model actor error = %v, want ErrInvalidRequest", err)
	}
}

func TestStartAndFailInvestigationRequestHashesAreCentralizedAndSemantic(t *testing.T) {
	start := investigation.StartModelRequest{InvestigationID: "investigation-1"}
	startHash, err := investigation.StartModelRequestHash(start)
	otherStartHash, otherErr := investigation.StartModelRequestHash(investigation.StartModelRequest{InvestigationID: "investigation-2"})
	const goldenStartHash = "a6f0f410099e023333a8857e572648ad31eb41a2cc3b3de37145705498bf4336"
	if err != nil || otherErr != nil || startHash != goldenStartHash || startHash == otherStartHash {
		t.Fatalf("StartModelRequestHash() = %q", startHash)
	}

	failure := investigation.FailInvestigationRequest{InvestigationID: "investigation-1", FailureCode: "runner_failed"}
	failureHash, err := investigation.FailInvestigationRequestHash(failure)
	const goldenFailureHash = "dceffc784e94f2f43d930e3752168339a6562d5c8b58686b30a29b91b23211fc"
	if err != nil || failureHash != goldenFailureHash || failureHash == startHash {
		t.Fatalf("FailInvestigationRequestHash() = %q, %v", failureHash, err)
	}
	if _, err := investigation.FailInvestigationRequestHash(investigation.FailInvestigationRequest{InvestigationID: "investigation-1"}); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("FailInvestigationRequestHash(invalid) error = %v, want ErrInvalidRequest", err)
	}
}

func testSHA256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return fmt.Sprintf("%x", digest[:])
}
