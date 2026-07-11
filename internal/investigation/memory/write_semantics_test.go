package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigation/memory"
	"github.com/seaworld008/aiops-system/internal/store"
)

func TestFinalizeReplayIsImmutableFirstResponseSnapshotAfterFeedback(t *testing.T) {
	now := time.Date(2026, 7, 12, 23, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-snapshot", now)
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:snapshot",
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}},
	})
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}
	payload := []byte(`{"series_count":3}`)
	completion, err := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, TaskID: created.Tasks[0].ID,
		RunnerID: "runner-1", IdempotencyKey: "complete:snapshot", Status: domain.ReadTaskEvidence,
		Evidence: &investigation.EvidenceInput{Payload: payload, ContentHash: sha256Hex(payload), CollectedAt: now},
	})
	if err != nil {
		t.Fatalf("CompleteTask() error = %v", err)
	}
	startModel(t, repository, created.Investigation.ID, "model:start:snapshot")
	proposal := []byte(`{"summary":"pool saturation"}`)
	finalizeRequest := investigation.FinalizeInvestigationRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, IdempotencyKey: "finalize:snapshot",
		Status: domain.InvestigationCompleted, ModelStatus: domain.ModelCompleted,
		Hypotheses: []investigation.HypothesisSpec{{
			Rank: 1, Confidence: 0.84, Summary: "Database pool saturation", Proposal: proposal,
			ProposalHash: sha256Hex(proposal), EvidenceIDs: []string{completion.Evidence.ID},
		}},
	}
	firstFinalize, err := repository.FinalizeInvestigation(context.Background(), finalizeRequest)
	if err != nil {
		t.Fatalf("FinalizeInvestigation(first) error = %v", err)
	}
	hypothesisID := firstFinalize.Hypotheses[0].ID
	firstFinalize.Hypotheses[0].Status = domain.HypothesisRejected
	firstFinalize.Hypotheses[0].Proposal[2] = 'X'

	feedbackRequest := investigation.RecordFeedbackRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, InvestigationID: created.Investigation.ID,
		HypothesisID: hypothesisID, Actor: domain.Actor{Type: domain.ActorHuman, ID: "user-1"},
		Verdict: domain.FeedbackConfirmed, Details: []byte(` { "reviewer": "oncall", "reason_code": "evidence_matches" } `),
		IdempotencyKey: "feedback:snapshot",
	}
	firstFeedback, err := repository.RecordFeedback(context.Background(), feedbackRequest)
	if err != nil {
		t.Fatalf("RecordFeedback(first) error = %v", err)
	}
	const canonicalDetails = `{"reason_code":"evidence_matches","reviewer":"oncall"}`
	if !firstFeedback.Created || string(firstFeedback.Feedback.Details) != canonicalDetails {
		t.Fatalf("RecordFeedback(first) = %#v, want canonical Details", firstFeedback)
	}
	firstFeedback.Feedback.Details[2] = 'X'

	semanticReplay := feedbackRequest
	semanticReplay.Details = []byte(`{"reason_code":"evidence_matches","reviewer":"oncall"}`)
	replayedFeedback, err := repository.RecordFeedback(context.Background(), semanticReplay)
	if err != nil {
		t.Fatalf("RecordFeedback(semantic replay) error = %v", err)
	}
	if replayedFeedback.Created || replayedFeedback.Feedback.ID != firstFeedback.Feedback.ID ||
		string(replayedFeedback.Feedback.Details) != canonicalDetails {
		t.Fatalf("RecordFeedback(semantic replay) = %#v", replayedFeedback)
	}
	conflict := feedbackRequest
	conflict.Details = []byte(`{"reason_code":"different","reviewer":"oncall"}`)
	if _, err := repository.RecordFeedback(context.Background(), conflict); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("RecordFeedback(conflict) error = %v, want ErrIdempotencyConflict", err)
	}

	currentHypothesis, err := repository.GetHypothesis(context.Background(), "workspace-1", hypothesisID)
	if err != nil || currentHypothesis.Status != domain.HypothesisConfirmed {
		t.Fatalf("GetHypothesis() = %#v, %v; want current CONFIRMED projection", currentHypothesis, err)
	}
	replayedFinalize, err := repository.FinalizeInvestigation(context.Background(), finalizeRequest)
	if err != nil {
		t.Fatalf("FinalizeInvestigation(replay after feedback) error = %v", err)
	}
	if !replayedFinalize.Replayed || replayedFinalize.Hypotheses[0].Status != domain.HypothesisProposed ||
		string(replayedFinalize.Hypotheses[0].Proposal) != string(proposal) {
		t.Fatalf("FinalizeInvestigation(replay after feedback) = %#v, want immutable PROPOSED snapshot", replayedFinalize)
	}
	replayedFinalize.Hypotheses[0].Status = domain.HypothesisRejected
	replayedFinalize.Hypotheses[0].Proposal[2] = 'Y'
	secondReplay, err := repository.FinalizeInvestigation(context.Background(), finalizeRequest)
	if err != nil || secondReplay.Hypotheses[0].Status != domain.HypothesisProposed ||
		string(secondReplay.Hypotheses[0].Proposal) != string(proposal) {
		t.Fatalf("FinalizeInvestigation(second replay) = %#v, %v; snapshot aliases replay result", secondReplay, err)
	}
}

func TestListEvidenceUsesCollectedCreatedAndIDOrder(t *testing.T) {
	now := time.Date(2026, 7, 12, 23, 30, 0, 0, time.UTC)
	ids := []string{
		"incident-1", "investigation-1", "task-1", "task-2", "task-3",
		"evidence-m", "receipt-1", "evidence-z", "receipt-2", "evidence-a", "receipt-3",
	}
	nextID := 0
	repository, err := memory.New(memory.Options{
		Clock: func() time.Time { return now }, TenantResolver: testTenantResolver, TaskSpecAuthorizer: testTaskSpecAuthorizer,
		IDFactory: func() string {
			id := ids[nextID]
			nextID++
			return id
		},
	})
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	incident := createIncident(t, repository, "workspace-1", "signal-evidence-order", now)
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:evidence-order",
		Tasks: []investigation.TaskSpec{
			{Key: "a", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`)},
			{Key: "b", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`)},
			{Key: "c", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`)},
		},
	})
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}
	collectedAt := []time.Time{now.Add(-time.Minute), now.Add(-3 * time.Minute), now.Add(-3 * time.Minute)}
	for index, task := range created.Tasks {
		payload := []byte(`{"task":"` + task.Key + `"}`)
		if _, err := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
			WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, TaskID: task.ID,
			RunnerID: "runner-1", IdempotencyKey: "complete:evidence-order:" + task.Key, Status: domain.ReadTaskEvidence,
			Evidence: &investigation.EvidenceInput{Payload: payload, ContentHash: sha256Hex(payload), CollectedAt: collectedAt[index]},
		}); err != nil {
			t.Fatalf("CompleteTask(%s) error = %v", task.Key, err)
		}
	}

	first, err := repository.ListEvidence(context.Background(), investigation.ListEvidenceRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
	})
	if err != nil {
		t.Fatalf("ListEvidence(first) error = %v", err)
	}
	second, err := repository.ListEvidence(context.Background(), investigation.ListEvidenceRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
	})
	if err != nil {
		t.Fatalf("ListEvidence(second) error = %v", err)
	}
	wantIDs := []string{"evidence-a", "evidence-z", "evidence-m"}
	if len(first) != len(wantIDs) || len(second) != len(wantIDs) {
		t.Fatalf("ListEvidence() lengths = %d/%d, want %d", len(first), len(second), len(wantIDs))
	}
	for index, wantID := range wantIDs {
		if first[index].ID != wantID || second[index].ID != wantID {
			t.Fatalf("ListEvidence()[%d] IDs = %q/%q, want %q", index, first[index].ID, second[index].ID, wantID)
		}
	}
}
