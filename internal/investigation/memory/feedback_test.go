package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

func TestRecordFeedbackRequiresHumanAndIsTheOnlyRootCauseConfirmationPath(t *testing.T) {
	now := time.Date(2026, 7, 11, 17, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-feedback", now)
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:feedback",
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
		RunnerID: "read-runner-1", IdempotencyKey: "complete:feedback-task", Status: domain.ReadTaskEvidence,
		Evidence: &investigation.EvidenceInput{Payload: payload, ContentHash: sha256Hex(payload), CollectedAt: now},
	})
	if err != nil {
		t.Fatalf("CompleteTask() error = %v", err)
	}
	startModel(t, repository, created.Investigation.ID, "model:start:feedback")
	proposal := []byte(`{"summary":"pool saturation"}`)
	finalized, err := repository.FinalizeInvestigation(context.Background(), investigation.FinalizeInvestigationRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
		IdempotencyKey: "finalize:feedback", Status: domain.InvestigationCompleted, ModelStatus: domain.ModelCompleted,
		Hypotheses: []investigation.HypothesisSpec{{
			Rank: 1, Confidence: 0.84, Summary: "Database pool saturation", Proposal: proposal,
			ProposalHash: sha256Hex(proposal), EvidenceIDs: []string{completion.Evidence.ID},
		}, {
			Rank: 2, Confidence: 0.62, Summary: "Retry amplification", Proposal: proposal,
			ProposalHash: sha256Hex(proposal), EvidenceIDs: []string{completion.Evidence.ID},
		}},
	})
	if err != nil {
		t.Fatalf("FinalizeInvestigation() error = %v", err)
	}
	details := []byte(`{"reason_code":"evidence_matches"}`)
	request := investigation.RecordFeedbackRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, InvestigationID: created.Investigation.ID,
		HypothesisID: finalized.Hypotheses[0].ID, Actor: domain.Actor{Type: domain.ActorHuman, ID: "user-1"},
		Verdict: domain.FeedbackConfirmed, Details: details, IdempotencyKey: "feedback:confirm",
	}
	first, err := repository.RecordFeedback(context.Background(), request)
	if err != nil {
		t.Fatalf("RecordFeedback(first) error = %v", err)
	}
	first.Feedback.Details[2] = 'X'
	replay, err := repository.RecordFeedback(context.Background(), request)
	if err != nil {
		t.Fatalf("RecordFeedback(replay) error = %v", err)
	}
	if !first.Created || replay.Created || string(replay.Feedback.Details) != `{"reason_code":"evidence_matches"}` {
		t.Fatalf("feedback/replay = %#v / %#v", first, replay)
	}
	storedHypothesis, err := repository.GetHypothesis(context.Background(), "workspace-1", finalized.Hypotheses[0].ID)
	if err != nil || storedHypothesis.Status != domain.HypothesisConfirmed {
		t.Fatalf("GetHypothesis() = %#v, %v; want CONFIRMED", storedHypothesis, err)
	}
	storedIncident, err := repository.GetIncident(context.Background(), "workspace-1", incident.ID)
	if err != nil || storedIncident.ConfirmedHypothesisID != finalized.Hypotheses[0].ID {
		t.Fatalf("GetIncident() = %#v, %v; want confirmed hypothesis", storedIncident, err)
	}
	secondRequest := request
	secondRequest.HypothesisID = finalized.Hypotheses[1].ID
	secondRequest.IdempotencyKey = "feedback:confirm-second"
	if _, err := repository.RecordFeedback(context.Background(), secondRequest); !errors.Is(err, investigation.ErrInvalidTransition) {
		t.Fatalf("RecordFeedback(second hypothesis) error = %v, want ErrInvalidTransition", err)
	}
	afterSecond, err := repository.GetIncident(context.Background(), "workspace-1", incident.ID)
	if err != nil || afterSecond.ConfirmedHypothesisID != finalized.Hypotheses[0].ID {
		t.Fatalf("GetIncident(after second) = %#v, %v; want original root cause", afterSecond, err)
	}
	secondHypothesis, err := repository.GetHypothesis(context.Background(), "workspace-1", finalized.Hypotheses[1].ID)
	if err != nil || secondHypothesis.Status != domain.HypothesisProposed {
		t.Fatalf("GetHypothesis(second) = %#v, %v; want unchanged PROPOSED", secondHypothesis, err)
	}

	modelRequest := request
	modelRequest.IdempotencyKey = "feedback:model"
	modelRequest.Actor = domain.Actor{Type: domain.ActorModel, ID: "model-1"}
	if _, err := repository.RecordFeedback(context.Background(), modelRequest); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("RecordFeedback(model) error = %v, want ErrInvalidRequest", err)
	}
}
