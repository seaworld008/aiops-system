package memory_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigation/memory"
	"github.com/seaworld008/aiops-system/internal/store"
)

func TestCorrelateFiringSignalCreatesOneIncidentAndReplayDoesNotRecount(t *testing.T) {
	now := time.Date(2026, 7, 11, 13, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	signal := testSignal("workspace-1", "signal-1", "firing", now)
	if created, err := repository.RegisterSignal(context.Background(), signal); err != nil || !created {
		t.Fatalf("RegisterSignal() = %v, %v; want true, nil", created, err)
	}
	request := investigation.CorrelateSignalRequest{
		WorkspaceID: "workspace-1", SignalID: "signal-1", CorrelationKey: "payments:prod:latency",
		ServiceID: "payments", EnvironmentID: "prod", MappingStatus: domain.MappingExact,
	}

	first, err := repository.CorrelateSignal(context.Background(), request)
	if err != nil {
		t.Fatalf("CorrelateSignal(first) error = %v", err)
	}
	second, err := repository.CorrelateSignal(context.Background(), request)
	if err != nil {
		t.Fatalf("CorrelateSignal(replay) error = %v", err)
	}
	if !first.Created || !first.Associated || !first.Counted {
		t.Fatalf("first result = %#v, want created/associated/counted", first)
	}
	if second.Created || !second.Associated || second.Counted || second.Incident.ID != first.Incident.ID {
		t.Fatalf("replay result = %#v, want same uncounted incident", second)
	}
	if second.Incident.SignalCount != 1 || second.Incident.LastSignalAt != now {
		t.Fatalf("incident signal metadata = %d/%s, want 1/%s", second.Incident.SignalCount, second.Incident.LastSignalAt, now)
	}
}

func TestResolvedSignalOnlyAssociatesAnExistingActiveIncidentOnce(t *testing.T) {
	now := time.Date(2026, 7, 11, 13, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	request := investigation.CorrelateSignalRequest{
		WorkspaceID: "workspace-1", CorrelationKey: "payments:prod:latency",
		ServiceID: "payments", EnvironmentID: "prod", MappingStatus: domain.MappingExact,
	}

	resolvedWithoutIncident := testSignal("workspace-1", "resolved-orphan", "resolved", now)
	if _, err := repository.RegisterSignal(context.Background(), resolvedWithoutIncident); err != nil {
		t.Fatalf("RegisterSignal(orphan) error = %v", err)
	}
	request.SignalID = resolvedWithoutIncident.ID
	orphan, err := repository.CorrelateSignal(context.Background(), request)
	if err != nil {
		t.Fatalf("CorrelateSignal(orphan resolved) error = %v", err)
	}
	if orphan.Associated || orphan.Created || orphan.Counted || orphan.Incident.ID != "" {
		t.Fatalf("orphan resolved result = %#v, want no incident", orphan)
	}

	firing := testSignal("workspace-1", "firing-1", "firing", now)
	resolved := testSignal("workspace-1", "resolved-1", "resolved", now.Add(time.Minute))
	for _, item := range []domain.Signal{firing, resolved} {
		if _, err := repository.RegisterSignal(context.Background(), item); err != nil {
			t.Fatalf("RegisterSignal(%s) error = %v", item.ID, err)
		}
	}
	request.SignalID = firing.ID
	if _, err := repository.CorrelateSignal(context.Background(), request); err != nil {
		t.Fatalf("CorrelateSignal(firing) error = %v", err)
	}
	request.SignalID = resolved.ID
	first, err := repository.CorrelateSignal(context.Background(), request)
	if err != nil {
		t.Fatalf("CorrelateSignal(resolved) error = %v", err)
	}
	replay, err := repository.CorrelateSignal(context.Background(), request)
	if err != nil {
		t.Fatalf("CorrelateSignal(resolved replay) error = %v", err)
	}
	if !first.Associated || !first.Counted || first.Created || first.Incident.SignalCount != 2 {
		t.Fatalf("first resolved result = %#v, want one counted association", first)
	}
	if !replay.Associated || replay.Counted || replay.Incident.SignalCount != 2 {
		t.Fatalf("resolved replay result = %#v, want no recount", replay)
	}
}

func TestIncidentCorrelationAndReadsAreWorkspaceIsolated(t *testing.T) {
	now := time.Date(2026, 7, 11, 13, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	var incidentIDs []string
	for _, workspaceID := range []string{"workspace-1", "workspace-2"} {
		signal := testSignal(workspaceID, "shared-signal-id", "firing", now)
		if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
			t.Fatalf("RegisterSignal(%s) error = %v", workspaceID, err)
		}
		result, err := repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
			WorkspaceID: workspaceID, SignalID: signal.ID, CorrelationKey: "payments:prod:latency",
			MappingStatus: domain.MappingUnresolved,
		})
		if err != nil {
			t.Fatalf("CorrelateSignal(%s) error = %v", workspaceID, err)
		}
		incidentIDs = append(incidentIDs, result.Incident.ID)
		items, err := repository.ListIncidents(context.Background(), investigation.ListIncidentsRequest{WorkspaceID: workspaceID})
		if err != nil || len(items) != 1 || items[0].WorkspaceID != workspaceID {
			t.Fatalf("ListIncidents(%s) = %#v, %v; want one scoped item", workspaceID, items, err)
		}
	}
	if incidentIDs[0] == incidentIDs[1] {
		t.Fatalf("incident IDs = %v, want independent incidents", incidentIDs)
	}
	if _, err := repository.GetIncident(context.Background(), "workspace-2", incidentIDs[0]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetIncident(cross-workspace) error = %v, want ErrNotFound", err)
	}
}

func TestCreateOrGetInvestigationIsIdempotentAndSortsTasksStably(t *testing.T) {
	now := time.Date(2026, 7, 11, 14, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-1", now)
	tasks := []investigation.TaskSpec{
		{Key: "logs", ConnectorID: "victorialogs-prod", Operation: "search", Input: []byte(`{"lookback_minutes":30}`)},
		{Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`)},
	}
	request := investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:signal-1", Tasks: tasks,
	}

	first, err := repository.CreateOrGetInvestigation(context.Background(), request)
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation(first) error = %v", err)
	}
	request.Tasks[0], request.Tasks[1] = request.Tasks[1], request.Tasks[0]
	replay, err := repository.CreateOrGetInvestigation(context.Background(), request)
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation(replay) error = %v", err)
	}
	if !first.Created || replay.Created || replay.Investigation.ID != first.Investigation.ID {
		t.Fatalf("create/replay = %#v / %#v, want one investigation", first, replay)
	}
	if len(first.Tasks) != 2 || first.Tasks[0].Key != "logs" || first.Tasks[0].Position != 1 ||
		first.Tasks[1].Key != "metrics" || first.Tasks[1].Position != 2 {
		t.Fatalf("tasks = %#v, want stable key order and positions", first.Tasks)
	}

	conflict := request
	conflict.Tasks = append([]investigation.TaskSpec(nil), request.Tasks...)
	conflict.Tasks[0].Operation = "instant_query"
	if _, err := repository.CreateOrGetInvestigation(context.Background(), conflict); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("CreateOrGetInvestigation(conflict) error = %v, want ErrIdempotencyConflict", err)
	}
}

func TestCreateOrGetInvestigationSerializesAtLeastThirtyTwoConcurrentReplays(t *testing.T) {
	now := time.Date(2026, 7, 11, 14, 30, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-concurrent", now)
	request := investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:concurrent",
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query",
			Input: []byte(`{"lookback_minutes":15}`),
		}},
	}

	const goroutines = 64
	start := make(chan struct{})
	results := make(chan investigation.CreateOrGetInvestigationResult, goroutines)
	errorsCh := make(chan error, goroutines)
	var group sync.WaitGroup
	for index := 0; index < goroutines; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			result, err := repository.CreateOrGetInvestigation(context.Background(), request)
			results <- result
			errorsCh <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)
	close(errorsCh)

	for err := range errorsCh {
		if err != nil {
			t.Fatalf("CreateOrGetInvestigation() error = %v", err)
		}
	}
	created := 0
	var investigationID string
	for result := range results {
		if result.Created {
			created++
		}
		if investigationID == "" {
			investigationID = result.Investigation.ID
		} else if result.Investigation.ID != investigationID {
			t.Fatalf("investigation ID = %q, want %q", result.Investigation.ID, investigationID)
		}
	}
	if created != 1 {
		t.Fatalf("created results = %d, want 1", created)
	}
	items, err := repository.ListInvestigations(context.Background(), investigation.ListInvestigationsRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID,
	})
	if err != nil || len(items) != 1 {
		t.Fatalf("ListInvestigations() = %#v, %v; want one item", items, err)
	}
}

func TestCompleteTaskPersistsEvidenceReceiptAndDefensiveCopies(t *testing.T) {
	now := time.Date(2026, 7, 11, 15, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-complete", now)
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:complete",
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}},
	})
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}
	payload := []byte(`{"series_count":3}`)
	attributes := map[string]string{"trust": "untrusted", "redaction": "applied"}
	request := investigation.CompleteTaskRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, TaskID: created.Tasks[0].ID,
		RunnerID: "read-runner-1", IdempotencyKey: "complete:task-1", Status: domain.ReadTaskEvidence,
		Evidence: &investigation.EvidenceInput{
			Payload: payload, ContentHash: sha256Hex(payload), Attributes: attributes, CollectedAt: now,
		},
	}
	first, err := repository.CompleteTask(context.Background(), request)
	if err != nil {
		t.Fatalf("CompleteTask(first) error = %v", err)
	}
	replay, err := repository.CompleteTask(context.Background(), request)
	if err != nil {
		t.Fatalf("CompleteTask(replay) error = %v", err)
	}
	if first.Task.Status != domain.ReadTaskEvidence || first.Evidence == nil || first.Receipt.EvidenceID != first.Evidence.ID ||
		!replay.Replayed || replay.Evidence == nil || replay.Evidence.ID != first.Evidence.ID {
		t.Fatalf("complete/replay = %#v / %#v", first, replay)
	}
	storedInvestigation, err := repository.GetInvestigation(context.Background(), "workspace-1", created.Investigation.ID)
	if err != nil || storedInvestigation.Status != domain.InvestigationRunning {
		t.Fatalf("GetInvestigation() = %#v, %v; want RUNNING", storedInvestigation, err)
	}

	payload[2] = 'X'
	attributes["trust"] = "tampered"
	first.Evidence.Payload[2] = 'Y'
	first.Evidence.Attributes["redaction"] = "tampered"
	stored, err := repository.GetEvidence(context.Background(), "workspace-1", first.Evidence.ID)
	if err != nil {
		t.Fatalf("GetEvidence() error = %v", err)
	}
	if string(stored.Payload) != `{"series_count":3}` || stored.Attributes["trust"] != "untrusted" || stored.Attributes["redaction"] != "applied" {
		t.Fatalf("stored evidence mutated through aliases: %#v", stored)
	}

	conflict := request
	conflict.Status = domain.ReadTaskFailed
	conflict.Evidence = nil
	conflict.FailureCode = "collector_timeout"
	if _, err := repository.CompleteTask(context.Background(), conflict); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("CompleteTask(conflict) error = %v, want ErrIdempotencyConflict", err)
	}
}

func TestFinalizeInvestigationPersistsRankedHypothesesAndReleasesActiveSlot(t *testing.T) {
	now := time.Date(2026, 7, 11, 16, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-finalize", now)
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:finalize",
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
		RunnerID: "read-runner-1", IdempotencyKey: "complete:finalize-task", Status: domain.ReadTaskEvidence,
		Evidence: &investigation.EvidenceInput{Payload: payload, ContentHash: sha256Hex(payload), CollectedAt: now},
	})
	if err != nil {
		t.Fatalf("CompleteTask() error = %v", err)
	}
	startModel(t, repository, created.Investigation.ID, "model:start:finalize")
	proposal := []byte(`{"summary":"pool saturation"}`)
	request := investigation.FinalizeInvestigationRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
		IdempotencyKey: "finalize:investigation-1", Status: domain.InvestigationCompleted, ModelStatus: domain.ModelCompleted,
		Hypotheses: []investigation.HypothesisSpec{{
			Rank: 1, Confidence: 0.84, Summary: "Database pool saturation", Proposal: proposal,
			ProposalHash: sha256Hex(proposal), Unknowns: []string{"Retry amplification"},
			EvidenceIDs: []string{completion.Evidence.ID},
		}},
	}
	first, err := repository.FinalizeInvestigation(context.Background(), request)
	if err != nil {
		t.Fatalf("FinalizeInvestigation(first) error = %v", err)
	}
	replay, err := repository.FinalizeInvestigation(context.Background(), request)
	if err != nil {
		t.Fatalf("FinalizeInvestigation(replay) error = %v", err)
	}
	if first.Investigation.Status != domain.InvestigationCompleted || len(first.Hypotheses) != 1 ||
		first.Hypotheses[0].Rank != 1 || !replay.Replayed || replay.Hypotheses[0].ID != first.Hypotheses[0].ID {
		t.Fatalf("finalize/replay = %#v / %#v", first, replay)
	}

	proposal[2] = 'X'
	request.Hypotheses[0].Unknowns[0] = "tampered"
	first.Hypotheses[0].Proposal[2] = 'Y'
	first.Hypotheses[0].EvidenceIDs[0] = "tampered"
	stored, err := repository.GetHypothesis(context.Background(), "workspace-1", first.Hypotheses[0].ID)
	if err != nil {
		t.Fatalf("GetHypothesis() error = %v", err)
	}
	if string(stored.Proposal) != `{"summary":"pool saturation"}` || stored.Unknowns[0] != "Retry amplification" ||
		stored.EvidenceIDs[0] != completion.Evidence.ID {
		t.Fatalf("stored hypothesis mutated through aliases: %#v", stored)
	}

	second, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:after-terminal",
		Tasks: []investigation.TaskSpec{{
			Key: "logs", ConnectorID: "victorialogs-prod", Operation: "search", Input: []byte(`{"lookback_minutes":30}`),
		}},
	})
	if err != nil || !second.Created || second.Investigation.ID == created.Investigation.ID {
		t.Fatalf("CreateOrGetInvestigation(after terminal) = %#v, %v; want a new investigation", second, err)
	}
}

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

	modelRequest := request
	modelRequest.IdempotencyKey = "feedback:model"
	modelRequest.Actor = domain.Actor{Type: domain.ActorModel, ID: "model-1"}
	if _, err := repository.RecordFeedback(context.Background(), modelRequest); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("RecordFeedback(model) error = %v, want ErrInvalidRequest", err)
	}
}

func TestFinalizeUsesTaskResultsEvenWhenModelFails(t *testing.T) {
	now := time.Date(2026, 7, 11, 18, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-model-failure", now)
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:model-failure",
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}},
	})
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}
	payload := []byte(`{"series_count":3}`)
	if _, err := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, TaskID: created.Tasks[0].ID,
		RunnerID: "read-runner-1", IdempotencyKey: "complete:model-failure", Status: domain.ReadTaskEvidence,
		Evidence: &investigation.EvidenceInput{Payload: payload, ContentHash: sha256Hex(payload), CollectedAt: now},
	}); err != nil {
		t.Fatalf("CompleteTask() error = %v", err)
	}
	startModel(t, repository, created.Investigation.ID, "model:start:failure")

	result, err := repository.FinalizeInvestigation(context.Background(), investigation.FinalizeInvestigationRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
		IdempotencyKey: "finalize:model-failure", Status: domain.InvestigationCompleted,
		ModelStatus: domain.ModelFailed, ModelFailureCode: "model_unavailable",
	})
	if err != nil {
		t.Fatalf("FinalizeInvestigation() error = %v", err)
	}
	if result.Investigation.Status != domain.InvestigationCompleted || result.Investigation.ModelStatus != domain.ModelFailed ||
		result.Investigation.ModelFailureCode != "model_unavailable" || len(result.Hypotheses) != 0 {
		t.Fatalf("finalized investigation = %#v, want evidence-only COMPLETED report", result)
	}
}

func TestConcurrentSignalStormMergesIntoOneIncidentWithExactTimeBounds(t *testing.T) {
	now := time.Date(2026, 7, 11, 19, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	const goroutines = 64
	for index := 0; index < goroutines; index++ {
		signal := testSignal("workspace-1", fmt.Sprintf("storm-%02d", index), "firing", now.Add(time.Duration(index)*time.Minute))
		if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
			t.Fatalf("RegisterSignal(%d) error = %v", index, err)
		}
	}
	start := make(chan struct{})
	results := make(chan investigation.CorrelateSignalResult, goroutines)
	errorsCh := make(chan error, goroutines)
	var group sync.WaitGroup
	for index := 0; index < goroutines; index++ {
		index := index
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			result, err := repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
				WorkspaceID: "workspace-1", SignalID: fmt.Sprintf("storm-%02d", index),
				CorrelationKey: "payments:prod:storm", MappingStatus: domain.MappingUnresolved,
			})
			results <- result
			errorsCh <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatalf("CorrelateSignal() error = %v", err)
		}
	}
	created := 0
	var incidentID string
	for result := range results {
		if result.Created {
			created++
		}
		if incidentID == "" {
			incidentID = result.Incident.ID
		} else if result.Incident.ID != incidentID {
			t.Fatalf("incident ID = %q, want %q", result.Incident.ID, incidentID)
		}
	}
	stored, err := repository.GetIncident(context.Background(), "workspace-1", incidentID)
	if err != nil {
		t.Fatalf("GetIncident() error = %v", err)
	}
	if created != 1 || stored.SignalCount != goroutines || stored.OpenedAt != now ||
		stored.LastSignalAt != now.Add((goroutines-1)*time.Minute) {
		t.Fatalf("storm result created=%d incident=%#v", created, stored)
	}
}

func TestRegisterSignalCopiesCallerLabels(t *testing.T) {
	now := time.Date(2026, 7, 11, 20, 30, 0, 0, time.UTC)
	repository := newRepository(t, now)
	signal := testSignal("workspace-1", "signal-labels", "firing", now)
	if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
		t.Fatalf("RegisterSignal(first) error = %v", err)
	}
	signal.Labels["service"] = "tampered"
	replay := testSignal("workspace-1", "signal-labels", "firing", now)
	created, err := repository.RegisterSignal(context.Background(), replay)
	if err != nil || created {
		t.Fatalf("RegisterSignal(replay) = %v, %v; want false, nil after caller mutation", created, err)
	}
}

func TestRepositoryRejectsInvalidOrDuplicateFactoryIDsWithoutPartialInvestigation(t *testing.T) {
	now := time.Date(2026, 7, 11, 21, 0, 0, 0, time.UTC)
	invalidFactory, err := memory.New(memory.Options{
		Clock: func() time.Time { return now }, IDFactory: func() string { return "invalid id" },
	})
	if err != nil {
		t.Fatalf("memory.New(invalid ID factory) error = %v", err)
	}
	signal := testSignal("workspace-1", "signal-invalid-id", "firing", now)
	if _, err := invalidFactory.RegisterSignal(context.Background(), signal); err != nil {
		t.Fatalf("RegisterSignal() error = %v", err)
	}
	if _, err := invalidFactory.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
		WorkspaceID: "workspace-1", SignalID: signal.ID, CorrelationKey: "payments:prod:invalid-id",
		MappingStatus: domain.MappingUnresolved,
	}); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("CorrelateSignal(invalid generated ID) error = %v, want ErrInvalidRequest", err)
	}

	ids := []string{"incident-generated", "investigation-generated", "duplicate-task", "duplicate-task"}
	index := 0
	duplicateFactory, err := memory.New(memory.Options{
		Clock: func() time.Time { return now },
		IDFactory: func() string {
			value := ids[index]
			index++
			return value
		},
	})
	if err != nil {
		t.Fatalf("memory.New(duplicate ID factory) error = %v", err)
	}
	incident := createIncident(t, duplicateFactory, "workspace-1", "signal-duplicate-id", now)
	_, err = duplicateFactory.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:duplicate-id",
		Tasks: []investigation.TaskSpec{
			{Key: "logs", ConnectorID: "victorialogs-prod", Operation: "search", Input: []byte(`{"lookback_minutes":30}`)},
			{Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`)},
		},
	})
	if !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("CreateOrGetInvestigation(duplicate generated IDs) error = %v, want ErrInvalidRequest", err)
	}
	items, listErr := duplicateFactory.ListInvestigations(context.Background(), investigation.ListInvestigationsRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID,
	})
	if listErr != nil || len(items) != 0 {
		t.Fatalf("ListInvestigations() = %#v, %v; want no partial investigation", items, listErr)
	}
}

func TestRepositoryRejectsNULScopeKeyCollisionInputs(t *testing.T) {
	now := time.Date(2026, 7, 12, 9, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)

	for _, signal := range []domain.Signal{
		testSignal("a\x00b", "c", "firing", now),
		testSignal("a", "b\x00c", "firing", now),
	} {
		if _, err := repository.RegisterSignal(context.Background(), signal); !errors.Is(err, investigation.ErrInvalidRequest) {
			t.Fatalf("RegisterSignal(%q/%q) error = %v, want ErrInvalidRequest", signal.WorkspaceID, signal.ID, err)
		}
	}

	if _, err := repository.GetIncident(context.Background(), "a\x00b", "c"); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("GetIncident(NUL workspace) error = %v, want ErrInvalidRequest", err)
	}
	if _, err := repository.GetIncident(context.Background(), "a", "b\x00c"); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("GetIncident(NUL resource) error = %v, want ErrInvalidRequest", err)
	}
	if _, err := repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
		WorkspaceID: "a", SignalID: "b\x00c", CorrelationKey: "safe:key", MappingStatus: domain.MappingUnresolved,
	}); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("CorrelateSignal(NUL signal) error = %v, want ErrInvalidRequest", err)
	}
}

func TestAllRepositoryOperationsRejectUnsafeResourceScopes(t *testing.T) {
	repository := newRepository(t, time.Date(2026, 7, 12, 9, 30, 0, 0, time.UTC))
	ctx := context.Background()
	unsafeWorkspace := "workspace\x00other"
	validTask := investigation.TaskSpec{
		Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
	}

	operations := map[string]func() error{
		"list incidents": func() error {
			_, err := repository.ListIncidents(ctx, investigation.ListIncidentsRequest{WorkspaceID: unsafeWorkspace})
			return err
		},
		"create investigation": func() error {
			_, err := repository.CreateOrGetInvestigation(ctx, investigation.CreateOrGetInvestigationRequest{
				WorkspaceID: unsafeWorkspace, IncidentID: "incident-1", IdempotencyKey: "create:1", Tasks: []investigation.TaskSpec{validTask},
			})
			return err
		},
		"get investigation": func() error {
			_, err := repository.GetInvestigation(ctx, unsafeWorkspace, "investigation-1")
			return err
		},
		"list investigations": func() error {
			_, err := repository.ListInvestigations(ctx, investigation.ListInvestigationsRequest{WorkspaceID: unsafeWorkspace})
			return err
		},
		"get task": func() error {
			_, err := repository.GetTask(ctx, unsafeWorkspace, "task-1")
			return err
		},
		"list tasks": func() error {
			_, err := repository.ListTasks(ctx, investigation.ListTasksRequest{WorkspaceID: unsafeWorkspace, InvestigationID: "investigation-1"})
			return err
		},
		"get evidence": func() error {
			_, err := repository.GetEvidence(ctx, unsafeWorkspace, "evidence-1")
			return err
		},
		"list evidence": func() error {
			_, err := repository.ListEvidence(ctx, investigation.ListEvidenceRequest{WorkspaceID: unsafeWorkspace, InvestigationID: "investigation-1"})
			return err
		},
		"get hypothesis": func() error {
			_, err := repository.GetHypothesis(ctx, unsafeWorkspace, "hypothesis-1")
			return err
		},
		"list hypotheses": func() error {
			_, err := repository.ListHypotheses(ctx, investigation.ListHypothesesRequest{WorkspaceID: unsafeWorkspace, InvestigationID: "investigation-1"})
			return err
		},
		"complete task": func() error {
			_, err := repository.CompleteTask(ctx, investigation.CompleteTaskRequest{
				WorkspaceID: unsafeWorkspace, InvestigationID: "investigation-1", TaskID: "task-1", RunnerID: "runner-1",
				IdempotencyKey: "complete:1", Status: domain.ReadTaskFailed, FailureCode: "collector_failed",
			})
			return err
		},
		"start model": func() error {
			_, err := repository.StartModel(ctx, investigation.StartModelRequest{
				WorkspaceID: unsafeWorkspace, InvestigationID: "investigation-1", IdempotencyKey: "model:start:unsafe",
			})
			return err
		},
		"finalize": func() error {
			_, err := repository.FinalizeInvestigation(ctx, investigation.FinalizeInvestigationRequest{
				WorkspaceID: unsafeWorkspace, InvestigationID: "investigation-1", IdempotencyKey: "finalize:1",
				Status: domain.InvestigationCancelled, ModelStatus: domain.ModelCancelled, FailureCode: "cancelled",
			})
			return err
		},
		"feedback": func() error {
			_, err := repository.RecordFeedback(ctx, investigation.RecordFeedbackRequest{
				WorkspaceID: unsafeWorkspace, IncidentID: "incident-1", InvestigationID: "investigation-1",
				HypothesisID: "hypothesis-1", Actor: domain.Actor{Type: domain.ActorHuman, ID: "user-1"},
				Verdict: domain.FeedbackInconclusive, Details: []byte(`{"reason":"unknown"}`), IdempotencyKey: "feedback:1",
			})
			return err
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			if err := operation(); !errors.Is(err, investigation.ErrInvalidRequest) {
				t.Fatalf("operation error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestIdempotencyKeyHasOneWorkspaceWideOperationOwner(t *testing.T) {
	now := time.Date(2026, 7, 12, 11, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-idempotency-owner", now)
	const sharedKey = "shared:operation-key"
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: sharedKey,
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}},
	})
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}

	operations := map[string]func() error{
		"complete": func() error {
			_, err := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
				WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, TaskID: created.Tasks[0].ID,
				RunnerID: "runner-1", IdempotencyKey: sharedKey, Status: domain.ReadTaskFailed, FailureCode: "collector_failed",
			})
			return err
		},
		"finalize": func() error {
			_, err := repository.FinalizeInvestigation(context.Background(), investigation.FinalizeInvestigationRequest{
				WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, IdempotencyKey: sharedKey,
				Status: domain.InvestigationCancelled, ModelStatus: domain.ModelCancelled, FailureCode: "cancelled",
			})
			return err
		},
		"start model": func() error {
			_, err := repository.StartModel(context.Background(), investigation.StartModelRequest{
				WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
				IdempotencyKey: sharedKey,
			})
			return err
		},
		"feedback": func() error {
			_, err := repository.RecordFeedback(context.Background(), investigation.RecordFeedbackRequest{
				WorkspaceID: "workspace-1", IncidentID: incident.ID, InvestigationID: created.Investigation.ID,
				HypothesisID: "hypothesis-1", Actor: domain.Actor{Type: domain.ActorHuman, ID: "user-1"},
				Verdict: domain.FeedbackInconclusive, Details: []byte(`{"reason":"unknown"}`), IdempotencyKey: sharedKey,
			})
			return err
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			if err := operation(); !errors.Is(err, store.ErrIdempotencyConflict) {
				t.Fatalf("operation error = %v, want ErrIdempotencyConflict", err)
			}
		})
	}
}

func TestRegisterSignalEnforcesInvestigationFixtureBoundary(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	valid := testSignal("workspace-1", "signal-boundary", "firing", now)

	tooManyLabels := make(map[string]string, 65)
	for index := 0; index < 65; index++ {
		tooManyLabels[fmt.Sprintf("label_%02d", index)] = "value"
	}
	for name, mutate := range map[string]func(*domain.Signal){
		"short payload hash": func(signal *domain.Signal) { signal.PayloadHash = "short" },
		"uppercase payload hash": func(signal *domain.Signal) {
			signal.PayloadHash = strings.Repeat("A", 64)
		},
		"too many labels": func(signal *domain.Signal) { signal.Labels = tooManyLabels },
		"unsafe label key": func(signal *domain.Signal) {
			signal.Labels = map[string]string{"bad\nkey": "value"}
		},
		"unsafe label value": func(signal *domain.Signal) {
			signal.Labels = map[string]string{"service": "payments\x00other"}
		},
		"sensitive label": func(signal *domain.Signal) {
			signal.Labels = map[string]string{"authorization": "Bearer fixture-canary"}
		},
		"oversized signal id": func(signal *domain.Signal) {
			signal.ID = strings.Repeat("s", domain.MaxResourceIDBytes+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			repository := newRepository(t, now)
			item := valid
			item.Labels = cloneStringMap(valid.Labels)
			mutate(&item)
			if _, err := repository.RegisterSignal(context.Background(), item); !errors.Is(err, investigation.ErrInvalidRequest) {
				t.Fatalf("RegisterSignal() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestCorrelateSignalValidatesOptionalAndExactMappingResourceIDs(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 30, 0, 0, time.UTC)
	for name, request := range map[string]investigation.CorrelateSignalRequest{
		"exact unsafe service": {
			WorkspaceID: "workspace-1", SignalID: "signal-1", CorrelationKey: "payments:prod:exact",
			MappingStatus: domain.MappingExact, ServiceID: "payments\x00other", EnvironmentID: "prod",
		},
		"ambiguous unsafe optional service": {
			WorkspaceID: "workspace-1", SignalID: "signal-1", CorrelationKey: "payments:prod:ambiguous",
			MappingStatus: domain.MappingAmbiguous, ServiceID: "payments\nother",
		},
		"unresolved oversized optional environment": {
			WorkspaceID: "workspace-1", SignalID: "signal-1", CorrelationKey: "payments:prod:unresolved",
			MappingStatus: domain.MappingUnresolved, EnvironmentID: strings.Repeat("e", domain.MaxResourceIDBytes+1),
		},
	} {
		t.Run(name, func(t *testing.T) {
			repository := newRepository(t, now)
			if _, err := repository.RegisterSignal(context.Background(), testSignal("workspace-1", "signal-1", "firing", now)); err != nil {
				t.Fatalf("RegisterSignal() error = %v", err)
			}
			if _, err := repository.CorrelateSignal(context.Background(), request); !errors.Is(err, investigation.ErrInvalidRequest) {
				t.Fatalf("CorrelateSignal() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestActiveInvestigationRejectsDifferentTaskRequestHash(t *testing.T) {
	now := time.Date(2026, 7, 12, 13, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-active-hash", now)
	if _, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:metrics",
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}},
	}); err != nil {
		t.Fatalf("CreateOrGetInvestigation(first) error = %v", err)
	}

	_, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:logs",
		Tasks: []investigation.TaskSpec{{
			Key: "logs", ConnectorID: "victorialogs-prod", Operation: "search", Input: []byte(`{"lookback_minutes":30}`),
		}},
	})
	if !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("CreateOrGetInvestigation(different active tasks) error = %v, want ErrIdempotencyConflict", err)
	}
}

func TestStartModelPersistsPendingToRunningAndReplaysIdempotently(t *testing.T) {
	now := time.Date(2026, 7, 12, 13, 30, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-start-model", now)
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:start-model",
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}},
	})
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}
	payload := []byte(`{"series_count":3}`)
	if _, err := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, TaskID: created.Tasks[0].ID,
		RunnerID: "runner-1", IdempotencyKey: "complete:start-model", Status: domain.ReadTaskEvidence,
		Evidence: &investigation.EvidenceInput{Payload: payload, ContentHash: sha256Hex(payload), CollectedAt: now},
	}); err != nil {
		t.Fatalf("CompleteTask() error = %v", err)
	}
	request := investigation.StartModelRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, IdempotencyKey: "model:start:1",
	}
	first, err := repository.StartModel(context.Background(), request)
	if err != nil {
		t.Fatalf("StartModel(first) error = %v", err)
	}
	replay, err := repository.StartModel(context.Background(), request)
	if err != nil {
		t.Fatalf("StartModel(replay) error = %v", err)
	}
	if first.Investigation.ModelStatus != domain.ModelRunning || !replay.Replayed ||
		replay.Investigation.ModelStatus != domain.ModelRunning {
		t.Fatalf("StartModel results = %#v / %#v", first, replay)
	}
}

func TestFinalizeRequiresExplicitModelStateTransition(t *testing.T) {
	now := time.Date(2026, 7, 12, 14, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-model-transition", now)
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:model-transition",
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
		RunnerID: "runner-1", IdempotencyKey: "complete:model-transition", Status: domain.ReadTaskEvidence,
		Evidence: &investigation.EvidenceInput{Payload: payload, ContentHash: sha256Hex(payload), CollectedAt: now},
	})
	if err != nil {
		t.Fatalf("CompleteTask() error = %v", err)
	}
	proposal := []byte(`{"summary":"pool saturation"}`)
	completedRequest := investigation.FinalizeInvestigationRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
		IdempotencyKey: "finalize:model-completed", Status: domain.InvestigationCompleted, ModelStatus: domain.ModelCompleted,
		Hypotheses: []investigation.HypothesisSpec{{
			Rank: 1, Confidence: 0.8, Summary: "Database pool saturation", Proposal: proposal,
			ProposalHash: sha256Hex(proposal), EvidenceIDs: []string{completion.Evidence.ID},
		}},
	}
	if _, err := repository.FinalizeInvestigation(context.Background(), completedRequest); !errors.Is(err, investigation.ErrInvalidTransition) {
		t.Fatalf("FinalizeInvestigation(COMPLETED from PENDING) error = %v, want ErrInvalidTransition", err)
	}
	if _, err := repository.StartModel(context.Background(), investigation.StartModelRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, IdempotencyKey: "model:start:transition",
	}); err != nil {
		t.Fatalf("StartModel() error = %v", err)
	}
	if _, err := repository.FinalizeInvestigation(context.Background(), investigation.FinalizeInvestigationRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
		IdempotencyKey: "finalize:model-skipped", Status: domain.InvestigationCompleted, ModelStatus: domain.ModelSkipped,
	}); !errors.Is(err, investigation.ErrInvalidTransition) {
		t.Fatalf("FinalizeInvestigation(SKIPPED from RUNNING) error = %v, want ErrInvalidTransition", err)
	}
	result, err := repository.FinalizeInvestigation(context.Background(), completedRequest)
	if err != nil || result.Investigation.ModelStatus != domain.ModelCompleted {
		t.Fatalf("FinalizeInvestigation(COMPLETED from RUNNING) = %#v, %v", result, err)
	}
}

func TestFinalizeDistinguishesSkippedConfigurationFromCancellation(t *testing.T) {
	now := time.Date(2026, 7, 12, 14, 30, 0, 0, time.UTC)
	t.Run("skipped from pending", func(t *testing.T) {
		repository := newRepository(t, now)
		incident := createIncident(t, repository, "workspace-1", "signal-model-skipped", now)
		created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
			WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:model-skipped",
			Tasks: []investigation.TaskSpec{{
				Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
			}},
		})
		if err != nil {
			t.Fatalf("CreateOrGetInvestigation() error = %v", err)
		}
		payload := []byte(`{"series_count":3}`)
		if _, err := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
			WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, TaskID: created.Tasks[0].ID,
			RunnerID: "runner-1", IdempotencyKey: "complete:model-skipped", Status: domain.ReadTaskEvidence,
			Evidence: &investigation.EvidenceInput{Payload: payload, ContentHash: sha256Hex(payload), CollectedAt: now},
		}); err != nil {
			t.Fatalf("CompleteTask() error = %v", err)
		}
		result, err := repository.FinalizeInvestigation(context.Background(), investigation.FinalizeInvestigationRequest{
			WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
			IdempotencyKey: "finalize:model-skipped", Status: domain.InvestigationCompleted, ModelStatus: domain.ModelSkipped,
		})
		if err != nil || result.Investigation.ModelStatus != domain.ModelSkipped {
			t.Fatalf("FinalizeInvestigation(SKIPPED) = %#v, %v", result, err)
		}
	})

	for _, startRunning := range []bool{false, true} {
		name := "cancelled from pending"
		if startRunning {
			name = "cancelled from running"
		}
		t.Run(name, func(t *testing.T) {
			repository := newRepository(t, now)
			suffix := "pending"
			if startRunning {
				suffix = "running"
			}
			incident := createIncident(t, repository, "workspace-1", "signal-model-cancelled-"+suffix, now)
			created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
				WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:model-cancelled-" + suffix,
				Tasks: []investigation.TaskSpec{{
					Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
				}},
			})
			if err != nil {
				t.Fatalf("CreateOrGetInvestigation() error = %v", err)
			}
			if startRunning {
				payload := []byte(`{"series_count":3}`)
				if _, err := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
					WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, TaskID: created.Tasks[0].ID,
					RunnerID: "runner-1", IdempotencyKey: "complete:model-cancelled", Status: domain.ReadTaskEvidence,
					Evidence: &investigation.EvidenceInput{Payload: payload, ContentHash: sha256Hex(payload), CollectedAt: now},
				}); err != nil {
					t.Fatalf("CompleteTask() error = %v", err)
				}
				startModel(t, repository, created.Investigation.ID, "model:start:cancelled")
			}
			result, err := repository.FinalizeInvestigation(context.Background(), investigation.FinalizeInvestigationRequest{
				WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
				IdempotencyKey: "finalize:model-cancelled-" + suffix,
				Status:         domain.InvestigationCancelled, ModelStatus: domain.ModelCancelled, FailureCode: "cancelled",
			})
			if err != nil || result.Investigation.ModelStatus != domain.ModelCancelled {
				t.Fatalf("FinalizeInvestigation(CANCELLED) = %#v, %v", result, err)
			}
		})
	}
}

func newRepository(t *testing.T, now time.Time) *memory.Repository {
	t.Helper()
	var mu sync.Mutex
	next := 0
	repository, err := memory.New(memory.Options{
		Clock: func() time.Time { return now },
		IDFactory: func() string {
			mu.Lock()
			defer mu.Unlock()
			next++
			return fmt.Sprintf("generated-%d", next)
		},
	})
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	return repository
}

func testSignal(workspaceID, signalID, status string, observedAt time.Time) domain.Signal {
	return domain.Signal{
		ID: signalID, WorkspaceID: workspaceID, IntegrationID: "integration-1", Provider: "alertmanager",
		ProviderEventID: signalID, PayloadHash: sha256Hex([]byte("payload-" + signalID)), Fingerprint: "fingerprint-1",
		Status: status, Labels: map[string]string{"service": "payments"}, ObservedAt: observedAt,
	}
}

func cloneStringMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func createIncident(t *testing.T, repository *memory.Repository, workspaceID, signalID string, now time.Time) domain.Incident {
	t.Helper()
	signal := testSignal(workspaceID, signalID, "firing", now)
	if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
		t.Fatalf("RegisterSignal() error = %v", err)
	}
	result, err := repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
		WorkspaceID: workspaceID, SignalID: signalID, CorrelationKey: "payments:prod:" + signalID,
		ServiceID: "payments", EnvironmentID: "prod", MappingStatus: domain.MappingExact,
	})
	if err != nil {
		t.Fatalf("CorrelateSignal() error = %v", err)
	}
	return result.Incident
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func startModel(t *testing.T, repository *memory.Repository, investigationID, idempotencyKey string) {
	t.Helper()
	if _, err := repository.StartModel(context.Background(), investigation.StartModelRequest{
		WorkspaceID: "workspace-1", InvestigationID: investigationID, IdempotencyKey: idempotencyKey,
	}); err != nil {
		t.Fatalf("StartModel() error = %v", err)
	}
}
