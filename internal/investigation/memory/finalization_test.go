package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

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
	tamperedFinalize := request
	tamperedFinalize.Hypotheses = append([]investigation.HypothesisSpec(nil), request.Hypotheses...)
	tamperedFinalize.Hypotheses[0].Proposal = []byte(` {"summary":"pool saturation"} `)
	if _, err := repository.FinalizeInvestigation(context.Background(), tamperedFinalize); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("FinalizeInvestigation(tampered replay) error = %v, want ErrInvalidRequest", err)
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
	if _, err := repository.FinalizeInvestigation(context.Background(), investigation.FinalizeInvestigationRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
		IdempotencyKey: "finalize:model-failure-bypass", Status: domain.InvestigationFailed,
		ModelStatus: domain.ModelFailed, FailureCode: "internal_failure", ModelFailureCode: "model_unavailable",
	}); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("FinalizeInvestigation(FAILED bypass) error = %v, want ErrInvalidRequest", err)
	}

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

func TestFinalizeCancellationAtomicallyCancelsQueuedTasksAndReleasesActiveSlot(t *testing.T) {
	now := time.Date(2026, 7, 12, 20, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-cancel-queued", now)
	taskSpecs := []investigation.TaskSpec{
		{Key: "logs", ConnectorID: "victorialogs-prod", Operation: "search", Input: []byte(`{"lookback_minutes":30}`)},
		{Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`)},
	}
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:cancel-queued", Tasks: taskSpecs,
	})
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}
	result, err := repository.FinalizeInvestigation(context.Background(), investigation.FinalizeInvestigationRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, IdempotencyKey: "finalize:cancel-queued",
		Status: domain.InvestigationCancelled, ModelStatus: domain.ModelCancelled, FailureCode: "operator_cancelled",
	})
	if err != nil {
		t.Fatalf("FinalizeInvestigation(CANCELLED) error = %v", err)
	}
	tasks, err := repository.ListTasks(context.Background(), investigation.ListTasksRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
	})
	if err != nil || len(tasks) != len(taskSpecs) {
		t.Fatalf("ListTasks() = %#v, %v", tasks, err)
	}
	for _, task := range tasks {
		if task.Status != domain.ReadTaskCancelled || task.FailureCode != "operator_cancelled" ||
			!task.StartedAt.IsZero() || task.CompletedAt != result.Investigation.CompletedAt || task.UpdatedAt != result.Investigation.CompletedAt {
			t.Fatalf("cancelled queued task = %#v, want atomic pre-start cancellation", task)
		}
	}
	second, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:after-cancel", Tasks: taskSpecs,
	})
	if err != nil || !second.Created || second.Investigation.ID == created.Investigation.ID {
		t.Fatalf("CreateOrGetInvestigation(after cancel) = %#v, %v; want new active investigation", second, err)
	}
}

func TestFinalizeCancellationPreservesTerminalTasksAndCancelsQueuedRemainder(t *testing.T) {
	now := time.Date(2026, 7, 12, 20, 15, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-cancel-mixed", now)
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:cancel-mixed",
		Tasks: []investigation.TaskSpec{
			{Key: "logs", ConnectorID: "victorialogs-prod", Operation: "search", Input: []byte(`{"lookback_minutes":30}`)},
			{Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`)},
			{Key: "traces", ConnectorID: "tempo-prod", Operation: "search", Input: []byte(`{"lookback_minutes":20}`)},
		},
	})
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}
	payload := []byte(`{"matches":2}`)
	evidenceResult, err := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, TaskID: created.Tasks[0].ID,
		RunnerID: "runner-1", IdempotencyKey: "complete:cancel-mixed:evidence", Status: domain.ReadTaskEvidence,
		Evidence: &investigation.EvidenceInput{Payload: payload, ContentHash: sha256Hex(payload), CollectedAt: now},
	})
	if err != nil {
		t.Fatalf("CompleteTask(evidence) error = %v", err)
	}
	failedResult, err := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, TaskID: created.Tasks[1].ID,
		RunnerID: "runner-1", IdempotencyKey: "complete:cancel-mixed:failed", Status: domain.ReadTaskFailed, FailureCode: "source_failed",
	})
	if err != nil {
		t.Fatalf("CompleteTask(failed) error = %v", err)
	}
	if _, err := repository.FinalizeInvestigation(context.Background(), investigation.FinalizeInvestigationRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, IdempotencyKey: "finalize:cancel-mixed",
		Status: domain.InvestigationCancelled, ModelStatus: domain.ModelCancelled, FailureCode: "operator_cancelled",
	}); err != nil {
		t.Fatalf("FinalizeInvestigation(CANCELLED) error = %v", err)
	}
	tasks, err := repository.ListTasks(context.Background(), investigation.ListTasksRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
	})
	if err != nil || len(tasks) != 3 {
		t.Fatalf("ListTasks() = %#v, %v", tasks, err)
	}
	byID := make(map[string]domain.ReadTask, len(tasks))
	for _, task := range tasks {
		byID[task.ID] = task
		if task.Status == domain.ReadTaskQueued || task.Status == domain.ReadTaskRunning {
			t.Fatalf("task remained non-terminal after cancellation: %#v", task)
		}
	}
	if task := byID[evidenceResult.Task.ID]; task.Status != domain.ReadTaskEvidence || task.EvidenceID != evidenceResult.Evidence.ID || task.FailureCode != "" {
		t.Fatalf("evidence task changed during cancellation: %#v", task)
	}
	if task := byID[failedResult.Task.ID]; task.Status != domain.ReadTaskFailed || task.FailureCode != "source_failed" {
		t.Fatalf("failed task changed during cancellation: %#v", task)
	}
	if task := byID[created.Tasks[2].ID]; task.Status != domain.ReadTaskCancelled || task.FailureCode != "operator_cancelled" {
		t.Fatalf("queued task was not cancelled: %#v", task)
	}
}
