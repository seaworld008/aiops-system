package memory_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func TestCompleteTaskPersistsEvidenceReceiptAndDefensiveCopies(t *testing.T) {
	now := time.Date(2026, 7, 11, 15, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-complete", now)
	created, err := repository.CreateOrGetInvestigation(context.Background(), boundCreateRequest(t, investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:complete",
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-prod-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}},
	}))

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
	tamperedReplay := request
	tamperedEvidence := *request.Evidence
	tamperedEvidence.Payload = []byte(` {"series_count":3} `)
	tamperedReplay.Evidence = &tamperedEvidence
	if _, err := repository.CompleteTask(context.Background(), tamperedReplay); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("CompleteTask(tampered replay) error = %v, want ErrInvalidRequest", err)
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

func TestCompleteTaskRejectsEvidenceCollectedBeyondTrustedCommitBoundWithoutPartialWrites(t *testing.T) {
	now := time.Date(2026, 7, 12, 21, 15, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-future-evidence", now)
	created, err := repository.CreateOrGetInvestigation(context.Background(), boundCreateRequest(t, investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:future-evidence",
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-prod-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}},
	}))

	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}
	payload := []byte(`{"series_count":3}`)
	if _, err := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, TaskID: created.Tasks[0].ID,
		RunnerID: "runner-1", IdempotencyKey: "complete:future-evidence", Status: domain.ReadTaskEvidence,
		Evidence: &investigation.EvidenceInput{Payload: payload, ContentHash: sha256Hex(payload), CollectedAt: now.Add(time.Hour)},
	}); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("CompleteTask(future evidence) error = %v, want ErrInvalidRequest", err)
	}
	task, err := repository.GetTask(context.Background(), "workspace-1", created.Tasks[0].ID)
	if err != nil || task.Status != domain.ReadTaskQueued || !task.CompletedAt.IsZero() {
		t.Fatalf("GetTask() = %#v, %v; want unchanged QUEUED task", task, err)
	}
	evidence, err := repository.ListEvidence(context.Background(), investigation.ListEvidenceRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
	})
	if err != nil || len(evidence) != 0 {
		t.Fatalf("ListEvidence() = %#v, %v; want no partial evidence", evidence, err)
	}
}

func TestConcurrentTaskCompletionCannotChangeListEvidenceOrder(t *testing.T) {
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-concurrent-evidence-order", now)
	tasks := make([]investigation.TaskSpec, 8)
	for index := range tasks {
		tasks[index] = investigation.TaskSpec{
			Key: fmt.Sprintf("task-%02d", index), ConnectorID: "prometheus-prod-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Operation: "range_query",
			Input: []byte(`{"lookback_minutes":15}`),
		}
	}
	created, err := repository.CreateOrGetInvestigation(context.Background(), boundCreateRequest(t, investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:concurrent-evidence-order", Tasks: tasks,
	}))

	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}

	start := make(chan struct{})
	errorsByTask := make(chan error, len(created.Tasks))
	var group sync.WaitGroup
	for index, task := range created.Tasks {
		index, task := index, task
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			payload := []byte(fmt.Sprintf(`{"position":%d}`, index))
			_, completeErr := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
				WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, TaskID: task.ID,
				RunnerID: "runner-1", IdempotencyKey: fmt.Sprintf("complete:concurrent-order:%d", index),
				Status: domain.ReadTaskEvidence,
				Evidence: &investigation.EvidenceInput{
					Payload: payload, ContentHash: sha256Hex(payload),
					CollectedAt: now.Add(-time.Duration((index*5)%7) * time.Minute),
				},
			})
			errorsByTask <- completeErr
		}()
	}
	close(start)
	group.Wait()
	close(errorsByTask)
	for completeErr := range errorsByTask {
		if completeErr != nil {
			t.Fatalf("CompleteTask(concurrent) error = %v", completeErr)
		}
	}

	first, err := repository.ListEvidence(context.Background(), investigation.ListEvidenceRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
	})
	if err != nil || len(first) != len(created.Tasks) {
		t.Fatalf("ListEvidence(first) = %#v, %v", first, err)
	}
	second, err := repository.ListEvidence(context.Background(), investigation.ListEvidenceRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
	})
	if err != nil || len(second) != len(first) {
		t.Fatalf("ListEvidence(second) = %#v, %v", second, err)
	}
	for index := range first {
		if first[index].ID != second[index].ID {
			t.Fatalf("ListEvidence repeat IDs differ at %d: %q/%q", index, first[index].ID, second[index].ID)
		}
		if index == 0 {
			continue
		}
		previous, current := first[index-1], first[index]
		ordered := previous.CollectedAt.Before(current.CollectedAt) ||
			previous.CollectedAt.Equal(current.CollectedAt) && (previous.CreatedAt.Before(current.CreatedAt) ||
				previous.CreatedAt.Equal(current.CreatedAt) && previous.ID < current.ID)
		if !ordered {
			t.Fatalf("ListEvidence order at %d = (%s,%s,%q) then (%s,%s,%q)", index,
				previous.CollectedAt, previous.CreatedAt, previous.ID, current.CollectedAt, current.CreatedAt, current.ID)
		}
	}
}
