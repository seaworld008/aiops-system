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

func TestRepositoryRejectsInvalidOrDuplicateFactoryIDsWithoutPartialInvestigation(t *testing.T) {
	now := time.Date(2026, 7, 11, 21, 0, 0, 0, time.UTC)
	invalidFactory, err := memory.New(memory.Options{
		TaskRuntimeBinder: testTaskRuntimeBinder,
		Clock:             func() time.Time { return now }, IDFactory: func() string { return "invalid id" }, TenantResolver: testTenantResolver,
		TaskSpecAuthorizer: testTaskSpecAuthorizer,
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
		TaskRuntimeBinder:  testTaskRuntimeBinder,
		Clock:              func() time.Time { return now },
		TenantResolver:     testTenantResolver,
		TaskSpecAuthorizer: testTaskSpecAuthorizer,
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
	_, err = duplicateFactory.CreateOrGetInvestigation(context.Background(), boundCreateRequest(t, investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:duplicate-id",
		Tasks: []investigation.TaskSpec{
			{Key: "logs", ConnectorID: "victorialogs-prod-v1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Operation: "search", Input: []byte(`{"lookback_minutes":30}`)},
			{Key: "metrics", ConnectorID: "prometheus-prod-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`)},
		},
	}))

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
		Key: "metrics", ConnectorID: "prometheus-prod-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
	}

	operations := map[string]func() error{
		"list incidents": func() error {
			_, err := repository.ListIncidents(ctx, investigation.ListIncidentsRequest{WorkspaceID: unsafeWorkspace})
			return err
		},
		"create investigation": func() error {
			_, err := repository.CreateOrGetInvestigation(ctx, boundCreateRequest(t, investigation.CreateOrGetInvestigationRequest{
				WorkspaceID: unsafeWorkspace, IncidentID: "incident-1", IdempotencyKey: "create:1", Tasks: []investigation.TaskSpec{validTask},
			}))

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
		"fail investigation": func() error {
			_, err := repository.FailInvestigation(ctx, investigation.FailInvestigationRequest{
				WorkspaceID: unsafeWorkspace, InvestigationID: "investigation-1",
				IdempotencyKey: "fail:unsafe", FailureCode: "internal_failure",
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
	created, err := repository.CreateOrGetInvestigation(context.Background(), boundCreateRequest(t, investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: sharedKey,
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-prod-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}},
	}))

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
		"fail investigation": func() error {
			_, err := repository.FailInvestigation(context.Background(), investigation.FailInvestigationRequest{
				WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
				IdempotencyKey: sharedKey, FailureCode: "internal_failure",
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
