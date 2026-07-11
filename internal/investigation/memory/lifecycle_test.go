package memory_test

import (
	"context"
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
	conflict.Tasks[0].Input = []byte(`{"lookback_minutes":16}`)
	if _, err := repository.CreateOrGetInvestigation(context.Background(), conflict); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("CreateOrGetInvestigation(conflict) error = %v, want ErrIdempotencyConflict", err)
	}
}

func TestCreateInvestigationReadsMonotonicCommitTimeInsideLockedPreparation(t *testing.T) {
	base := time.Date(2026, 7, 13, 3, 0, 0, 0, time.UTC)
	commitAt := base.Add(10 * time.Minute)
	clockNow := base
	nextID := 0
	repository, err := memory.New(memory.Options{
		Clock: func() time.Time { return clockNow }, TenantResolver: testTenantResolver, TaskSpecAuthorizer: testTaskSpecAuthorizer,
		IDFactory: func() string {
			nextID++
			if nextID == 2 {
				clockNow = commitAt
			}
			return fmt.Sprintf("create-commit-%d", nextID)
		},
	})
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	incident := createIncident(t, repository, "workspace-1", "signal-create-commit", base)
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:create-commit",
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}},
	})
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}
	if created.Investigation.CreatedAt != commitAt || created.Investigation.UpdatedAt != commitAt ||
		created.Tasks[0].CreatedAt != commitAt || created.Tasks[0].UpdatedAt != commitAt {
		t.Fatalf("created times = investigation %s/%s task %s/%s, want locked commit %s",
			created.Investigation.CreatedAt, created.Investigation.UpdatedAt,
			created.Tasks[0].CreatedAt, created.Tasks[0].UpdatedAt, commitAt)
	}
}

func TestCreateInvestigationUsesIncidentTimeUpperBoundWhenClockRollsBack(t *testing.T) {
	base := time.Date(2026, 7, 13, 4, 30, 0, 0, time.UTC)
	incidentTime := base.Add(4 * time.Minute)
	clockNow := base
	nextID := 0
	repository, err := memory.New(memory.Options{
		Clock: func() time.Time { return clockNow }, TenantResolver: testTenantResolver, TaskSpecAuthorizer: testTaskSpecAuthorizer,
		IDFactory: func() string { nextID++; return fmt.Sprintf("incident-bound-%d", nextID) },
	})
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	signal := testSignal("workspace-1", "signal-incident-time-bound", "firing", incidentTime)
	if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
		t.Fatalf("RegisterSignal() error = %v", err)
	}
	correlated, err := repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
		WorkspaceID: "workspace-1", SignalID: signal.ID, CorrelationKey: "payments:prod:incident-time-bound",
		ServiceID: "payments", EnvironmentID: "prod", MappingStatus: domain.MappingExact,
	})
	if err != nil {
		t.Fatalf("CorrelateSignal() error = %v", err)
	}
	clockNow = base.Add(-time.Hour)
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: correlated.Incident.ID, IdempotencyKey: "investigate:incident-time-bound",
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}},
	})
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}
	storedIncident, err := repository.GetIncident(context.Background(), "workspace-1", correlated.Incident.ID)
	if err != nil || storedIncident.UpdatedAt != incidentTime {
		t.Fatalf("GetIncident() = %#v, %v; want transition at %s", storedIncident, err, incidentTime)
	}
	if created.Investigation.CreatedAt != incidentTime || created.Investigation.UpdatedAt != incidentTime ||
		created.Tasks[0].CreatedAt != incidentTime || created.Tasks[0].UpdatedAt != incidentTime {
		t.Fatalf("Create times = %#v/%#v, want Incident upper bound %s", created.Investigation, created.Tasks[0], incidentTime)
	}
}

func TestCreateInvestigationRequiresTrustedTaskSpecAuthorizationWithoutPartialWrite(t *testing.T) {
	now := time.Date(2026, 7, 13, 4, 45, 0, 0, time.UTC)
	nextID := 0
	repository, err := memory.New(memory.Options{
		Clock: func() time.Time { return now }, TenantResolver: testTenantResolver,
		IDFactory: func() string { nextID++; return fmt.Sprintf("authorized-create-%d", nextID) },
		TaskSpecAuthorizer: func(_ context.Context, _ string, spec investigation.TaskSpec) error {
			if spec.ConnectorID != "prometheus-prod" || spec.Operation != "range_query" {
				return errors.New("task-authorizer-canary")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	incident := createIncident(t, repository, "workspace-1", "signal-authorized-create", now)
	request := investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:authorized-create",
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "unknown-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}},
	}
	if _, err := repository.CreateOrGetInvestigation(context.Background(), request); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("CreateOrGetInvestigation(unauthorized) error = %v, want ErrInvalidRequest", err)
	} else if strings.Contains(err.Error(), "task-authorizer-canary") {
		t.Fatalf("CreateOrGetInvestigation() leaked authorizer error: %v", err)
	}
	storedIncident, err := repository.GetIncident(context.Background(), "workspace-1", incident.ID)
	if err != nil || storedIncident != incident {
		t.Fatalf("GetIncident(after rejection) = %#v, %v; want unchanged %#v", storedIncident, err, incident)
	}
	items, err := repository.ListInvestigations(context.Background(), investigation.ListInvestigationsRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID,
	})
	if err != nil || len(items) != 0 {
		t.Fatalf("ListInvestigations(after rejection) = %#v, %v; want empty", items, err)
	}
	request.Tasks[0].ConnectorID = "prometheus-prod"
	if result, err := repository.CreateOrGetInvestigation(context.Background(), request); err != nil || !result.Created {
		t.Fatalf("CreateOrGetInvestigation(corrected) = %#v, %v; rejection left partial state", result, err)
	}
}

func TestCreateInvestigationReplaySurvivesLaterTaskAuthorizationRevocation(t *testing.T) {
	now := time.Date(2026, 7, 13, 5, 10, 0, 0, time.UTC)
	authorized := true
	nextID := 0
	repository, err := memory.New(memory.Options{
		Clock: func() time.Time { return now }, TenantResolver: testTenantResolver,
		IDFactory: func() string { nextID++; return fmt.Sprintf("authorization-replay-%d", nextID) },
		TaskSpecAuthorizer: func(context.Context, string, investigation.TaskSpec) error {
			if !authorized {
				return errors.New("revoked-task-authorizer-canary")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	incident := createIncident(t, repository, "workspace-1", "signal-registry-replay", now)
	request := investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:authorization-replay",
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}},
	}
	first, err := repository.CreateOrGetInvestigation(context.Background(), request)
	if err != nil || !first.Created {
		t.Fatalf("CreateOrGetInvestigation(first) = %#v, %v; want created", first, err)
	}
	authorized = false
	replay, err := repository.CreateOrGetInvestigation(context.Background(), request)
	if err != nil || replay.Created || replay.Investigation.ID != first.Investigation.ID {
		t.Fatalf("CreateOrGetInvestigation(replay after revocation) = %#v, %v; want original resource", replay, err)
	}

	conflict := request
	conflict.Tasks = []investigation.TaskSpec{{
		Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":16}`),
	}}
	if _, err := repository.CreateOrGetInvestigation(context.Background(), conflict); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("CreateOrGetInvestigation(conflicting replay) error = %v, want ErrIdempotencyConflict", err)
	}

	newKey := request
	newKey.IdempotencyKey = "investigate:authorization-replay:new-key"
	if _, err := repository.CreateOrGetInvestigation(context.Background(), newKey); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("CreateOrGetInvestigation(new key after revocation) error = %v, want authorization rejection", err)
	} else if strings.Contains(err.Error(), "revoked-task-authorizer-canary") {
		t.Fatalf("CreateOrGetInvestigation() leaked authorizer error: %v", err)
	}
	authorized = true
	bound, err := repository.CreateOrGetInvestigation(context.Background(), newKey)
	if err != nil || bound.Created || bound.Investigation.ID != first.Investigation.ID {
		t.Fatalf("CreateOrGetInvestigation(new key after reauthorization) = %#v, %v; want active resource", bound, err)
	}
}

func TestCreateInvestigationRejectsTaskSpecOutsideTrustedServerSchema(t *testing.T) {
	now := time.Date(2026, 7, 13, 5, 0, 0, 0, time.UTC)
	for name, spec := range map[string]investigation.TaskSpec{
		"unknown operation": {
			Key: "metrics", ConnectorID: "prometheus-prod", Operation: "search", Input: []byte(`{"lookback_minutes":15}`),
		},
		"unknown field": {
			Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query",
			Input: []byte(`{"lookback_minutes":15,"namespace":"task-schema-canary"}`),
		},
		"wrong type": {
			Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":"15"}`),
		},
		"out of range": {
			Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":1441}`),
		},
	} {
		t.Run(name, func(t *testing.T) {
			repository := newRepository(t, now)
			incident := createIncident(t, repository, "workspace-1", "signal-task-schema-"+strings.ReplaceAll(name, " ", "-"), now)
			_, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
				WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:task-schema", Tasks: []investigation.TaskSpec{spec},
			})
			if !errors.Is(err, investigation.ErrInvalidRequest) {
				t.Fatalf("CreateOrGetInvestigation() error = %v, want ErrInvalidRequest", err)
			}
			if strings.Contains(err.Error(), "task-schema-canary") {
				t.Fatalf("CreateOrGetInvestigation() echoed task input: %v", err)
			}
			stored, getErr := repository.GetIncident(context.Background(), "workspace-1", incident.ID)
			if getErr != nil || stored != incident {
				t.Fatalf("GetIncident(after schema rejection) = %#v, %v; want unchanged", stored, getErr)
			}
		})
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

func TestCompletionFinalizationAndFeedbackUseMonotonicCommitTime(t *testing.T) {
	base := time.Date(2026, 7, 12, 21, 0, 0, 0, time.UTC)
	clockNow := base
	nextID := 0
	repository, err := memory.New(memory.Options{
		Clock: func() time.Time { return clockNow }, TenantResolver: testTenantResolver, TaskSpecAuthorizer: testTaskSpecAuthorizer,
		IDFactory: func() string { nextID++; return fmt.Sprintf("monotonic-%d", nextID) },
	})
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	incident := createIncident(t, repository, "workspace-1", "signal-monotonic", base)
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:monotonic",
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}},
	})
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}
	clockNow = base.Add(-time.Hour)
	collectedAt := base
	payload := []byte(`{"series_count":3}`)
	completion, err := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, TaskID: created.Tasks[0].ID,
		RunnerID: "runner-1", IdempotencyKey: "complete:monotonic", Status: domain.ReadTaskEvidence,
		Evidence: &investigation.EvidenceInput{Payload: payload, ContentHash: sha256Hex(payload), CollectedAt: collectedAt},
	})
	if err != nil {
		t.Fatalf("CompleteTask(clock rollback) error = %v", err)
	}
	if completion.Task.CompletedAt.Before(collectedAt) || completion.Evidence.CreatedAt.Before(collectedAt) {
		t.Fatalf("completion times = task %s evidence %s, want >= collected %s", completion.Task.CompletedAt, completion.Evidence.CreatedAt, collectedAt)
	}
	startModel(t, repository, created.Investigation.ID, "model:start:monotonic")
	proposal := []byte(`{"summary":"pool saturation"}`)
	finalized, err := repository.FinalizeInvestigation(context.Background(), investigation.FinalizeInvestigationRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, IdempotencyKey: "finalize:monotonic",
		Status: domain.InvestigationCompleted, ModelStatus: domain.ModelCompleted,
		Hypotheses: []investigation.HypothesisSpec{{
			Rank: 1, Confidence: 0.8, Summary: "Pool saturation", Proposal: proposal, ProposalHash: sha256Hex(proposal),
			EvidenceIDs: []string{completion.Evidence.ID},
		}},
	})
	if err != nil {
		t.Fatalf("FinalizeInvestigation(clock rollback) error = %v", err)
	}
	if finalized.Investigation.CompletedAt.Before(completion.Task.CompletedAt) {
		t.Fatalf("Investigation.CompletedAt = %s, want >= task %s", finalized.Investigation.CompletedAt, completion.Task.CompletedAt)
	}
	feedback, err := repository.RecordFeedback(context.Background(), investigation.RecordFeedbackRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, InvestigationID: created.Investigation.ID,
		HypothesisID: finalized.Hypotheses[0].ID, Actor: domain.Actor{Type: domain.ActorHuman, ID: "user-1"},
		Verdict: domain.FeedbackConfirmed, Details: []byte(`{"reason_code":"confirmed"}`), IdempotencyKey: "feedback:monotonic",
	})
	if err != nil {
		t.Fatalf("RecordFeedback(clock rollback) error = %v", err)
	}
	if feedback.Feedback.CreatedAt.Before(finalized.Investigation.CompletedAt) {
		t.Fatalf("Feedback.CreatedAt = %s, want >= investigation %s", feedback.Feedback.CreatedAt, finalized.Investigation.CompletedAt)
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

func TestStartModelRequiresEveryTaskToBeTerminal(t *testing.T) {
	now := time.Date(2026, 7, 13, 3, 30, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-model-task-barrier", now)
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:model-task-barrier",
		Tasks: []investigation.TaskSpec{
			{Key: "logs", ConnectorID: "victorialogs-prod", Operation: "search", Input: []byte(`{"lookback_minutes":30}`)},
			{Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`)},
		},
	})
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}
	if _, err := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, TaskID: created.Tasks[0].ID,
		RunnerID: "runner-1", IdempotencyKey: "complete:model-task-barrier:1",
		Status: domain.ReadTaskFailed, FailureCode: "source_failed",
	}); err != nil {
		t.Fatalf("CompleteTask(first) error = %v", err)
	}
	request := investigation.StartModelRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, IdempotencyKey: "model:start:task-barrier",
	}
	if _, err := repository.StartModel(context.Background(), request); !errors.Is(err, investigation.ErrInvalidTransition) {
		t.Fatalf("StartModel(with queued task) error = %v, want ErrInvalidTransition", err)
	}
	stored, err := repository.GetInvestigation(context.Background(), "workspace-1", created.Investigation.ID)
	if err != nil || stored.ModelStatus != domain.ModelPending {
		t.Fatalf("GetInvestigation(after rejected start) = %#v, %v; want PENDING", stored, err)
	}
	if _, err := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, TaskID: created.Tasks[1].ID,
		RunnerID: "runner-1", IdempotencyKey: "complete:model-task-barrier:2",
		Status: domain.ReadTaskFailed, FailureCode: "source_failed",
	}); err != nil {
		t.Fatalf("CompleteTask(second) error = %v", err)
	}
	if _, err := repository.StartModel(context.Background(), request); err != nil {
		t.Fatalf("StartModel(all terminal) error = %v", err)
	}
}

func TestStartModelReplayReturnsImmutableFirstRunningSnapshotAfterFailure(t *testing.T) {
	now := time.Date(2026, 7, 13, 4, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-model-start-snapshot", now)
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:model-start-snapshot",
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}},
	})
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}
	if _, err := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, TaskID: created.Tasks[0].ID,
		RunnerID: "runner-1", IdempotencyKey: "complete:model-start-snapshot",
		Status: domain.ReadTaskFailed, FailureCode: "source_failed",
	}); err != nil {
		t.Fatalf("CompleteTask() error = %v", err)
	}
	request := investigation.StartModelRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, IdempotencyKey: "model:start:snapshot",
	}
	first, err := repository.StartModel(context.Background(), request)
	if err != nil {
		t.Fatalf("StartModel(first) error = %v", err)
	}
	firstUpdatedAt := first.Investigation.UpdatedAt
	first.Investigation.Status = domain.InvestigationCancelled
	if _, err := repository.FailInvestigation(context.Background(), investigation.FailInvestigationRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
		IdempotencyKey: "fail:after-model-start", FailureCode: "internal_failure",
	}); err != nil {
		t.Fatalf("FailInvestigation() error = %v", err)
	}
	replay, err := repository.StartModel(context.Background(), request)
	if err != nil {
		t.Fatalf("StartModel(replay after failure) error = %v", err)
	}
	if !replay.Replayed || replay.Investigation.Status != domain.InvestigationRunning ||
		replay.Investigation.ModelStatus != domain.ModelRunning || replay.Investigation.UpdatedAt != firstUpdatedAt {
		t.Fatalf("StartModel(replay after failure) = %#v, want first RUNNING snapshot", replay)
	}
	replay.Investigation.Status = domain.InvestigationCancelled
	secondReplay, err := repository.StartModel(context.Background(), request)
	if err != nil || secondReplay.Investigation.Status != domain.InvestigationRunning ||
		secondReplay.Investigation.ModelStatus != domain.ModelRunning {
		t.Fatalf("StartModel(second replay) = %#v, %v; snapshot aliases replay", secondReplay, err)
	}
}

func TestStartModelReplayReturnsFirstRunningSnapshotAfterFinalization(t *testing.T) {
	now := time.Date(2026, 7, 13, 5, 30, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-model-start-finalize-snapshot", now)
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:model-start-finalize-snapshot",
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
		RunnerID: "runner-1", IdempotencyKey: "complete:model-start-finalize-snapshot", Status: domain.ReadTaskEvidence,
		Evidence: &investigation.EvidenceInput{Payload: payload, ContentHash: sha256Hex(payload), CollectedAt: now},
	}); err != nil {
		t.Fatalf("CompleteTask() error = %v", err)
	}
	request := investigation.StartModelRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, IdempotencyKey: "model:start:finalize-snapshot",
	}
	if _, err := repository.StartModel(context.Background(), request); err != nil {
		t.Fatalf("StartModel(first) error = %v", err)
	}
	if _, err := repository.FinalizeInvestigation(context.Background(), investigation.FinalizeInvestigationRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
		IdempotencyKey: "finalize:after-model-start", Status: domain.InvestigationCompleted,
		ModelStatus: domain.ModelFailed, ModelFailureCode: "model_unavailable",
	}); err != nil {
		t.Fatalf("FinalizeInvestigation() error = %v", err)
	}
	replay, err := repository.StartModel(context.Background(), request)
	if err != nil || !replay.Replayed || replay.Investigation.Status != domain.InvestigationRunning ||
		replay.Investigation.ModelStatus != domain.ModelRunning {
		t.Fatalf("StartModel(replay after finalize) = %#v, %v; want first RUNNING snapshot", replay, err)
	}
}

func TestFailInvestigationAtomicallyCancelsTasksReplaysAndReleasesActiveSlot(t *testing.T) {
	now := time.Date(2026, 7, 12, 20, 45, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-fail-investigation", now)
	taskSpecs := []investigation.TaskSpec{
		{Key: "logs", ConnectorID: "victorialogs-prod", Operation: "search", Input: []byte(`{"lookback_minutes":30}`)},
		{Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`)},
	}
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:fail", Tasks: taskSpecs,
	})
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}
	request := investigation.FailInvestigationRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
		IdempotencyKey: "fail:investigation", FailureCode: "internal_failure",
	}
	first, err := repository.FailInvestigation(context.Background(), request)
	if err != nil {
		t.Fatalf("FailInvestigation(first) error = %v", err)
	}
	replay, err := repository.FailInvestigation(context.Background(), request)
	if err != nil {
		t.Fatalf("FailInvestigation(replay) error = %v", err)
	}
	if first.Investigation.Status != domain.InvestigationFailed || first.Investigation.ModelStatus != domain.ModelCancelled ||
		first.Investigation.FailureCode != request.FailureCode || first.Investigation.CompletedAt.IsZero() ||
		!replay.Replayed || replay.Investigation != first.Investigation {
		t.Fatalf("FailInvestigation results = %#v / %#v", first, replay)
	}
	conflict := request
	conflict.FailureCode = "different_failure"
	if _, err := repository.FailInvestigation(context.Background(), conflict); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("FailInvestigation(conflict) error = %v, want ErrIdempotencyConflict", err)
	}
	afterTerminal := request
	afterTerminal.IdempotencyKey = "fail:after-terminal"
	if _, err := repository.FailInvestigation(context.Background(), afterTerminal); !errors.Is(err, investigation.ErrInvalidTransition) {
		t.Fatalf("FailInvestigation(after terminal) error = %v, want ErrInvalidTransition", err)
	}
	tasks, err := repository.ListTasks(context.Background(), investigation.ListTasksRequest{
		WorkspaceID: request.WorkspaceID, InvestigationID: request.InvestigationID,
	})
	if err != nil || len(tasks) != len(taskSpecs) {
		t.Fatalf("ListTasks() = %#v, %v", tasks, err)
	}
	for _, task := range tasks {
		if task.Status != domain.ReadTaskCancelled || task.FailureCode != request.FailureCode ||
			task.CompletedAt != first.Investigation.CompletedAt {
			t.Fatalf("failed investigation task = %#v, want atomic cancellation", task)
		}
	}
	second, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:after-fail", Tasks: taskSpecs,
	})
	if err != nil || !second.Created || second.Investigation.ID == created.Investigation.ID {
		t.Fatalf("CreateOrGetInvestigation(after fail) = %#v, %v; want new investigation", second, err)
	}
}

func TestFailInvestigationUsesMonotonicCommitTimeWhenClockMovesBackward(t *testing.T) {
	base := time.Date(2026, 7, 12, 21, 30, 0, 0, time.UTC)
	clockNow := base
	nextID := 0
	repository, err := memory.New(memory.Options{
		Clock: func() time.Time { return clockNow }, TenantResolver: testTenantResolver, TaskSpecAuthorizer: testTaskSpecAuthorizer,
		IDFactory: func() string { nextID++; return fmt.Sprintf("fail-time-%d", nextID) },
	})
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	incident := createIncident(t, repository, "workspace-1", "signal-fail-time", base)
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:fail-time",
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}},
	})
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}
	clockNow = base.Add(-time.Hour)
	failed, err := repository.FailInvestigation(context.Background(), investigation.FailInvestigationRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
		IdempotencyKey: "fail:time", FailureCode: "internal_failure",
	})
	if err != nil {
		t.Fatalf("FailInvestigation(clock rollback) error = %v", err)
	}
	if failed.Investigation.CompletedAt.Before(created.Investigation.UpdatedAt) {
		t.Fatalf("CompletedAt = %s, want >= prior UpdatedAt %s", failed.Investigation.CompletedAt, created.Investigation.UpdatedAt)
	}
	task, err := repository.GetTask(context.Background(), "workspace-1", created.Tasks[0].ID)
	if err != nil || task.CompletedAt != failed.Investigation.CompletedAt {
		t.Fatalf("GetTask() = %#v, %v; want same atomic commit time", task, err)
	}
}

func TestFailInvestigationAllowsRunningAndPreservesTerminalTasks(t *testing.T) {
	now := time.Date(2026, 7, 12, 21, 45, 0, 0, time.UTC)
	repository := newRepository(t, now)
	incident := createIncident(t, repository, "workspace-1", "signal-fail-running", now)
	created, err := repository.CreateOrGetInvestigation(context.Background(), investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: "workspace-1", IncidentID: incident.ID, IdempotencyKey: "investigate:fail-running",
		Tasks: []investigation.TaskSpec{
			{Key: "logs", ConnectorID: "victorialogs-prod", Operation: "search", Input: []byte(`{"lookback_minutes":30}`)},
			{Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`)},
		},
	})
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation() error = %v", err)
	}
	payload := []byte(`{"matches":2}`)
	completed, err := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID, TaskID: created.Tasks[0].ID,
		RunnerID: "runner-1", IdempotencyKey: "complete:fail-running", Status: domain.ReadTaskEvidence,
		Evidence: &investigation.EvidenceInput{Payload: payload, ContentHash: sha256Hex(payload), CollectedAt: now},
	})
	if err != nil {
		t.Fatalf("CompleteTask() error = %v", err)
	}
	if _, err := repository.FailInvestigation(context.Background(), investigation.FailInvestigationRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
		IdempotencyKey: "fail:running", FailureCode: "internal_failure",
	}); err != nil {
		t.Fatalf("FailInvestigation(RUNNING) error = %v", err)
	}
	tasks, err := repository.ListTasks(context.Background(), investigation.ListTasksRequest{
		WorkspaceID: "workspace-1", InvestigationID: created.Investigation.ID,
	})
	if err != nil || len(tasks) != 2 {
		t.Fatalf("ListTasks() = %#v, %v", tasks, err)
	}
	byID := map[string]domain.ReadTask{tasks[0].ID: tasks[0], tasks[1].ID: tasks[1]}
	if task := byID[completed.Task.ID]; task.Status != domain.ReadTaskEvidence || task.EvidenceID != completed.Evidence.ID {
		t.Fatalf("terminal evidence task changed: %#v", task)
	}
	if task := byID[created.Tasks[1].ID]; task.Status != domain.ReadTaskCancelled || task.FailureCode != "internal_failure" {
		t.Fatalf("queued remainder not cancelled: %#v", task)
	}
}
