package memory

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

func TestFinalizeCancellationPreservesRunningTaskStartTime(t *testing.T) {
	createdAt := time.Date(2026, 7, 12, 20, 30, 0, 0, time.UTC)
	commitAt := createdAt.Add(time.Minute)
	repository, err := New(Options{
		TaskRuntimeBinder: testTaskRuntimeBinder,
		Clock:             func() time.Time { return commitAt }, IDFactory: func() string { return "unused" },
		TenantResolver:     func(string) (string, error) { return "tenant-1", nil },
		TaskSpecAuthorizer: allowTaskSpecForTest,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	input := []byte(`{"lookback_minutes":15}`)
	inputDigest := sha256.Sum256(input)
	requestDigest := sha256.Sum256([]byte("request"))
	item := domain.Investigation{
		ID: "investigation-1", WorkspaceID: "workspace-1", IncidentID: "incident-1",
		Status: domain.InvestigationRunning, ModelStatus: domain.ModelRunning,
		IdempotencyKey: "investigate:running", RequestHash: fmt.Sprintf("%x", requestDigest),
		RequestHashVersion: domain.InvestigationCreateRequestVersionV1,
		CreatedAt:          createdAt, StartedAt: createdAt, UpdatedAt: createdAt,
	}
	task := domain.ReadTask{
		ID: "task-1", WorkspaceID: item.WorkspaceID, IncidentID: item.IncidentID, InvestigationID: item.ID,
		Key: "metrics", Position: 1, ConnectorID: "prometheus-prod-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Operation: "range_query",
		Input: input, InputHash: fmt.Sprintf("%x", inputDigest), Status: domain.ReadTaskRunning,
		CreatedAt: createdAt, StartedAt: createdAt, UpdatedAt: createdAt,
	}
	repository.investigations[scoped(item.WorkspaceID, item.ID)] = item
	repository.tasks[scoped(item.WorkspaceID, task.ID)] = task
	repository.taskIDsByInvestigation[scoped(item.WorkspaceID, item.ID)] = []string{task.ID}
	repository.activeInvestigation[scoped(item.WorkspaceID, item.IncidentID)] = item.ID

	result, err := repository.FinalizeInvestigation(context.Background(), investigation.FinalizeInvestigationRequest{
		WorkspaceID: item.WorkspaceID, InvestigationID: item.ID, IdempotencyKey: "finalize:running",
		Status: domain.InvestigationCancelled, ModelStatus: domain.ModelCancelled, FailureCode: "operator_cancelled",
	})
	if err != nil {
		t.Fatalf("FinalizeInvestigation() error = %v", err)
	}
	stored := repository.tasks[scoped(item.WorkspaceID, task.ID)]
	if stored.Status != domain.ReadTaskCancelled || stored.StartedAt != task.StartedAt ||
		stored.CompletedAt != result.Investigation.CompletedAt || stored.UpdatedAt != result.Investigation.CompletedAt {
		t.Fatalf("cancelled running task = %#v, investigation = %#v", stored, result.Investigation)
	}
	if active := repository.activeInvestigation[scoped(item.WorkspaceID, item.IncidentID)]; active != "" {
		t.Fatalf("active investigation = %q, want released", active)
	}
}

func TestCompleteTaskReadsCommitClockAfterLockedPreparation(t *testing.T) {
	createdAt := time.Date(2026, 7, 12, 22, 0, 0, 0, time.UTC)
	commitAt := createdAt.Add(time.Minute)
	clockNow := createdAt
	repository, err := New(Options{
		TaskRuntimeBinder: testTaskRuntimeBinder,
		Clock:             func() time.Time { return clockNow },
		IDFactory: func() string {
			clockNow = commitAt
			return "receipt-1"
		},
		TenantResolver:     func(string) (string, error) { return "tenant-1", nil },
		TaskSpecAuthorizer: allowTaskSpecForTest,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	input := []byte(`{"lookback_minutes":15}`)
	inputDigest := sha256.Sum256(input)
	requestDigest := sha256.Sum256([]byte("request"))
	item := domain.Investigation{
		ID: "investigation-1", WorkspaceID: "workspace-1", IncidentID: "incident-1",
		Status: domain.InvestigationQueued, ModelStatus: domain.ModelPending,
		IdempotencyKey: "investigate:clock-order", RequestHash: fmt.Sprintf("%x", requestDigest),
		RequestHashVersion: domain.InvestigationCreateRequestVersionV1,
		CreatedAt:          createdAt, UpdatedAt: createdAt,
	}
	task := domain.ReadTask{
		ID: "task-1", WorkspaceID: item.WorkspaceID, IncidentID: item.IncidentID, InvestigationID: item.ID,
		Key: "metrics", Position: 1, ConnectorID: "prometheus-prod-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Operation: "range_query",
		Input: input, InputHash: fmt.Sprintf("%x", inputDigest), Status: domain.ReadTaskQueued,
		CreatedAt: createdAt, UpdatedAt: createdAt,
	}
	repository.investigations[scoped(item.WorkspaceID, item.ID)] = item
	repository.tasks[scoped(item.WorkspaceID, task.ID)] = task
	repository.taskIDsByInvestigation[scoped(item.WorkspaceID, item.ID)] = []string{task.ID}

	result, err := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
		WorkspaceID: item.WorkspaceID, InvestigationID: item.ID, TaskID: task.ID, RunnerID: "runner-1",
		IdempotencyKey: "complete:clock-order", Status: domain.ReadTaskFailed, FailureCode: "source_failed",
	})
	if err != nil {
		t.Fatalf("CompleteTask() error = %v", err)
	}
	if result.Task.CompletedAt != commitAt || result.Receipt.ReceivedAt != commitAt {
		t.Fatalf("commit times = task %s receipt %s, want post-preparation %s", result.Task.CompletedAt, result.Receipt.ReceivedAt, commitAt)
	}
}

func allowTaskSpecForTest(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error {
	return nil
}
