package investigationworkflow_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigation/memory"
	"github.com/seaworld008/aiops-system/internal/investigationplan"
	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/seaworld008/aiops-system/internal/readconnector"
	"go.temporal.io/sdk/temporal"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	activityEnvironmentID = "88888888-8888-4888-8888-888888888888"
	activityServiceID     = "99999999-9999-4999-8999-999999999999"
	activityIntegrationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

func TestPreparationActivityCreatesAndRevalidatesDurableInvestigationFacts(t *testing.T) {
	fixture := newActivityFixture(t, "firing")
	receipt, err := investigationworkflow.PrepareActivityForTest(fixture.activities, context.Background(), fixture.input)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if receipt.State != investigationworkflow.StatePrepared || receipt.OutboxEventID != fixture.input.OutboxEventID ||
		receipt.TenantID != fixture.input.TenantID || receipt.WorkspaceID != fixture.input.WorkspaceID ||
		receipt.SignalID != fixture.input.SignalID || receipt.IncidentID == "" || receipt.InvestigationID == "" ||
		receipt.TaskCount != 1 || len(receipt.TaskIDs) != 1 || receipt.ManifestDigest != fixture.input.ManifestDigest ||
		receipt.RegistryDigest != fixture.input.RegistryDigest || receipt.ProfileDigest == "" || receipt.TasksHash == "" {
		t.Fatalf("Prepare() receipt = %#v", receipt)
	}
	replay, err := investigationworkflow.PrepareActivityForTest(fixture.activities, context.Background(), fixture.input)
	if err != nil || !reflect.DeepEqual(replay, receipt) {
		t.Fatalf("Prepare(replay) = %#v, %v; want %#v", replay, err, receipt)
	}
	tasks, err := fixture.repository.ListTasks(context.Background(), investigation.ListTasksRequest{
		WorkspaceID: receipt.WorkspaceID, InvestigationID: receipt.InvestigationID,
	})
	if err != nil || len(tasks) != 1 || tasks[0].ID != receipt.TaskIDs[0] || tasks[0].Position != 1 {
		t.Fatalf("persisted tasks = %#v, %v", tasks, err)
	}
}

func TestPreparationActivityReturnsNoActiveIncidentForResolvedSignal(t *testing.T) {
	fixture := newActivityFixture(t, "resolved")
	receipt, err := investigationworkflow.PrepareActivityForTest(fixture.activities, context.Background(), fixture.input)
	if err != nil || receipt.State != investigationworkflow.StateNoActiveIncident || receipt.IncidentID != "" ||
		receipt.InvestigationID != "" || receipt.TaskCount != 0 || len(receipt.TaskIDs) != 0 ||
		receipt.ProfileDigest == "" || receipt.TasksHash == "" {
		t.Fatalf("Prepare(resolved) = %#v, %v", receipt, err)
	}
}

func TestPreparationActivityInjectsSignalSnapshotFenceOutsideHistoryDTOs(t *testing.T) {
	fixture := newActivityFixture(t, "firing")
	repository := &projectionRepository{Repository: fixture.repository}
	activities, err := investigationworkflow.NewActivities(fixture.repository, repository, fixture.authority, fixture.planner)
	if err != nil {
		t.Fatalf("NewActivities() error = %v", err)
	}
	if _, err := investigationworkflow.PrepareActivityForTest(activities, context.Background(), fixture.input); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if !domain.ValidSHA256Hex(repository.expectedSignalHash) {
		t.Fatalf("Activity correlation snapshot hash = %q", repository.expectedSignalHash)
	}
	encodedInput, _ := json.Marshal(fixture.input)
	encodedReceipt, _ := json.Marshal(validReceipt())
	if bytes.Contains(encodedInput, []byte(repository.expectedSignalHash)) || bytes.Contains(encodedReceipt, []byte(repository.expectedSignalHash)) {
		t.Fatalf("signal snapshot fence entered History DTO")
	}
}

func TestPreparationActivityTenantBoundSnapshotPreventsMiswiredRepositoryWrites(t *testing.T) {
	fixture := newActivityFixture(t, "firing")
	signal, err := fixture.repository.GetSignal(context.Background(), fixture.input.WorkspaceID, fixture.input.SignalID)
	if err != nil {
		t.Fatalf("GetSignal() error = %v", err)
	}
	repository, err := memory.New(memory.Options{
		Clock:              func() time.Time { return time.Date(2026, 7, 12, 4, 0, 0, 0, time.UTC) },
		IDFactory:          func() string { return "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" },
		TenantResolver:     func(string) (string, error) { return "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", nil },
		TaskSpecAuthorizer: func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error { return nil },
	})
	if err != nil {
		t.Fatalf("memory.New(miswired tenant) error = %v", err)
	}
	if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
		t.Fatalf("RegisterSignal(miswired tenant) error = %v", err)
	}
	activities, err := investigationworkflow.NewActivities(
		fixture.repository, repository, fixture.authority, fixture.planner,
	)
	if err != nil {
		t.Fatalf("NewActivities(miswired repository) error = %v", err)
	}
	_, err = investigationworkflow.PrepareActivityForTest(activities, context.Background(), fixture.input)
	var applicationError *temporal.ApplicationError
	if !errors.As(err, &applicationError) || applicationError.Type() != "PREPARE_FACT_CONFLICT" {
		t.Fatalf("Prepare(miswired tenant) error = %v", err)
	}
	incidents, listErr := repository.ListIncidents(context.Background(), investigation.ListIncidentsRequest{
		WorkspaceID: fixture.input.WorkspaceID,
	})
	if listErr != nil || len(incidents) != 0 {
		t.Fatalf("miswired repository left incidents = %#v, %v", incidents, listErr)
	}
}

func TestPreparationActivityIsConcurrentReplaySafe(t *testing.T) {
	fixture := newActivityFixture(t, "firing")
	const goroutines = 12
	results := make(chan investigationworkflow.PreparationReceipt, goroutines)
	errorsFound := make(chan error, goroutines)
	var wait sync.WaitGroup
	for index := 0; index < goroutines; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			receipt, err := investigationworkflow.PrepareActivityForTest(fixture.activities, context.Background(), fixture.input)
			if err != nil {
				errorsFound <- err
				return
			}
			results <- receipt
		}()
	}
	wait.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		t.Fatalf("concurrent Prepare() error = %v", err)
	}
	var first investigationworkflow.PreparationReceipt
	for receipt := range results {
		if first.InvestigationID == "" {
			first = receipt
			continue
		}
		if receipt.InvestigationID != first.InvestigationID || !reflect.DeepEqual(receipt.TaskIDs, first.TaskIDs) {
			t.Fatalf("concurrent receipts diverged: %#v / %#v", first, receipt)
		}
	}
}

func TestPreparationActivityAllowsMutableProjectionProgressAndTerminalIncidentReplay(t *testing.T) {
	fixture := newActivityFixture(t, "firing")
	repository := &projectionRepository{Repository: fixture.repository, advance: true, terminalIncident: true}
	activities, err := investigationworkflow.NewActivities(fixture.repository, repository, fixture.authority, fixture.planner)
	if err != nil {
		t.Fatalf("NewActivities() error = %v", err)
	}
	receipt, err := investigationworkflow.PrepareActivityForTest(activities, context.Background(), fixture.input)
	if err != nil || receipt.State != investigationworkflow.StatePrepared {
		t.Fatalf("Prepare(progressed projection) = %#v, %v", receipt, err)
	}
}

func TestPreparationActivityAllowsValidTerminalAndPartialProjectionProgress(t *testing.T) {
	tests := map[string]projectionMutation{
		"completed with evidence": {
			investigation: func(item *domain.Investigation) {
				item.Status = domain.InvestigationCompleted
				item.ModelStatus = domain.ModelCompleted
				item.StartedAt, item.CompletedAt, item.UpdatedAt = item.CreatedAt, item.CreatedAt, item.CreatedAt
			},
			tasks: func(tasks []domain.ReadTask) {
				tasks[0].Status = domain.ReadTaskEvidence
				tasks[0].EvidenceID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
				tasks[0].StartedAt, tasks[0].CompletedAt, tasks[0].UpdatedAt = tasks[0].CreatedAt, tasks[0].CreatedAt, tasks[0].CreatedAt
			},
		},
		"partial with failed task": {
			investigation: func(item *domain.Investigation) {
				item.Status = domain.InvestigationPartial
				item.ModelStatus = domain.ModelFailed
				item.ModelFailureCode = "model_unavailable"
				item.StartedAt, item.CompletedAt, item.UpdatedAt = item.CreatedAt, item.CreatedAt, item.CreatedAt
			},
			tasks: func(tasks []domain.ReadTask) {
				tasks[0].Status = domain.ReadTaskFailed
				tasks[0].FailureCode = "connector_unavailable"
				tasks[0].StartedAt, tasks[0].CompletedAt, tasks[0].UpdatedAt = tasks[0].CreatedAt, tasks[0].CreatedAt, tasks[0].CreatedAt
			},
		},
		"failed with cancelled task": {
			investigation: func(item *domain.Investigation) {
				item.Status = domain.InvestigationFailed
				item.ModelStatus = domain.ModelCancelled
				item.FailureCode = "dependency_failed"
				item.StartedAt, item.CompletedAt, item.UpdatedAt = item.CreatedAt, item.CreatedAt, item.CreatedAt
			},
			tasks: func(tasks []domain.ReadTask) {
				tasks[0].Status = domain.ReadTaskCancelled
				tasks[0].FailureCode = "investigation_failed"
				tasks[0].StartedAt, tasks[0].CompletedAt, tasks[0].UpdatedAt = tasks[0].CreatedAt, tasks[0].CreatedAt, tasks[0].CreatedAt
			},
		},
		"cancelled with cancelled task": {
			investigation: func(item *domain.Investigation) {
				item.Status = domain.InvestigationCancelled
				item.ModelStatus = domain.ModelCancelled
				item.FailureCode = "operator_cancelled"
				item.StartedAt, item.CompletedAt, item.UpdatedAt = item.CreatedAt, item.CreatedAt, item.CreatedAt
			},
			tasks: func(tasks []domain.ReadTask) {
				tasks[0].Status = domain.ReadTaskCancelled
				tasks[0].FailureCode = "investigation_cancelled"
				tasks[0].StartedAt, tasks[0].CompletedAt, tasks[0].UpdatedAt = tasks[0].CreatedAt, tasks[0].CreatedAt, tasks[0].CreatedAt
			},
		},
	}
	for name, mutation := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newActivityFixture(t, "firing")
			repository := &projectionRepository{Repository: fixture.repository, mutation: mutation}
			activities, err := investigationworkflow.NewActivities(fixture.repository, repository, fixture.authority, fixture.planner)
			if err != nil {
				t.Fatalf("NewActivities() error = %v", err)
			}
			receipt, err := investigationworkflow.PrepareActivityForTest(activities, context.Background(), fixture.input)
			if err != nil || receipt.State != investigationworkflow.StatePrepared {
				t.Fatalf("Prepare(%s projection) = %#v, %v", name, receipt, err)
			}
		})
	}
}

func TestPreparationActivityAllowsDifferentSignalKeyToBindSameActiveInvestigation(t *testing.T) {
	fixture := newActivityFixture(t, "firing")
	first, err := investigationworkflow.PrepareActivityForTest(fixture.activities, context.Background(), fixture.input)
	if err != nil {
		t.Fatalf("Prepare(first) error = %v", err)
	}
	secondSignalID := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	secondOutboxID := "ffffffff-ffff-4fff-8fff-ffffffffffff"
	second := domain.Signal{
		ID: secondSignalID, WorkspaceID: workflowWorkspace, IntegrationID: activityIntegrationID,
		Provider: "alertmanager", ProviderEventID: "event-prepare-2", PayloadHash: strings.Repeat("1", 64),
		Fingerprint: "payments-staging", Status: "firing", Labels: map[string]string{"service": "payments"},
		ObservedAt: time.Date(2026, 7, 12, 4, 1, 0, 0, time.UTC),
	}
	if _, err := fixture.repository.RegisterSignal(context.Background(), second); err != nil {
		t.Fatalf("RegisterSignal(second) error = %v", err)
	}
	input := fixture.input
	input.OutboxEventID = secondOutboxID
	input.SignalID = secondSignalID
	bound, err := investigationworkflow.PrepareActivityForTest(fixture.activities, context.Background(), input)
	if err != nil || bound.InvestigationID != first.InvestigationID || !reflect.DeepEqual(bound.TaskIDs, first.TaskIDs) {
		t.Fatalf("Prepare(second signal binding) = %#v, %v; first=%#v", bound, err, first)
	}
}

func TestPreparationActivityRejectsImmutableProjectionDrift(t *testing.T) {
	mutations := map[string]projectionMutation{
		"incident id":                {incident: func(item *domain.Incident) { item.ID = workflowSignalID }},
		"investigation workspace":    {investigation: func(item *domain.Investigation) { item.WorkspaceID = workflowTenantID }},
		"investigation incident":     {investigation: func(item *domain.Investigation) { item.IncidentID = workflowSignalID }},
		"investigation request hash": {investigation: func(item *domain.Investigation) { item.RequestHash = strings.Repeat("e", 64) }},
		"task id":                    {tasks: func(tasks []domain.ReadTask) { tasks[0].ID = workflowSignalID }},
		"task parent":                {tasks: func(tasks []domain.ReadTask) { tasks[0].InvestigationID = workflowIncidentID }},
		"task incident":              {tasks: func(tasks []domain.ReadTask) { tasks[0].IncidentID = workflowSignalID }},
		"task workspace":             {tasks: func(tasks []domain.ReadTask) { tasks[0].WorkspaceID = workflowTenantID }},
		"task position":              {tasks: func(tasks []domain.ReadTask) { tasks[0].Position = 2 }},
		"task key":                   {tasks: func(tasks []domain.ReadTask) { tasks[0].Key = "logs" }},
		"task operation":             {tasks: func(tasks []domain.ReadTask) { tasks[0].Operation = "search" }},
		"task input":                 {tasks: func(tasks []domain.ReadTask) { tasks[0].Input = []byte(`{"lookback_minutes":30}`) }},
		"task input hash":            {tasks: func(tasks []domain.ReadTask) { tasks[0].InputHash = strings.Repeat("e", 64) }},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			fixture := newActivityFixture(t, "firing")
			repository := &projectionRepository{Repository: fixture.repository, mutation: mutate}
			activities, err := investigationworkflow.NewActivities(fixture.repository, repository, fixture.authority, fixture.planner)
			if err != nil {
				t.Fatalf("NewActivities() error = %v", err)
			}
			_, err = investigationworkflow.PrepareActivityForTest(activities, context.Background(), fixture.input)
			var applicationError *temporal.ApplicationError
			if !errors.As(err, &applicationError) || applicationError.Type() != "PREPARE_FACT_CONFLICT" {
				t.Fatalf("Prepare(%s drift) error = %v", name, err)
			}
		})
	}
}

func TestPreparationActivityMapsDependencyPanicWithoutCanary(t *testing.T) {
	const canary = "dependency-panic-secret-canary"
	fixture := newActivityFixture(t, "firing")
	activities, err := investigationworkflow.NewActivities(
		panicRegistrationReader{value: canary}, fixture.repository, fixture.authority, fixture.planner,
	)
	if err != nil {
		t.Fatalf("NewActivities() error = %v", err)
	}
	_, err = investigationworkflow.PrepareActivityForTest(activities, context.Background(), fixture.input)
	var applicationError *temporal.ApplicationError
	if !errors.As(err, &applicationError) || applicationError.Type() != "PREPARE_DEPENDENCY_UNAVAILABLE" ||
		strings.Contains(fmt.Sprintf("%+v", err), canary) {
		t.Fatalf("Prepare(panic) error = %+v", err)
	}
	failure := temporal.GetDefaultFailureConverter().ErrorToFailure(err)
	encoded, marshalErr := protojson.Marshal(failure)
	if marshalErr != nil || strings.Contains(string(encoded), canary) {
		t.Fatalf("panic failure history payload leaked canary: %s, %v", encoded, marshalErr)
	}
}

func TestNewActivitiesRejectsAuthorityNotBoundToPlanner(t *testing.T) {
	fixture := newActivityFixture(t, "firing")
	if activities, err := investigationworkflow.NewActivities(
		fixture.repository, fixture.repository, investigationplan.NewScopeAuthority(), fixture.planner,
	); activities != nil || !errors.Is(err, investigationworkflow.ErrInvalidInput) {
		t.Fatalf("NewActivities(foreign authority) = %#v, %v", activities, err)
	}
}

func TestPreparationActivityRejectsWorkflowScopeAndDigestSubstitutionBeforeWrites(t *testing.T) {
	for name, mutate := range map[string]func(*investigationworkflow.WorkflowInput){
		"tenant":    func(input *investigationworkflow.WorkflowInput) { input.TenantID = workflowWorkspace },
		"workspace": func(input *investigationworkflow.WorkflowInput) { input.WorkspaceID = workflowTenantID },
		"signal":    func(input *investigationworkflow.WorkflowInput) { input.SignalID = workflowIncidentID },
		"manifest":  func(input *investigationworkflow.WorkflowInput) { input.ManifestDigest = strings.Repeat("e", 64) },
		"registry":  func(input *investigationworkflow.WorkflowInput) { input.RegistryDigest = strings.Repeat("e", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newActivityFixture(t, "firing")
			input := fixture.input
			mutate(&input)
			_, err := investigationworkflow.PrepareActivityForTest(fixture.activities, context.Background(), input)
			var applicationError *temporal.ApplicationError
			if !errors.As(err, &applicationError) || applicationError.Type() == "PREPARE_DEPENDENCY_UNAVAILABLE" {
				t.Fatalf("Prepare(substitution) error = %v", err)
			}
			incidents, listErr := fixture.repository.ListIncidents(context.Background(), investigation.ListIncidentsRequest{WorkspaceID: fixture.input.WorkspaceID})
			if listErr != nil || len(incidents) != 0 {
				t.Fatalf("substitution left incident facts = %#v, %v", incidents, listErr)
			}
		})
	}
}

type activityFixture struct {
	activities *investigationworkflow.Activities
	repository *memory.Repository
	authority  *investigationplan.ScopeAuthority
	planner    *investigationplan.Planner
	input      investigationworkflow.WorkflowInput
}

func newActivityFixture(t *testing.T, status string) activityFixture {
	return newActivityFixtureWithCanary(t, status, "")
}

func newActivityFixtureWithCanary(t *testing.T, status, canary string) activityFixture {
	t.Helper()
	now := time.Date(2026, 7, 12, 4, 0, 0, 0, time.UTC)
	registry, connectorID := activityRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	planner, err := investigationplan.New(context.Background(), authority, registry, investigationplan.Definition{
		RegistryDigest: registry.Digest(),
		Profiles: []investigationplan.ProfileDefinition{{
			Scope: investigationplan.Scope{TenantID: workflowTenantID, WorkspaceID: workflowWorkspace, EnvironmentID: activityEnvironmentID, ServiceID: activityServiceID},
			Match: investigationplan.MatchDefinition{IntegrationID: activityIntegrationID, Provider: "alertmanager", Labels: []investigationplan.LabelMatch{{Key: "service", Value: "payments"}}},
			Tasks: []investigationplan.TaskDefinition{{Key: "metrics", ConnectorID: connectorID, Operation: readconnector.OperationPrometheusRangeQuery, Input: []byte(`{"lookback_minutes":15}`)}},
		}},
	})
	if err != nil {
		t.Fatalf("investigationplan.New() error = %v", err)
	}
	ids := []string{workflowIncidentID, workflowInvestigationID, workflowTaskID}
	var idMu sync.Mutex
	nextID := 0
	repository, err := memory.New(memory.Options{
		Clock: func() time.Time { return now },
		IDFactory: func() string {
			idMu.Lock()
			defer idMu.Unlock()
			if nextID >= len(ids) {
				return "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
			}
			id := ids[nextID]
			nextID++
			return id
		},
		TenantResolver: func(workspaceID string) (string, error) {
			if workspaceID != workflowWorkspace {
				return "", errors.New("unknown workspace")
			}
			return workflowTenantID, nil
		},
		TaskSpecAuthorizer: registry.AuthorizeTaskSpec,
	})
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	labels := map[string]string{"service": "payments"}
	providerEventID := "event-prepare"
	fingerprint := "payments-staging"
	if canary != "" {
		labels["history_canary"] = canary
		providerEventID = canary
		fingerprint = canary
	}
	signal := domain.Signal{
		ID: workflowSignalID, WorkspaceID: workflowWorkspace, IntegrationID: activityIntegrationID,
		Provider: "alertmanager", ProviderEventID: providerEventID, PayloadHash: strings.Repeat("f", 64),
		Fingerprint: fingerprint, Status: status, Labels: labels, ObservedAt: now,
	}
	if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
		t.Fatalf("RegisterSignal() error = %v", err)
	}
	activities, err := investigationworkflow.NewActivities(repository, repository, authority, planner)
	if err != nil {
		t.Fatalf("NewActivities() error = %v", err)
	}
	return activityFixture{
		activities: activities, repository: repository, authority: authority, planner: planner,
		input: investigationworkflow.WorkflowInput{
			Version: investigationworkflow.SchemaVersion, OutboxEventID: workflowOutboxID,
			TenantID: workflowTenantID, WorkspaceID: workflowWorkspace, SignalID: workflowSignalID,
			AggregateVersion: 1, ManifestDigest: planner.ManifestDigest(), RegistryDigest: registry.Digest(),
		},
	}
}

func activityRegistry(t *testing.T) (*readconnector.Registry, string) {
	t.Helper()
	definition := readconnector.Definition{
		Scope:                readconnector.Scope{TenantID: workflowTenantID, WorkspaceID: workflowWorkspace, EnvironmentID: activityEnvironmentID, ServiceID: activityServiceID},
		TargetRef:            "prometheus-staging-v1-" + strings.Repeat("1", 64),
		PrometheusRangeQuery: &readconnector.PrometheusRangeQueryV1{Expression: "up", StepSeconds: 30, MaxLookbackMinutes: 60, MaxItems: 100, MaxSamples: 121},
	}
	connectorID, err := readconnector.BuildConnectorID("prometheus-staging", definition)
	if err != nil {
		t.Fatalf("BuildConnectorID() error = %v", err)
	}
	definition.ConnectorID = connectorID
	registry, err := readconnector.New([]readconnector.Definition{definition})
	if err != nil {
		t.Fatalf("readconnector.New() error = %v", err)
	}
	return registry, connectorID
}

type panicRegistrationReader struct{ value string }

func (reader panicRegistrationReader) GetRegisteredSignal(context.Context, string) (investigation.RegisteredSignal, error) {
	panic(reader.value)
}

type projectionRepository struct {
	investigation.Repository
	mutation           projectionMutation
	advance            bool
	terminalIncident   bool
	expectedSignalHash string
}

type projectionMutation struct {
	incident      func(*domain.Incident)
	investigation func(*domain.Investigation)
	tasks         func([]domain.ReadTask)
}

func (repository *projectionRepository) CorrelateSignal(ctx context.Context, request investigation.CorrelateSignalRequest) (investigation.CorrelateSignalResult, error) {
	repository.expectedSignalHash = request.ExpectedSignalHash
	return repository.Repository.CorrelateSignal(ctx, request)
}

func (repository *projectionRepository) GetIncident(ctx context.Context, workspaceID, incidentID string) (domain.Incident, error) {
	item, err := repository.Repository.GetIncident(ctx, workspaceID, incidentID)
	if err == nil && repository.terminalIncident {
		item.Status = domain.IncidentResolved
	}
	if err == nil && repository.mutation.incident != nil {
		repository.mutation.incident(&item)
	}
	return item, err
}

func (repository *projectionRepository) GetInvestigation(ctx context.Context, workspaceID, investigationID string) (domain.Investigation, error) {
	item, err := repository.Repository.GetInvestigation(ctx, workspaceID, investigationID)
	if err != nil {
		return item, err
	}
	if repository.advance && item.Status == domain.InvestigationQueued {
		item.Status = domain.InvestigationRunning
		item.StartedAt = item.CreatedAt
	}
	if repository.mutation.investigation != nil {
		repository.mutation.investigation(&item)
	}
	return item, nil
}

func (repository *projectionRepository) ListTasks(ctx context.Context, request investigation.ListTasksRequest) ([]domain.ReadTask, error) {
	tasks, err := repository.Repository.ListTasks(ctx, request)
	if err != nil {
		return nil, err
	}
	if repository.advance {
		for index := range tasks {
			if tasks[index].Status == domain.ReadTaskQueued {
				tasks[index].Status = domain.ReadTaskRunning
				tasks[index].StartedAt = tasks[index].CreatedAt
			}
		}
	}
	if repository.mutation.tasks != nil {
		repository.mutation.tasks(tasks)
	}
	return tasks, nil
}
