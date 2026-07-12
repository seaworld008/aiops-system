package investigationworkflow_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/seaworld008/aiops-system/internal/outbox"
	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestTemporalDevServerRawPrestartCannotMixValidMemoWithDifferentInput(t *testing.T) {
	if os.Getenv("AIOPS_TEMPORAL_INTEGRATION") != "1" {
		t.Skip("set AIOPS_TEMPORAL_INTEGRATION=1 to run the pinned Temporal dev-server contract")
	}
	if version := os.Getenv("AIOPS_TEMPORAL_CLI_VERSION"); version != "1.6.1" {
		t.Fatalf("AIOPS_TEMPORAL_CLI_VERSION = %q, want pinned 1.6.1", version)
	}
	address := os.Getenv("AIOPS_TEMPORAL_ADDRESS")
	if address == "" {
		t.Fatal("AIOPS_TEMPORAL_ADDRESS is required when integration is enabled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	temporalRuntimeClient, err := investigationworkflow.DialTemporalClient(ctx, client.Options{HostPort: address, Namespace: "default"})
	if err != nil {
		t.Fatalf("DialTemporalClient() error = %v", err)
	}
	defer temporalRuntimeClient.Close()
	temporalClient := investigationworkflow.SDKClientForTest(temporalRuntimeClient)
	if temporalClient == nil {
		t.Fatal("DialTemporalClient() returned no sealed SDK client")
	}
	fixture := newActivityFixture(t, "firing")
	runtimeWorker, err := investigationworkflow.NewWorker(
		temporalRuntimeClient, fixture.activities, fixture.input.ManifestDigest, fixture.input.RegistryDigest,
	)
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}
	if err := runtimeWorker.Start(); err != nil {
		t.Fatalf("worker.Start() error = %v", err)
	}
	defer runtimeWorker.Stop()

	workflowID := uuid.NewString()
	inputA := fixture.input
	inputA.OutboxEventID = workflowID
	inputB := inputA
	inputB.SignalID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	memoA, err := investigationworkflow.MemoIdentityValueForTest(inputA)
	if err != nil {
		t.Fatalf("MemoIdentityValueForTest() error = %v", err)
	}
	queue, err := investigationworkflow.TaskQueue(inputA.ManifestDigest, inputA.RegistryDigest)
	if err != nil {
		t.Fatalf("TaskQueue() error = %v", err)
	}
	run, err := temporalClient.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID: workflowID, TaskQueue: queue, WorkflowTaskTimeout: 10 * time.Second,
		WorkflowIDConflictPolicy:                 enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL,
		WorkflowIDReusePolicy:                    enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE,
		WorkflowExecutionErrorWhenAlreadyStarted: true,
		Memo:                                     map[string]interface{}{investigationworkflow.MemoIdentityKey: memoA},
	}, investigationworkflow.WorkflowName, inputB)
	if err != nil {
		t.Fatalf("raw ExecuteWorkflow(mixed identity) error = %v", err)
	}
	if err := run.Get(ctx, nil); err == nil {
		t.Fatal("raw mixed Memo/Input Workflow unexpectedly completed")
	}
	history := readCompleteHistory(t, ctx, temporalClient, workflowID, run.GetRunID())
	for _, event := range history.Events {
		switch event.GetEventType() {
		case enumspb.EVENT_TYPE_ACTIVITY_TASK_SCHEDULED,
			enumspb.EVENT_TYPE_ACTIVITY_TASK_STARTED,
			enumspb.EVENT_TYPE_ACTIVITY_TASK_COMPLETED:
			t.Fatalf("mixed Memo/Input reached Activity boundary: event=%s id=%d", event.GetEventType(), event.GetEventId())
		}
	}
	incidents, err := fixture.repository.ListIncidents(context.Background(), investigation.ListIncidentsRequest{
		WorkspaceID: fixture.input.WorkspaceID,
	})
	if err != nil || len(incidents) != 0 {
		t.Fatalf("mixed Memo/Input Workflow left incidents = %#v, %v", incidents, err)
	}
	starter, err := investigationworkflow.NewStarter(temporalRuntimeClient, inputA.ManifestDigest, inputA.RegistryDigest)
	if err != nil {
		t.Fatalf("NewStarter() error = %v", err)
	}
	outcome, err := starter.Start(ctx, outbox.SignalWorkflowStart{
		Version: 1, WorkflowID: workflowID, OutboxEventID: workflowID,
		TenantID: inputA.TenantID, WorkspaceID: inputA.WorkspaceID, SignalID: inputA.SignalID, AggregateVersion: 1,
	})
	if err == nil || outcome != "" {
		t.Fatalf("Starter ACKed raw mixed Memo/Input Workflow: outcome=%s error=%v", outcome, err)
	}
}

func TestTemporalDevServerPreparationRoundTripHistoryAndReplay(t *testing.T) {
	if os.Getenv("AIOPS_TEMPORAL_INTEGRATION") != "1" {
		t.Skip("set AIOPS_TEMPORAL_INTEGRATION=1 to run the pinned Temporal dev-server contract")
	}
	if version := os.Getenv("AIOPS_TEMPORAL_CLI_VERSION"); version != "1.6.1" {
		t.Fatalf("AIOPS_TEMPORAL_CLI_VERSION = %q, want pinned 1.6.1", version)
	}
	address := os.Getenv("AIOPS_TEMPORAL_ADDRESS")
	if address == "" {
		t.Fatal("AIOPS_TEMPORAL_ADDRESS is required when integration is enabled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	temporalRuntimeClient, err := investigationworkflow.DialTemporalClient(ctx, client.Options{HostPort: address, Namespace: "default"})
	if err != nil {
		t.Fatalf("DialTemporalClient() error = %v", err)
	}
	defer temporalRuntimeClient.Close()
	temporalClient := investigationworkflow.SDKClientForTest(temporalRuntimeClient)
	if temporalClient == nil {
		t.Fatal("DialTemporalClient() returned no sealed SDK client")
	}

	const canary = "temporal-history-secret-canary"
	fixture := newActivityFixtureWithCanary(t, "firing", canary)
	runtimeWorker, err := investigationworkflow.NewWorker(
		temporalRuntimeClient, fixture.activities, fixture.input.ManifestDigest, fixture.input.RegistryDigest,
	)
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}
	if err := runtimeWorker.Start(); err != nil {
		t.Fatalf("worker.Start() error = %v", err)
	}
	defer runtimeWorker.Stop()
	starter, err := investigationworkflow.NewStarter(temporalRuntimeClient, fixture.input.ManifestDigest, fixture.input.RegistryDigest)
	if err != nil {
		t.Fatalf("NewStarter() error = %v", err)
	}
	workflowID := uuid.NewString()
	start := outbox.SignalWorkflowStart{
		Version: 1, WorkflowID: workflowID, OutboxEventID: workflowID,
		TenantID: fixture.input.TenantID, WorkspaceID: fixture.input.WorkspaceID,
		SignalID: fixture.input.SignalID, AggregateVersion: 1,
	}
	first, err := starter.Start(ctx, start)
	if err != nil || first != outbox.StartOutcomeStarted {
		t.Fatalf("Start(first) = %s, %v", first, err)
	}
	// Simulate an ACK response loss: the same outbox event is delivered again.
	duplicate, err := starter.Start(ctx, start)
	if err != nil || duplicate != outbox.StartOutcomeAlreadyExists {
		t.Fatalf("Start(ACK-lost duplicate) = %s, %v", duplicate, err)
	}
	var receipt investigationworkflow.PreparationReceipt
	if err := temporalClient.GetWorkflow(ctx, workflowID, "").Get(ctx, &receipt); err != nil {
		t.Fatalf("GetWorkflow().Get() error = %v", err)
	}
	if receipt.State != investigationworkflow.StatePrepared || receipt.OutboxEventID != workflowID {
		t.Fatalf("workflow receipt = %#v", receipt)
	}
	described, err := temporalClient.DescribeWorkflowExecution(ctx, workflowID, "")
	if err != nil || described.WorkflowExecutionInfo == nil || described.WorkflowExecutionInfo.Execution == nil {
		t.Fatalf("DescribeWorkflowExecution() = %#v, %v", described, err)
	}
	runID := described.WorkflowExecutionInfo.Execution.RunId

	history := readCompleteHistory(t, ctx, temporalClient, workflowID, runID)
	material := strings.ToLower(historyMaterial(t, history))
	for name, digest := range map[string]string{
		"manifest": receipt.ManifestDigest, "registry": receipt.RegistryDigest,
		"profile": receipt.ProfileDigest, "tasks": receipt.TasksHash,
	} {
		if !strings.Contains(material, strings.ToLower(digest)) {
			t.Fatalf("Temporal History is missing %s digest", name)
		}
	}
	for _, forbidden := range []string{
		strings.ToLower(canary), "request_hash", "input_hash", "provider_event_id", "fingerprint", "labels",
		"credential", "password", "secret", "token", "payload_hash",
	} {
		if strings.Contains(material, forbidden) {
			t.Fatalf("Temporal History contains forbidden material %q", forbidden)
		}
	}
	assertOnlyFixedTemporalIdentityFields(t, history)
	replayer, err := worker.NewWorkflowReplayerWithOptions(worker.WorkflowReplayerOptions{DisableRegistrationAliasing: true})
	if err != nil {
		t.Fatalf("NewWorkflowReplayerWithOptions() error = %v", err)
	}
	replayer.RegisterWorkflowWithOptions(investigationworkflow.ProductionPreparationWorkflowForTest, workflow.RegisterOptions{Name: investigationworkflow.WorkflowName})
	if err := replayer.ReplayWorkflowHistoryWithOptions(nil, history, worker.ReplayWorkflowHistoryOptions{
		OriginalExecution: workflow.Execution{ID: workflowID, RunID: runID},
	}); err != nil {
		t.Fatalf("ReplayWorkflowHistory() error = %v", err)
	}
}

func assertOnlyFixedTemporalIdentityFields(t *testing.T, history *historypb.History) {
	t.Helper()
	values := make([]string, 0, 8)
	collectTemporalIdentityFields(history.ProtoReflect(), &values)
	if len(values) == 0 {
		t.Fatal("Temporal History has no explicit identity evidence")
	}
	want := investigationworkflow.TemporalClientIdentityForTest()
	for _, value := range values {
		if value != "" && value != want {
			t.Fatalf("Temporal History contains non-fixed identity %q", value)
		}
	}
}

func collectTemporalIdentityFields(message protoreflect.Message, values *[]string) {
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if !field.IsList() && !field.IsMap() && field.Kind() == protoreflect.StringKind && field.Name() == "identity" {
			*values = append(*values, value.String())
		}
		collectTemporalIdentityValue(field, value, values)
		return true
	})
}

func collectTemporalIdentityValue(field protoreflect.FieldDescriptor, value protoreflect.Value, values *[]string) {
	if field.IsList() {
		list := value.List()
		if field.Kind() == protoreflect.MessageKind || field.Kind() == protoreflect.GroupKind {
			for index := 0; index < list.Len(); index++ {
				collectTemporalIdentityFields(list.Get(index).Message(), values)
			}
		}
		return
	}
	if field.IsMap() {
		if field.MapValue().Kind() == protoreflect.MessageKind || field.MapValue().Kind() == protoreflect.GroupKind {
			value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
				collectTemporalIdentityFields(item.Message(), values)
				return true
			})
		}
		return
	}
	if field.Kind() == protoreflect.MessageKind || field.Kind() == protoreflect.GroupKind {
		collectTemporalIdentityFields(value.Message(), values)
	}
}

func readCompleteHistory(t *testing.T, ctx context.Context, temporalClient client.Client, workflowID, runID string) *historypb.History {
	t.Helper()
	iterator := temporalClient.GetWorkflowHistory(ctx, workflowID, runID, false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	history := &historypb.History{}
	for iterator.HasNext() {
		event, err := iterator.Next()
		if err != nil {
			t.Fatalf("history iterator error = %v", err)
		}
		history.Events = append(history.Events, event)
	}
	if len(history.Events) == 0 {
		t.Fatal("Temporal History is empty")
	}
	return history
}

func historyMaterial(t *testing.T, history *historypb.History) string {
	t.Helper()
	encoded, err := protojson.Marshal(history)
	if err != nil {
		t.Fatalf("protojson.Marshal(history) error = %v", err)
	}
	var material strings.Builder
	material.Write(encoded)
	appendMessageMaterial(&material, history.ProtoReflect())
	return material.String()
}

func appendMessageMaterial(material *strings.Builder, message protoreflect.Message) {
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		appendReflectValue(material, field, value)
		return true
	})
}

func appendReflectValue(material *strings.Builder, field protoreflect.FieldDescriptor, value protoreflect.Value) {
	if field.IsList() {
		list := value.List()
		for index := 0; index < list.Len(); index++ {
			appendScalarMaterial(material, field.Kind(), list.Get(index))
		}
		return
	}
	if field.IsMap() {
		value.Map().Range(func(key protoreflect.MapKey, item protoreflect.Value) bool {
			material.WriteString(fmt.Sprint(key.Interface()))
			appendScalarMaterial(material, field.MapValue().Kind(), item)
			return true
		})
		return
	}
	appendScalarMaterial(material, field.Kind(), value)
}

func appendScalarMaterial(material *strings.Builder, kind protoreflect.Kind, value protoreflect.Value) {
	switch kind {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		appendMessageMaterial(material, value.Message())
	case protoreflect.BytesKind:
		material.Write(value.Bytes())
	case protoreflect.StringKind:
		material.WriteString(value.String())
	}
}
