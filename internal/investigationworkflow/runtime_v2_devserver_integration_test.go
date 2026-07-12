package investigationworkflow_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/seaworld008/aiops-system/internal/outbox"
	"github.com/seaworld008/aiops-system/internal/readtask"
	enumspb "go.temporal.io/api/enums/v1"
	workflowservicepb "go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestTemporalDevServerRuntimeV2RoleSeparatedStarterAndControlWorker(t *testing.T) {
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
	inspectionClient, err := client.DialContext(ctx, client.Options{
		HostPort: address, Namespace: "default", Identity: "aiops-investigation-read-v2-inspection-test",
	})
	if err != nil {
		t.Fatalf("inspection client DialContext() error = %v", err)
	}
	defer inspectionClient.Close()
	assertTemporalDevServerRuntimeV2Identity(t, ctx, inspectionClient)
	starterClient, controlClient, err := investigationworkflow.DialRuntimeV2PlaintextRolesForTest(
		ctx, address, "default",
	)
	if err != nil {
		t.Fatalf("DialRuntimeV2PlaintextRolesForTest() error = %v", err)
	}
	defer starterClient.Close()
	defer controlClient.Close()

	fixture := newActivityFixtureWithCanary(t, "resolved", "runtime-v2-role-history-secret-canary")
	input := investigationworkflow.WorkflowInputV2{
		Version:       investigationworkflow.RuntimeV2SchemaVersion,
		OutboxEventID: uuid.NewString(),
		TenantID:      fixture.input.TenantID, WorkspaceID: fixture.input.WorkspaceID,
		SignalID: fixture.input.SignalID, AggregateVersion: fixture.input.AggregateVersion,
		ManifestDigest: fixture.input.ManifestDigest, RegistryDigest: fixture.input.RegistryDigest,
		BundleDigest: strings.Repeat("6", 64),
	}
	recovery, err := investigationworkflow.NewRecoveryActivities(recoveryReaderFunc(func(
		context.Context,
		readtask.RecoveryRequest,
	) (readtask.RecoveryResult, error) {
		return readtask.RecoveryResult{}, errors.New("recovery must not run for a resolved signal")
	}))
	if err != nil {
		t.Fatalf("NewRecoveryActivities() error = %v", err)
	}
	runtimeActivities, err := investigationworkflow.NewRuntimeV2Activities(
		fixture.activities, recovery, input.BundleDigest, "default",
	)
	if err != nil {
		t.Fatalf("NewRuntimeV2Activities() error = %v", err)
	}
	controlWorker, err := investigationworkflow.NewRuntimeV2ControlWorkerForTest(
		controlClient, runtimeActivities, input.ManifestDigest, input.RegistryDigest, input.BundleDigest,
	)
	if err != nil {
		t.Fatalf("NewRuntimeV2ControlWorker() error = %v", err)
	}
	if err := controlWorker.Start(); err != nil {
		t.Fatalf("control Worker Start() error = %v", err)
	}
	defer controlWorker.Stop()
	starter, err := investigationworkflow.NewRuntimeV2StarterForTest(
		starterClient, input.ManifestDigest, input.RegistryDigest, input.BundleDigest,
	)
	if err != nil {
		t.Fatalf("NewRuntimeV2Starter() error = %v", err)
	}
	start := outbox.SignalWorkflowStart{
		Version: 1, WorkflowID: input.OutboxEventID, OutboxEventID: input.OutboxEventID,
		TenantID: input.TenantID, WorkspaceID: input.WorkspaceID, SignalID: input.SignalID,
		AggregateVersion: input.AggregateVersion,
	}
	if outcome, startErr := starter.Start(ctx, start); startErr != nil || outcome != outbox.StartOutcomeStarted {
		t.Fatalf("RuntimeV2Starter.Start() = %q, %v", outcome, startErr)
	}
	run := inspectionClient.GetWorkflow(ctx, input.OutboxEventID, "")
	var result investigationworkflow.WorkflowResultV2
	if err := run.Get(ctx, &result); err != nil || result.ValidateAgainst(input) != nil ||
		result.State != investigationworkflow.RuntimeStateNoActiveIncident {
		t.Fatalf("role-separated Workflow result = %#v, %v", result, err)
	}
	if outcome, startErr := starter.Start(ctx, start); startErr != nil || outcome != outbox.StartOutcomeAlreadyExists {
		t.Fatalf("RuntimeV2Starter.Start(ACK-lost duplicate) = %q, %v", outcome, startErr)
	}
	described, err := inspectionClient.DescribeWorkflowExecution(ctx, input.OutboxEventID, "")
	if err != nil || described.GetWorkflowExecutionInfo().GetExecution().GetRunId() == "" {
		t.Fatalf("DescribeWorkflowExecution() = %#v, %v", described, err)
	}
	runID := described.GetWorkflowExecutionInfo().GetExecution().GetRunId()
	history := readCompleteHistory(t, ctx, inspectionClient, input.OutboxEventID, runID)
	material := historyMaterial(t, history)
	for _, identity := range []string{
		"aiops-investigation-read-v2-starter",
		"aiops-investigation-read-v2-control",
	} {
		if !strings.Contains(material, identity) {
			t.Fatalf("role-separated Temporal History is missing fixed identity %q", identity)
		}
	}
	if strings.Contains(material, "runtime-v2-role-history-secret-canary") {
		t.Fatal("role-separated Temporal History contains the Signal canary")
	}
	strictReplayer, err := investigationworkflow.NewRuntimeV2WorkflowReplayerForTest()
	if err != nil {
		t.Fatalf("NewRuntimeV2WorkflowReplayerForTest() error = %v", err)
	}
	strictReplayer.RegisterWorkflowWithOptions(
		investigationworkflow.ProductionReadWorkflowV2ForTest,
		workflow.RegisterOptions{Name: investigationworkflow.WorkflowNameV2},
	)
	if err := strictReplayer.ReplayWorkflowExecution(
		ctx,
		inspectionClient.WorkflowService(),
		nil,
		"default",
		workflow.Execution{ID: input.OutboxEventID, RunID: runID},
	); err != nil {
		t.Fatalf("strict role-separated ReplayWorkflowExecution() error = %v", err)
	}

	const failureCanary = "runtime-v2-failure-details-secret-canary"
	failedPreparation, err := investigationworkflow.NewActivities(
		runtimeV2RejectingSignalReader{canary: failureCanary},
		fixture.repository,
		fixture.authority,
		fixture.planner,
	)
	if err != nil {
		t.Fatalf("NewActivities(rejecting reader) error = %v", err)
	}
	failedInput := input
	failedInput.OutboxEventID = uuid.NewString()
	failedInput.BundleDigest = strings.Repeat("7", 64)
	failedRuntimeActivities, err := investigationworkflow.NewRuntimeV2Activities(
		failedPreparation, recovery, failedInput.BundleDigest, "default",
	)
	if err != nil {
		t.Fatalf("NewRuntimeV2Activities(rejecting reader) error = %v", err)
	}
	failedControlWorker, err := investigationworkflow.NewRuntimeV2ControlWorkerForTest(
		controlClient,
		failedRuntimeActivities,
		failedInput.ManifestDigest,
		failedInput.RegistryDigest,
		failedInput.BundleDigest,
	)
	if err != nil {
		t.Fatalf("NewRuntimeV2ControlWorker(rejecting reader) error = %v", err)
	}
	if err := failedControlWorker.Start(); err != nil {
		t.Fatalf("rejecting control Worker Start() error = %v", err)
	}
	defer failedControlWorker.Stop()
	failedStarter, err := investigationworkflow.NewRuntimeV2StarterForTest(
		starterClient, failedInput.ManifestDigest, failedInput.RegistryDigest, failedInput.BundleDigest,
	)
	if err != nil {
		t.Fatalf("NewRuntimeV2Starter(rejecting reader) error = %v", err)
	}
	failedStart := start
	failedStart.WorkflowID = failedInput.OutboxEventID
	failedStart.OutboxEventID = failedInput.OutboxEventID
	if outcome, startErr := failedStarter.Start(ctx, failedStart); startErr != nil ||
		outcome != outbox.StartOutcomeStarted {
		t.Fatalf("RuntimeV2Starter.Start(rejecting reader) = %q, %v", outcome, startErr)
	}
	failedRun := inspectionClient.GetWorkflow(ctx, failedInput.OutboxEventID, "")
	var failedResult investigationworkflow.WorkflowResultV2
	if failure := failedRun.Get(ctx, &failedResult); failure == nil {
		t.Fatalf("rejecting role-separated Workflow unexpectedly succeeded: %#v", failedResult)
	}
	failedDescription, err := inspectionClient.DescribeWorkflowExecution(ctx, failedInput.OutboxEventID, "")
	if err != nil || failedDescription.GetWorkflowExecutionInfo().GetExecution().GetRunId() == "" {
		t.Fatalf("DescribeWorkflowExecution(rejecting reader) = %#v, %v", failedDescription, err)
	}
	failedHistory := readCompleteHistory(
		t,
		ctx,
		inspectionClient,
		failedInput.OutboxEventID,
		failedDescription.GetWorkflowExecutionInfo().GetExecution().GetRunId(),
	)
	failedMaterial := historyMaterial(t, failedHistory)
	if !strings.Contains(failedMaterial, "PREPARE_FACT_CONFLICT") ||
		strings.Contains(failedMaterial, failureCanary) {
		t.Fatalf("strict converter failure History violated low-sensitive contract")
	}
	if err := strictReplayer.ReplayWorkflowExecution(
		ctx,
		inspectionClient.WorkflowService(),
		nil,
		"default",
		workflow.Execution{
			ID:    failedInput.OutboxEventID,
			RunID: failedDescription.GetWorkflowExecutionInfo().GetExecution().GetRunId(),
		},
	); err != nil {
		t.Fatalf("strict failed-history ReplayWorkflowExecution() error = %v", err)
	}
}

func assertTemporalDevServerRuntimeV2Identity(
	t *testing.T,
	ctx context.Context,
	temporalClient client.Client,
) {
	t.Helper()
	cluster, err := temporalClient.WorkflowService().GetClusterInfo(
		ctx, &workflowservicepb.GetClusterInfoRequest{},
	)
	if err != nil || cluster == nil || cluster.GetClusterName() == "" {
		t.Fatalf("GetClusterInfo() = %#v, %v", cluster, err)
	}
	clusterID, err := uuid.Parse(cluster.GetClusterId())
	if err != nil || clusterID == uuid.Nil || clusterID.String() != cluster.GetClusterId() {
		t.Fatalf("Temporal cluster ID is not a canonical non-zero UUID")
	}
	described, err := temporalClient.WorkflowService().DescribeNamespace(
		ctx,
		&workflowservicepb.DescribeNamespaceRequest{Namespace: "default", WeakConsistency: false},
	)
	if err != nil || described == nil || described.GetNamespaceInfo() == nil ||
		described.GetNamespaceInfo().GetName() != "default" ||
		described.GetNamespaceInfo().GetState() != enumspb.NAMESPACE_STATE_REGISTERED {
		t.Fatalf("DescribeNamespace(default) = %#v, %v", described, err)
	}
	namespaceID, err := uuid.Parse(described.GetNamespaceInfo().GetId())
	if err != nil || namespaceID == uuid.Nil || namespaceID.String() != described.GetNamespaceInfo().GetId() {
		t.Fatalf("Temporal namespace ID is not a canonical non-zero UUID")
	}
}

type runtimeV2RejectingSignalReader struct{ canary string }

func (reader runtimeV2RejectingSignalReader) GetRegisteredSignal(
	context.Context,
	string,
) (investigation.RegisteredSignal, error) {
	return investigation.RegisteredSignal{}, errors.Join(errors.New(reader.canary), investigation.ErrInvalidRequest)
}

func TestTemporalDevServerReadWorkflowV2HistoryAllowlistAndReplay(t *testing.T) {
	const signalCanary = "runtime-v2-signal-history-secret-canary"
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
	temporalClient, err := client.DialContext(ctx, client.Options{
		HostPort: address, Namespace: "default", Identity: "aiops-investigation-read-v2-history-test",
	})
	if err != nil {
		t.Fatalf("client.DialContext() error = %v", err)
	}
	defer temporalClient.Close()

	fixture := newActivityFixtureWithCanary(t, "firing", signalCanary)
	input := investigationworkflow.WorkflowInputV2{
		Version:       investigationworkflow.RuntimeV2SchemaVersion,
		OutboxEventID: uuid.NewString(),
		TenantID:      fixture.input.TenantID, WorkspaceID: fixture.input.WorkspaceID,
		SignalID: fixture.input.SignalID, AggregateVersion: fixture.input.AggregateVersion,
		ManifestDigest: fixture.input.ManifestDigest, RegistryDigest: fixture.input.RegistryDigest,
		BundleDigest: strings.Repeat("5", 64),
	}
	controlQueue, err := investigationworkflow.ControlTaskQueue(
		input.ManifestDigest, input.RegistryDigest, input.BundleDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	runnerQueue, err := investigationworkflow.RunnerTaskQueue(
		activityEnvironmentID, input.ManifestDigest, input.RegistryDigest, input.BundleDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := investigationworkflow.NewRecoveryActivities(recoveryReaderFunc(func(
		_ context.Context,
		request readtask.RecoveryRequest,
	) (readtask.RecoveryResult, error) {
		return readtask.RecoveryResult{
			State: readtask.RecoveryCommitted, InvestigationID: request.InvestigationID,
			TaskID: request.TaskID, Position: request.Position, TaskStatus: domain.ReadTaskFailed,
			ReceiptID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ReceiptHash: strings.Repeat("b", 64),
		}, nil
	}))
	if err != nil {
		t.Fatalf("NewRecoveryActivities() error = %v", err)
	}
	runtimeActivities, err := investigationworkflow.NewRuntimeV2Activities(
		fixture.activities, recovery, input.BundleDigest, "default",
	)
	if err != nil {
		t.Fatalf("NewRuntimeV2Activities() error = %v", err)
	}
	controlWorker := worker.New(temporalClient, controlQueue, worker.Options{
		DisableRegistrationAliasing: true, DisableEagerActivities: true,
	})
	if err := investigationworkflow.RegisterRuntimeV2ForTest(controlWorker, runtimeActivities); err != nil {
		t.Fatalf("RegisterRuntimeV2ForTest() error = %v", err)
	}
	runnerWorker := worker.New(temporalClient, runnerQueue, worker.Options{
		DisableRegistrationAliasing: true, DisableEagerActivities: true,
	})
	runnerWorker.RegisterActivityWithOptions(func(
		_ context.Context,
		runnerInput investigationworkflow.ReadTaskActivityInputV1,
	) (investigationworkflow.ReadTaskActivityOutputV1, error) {
		return runnerOutput(runnerInput, investigationworkflow.ReadTaskActivityRecoveryRequired), nil
	}, activity.RegisterOptions{Name: investigationworkflow.ExecuteActivityNameV1})
	if err := controlWorker.Start(); err != nil {
		t.Fatalf("control Worker Start() error = %v", err)
	}
	defer controlWorker.Stop()
	if err := runnerWorker.Start(); err != nil {
		t.Fatalf("Runner Worker Start() error = %v", err)
	}
	defer runnerWorker.Stop()

	memoPayload, err := investigationworkflow.CanonicalWorkflowInputV2PayloadForTest(input)
	if err != nil {
		t.Fatal(err)
	}
	run, err := temporalClient.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID: input.OutboxEventID, TaskQueue: controlQueue, WorkflowTaskTimeout: 10 * time.Second,
		Memo: map[string]interface{}{
			investigationworkflow.RuntimeMemoIdentityKeyV2: json.RawMessage(memoPayload.Data),
		},
	}, investigationworkflow.WorkflowNameV2, input)
	if err != nil {
		t.Fatalf("ExecuteWorkflow() error = %v", err)
	}
	var result investigationworkflow.WorkflowResultV2
	if err := run.Get(ctx, &result); err != nil || result.ValidateAgainst(input) != nil {
		t.Fatalf("Workflow result = %#v, %v", result, err)
	}
	history := readCompleteHistory(t, ctx, temporalClient, run.GetID(), run.GetRunID())
	assertRuntimeV2HistoryPayloadKeys(t, history.ProtoReflect())
	material := strings.ToLower(historyMaterial(t, history))
	for name, expected := range map[string]string{
		"outbox": input.OutboxEventID, "workspace": input.WorkspaceID,
		"task": workflowTaskID, "bundle": input.BundleDigest,
	} {
		if !strings.Contains(material, strings.ToLower(expected)) {
			t.Fatalf("Temporal v2 History is missing safe %s identity", name)
		}
	}
	for _, forbidden := range []string{
		strings.ToLower(signalCanary),
		"authorization", "credential", "secret", "lease_token", "target_ref", "runtime_binding",
		"connector_id", "certificate_sha256", "runner_id", "receipt_hash", "receipt_id",
		"input_hash", "request_hash", "provider_event_id", "labels",
	} {
		if strings.Contains(material, forbidden) {
			t.Fatalf("Temporal v2 History contains forbidden material %q", forbidden)
		}
	}
	replayer, err := worker.NewWorkflowReplayerWithOptions(worker.WorkflowReplayerOptions{
		DisableRegistrationAliasing: true,
	})
	if err != nil {
		t.Fatalf("NewWorkflowReplayerWithOptions() error = %v", err)
	}
	replayer.RegisterWorkflowWithOptions(
		investigationworkflow.ProductionReadWorkflowV2ForTest,
		workflow.RegisterOptions{Name: investigationworkflow.WorkflowNameV2},
	)
	if err := replayer.ReplayWorkflowExecution(
		ctx,
		temporalClient.WorkflowService(),
		nil,
		"default",
		workflow.Execution{ID: run.GetID(), RunID: run.GetRunID()},
	); err != nil {
		t.Fatalf("ReplayWorkflowExecution() error = %v", err)
	}
}

func assertRuntimeV2HistoryPayloadKeys(t *testing.T, message protoreflect.Message) {
	t.Helper()
	allowed := map[string]struct{}{
		"version": {}, "outbox_event_id": {}, "tenant_id": {}, "workspace_id": {}, "signal_id": {},
		"aggregate_version": {}, "manifest_digest": {}, "registry_digest": {}, "bundle_digest": {},
		"state": {}, "incident_id": {}, "environment_id": {}, "service_id": {}, "investigation_id": {},
		"tasks": {}, "task_id": {}, "position": {}, "profile_digest": {}, "tasks_hash": {}, "round": {},
		"task_status": {}, "evidence_id": {}, "content_hash": {},
	}
	objects := 0
	var visit func(protoreflect.Message)
	visit = func(current protoreflect.Message) {
		if current.Descriptor().FullName() == "temporal.api.common.v1.Payload" {
			dataField := current.Descriptor().Fields().ByName("data")
			if dataField != nil {
				data := current.Get(dataField).Bytes()
				var document any
				if len(data) > 0 && json.Unmarshal(data, &document) == nil {
					if object, ok := document.(map[string]any); ok {
						objects++
						assertRuntimeV2JSONKeys(t, object, allowed)
					}
				}
			}
		}
		current.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
			visitRuntimeV2ProtoValue(field, value, visit)
			return true
		})
	}
	visit(message)
	if objects < 6 {
		t.Fatalf("Temporal v2 History exposed only %d JSON object payloads; allowlist test is incomplete", objects)
	}
}

func visitRuntimeV2ProtoValue(
	field protoreflect.FieldDescriptor,
	value protoreflect.Value,
	visit func(protoreflect.Message),
) {
	if field.IsList() {
		if field.Kind() == protoreflect.MessageKind || field.Kind() == protoreflect.GroupKind {
			list := value.List()
			for index := 0; index < list.Len(); index++ {
				visit(list.Get(index).Message())
			}
		}
		return
	}
	if field.IsMap() {
		if field.MapValue().Kind() == protoreflect.MessageKind || field.MapValue().Kind() == protoreflect.GroupKind {
			value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
				visit(item.Message())
				return true
			})
		}
		return
	}
	if field.Kind() == protoreflect.MessageKind || field.Kind() == protoreflect.GroupKind {
		visit(value.Message())
	}
}

func assertRuntimeV2JSONKeys(t *testing.T, value any, allowed map[string]struct{}) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if _, ok := allowed[key]; !ok {
				t.Fatalf("Temporal v2 History payload contains non-allowlisted key %q", key)
			}
			assertRuntimeV2JSONKeys(t, nested, allowed)
		}
	case []any:
		for _, nested := range typed {
			assertRuntimeV2JSONKeys(t, nested, allowed)
		}
	}
}
