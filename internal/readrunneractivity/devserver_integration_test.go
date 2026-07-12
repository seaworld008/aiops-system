package readrunneractivity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/seaworld008/aiops-system/internal/readexecutor"
	"github.com/seaworld008/aiops-system/internal/readtask"
	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const temporalRemoteCanary = "Authorization Bearer read-runner-remote-history-canary"

// TestTemporalDevServerReadRunnerActivitySanitizesRemoteFailure runs the
// package-owned production Activity method against a real Temporal server.
// The fake port represents an untrusted remote boundary and deliberately
// returns a sensitive error; only the fixed RECOVERY_REQUIRED projection may
// cross into durable History.
func TestTemporalDevServerReadRunnerActivitySanitizesRemoteFailure(t *testing.T) {
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
		HostPort: address, Namespace: "default", Identity: "aiops-read-runner-activity-history-test",
	})
	if err != nil {
		t.Fatalf("client.DialContext() error = %v", err)
	}
	defer temporalClient.Close()

	input := validActivityInput()
	input.OutboxEventID = uuid.NewString()
	queue, err := investigationworkflow.RunnerTaskQueue(
		input.EnvironmentID, input.ManifestDigest, input.RegistryDigest, input.BundleDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	activities, err := newActivities(
		&fakeGateway{err: errors.New(temporalRemoteCanary)},
		&fakeRuntime{},
		readexecutor.BearerSource(func(context.Context, string, func([]byte)) readtask.FailureCode { return "" }),
		activityRuntime{
			info:      activity.GetInfo,
			heartbeat: func(activityContext context.Context) { activity.RecordHeartbeat(activityContext) },
			interval:  temporalHeartbeatInterval,
		},
		gatewayHeartbeatInterval,
		"default",
		input.ManifestDigest,
		input.RegistryDigest,
	)
	if err != nil {
		t.Fatalf("newActivities() error = %v", err)
	}

	runnerWorker := worker.New(temporalClient, queue, worker.Options{
		DisableRegistrationAliasing: true,
		DisableEagerActivities:      true,
	})
	runnerWorker.RegisterWorkflowWithOptions(
		temporalReadRunnerActivityContractWorkflow,
		workflow.RegisterOptions{Name: investigationworkflow.WorkflowNameV2},
	)
	if err := Register(runnerWorker, activities); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if err := runnerWorker.Start(); err != nil {
		t.Fatalf("Runner Worker Start() error = %v", err)
	}
	defer runnerWorker.Stop()

	run, err := temporalClient.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID:                  input.OutboxEventID,
		TaskQueue:           queue,
		WorkflowTaskTimeout: 10 * time.Second,
	}, investigationworkflow.WorkflowNameV2, input)
	if err != nil {
		t.Fatalf("ExecuteWorkflow() error = %v", err)
	}
	var output investigationworkflow.ReadTaskActivityOutputV1
	if err := run.Get(ctx, &output); err != nil {
		t.Fatalf("Workflow Get() error = %v", err)
	}
	assertOutput(t, input, output, investigationworkflow.ReadTaskActivityRecoveryRequired)

	history := readCompleteRunnerActivityHistory(t, ctx, temporalClient, run.GetID(), run.GetRunID())
	material := strings.ToLower(runnerActivityHistoryMaterial(t, history))
	if strings.Contains(material, strings.ToLower(temporalRemoteCanary)) {
		t.Fatalf("Temporal History contains remote dependency canary %q", temporalRemoteCanary)
	}
	for name, expected := range map[string]string{
		"outbox": input.OutboxEventID,
		"task":   input.TaskID,
		"bundle": input.BundleDigest,
	} {
		if !strings.Contains(material, strings.ToLower(expected)) {
			t.Fatalf("Temporal History is missing safe %s identity", name)
		}
	}
}

func temporalReadRunnerActivityContractWorkflow(
	ctx workflow.Context,
	input investigationworkflow.ReadTaskActivityInputV1,
) (investigationworkflow.ReadTaskActivityOutputV1, error) {
	queue, err := investigationworkflow.RunnerTaskQueue(
		input.EnvironmentID, input.ManifestDigest, input.RegistryDigest, input.BundleDigest,
	)
	if err != nil {
		return investigationworkflow.ReadTaskActivityOutputV1{}, err
	}
	activityID, err := investigationworkflow.ReadTaskActivityID(input.Round, input.Position, input.TaskID)
	if err != nil {
		return investigationworkflow.ReadTaskActivityOutputV1{}, err
	}
	activityContext := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		TaskQueue:              queue,
		ActivityID:             activityID,
		ScheduleToCloseTimeout: investigationworkflow.RunnerActivityScheduleToCloseTimeout,
		StartToCloseTimeout:    investigationworkflow.RunnerActivityStartToCloseTimeout,
		HeartbeatTimeout:       investigationworkflow.RunnerActivityHeartbeatTimeout,
		RetryPolicy:            &temporal.RetryPolicy{MaximumAttempts: 1},
		WaitForCancellation:    true,
		DisableEagerExecution:  true,
	})
	var output investigationworkflow.ReadTaskActivityOutputV1
	if err := workflow.ExecuteActivity(
		activityContext, investigationworkflow.ExecuteActivityNameV1, input,
	).Get(activityContext, &output); err != nil {
		return investigationworkflow.ReadTaskActivityOutputV1{}, err
	}
	return output, nil
}

func readCompleteRunnerActivityHistory(
	t *testing.T,
	ctx context.Context,
	temporalClient client.Client,
	workflowID string,
	runID string,
) *historypb.History {
	t.Helper()
	iterator := temporalClient.GetWorkflowHistory(
		ctx, workflowID, runID, false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT,
	)
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

func runnerActivityHistoryMaterial(t *testing.T, history *historypb.History) string {
	t.Helper()
	encoded, err := protojson.Marshal(history)
	if err != nil {
		t.Fatalf("protojson.Marshal(history) error = %v", err)
	}
	var material strings.Builder
	material.Write(encoded)
	appendRunnerActivityMessageMaterial(&material, history.ProtoReflect())
	return material.String()
}

func appendRunnerActivityMessageMaterial(material *strings.Builder, message protoreflect.Message) {
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		appendRunnerActivityReflectValue(material, field, value)
		return true
	})
}

func appendRunnerActivityReflectValue(
	material *strings.Builder,
	field protoreflect.FieldDescriptor,
	value protoreflect.Value,
) {
	if field.IsList() {
		list := value.List()
		for index := 0; index < list.Len(); index++ {
			appendRunnerActivityScalarMaterial(material, field.Kind(), list.Get(index))
		}
		return
	}
	if field.IsMap() {
		value.Map().Range(func(key protoreflect.MapKey, item protoreflect.Value) bool {
			material.WriteString(fmt.Sprint(key.Interface()))
			appendRunnerActivityScalarMaterial(material, field.MapValue().Kind(), item)
			return true
		})
		return
	}
	appendRunnerActivityScalarMaterial(material, field.Kind(), value)
}

func appendRunnerActivityScalarMaterial(
	material *strings.Builder,
	kind protoreflect.Kind,
	value protoreflect.Value,
) {
	switch kind {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		appendRunnerActivityMessageMaterial(material, value.Message())
	case protoreflect.BytesKind:
		material.Write(value.Bytes())
	case protoreflect.StringKind:
		material.WriteString(value.String())
	}
}
