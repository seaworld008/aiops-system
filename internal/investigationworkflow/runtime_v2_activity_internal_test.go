package investigationworkflow

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigationplan"
	"github.com/seaworld008/aiops-system/internal/readtask"
	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

func TestRuntimeV2WorkflowInfoBindsExactNamespaceAndUUIDRun(t *testing.T) {
	input := WorkflowInputV2{
		Version:       RuntimeV2SchemaVersion,
		OutboxEventID: "10101010-1010-4010-8010-101010101010",
		TenantID:      "20202020-2020-4020-8020-202020202020",
		WorkspaceID:   "30303030-3030-4030-8030-303030303030",
		SignalID:      "40404040-4040-4040-8040-404040404040", AggregateVersion: 1,
		ManifestDigest: strings.Repeat("1", 64), RegistryDigest: strings.Repeat("2", 64),
		BundleDigest: inputBundleDigestForRuntimeV2Test,
	}
	queue, err := ControlTaskQueue(input.ManifestDigest, input.RegistryDigest, input.BundleDigest)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := canonicalWorkflowInputV2Payload(input)
	if err != nil {
		t.Fatal(err)
	}
	validInfo := &workflow.Info{
		WorkflowExecution: workflow.Execution{
			ID: input.OutboxEventID, RunID: "11111111-1111-4111-8111-111111111111",
		},
		WorkflowType:  workflow.Type{Name: WorkflowNameV2},
		TaskQueueName: queue, WorkflowTaskTimeout: 10 * time.Second,
		Namespace: "default", Attempt: 1,
		Memo: &commonpb.Memo{Fields: map[string]*commonpb.Payload{RuntimeMemoIdentityKeyV2: identity}},
	}
	if !validRuntimeV2WorkflowInfo(validInfo, input, queue, identity, "default") {
		t.Fatal("exact WorkflowInfo was rejected")
	}
	for name, mutate := range map[string]func(*workflow.Info){
		"legal foreign namespace": func(info *workflow.Info) { info.Namespace = "other-valid-namespace" },
		"malformed run id":        func(info *workflow.Info) { info.WorkflowExecution.RunID = "not-a-run" },
		"foreign workflow type":   func(info *workflow.Info) { info.WorkflowType.Name = WorkflowName },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := *validInfo
			if mutate(&candidate); validRuntimeV2WorkflowInfo(&candidate, input, queue, identity, "default") {
				t.Fatalf("WorkflowInfo accepted %s drift", name)
			}
		})
	}
}

func TestRuntimeV2PrepareRejectsNonActivityContextBeforeTrustedReads(t *testing.T) {
	authority := investigationplan.NewScopeAuthority()
	planner := internalWorkerPlanner(t, authority)
	reader := &runtimeV2CountingSignalReader{}
	preparation := &Activities{
		reader: reader, repository: &runtimeV2NeverPreparationRepository{},
		authority: authority, planner: planner,
	}
	recovery := &RecoveryActivities{reader: runtimeV2PendingRecoveryReader{}}
	activities, err := NewRuntimeV2Activities(preparation, recovery, inputBundleDigestForRuntimeV2Test, "default")
	if err != nil {
		t.Fatalf("NewRuntimeV2Activities() error = %v", err)
	}
	input := WorkflowInputV2{
		Version:       RuntimeV2SchemaVersion,
		OutboxEventID: "10101010-1010-4010-8010-101010101010",
		TenantID:      "20202020-2020-4020-8020-202020202020",
		WorkspaceID:   "30303030-3030-4030-8030-303030303030",
		SignalID:      "40404040-4040-4040-8040-404040404040", AggregateVersion: 1,
		ManifestDigest: planner.ManifestDigest(), RegistryDigest: planner.RegistryDigest(),
		BundleDigest: inputBundleDigestForRuntimeV2Test,
	}
	result, err := activities.prepareActivityV2(context.Background(), input)
	var applicationError *temporal.ApplicationError
	if result.Version != 0 || !errors.As(err, &applicationError) ||
		applicationError.Type() != "READ_PREPARE_EXECUTION_MISMATCH" || !applicationError.NonRetryable() {
		t.Fatalf("prepareActivityV2(non Activity) = %#v, %v", result, err)
	}
	if reader.calls.Load() != 0 {
		t.Fatalf("untrusted Activity context reached Signal reader %d times", reader.calls.Load())
	}
}

func TestRuntimeV2ControlActivityInfoIsExactAndRejectedBeforeRecoveryRead(t *testing.T) {
	authority := investigationplan.NewScopeAuthority()
	planner := internalWorkerPlanner(t, authority)
	recoveryReader := &runtimeV2CountingRecoveryReader{}
	activities, err := NewRuntimeV2Activities(
		&Activities{
			reader: &runtimeV2CountingSignalReader{}, repository: &runtimeV2NeverPreparationRepository{},
			authority: authority, planner: planner,
		},
		&RecoveryActivities{reader: recoveryReader}, inputBundleDigestForRuntimeV2Test, "default",
	)
	if err != nil {
		t.Fatal(err)
	}
	input := RecoveryActivityInput{
		Version:         RecoveryActivitySchemaVersion,
		TenantID:        "20202020-2020-4020-8020-202020202020",
		WorkspaceID:     "30303030-3030-4030-8030-303030303030",
		IncidentID:      "50505050-5050-4050-8050-505050505050",
		InvestigationID: "80808080-8080-4080-8080-808080808080",
		TaskID:          "90909090-9090-4090-8090-909090909090", Position: 1,
		ManifestDigest: planner.ManifestDigest(), RegistryDigest: planner.RegistryDigest(),
		ProfileDigest: strings.Repeat("3", 64), TasksHash: strings.Repeat("4", 64),
	}
	queue, err := ControlTaskQueue(input.ManifestDigest, input.RegistryDigest, inputBundleDigestForRuntimeV2Test)
	if err != nil {
		t.Fatal(err)
	}
	activityID, err := RecoveryActivityID(1, 1, input.Position, input.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	validInfo := activity.Info{
		WorkflowType: &workflow.Type{Name: WorkflowNameV2},
		WorkflowExecution: workflow.Execution{
			ID:    "10101010-1010-4010-8010-101010101010",
			RunID: "11111111-1111-4111-8111-111111111111",
		},
		ActivityID: activityID, ActivityType: activity.Type{Name: RecoveryActivityNameV1},
		TaskQueue: queue, Namespace: "default", StartToCloseTimeout: recoveryActivityStartToCloseTimeoutV1,
		Attempt: 1, RetryPolicy: &temporal.RetryPolicy{
			InitialInterval: time.Second, BackoffCoefficient: 2, MaximumInterval: 15 * time.Second,
			MaximumAttempts: 0, NonRetryableErrorTypes: recoveryNonRetryableTypesV1(),
		},
	}
	if !validRecoveryActivityInfoV1(validInfo, input, inputBundleDigestForRuntimeV2Test, "default") {
		t.Fatal("exact Recovery ActivityInfo was rejected")
	}
	mutations := map[string]func(*activity.Info){
		"workflow type": func(info *activity.Info) { info.WorkflowType.Name = WorkflowName },
		"workflow run":  func(info *activity.Info) { info.WorkflowExecution.RunID = "not-a-run" },
		"namespace":     func(info *activity.Info) { info.Namespace = "other-valid-namespace" },
		"activity type": func(info *activity.Info) { info.ActivityType.Name = PrepareActivityNameV2 },
		"activity id":   func(info *activity.Info) { info.ActivityID += "-forged" },
		"queue":         func(info *activity.Info) { info.TaskQueue += "-forged" },
		"attempt":       func(info *activity.Info) { info.Attempt = 0 },
		"timeout":       func(info *activity.Info) { info.StartToCloseTimeout++ },
		"retry":         func(info *activity.Info) { info.RetryPolicy.MaximumAttempts = 1 },
		"local":         func(info *activity.Info) { info.IsLocalActivity = true },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := validInfo
			workflowType := *validInfo.WorkflowType
			candidate.WorkflowType = &workflowType
			retry := *validInfo.RetryPolicy
			retry.NonRetryableErrorTypes = append([]string(nil), validInfo.RetryPolicy.NonRetryableErrorTypes...)
			candidate.RetryPolicy = &retry
			mutate(&candidate)
			if validRecoveryActivityInfoV1(candidate, input, inputBundleDigestForRuntimeV2Test, "default") {
				t.Fatalf("Recovery ActivityInfo accepted %s drift", name)
			}
		})
	}
	result, err := activities.recoverActivityV1(context.Background(), input)
	var applicationError *temporal.ApplicationError
	if result.Version != 0 || !errors.As(err, &applicationError) ||
		applicationError.Type() != "READ_RESULT_RECOVERY_EXECUTION_MISMATCH" || recoveryReader.calls.Load() != 0 {
		t.Fatalf("recoverActivityV1(untrusted context) = %#v, %v; reads=%d", result, err, recoveryReader.calls.Load())
	}
}

const inputBundleDigestForRuntimeV2Test = "5555555555555555555555555555555555555555555555555555555555555555"

type runtimeV2CountingSignalReader struct{ calls atomic.Int64 }

func (reader *runtimeV2CountingSignalReader) GetRegisteredSignal(
	context.Context,
	string,
) (investigation.RegisteredSignal, error) {
	reader.calls.Add(1)
	return investigation.RegisteredSignal{}, errors.New("must not read")
}

type runtimeV2NeverPreparationRepository struct{ preparationRepository }

type runtimeV2PendingRecoveryReader struct{}

func (runtimeV2PendingRecoveryReader) Recover(
	context.Context,
	readtask.RecoveryRequest,
) (readtask.RecoveryResult, error) {
	return readtask.RecoveryResult{}, errors.New("must not recover")
}

type runtimeV2CountingRecoveryReader struct{ calls atomic.Int64 }

func (reader *runtimeV2CountingRecoveryReader) Recover(
	context.Context,
	readtask.RecoveryRequest,
) (readtask.RecoveryResult, error) {
	reader.calls.Add(1)
	return readtask.RecoveryResult{}, errors.New("must not recover")
}
