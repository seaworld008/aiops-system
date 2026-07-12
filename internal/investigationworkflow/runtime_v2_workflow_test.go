package investigationworkflow_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/seaworld008/aiops-system/internal/readtask"
	"github.com/stretchr/testify/mock"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
)

const (
	runtimeV2Outbox        = "10101010-1010-4010-8010-101010101010"
	runtimeV2Tenant        = "20202020-2020-4020-8020-202020202020"
	runtimeV2Workspace     = "30303030-3030-4030-8030-303030303030"
	runtimeV2Signal        = "40404040-4040-4040-8040-404040404040"
	runtimeV2Incident      = "50505050-5050-4050-8050-505050505050"
	runtimeV2Environment   = "60606060-6060-4060-8060-606060606060"
	runtimeV2Service       = "70707070-7070-4070-8070-707070707070"
	runtimeV2Investigation = "80808080-8080-4080-8080-808080808080"
	runtimeV2TaskOne       = "90909090-9090-4090-8090-909090909090"
	runtimeV2TaskTwo       = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

func TestReadWorkflowV2ExecutesTasksSeriallyAndReturnsOnlyRecoveredTerminalFacts(t *testing.T) {
	input := validRuntimeV2WorkflowInput()
	prepared := validRuntimeV2PreparationReceipt()
	var mu sync.Mutex
	var calls []string

	environment := newRuntimeV2WorkflowEnvironment(t, input)
	environment.RegisterWorkflowWithOptions(
		investigationworkflow.ReadWorkflowV2ForTest,
		workflow.RegisterOptions{Name: investigationworkflow.WorkflowNameV2},
	)
	environment.RegisterActivityWithOptions(func(
		context.Context,
		investigationworkflow.WorkflowInputV2,
	) (investigationworkflow.PreparationReceiptV2, error) {
		mu.Lock()
		calls = append(calls, "prepare")
		mu.Unlock()
		return prepared, nil
	}, activity.RegisterOptions{Name: investigationworkflow.PrepareActivityNameV2})
	environment.RegisterActivityWithOptions(func(
		_ context.Context,
		activityInput investigationworkflow.ReadTaskActivityInputV1,
	) (investigationworkflow.ReadTaskActivityOutputV1, error) {
		mu.Lock()
		calls = append(calls, "execute:"+activityInput.TaskID)
		mu.Unlock()
		return investigationworkflow.ReadTaskActivityOutputV1{
			Version:         investigationworkflow.ReadTaskActivitySchemaVersion,
			State:           investigationworkflow.ReadTaskActivityCompleteAcknowledged,
			InvestigationID: activityInput.InvestigationID, TaskID: activityInput.TaskID,
			Position: activityInput.Position, Round: activityInput.Round,
		}, nil
	}, activity.RegisterOptions{Name: investigationworkflow.ExecuteActivityNameV1})
	environment.RegisterActivityWithOptions(func(
		_ context.Context,
		recoveryInput investigationworkflow.RecoveryActivityInput,
	) (investigationworkflow.RecoveryActivityOutput, error) {
		mu.Lock()
		calls = append(calls, "recover:"+recoveryInput.TaskID)
		mu.Unlock()
		output := investigationworkflow.RecoveryActivityOutput{
			Version: investigationworkflow.RecoveryActivitySchemaVersion,
			State:   readtask.RecoveryCommitted, InvestigationID: recoveryInput.InvestigationID,
			TaskID: recoveryInput.TaskID, Position: recoveryInput.Position,
		}
		if recoveryInput.Position == 1 {
			output.TaskStatus = domain.ReadTaskEvidence
			output.EvidenceID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
			output.ContentHash = strings.Repeat("b", 64)
		} else {
			output.TaskStatus = domain.ReadTaskFailed
		}
		return output, nil
	}, activity.RegisterOptions{Name: investigationworkflow.RecoveryActivityNameV1})

	environment.ExecuteWorkflow(investigationworkflow.WorkflowNameV2, input)
	if err := environment.GetWorkflowError(); err != nil {
		t.Fatalf("read Workflow v2 error = %v", err)
	}
	var result investigationworkflow.WorkflowResultV2
	if err := environment.GetWorkflowResult(&result); err != nil {
		t.Fatalf("GetWorkflowResult() error = %v", err)
	}
	if result.State != investigationworkflow.RuntimeStateReadTasksTerminal ||
		len(result.Tasks) != 2 || result.Tasks[0].TaskStatus != domain.ReadTaskEvidence ||
		result.Tasks[1].TaskStatus != domain.ReadTaskFailed || result.ValidateAgainst(input) != nil {
		t.Fatalf("WorkflowResultV2 = %#v", result)
	}
	wantCalls := []string{
		"prepare",
		"execute:" + runtimeV2TaskOne, "recover:" + runtimeV2TaskOne,
		"execute:" + runtimeV2TaskTwo, "recover:" + runtimeV2TaskTwo,
	}
	mu.Lock()
	gotCalls := append([]string(nil), calls...)
	mu.Unlock()
	if !reflect.DeepEqual(gotCalls, wantCalls) {
		t.Fatalf("Activity call order = %#v, want %#v", gotCalls, wantCalls)
	}
}

func TestReadWorkflowV2ReturnsNoActiveIncidentWithoutSchedulingRunnerOrRecovery(t *testing.T) {
	input := validRuntimeV2WorkflowInput()
	prepared := validRuntimeV2PreparationReceipt()
	prepared.State = investigationworkflow.StateNoActiveIncident
	prepared.IncidentID, prepared.EnvironmentID, prepared.ServiceID, prepared.InvestigationID = "", "", "", ""
	prepared.Tasks = nil
	environment := newRuntimeV2WorkflowEnvironment(t, input)
	registerRuntimeV2TestProtocol(environment,
		func(context.Context, investigationworkflow.WorkflowInputV2) (investigationworkflow.PreparationReceiptV2, error) {
			return prepared, nil
		},
		func(context.Context, investigationworkflow.ReadTaskActivityInputV1) (investigationworkflow.ReadTaskActivityOutputV1, error) {
			t.Fatal("NO_ACTIVE_INCIDENT scheduled Runner Activity")
			return investigationworkflow.ReadTaskActivityOutputV1{}, nil
		},
		func(context.Context, investigationworkflow.RecoveryActivityInput) (investigationworkflow.RecoveryActivityOutput, error) {
			t.Fatal("NO_ACTIVE_INCIDENT scheduled Recovery Activity")
			return investigationworkflow.RecoveryActivityOutput{}, nil
		},
	)
	environment.ExecuteWorkflow(investigationworkflow.WorkflowNameV2, input)
	var result investigationworkflow.WorkflowResultV2
	if err := environment.GetWorkflowResult(&result); err != nil ||
		result.State != investigationworkflow.RuntimeStateNoActiveIncident || result.ValidateAgainst(input) != nil {
		t.Fatalf("NO_ACTIVE result = %#v, %v", result, err)
	}
}

func TestReadWorkflowV2AlwaysRecoversRunnerErrorTimeoutAndInvalidOutput(t *testing.T) {
	input := validRuntimeV2WorkflowInput()
	prepared := oneTaskRuntimeV2PreparationReceipt()
	tests := map[string]runtimeV2RunnerActivity{
		"error": func(context.Context, investigationworkflow.ReadTaskActivityInputV1) (investigationworkflow.ReadTaskActivityOutputV1, error) {
			return investigationworkflow.ReadTaskActivityOutputV1{}, temporal.NewApplicationError(
				"READ runner dependency unavailable", "READ_RUNNER_DEPENDENCY_UNAVAILABLE",
			)
		},
		"timeout": func(context.Context, investigationworkflow.ReadTaskActivityInputV1) (investigationworkflow.ReadTaskActivityOutputV1, error) {
			return investigationworkflow.ReadTaskActivityOutputV1{}, temporal.NewTimeoutError(
				enumspb.TIMEOUT_TYPE_START_TO_CLOSE, nil,
			)
		},
		"invalid output": func(context.Context, investigationworkflow.ReadTaskActivityInputV1) (investigationworkflow.ReadTaskActivityOutputV1, error) {
			return investigationworkflow.ReadTaskActivityOutputV1{
				Version: investigationworkflow.ReadTaskActivitySchemaVersion,
				State:   "FORGED_TERMINAL_STATE", InvestigationID: runtimeV2Investigation,
				TaskID: runtimeV2TaskOne, Position: 1, Round: 1,
			}, nil
		},
	}
	for name, runner := range tests {
		t.Run(name, func(t *testing.T) {
			var recoveryCalls atomic.Int64
			environment := newRuntimeV2WorkflowEnvironment(t, input)
			registerRuntimeV2TestProtocol(environment, fixedRuntimeV2Prepare(prepared), runner,
				func(_ context.Context, recoveryInput investigationworkflow.RecoveryActivityInput) (investigationworkflow.RecoveryActivityOutput, error) {
					recoveryCalls.Add(1)
					return failedRecoveryOutput(recoveryInput), nil
				},
			)
			environment.ExecuteWorkflow(investigationworkflow.WorkflowNameV2, input)
			var result investigationworkflow.WorkflowResultV2
			if err := environment.GetWorkflowResult(&result); err != nil || recoveryCalls.Load() != 1 ||
				len(result.Tasks) != 1 || result.Tasks[0].TaskStatus != domain.ReadTaskFailed {
				t.Fatalf("runner %s recovery result = %#v, %v; calls=%d", name, result, err, recoveryCalls.Load())
			}
		})
	}
}

func TestReadWorkflowV2RejectsAcknowledgedCompletionWhenRecoveryIsPending(t *testing.T) {
	input := validRuntimeV2WorkflowInput()
	prepared := oneTaskRuntimeV2PreparationReceipt()
	var recoveryCalls atomic.Int64
	environment := newRuntimeV2WorkflowEnvironment(t, input)
	registerRuntimeV2TestProtocol(environment, fixedRuntimeV2Prepare(prepared),
		func(_ context.Context, runnerInput investigationworkflow.ReadTaskActivityInputV1) (investigationworkflow.ReadTaskActivityOutputV1, error) {
			return runnerOutput(runnerInput, investigationworkflow.ReadTaskActivityCompleteAcknowledged), nil
		},
		func(_ context.Context, recoveryInput investigationworkflow.RecoveryActivityInput) (investigationworkflow.RecoveryActivityOutput, error) {
			recoveryCalls.Add(1)
			return pendingRecoveryOutput(recoveryInput), nil
		},
	)
	environment.ExecuteWorkflow(investigationworkflow.WorkflowNameV2, input)
	var applicationError *temporal.ApplicationError
	if err := environment.GetWorkflowError(); !errors.As(err, &applicationError) ||
		applicationError.Type() != "READ_TASK_ACK_PENDING" || !applicationError.NonRetryable() ||
		recoveryCalls.Load() != 1 {
		t.Fatalf("ACK+PENDING error = %v; recovery calls=%d", err, recoveryCalls.Load())
	}
}

func TestReadWorkflowV2WaitsExactly35SecondsThenRecoversCommittedResult(t *testing.T) {
	input := validRuntimeV2WorkflowInput()
	prepared := oneTaskRuntimeV2PreparationReceipt()
	var recoveryCalls atomic.Int64
	var timers []time.Duration
	environment := newRuntimeV2WorkflowEnvironment(t, input)
	environment.SetOnTimerScheduledListener(func(_ string, duration time.Duration) { timers = append(timers, duration) })
	registerRuntimeV2TestProtocol(environment, fixedRuntimeV2Prepare(prepared),
		func(_ context.Context, runnerInput investigationworkflow.ReadTaskActivityInputV1) (investigationworkflow.ReadTaskActivityOutputV1, error) {
			return runnerOutput(runnerInput, investigationworkflow.ReadTaskActivityNotClaimed), nil
		},
		func(_ context.Context, recoveryInput investigationworkflow.RecoveryActivityInput) (investigationworkflow.RecoveryActivityOutput, error) {
			if recoveryCalls.Add(1) == 1 {
				return pendingRecoveryOutput(recoveryInput), nil
			}
			return failedRecoveryOutput(recoveryInput), nil
		},
	)
	environment.ExecuteWorkflow(investigationworkflow.WorkflowNameV2, input)
	var result investigationworkflow.WorkflowResultV2
	if err := environment.GetWorkflowResult(&result); err != nil || recoveryCalls.Load() != 2 ||
		!reflect.DeepEqual(timers, []time.Duration{investigationworkflow.ReadTaskRecoveryWait}) ||
		len(result.Tasks) != 1 || result.Tasks[0].TaskStatus != domain.ReadTaskFailed {
		t.Fatalf("PENDING->COMMITTED result = %#v, %v; calls=%d timers=%v", result, err, recoveryCalls.Load(), timers)
	}
}

func TestReadWorkflowV2ExhaustsThreePendingRoundsWithoutForgingFailure(t *testing.T) {
	input := validRuntimeV2WorkflowInput()
	prepared := oneTaskRuntimeV2PreparationReceipt()
	var runnerCalls, recoveryCalls atomic.Int64
	var timers []time.Duration
	environment := newRuntimeV2WorkflowEnvironment(t, input)
	environment.SetOnTimerScheduledListener(func(_ string, duration time.Duration) { timers = append(timers, duration) })
	registerRuntimeV2TestProtocol(environment, fixedRuntimeV2Prepare(prepared),
		func(_ context.Context, runnerInput investigationworkflow.ReadTaskActivityInputV1) (investigationworkflow.ReadTaskActivityOutputV1, error) {
			runnerCalls.Add(1)
			return runnerOutput(runnerInput, investigationworkflow.ReadTaskActivityNotClaimed), nil
		},
		func(_ context.Context, recoveryInput investigationworkflow.RecoveryActivityInput) (investigationworkflow.RecoveryActivityOutput, error) {
			recoveryCalls.Add(1)
			return pendingRecoveryOutput(recoveryInput), nil
		},
	)
	environment.ExecuteWorkflow(investigationworkflow.WorkflowNameV2, input)
	var applicationError *temporal.ApplicationError
	if err := environment.GetWorkflowError(); !errors.As(err, &applicationError) ||
		applicationError.Type() != investigationworkflow.ReadTaskPendingErrorType || !applicationError.NonRetryable() ||
		runnerCalls.Load() != investigationworkflow.MaximumReadTaskRounds ||
		recoveryCalls.Load() != 2*investigationworkflow.MaximumReadTaskRounds ||
		len(timers) != investigationworkflow.MaximumReadTaskRounds {
		t.Fatalf("pending exhaustion = %v; runner=%d recovery=%d timers=%v",
			err, runnerCalls.Load(), recoveryCalls.Load(), timers)
	}
}

func TestReadWorkflowV2CancelWithThreePendingRoundsUsesDurableManualHandoff(t *testing.T) {
	input := validRuntimeV2WorkflowInput()
	prepared := oneTaskRuntimeV2PreparationReceipt()
	var runnerCalls, recoveryCalls atomic.Int64
	environment := newRuntimeV2WorkflowEnvironment(t, input)
	registerRuntimeV2TestProtocol(environment, fixedRuntimeV2Prepare(prepared),
		func(_ context.Context, runnerInput investigationworkflow.ReadTaskActivityInputV1) (investigationworkflow.ReadTaskActivityOutputV1, error) {
			runnerCalls.Add(1)
			return runnerOutput(runnerInput, investigationworkflow.ReadTaskActivityNotClaimed), nil
		},
		func(_ context.Context, recoveryInput investigationworkflow.RecoveryActivityInput) (investigationworkflow.RecoveryActivityOutput, error) {
			recoveryCalls.Add(1)
			return pendingRecoveryOutput(recoveryInput), nil
		},
	)
	environment.RegisterDelayedCallback(environment.CancelWorkflow, time.Second)
	environment.ExecuteWorkflow(investigationworkflow.WorkflowNameV2, input)
	var applicationError *temporal.ApplicationError
	if err := environment.GetWorkflowError(); !errors.As(err, &applicationError) ||
		applicationError.Type() != investigationworkflow.ReadTaskPendingErrorType ||
		!applicationError.NonRetryable() || temporal.IsCanceledError(err) ||
		runnerCalls.Load() != investigationworkflow.MaximumReadTaskRounds ||
		recoveryCalls.Load() != 2*investigationworkflow.MaximumReadTaskRounds {
		t.Fatalf("cancel+PENDING handoff = %v; runner=%d recovery=%d",
			err, runnerCalls.Load(), recoveryCalls.Load())
	}
}

func TestReadWorkflowV2OrdinaryCancelWaitsForDurableTaskTerminal(t *testing.T) {
	for _, phase := range []string{"before runner", "during runner"} {
		t.Run(phase, func(t *testing.T) {
			input := validRuntimeV2WorkflowInput()
			prepared := oneTaskRuntimeV2PreparationReceipt()
			var runnerCalls, recoveryCalls atomic.Int64
			environment := newRuntimeV2WorkflowEnvironment(t, input)
			registerRuntimeV2TestProtocol(environment, fixedRuntimeV2Prepare(prepared),
				func(_ context.Context, runnerInput investigationworkflow.ReadTaskActivityInputV1) (investigationworkflow.ReadTaskActivityOutputV1, error) {
					runnerCalls.Add(1)
					return runnerOutput(runnerInput, investigationworkflow.ReadTaskActivityRecoveryRequired), nil
				},
				func(_ context.Context, recoveryInput investigationworkflow.RecoveryActivityInput) (investigationworkflow.RecoveryActivityOutput, error) {
					recoveryCalls.Add(1)
					return failedRecoveryOutput(recoveryInput), nil
				},
			)
			if phase == "before runner" {
				environment.OnActivity(
					investigationworkflow.PrepareActivityNameV2, mock.Anything, input,
				).Return(prepared, nil).After(2 * time.Second)
			} else {
				expectedRunnerInput := runtimeV2RunnerInput(prepared, 1)
				environment.OnActivity(
					investigationworkflow.ExecuteActivityNameV1, mock.Anything, mock.Anything,
				).Return(runnerOutput(expectedRunnerInput, investigationworkflow.ReadTaskActivityRecoveryRequired), nil).
					Run(func(mock.Arguments) { runnerCalls.Add(1) }).After(2 * time.Second)
			}
			environment.RegisterDelayedCallback(environment.CancelWorkflow, time.Second)
			environment.ExecuteWorkflow(investigationworkflow.WorkflowNameV2, input)
			if err := environment.GetWorkflowError(); !temporal.IsCanceledError(err) ||
				runnerCalls.Load() != 1 || recoveryCalls.Load() != 1 {
				t.Fatalf("cancel %s = %v; runner=%d recovery=%d", phase, err, runnerCalls.Load(), recoveryCalls.Load())
			}
		})
	}
}

func TestReadWorkflowV2RejectsMissingExtraMismatchedAndNonCanonicalMemoBeforeActivity(t *testing.T) {
	input := validRuntimeV2WorkflowInput()
	validPayload, err := investigationworkflow.CanonicalWorkflowInputV2PayloadForTest(input)
	if err != nil {
		t.Fatal(err)
	}
	other := input
	other.BundleDigest = strings.Repeat("6", 64)
	otherPayload, err := investigationworkflow.CanonicalWorkflowInputV2PayloadForTest(other)
	if err != nil {
		t.Fatal(err)
	}
	nonCanonical, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]map[string]interface{}{
		"missing": {},
		"extra": {
			investigationworkflow.RuntimeMemoIdentityKeyV2: json.RawMessage(validPayload.Data),
			"unexpected": true,
		},
		"mismatched": {
			investigationworkflow.RuntimeMemoIdentityKeyV2: json.RawMessage(otherPayload.Data),
		},
		"non canonical": {
			investigationworkflow.RuntimeMemoIdentityKeyV2: json.RawMessage(nonCanonical),
		},
	}
	for name, memo := range tests {
		t.Run(name, func(t *testing.T) {
			environment := newRuntimeV2WorkflowEnvironment(t, input)
			if err := environment.SetMemoOnStart(memo); err != nil {
				t.Fatal(err)
			}
			activityCalls := atomic.Int64{}
			environment.SetOnActivityStartedListener(func(*activity.Info, context.Context, converter.EncodedValues) {
				activityCalls.Add(1)
			})
			environment.RegisterWorkflowWithOptions(
				investigationworkflow.ReadWorkflowV2ForTest,
				workflow.RegisterOptions{Name: investigationworkflow.WorkflowNameV2},
			)
			environment.ExecuteWorkflow(investigationworkflow.WorkflowNameV2, input)
			var applicationError *temporal.ApplicationError
			if err := environment.GetWorkflowError(); !errors.As(err, &applicationError) ||
				applicationError.Type() != "READ_WORKFLOW_EXECUTION_MISMATCH" || activityCalls.Load() != 0 {
				t.Fatalf("memo %s error = %v; activity calls=%d", name, err, activityCalls.Load())
			}
		})
	}
}

func newRuntimeV2WorkflowEnvironment(
	t *testing.T,
	input investigationworkflow.WorkflowInputV2,
) *testsuite.TestWorkflowEnvironment {
	t.Helper()
	var suite testsuite.WorkflowTestSuite
	suite.SetDisableRegistrationAliasing(true)
	environment := suite.NewTestWorkflowEnvironment()
	queue, err := investigationworkflow.ControlTaskQueue(input.ManifestDigest, input.RegistryDigest, input.BundleDigest)
	if err != nil {
		t.Fatalf("ControlTaskQueue() error = %v", err)
	}
	environment.SetStartWorkflowOptions(client.StartWorkflowOptions{
		ID: input.OutboxEventID, TaskQueue: queue, WorkflowTaskTimeout: 10 * time.Second,
	})
	payload, err := investigationworkflow.CanonicalWorkflowInputV2PayloadForTest(input)
	if err != nil {
		t.Fatalf("CanonicalWorkflowInputV2PayloadForTest() error = %v", err)
	}
	if err := environment.SetMemoOnStart(map[string]interface{}{
		investigationworkflow.RuntimeMemoIdentityKeyV2: json.RawMessage(payload.Data),
	}); err != nil {
		t.Fatalf("SetMemoOnStart() error = %v", err)
	}
	return environment
}

func validRuntimeV2WorkflowInput() investigationworkflow.WorkflowInputV2 {
	return investigationworkflow.WorkflowInputV2{
		Version:       investigationworkflow.RuntimeV2SchemaVersion,
		OutboxEventID: runtimeV2Outbox, TenantID: runtimeV2Tenant,
		WorkspaceID: runtimeV2Workspace, SignalID: runtimeV2Signal, AggregateVersion: 1,
		ManifestDigest: strings.Repeat("1", 64), RegistryDigest: strings.Repeat("2", 64),
		BundleDigest: strings.Repeat("5", 64),
	}
}

func validRuntimeV2PreparationReceipt() investigationworkflow.PreparationReceiptV2 {
	return investigationworkflow.PreparationReceiptV2{
		Version: investigationworkflow.RuntimeV2SchemaVersion, State: investigationworkflow.StatePrepared,
		OutboxEventID: runtimeV2Outbox, TenantID: runtimeV2Tenant,
		WorkspaceID: runtimeV2Workspace, SignalID: runtimeV2Signal,
		IncidentID: runtimeV2Incident, EnvironmentID: runtimeV2Environment, ServiceID: runtimeV2Service,
		InvestigationID: runtimeV2Investigation,
		Tasks: []investigationworkflow.ReadTaskReferenceV2{
			{TaskID: runtimeV2TaskOne, Position: 1}, {TaskID: runtimeV2TaskTwo, Position: 2},
		},
		ManifestDigest: strings.Repeat("1", 64), RegistryDigest: strings.Repeat("2", 64),
		BundleDigest:  strings.Repeat("5", 64),
		ProfileDigest: strings.Repeat("3", 64), TasksHash: strings.Repeat("4", 64),
	}
}

type runtimeV2PrepareActivity func(
	context.Context,
	investigationworkflow.WorkflowInputV2,
) (investigationworkflow.PreparationReceiptV2, error)

type runtimeV2RunnerActivity func(
	context.Context,
	investigationworkflow.ReadTaskActivityInputV1,
) (investigationworkflow.ReadTaskActivityOutputV1, error)

type runtimeV2RecoveryActivity func(
	context.Context,
	investigationworkflow.RecoveryActivityInput,
) (investigationworkflow.RecoveryActivityOutput, error)

func registerRuntimeV2TestProtocol(
	environment *testsuite.TestWorkflowEnvironment,
	prepare runtimeV2PrepareActivity,
	runner runtimeV2RunnerActivity,
	recovery runtimeV2RecoveryActivity,
) {
	environment.RegisterWorkflowWithOptions(
		investigationworkflow.ReadWorkflowV2ForTest,
		workflow.RegisterOptions{Name: investigationworkflow.WorkflowNameV2},
	)
	environment.RegisterActivityWithOptions(prepare, activity.RegisterOptions{Name: investigationworkflow.PrepareActivityNameV2})
	environment.RegisterActivityWithOptions(runner, activity.RegisterOptions{Name: investigationworkflow.ExecuteActivityNameV1})
	environment.RegisterActivityWithOptions(recovery, activity.RegisterOptions{Name: investigationworkflow.RecoveryActivityNameV1})
}

func fixedRuntimeV2Prepare(prepared investigationworkflow.PreparationReceiptV2) runtimeV2PrepareActivity {
	return func(context.Context, investigationworkflow.WorkflowInputV2) (investigationworkflow.PreparationReceiptV2, error) {
		return prepared, nil
	}
}

func oneTaskRuntimeV2PreparationReceipt() investigationworkflow.PreparationReceiptV2 {
	prepared := validRuntimeV2PreparationReceipt()
	prepared.Tasks = prepared.Tasks[:1]
	return prepared
}

func runtimeV2RunnerInput(
	prepared investigationworkflow.PreparationReceiptV2,
	round int,
) investigationworkflow.ReadTaskActivityInputV1 {
	return investigationworkflow.ReadTaskActivityInputV1{
		Version:       investigationworkflow.ReadTaskActivitySchemaVersion,
		OutboxEventID: prepared.OutboxEventID,
		TenantID:      prepared.TenantID, WorkspaceID: prepared.WorkspaceID,
		EnvironmentID: prepared.EnvironmentID, ServiceID: prepared.ServiceID,
		IncidentID: prepared.IncidentID, InvestigationID: prepared.InvestigationID,
		TaskID: prepared.Tasks[0].TaskID, Position: prepared.Tasks[0].Position,
		ManifestDigest: prepared.ManifestDigest, RegistryDigest: prepared.RegistryDigest,
		BundleDigest: prepared.BundleDigest, ProfileDigest: prepared.ProfileDigest,
		TasksHash: prepared.TasksHash, Round: round,
	}
}

func runnerOutput(
	input investigationworkflow.ReadTaskActivityInputV1,
	state string,
) investigationworkflow.ReadTaskActivityOutputV1 {
	return investigationworkflow.ReadTaskActivityOutputV1{
		Version: investigationworkflow.ReadTaskActivitySchemaVersion, State: state,
		InvestigationID: input.InvestigationID, TaskID: input.TaskID,
		Position: input.Position, Round: input.Round,
	}
}

func pendingRecoveryOutput(input investigationworkflow.RecoveryActivityInput) investigationworkflow.RecoveryActivityOutput {
	return investigationworkflow.RecoveryActivityOutput{
		Version: investigationworkflow.RecoveryActivitySchemaVersion,
		State:   readtask.RecoveryPending, InvestigationID: input.InvestigationID,
		TaskID: input.TaskID, Position: input.Position, TaskStatus: domain.ReadTaskQueued,
	}
}

func failedRecoveryOutput(input investigationworkflow.RecoveryActivityInput) investigationworkflow.RecoveryActivityOutput {
	return investigationworkflow.RecoveryActivityOutput{
		Version: investigationworkflow.RecoveryActivitySchemaVersion,
		State:   readtask.RecoveryCommitted, InvestigationID: input.InvestigationID,
		TaskID: input.TaskID, Position: input.Position, TaskStatus: domain.ReadTaskFailed,
	}
}
