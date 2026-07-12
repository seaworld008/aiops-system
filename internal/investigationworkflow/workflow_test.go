package investigationworkflow_test

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
)

const (
	workflowOutboxID        = "11111111-1111-4111-8111-111111111111"
	workflowTenantID        = "22222222-2222-4222-8222-222222222222"
	workflowWorkspace       = "33333333-3333-4333-8333-333333333333"
	workflowSignalID        = "44444444-4444-4444-8444-444444444444"
	workflowIncidentID      = "55555555-5555-4555-8555-555555555555"
	workflowInvestigationID = "66666666-6666-4666-8666-666666666666"
	workflowTaskID          = "77777777-7777-4777-8777-777777777777"
	workflowManifest        = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	workflowRegistry        = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	workflowProfile         = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	workflowTasks           = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

func TestPreparationWorkflowRunsOneExplicitActivityAndReturnsSafeReceipt(t *testing.T) {
	input := validWorkflowInput()
	receipt := validReceipt()
	environment := newWorkflowEnvironment()
	environment.SetStartWorkflowOptions(client.StartWorkflowOptions{ID: input.OutboxEventID, TaskQueue: mustTaskQueue(t, input)})
	environment.RegisterWorkflowWithOptions(investigationworkflow.PreparationWorkflow, workflow.RegisterOptions{Name: investigationworkflow.WorkflowName})
	environment.RegisterActivityWithOptions(func(context.Context, investigationworkflow.WorkflowInput) (investigationworkflow.PreparationReceipt, error) {
		return receipt, nil
	}, activity.RegisterOptions{Name: investigationworkflow.ActivityName})
	environment.ExecuteWorkflow(investigationworkflow.WorkflowName, input)
	if !environment.IsWorkflowCompleted() || environment.GetWorkflowError() != nil {
		t.Fatalf("workflow error = %v", environment.GetWorkflowError())
	}
	var got investigationworkflow.PreparationReceipt
	if err := environment.GetWorkflowResult(&got); err != nil || !reflect.DeepEqual(got, receipt) {
		t.Fatalf("workflow result = %#v, %v", got, err)
	}
}

func TestPreparationWorkflowRejectsReceiptTampering(t *testing.T) {
	for name, mutate := range map[string]func(*investigationworkflow.PreparationReceipt){
		"manifest": func(receipt *investigationworkflow.PreparationReceipt) {
			receipt.ManifestDigest = strings.Repeat("e", 64)
		},
		"registry": func(receipt *investigationworkflow.PreparationReceipt) {
			receipt.RegistryDigest = strings.Repeat("e", 64)
		},
		"missing profile": func(receipt *investigationworkflow.PreparationReceipt) { receipt.ProfileDigest = "" },
		"missing tasks":   func(receipt *investigationworkflow.PreparationReceipt) { receipt.TasksHash = "" },
		"workspace":       func(receipt *investigationworkflow.PreparationReceipt) { receipt.WorkspaceID = workflowTenantID },
		"task count":      func(receipt *investigationworkflow.PreparationReceipt) { receipt.TaskCount++ },
	} {
		t.Run(name, func(t *testing.T) {
			input := validWorkflowInput()
			receipt := validReceipt()
			mutate(&receipt)
			environment := newWorkflowEnvironment()
			environment.SetStartWorkflowOptions(client.StartWorkflowOptions{ID: input.OutboxEventID, TaskQueue: mustTaskQueue(t, input)})
			environment.RegisterWorkflowWithOptions(investigationworkflow.PreparationWorkflow, workflow.RegisterOptions{Name: investigationworkflow.WorkflowName})
			environment.RegisterActivityWithOptions(func(context.Context, investigationworkflow.WorkflowInput) (investigationworkflow.PreparationReceipt, error) {
				return receipt, nil
			}, activity.RegisterOptions{Name: investigationworkflow.ActivityName})
			environment.ExecuteWorkflow(investigationworkflow.WorkflowName, input)
			if environment.GetWorkflowError() == nil || strings.Contains(environment.GetWorkflowError().Error(), workflowIncidentID) {
				t.Fatalf("tampered workflow error = %v", environment.GetWorkflowError())
			}
		})
	}
}

func TestPreparationWorkflowRetriesLowSensitivityActivityError(t *testing.T) {
	input := validWorkflowInput()
	attempts := 0
	environment := newWorkflowEnvironment()
	environment.SetStartWorkflowOptions(client.StartWorkflowOptions{ID: input.OutboxEventID, TaskQueue: mustTaskQueue(t, input)})
	environment.RegisterWorkflowWithOptions(investigationworkflow.PreparationWorkflow, workflow.RegisterOptions{Name: investigationworkflow.WorkflowName})
	environment.RegisterActivityWithOptions(func(context.Context, investigationworkflow.WorkflowInput) (investigationworkflow.PreparationReceipt, error) {
		attempts++
		if attempts == 1 {
			return investigationworkflow.PreparationReceipt{}, temporal.NewApplicationError("preparation dependency unavailable", "PREPARE_DEPENDENCY_UNAVAILABLE")
		}
		return validReceipt(), nil
	}, activity.RegisterOptions{Name: investigationworkflow.ActivityName})
	environment.ExecuteWorkflow(investigationworkflow.WorkflowName, input)
	if err := environment.GetWorkflowError(); err != nil || attempts != 2 {
		t.Fatalf("workflow retries = %d, error = %v", attempts, err)
	}
}

func TestPreparationWorkflowRejectsInvalidInputBeforeActivity(t *testing.T) {
	for name, mutate := range invalidInputMutations() {
		t.Run(name, func(t *testing.T) {
			input := validWorkflowInput()
			mutate(&input)
			environment := newWorkflowEnvironment()
			environment.RegisterWorkflowWithOptions(investigationworkflow.PreparationWorkflow, workflow.RegisterOptions{Name: investigationworkflow.WorkflowName})
			environment.ExecuteWorkflow(investigationworkflow.WorkflowName, input)
			if environment.GetWorkflowError() == nil {
				t.Fatalf("invalid input succeeded")
			}
		})
	}
}

func invalidInputMutations() map[string]func(*investigationworkflow.WorkflowInput) {
	mutations := map[string]func(*investigationworkflow.WorkflowInput){
		"version zero":     func(input *investigationworkflow.WorkflowInput) { input.Version = 0 },
		"version future":   func(input *investigationworkflow.WorkflowInput) { input.Version = 2 },
		"outbox empty":     func(input *investigationworkflow.WorkflowInput) { input.OutboxEventID = "" },
		"tenant empty":     func(input *investigationworkflow.WorkflowInput) { input.TenantID = "" },
		"workspace empty":  func(input *investigationworkflow.WorkflowInput) { input.WorkspaceID = "" },
		"signal empty":     func(input *investigationworkflow.WorkflowInput) { input.SignalID = "" },
		"aggregate zero":   func(input *investigationworkflow.WorkflowInput) { input.AggregateVersion = 0 },
		"aggregate future": func(input *investigationworkflow.WorkflowInput) { input.AggregateVersion = 2 },
		"manifest empty":   func(input *investigationworkflow.WorkflowInput) { input.ManifestDigest = "" },
		"manifest uppercase": func(input *investigationworkflow.WorkflowInput) {
			input.ManifestDigest = strings.ToUpper(input.ManifestDigest)
		},
		"registry empty": func(input *investigationworkflow.WorkflowInput) { input.RegistryDigest = "" },
		"registry short": func(input *investigationworkflow.WorkflowInput) { input.RegistryDigest = "abc" },
	}
	for index := 0; index < 30; index++ {
		value := index
		mutations["invalid UUID variant "+string(rune('A'+index))] = func(input *investigationworkflow.WorkflowInput) {
			ids := []*string{&input.OutboxEventID, &input.TenantID, &input.WorkspaceID, &input.SignalID}
			*ids[value%len(ids)] = strings.Repeat("x", value+1)
		}
	}
	return mutations
}

func validWorkflowInput() investigationworkflow.WorkflowInput {
	return investigationworkflow.WorkflowInput{
		Version: investigationworkflow.SchemaVersion, OutboxEventID: workflowOutboxID, TenantID: workflowTenantID,
		WorkspaceID: workflowWorkspace, SignalID: workflowSignalID, AggregateVersion: 1,
		ManifestDigest: workflowManifest, RegistryDigest: workflowRegistry,
	}
}

func validReceipt() investigationworkflow.PreparationReceipt {
	return investigationworkflow.PreparationReceipt{
		Version: investigationworkflow.SchemaVersion, State: investigationworkflow.StatePrepared, OutboxEventID: workflowOutboxID,
		TenantID: workflowTenantID, WorkspaceID: workflowWorkspace, SignalID: workflowSignalID,
		IncidentID: workflowIncidentID, InvestigationID: workflowInvestigationID,
		TaskIDs: []string{workflowTaskID}, TaskCount: 1,
		ManifestDigest: workflowManifest, RegistryDigest: workflowRegistry,
		ProfileDigest: workflowProfile, TasksHash: workflowTasks,
	}
}

func mustTaskQueue(t *testing.T, input investigationworkflow.WorkflowInput) string {
	t.Helper()
	queue, err := investigationworkflow.TaskQueue(input.ManifestDigest, input.RegistryDigest)
	if err != nil {
		t.Fatalf("TaskQueue() error = %v", err)
	}
	if !strings.Contains(queue, input.ManifestDigest) || !strings.Contains(queue, input.RegistryDigest) {
		t.Fatalf("TaskQueue() = %q does not contain full digests", queue)
	}
	return queue
}

func newWorkflowEnvironment() *testsuite.TestWorkflowEnvironment {
	var suite testsuite.WorkflowTestSuite
	suite.SetDisableRegistrationAliasing(true)
	return suite.NewTestWorkflowEnvironment()
}

func TestPreparationWorkflowCancellationCannotInterruptDurablePreparation(t *testing.T) {
	input := validWorkflowInput()
	environment := newWorkflowEnvironment()
	environment.SetStartWorkflowOptions(client.StartWorkflowOptions{ID: input.OutboxEventID, TaskQueue: mustTaskQueue(t, input)})
	environment.RegisterWorkflowWithOptions(investigationworkflow.PreparationWorkflow, workflow.RegisterOptions{Name: investigationworkflow.WorkflowName})
	environment.RegisterActivityWithOptions(func(context.Context, investigationworkflow.WorkflowInput) (investigationworkflow.PreparationReceipt, error) {
		return validReceipt(), nil
	}, activity.RegisterOptions{Name: investigationworkflow.ActivityName})
	environment.OnActivity(investigationworkflow.ActivityName, mock.Anything, input).
		Return(validReceipt(), nil).After(2 * time.Second)
	cancelRequested := false
	environment.RegisterDelayedCallback(func() {
		cancelRequested = true
		environment.CancelWorkflow()
	}, time.Second)
	environment.ExecuteWorkflow(investigationworkflow.WorkflowName, input)
	if !cancelRequested || environment.GetWorkflowError() != nil {
		t.Fatalf("cancel request interrupted durable preparation: %v", environment.GetWorkflowError())
	}
}
