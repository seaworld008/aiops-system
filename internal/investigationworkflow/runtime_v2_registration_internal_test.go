package investigationworkflow

import (
	"testing"

	"github.com/seaworld008/aiops-system/internal/investigationplan"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/workflow"
)

func TestRuntimeV2RegistrationIsExplicitAndRunnerOptionsAreFailClosed(t *testing.T) {
	authority := investigationplan.NewScopeAuthority()
	planner := internalWorkerPlanner(t, authority)
	activities, err := NewRuntimeV2Activities(
		&Activities{
			reader: &embeddedSignalReader{}, repository: &embeddedPreparationRepository{},
			authority: authority, planner: planner,
		},
		&RecoveryActivities{reader: runtimeV2PendingRecoveryReader{}},
		inputBundleDigestForRuntimeV2Test,
		"default",
	)
	if err != nil {
		t.Fatalf("NewRuntimeV2Activities() error = %v", err)
	}
	registry := &runtimeV2CaptureRegistry{}
	if err := RegisterRuntimeV2(registry, activities); err != nil {
		t.Fatalf("RegisterRuntimeV2() error = %v", err)
	}
	if len(registry.workflows) != 1 || registry.workflows[0].Name != WorkflowNameV2 {
		t.Fatalf("registered Workflows = %#v", registry.workflows)
	}
	if len(registry.activities) != 2 || registry.activities[0].Name != PrepareActivityNameV2 ||
		registry.activities[1].Name != RecoveryActivityNameV1 {
		t.Fatalf("registered Activities = %#v", registry.activities)
	}
	options := runnerActivityOptionsV1("runner-queue", "read-execute-r1-p1-10101010-1010-4010-8010-101010101010")
	if options.RetryPolicy == nil || options.RetryPolicy.MaximumAttempts != 1 ||
		!options.WaitForCancellation || !options.DisableEagerExecution {
		t.Fatalf("Runner Activity trust options = %#v", options)
	}
}

type runtimeV2CaptureRegistry struct {
	workflows  []workflow.RegisterOptions
	activities []activity.RegisterOptions
}

func (registry *runtimeV2CaptureRegistry) RegisterWorkflowWithOptions(_ interface{}, options workflow.RegisterOptions) {
	registry.workflows = append(registry.workflows, options)
}

func (registry *runtimeV2CaptureRegistry) RegisterActivityWithOptions(_ interface{}, options activity.RegisterOptions) {
	registry.activities = append(registry.activities, options)
}
