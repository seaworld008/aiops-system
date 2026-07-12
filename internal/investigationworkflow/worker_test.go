package investigationworkflow_test

import (
	"reflect"
	"testing"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/workflow"

	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
)

func TestRegisterUsesOnlyExplicitWorkflowAndActivityNames(t *testing.T) {
	fixture := newActivityFixture(t, "firing")
	registry := &fakeTemporalRegistry{}
	if err := investigationworkflow.Register(registry, fixture.activities); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if registry.workflowOptions.Name != investigationworkflow.WorkflowName || registry.activityOptions.Name != investigationworkflow.ActivityName ||
		reflect.ValueOf(registry.workflow).Pointer() != reflect.ValueOf(investigationworkflow.PreparationWorkflow).Pointer() ||
		reflect.ValueOf(registry.activity).Pointer() != reflect.ValueOf(fixture.activities.Prepare).Pointer() {
		t.Fatalf("registered workflow/activity = %#v/%#v options=%#v/%#v",
			registry.workflow, registry.activity, registry.workflowOptions, registry.activityOptions)
	}
	options := investigationworkflow.WorkerOptions()
	if !options.DisableRegistrationAliasing || !options.DisableEagerActivities {
		t.Fatalf("WorkerOptions trust gates = %#v", options)
	}
}

type fakeTemporalRegistry struct {
	workflow        interface{}
	workflowOptions workflow.RegisterOptions
	activity        interface{}
	activityOptions activity.RegisterOptions
}

func (registry *fakeTemporalRegistry) RegisterWorkflowWithOptions(value interface{}, options workflow.RegisterOptions) {
	registry.workflow, registry.workflowOptions = value, options
}

func (registry *fakeTemporalRegistry) RegisterActivityWithOptions(value interface{}, options activity.RegisterOptions) {
	registry.activity, registry.activityOptions = value, options
}
