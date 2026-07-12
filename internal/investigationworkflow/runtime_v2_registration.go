package investigationworkflow

import (
	"errors"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/workflow"
)

type RuntimeV2Registry interface {
	RegisterWorkflowWithOptions(interface{}, workflow.RegisterOptions)
	RegisterActivityWithOptions(interface{}, activity.RegisterOptions)
}

// registerRuntimeV2 is package-owned so production callers cannot combine the
// private Workflow/Activity methods with a raw SDK Worker. Tests reach it only
// through a _test bridge; the sealed control Worker is the production path.
func registerRuntimeV2(
	registry RuntimeV2Registry,
	activities *RuntimeV2Activities,
) (returnedErr error) {
	if nilInterface(registry) || !activities.ready() {
		return ErrInvalidRuntimeV2Input
	}
	defer func() {
		if recover() != nil {
			returnedErr = errors.New("investigation READ runtime registration rejected")
		}
	}()
	registry.RegisterWorkflowWithOptions(activities.readWorkflowV2, workflow.RegisterOptions{Name: WorkflowNameV2})
	registry.RegisterActivityWithOptions(
		activities.registeredPrepareActivityV2,
		activity.RegisterOptions{Name: PrepareActivityNameV2},
	)
	registry.RegisterActivityWithOptions(
		activities.registeredRecoverActivityV1,
		activity.RegisterOptions{Name: RecoveryActivityNameV1},
	)
	return nil
}
