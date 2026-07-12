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

// RegisterRuntimeV2 registers only the digest-bound control-plane protocol.
// It does not construct a Worker, Temporal client, Starter, Outbox dispatcher,
// or READ Runner and therefore cannot open claims by itself.
func RegisterRuntimeV2(
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
		activities.prepareActivityV2,
		activity.RegisterOptions{Name: PrepareActivityNameV2},
	)
	registry.RegisterActivityWithOptions(
		activities.recoverActivityV1,
		activity.RegisterOptions{Name: RecoveryActivityNameV1},
	)
	return nil
}
