package investigationworkflow

import (
	"errors"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

type TemporalRegistry interface {
	RegisterWorkflowWithOptions(interface{}, workflow.RegisterOptions)
	RegisterActivityWithOptions(interface{}, activity.RegisterOptions)
}

func WorkerOptions() worker.Options {
	return worker.Options{DisableRegistrationAliasing: true, DisableEagerActivities: true}
}

func Register(registry TemporalRegistry, activities *Activities) (returnedErr error) {
	if nilInterface(registry) || activities == nil || nilInterface(activities.reader) ||
		nilInterface(activities.repository) || activities.authority == nil || activities.planner == nil || !activities.planner.Ready() {
		return ErrInvalidInput
	}
	defer func() {
		if recover() != nil {
			returnedErr = errors.New("investigation preparation registration rejected")
		}
	}()
	registry.RegisterWorkflowWithOptions(PreparationWorkflow, workflow.RegisterOptions{Name: WorkflowName})
	registry.RegisterActivityWithOptions(activities.Prepare, activity.RegisterOptions{Name: ActivityName})
	return nil
}

func NewWorker(
	temporalClient client.Client,
	activities *Activities,
	manifestDigest string,
	registryDigest string,
) (worker.Worker, error) {
	if nilInterface(temporalClient) || activities == nil || activities.planner == nil ||
		activities.planner.ManifestDigest() != manifestDigest || activities.planner.RegistryDigest() != registryDigest {
		return nil, ErrInvalidInput
	}
	queue, err := TaskQueue(manifestDigest, registryDigest)
	if err != nil {
		return nil, ErrInvalidInput
	}
	created := worker.New(temporalClient, queue, WorkerOptions())
	if created == nil {
		return nil, ErrInvalidInput
	}
	if err := Register(created, activities); err != nil {
		return nil, err
	}
	return created, nil
}
