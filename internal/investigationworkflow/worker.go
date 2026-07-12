package investigationworkflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

type temporalRegistry interface {
	RegisterWorkflowWithOptions(interface{}, workflow.RegisterOptions)
	RegisterActivityWithOptions(interface{}, activity.RegisterOptions)
}

func workerOptions() worker.Options {
	return worker.Options{
		DisableRegistrationAliasing: true,
		DisableEagerActivities:      true,
		WorkerStopTimeout:           35 * time.Second,
	}
}

func register(registry temporalRegistry, activities *Activities) (returnedErr error) {
	if nilInterface(registry) || !activities.ready() {
		return ErrInvalidInput
	}
	defer func() {
		if recover() != nil {
			returnedErr = errors.New("investigation preparation registration rejected")
		}
	}()
	registry.RegisterWorkflowWithOptions(preparationWorkflow, workflow.RegisterOptions{Name: WorkflowName})
	registry.RegisterActivityWithOptions(activities.prepareActivity, activity.RegisterOptions{Name: ActivityName})
	return nil
}

type temporalWorkerMarker struct{ value byte }

var sealedTemporalWorkerMarker = &temporalWorkerMarker{value: 1}

type temporalWorkerLifecycle interface {
	Start() error
	Stop()
}

type temporalWorkerState uint8

const (
	temporalWorkerStateNew temporalWorkerState = iota
	temporalWorkerStateStarting
	temporalWorkerStateRunning
	temporalWorkerStateStopped
)

var errTemporalWorkerLifecycleRejected = errors.New("investigation preparation worker lifecycle rejected")

type temporalWorkerRuntimeState struct {
	mu      sync.Mutex
	state   temporalWorkerState
	stopErr error
}

// TemporalWorker exposes lifecycle only; registration remains package-owned.
type TemporalWorker struct {
	worker  temporalWorkerLifecycle
	client  *TemporalClient
	seal    *temporalWorkerMarker
	self    *TemporalWorker
	runtime *temporalWorkerRuntimeState
}

func (temporalWorker *TemporalWorker) valid() bool {
	return temporalWorker != nil && temporalWorker.seal == sealedTemporalWorkerMarker &&
		temporalWorker.self == temporalWorker && !nilInterface(temporalWorker.worker) &&
		temporalWorker.client.structurallyValidForWorker() && temporalWorker.runtime != nil
}

func (temporalWorker *TemporalWorker) Start() (returnedErr error) {
	if !temporalWorker.valid() {
		return ErrInvalidInput
	}
	runtime := temporalWorker.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.state == temporalWorkerStateStopped ||
		runtime.state == temporalWorkerStateStarting ||
		runtime.state == temporalWorkerStateRunning {
		return ErrInvalidInput
	}
	if !temporalWorker.client.validForWorker() {
		return ErrInvalidInput
	}
	runtime.state = temporalWorkerStateStarting
	defer func() {
		if recover() != nil {
			_ = temporalWorker.stopWorkerNoPanic()
			runtime.stopErr = errTemporalWorkerLifecycleRejected
			runtime.state = temporalWorkerStateStopped
			returnedErr = errTemporalWorkerLifecycleRejected
			return
		}
		if returnedErr != nil {
			_ = temporalWorker.stopWorkerNoPanic()
			runtime.stopErr = errTemporalWorkerLifecycleRejected
			runtime.state = temporalWorkerStateStopped
			returnedErr = errTemporalWorkerLifecycleRejected
			return
		}
		runtime.state = temporalWorkerStateRunning
	}()
	return temporalWorker.worker.Start()
}

func (temporalWorker *TemporalWorker) Stop() error {
	if !temporalWorker.valid() {
		return ErrInvalidInput
	}
	runtime := temporalWorker.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.state == temporalWorkerStateStopped {
		return runtime.stopErr
	}
	runtime.state = temporalWorkerStateStopped
	runtime.stopErr = temporalWorker.stopWorkerNoPanic()
	return runtime.stopErr
}

// stopWorkerNoPanic is called only while mu is held. The SDK worker may have
// partially started before returning an error or panicking, so every failed
// Start still gets one best-effort cleanup without exposing an SDK panic to a
// supervisor.
func (temporalWorker *TemporalWorker) stopWorkerNoPanic() (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = errTemporalWorkerLifecycleRejected
		}
	}()
	temporalWorker.worker.Stop()
	return nil
}

func (*TemporalWorker) String() string   { return "<aiops-temporal-worker>" }
func (*TemporalWorker) GoString() string { return "<aiops-temporal-worker>" }
func (*TemporalWorker) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-temporal-worker>")
}
func (*TemporalWorker) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }
func (*TemporalWorker) UnmarshalJSON([]byte) error   { return ErrInvalidInput }

var _ json.Marshaler = (*TemporalWorker)(nil)

func NewWorker(
	temporalClient *TemporalClient,
	activities *Activities,
	manifestDigest string,
	registryDigest string,
) (*TemporalWorker, error) {
	if !temporalClient.validForWorker() || !activities.ready() ||
		activities.planner.ManifestDigest() != manifestDigest || activities.planner.RegistryDigest() != registryDigest {
		return nil, ErrInvalidInput
	}
	queue, err := TaskQueue(manifestDigest, registryDigest)
	if err != nil {
		return nil, ErrInvalidInput
	}
	created := worker.New(temporalClient.sdk, queue, workerOptions())
	if created == nil {
		return nil, ErrInvalidInput
	}
	if err := register(created, activities); err != nil {
		return nil, err
	}
	temporalWorker := &TemporalWorker{
		worker: created, client: temporalClient, seal: sealedTemporalWorkerMarker,
		runtime: &temporalWorkerRuntimeState{},
	}
	temporalWorker.self = temporalWorker
	return temporalWorker, nil
}
