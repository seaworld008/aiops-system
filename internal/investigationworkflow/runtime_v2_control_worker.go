package investigationworkflow

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

const (
	runtimeV2ControlMaxActivities = 16
	runtimeV2ControlMaxWorkflows  = 32
	runtimeV2ControlPollers       = 2
	runtimeV2ControlStopTimeout   = 35 * time.Second
)

var ErrRuntimeV2ControlWorkerRejected = errors.New("investigation READ control worker rejected")

type runtimeV2ControlWorkerRuntime interface {
	temporalWorkerLifecycle
	RuntimeV2Registry
}

type runtimeV2ControlWorkerFactory func(
	client.Client,
	string,
	worker.Options,
) runtimeV2ControlWorkerRuntime

type runtimeV2ControlWorkerPhase uint8

const (
	runtimeV2ControlWorkerNew runtimeV2ControlWorkerPhase = iota
	runtimeV2ControlWorkerStarting
	runtimeV2ControlWorkerRunning
	runtimeV2ControlWorkerStopping
	runtimeV2ControlWorkerStopped
)

type runtimeV2ControlWorkerState struct {
	mu               sync.Mutex
	phase            runtimeV2ControlWorkerPhase
	stopRequested    bool
	terminalRejected bool
	startDone        chan struct{}
	startDoneOnce    sync.Once
	stopDone         chan struct{}
	stopOnce         sync.Once
	stopErr          error
	fatal            chan struct{}
	fatalOnce        sync.Once
	fatalSet         atomic.Bool
}

func newRuntimeV2ControlWorkerState() *runtimeV2ControlWorkerState {
	return &runtimeV2ControlWorkerState{
		startDone: make(chan struct{}),
		stopDone:  make(chan struct{}),
		fatal:     make(chan struct{}),
	}
}

func (state *runtimeV2ControlWorkerState) recordFatal(error) {
	if state == nil {
		return
	}
	state.fatalSet.Store(true)
	state.fatalOnce.Do(func() { close(state.fatal) })
}

func runtimeV2ControlWorkerOptions(state *runtimeV2ControlWorkerState) worker.Options {
	return worker.Options{
		MaxConcurrentActivityExecutionSize:      runtimeV2ControlMaxActivities,
		WorkerActivitiesPerSecond:               runtimeV2ControlMaxActivities,
		MaxConcurrentLocalActivityExecutionSize: 1,
		WorkerLocalActivitiesPerSecond:          1,
		MaxConcurrentActivityTaskPollers:        runtimeV2ControlPollers,
		MaxConcurrentWorkflowTaskExecutionSize:  runtimeV2ControlMaxWorkflows,
		MaxConcurrentWorkflowTaskPollers:        runtimeV2ControlPollers,
		WorkerStopTimeout:                       runtimeV2ControlStopTimeout,
		DeadlockDetectionTimeout:                time.Second,
		MaxHeartbeatThrottleInterval:            5 * time.Second,
		DefaultHeartbeatThrottleInterval:        5 * time.Second,
		OnFatalError:                            state.recordFatal,
		DisableEagerActivities:                  true,
		DisableRegistrationAliasing:             true,
	}
}

type runtimeV2ControlWorkerMarker struct{ value byte }

var sealedRuntimeV2ControlWorkerMarker = &runtimeV2ControlWorkerMarker{value: 1}

// RuntimeV2ControlWorker is the terminal lifecycle boundary for one exact
// control queue. Registration and the raw SDK Worker remain package-owned.
type RuntimeV2ControlWorker struct {
	worker runtimeV2ControlWorkerRuntime
	client *RuntimeV2ControlClient
	state  *runtimeV2ControlWorkerState
	seal   *runtimeV2ControlWorkerMarker
	self   *RuntimeV2ControlWorker
}

func (controlWorker *RuntimeV2ControlWorker) structurallyValid() bool {
	return controlWorker != nil && controlWorker.self == controlWorker &&
		controlWorker.seal == sealedRuntimeV2ControlWorkerMarker &&
		!nilInterface(controlWorker.worker) && controlWorker.client.structurallyValid() &&
		controlWorker.state != nil && controlWorker.state.startDone != nil &&
		controlWorker.state.stopDone != nil && controlWorker.state.fatal != nil
}

func runtimeV2ProductionControlWorkerFactory(
	sdk client.Client,
	queue string,
	options worker.Options,
) runtimeV2ControlWorkerRuntime {
	created := worker.New(sdk, queue, options)
	if created == nil {
		return nil
	}
	return created
}

func newRuntimeV2ControlWorker(
	controlClient *RuntimeV2ControlClient,
	activities *RuntimeV2Activities,
	manifestDigest string,
	registryDigest string,
	bundleDigest string,
	factory runtimeV2ControlWorkerFactory,
) (created *RuntimeV2ControlWorker, returnedErr error) {
	var runtime runtimeV2ControlWorkerRuntime
	defer func() {
		if recover() != nil {
			stopRuntimeV2Worker(runtime)
			created = nil
			returnedErr = ErrRuntimeV2ControlWorkerRejected
		}
	}()
	if !controlClient.valid() || !activities.ready() || factory == nil ||
		!domain.ValidSHA256Hex(manifestDigest) || !domain.ValidSHA256Hex(registryDigest) ||
		!domain.ValidSHA256Hex(bundleDigest) || activities.namespace != controlClient.namespaceValue() ||
		!sameRuntimeV2Digest(activities.preparation.planner.ManifestDigest(), manifestDigest) ||
		!sameRuntimeV2Digest(activities.preparation.planner.RegistryDigest(), registryDigest) ||
		!sameRuntimeV2Digest(activities.bundleDigest, bundleDigest) {
		return nil, ErrRuntimeV2ControlWorkerRejected
	}
	queue, err := ControlTaskQueue(manifestDigest, registryDigest, bundleDigest)
	if err != nil {
		return nil, ErrRuntimeV2ControlWorkerRejected
	}
	state := newRuntimeV2ControlWorkerState()
	runtime = factory(controlClient.sdkValue(), queue, runtimeV2ControlWorkerOptions(state))
	if nilInterface(runtime) {
		return nil, ErrRuntimeV2ControlWorkerRejected
	}
	if err := registerRuntimeV2(runtime, activities); err != nil {
		stopRuntimeV2Worker(runtime)
		return nil, ErrRuntimeV2ControlWorkerRejected
	}
	created = &RuntimeV2ControlWorker{
		worker: runtime, client: controlClient, state: state,
		seal: sealedRuntimeV2ControlWorkerMarker,
	}
	created.self = created
	if !created.structurallyValid() {
		stopRuntimeV2Worker(runtime)
		return nil, ErrRuntimeV2ControlWorkerRejected
	}
	return created, nil
}

func sameRuntimeV2Digest(left, right string) bool {
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func stopRuntimeV2Worker(runtime temporalWorkerLifecycle) {
	defer func() { _ = recover() }()
	if !nilInterface(runtime) {
		runtime.Stop()
	}
}

func (controlWorker *RuntimeV2ControlWorker) Start() (returnedErr error) {
	if !controlWorker.structurallyValid() {
		return ErrRuntimeV2ControlWorkerRejected
	}
	state := controlWorker.state
	state.mu.Lock()
	if state.phase != runtimeV2ControlWorkerNew || state.fatalSet.Load() || !controlWorker.client.valid() {
		state.mu.Unlock()
		return ErrRuntimeV2ControlWorkerRejected
	}
	state.phase = runtimeV2ControlWorkerStarting
	state.mu.Unlock()

	startErr := startRuntimeV2WorkerWithError(controlWorker.worker)
	state.mu.Lock()
	fatal := state.fatalSet.Load()
	stopRequested := state.stopRequested
	if startErr != nil {
		state.terminalRejected = true
	}
	if startErr != nil || fatal || stopRequested {
		state.phase = runtimeV2ControlWorkerStopping
	} else {
		state.phase = runtimeV2ControlWorkerRunning
	}
	state.startDoneOnce.Do(func() { close(state.startDone) })
	state.mu.Unlock()

	if fatal {
		// Temporal owns automatic cleanup after OnFatalError returns. Calling
		// Stop here would race the SDK's own non-concurrent Stop path.
		return ErrRuntimeV2ControlWorkerRejected
	}
	if startErr != nil {
		_ = controlWorker.finishStop()
		return ErrRuntimeV2ControlWorkerRejected
	}
	if stopRequested {
		_ = controlWorker.finishStop()
		return ErrRuntimeV2ControlWorkerRejected
	}
	return nil
}

func (controlWorker *RuntimeV2ControlWorker) Stop() error {
	if !controlWorker.structurallyValid() {
		return ErrRuntimeV2ControlWorkerRejected
	}
	state := controlWorker.state
	for {
		state.mu.Lock()
		if state.phase == runtimeV2ControlWorkerStopped {
			state.mu.Unlock()
			return controlWorker.finishStop()
		}
		if state.fatalSet.Load() {
			state.mu.Unlock()
			return ErrRuntimeV2ControlWorkerRejected
		}
		switch state.phase {
		case runtimeV2ControlWorkerNew:
			state.phase = runtimeV2ControlWorkerStopping
			state.startDoneOnce.Do(func() { close(state.startDone) })
			state.mu.Unlock()
			return controlWorker.finishStop()
		case runtimeV2ControlWorkerStarting:
			state.stopRequested = true
			startDone := state.startDone
			state.mu.Unlock()
			<-startDone
			continue
		case runtimeV2ControlWorkerRunning:
			state.phase = runtimeV2ControlWorkerStopping
			state.mu.Unlock()
			return controlWorker.finishStop()
		case runtimeV2ControlWorkerStopping:
			state.mu.Unlock()
			return controlWorker.finishStop()
		default:
			state.mu.Unlock()
			return ErrRuntimeV2ControlWorkerRejected
		}
	}
}

func startRuntimeV2WorkerWithError(runtime temporalWorkerLifecycle) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = ErrRuntimeV2ControlWorkerRejected
		}
	}()
	if nilInterface(runtime) {
		return ErrRuntimeV2ControlWorkerRejected
	}
	if err := runtime.Start(); err != nil {
		return ErrRuntimeV2ControlWorkerRejected
	}
	return nil
}

func (controlWorker *RuntimeV2ControlWorker) finishStop() error {
	state := controlWorker.state
	if state.fatalSet.Load() {
		return ErrRuntimeV2ControlWorkerRejected
	}
	state.stopOnce.Do(func() {
		stopErr := stopRuntimeV2WorkerWithError(controlWorker.worker)
		state.mu.Lock()
		if stopErr != nil || state.terminalRejected {
			state.stopErr = ErrRuntimeV2ControlWorkerRejected
		} else {
			state.stopErr = nil
		}
		state.phase = runtimeV2ControlWorkerStopped
		close(state.stopDone)
		state.mu.Unlock()
	})
	<-state.stopDone
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.stopErr
}

func stopRuntimeV2WorkerWithError(runtime temporalWorkerLifecycle) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = ErrRuntimeV2ControlWorkerRejected
		}
	}()
	if nilInterface(runtime) {
		return ErrRuntimeV2ControlWorkerRejected
	}
	runtime.Stop()
	return nil
}

// Fatal closes when the SDK reports a fatal worker error. It deliberately
// carries no raw error material. Temporal owns automatic Worker cleanup after
// its callback returns; a supervisor must mark the process unhealthy and must
// not call Stop or close either client solely in response to this signal.
func (controlWorker *RuntimeV2ControlWorker) Fatal() <-chan struct{} {
	if !controlWorker.structurallyValid() {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return controlWorker.state.fatal
}

func (RuntimeV2ControlWorker) String() string {
	return "<aiops-runtime-v2-control-worker>"
}

func (RuntimeV2ControlWorker) GoString() string {
	return "<aiops-runtime-v2-control-worker>"
}

func (RuntimeV2ControlWorker) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-runtime-v2-control-worker>")
}

func (RuntimeV2ControlWorker) MarshalJSON() ([]byte, error) {
	return nil, ErrRuntimeV2ControlWorkerRejected
}

func (*RuntimeV2ControlWorker) UnmarshalJSON([]byte) error {
	return ErrRuntimeV2ControlWorkerRejected
}

var _ json.Marshaler = (*RuntimeV2ControlWorker)(nil)
