package investigationworkflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/investigationplan"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

func TestRuntimeV2ControlWorkerBindsExactQueueRegistrationAndOptions(t *testing.T) {
	roleClient, activities, manifest, registry := newRuntimeV2ControlWorkerFixture(t, "default")
	runtime := &captureRuntimeV2ControlWorker{}
	var capturedSDK client.Client
	var queue string
	var options worker.Options
	created, err := newRuntimeV2ControlWorker(
		roleClient, activities, manifest, registry, inputBundleDigestForRuntimeV2Test,
		func(sdk client.Client, candidateQueue string, candidateOptions worker.Options) runtimeV2ControlWorkerRuntime {
			capturedSDK, queue, options = sdk, candidateQueue, candidateOptions
			return runtime
		},
	)
	if err != nil || created == nil || !created.structurallyValid() {
		t.Fatalf("newRuntimeV2ControlWorker() = %#v, %v", created, err)
	}
	wantQueue, err := ControlTaskQueue(manifest, registry, inputBundleDigestForRuntimeV2Test)
	if err != nil {
		t.Fatal(err)
	}
	if capturedSDK != roleClient.sdkValue() || queue != wantQueue {
		t.Fatalf("worker factory SDK/queue = %#v / %q", capturedSDK, queue)
	}
	if len(runtime.workflows) != 1 || runtime.workflows[0].Name != WorkflowNameV2 ||
		len(runtime.activities) != 2 || runtime.activities[0].Name != PrepareActivityNameV2 ||
		runtime.activities[1].Name != RecoveryActivityNameV1 {
		t.Fatalf("registered handlers = workflows:%#v activities:%#v", runtime.workflows, runtime.activities)
	}
	assertRuntimeV2ControlWorkerOptions(t, options)
	select {
	case <-created.Fatal():
		t.Fatal("Fatal channel is closed before an SDK fatal error")
	default:
	}
}

func TestRuntimeV2ControlWorkerRejectsIdentityRoleAndNamespaceDrift(t *testing.T) {
	roleClient, activities, manifest, registry := newRuntimeV2ControlWorkerFixture(t, "default")
	tests := map[string]func(**RuntimeV2ControlClient, **RuntimeV2Activities, *string, *string, *string, *runtimeV2ControlWorkerFactory){
		"nil client": func(client **RuntimeV2ControlClient, _ **RuntimeV2Activities, _, _, _ *string, _ *runtimeV2ControlWorkerFactory) {
			*client = nil
		},
		"zero client": func(client **RuntimeV2ControlClient, _ **RuntimeV2Activities, _, _, _ *string, _ *runtimeV2ControlWorkerFactory) {
			*client = &RuntimeV2ControlClient{}
		},
		"nil activities": func(_ **RuntimeV2ControlClient, value **RuntimeV2Activities, _, _, _ *string, _ *runtimeV2ControlWorkerFactory) {
			*value = nil
		},
		"foreign Plan": func(_ **RuntimeV2ControlClient, _ **RuntimeV2Activities, value, _, _ *string, _ *runtimeV2ControlWorkerFactory) {
			*value = digestForRuntimeV2ControlWorker('a')
		},
		"foreign Registry": func(_ **RuntimeV2ControlClient, _ **RuntimeV2Activities, _, value, _ *string, _ *runtimeV2ControlWorkerFactory) {
			*value = digestForRuntimeV2ControlWorker('b')
		},
		"foreign Bundle": func(_ **RuntimeV2ControlClient, _ **RuntimeV2Activities, _, _, value *string, _ *runtimeV2ControlWorkerFactory) {
			*value = digestForRuntimeV2ControlWorker('c')
		},
		"nil factory": func(_ **RuntimeV2ControlClient, _ **RuntimeV2Activities, _, _, _ *string, factory *runtimeV2ControlWorkerFactory) {
			*factory = nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidateClient, candidateActivities := roleClient, activities
			candidateManifest, candidateRegistry := manifest, registry
			candidateBundle := inputBundleDigestForRuntimeV2Test
			factory := runtimeV2ControlWorkerFactory(func(client.Client, string, worker.Options) runtimeV2ControlWorkerRuntime {
				t.Fatal("rejected identity reached Worker factory")
				return nil
			})
			mutate(
				&candidateClient, &candidateActivities, &candidateManifest, &candidateRegistry, &candidateBundle, &factory,
			)
			created, err := newRuntimeV2ControlWorker(
				candidateClient, candidateActivities, candidateManifest, candidateRegistry, candidateBundle, factory,
			)
			if created != nil || !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) {
				t.Fatalf("newRuntimeV2ControlWorker(%s) = %#v, %v", name, created, err)
			}
		})
	}

	_, foreignActivities, _, _ := newRuntimeV2ControlWorkerFixture(t, "other")
	if created, err := newRuntimeV2ControlWorker(
		roleClient, foreignActivities, manifest, registry, inputBundleDigestForRuntimeV2Test,
		func(client.Client, string, worker.Options) runtimeV2ControlWorkerRuntime {
			t.Fatal("foreign namespace reached Worker factory")
			return nil
		},
	); created != nil || !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) {
		t.Fatalf("newRuntimeV2ControlWorker(foreign namespace) = %#v, %v", created, err)
	}
}

func TestRuntimeV2ControlWorkerCleansPartialRuntimeOnConstructionFailure(t *testing.T) {
	roleClient, activities, manifest, registry := newRuntimeV2ControlWorkerFixture(t, "default")
	created, err := newRuntimeV2ControlWorker(
		roleClient, activities, manifest, registry, inputBundleDigestForRuntimeV2Test,
		func(client.Client, string, worker.Options) runtimeV2ControlWorkerRuntime { return nil },
	)
	if created != nil || !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) {
		t.Fatalf("newRuntimeV2ControlWorker(nil runtime) = %#v, %v", created, err)
	}

	runtime := &captureRuntimeV2ControlWorker{registrationPanic: "WORKER-SECRET-CANARY"}
	created, err = newRuntimeV2ControlWorker(
		roleClient, activities, manifest, registry, inputBundleDigestForRuntimeV2Test,
		func(client.Client, string, worker.Options) runtimeV2ControlWorkerRuntime { return runtime },
	)
	if created != nil || !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) ||
		containsRuntimeV2ControlWorkerCanary(err) || runtime.stops.Load() != 1 {
		t.Fatalf("newRuntimeV2ControlWorker(registration panic) = %#v, %v; stops=%d",
			created, err, runtime.stops.Load())
	}
	created, err = newRuntimeV2ControlWorker(
		roleClient, activities, manifest, registry, inputBundleDigestForRuntimeV2Test,
		func(client.Client, string, worker.Options) runtimeV2ControlWorkerRuntime {
			panic("WORKER-SECRET-CANARY")
		},
	)
	if created != nil || !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) ||
		containsRuntimeV2ControlWorkerCanary(err) {
		t.Fatalf("newRuntimeV2ControlWorker(factory panic) = %#v, %v", created, err)
	}
}

func TestRuntimeV2ControlWorkerLifecycleIsTerminalAndLowSensitive(t *testing.T) {
	roleClient, activities, manifest, registry := newRuntimeV2ControlWorkerFixture(t, "default")
	for name, configure := range map[string]func(*captureRuntimeV2ControlWorker){
		"start error": func(runtime *captureRuntimeV2ControlWorker) { runtime.startErr = errors.New("WORKER-SECRET-CANARY") },
		"start panic": func(runtime *captureRuntimeV2ControlWorker) { runtime.startPanic = "WORKER-SECRET-CANARY" },
	} {
		t.Run(name, func(t *testing.T) {
			runtime := &captureRuntimeV2ControlWorker{}
			configure(runtime)
			created := mustNewRuntimeV2ControlWorkerForTest(t, roleClient, activities, manifest, registry, runtime)
			err := created.Start()
			if !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) ||
				containsRuntimeV2ControlWorkerCanary(err) || runtime.starts.Load() != 1 || runtime.stops.Load() != 1 {
				t.Fatalf("Start() = %v; starts=%d stops=%d", err, runtime.starts.Load(), runtime.stops.Load())
			}
			if err := created.Start(); !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) || runtime.starts.Load() != 1 {
				t.Fatalf("second Start() = %v; starts=%d", err, runtime.starts.Load())
			}
			if err := created.Stop(); !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) || runtime.stops.Load() != 1 {
				t.Fatalf("Stop(after failed Start) = %v; stops=%d", err, runtime.stops.Load())
			}
		})
	}

	runtime := &captureRuntimeV2ControlWorker{}
	created := mustNewRuntimeV2ControlWorkerForTest(t, roleClient, activities, manifest, registry, runtime)
	if err := created.Start(); err != nil || runtime.starts.Load() != 1 {
		t.Fatalf("Start() = %v; starts=%d", err, runtime.starts.Load())
	}
	if err := created.Start(); !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) || runtime.starts.Load() != 1 {
		t.Fatalf("second Start() = %v; starts=%d", err, runtime.starts.Load())
	}
	if err := created.Stop(); err != nil || runtime.stops.Load() != 1 {
		t.Fatalf("Stop() = %v; stops=%d", err, runtime.stops.Load())
	}
	if err := created.Stop(); err != nil || runtime.stops.Load() != 1 {
		t.Fatalf("second Stop() = %v; stops=%d", err, runtime.stops.Load())
	}
}

func TestRuntimeV2ControlWorkerFatalSignalContainsNoSDKError(t *testing.T) {
	roleClient, activities, manifest, registry := newRuntimeV2ControlWorkerFixture(t, "default")
	runtime := &captureRuntimeV2ControlWorker{}
	created := mustNewRuntimeV2ControlWorkerForTest(t, roleClient, activities, manifest, registry, runtime)
	if err := created.Start(); err != nil {
		t.Fatal(err)
	}
	runtime.triggerFatal(errors.New("FATAL-SECRET-CANARY"))
	select {
	case <-created.Fatal():
	default:
		t.Fatal("Fatal channel remained open")
	}
	if err := created.Stop(); !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) || runtime.stops.Load() != 1 {
		t.Fatalf("Stop() = %v; stops=%d", err, runtime.stops.Load())
	}
	if rendered := fmt.Sprintf("%s %+v %#v", created, *created, *created); rendered !=
		"<aiops-runtime-v2-control-worker> <aiops-runtime-v2-control-worker> <aiops-runtime-v2-control-worker>" {
		t.Fatalf("formatted Worker = %q", rendered)
	}
	if _, err := json.Marshal(created); !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) {
		t.Fatalf("json.Marshal() error = %v", err)
	}
}

func TestRuntimeV2ControlWorkerStopIntentDoesNotHoldStateLockDuringSDKStart(t *testing.T) {
	roleClient, activities, manifest, registry := newRuntimeV2ControlWorkerFixture(t, "default")
	runtime := &captureRuntimeV2ControlWorker{
		startEntered: make(chan struct{}),
		startRelease: make(chan struct{}),
	}
	created := mustNewRuntimeV2ControlWorkerForTest(t, roleClient, activities, manifest, registry, runtime)
	firstStart := make(chan error, 1)
	go func() { firstStart <- created.Start() }()
	select {
	case <-runtime.startEntered:
	case <-time.After(time.Second):
		t.Fatal("Worker Start did not enter the SDK runtime")
	}
	stopResult := make(chan error, 1)
	go func() { stopResult <- created.Stop() }()
	intentDeadline := time.Now().Add(time.Second)
	for {
		created.state.mu.Lock()
		stopRequested := created.state.stopRequested
		created.state.mu.Unlock()
		if stopRequested {
			break
		}
		if time.Now().After(intentDeadline) {
			t.Fatal("Stop did not record its intent while SDK Start was blocked")
		}
		time.Sleep(time.Millisecond)
	}
	secondStart := make(chan error, 1)
	go func() { secondStart <- created.Start() }()
	select {
	case err := <-secondStart:
		if !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) {
			t.Fatalf("second Start() error = %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("second Start blocked behind the external SDK Start call")
	}
	if runtime.stops.Load() != 0 {
		t.Fatal("SDK Stop ran concurrently with SDK Start")
	}
	close(runtime.startRelease)
	if err := <-firstStart; !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) {
		t.Fatalf("first Start() error = %v", err)
	}
	if err := <-stopResult; err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if runtime.starts.Load() != 1 || runtime.stops.Load() != 1 {
		t.Fatalf("SDK lifecycle calls = %d/%d, want 1/1", runtime.starts.Load(), runtime.stops.Load())
	}
}

func TestRuntimeV2ControlWorkerConcurrentStartStopIsTerminal(t *testing.T) {
	roleClient, activities, manifest, registry := newRuntimeV2ControlWorkerFixture(t, "default")
	runtime := &captureRuntimeV2ControlWorker{
		startEntered: make(chan struct{}),
		startRelease: make(chan struct{}),
	}
	created := mustNewRuntimeV2ControlWorkerForTest(t, roleClient, activities, manifest, registry, runtime)
	firstStart := make(chan error, 1)
	go func() { firstStart <- created.Start() }()
	select {
	case <-runtime.startEntered:
	case <-time.After(time.Second):
		t.Fatal("Worker Start did not enter the SDK runtime")
	}

	const goroutines = 32
	results := make(chan error, goroutines)
	var group sync.WaitGroup
	for index := 0; index < goroutines; index++ {
		group.Add(1)
		go func(stop bool) {
			defer group.Done()
			if stop {
				results <- created.Stop()
				return
			}
			results <- created.Start()
		}(index%2 == 0)
	}
	close(runtime.startRelease)
	if err := <-firstStart; err != nil && !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) {
		t.Fatalf("first Start() error = %v", err)
	}
	group.Wait()
	close(results)
	for err := range results {
		if err != nil && !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) {
			t.Fatalf("concurrent lifecycle error = %v", err)
		}
	}
	if runtime.starts.Load() != 1 || runtime.stops.Load() != 1 {
		t.Fatalf("concurrent lifecycle starts/stops = %d/%d, want 1/1",
			runtime.starts.Load(), runtime.stops.Load())
	}
	if err := created.Start(); !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) {
		t.Fatalf("Start(after terminal Stop) error = %v", err)
	}
}

func TestRuntimeV2ControlWorkerStopPanicAndPreStartFatalFailClosed(t *testing.T) {
	roleClient, activities, manifest, registry := newRuntimeV2ControlWorkerFixture(t, "default")
	panicRuntime := &captureRuntimeV2ControlWorker{stopPanic: "WORKER-SECRET-CANARY"}
	panicWorker := mustNewRuntimeV2ControlWorkerForTest(
		t, roleClient, activities, manifest, registry, panicRuntime,
	)
	if err := panicWorker.Stop(); !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) ||
		containsRuntimeV2ControlWorkerCanary(err) || panicRuntime.stops.Load() != 1 {
		t.Fatalf("Stop(panic) = %v; stops=%d", err, panicRuntime.stops.Load())
	}
	if err := panicWorker.Stop(); !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) ||
		panicRuntime.stops.Load() != 1 {
		t.Fatalf("second Stop(panic) = %v; stops=%d", err, panicRuntime.stops.Load())
	}

	fatalRuntime := &captureRuntimeV2ControlWorker{}
	fatalWorker := mustNewRuntimeV2ControlWorkerForTest(
		t, roleClient, activities, manifest, registry, fatalRuntime,
	)
	fatalRuntime.triggerFatal(errors.New("WORKER-SECRET-CANARY"))
	if err := fatalWorker.Start(); !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) ||
		fatalRuntime.starts.Load() != 0 {
		t.Fatalf("Start(after pre-start fatal) = %v; starts=%d", err, fatalRuntime.starts.Load())
	}
	if err := fatalWorker.Stop(); !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) || fatalRuntime.stops.Load() != 1 {
		t.Fatalf("Stop(after pre-start fatal) = %v; stops=%d", err, fatalRuntime.stops.Load())
	}
}

func TestRuntimeV2ControlWorkerCopyAndClosedClientFailClosed(t *testing.T) {
	roleClient, activities, manifest, registry := newRuntimeV2ControlWorkerFixture(t, "default")
	runtime := &captureRuntimeV2ControlWorker{}
	created := mustNewRuntimeV2ControlWorkerForTest(t, roleClient, activities, manifest, registry, runtime)
	copy := *created
	if copy.structurallyValid() || !errors.Is(copy.Start(), ErrRuntimeV2ControlWorkerRejected) ||
		!errors.Is(copy.Stop(), ErrRuntimeV2ControlWorkerRejected) {
		t.Fatal("copied RuntimeV2ControlWorker retained lifecycle authority")
	}
	if err := roleClient.Close(); err != nil {
		t.Fatal(err)
	}
	if err := created.Start(); !errors.Is(err, ErrRuntimeV2ControlWorkerRejected) || runtime.starts.Load() != 0 {
		t.Fatalf("Start(closed client) = %v; starts=%d", err, runtime.starts.Load())
	}
	if err := created.Stop(); err != nil || runtime.stops.Load() != 1 {
		t.Fatalf("Stop(closed client) = %v; stops=%d", err, runtime.stops.Load())
	}
}

func assertRuntimeV2ControlWorkerOptions(t *testing.T, options worker.Options) {
	t.Helper()
	if options.MaxConcurrentActivityExecutionSize != runtimeV2ControlMaxActivities ||
		options.WorkerActivitiesPerSecond != runtimeV2ControlMaxActivities ||
		options.MaxConcurrentLocalActivityExecutionSize != 1 || options.WorkerLocalActivitiesPerSecond != 1 ||
		options.MaxConcurrentActivityTaskPollers != runtimeV2ControlPollers ||
		options.MaxConcurrentWorkflowTaskExecutionSize != runtimeV2ControlMaxWorkflows ||
		options.MaxConcurrentWorkflowTaskPollers != runtimeV2ControlPollers ||
		options.WorkerStopTimeout != runtimeV2ControlStopTimeout || options.DeadlockDetectionTimeout != time.Second ||
		options.MaxHeartbeatThrottleInterval != 5*time.Second ||
		options.DefaultHeartbeatThrottleInterval != 5*time.Second ||
		options.OnFatalError == nil || !options.DisableEagerActivities || !options.DisableRegistrationAliasing ||
		options.Identity != "" || len(options.Interceptors) != 0 || len(options.Plugins) != 0 ||
		options.EnableLoggingInReplay || options.EnableSessionWorker || options.DisableWorkflowWorker ||
		options.LocalActivityWorkerOnly {
		t.Fatalf("Runtime v2 control Worker options = %#v", options)
	}
}

func newRuntimeV2ControlWorkerFixture(
	t *testing.T,
	namespace string,
) (*RuntimeV2ControlClient, *RuntimeV2Activities, string, string) {
	t.Helper()
	roleClient, err := newRuntimeV2ControlClient(&inertTemporalSDKClient{}, namespace)
	if err != nil {
		t.Fatalf("newRuntimeV2ControlClient() error = %v", err)
	}
	authority := investigationplan.NewScopeAuthority()
	planner := internalWorkerPlanner(t, authority)
	activities, err := NewRuntimeV2Activities(
		&Activities{
			reader: &embeddedSignalReader{}, repository: &embeddedPreparationRepository{},
			authority: authority, planner: planner,
		},
		&RecoveryActivities{reader: runtimeV2PendingRecoveryReader{}},
		inputBundleDigestForRuntimeV2Test,
		namespace,
	)
	if err != nil {
		t.Fatalf("NewRuntimeV2Activities() error = %v", err)
	}
	return roleClient, activities, planner.ManifestDigest(), planner.RegistryDigest()
}

func mustNewRuntimeV2ControlWorkerForTest(
	t *testing.T,
	roleClient *RuntimeV2ControlClient,
	activities *RuntimeV2Activities,
	manifest string,
	registry string,
	runtime *captureRuntimeV2ControlWorker,
) *RuntimeV2ControlWorker {
	t.Helper()
	created, err := newRuntimeV2ControlWorker(
		roleClient, activities, manifest, registry, inputBundleDigestForRuntimeV2Test,
		func(_ client.Client, _ string, options worker.Options) runtimeV2ControlWorkerRuntime {
			runtime.options = options
			return runtime
		},
	)
	if err != nil {
		t.Fatalf("newRuntimeV2ControlWorker() error = %v", err)
	}
	return created
}

func digestForRuntimeV2ControlWorker(value byte) string {
	result := make([]byte, 64)
	for index := range result {
		result[index] = value
	}
	return string(result)
}

func containsRuntimeV2ControlWorkerCanary(err error) bool {
	return err != nil && strings.Contains(err.Error(), "WORKER-SECRET-CANARY")
}

type captureRuntimeV2ControlWorker struct {
	workflows         []workflow.RegisterOptions
	activities        []activity.RegisterOptions
	options           worker.Options
	starts            atomic.Int64
	stops             atomic.Int64
	startErr          error
	startPanic        any
	stopPanic         any
	registrationPanic any
	startEntered      chan struct{}
	startRelease      chan struct{}
	startOnce         sync.Once
	mu                sync.Mutex
}

func (runtime *captureRuntimeV2ControlWorker) RegisterWorkflowWithOptions(
	_ interface{}, options workflow.RegisterOptions,
) {
	if runtime.registrationPanic != nil {
		panic(runtime.registrationPanic)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.workflows = append(runtime.workflows, options)
}

func (runtime *captureRuntimeV2ControlWorker) RegisterActivityWithOptions(
	_ interface{}, options activity.RegisterOptions,
) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.activities = append(runtime.activities, options)
}

func (runtime *captureRuntimeV2ControlWorker) Start() error {
	runtime.starts.Add(1)
	if runtime.startEntered != nil {
		runtime.startOnce.Do(func() { close(runtime.startEntered) })
	}
	if runtime.startRelease != nil {
		<-runtime.startRelease
	}
	if runtime.startPanic != nil {
		panic(runtime.startPanic)
	}
	return runtime.startErr
}

func (runtime *captureRuntimeV2ControlWorker) Stop() {
	runtime.stops.Add(1)
	if runtime.stopPanic != nil {
		panic(runtime.stopPanic)
	}
}

// triggerFatal models Temporal SDK v1.46: it invokes OnFatalError and then
// owns the automatic Worker Stop after the callback returns.
func (runtime *captureRuntimeV2ControlWorker) triggerFatal(err error) {
	runtime.options.OnFatalError(err)
	runtime.Stop()
}
