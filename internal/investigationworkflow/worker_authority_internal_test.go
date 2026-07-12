package investigationworkflow

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigationplan"
	"github.com/seaworld008/aiops-system/internal/readconnector"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/workflow"
)

func TestTemporalWorkerLifecycleIsTerminalAndCleansUpFailures(t *testing.T) {
	startFailure := errors.New("sensitive-sdk-start-canary")
	tests := map[string]struct {
		startErr   error
		startPanic interface{}
		stopPanic  interface{}
	}{
		"start error": {startErr: startFailure},
		"start panic": {startPanic: "sensitive-sdk-panic-canary"},
		"stop panic":  {stopPanic: "sensitive-sdk-stop-canary"},
		"start failure cleanup panic": {
			startErr: startFailure, stopPanic: "sensitive-sdk-cleanup-canary",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			lifecycle := &fakeTemporalWorkerLifecycle{
				startErr: test.startErr, startPanic: test.startPanic, stopPanic: test.stopPanic,
			}
			wrapped := newTemporalWorkerForLifecycleTest(t, lifecycle)
			startErr := wrapped.Start()
			if test.startErr != nil || test.startPanic != nil {
				if !errors.Is(startErr, errTemporalWorkerLifecycleRejected) ||
					strings.Contains(startErr.Error(), "canary") {
					t.Fatalf("Start() error = %v", startErr)
				}
			} else if startErr != nil {
				t.Fatalf("Start() error = %v", startErr)
			}
			firstStopErr := wrapped.Stop()
			secondStopErr := wrapped.Stop()
			if test.stopPanic != nil || test.startErr != nil || test.startPanic != nil {
				if !errors.Is(firstStopErr, errTemporalWorkerLifecycleRejected) ||
					!errors.Is(secondStopErr, errTemporalWorkerLifecycleRejected) ||
					strings.Contains(firstStopErr.Error(), "canary") || strings.Contains(secondStopErr.Error(), "canary") {
					t.Fatalf("Stop() errors = %v / %v", firstStopErr, secondStopErr)
				}
			} else if firstStopErr != nil || secondStopErr != nil {
				t.Fatalf("Stop() errors = %v / %v", firstStopErr, secondStopErr)
			}
			if err := wrapped.Start(); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Start(after terminal Stop) error = %v", err)
			}
			if got := lifecycle.starts.Load(); got != 1 {
				t.Fatalf("underlying Start calls = %d, want 1", got)
			}
			if got := lifecycle.stops.Load(); got != 1 {
				t.Fatalf("underlying Stop calls = %d, want 1", got)
			}
		})
	}
}

func TestTemporalWorkerStopBeforeStartIsTerminal(t *testing.T) {
	lifecycle := &fakeTemporalWorkerLifecycle{}
	wrapped := newTemporalWorkerForLifecycleTest(t, lifecycle)
	if err := wrapped.Stop(); err != nil {
		t.Fatalf("Stop(before Start) error = %v", err)
	}
	if err := wrapped.Stop(); err != nil {
		t.Fatalf("Stop(repeated) error = %v", err)
	}
	if err := wrapped.Start(); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Start(after Stop) error = %v", err)
	}
	if got := lifecycle.starts.Load(); got != 0 {
		t.Fatalf("underlying Start calls = %d, want 0", got)
	}
	if got := lifecycle.stops.Load(); got != 1 {
		t.Fatalf("underlying Stop calls = %d, want 1", got)
	}
}

func TestTemporalWorkerConcurrentStartStopIsSerialized(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	lifecycle := &fakeTemporalWorkerLifecycle{startEntered: entered, releaseStart: release}
	wrapped := newTemporalWorkerForLifecycleTest(t, lifecycle)

	startResult := make(chan error, 1)
	go func() { startResult <- wrapped.Start() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("underlying Start was not entered")
	}
	stopDone := make(chan error, 1)
	go func() {
		stopDone <- wrapped.Stop()
	}()
	select {
	case err := <-stopDone:
		t.Fatalf("Stop ran concurrently with in-flight Start: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-startResult:
		if err != nil {
			t.Fatalf("Start() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start did not finish")
	}
	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("Stop() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not finish after Start")
	}
	if got := lifecycle.starts.Load(); got != 1 {
		t.Fatalf("underlying Start calls = %d, want 1", got)
	}
	if got := lifecycle.stops.Load(); got != 1 {
		t.Fatalf("underlying Stop calls = %d, want 1", got)
	}
	if err := wrapped.Start(); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Start(after concurrent Stop) error = %v", err)
	}
}

func TestTemporalWorkerCopyAndClosedClientAreFailClosed(t *testing.T) {
	t.Run("copy", func(t *testing.T) {
		lifecycle := &fakeTemporalWorkerLifecycle{}
		wrapped := newTemporalWorkerForLifecycleTest(t, lifecycle)
		copyValue := reflect.New(reflect.TypeOf(wrapped).Elem())
		copyValue.Elem().Set(reflect.ValueOf(wrapped).Elem())
		copied := copyValue.Interface().(*TemporalWorker)
		if copied.valid() {
			t.Fatal("copied TemporalWorker passed its self seal")
		}
		if err := copied.Start(); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("copied.Start() error = %v", err)
		}
		if err := copied.Stop(); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("copied.Stop() error = %v", err)
		}
		if lifecycle.starts.Load() != 0 || lifecycle.stops.Load() != 0 {
			t.Fatalf("copied worker reached SDK lifecycle: starts=%d stops=%d", lifecycle.starts.Load(), lifecycle.stops.Load())
		}
		if err := wrapped.Stop(); err != nil {
			t.Fatalf("original.Stop() error = %v", err)
		}
		// Restore the pre-Stop shallow snapshot into the original address. The
		// shared private runtime state must remain terminal.
		reflect.ValueOf(wrapped).Elem().Set(copyValue.Elem())
		if err := wrapped.Stop(); err != nil {
			t.Fatalf("original.Stop(after snapshot restore) error = %v", err)
		}
		if err := wrapped.Start(); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("original.Start(after snapshot restore) error = %v", err)
		}
		if lifecycle.stops.Load() != 1 {
			t.Fatalf("snapshot restore repeated SDK Stop: %d", lifecycle.stops.Load())
		}
	})

	t.Run("closed client", func(t *testing.T) {
		lifecycle := &fakeTemporalWorkerLifecycle{}
		wrapped := newTemporalWorkerForLifecycleTest(t, lifecycle)
		if err := wrapped.client.Close(); err != nil {
			t.Fatalf("client.Close() error = %v", err)
		}
		if err := wrapped.Start(); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("Start(closed client) error = %v", err)
		}
		if lifecycle.starts.Load() != 0 {
			t.Fatalf("closed client reached SDK Start %d times", lifecycle.starts.Load())
		}
		if err := wrapped.Stop(); err != nil {
			t.Fatalf("Stop(after client Close) error = %v", err)
		}
		if lifecycle.stops.Load() != 1 {
			t.Fatalf("Stop(after client Close) calls = %d, want 1", lifecycle.stops.Load())
		}
	})
}

type fakeTemporalWorkerLifecycle struct {
	startErr     error
	startPanic   interface{}
	stopPanic    interface{}
	startEntered chan struct{}
	releaseStart chan struct{}
	enteredOnce  sync.Once
	starts       atomic.Int64
	stops        atomic.Int64
}

type inertTemporalStarterTransport struct{ temporalStarterTransport }

type inertTemporalSDKClient struct{ client.Client }

func (*inertTemporalSDKClient) Close() {}

func newTemporalWorkerForLifecycleTest(t *testing.T, lifecycle temporalWorkerLifecycle) *TemporalWorker {
	t.Helper()
	router, err := newMemoRoutingDataConverter(converter.GetDefaultDataConverter())
	if err != nil {
		t.Fatalf("newMemoRoutingDataConverter() error = %v", err)
	}
	temporalClient, err := newTemporalClient(
		&inertTemporalStarterTransport{}, &inertTemporalSDKClient{}, router, defaultTemporalNamespace,
	)
	if err != nil {
		t.Fatalf("newTemporalClient() error = %v", err)
	}
	wrapped := &TemporalWorker{
		worker: lifecycle, client: temporalClient, seal: sealedTemporalWorkerMarker,
		runtime: &temporalWorkerRuntimeState{},
	}
	wrapped.self = wrapped
	return wrapped
}

func (lifecycle *fakeTemporalWorkerLifecycle) Start() error {
	lifecycle.starts.Add(1)
	if lifecycle.startEntered != nil {
		lifecycle.enteredOnce.Do(func() { close(lifecycle.startEntered) })
	}
	if lifecycle.releaseStart != nil {
		<-lifecycle.releaseStart
	}
	if lifecycle.startPanic != nil {
		panic(lifecycle.startPanic)
	}
	return lifecycle.startErr
}

func (lifecycle *fakeTemporalWorkerLifecycle) Stop() {
	lifecycle.stops.Add(1)
	if lifecycle.stopPanic != nil {
		panic(lifecycle.stopPanic)
	}
}

func TestRegisterRejectsActivitiesWithForeignScopeAuthority(t *testing.T) {
	plannerAuthority := investigationplan.NewScopeAuthority()
	planner := internalWorkerPlanner(t, plannerAuthority)
	activities := &Activities{
		reader:     &embeddedSignalReader{},
		repository: &embeddedPreparationRepository{},
		authority:  investigationplan.NewScopeAuthority(),
		planner:    planner,
	}
	registry := &internalTemporalRegistry{}
	if err := register(registry, activities); err != ErrInvalidInput {
		t.Fatalf("register(foreign authority) error = %v, want ErrInvalidInput", err)
	}
	if registry.workflow != nil || registry.activity != nil {
		t.Fatalf("foreign authority registered runtime functions: %#v/%#v", registry.workflow, registry.activity)
	}
}

func TestRegisterUsesOnlyPrivateExplicitTargetsAndSafeOptions(t *testing.T) {
	authority := investigationplan.NewScopeAuthority()
	planner := internalWorkerPlanner(t, authority)
	activities := &Activities{
		reader: &embeddedSignalReader{}, repository: &embeddedPreparationRepository{}, authority: authority, planner: planner,
	}
	registry := &internalTemporalRegistry{}
	if err := register(registry, activities); err != nil {
		t.Fatalf("register() error = %v", err)
	}
	if registry.workflowOptions.Name != WorkflowName || registry.activityOptions.Name != ActivityName ||
		reflect.ValueOf(registry.workflow).Pointer() != reflect.ValueOf(preparationWorkflow).Pointer() ||
		reflect.ValueOf(registry.activity).Pointer() != reflect.ValueOf(activities.prepareActivity).Pointer() {
		t.Fatalf("registered workflow/activity = %#v/%#v options=%#v/%#v",
			registry.workflow, registry.activity, registry.workflowOptions, registry.activityOptions)
	}
	options := workerOptions()
	if !options.DisableRegistrationAliasing || !options.DisableEagerActivities || options.WorkerStopTimeout != 35*time.Second {
		t.Fatalf("workerOptions() trust gates = %#v", options)
	}
}

type embeddedSignalReader struct {
	investigation.SignalRegistrationReader
}
type embeddedPreparationRepository struct{ preparationRepository }

type internalTemporalRegistry struct {
	workflow        interface{}
	workflowOptions workflow.RegisterOptions
	activity        interface{}
	activityOptions activity.RegisterOptions
}

func (registry *internalTemporalRegistry) RegisterWorkflowWithOptions(value interface{}, options workflow.RegisterOptions) {
	registry.workflow, registry.workflowOptions = value, options
}

func (registry *internalTemporalRegistry) RegisterActivityWithOptions(value interface{}, options activity.RegisterOptions) {
	registry.activity, registry.activityOptions = value, options
}

func internalWorkerPlanner(t *testing.T, authority *investigationplan.ScopeAuthority) *investigationplan.Planner {
	t.Helper()
	const (
		tenantID      = "11111111-1111-4111-8111-111111111111"
		workspaceID   = "22222222-2222-4222-8222-222222222222"
		environmentID = "33333333-3333-4333-8333-333333333333"
		serviceID     = "44444444-4444-4444-8444-444444444444"
		integrationID = "55555555-5555-4555-8555-555555555555"
	)
	definition := readconnector.Definition{
		Scope: readconnector.Scope{
			TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: environmentID, ServiceID: serviceID,
		},
		TargetRef: "prometheus-staging-v1-" + strings.Repeat("a", 64),
		PrometheusRangeQuery: &readconnector.PrometheusRangeQueryV1{
			Expression: "up", StepSeconds: 30, MaxLookbackMinutes: 60, MaxItems: 100, MaxSamples: 121,
		},
	}
	connectorID, err := readconnector.BuildConnectorID("prometheus-staging", definition)
	if err != nil {
		t.Fatalf("BuildConnectorID() error = %v", err)
	}
	definition.ConnectorID = connectorID
	registry, err := readconnector.New([]readconnector.Definition{definition})
	if err != nil {
		t.Fatalf("readconnector.New() error = %v", err)
	}
	planner, err := investigationplan.New(context.Background(), authority, registry, investigationplan.Definition{
		RegistryDigest: registry.Digest(),
		Profiles: []investigationplan.ProfileDefinition{{
			Scope: investigationplan.Scope{
				TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: environmentID, ServiceID: serviceID,
			},
			Match: investigationplan.MatchDefinition{
				IntegrationID: integrationID, Provider: "alertmanager",
				Labels: []investigationplan.LabelMatch{{Key: "service", Value: "payments"}},
			},
			Tasks: []investigationplan.TaskDefinition{{
				Key: "metrics", ConnectorID: connectorID,
				Operation: readconnector.OperationPrometheusRangeQuery, Input: []byte(`{"lookback_minutes":15}`),
			}},
		}},
	})
	if err != nil {
		t.Fatalf("investigationplan.New() error = %v", err)
	}
	return planner
}
