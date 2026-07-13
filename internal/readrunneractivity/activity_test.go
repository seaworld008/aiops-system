package readrunneractivity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/seaworld008/aiops-system/internal/readexecutor"
	"github.com/seaworld008/aiops-system/internal/readrunnerclient"
	"github.com/seaworld008/aiops-system/internal/readruntime"
	"github.com/seaworld008/aiops-system/internal/readtask"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

const testCanary = "runner-secret-canary-DO-NOT-RETURN"

func TestExecuteReturnsNotClaimedOnlyForExactEmptyClaim(t *testing.T) {
	input := validActivityInput()
	gateway := &fakeGateway{}
	runtime := &fakeRuntime{}
	activities := newTestActivities(t, input, gateway, runtime, time.Millisecond, nil)

	output, err := activities.execute(context.Background(), input)
	if err != nil {
		t.Fatalf("execute() error = %v", err)
	}
	assertOutput(t, input, output, investigationworkflow.ReadTaskActivityNotClaimed)
	if gateway.claims != 1 || runtime.prepareCalls != 0 {
		t.Fatalf("calls = claim:%d prepare:%d", gateway.claims, runtime.prepareCalls)
	}
	if gateway.expected.TaskID != input.TaskID || gateway.expected.Position != input.Position ||
		gateway.expected.TenantID != input.TenantID || gateway.expected.WorkspaceID != input.WorkspaceID ||
		gateway.expected.EnvironmentID != input.EnvironmentID || gateway.expected.ServiceID != input.ServiceID ||
		gateway.expected.IncidentID != input.IncidentID || gateway.expected.InvestigationID != input.InvestigationID ||
		gateway.expected.PlanBinding.ManifestDigest != input.ManifestDigest ||
		gateway.expected.PlanBinding.RegistryDigest != input.RegistryDigest ||
		gateway.expected.PlanBinding.ProfileDigest != input.ProfileDigest ||
		gateway.expected.PlanBinding.TasksHash != input.TasksHash {
		t.Fatalf("Claim expected task was not exact: %#v", gateway.expected)
	}
}

func TestPrepareFailureRequiresAcknowledgedReleaseForNotClaimed(t *testing.T) {
	input := validActivityInput()
	for _, test := range []struct {
		name          string
		releaseErr    error
		expectedState string
	}{
		{name: "release acknowledged", expectedState: investigationworkflow.ReadTaskActivityNotClaimed},
		{name: "release ambiguous", releaseErr: errors.New(testCanary), expectedState: investigationworkflow.ReadTaskActivityRecoveryRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease := newFakeLease()
			lease.releaseErr = test.releaseErr
			gateway := &fakeGateway{lease: lease}
			runtime := &fakeRuntime{prepareErr: errors.New(testCanary)}
			activities := newTestActivities(t, input, gateway, runtime, time.Millisecond, nil)

			output, err := activities.execute(context.Background(), input)
			if err != nil {
				t.Fatalf("execute() error = %v", err)
			}
			assertOutput(t, input, output, test.expectedState)
			lease.mu.Lock()
			defer lease.mu.Unlock()
			if lease.releaseCalls != 1 || lease.releaseReason != readtask.ReleaseConnectorNotReady || lease.startCalls != 0 || lease.completeCalls != 0 {
				t.Fatalf("lease calls = release:%d reason:%q start:%d complete:%d", lease.releaseCalls, lease.releaseReason, lease.startCalls, lease.completeCalls)
			}
			if !lease.destroyed {
				t.Fatal("lease bearer was not destroyed")
			}
		})
	}
}

func TestAmbiguousClaimDestroysAnyReturnedBearerAndRequiresRecovery(t *testing.T) {
	input := validActivityInput()
	lease := newFakeLease()
	activities := newTestActivities(
		t, input, &fakeGateway{lease: lease, err: errors.New(testCanary)}, &fakeRuntime{}, time.Millisecond, nil,
	)

	output, err := activities.execute(context.Background(), input)
	if err != nil {
		t.Fatalf("execute() error = %v", err)
	}
	assertOutput(t, input, output, investigationworkflow.ReadTaskActivityRecoveryRequired)
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if !lease.destroyed || lease.startCalls != 0 || lease.completeCalls != 0 {
		t.Fatalf("ambiguous claim cleanup = destroyed:%v start:%d complete:%d", lease.destroyed, lease.startCalls, lease.completeCalls)
	}
}

func TestStartedExecutionCompletesExactlyOnceAfterAcknowledgement(t *testing.T) {
	input := validActivityInput()
	lease := newFakeLease()
	prepared := &fakePrepared{execute: func(context.Context) (readrunnerclient.Completion, error) {
		return readrunnerclient.Completion{}, nil
	}}
	activities := newTestActivities(
		t, input, &fakeGateway{lease: lease}, &fakeRuntime{prepared: prepared}, time.Second, nil,
	)

	output, err := activities.execute(context.Background(), input)
	if err != nil {
		t.Fatalf("execute() error = %v", err)
	}
	assertOutput(t, input, output, investigationworkflow.ReadTaskActivityCompleteAcknowledged)
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.startCalls != 1 || lease.completeCalls != 1 || lease.releaseCalls != 0 || !lease.destroyed {
		t.Fatalf("lease calls = start:%d complete:%d release:%d destroyed:%v", lease.startCalls, lease.completeCalls, lease.releaseCalls, lease.destroyed)
	}
}

func TestCompleteUnknownResultIsNeverRetriedOrExposed(t *testing.T) {
	input := validActivityInput()
	lease := newFakeLease()
	lease.completeErr = errors.New(testCanary)
	evidence := &readtask.EvidenceCompletion{
		CollectedAt: time.Now().UTC(), Items: []json.RawMessage{json.RawMessage(`{"body":"` + testCanary + `"}`)},
	}
	prepared := &fakePrepared{execute: func(context.Context) (readrunnerclient.Completion, error) {
		return readrunnerclient.Completion{
			Outcome:  readtask.CompletionEvidence,
			Evidence: evidence,
		}, nil
	}}
	activities := newTestActivities(t, input, &fakeGateway{lease: lease}, &fakeRuntime{prepared: prepared}, time.Second, nil)

	output, err := activities.execute(context.Background(), input)
	if err != nil {
		t.Fatalf("execute() error leaked dependency: %v", err)
	}
	assertOutput(t, input, output, investigationworkflow.ReadTaskActivityRecoveryRequired)
	if containsCanary(output, err) {
		t.Fatal("activity output/error exposed dependency detail")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.completeCalls != 1 {
		t.Fatalf("Complete calls = %d, want exactly 1", lease.completeCalls)
	}
	if evidence.Items != nil || !evidence.CollectedAt.IsZero() {
		t.Fatalf("completion evidence was not cleared after one attempt: %#v", evidence)
	}
}

func TestHeartbeatContinuesWithMonotonicGatewaySequenceAndNoDetailTemporalAPI(t *testing.T) {
	input := validActivityInput()
	lease := newFakeLease()
	allowExecution := make(chan struct{})
	var once sync.Once
	lease.heartbeat = func(ctx context.Context, sequence int64) (readrunnerclient.HeartbeatResult, error) {
		if sequence == 2 {
			once.Do(func() { close(allowExecution) })
		}
		return readrunnerclient.HeartbeatResult{AcceptedSequence: sequence, Directive: readtask.HeartbeatContinue}, nil
	}
	prepared := &fakePrepared{execute: func(ctx context.Context) (readrunnerclient.Completion, error) {
		select {
		case <-allowExecution:
			return readrunnerclient.Completion{}, nil
		case <-ctx.Done():
			return readrunnerclient.Completion{}, ctx.Err()
		}
	}}
	var temporalHeartbeats atomic.Int64
	activities := newTestActivities(
		t, input, &fakeGateway{lease: lease}, &fakeRuntime{prepared: prepared}, time.Millisecond,
		func(context.Context) { temporalHeartbeats.Add(1) },
	)

	output, err := activities.execute(context.Background(), input)
	if err != nil {
		t.Fatalf("execute() error = %v", err)
	}
	assertOutput(t, input, output, investigationworkflow.ReadTaskActivityCompleteAcknowledged)
	lease.mu.Lock()
	sequences := append([]int64(nil), lease.sequences...)
	lease.mu.Unlock()
	// Closing allowExecution at sequence 2 races legitimately with the next
	// ticker delivery. Assert the protocol invariant instead of scheduler-
	// dependent exact cardinality.
	if len(sequences) < 2 {
		t.Fatalf("heartbeat sequences = %v, want at least immediate plus periodic", sequences)
	}
	for index, sequence := range sequences {
		if sequence != int64(index+1) {
			t.Fatalf("heartbeat sequences = %v, want contiguous monotonic values", sequences)
		}
	}
	if temporalHeartbeats.Load() < 2 {
		t.Fatalf("Temporal heartbeats = %d, want immediate plus periodic", temporalHeartbeats.Load())
	}
}

func TestTerminateAndGatewayHeartbeatFailureCancelAndJoinExecution(t *testing.T) {
	input := validActivityInput()
	for _, test := range []struct {
		name      string
		directive readtask.HeartbeatDirective
		err       error
	}{
		{name: "terminate", directive: readtask.HeartbeatTerminate},
		{name: "transport failure", err: errors.New(testCanary)},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease := newFakeLease()
			lease.heartbeat = func(context.Context, int64) (readrunnerclient.HeartbeatResult, error) {
				return readrunnerclient.HeartbeatResult{Directive: test.directive}, test.err
			}
			var joined atomic.Bool
			prepared := &fakePrepared{execute: func(ctx context.Context) (readrunnerclient.Completion, error) {
				<-ctx.Done()
				joined.Store(true)
				return readrunnerclient.Completion{}, ctx.Err()
			}}
			activities := newTestActivities(t, input, &fakeGateway{lease: lease}, &fakeRuntime{prepared: prepared}, time.Millisecond, nil)

			output, err := activities.execute(context.Background(), input)
			if err != nil {
				t.Fatalf("execute() error = %v", err)
			}
			assertOutput(t, input, output, investigationworkflow.ReadTaskActivityRecoveryRequired)
			if !joined.Load() {
				t.Fatal("activity returned before executor goroutine joined")
			}
			lease.mu.Lock()
			defer lease.mu.Unlock()
			if lease.completeCalls != 0 {
				t.Fatalf("Complete calls = %d", lease.completeCalls)
			}
		})
	}
}

func TestContextCancellationInterruptsBlockingHeartbeatAndJoinsExecution(t *testing.T) {
	input := validActivityInput()
	lease := newFakeLease()
	heartbeatEntered := make(chan struct{})
	lease.heartbeat = func(ctx context.Context, _ int64) (readrunnerclient.HeartbeatResult, error) {
		close(heartbeatEntered)
		<-ctx.Done()
		return readrunnerclient.HeartbeatResult{}, ctx.Err()
	}
	var joined atomic.Bool
	prepared := &fakePrepared{execute: func(ctx context.Context) (readrunnerclient.Completion, error) {
		<-ctx.Done()
		joined.Store(true)
		return readrunnerclient.Completion{}, ctx.Err()
	}}
	activities := newTestActivities(t, input, &fakeGateway{lease: lease}, &fakeRuntime{prepared: prepared}, time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan investigationworkflow.ReadTaskActivityOutputV1, 1)
	go func() {
		output, _ := activities.execute(ctx, input)
		result <- output
	}()
	select {
	case <-heartbeatEntered:
	case <-time.After(time.Second):
		t.Fatal("Gateway heartbeat did not start")
	}
	cancel()
	select {
	case output := <-result:
		assertOutput(t, input, output, investigationworkflow.ReadTaskActivityRecoveryRequired)
	case <-time.After(time.Second):
		t.Fatal("activity did not converge after cancellation")
	}
	if !joined.Load() {
		t.Fatal("activity returned before executor goroutine joined")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.completeCalls != 0 {
		t.Fatalf("Complete calls = %d", lease.completeCalls)
	}
}

func TestTemporalHeartbeatSupervisorCoversEveryPreStartBlockingStage(t *testing.T) {
	input := validActivityInput()
	for _, stage := range []string{"claim", "prepare", "start"} {
		t.Run(stage, func(t *testing.T) {
			allow := make(chan struct{})
			var closeOnce sync.Once
			var heartbeats atomic.Int64
			recorder := func(context.Context) {
				if heartbeats.Add(1) >= 3 {
					closeOnce.Do(func() { close(allow) })
				}
			}
			lease := newFakeLease()
			gateway := &fakeGateway{lease: lease}
			runtime := &fakeRuntime{}
			switch stage {
			case "claim":
				gateway.claim = func(ctx context.Context, _ readrunnerclient.ExpectedTask) (leaseSession, error) {
					select {
					case <-allow:
						return nil, nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
			case "prepare":
				runtime.prepare = func(ctx context.Context) (preparedSession, error) {
					select {
					case <-allow:
						return nil, errors.New(testCanary)
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
			case "start":
				lease.start = func(ctx context.Context) (startSession, error) {
					select {
					case <-allow:
						return nil, errors.New(testCanary)
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
			}
			activities := newTestActivities(t, input, gateway, runtime, time.Millisecond, recorder)
			output, err := activities.execute(context.Background(), input)
			if err != nil {
				t.Fatalf("execute() error = %v", err)
			}
			if stage == "start" {
				assertOutput(t, input, output, investigationworkflow.ReadTaskActivityRecoveryRequired)
			} else {
				assertOutput(t, input, output, investigationworkflow.ReadTaskActivityNotClaimed)
			}
			if heartbeats.Load() < 3 {
				t.Fatalf("Temporal heartbeats = %d", heartbeats.Load())
			}
		})
	}
}

func TestCancellationBeforeStartUsesOneValueFreeCleanupRelease(t *testing.T) {
	input := validActivityInput()
	lease := newFakeLease()
	prepareEntered := make(chan struct{})
	runtime := &fakeRuntime{prepare: func(ctx context.Context) (preparedSession, error) {
		close(prepareEntered)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	type contextKey struct{}
	lease.release = func(ctx context.Context, reason readtask.ReleaseReason) error {
		if ctx.Err() != nil || ctx.Value(contextKey{}) != nil || reason != readtask.ReleaseTransientRunnerFailure {
			return errors.New(testCanary)
		}
		return nil
	}
	activities := newTestActivities(t, input, &fakeGateway{lease: lease}, runtime, time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), contextKey{}, testCanary))
	result := make(chan investigationworkflow.ReadTaskActivityOutputV1, 1)
	go func() {
		output, _ := activities.execute(ctx, input)
		result <- output
	}()
	select {
	case <-prepareEntered:
	case <-time.After(time.Second):
		t.Fatal("Prepare did not start")
	}
	cancel()
	select {
	case output := <-result:
		assertOutput(t, input, output, investigationworkflow.ReadTaskActivityNotClaimed)
	case <-time.After(time.Second):
		t.Fatal("pre-start cleanup did not converge")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.releaseCalls != 1 || lease.startCalls != 0 || lease.releaseReason != readtask.ReleaseTransientRunnerFailure {
		t.Fatalf("cleanup calls = release:%d start:%d reason:%q", lease.releaseCalls, lease.startCalls, lease.releaseReason)
	}
}

func TestTemporalHeartbeatSupervisorStopsBeforeActivityReturns(t *testing.T) {
	input := validActivityInput()
	var heartbeats atomic.Int64
	activities := newTestActivities(t, input, &fakeGateway{}, &fakeRuntime{}, time.Millisecond,
		func(context.Context) { heartbeats.Add(1) })
	output, err := activities.execute(context.Background(), input)
	if err != nil {
		t.Fatalf("execute() error = %v", err)
	}
	assertOutput(t, input, output, investigationworkflow.ReadTaskActivityNotClaimed)
	count := heartbeats.Load()
	time.Sleep(5 * time.Millisecond)
	if heartbeats.Load() != count {
		t.Fatalf("heartbeat supervisor leaked after return: before=%d after=%d", count, heartbeats.Load())
	}
}

func TestTemporalHeartbeatPanicCancelsBlockingDependencyWithoutLeakingCause(t *testing.T) {
	input := validActivityInput()
	var heartbeats atomic.Int64
	gateway := &fakeGateway{claim: func(ctx context.Context, _ readrunnerclient.ExpectedTask) (leaseSession, error) {
		<-ctx.Done()
		return nil, errors.New(testCanary)
	}}
	activities := newTestActivities(t, input, gateway, &fakeRuntime{}, time.Millisecond, func(context.Context) {
		if heartbeats.Add(1) == 2 {
			panic(testCanary)
		}
	})
	output, err := activities.execute(context.Background(), input)
	if err != nil || containsCanary(output, err) {
		t.Fatalf("heartbeat panic leaked: output=%#v error=%v", output, err)
	}
	assertOutput(t, input, output, investigationworkflow.ReadTaskActivityRecoveryRequired)
	if heartbeats.Load() != 2 {
		t.Fatalf("Temporal heartbeat calls = %d", heartbeats.Load())
	}
}

func TestDependencyPanicBecomesLowSensitivityRecovery(t *testing.T) {
	input := validActivityInput()
	lease := newFakeLease()
	prepared := &fakePrepared{execute: func(context.Context) (readrunnerclient.Completion, error) {
		panic(testCanary)
	}}
	activities := newTestActivities(t, input, &fakeGateway{lease: lease}, &fakeRuntime{prepared: prepared}, time.Second, nil)

	output, err := activities.execute(context.Background(), input)
	if err != nil || containsCanary(output, err) {
		t.Fatalf("panic leaked: output=%#v error=%v", output, err)
	}
	assertOutput(t, input, output, investigationworkflow.ReadTaskActivityRecoveryRequired)
}

func TestActivityInfoAndInputAreStrictlyBoundBeforeClaim(t *testing.T) {
	input := validActivityInput()
	baseInfo := validInfo(t, input)
	tests := map[string]func(*activity.Info, *investigationworkflow.ReadTaskActivityInputV1){
		"input version": func(_ *activity.Info, value *investigationworkflow.ReadTaskActivityInputV1) { value.Version = 2 },
		"workflow id": func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) {
			value.WorkflowExecution.ID = "foreign"
		},
		"workflow run id": func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) {
			value.WorkflowExecution.RunID = "foreign"
		},
		"namespace": func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) {
			value.Namespace = "space rejected"
		},
		"legal foreign namespace": func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) {
			value.Namespace = "other-valid-namespace"
		},
		"deprecated namespace mismatch": func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) {
			value.WorkflowNamespace = "foreign"
		},
		"workflow type": func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) {
			value.WorkflowType.Name = "foreign"
		},
		"activity type": func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) {
			value.ActivityType.Name = "foreign"
		},
		"activity id": func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) {
			value.ActivityID = "foreign"
		},
		"runner queue": func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) {
			value.TaskQueue = "foreign"
		},
		"attempt": func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) { value.Attempt = 2 },
		"schedule timeout": func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) {
			value.ScheduleToCloseTimeout++
		},
		"start timeout": func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) {
			value.StartToCloseTimeout++
		},
		"heartbeat timeout": func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) { value.HeartbeatTimeout++ },
		"retry absent":      func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) { value.RetryPolicy = nil },
		"retry attempts": func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) {
			value.RetryPolicy.MaximumAttempts = 2
		},
		"local activity": func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) {
			value.IsLocalActivity = true
		},
		"direct activity": func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) {
			value.ActivityRunID = "run"
		},
		"priority": func(value *activity.Info, _ *investigationworkflow.ReadTaskActivityInputV1) {
			value.Priority.PriorityKey = 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidateInput := input
			candidateInfo := baseInfo
			workflowType := *baseInfo.WorkflowType
			candidateInfo.WorkflowType = &workflowType
			retry := *baseInfo.RetryPolicy
			candidateInfo.RetryPolicy = &retry
			mutate(&candidateInfo, &candidateInput)
			gateway := &fakeGateway{}
			activities := newTestActivitiesWithInfo(t, input, gateway, &fakeRuntime{}, time.Millisecond, candidateInfo, nil)
			output, err := activities.execute(context.Background(), candidateInput)
			if !errors.Is(err, ErrActivityRejected) || output != (investigationworkflow.ReadTaskActivityOutputV1{}) {
				t.Fatalf("execute() = %#v, %v", output, err)
			}
			if gateway.claims != 0 {
				t.Fatalf("Claim calls = %d", gateway.claims)
			}
		})
	}
}

func TestBundleDigestMismatchFailsBeforeClaim(t *testing.T) {
	input := validActivityInput()
	gateway := &fakeGateway{}
	runtime := &fakeRuntime{bundleDigest: stringOf('f', 64)}
	activities := newTestActivities(t, input, gateway, runtime, time.Millisecond, nil)

	output, err := activities.execute(context.Background(), input)
	if !errors.Is(err, ErrActivityRejected) || output != (investigationworkflow.ReadTaskActivityOutputV1{}) {
		t.Fatalf("execute() = %#v, %v", output, err)
	}
	if gateway.claims != 0 || runtime.prepareCalls != 0 {
		t.Fatalf("network/runtime calls = claim:%d prepare:%d", gateway.claims, runtime.prepareCalls)
	}
}

func TestPlanningSnapshotMismatchFailsBeforeClaim(t *testing.T) {
	pinned := validActivityInput()
	gateway := &fakeGateway{}
	runtime := &fakeRuntime{}
	activities := newTestActivities(t, pinned, gateway, runtime, time.Millisecond, nil)

	foreign := pinned
	foreign.ManifestDigest = stringOf('f', 64)
	output, err := activities.execute(context.Background(), foreign)
	if !errors.Is(err, ErrActivityRejected) || output != (investigationworkflow.ReadTaskActivityOutputV1{}) {
		t.Fatalf("execute(foreign Plan) = %#v, %v", output, err)
	}
	if gateway.claims != 0 || runtime.prepareCalls != 0 {
		t.Fatalf("foreign Plan reached network/runtime: claims=%d prepare=%d", gateway.claims, runtime.prepareCalls)
	}

	foreign = pinned
	foreign.RegistryDigest = stringOf('f', 64)
	output, err = activities.execute(context.Background(), foreign)
	if !errors.Is(err, ErrActivityRejected) || output != (investigationworkflow.ReadTaskActivityOutputV1{}) {
		t.Fatalf("execute(foreign Registry) = %#v, %v", output, err)
	}
	if gateway.claims != 0 || runtime.prepareCalls != 0 {
		t.Fatalf("foreign Registry reached network/runtime: claims=%d prepare=%d", gateway.claims, runtime.prepareCalls)
	}
}

func TestPlanBoundRuntimeRejectsForeignDescriptorBeforeInnerPrepare(t *testing.T) {
	input := validActivityInput()
	binding := domain.InvestigationPlanBinding{
		SchemaVersion: domain.InvestigationPlanBindingSchemaVersion, ManifestDigest: input.ManifestDigest,
		RegistryDigest: input.RegistryDigest, ProfileDigest: input.ProfileDigest, TasksHash: input.TasksHash,
	}
	tests := map[string]func(*domain.InvestigationPlanBinding){
		"foreign Plan":     func(value *domain.InvestigationPlanBinding) { value.ManifestDigest = stringOf('f', 64) },
		"foreign Registry": func(value *domain.InvestigationPlanBinding) { value.RegistryDigest = stringOf('f', 64) },
		"invalid binding":  func(value *domain.InvestigationPlanBinding) { value.SchemaVersion = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			inner := &fakeRuntime{}
			runtime := &planBoundRuntime{
				inner: inner, planManifestDigest: input.ManifestDigest,
				connectorRegistryDigest: input.RegistryDigest,
			}
			foreign := binding
			mutate(&foreign)
			prepared, err := runtime.Prepare(
				context.Background(), readtask.Descriptor{PlanBinding: foreign}, 1, 1,
			)
			if prepared != nil || !errors.Is(err, ErrActivityRejected) {
				t.Fatalf("Prepare(foreign descriptor) = %#v, %v", prepared, err)
			}
			if inner.prepareCalls != 0 {
				t.Fatalf("foreign descriptor reached inner runtime %d times", inner.prepareCalls)
			}
		})
	}

	inner := &fakeRuntime{}
	runtime := &planBoundRuntime{
		inner: inner, planManifestDigest: input.ManifestDigest,
		connectorRegistryDigest: input.RegistryDigest,
	}
	prepared, err := runtime.Prepare(context.Background(), readtask.Descriptor{PlanBinding: binding}, 1, 1)
	if err != nil || prepared == nil || inner.prepareCalls != 1 {
		t.Fatalf("Prepare(pinned descriptor) = %#v, %v; calls=%d", prepared, err, inner.prepareCalls)
	}
}

func TestNewActivitiesHasNoCredentialFreeOrUnsealedFallback(t *testing.T) {
	bearer := readexecutor.BearerSource(func(context.Context, string, func([]byte)) readtask.FailureCode { return "" })
	if activities, err := NewActivities(nil, nil, stringOf('a', 64), bearer, "default"); activities != nil || !errors.Is(err, ErrActivityRejected) {
		t.Fatalf("NewActivities(nil) = %#v, %v", activities, err)
	}
	if activities, err := NewActivities(&readrunnerclient.Client{}, &readruntime.Bundle{}, stringOf('a', 64), bearer, "default"); activities != nil || !errors.Is(err, ErrActivityRejected) {
		t.Fatalf("NewActivities(zero values) = %#v, %v", activities, err)
	}
	if activities, err := NewActivities(&readrunnerclient.Client{}, &readruntime.Bundle{}, stringOf('a', 64), nil, "default"); activities != nil || !errors.Is(err, ErrActivityRejected) {
		t.Fatalf("NewActivities(nil bearer) = %#v, %v", activities, err)
	}
	if activities, err := NewActivities(&readrunnerclient.Client{}, &readruntime.Bundle{}, stringOf('a', 64), bearer, ""); activities != nil || !errors.Is(err, ErrActivityRejected) {
		t.Fatalf("NewActivities(empty namespace) = %#v, %v", activities, err)
	}
	if activities, err := NewActivities(&readrunnerclient.Client{}, &readruntime.Bundle{}, "", bearer, "default"); activities != nil || !errors.Is(err, ErrActivityRejected) {
		t.Fatalf("NewActivities(empty Plan digest) = %#v, %v", activities, err)
	}
}

func assertOutput(
	t *testing.T,
	input investigationworkflow.ReadTaskActivityInputV1,
	output investigationworkflow.ReadTaskActivityOutputV1,
	state string,
) {
	t.Helper()
	if output.State != state || output.ValidateAgainst(input) != nil {
		t.Fatalf("output = %#v, want state %s bound to input", output, state)
	}
}

func containsCanary(output investigationworkflow.ReadTaskActivityOutputV1, err error) bool {
	return (err != nil && strings.Contains(fmt.Sprint(err), testCanary)) ||
		strings.Contains(fmt.Sprint(output), testCanary)
}

func validActivityInput() investigationworkflow.ReadTaskActivityInputV1 {
	return investigationworkflow.ReadTaskActivityInputV1{
		Version: 1, OutboxEventID: "10101010-1010-4010-8010-101010101010",
		TenantID: "11111111-1111-4111-8111-111111111111", WorkspaceID: "22222222-2222-4222-8222-222222222222",
		EnvironmentID: "33333333-3333-4333-8333-333333333333", ServiceID: "44444444-4444-4444-8444-444444444444",
		IncidentID: "55555555-5555-4555-8555-555555555555", InvestigationID: "66666666-6666-4666-8666-666666666666",
		TaskID: "77777777-7777-4777-8777-777777777777", Position: 2,
		ManifestDigest: stringOf('a', 64), RegistryDigest: stringOf('b', 64),
		BundleDigest: stringOf('e', 64), ProfileDigest: stringOf('c', 64), TasksHash: stringOf('d', 64), Round: 3,
	}
}

func stringOf(value byte, count int) string { return string(makeBytes(value, count)) }
func makeBytes(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func validInfo(t *testing.T, input investigationworkflow.ReadTaskActivityInputV1) activity.Info {
	t.Helper()
	queue, err := investigationworkflow.RunnerTaskQueue(
		input.EnvironmentID, input.ManifestDigest, input.RegistryDigest, input.BundleDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	activityID, err := investigationworkflow.ReadTaskActivityID(input.Round, input.Position, input.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	return activity.Info{
		WorkflowType: &workflow.Type{Name: investigationworkflow.WorkflowNameV2},
		WorkflowExecution: workflow.Execution{
			ID: input.OutboxEventID, RunID: "90909090-9090-4090-8090-909090909090",
		},
		Namespace:  "default",
		ActivityID: activityID, ActivityType: activity.Type{Name: investigationworkflow.ExecuteActivityNameV1},
		TaskQueue: queue, Attempt: 1,
		ScheduleToCloseTimeout: investigationworkflow.RunnerActivityScheduleToCloseTimeout,
		StartToCloseTimeout:    investigationworkflow.RunnerActivityStartToCloseTimeout,
		HeartbeatTimeout:       investigationworkflow.RunnerActivityHeartbeatTimeout,
		RetryPolicy:            &temporal.RetryPolicy{MaximumAttempts: 1},
	}
}

func newTestActivities(
	t *testing.T,
	input investigationworkflow.ReadTaskActivityInputV1,
	gateway gatewayProtocol,
	runtime runtimeProtocol,
	interval time.Duration,
	heartbeat func(context.Context),
) *Activities {
	t.Helper()
	return newTestActivitiesWithInfo(t, input, gateway, runtime, interval, validInfo(t, input), heartbeat)
}

func newTestActivitiesWithInfo(
	t *testing.T,
	pinned investigationworkflow.ReadTaskActivityInputV1,
	gateway gatewayProtocol,
	runtime runtimeProtocol,
	interval time.Duration,
	info activity.Info,
	heartbeat func(context.Context),
) *Activities {
	t.Helper()
	if heartbeat == nil {
		heartbeat = func(context.Context) {}
	}
	activities, err := newActivities(
		gateway, runtime,
		func(context.Context, string, func([]byte)) readtask.FailureCode { return "" },
		activityRuntime{info: func(context.Context) activity.Info { return info }, heartbeat: heartbeat, interval: interval},
		interval,
		"default",
		pinned.ManifestDigest,
		pinned.RegistryDigest,
	)
	if err != nil {
		t.Fatalf("newActivities() error = %v", err)
	}
	return activities
}

type fakeGateway struct {
	lease    leaseSession
	err      error
	panicNow bool
	claims   int
	expected readrunnerclient.ExpectedTask
	claim    func(context.Context, readrunnerclient.ExpectedTask) (leaseSession, error)
}

func (gateway *fakeGateway) Claim(ctx context.Context, expected readrunnerclient.ExpectedTask) (leaseSession, error) {
	if gateway.panicNow {
		panic(testCanary)
	}
	gateway.claims++
	gateway.expected = expected
	if gateway.claim != nil {
		return gateway.claim(ctx, expected)
	}
	return gateway.lease, gateway.err
}

type fakeStart struct{}

func (*fakeStart) readRunnerActivityStart() {}

type fakeLease struct {
	mu            sync.Mutex
	descriptor    readtask.Descriptor
	epoch         int64
	scopeRevision int64
	releaseCalls  int
	releaseReason readtask.ReleaseReason
	releaseErr    error
	release       func(context.Context, readtask.ReleaseReason) error
	startCalls    int
	startErr      error
	start         func(context.Context) (startSession, error)
	heartbeat     func(context.Context, int64) (readrunnerclient.HeartbeatResult, error)
	sequences     []int64
	completeCalls int
	completeErr   error
	destroyed     bool
}

func newFakeLease() *fakeLease                           { return &fakeLease{epoch: 7, scopeRevision: 9} }
func (lease *fakeLease) Descriptor() readtask.Descriptor { return lease.descriptor }
func (lease *fakeLease) LeaseEpoch() int64               { return lease.epoch }
func (lease *fakeLease) ScopeRevision() int64            { return lease.scopeRevision }
func (lease *fakeLease) Release(ctx context.Context, reason readtask.ReleaseReason) error {
	lease.mu.Lock()
	lease.releaseCalls++
	lease.releaseReason = reason
	release := lease.release
	releaseErr := lease.releaseErr
	lease.mu.Unlock()
	if release != nil {
		return release(ctx, reason)
	}
	return releaseErr
}
func (lease *fakeLease) Start(ctx context.Context) (startSession, error) {
	lease.mu.Lock()
	lease.startCalls++
	start := lease.start
	startErr := lease.startErr
	lease.mu.Unlock()
	if start != nil {
		return start(ctx)
	}
	if startErr != nil {
		return nil, startErr
	}
	return &fakeStart{}, nil
}
func (lease *fakeLease) Heartbeat(ctx context.Context, _ startSession, sequence int64) (readrunnerclient.HeartbeatResult, error) {
	lease.mu.Lock()
	lease.sequences = append(lease.sequences, sequence)
	heartbeat := lease.heartbeat
	lease.mu.Unlock()
	if heartbeat == nil {
		return readrunnerclient.HeartbeatResult{AcceptedSequence: sequence, Directive: readtask.HeartbeatContinue}, nil
	}
	return heartbeat(ctx, sequence)
}
func (lease *fakeLease) Complete(context.Context, startSession, readrunnerclient.Completion) error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	lease.completeCalls++
	return lease.completeErr
}
func (lease *fakeLease) Destroy() {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	lease.destroyed = true
}

type fakeRuntime struct {
	prepared     preparedSession
	prepareErr   error
	prepareCalls int
	bundleDigest string
	prepare      func(context.Context) (preparedSession, error)
}

func (runtime *fakeRuntime) BundleDigest() string {
	if runtime.bundleDigest != "" {
		return runtime.bundleDigest
	}
	return stringOf('e', 64)
}

func (runtime *fakeRuntime) Prepare(ctx context.Context, _ readtask.Descriptor, _ int64, _ int64) (preparedSession, error) {
	runtime.prepareCalls++
	if runtime.prepare != nil {
		return runtime.prepare(ctx)
	}
	if runtime.prepareErr != nil {
		return nil, runtime.prepareErr
	}
	if runtime.prepared == nil {
		return &fakePrepared{execute: func(context.Context) (readrunnerclient.Completion, error) {
			return readrunnerclient.Completion{}, nil
		}}, nil
	}
	return runtime.prepared, nil
}

type fakePrepared struct {
	execute func(context.Context) (readrunnerclient.Completion, error)
}

func (prepared *fakePrepared) Execute(
	ctx context.Context,
	_ startSession,
	credentials readexecutor.BearerSource,
) (readrunnerclient.Completion, error) {
	if prepared == nil || prepared.execute == nil || credentials == nil {
		return readrunnerclient.Completion{}, ErrActivityRejected
	}
	return prepared.execute(ctx)
}
