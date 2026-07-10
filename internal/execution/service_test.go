package execution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/action"
	"github.com/aiops-system/control-plane/internal/credential"
	"github.com/aiops-system/control-plane/internal/executionlease"
	"github.com/aiops-system/control-plane/internal/policy"
)

func TestSubmitDerivesWriteScopeProductionAndTargetOnlyFromVerifiedEnvelope(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})

	queued, err := fixture.service.Submit(context.Background(), envelope)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	stored, err := fixture.leases.Get(context.Background(), envelope.ActionID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if queued != stored {
		t.Fatalf("Submit() = %#v, stored = %#v", queued, stored)
	}
	if stored.Pool != executionlease.PoolWrite || !stored.Production {
		t.Fatalf("derived execution classification = pool %q production %v", stored.Pool, stored.Production)
	}
	wantTarget, err := deriveTargetKey(envelope)
	if err != nil {
		t.Fatalf("deriveTargetKey() error = %v", err)
	}
	if stored.TargetKey != wantTarget {
		t.Fatalf("TargetKey = %q, want %q", stored.TargetKey, wantTarget)
	}
}

func TestSubmitRejectsUnverifiedAndUntrustedEnvironmentState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	valid, keys := signedEnvelope(t, restartEnvelope(now))

	tests := map[string]struct {
		envelope  action.Envelope
		snapshot  EnvironmentSnapshot
		wantError error
	}{
		"tampered signed envelope": {
			envelope: func() action.Envelope {
				candidate := cloneEnvelope(valid)
				candidate.Target.KubernetesDeployment.Name = "tampered"
				return candidate
			}(),
			snapshot:  validEnvironment(valid, now),
			wantError: ErrInvalidAction,
		},
		"stale environment snapshot": {
			envelope: valid,
			snapshot: func() EnvironmentSnapshot {
				candidate := validEnvironment(valid, now)
				candidate.ObservedAt = now.Add(-MaxEnvironmentSnapshotAge - time.Second)
				return candidate
			}(),
			wantError: ErrEnvironmentUnavailable,
		},
		"wrong environment scope": {
			envelope: valid,
			snapshot: func() EnvironmentSnapshot {
				candidate := validEnvironment(valid, now)
				candidate.WorkspaceID = "another-workspace"
				return candidate
			}(),
			wantError: ErrEnvironmentUnavailable,
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			queue := mustMemoryActionQueue(t, func() time.Time { return now })
			service := mustService(t, Dependencies{
				Queue: queue, Keys: keys,
				Environments: &fakeEnvironmentResolver{snapshots: []EnvironmentSnapshot{test.snapshot}},
				Safety:       &fakeSafetyGate{snapshots: []ClaimSafetySnapshot{validSafety(now)}},
				Credentials:  &fakeCredentialBroker{err: errors.New("must not be reached")},
				Policy:       &fakePreExecutionGate{},
				Executors:    noOpExecutors(),
			}, Options{RunnerID: "runner-1", AllowedWorkspaceIDs: []string{"workspace-1"}, AllowedEnvironmentIDs: []string{"PROD"}, LeaseDuration: time.Minute, Clock: func() time.Time { return now }})

			if _, err := service.Submit(context.Background(), test.envelope); !errors.Is(err, test.wantError) {
				t.Fatalf("Submit() error = %v, want %v", err, test.wantError)
			}
			if _, err := queue.Get(context.Background(), test.envelope.ActionID); !errors.Is(err, executionlease.ErrNotFound) {
				t.Fatalf("untrusted submission created a lease: %v", err)
			}
		})
	}
}

func TestSubmitRejectsAnEnvironmentOutsideTheTrustedRunnerAllowlist(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	unsigned := restartEnvelope(now)
	unsigned.Target.EnvironmentID = "STAGING"
	envelope, keys := signedEnvelope(t, unsigned)
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed,
	})

	if _, err := fixture.service.Submit(context.Background(), envelope); !errors.Is(err, ErrEnvironmentNotAllowed) {
		t.Fatalf("Submit() error = %v, want %v", err, ErrEnvironmentNotAllowed)
	}
	if _, err := fixture.leases.Get(context.Background(), envelope.ActionID); !errors.Is(err, executionlease.ErrNotFound) {
		t.Fatalf("cross-environment submission reached the queue: %v", err)
	}
}

func TestSubmitVerifiesEnvelopeBeforeCheckingRunnerScope(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	envelope.Target.EnvironmentID = "STAGING"
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed,
	})

	if _, err := fixture.service.Submit(context.Background(), envelope); !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("Submit() error = %v, want signature failure before scope rejection", err)
	}
	if fixture.environment.calls != 0 {
		t.Fatalf("unverified envelope reached environment resolver %d times", fixture.environment.calls)
	}
}

func TestRunNextCallsSafetyClaimCredentialPolicyStartTypedExecutorAndCompleteInOrder(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	fixture.events.reset()

	execution, err := fixture.service.RunNext(context.Background())
	if err != nil {
		t.Fatalf("RunNext() error = %v", err)
	}
	if execution.Status != executionlease.StatusSucceeded || len(execution.ResultHash) != 64 {
		t.Fatalf("RunNext() execution = %#v", execution)
	}
	wantOrder := []string{
		"safety:claim", "lease:claim", "environment:resolve", "credential:policy", "credential:issue",
		"policy:pre-execution", "safety:start", "environment:resolve", "lease:start", "executor:kubernetes-rollout-restart", "lease:complete",
		"credential:revoke",
	}
	if got := fixture.events.snapshot(); !equalStrings(got, wantOrder) {
		t.Fatalf("call order = %v, want %v", got, wantOrder)
	}
	if len(fixture.safety.requests) != 2 {
		t.Fatalf("safety requests = %#v", fixture.safety.requests)
	}
	startRequest := fixture.safety.requests[1]
	if startRequest.WorkspaceID != envelope.WorkspaceID || startRequest.EnvironmentID != envelope.Target.EnvironmentID ||
		startRequest.ConnectorID != envelope.CredentialScope.ConnectorID || startRequest.ActionType != envelope.ActionType {
		t.Fatalf("start safety request is not action-scoped: %#v", startRequest)
	}
	if fixture.executors.capturedCredential == nil || fixture.executors.capturedCredential.Secret() != nil {
		t.Fatal("credential was not destroyed after executor returned")
	}
}

func TestServicesShareAtomicActionQueueWithoutProcessLocalJobState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	secondService := mustService(t, fixture.service.dependencies, Options{
		RunnerID: "runner-1", AllowedWorkspaceIDs: []string{"workspace-1"}, AllowedEnvironmentIDs: []string{"PROD"},
		LeaseDuration: time.Minute, FinalizeTimeout: time.Second, Clock: func() time.Time { return now },
	})
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("first service Submit() error = %v", err)
	}

	completed, err := secondService.RunNext(context.Background())
	if err != nil {
		t.Fatalf("second service RunNext() error = %v", err)
	}
	if completed.Status != executionlease.StatusSucceeded {
		t.Fatalf("second service completed status = %s", completed.Status)
	}
}

func TestRunNextKillSwitchFailsClosedBeforeClaimAndBeforeStart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))

	tests := map[string][]ClaimSafetySnapshot{
		"disabled before claim": {func() ClaimSafetySnapshot {
			snapshot := validSafety(now)
			snapshot.Enabled = false
			return snapshot
		}()},
		"disabled immediately before start": {validSafety(now), func() ClaimSafetySnapshot {
			snapshot := validStartSafety(envelope, now)
			snapshot.Enabled = false
			snapshot.Revision = "safety-2"
			return snapshot
		}()},
		"changed safety revision before start": {validSafety(now), func() ClaimSafetySnapshot {
			snapshot := validStartSafety(envelope, now)
			snapshot.Revision = "safety-2"
			return snapshot
		}()},
		"mismatched safety scope before start": {validSafety(now), func() ClaimSafetySnapshot {
			snapshot := validStartSafety(envelope, now)
			snapshot.WorkspaceID = "another-workspace"
			return snapshot
		}()},
	}
	for name, snapshots := range tests {
		name, snapshots := name, snapshots
		t.Run(name, func(t *testing.T) {
			events := &eventLog{}
			fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
				Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
			})
			fixture.events = events
			fixture.safety.events = events
			fixture.safety.snapshots = snapshots
			fixture.leases.events = events
			fixture.environment.events = events
			fixture.preExecution.events = events
			fixture.credentialGate.events = events
			fixture.issuer.events = events
			fixture.executors.events = events
			if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
				t.Fatalf("Submit() error = %v", err)
			}
			events.reset()

			if _, err := fixture.service.RunNext(context.Background()); !errors.Is(err, ErrClaimsDisabled) {
				t.Fatalf("RunNext() error = %v, want %v", err, ErrClaimsDisabled)
			}
			for _, event := range events.snapshot() {
				if strings.HasPrefix(event, "executor:") || event == "lease:start" {
					t.Fatalf("kill switch denial reached side effect: %v", events.snapshot())
				}
			}
			if name == "disabled before claim" && contains(events.snapshot(), "lease:claim") {
				t.Fatalf("disabled safety gate reached Claim(): %v", events.snapshot())
			}
		})
	}
}

func TestRunNextHeartbeatsTheRunningFenceUntilTypedExecutionCompletes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	fixture.service.heartbeatInterval = 5 * time.Millisecond
	heartbeatObserved := make(chan struct{}, 1)
	releaseExecutor := make(chan struct{})
	fixture.leases.heartbeatObserved = heartbeatObserved
	fixture.executors.release = releaseExecutor
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}

	type runResult struct {
		execution executionlease.Execution
		err       error
	}
	completed := make(chan runResult, 1)
	go func() {
		execution, err := fixture.service.RunNext(context.Background())
		completed <- runResult{execution: execution, err: err}
	}()
	select {
	case <-heartbeatObserved:
	case <-time.After(time.Second):
		t.Fatal("running execution did not heartbeat its fenced lease")
	}
	close(releaseExecutor)
	result := <-completed
	if result.err != nil || result.execution.Status != executionlease.StatusSucceeded {
		t.Fatalf("RunNext() = %#v, %v", result.execution, result.err)
	}
	if !contains(fixture.events.snapshot(), "lease:heartbeat") {
		t.Fatalf("heartbeat was not recorded: %v", fixture.events.snapshot())
	}
}

func TestRunNextTreatsHeartbeatFailureAsUncertainAndCancelsTheExecutor(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	fixture.service.heartbeatInterval = 5 * time.Millisecond
	fixture.leases.heartbeatErr = errors.New("heartbeat transport failed")
	fixture.executors.waitForCancellation = true
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}

	execution, err := fixture.service.RunNext(context.Background())
	if !errors.Is(err, ErrExecutionUncertain) {
		t.Fatalf("RunNext() error = %v, want %v", err, ErrExecutionUncertain)
	}
	if execution.Status != executionlease.StatusUncertain || len(execution.ResultHash) != 64 {
		t.Fatalf("execution = %#v", execution)
	}
	if fixture.executors.capturedCredential == nil || fixture.executors.capturedCredential.Secret() != nil {
		t.Fatal("credential was not destroyed after heartbeat failure")
	}
}

func TestRunNextRejectsEnvironmentDriftOrExpiryBeforeCredentialOrSideEffect(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))

	tests := map[string]struct {
		snapshot EnvironmentSnapshot
		wantErr  error
		status   executionlease.Status
	}{
		"revision drift": {snapshot: func() EnvironmentSnapshot {
			snapshot := validEnvironment(envelope, now)
			snapshot.Revision = "environment-2"
			return snapshot
		}(), wantErr: ErrEnvironmentDrift, status: executionlease.StatusFailed},
		"production classification drift": {snapshot: func() EnvironmentSnapshot {
			snapshot := validEnvironment(envelope, now)
			snapshot.Production = false
			return snapshot
		}(), wantErr: ErrEnvironmentDrift, status: executionlease.StatusFailed},
		"snapshot expired": {snapshot: func() EnvironmentSnapshot {
			snapshot := validEnvironment(envelope, now)
			snapshot.ObservedAt = now.Add(-MaxEnvironmentSnapshotAge - time.Second)
			return snapshot
		}(), wantErr: ErrEnvironmentUnavailable, status: executionlease.StatusQueued},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
				Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
			})
			fixture.environment.snapshots = []EnvironmentSnapshot{validEnvironment(envelope, now), test.snapshot}
			if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
				t.Fatalf("Submit() error = %v", err)
			}
			fixture.events.reset()

			execution, err := fixture.service.RunNext(context.Background())
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("RunNext() error = %v, want %v", err, test.wantErr)
			}
			if execution.Status != test.status {
				t.Fatalf("RunNext() status = %s, want %s", execution.Status, test.status)
			}
			for _, event := range fixture.events.snapshot() {
				if strings.HasPrefix(event, "credential:") || strings.HasPrefix(event, "executor:") || event == "lease:start" {
					t.Fatalf("environment rejection reached credentials or side effect: %v", fixture.events.snapshot())
				}
			}
		})
	}
}

func TestRunNextRechecksEnvironmentImmediatelyBeforeStart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	changed := validEnvironment(envelope, now)
	changed.Revision = "environment-2"
	changed.Production = false
	fixture.environment.snapshots = []EnvironmentSnapshot{
		validEnvironment(envelope, now), validEnvironment(envelope, now), changed,
	}
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if _, err := fixture.service.RunNext(context.Background()); !errors.Is(err, ErrEnvironmentDrift) {
		t.Fatalf("RunNext() error = %v, want ErrEnvironmentDrift", err)
	}
	if len(fixture.executors.calls) != 0 {
		t.Fatalf("environment drift dispatched executor: %v", fixture.executors.calls)
	}
}

func TestRunNextPolicyDenialDoesNotStartOrDispatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	fixture.preExecution.decision = policy.Decision{
		Outcome: policy.OutcomeDeny, Stage: policy.StagePreExecution,
		PolicyVersion: envelope.PolicyVersion, PlanHash: envelope.PlanHash, EvaluatedAt: now,
	}
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	fixture.events.reset()

	rejected, err := fixture.service.RunNext(context.Background())
	if !errors.Is(err, ErrPreExecutionDenied) {
		t.Fatalf("RunNext() error = %v, want %v", err, ErrPreExecutionDenied)
	}
	if rejected.Status != executionlease.StatusFailed || len(rejected.ResultHash) != 64 {
		t.Fatalf("policy denial was not permanently rejected: %#v", rejected)
	}
	for _, event := range fixture.events.snapshot() {
		if strings.HasPrefix(event, "executor:") || event == "lease:start" {
			t.Fatalf("denied policy reached side effect: %v", fixture.events.snapshot())
		}
	}
	if _, err := fixture.leases.memory.Claim(context.Background(), ActionClaimRequest{
		Scope: RunnerScope{
			RunnerID: "runner-2", Pool: executionlease.PoolWrite,
			AllowedWorkspaceIDs: []string{"workspace-1"}, AllowedEnvironmentIDs: []string{"PROD"},
		},
		LeaseDuration: time.Minute,
	}); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("permanently denied action was redelivered: %v", err)
	}
	if fixture.issuer.revokeCalls != 1 {
		t.Fatalf("credential revoke calls = %d, want 1", fixture.issuer.revokeCalls)
	}
}

func TestRunNextPermanentlyRejectsDeterministicCredentialPolicyDenial(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return now })
	service := mustService(t, Dependencies{
		Queue: queue, Keys: keys,
		Environments: &fakeEnvironmentResolver{snapshots: []EnvironmentSnapshot{validEnvironment(envelope, now)}},
		Safety:       &fakeSafetyGate{snapshots: []ClaimSafetySnapshot{validSafety(now)}},
		Credentials:  &fakeCredentialBroker{err: credential.ErrCredentialDenied},
		Policy:       &fakePreExecutionGate{}, Executors: noOpExecutors(),
	}, Options{
		RunnerID: "runner-1", AllowedWorkspaceIDs: []string{"workspace-1"}, AllowedEnvironmentIDs: []string{"PROD"},
		LeaseDuration: time.Minute, Clock: func() time.Time { return now },
	})
	if _, err := service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	rejected, err := service.RunNext(context.Background())
	if !errors.Is(err, ErrCredentialDenied) || rejected.Status != executionlease.StatusFailed {
		t.Fatalf("RunNext() = %#v, %v; want permanent credential rejection", rejected, err)
	}
}

func TestRunNextRevalidatesPolicyCredentialAndSafetyFreshnessImmediatelyBeforeStart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixtureWithClock(t, func() time.Time { return clock }, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	fixture.safety.after = func(call int) {
		if call == 2 {
			clock = clock.Add(MaxPreExecutionDecisionAge + time.Second)
		}
	}
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}

	if _, err := fixture.service.RunNext(context.Background()); !errors.Is(err, ErrClaimsDisabled) {
		t.Fatalf("RunNext() error = %v, want ErrClaimsDisabled", err)
	}
	if len(fixture.executors.calls) != 0 {
		t.Fatalf("stale pre-execution state dispatched executor: %v", fixture.executors.calls)
	}
}

func TestRunNextBoundsExecutorContextBySignedVerificationTimeout(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	unsigned := restartEnvelope(now)
	unsigned.Verification.TimeoutSeconds = 1
	envelope, keys := signedEnvelope(t, unsigned)
	fixture := newRunnerFixtureWithClock(t, func() time.Time { return now }, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if _, err := fixture.service.RunNext(context.Background()); err != nil {
		t.Fatalf("RunNext() error = %v", err)
	}
	deadline := fixture.executors.capturedDeadline
	if deadline.IsZero() || deadline.After(now.Add(time.Second+100*time.Millisecond)) || !deadline.After(now) {
		t.Fatalf("executor deadline = %s, want within signed 1s verification timeout", deadline)
	}
}

func TestRunNextTreatsCompletionTransportFailureAsUncertain(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	fixture.leases.completeErr = errors.New("completion response lost")
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	execution, err := fixture.service.RunNext(context.Background())
	if !errors.Is(err, ErrExecutionUncertain) {
		t.Fatalf("RunNext() error = %v, want ErrExecutionUncertain", err)
	}
	if execution.LeaseToken != "" {
		t.Fatalf("completion error leaked lease token %q", execution.LeaseToken)
	}
	if fixture.issuer.revokeCalls != 1 {
		t.Fatalf("credential revoke calls = %d, want 1", fixture.issuer.revokeCalls)
	}
}

func TestRunNextExecutorCannotTamperWithCredentialRevocationMetadata(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	fixture.executors.mutateCredentialMetadata = true
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if _, err := fixture.service.RunNext(context.Background()); err != nil {
		t.Fatalf("RunNext() error = %v", err)
	}
	if fixture.issuer.revokeCalls != 1 || fixture.issuer.revokedLeaseID != "credential-lease-1" {
		t.Fatalf("credential revocation = calls %d lease %q", fixture.issuer.revokeCalls, fixture.issuer.revokedLeaseID)
	}
}

func TestRunNextStopsHeartbeatAndReturnsUncertainWhenExecutorIgnoresDeadline(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "LATE_RESULT", Verification: VerificationPassed, Changed: true,
	})
	release := make(chan struct{})
	finished := make(chan struct{})
	fixture.executors.ignoreCancellation = true
	fixture.executors.release = release
	fixture.executors.finished = finished
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	type runResult struct {
		execution executionlease.Execution
		err       error
	}
	completed := make(chan runResult, 1)
	go func() {
		execution, err := fixture.service.RunNext(ctx)
		completed <- runResult{execution: execution, err: err}
	}()
	select {
	case result := <-completed:
		if !errors.Is(result.err, ErrExecutionUncertain) || result.execution.LeaseToken != "" {
			t.Fatalf("RunNext(deadline) = %#v, %v", result.execution, result.err)
		}
	case <-time.After(500 * time.Millisecond):
		close(release)
		<-finished
		t.Fatal("RunNext waited indefinitely for an executor that ignored context")
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("late executor did not exit after test release")
	}
}

func TestRunNextDispatchesOnlyTheFourTypedActionExecutors(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		envelope action.Envelope
		want     string
	}{
		"Kubernetes rollout restart": {restartEnvelope(now), "kubernetes-rollout-restart"},
		"Kubernetes scale":           {scaleEnvelope(now), "kubernetes-scale"},
		"GitOps revert":              {gitOpsEnvelope(now), "gitops-revert"},
		"AWX service restart":        {awxEnvelope(now), "awx-service-restart"},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			envelope, keys := signedEnvelope(t, test.envelope)
			fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
				Outcome: ExecutorSucceeded, Code: "ACTION_VERIFIED", Verification: VerificationPassed, Changed: true,
			})
			if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
				t.Fatalf("Submit() error = %v", err)
			}
			fixture.events.reset()

			execution, err := fixture.service.RunNext(context.Background())
			if err != nil {
				t.Fatalf("RunNext() error = %v", err)
			}
			if execution.Status != executionlease.StatusSucceeded {
				t.Fatalf("status = %s", execution.Status)
			}
			if got := fixture.executors.calls; len(got) != 1 || got[0] != test.want {
				t.Fatalf("typed executor calls = %v, want [%s]", got, test.want)
			}
		})
	}
}

func TestRunNextMapsVerifiedFailedAndUnknownExecutorOutcomesAndStoresOnlySummaryHash(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		result      ExecutorResult
		executorErr error
		wantStatus  executionlease.Status
		wantError   error
	}{
		"success": {
			result:     ExecutorResult{Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true},
			wantStatus: executionlease.StatusSucceeded,
		},
		"definite failure": {
			result:     ExecutorResult{Outcome: ExecutorFailed, Code: "HEALTH_CHECK_FAILED", Verification: VerificationFailed, Changed: true},
			wantStatus: executionlease.StatusFailed, wantError: ErrExecutionFailed,
		},
		"unknown provider result": {
			executorErr: errors.New("provider connection dropped after write"),
			wantStatus:  executionlease.StatusUncertain, wantError: ErrExecutionUncertain,
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			envelope, keys := signedEnvelope(t, restartEnvelope(now))
			fixture := newRunnerFixture(t, now, envelope, keys, test.result)
			fixture.executors.err = test.executorErr
			if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
				t.Fatalf("Submit() error = %v", err)
			}

			execution, err := fixture.service.RunNext(context.Background())
			if !errors.Is(err, test.wantError) {
				t.Fatalf("RunNext() error = %v, want %v", err, test.wantError)
			}
			if execution.Status != test.wantStatus || len(execution.ResultHash) != 64 {
				t.Fatalf("execution = %#v", execution)
			}
			if strings.Contains(execution.ResultHash, "provider") || strings.Contains(execution.ResultHash, "HEALTH") {
				t.Fatalf("ResultHash leaked raw result: %q", execution.ResultHash)
			}
		})
	}
}

func TestRunNextStaleFenceNeverDispatchesExecutor(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	fixture.leases.startErr = executionlease.ErrStaleLease
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}

	execution, err := fixture.service.RunNext(context.Background())
	if !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("RunNext() error = %v, want %v", err, executionlease.ErrStaleLease)
	}
	if execution.LeaseToken != "" {
		t.Fatalf("Start error leaked lease token %q", execution.LeaseToken)
	}
	if len(fixture.executors.calls) != 0 {
		t.Fatalf("stale fence dispatched executor: %v", fixture.executors.calls)
	}
}

func TestDeriveTargetKeyUsesExactKubernetesAndGitOpsIdentityAndInventoryWideAWXLock(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	kubernetes := restartEnvelope(now)
	kubernetesOther := cloneEnvelope(restartEnvelope(now))
	kubernetesOther.Target.KubernetesDeployment.Name = "payments-worker"
	kubernetesOther.CredentialScope.Resource = "cluster-a/payments/deployment/payments-worker"
	assertTargetKeysDiffer(t, kubernetes, kubernetesOther)

	gitops := gitOpsEnvelope(now)
	gitopsOther := cloneEnvelope(gitOpsEnvelope(now))
	gitopsOther.Target.GitOpsApplication.Path = "apps/payments-canary"
	assertTargetKeysDiffer(t, gitops, gitopsOther)

	awx := awxEnvelope(now)
	awxOtherHosts := cloneEnvelope(awxEnvelope(now))
	awxOtherHosts.Target.AWXHosts.HostIDs = []int64{999}
	awxOtherHosts.ObservedState.AWXService.HostCount = 1
	first, err := deriveTargetKey(awx)
	if err != nil {
		t.Fatalf("deriveTargetKey() error = %v", err)
	}
	second, err := deriveTargetKey(awxOtherHosts)
	if err != nil {
		t.Fatalf("deriveTargetKey() error = %v", err)
	}
	if first != second {
		t.Fatalf("AWX inventory lock keys differ: %q != %q", first, second)
	}
}

func assertTargetKeysDiffer(t *testing.T, firstEnvelope, secondEnvelope action.Envelope) {
	t.Helper()
	first, err := deriveTargetKey(firstEnvelope)
	if err != nil {
		t.Fatalf("deriveTargetKey(first) error = %v", err)
	}
	second, err := deriveTargetKey(secondEnvelope)
	if err != nil {
		t.Fatalf("deriveTargetKey(second) error = %v", err)
	}
	if first == second {
		t.Fatalf("target keys unexpectedly equal: %q", first)
	}
}

type runnerFixture struct {
	service        *Service
	leases         *recordingActionQueue
	environment    *fakeEnvironmentResolver
	safety         *fakeSafetyGate
	preExecution   *fakePreExecutionGate
	credentialGate *fakeCredentialPolicyGate
	issuer         *fakeDynamicIssuer
	executors      *recordingExecutors
	events         *eventLog
}

func newRunnerFixture(t *testing.T, now time.Time, envelope action.Envelope, keys action.KeyResolver, result ExecutorResult) *runnerFixture {
	t.Helper()
	return newRunnerFixtureWithClock(t, func() time.Time { return now }, envelope, keys, result)
}

func newRunnerFixtureWithClock(t *testing.T, clock func() time.Time, envelope action.Envelope, keys action.KeyResolver, result ExecutorResult) *runnerFixture {
	t.Helper()
	events := &eventLog{}
	memoryQueue := mustMemoryActionQueue(t, clock)
	leases := &recordingActionQueue{ActionQueue: memoryQueue, memory: memoryQueue, events: events}
	environment := &fakeEnvironmentResolver{snapshots: []EnvironmentSnapshot{validEnvironment(envelope, clock()), validEnvironment(envelope, clock())}, events: events}
	safety := &fakeSafetyGate{snapshots: []ClaimSafetySnapshot{validSafety(clock()), validStartSafety(envelope, clock())}, events: events}
	credentialGate := &fakeCredentialPolicyGate{decision: credentialDecision(envelope, clock()), events: events}
	issuer := &fakeDynamicIssuer{expiresAt: clock().Add(5 * time.Minute), events: events}
	broker, err := credential.NewBroker(credentialGate, issuer, clock)
	if err != nil {
		t.Fatalf("credential.NewBroker() error = %v", err)
	}
	preExecution := &fakePreExecutionGate{decision: preExecutionDecision(envelope, clock()), events: events}
	executors := &recordingExecutors{result: result, events: events}
	service := mustService(t, Dependencies{
		Queue: leases, Keys: keys, Environments: environment, Safety: safety,
		Credentials: broker, Policy: preExecution, Executors: executors.asDependencies(),
	}, Options{RunnerID: "runner-1", AllowedWorkspaceIDs: []string{"workspace-1"}, AllowedEnvironmentIDs: []string{"PROD"}, LeaseDuration: time.Minute, FinalizeTimeout: time.Second, Clock: clock})
	return &runnerFixture{
		service: service, leases: leases, environment: environment, safety: safety,
		preExecution: preExecution, credentialGate: credentialGate, issuer: issuer,
		executors: executors, events: events,
	}
}

func mustService(t *testing.T, dependencies Dependencies, options Options) *Service {
	t.Helper()
	service, err := NewService(dependencies, options)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

type recordingActionQueue struct {
	ActionQueue
	memory            *MemoryActionQueue
	events            *eventLog
	startErr          error
	heartbeatErr      error
	completeErr       error
	heartbeatObserved chan<- struct{}
}

func (repository *recordingActionQueue) Claim(ctx context.Context, request ActionClaimRequest) (ClaimedAction, error) {
	repository.events.add("lease:claim")
	return repository.ActionQueue.Claim(ctx, request)
}

func (repository *recordingActionQueue) Start(ctx context.Context, lease executionlease.LeaseIdentity) (executionlease.Execution, error) {
	repository.events.add("lease:start")
	if repository.startErr != nil {
		return executionlease.Execution{}, repository.startErr
	}
	return repository.ActionQueue.Start(ctx, lease)
}

func (repository *recordingActionQueue) Complete(ctx context.Context, request executionlease.CompleteRequest) (executionlease.Execution, error) {
	repository.events.add("lease:complete")
	if repository.completeErr != nil {
		return executionlease.Execution{}, repository.completeErr
	}
	return repository.ActionQueue.Complete(ctx, request)
}

func (repository *recordingActionQueue) Heartbeat(ctx context.Context, request executionlease.HeartbeatRequest) (executionlease.Execution, error) {
	repository.events.add("lease:heartbeat")
	if repository.heartbeatObserved != nil {
		select {
		case repository.heartbeatObserved <- struct{}{}:
		default:
		}
	}
	if repository.heartbeatErr != nil {
		return executionlease.Execution{}, repository.heartbeatErr
	}
	return repository.ActionQueue.Heartbeat(ctx, request)
}

func (repository *recordingActionQueue) Get(ctx context.Context, executionID string) (executionlease.Execution, error) {
	return repository.memory.Get(ctx, executionID)
}

type fakeEnvironmentResolver struct {
	snapshots []EnvironmentSnapshot
	calls     int
	events    *eventLog
}

func (resolver *fakeEnvironmentResolver) Resolve(_ context.Context, _, _ string) (EnvironmentSnapshot, error) {
	if resolver.events != nil {
		resolver.events.add("environment:resolve")
	}
	if len(resolver.snapshots) == 0 {
		return EnvironmentSnapshot{}, errors.New("environment unavailable")
	}
	index := resolver.calls
	if index >= len(resolver.snapshots) {
		index = len(resolver.snapshots) - 1
	}
	resolver.calls++
	return resolver.snapshots[index], nil
}

type fakeSafetyGate struct {
	snapshots []ClaimSafetySnapshot
	calls     int
	events    *eventLog
	requests  []SafetyRequest
	after     func(int)
}

func (gate *fakeSafetyGate) Evaluate(_ context.Context, request SafetyRequest) (ClaimSafetySnapshot, error) {
	if gate.events != nil {
		gate.events.add("safety:" + string(request.Phase))
	}
	gate.requests = append(gate.requests, request)
	if len(gate.snapshots) == 0 {
		return ClaimSafetySnapshot{}, errors.New("safety unavailable")
	}
	index := gate.calls
	if index >= len(gate.snapshots) {
		index = len(gate.snapshots) - 1
	}
	gate.calls++
	snapshot := gate.snapshots[index]
	if gate.after != nil {
		gate.after(gate.calls)
	}
	return snapshot, nil
}

type fakeCredentialPolicyGate struct {
	decision policy.Decision
	events   *eventLog
}

func (gate *fakeCredentialPolicyGate) EvaluateCredentialIssue(context.Context, action.Envelope) (policy.Decision, error) {
	gate.events.add("credential:policy")
	return gate.decision, nil
}

type fakeDynamicIssuer struct {
	expiresAt      time.Time
	events         *eventLog
	revokeCalls    int
	revokedLeaseID string
}

func (issuer *fakeDynamicIssuer) Issue(context.Context, credential.IssueRequest) (credential.IssuedLease, error) {
	issuer.events.add("credential:issue")
	return credential.IssuedLease{LeaseID: "credential-lease-1", Secret: []byte("ephemeral-secret"), ExpiresAt: issuer.expiresAt}, nil
}

func (issuer *fakeDynamicIssuer) Revoke(_ context.Context, leaseID string) error {
	issuer.revokeCalls++
	issuer.revokedLeaseID = leaseID
	issuer.events.add("credential:revoke")
	return nil
}

type fakeCredentialBroker struct{ err error }

func (broker *fakeCredentialBroker) Issue(context.Context, action.Envelope) (credential.Credential, error) {
	return credential.Credential{}, broker.err
}

func (*fakeCredentialBroker) Revoke(context.Context, *credential.Credential) error { return nil }

type fakePreExecutionGate struct {
	decision policy.Decision
	after    func()
	events   *eventLog
}

func (gate *fakePreExecutionGate) EvaluatePreExecution(context.Context, action.Envelope) (policy.Decision, error) {
	if gate.events != nil {
		gate.events.add("policy:pre-execution")
	}
	if gate.after != nil {
		gate.after()
	}
	return gate.decision, nil
}

type recordingExecutors struct {
	result                   ExecutorResult
	err                      error
	calls                    []string
	events                   *eventLog
	capturedCredential       *credential.Credential
	release                  <-chan struct{}
	waitForCancellation      bool
	capturedDeadline         time.Time
	mutateCredentialMetadata bool
	ignoreCancellation       bool
	finished                 chan<- struct{}
}

func (executors *recordingExecutors) asDependencies() Executors {
	return Executors{
		KubernetesRolloutRestart: executors,
		KubernetesScale:          executors,
		GitOpsRevert:             executors,
		AWXServiceRestart:        executors,
	}
}

func (executors *recordingExecutors) record(ctx context.Context, name string, credential *credential.Credential) (ExecutorResult, error) {
	executors.calls = append(executors.calls, name)
	executors.capturedCredential = credential
	if executors.mutateCredentialMetadata {
		credential.LeaseID = "tampered-by-executor"
		credential.ExpiresAt = time.Time{}
	}
	if deadline, ok := ctx.Deadline(); ok {
		executors.capturedDeadline = deadline
	}
	if executors.events != nil {
		executors.events.add("executor:" + name)
	}
	if executors.ignoreCancellation {
		<-executors.release
		if executors.finished != nil {
			close(executors.finished)
		}
		return executors.result, executors.err
	}
	if executors.waitForCancellation {
		<-ctx.Done()
		return ExecutorResult{}, ctx.Err()
	}
	if executors.release != nil {
		select {
		case <-ctx.Done():
			return ExecutorResult{}, ctx.Err()
		case <-executors.release:
		}
	}
	return executors.result, executors.err
}

func (executors *recordingExecutors) ExecuteRolloutRestart(ctx context.Context, command KubernetesRolloutRestartCommand, credential *credential.Credential) (ExecutorResult, error) {
	if command.Target.Name == "" || command.Parameters.Reason == "" {
		return ExecutorResult{}, errors.New("missing typed restart command")
	}
	return executors.record(ctx, "kubernetes-rollout-restart", credential)
}

func (executors *recordingExecutors) ExecuteScale(ctx context.Context, command KubernetesScaleCommand, credential *credential.Credential) (ExecutorResult, error) {
	if command.Target.Name == "" || command.Parameters.Replicas < 0 {
		return ExecutorResult{}, errors.New("missing typed scale command")
	}
	return executors.record(ctx, "kubernetes-scale", credential)
}

func (executors *recordingExecutors) ExecuteGitOpsRevert(ctx context.Context, command GitOpsRevertCommand, credential *credential.Credential) (ExecutorResult, error) {
	if command.Target.RepositoryID == "" || command.Parameters.RevertCommit == "" {
		return ExecutorResult{}, errors.New("missing typed GitOps command")
	}
	return executors.record(ctx, "gitops-revert", credential)
}

func (executors *recordingExecutors) ExecuteAWXServiceRestart(ctx context.Context, command AWXServiceRestartCommand, credential *credential.Credential) (ExecutorResult, error) {
	if command.Target.InventoryID == 0 || command.Parameters.JobTemplateID == 0 {
		return ExecutorResult{}, errors.New("missing typed AWX command")
	}
	return executors.record(ctx, "awx-service-restart", credential)
}

func noOpExecutors() Executors {
	executors := &recordingExecutors{result: ExecutorResult{Outcome: ExecutorSucceeded, Code: "OK", Verification: VerificationPassed}}
	return executors.asDependencies()
}

type eventLog struct {
	mu     sync.Mutex
	values []string
}

func (log *eventLog) add(value string) {
	log.mu.Lock()
	log.values = append(log.values, value)
	log.mu.Unlock()
}
func (log *eventLog) reset() {
	log.mu.Lock()
	log.values = nil
	log.mu.Unlock()
}
func (log *eventLog) snapshot() []string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return append([]string(nil), log.values...)
}

func validEnvironment(envelope action.Envelope, now time.Time) EnvironmentSnapshot {
	return EnvironmentSnapshot{
		WorkspaceID: envelope.WorkspaceID, EnvironmentID: envelope.Target.EnvironmentID,
		Production: true, Revision: "environment-1", ObservedAt: now,
	}
}

func validSafety(now time.Time) ClaimSafetySnapshot {
	return ClaimSafetySnapshot{Enabled: true, Pool: executionlease.PoolWrite, RunnerID: "runner-1", Revision: "safety-1", ObservedAt: now}
}

func validStartSafety(envelope action.Envelope, now time.Time) ClaimSafetySnapshot {
	return ClaimSafetySnapshot{
		Enabled: true, Pool: executionlease.PoolWrite, RunnerID: "runner-1",
		WorkspaceID: envelope.WorkspaceID, EnvironmentID: envelope.Target.EnvironmentID,
		ConnectorID: envelope.CredentialScope.ConnectorID, ActionType: envelope.ActionType,
		Revision: "safety-1", ObservedAt: now,
	}
}

func credentialDecision(envelope action.Envelope, now time.Time) policy.Decision {
	return policy.Decision{
		Outcome: policy.OutcomeAllow, Stage: policy.StageCredentialIssue,
		PolicyVersion: envelope.PolicyVersion, PlanHash: envelope.PlanHash,
		SafetyRevision: "safety-1", TargetRevision: "target-1", RiskRevision: "risk-1", LimitsRevision: "limits-1",
		EvaluatedAt: now, CredentialExpiresAt: now.Add(5 * time.Minute),
	}
}

func preExecutionDecision(envelope action.Envelope, now time.Time) policy.Decision {
	return policy.Decision{
		Outcome: policy.OutcomeAllow, Stage: policy.StagePreExecution,
		PolicyVersion: envelope.PolicyVersion, PlanHash: envelope.PlanHash,
		SafetyRevision: "safety-1", TargetRevision: "target-1", RiskRevision: "risk-1", LimitsRevision: "limits-1",
		EvaluatedAt: now,
	}
}

func signedEnvelope(t *testing.T, envelope action.Envelope) (action.Envelope, action.KeyResolver) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	signer, err := action.NewEd25519Signer("execution-test-key", privateKey)
	if err != nil {
		t.Fatalf("action.NewEd25519Signer() error = %v", err)
	}
	sealed, err := action.Seal(context.Background(), envelope, envelope.RequestedBy, signer)
	if err != nil {
		t.Fatalf("action.Seal() error = %v", err)
	}
	keys, err := action.NewStaticKeySet(map[string]action.KeyRecord{"execution-test-key": {PublicKey: publicKey}})
	if err != nil {
		t.Fatalf("action.NewStaticKeySet() error = %v", err)
	}
	return sealed, keys
}

func restartEnvelope(now time.Time) action.Envelope {
	return action.Envelope{
		SchemaVersion: action.SchemaVersionV1, ActionID: "action-restart", WorkspaceID: "workspace-1", IncidentID: "incident-1", RequestedBy: "requester-1",
		ActionType: action.ActionKubernetesRolloutRestart,
		Target: action.TargetRef{ServiceID: "service-payments", EnvironmentID: "PROD", KubernetesDeployment: &action.KubernetesDeploymentTarget{
			ClusterID: "cluster-a", Namespace: "payments", Name: "payments-api", UID: "uid-1", ResourceVersion: "83",
		}},
		Parameters:    action.ActionParameters{KubernetesRolloutRestart: &action.KubernetesRolloutRestartParameters{Reason: "confirmed deadlock"}},
		ObservedState: action.ObservedState{KubernetesDeployment: &action.KubernetesDeploymentObservedState{Generation: 4, Replicas: 3, AvailableReplicas: 3, UpdatedReplicas: 3}},
		Preconditions: action.Preconditions{MappingResult: "EXACT", ExpectedResourceVersion: "83", RequireWhitelist: true},
		Verification:  action.VerificationPlan{Mode: "KUBERNETES_ROLLOUT", TimeoutSeconds: 300},
		Compensation:  action.CompensationPlan{Mode: "MANUAL_ONLY", Summary: "follow runbook"},
		Risk:          action.RiskAssessment{Level: "MEDIUM", ReasonCodes: []string{"PRODUCTION_CHANGE", "RESTART"}},
		PolicyVersion: "policy.v1",
		CredentialScope: action.CredentialScope{ConnectorID: "kubernetes-prod", Permission: "PATCH_DEPLOYMENT_RESTART",
			Resource: "cluster-a/payments/deployment/payments-api", TTLSeconds: 600},
		IdempotencyKey: "idem-action-restart", NotBefore: now, ExpiresAt: now.Add(30 * time.Minute), TraceID: strings.Repeat("a", 32),
	}
}

func scaleEnvelope(now time.Time) action.Envelope {
	envelope := restartEnvelope(now)
	envelope.ActionID = "action-scale"
	envelope.IdempotencyKey = "idem-action-scale"
	envelope.ActionType = action.ActionKubernetesScale
	envelope.Parameters = action.ActionParameters{KubernetesScale: &action.KubernetesScaleParameters{
		Replicas: 5, Minimum: 2, Maximum: 8, HPAAbsent: true, PDBChecked: true, QuotaChecked: true,
	}}
	envelope.CredentialScope.Permission = "PATCH_DEPLOYMENT_SCALE"
	return envelope
}

func gitOpsEnvelope(now time.Time) action.Envelope {
	head := strings.Repeat("b", 40)
	return action.Envelope{
		SchemaVersion: action.SchemaVersionV1, ActionID: "action-gitops", WorkspaceID: "workspace-1", IncidentID: "incident-1", RequestedBy: "requester-1",
		ActionType: action.ActionGitOpsRevert,
		Target: action.TargetRef{ServiceID: "service-payments", EnvironmentID: "PROD", GitOpsApplication: &action.GitOpsTarget{
			RepositoryID: "gitops-prod", Application: "payments", Path: "apps/payments",
		}},
		Parameters: action.ActionParameters{GitOpsRevert: &action.GitOpsRevertParameters{
			Provider: "GITLAB", BaseCommit: strings.Repeat("a", 40), HeadCommit: head, RevertCommit: strings.Repeat("c", 40),
			DiffSHA256: strings.Repeat("d", 64), TreeSHA256: strings.Repeat("e", 64),
		}},
		ObservedState: action.ObservedState{GitOpsApplication: &action.GitOpsObservedState{
			LiveRevision: head, DesiredRevision: head, HeadTreeSHA256: strings.Repeat("f", 64), SyncStatus: "SYNCED", HealthStatus: "HEALTHY",
		}},
		Preconditions: action.Preconditions{MappingResult: "EXACT", ExpectedGitHeadCommit: head, RequireWhitelist: true},
		Verification:  action.VerificationPlan{Mode: "ARGO_CD_HEALTH", TimeoutSeconds: 300},
		Compensation:  action.CompensationPlan{Mode: "MANUAL_ONLY", Summary: "follow runbook"},
		Risk:          action.RiskAssessment{Level: "HIGH", ReasonCodes: []string{"GITOPS_REVERT", "PRODUCTION_CHANGE"}},
		PolicyVersion: "policy.v1",
		CredentialScope: action.CredentialScope{ConnectorID: "gitlab-prod", Permission: "CREATE_REVERT_MR",
			Resource: "gitops-prod", TTLSeconds: 600},
		IdempotencyKey: "idem-action-gitops", NotBefore: now, ExpiresAt: now.Add(30 * time.Minute), TraceID: strings.Repeat("b", 32),
	}
}

func awxEnvelope(now time.Time) action.Envelope {
	return action.Envelope{
		SchemaVersion: action.SchemaVersionV1, ActionID: "action-awx", WorkspaceID: "workspace-1", IncidentID: "incident-1", RequestedBy: "requester-1",
		ActionType: action.ActionAWXServiceRestart,
		Target: action.TargetRef{ServiceID: "service-payments", EnvironmentID: "PROD", AWXHosts: &action.AWXTarget{
			InventoryID: 42, HostIDs: []int64{101, 102}, InventorySnapshotSHA256: strings.Repeat("f", 64), JobTemplateSnapshotSHA256: strings.Repeat("e", 64),
		}},
		Parameters: action.ActionParameters{AWXServiceRestart: &action.AWXServiceRestartParameters{
			JobTemplateID: 81, ServiceName: "payments-api", OSFamily: "LINUX_SYSTEMD", Serial: 1,
		}},
		ObservedState: action.ObservedState{AWXService: &action.AWXServiceObservedState{
			HostCount: 2, ServiceState: "RUNNING", InventorySnapshotSHA256: strings.Repeat("f", 64), ServiceStateSnapshotSHA256: strings.Repeat("d", 64),
		}},
		Preconditions: action.Preconditions{MappingResult: "EXACT", RequireWhitelist: true},
		Verification:  action.VerificationPlan{Mode: "AWX_SERVICE_HEALTH", TimeoutSeconds: 300},
		Compensation:  action.CompensationPlan{Mode: "MANUAL_ONLY", Summary: "follow runbook"},
		Risk:          action.RiskAssessment{Level: "HIGH", ReasonCodes: []string{"AWX_RESTART", "PRODUCTION_CHANGE"}},
		PolicyVersion: "policy.v1",
		CredentialScope: action.CredentialScope{ConnectorID: "awx-prod", Permission: "LAUNCH_SERVICE_RESTART_TEMPLATE",
			Resource: "inventory/42/job-template/81", TTLSeconds: 600},
		IdempotencyKey: "idem-action-awx", NotBefore: now, ExpiresAt: now.Add(30 * time.Minute), TraceID: strings.Repeat("c", 32),
	}
}

func equalStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
