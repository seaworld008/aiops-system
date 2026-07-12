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

	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/executionlease"
	"github.com/seaworld008/aiops-system/internal/policy"
)

func TestSubmitDerivesWriteScopeProductionAndTargetOnlyFromVerifiedEnvelope(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	fixture.environment.snapshots = []EnvironmentSnapshot{validEnvironment(envelope, now)}

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

func TestRunNextHardDisablesProductionWriteBeforeCredentialPolicyStartOrExecutor(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "MUST_NOT_RUN", Verification: VerificationPassed, Changed: true,
	})
	fixture.environment.snapshots = []EnvironmentSnapshot{validEnvironment(envelope, now)}
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit(production WRITE) error = %v", err)
	}
	fixture.events.reset()

	result, err := fixture.service.RunNext(context.Background())
	if !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("RunNext(production WRITE) = %#v, %v; want %v", result, err, executionlease.ErrNoLeaseAvailable)
	}
	if result != (executionlease.Execution{}) {
		t.Fatalf("RunNext(production WRITE) result = %#v, want zero execution", result)
	}
	if got, want := fixture.events.snapshot(), []string{"safety:claim", "lease:claim"}; !equalStrings(got, want) {
		t.Fatalf("production WRITE boundary events = %v, want %v", got, want)
	}
	if fixture.environment.calls != 1 || fixture.credentials.requestRevocationCalls != 0 || len(fixture.executors.calls) != 0 {
		t.Fatalf("production WRITE reached a post-claim dependency: environment calls=%d revocation requests=%d executor calls=%v",
			fixture.environment.calls, fixture.credentials.requestRevocationCalls, fixture.executors.calls)
	}
	queued, getErr := fixture.leases.Get(context.Background(), envelope.ActionID)
	if getErr != nil || queued.Status != executionlease.StatusQueued || !queued.Production {
		t.Fatalf("Get(production WRITE after denied claim) = %#v, %v; want retained production QUEUED action", queued, getErr)
	}
}

func TestRunNextRetainsAnUnexpectedProductionWriteClaimBeforeTrustEvaluation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	targetKey, err := deriveTargetKey(envelope)
	if err != nil {
		t.Fatalf("deriveTargetKey() error = %v", err)
	}
	const leaseToken = "must-never-leave-the-queue-boundary"
	claimed := ClaimedAction{
		Execution: executionlease.Execution{
			ExecutionID: envelope.ActionID, TargetKey: targetKey, Pool: executionlease.PoolWrite, Production: true,
			Status: executionlease.StatusLeased, RunnerID: "runner-1", RunnerTenantID: "tenant-test",
			RunnerWorkspaceID: envelope.WorkspaceID, RunnerEnvironmentID: envelope.Target.EnvironmentID,
			ScopeRevision: 1, LeaseToken: leaseToken, LeaseEpoch: 7, LeaseExpiresAt: now.Add(time.Minute),
		},
		Envelope: envelope, PlanHash: envelope.PlanHash, TargetKey: targetKey,
		EnvironmentRevision: "environment-1", Production: true,
	}
	fixture := newForcedClaimFixture(t, now, claimed)

	result, runErr := fixture.service.RunNext(context.Background())
	if runErr != ErrJobConflict {
		t.Fatalf("RunNext(unexpected production WRITE claim) error = %v, want exact %v", runErr, ErrJobConflict)
	}
	if strings.Contains(runErr.Error(), leaseToken) || result.LeaseToken != "" {
		t.Fatalf("production WRITE denial exposed its lease token: result=%#v error=%v", result, runErr)
	}
	if result.ExecutionID != envelope.ActionID || result.Status != executionlease.StatusLeased {
		t.Fatalf("RunNext() result = %#v, want the redacted retained lease", result)
	}
	if fixture.queue.claimCalls != 1 || len(fixture.queue.mutations) != 0 || fixture.queue.claimed.Execution.LeaseToken != leaseToken {
		t.Fatalf("unexpected queue handling: claims=%d mutations=%v retained token=%q",
			fixture.queue.claimCalls, fixture.queue.mutations, fixture.queue.claimed.Execution.LeaseToken)
	}
	if fixture.keys.calls != 0 || fixture.environment.calls != 0 || fixture.credentials.issueCalls != 0 || fixture.credentials.requestRevocationCalls != 0 ||
		len(fixture.policyEvents.snapshot()) != 0 || len(fixture.executors.calls) != 0 {
		t.Fatalf("production WRITE claim crossed the trust boundary: keys=%d environment=%d credential issue/revoke=%d/%d policy=%v executors=%v",
			fixture.keys.calls, fixture.environment.calls, fixture.credentials.issueCalls, fixture.credentials.requestRevocationCalls,
			fixture.policyEvents.snapshot(), fixture.executors.calls)
	}
}

func TestRunNextRetainsClaimMetadataAnomaliesBeforeTrustEvaluation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	targetKey, err := deriveTargetKey(envelope)
	if err != nil {
		t.Fatalf("deriveTargetKey() error = %v", err)
	}
	baseClaim := ClaimedAction{
		Execution: executionlease.Execution{
			ExecutionID: envelope.ActionID, TargetKey: targetKey, Pool: executionlease.PoolWrite,
			Status: executionlease.StatusLeased, RunnerID: "runner-1", LeaseToken: "metadata-anomaly-token",
			RunnerTenantID: "tenant-test", RunnerWorkspaceID: envelope.WorkspaceID,
			RunnerEnvironmentID: envelope.Target.EnvironmentID, ScopeRevision: 1,
			LeaseEpoch: 8, LeaseExpiresAt: now.Add(time.Minute),
		},
		Envelope: envelope, PlanHash: envelope.PlanHash, TargetKey: targetKey,
		EnvironmentRevision: "environment-1",
	}
	tests := map[string]func(*ClaimedAction){
		"unexpected READ pool": func(claimed *ClaimedAction) {
			claimed.Execution.Pool = executionlease.PoolRead
		},
		"production raised only on execution": func(claimed *ClaimedAction) {
			claimed.Execution.Production = true
		},
		"production raised only on claimed metadata": func(claimed *ClaimedAction) {
			claimed.Production = true
		},
		"execution id differs from envelope": func(claimed *ClaimedAction) {
			claimed.Execution.ExecutionID = "another-action"
		},
		"target key differs from execution": func(claimed *ClaimedAction) {
			claimed.TargetKey = "kubernetes-deployment:sha256:" + strings.Repeat("f", 64)
		},
		"plan hash differs from envelope": func(claimed *ClaimedAction) {
			claimed.PlanHash = strings.Repeat("f", 64)
		},
		"workspace and environment pair is outside runner scope": func(claimed *ClaimedAction) {
			claimed.Envelope.WorkspaceID = "workspace-outside-runner-scope"
			claimed.Execution.RunnerWorkspaceID = claimed.Envelope.WorkspaceID
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			claimed := baseClaim
			mutate(&claimed)
			fixture := newForcedClaimFixture(t, now, claimed)

			result, runErr := fixture.service.RunNext(context.Background())
			if runErr != ErrJobConflict || strings.Contains(runErr.Error(), claimed.Execution.LeaseToken) ||
				result.LeaseToken != "" || result.Status != executionlease.StatusLeased {
				t.Fatalf("RunNext(metadata anomaly) = %#v, %v; want redacted retained lease and exact %v", result, runErr, ErrJobConflict)
			}
			if fixture.queue.claimCalls != 1 || len(fixture.queue.mutations) != 0 ||
				fixture.keys.calls != 0 || fixture.environment.calls != 0 || fixture.credentials.issueCalls != 0 ||
				len(fixture.policyEvents.snapshot()) != 0 || len(fixture.executors.calls) != 0 {
				t.Fatalf("metadata anomaly crossed the trust boundary: claims=%d mutations=%v keys=%d environment=%d credentials=%d policy=%v executors=%v",
					fixture.queue.claimCalls, fixture.queue.mutations, fixture.keys.calls, fixture.environment.calls,
					fixture.credentials.issueCalls, fixture.policyEvents.snapshot(), fixture.executors.calls)
			}
		})
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
			}, Options{RunnerID: "runner-1", LeaseDuration: time.Minute, Clock: func() time.Time { return now }})

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
		"safety:claim", "lease:claim", "environment:resolve", "policy:credential-issue", "policy:pre-execution",
		"safety:start", "environment:resolve", "credential:prepare", "lease:start", "lease:heartbeat",
		"credential:issue", "credential:validate-manager", "credential:create-child", "credential:inspect-child",
		"credential:issue-dynamic", "lease:heartbeat", "executor:kubernetes-rollout-restart", "lease:heartbeat",
		"lease:complete", "credential:request-revocation", "lease:finalize",
	}
	if got := fixture.events.snapshot(); !equalStrings(got, wantOrder) {
		t.Fatalf("call order = %v, want %v", got, wantOrder)
	}
	preparedRequest := fixture.credentials.preparedRequest
	if preparedRequest.Selection.TenantID != "tenant-test" ||
		preparedRequest.Selection.WorkspaceID != envelope.WorkspaceID ||
		preparedRequest.Selection.EnvironmentID != envelope.Target.EnvironmentID ||
		preparedRequest.Selection.Production || preparedRequest.Selection.ActionType != string(envelope.ActionType) ||
		preparedRequest.Selection.ConnectorID != envelope.CredentialScope.ConnectorID ||
		preparedRequest.Selection.Permission != envelope.CredentialScope.Permission ||
		preparedRequest.Selection.Resource != envelope.CredentialScope.Resource ||
		preparedRequest.RequestedTTL != time.Duration(envelope.CredentialScope.TTLSeconds)*time.Second ||
		preparedRequest.PolicyExpiresAt != fixture.preExecution.credentialDecision.CredentialExpiresAt {
		t.Fatalf("durable credential request was not built from trusted runner/envelope/policy state: %#v", preparedRequest)
	}
	if len(fixture.safety.requests) != 2 {
		t.Fatalf("safety requests = %#v", fixture.safety.requests)
	}
	startRequest := fixture.safety.requests[1]
	if startRequest.WorkspaceID != envelope.WorkspaceID || startRequest.EnvironmentID != envelope.Target.EnvironmentID ||
		startRequest.ConnectorID != envelope.CredentialScope.ConnectorID || startRequest.ActionType != envelope.ActionType {
		t.Fatalf("start safety request is not action-scoped: %#v", startRequest)
	}
	if !fixture.executors.credentialCaptured || fixture.executors.capturedCredential.Secret() != nil {
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
		RunnerID: "runner-1", LeaseDuration: time.Minute, FinalizeTimeout: time.Second, Clock: func() time.Time { return now },
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
	fixture.service.heartbeatInterval = 2 * time.Second
	fixture.service.finalizeTimeout = 5 * time.Second
	heartbeatSequences := make(chan int64, 4)
	heartbeatSequenceEnabled := make(chan struct{})
	executorEntered := make(chan struct{}, 1)
	releaseExecutor := make(chan struct{})
	fixture.leases.heartbeatSequences = heartbeatSequences
	fixture.leases.heartbeatSequenceGate = heartbeatSequenceEnabled
	fixture.executors.entered = executorEntered
	fixture.executors.release = releaseExecutor
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseExecutor) }) }
	t.Cleanup(release)
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
	awaitTestSignal(t, executorEntered, "the typed executor to enter before periodic heartbeat")
	close(heartbeatSequenceEnabled)
	sequence := awaitTestValue(t, heartbeatSequences, "a periodic heartbeat after executor entry")
	if sequence < 3 {
		t.Fatalf("heartbeat after executor entry used sequence %d, want at least 3", sequence)
	}
	release()
	result := awaitTestValue(t, completed, "RunNext to complete after executor release")
	if result.err != nil || result.execution.Status != executionlease.StatusSucceeded {
		t.Fatalf("RunNext() = %#v, %v; events=%v", result.execution, result.err, fixture.events.snapshot())
	}
	if !contains(fixture.events.snapshot(), "lease:heartbeat") {
		t.Fatalf("heartbeat was not recorded: %v", fixture.events.snapshot())
	}
}

func TestRunNextInitialHeartbeatFailureRecordsNoCredentialBeforeIssuerOrExecutor(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	fixture.service.heartbeatInterval = 2 * time.Second
	fixture.service.finalizeTimeout = 5 * time.Second
	fixture.leases.heartbeatErr = errors.New("heartbeat transport failed")
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}

	execution, err := fixture.service.RunNext(context.Background())
	if !errors.Is(err, ErrExecutionUncertain) {
		t.Fatalf("RunNext() error = %v, want %v", err, ErrExecutionUncertain)
	}
	if execution.Status != executionlease.StatusRunning || execution.ResultHash != "" {
		t.Fatalf("execution = %#v", execution)
	}
	if fixture.credentials.issueCalls != 0 || fixture.credentials.recordNoCredentialCalls != 1 || len(fixture.executors.calls) != 0 {
		t.Fatalf("initial heartbeat failure crossed issuance boundary: issue=%d no-credential=%d executors=%v",
			fixture.credentials.issueCalls, fixture.credentials.recordNoCredentialCalls, fixture.executors.calls)
	}
}

func TestServiceDurableIssuerCanonicalizesChildExpiryAcrossPlatformClockPrecision(t *testing.T) {
	t.Parallel()

	authorizedAt := time.Date(2026, 7, 11, 6, 40, 0, 123, time.UTC)
	issuer := &serviceDurableIssuer{}
	child, err := issuer.CreateChild(context.Background(), credential.DurableChildCreateRequest{
		DatabaseAuthorizedAt: authorizedAt,
		TTL:                  time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateChild() error = %v", err)
	}
	defer child.Token.Destroy()
	defer child.Accessor.Destroy()
	want := credential.CanonicalCredentialExpiry(authorizedAt.Add(time.Minute))
	if child.ExpiresAt != want || child.ExpiresAt != credential.CanonicalCredentialExpiry(child.ExpiresAt) {
		t.Fatalf("CreateChild() expiry = %s, want canonical %s", child.ExpiresAt, want)
	}
}

func TestRunNextHeartbeatLossDuringIssuanceNeverStartsExecutor(t *testing.T) {
	now := time.Now().UTC()
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "MUST_NOT_RUN", Verification: VerificationPassed, Changed: true,
	})
	// The heartbeat cadence is part of the behavior under test, but reaching the
	// blocked issuer is synchronized by a channel rather than racing a tiny
	// timer. A two-second interval also keeps the heartbeat RPC deadline valid on
	// a loaded race-enabled CI runner.
	fixture.service.heartbeatInterval = 2 * time.Second
	fixture.service.finalizeTimeout = 5 * time.Second
	// This case verifies the durable pending-cleanup handoff. The shared fixture
	// normally completes revocation synchronously, which makes the assertion
	// depend on whether the cancellation deadline beats the fake revocation
	// worker on a loaded CI host.
	fixture.credentials.terminalOnRequest = false
	fixture.leases.heartbeatErr = errors.New("heartbeat lease lost")
	fixture.leases.heartbeatErrAfter = 2
	heartbeatFailureEnabled := make(chan struct{})
	heartbeatFailed := make(chan struct{}, 1)
	fixture.leases.heartbeatErrGate = heartbeatFailureEnabled
	fixture.leases.heartbeatFailed = heartbeatFailed
	issueEntered := make(chan struct{}, 1)
	issueRelease := make(chan struct{})
	fixture.issuer.issueEntered = issueEntered
	fixture.issuer.issueRelease = issueRelease
	fixture.issuer.ignoreCancellation = true
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}

	type runResult struct {
		execution executionlease.Execution
		err       error
	}
	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	var releaseIssue sync.Once
	release := func() { releaseIssue.Do(func() { close(issueRelease) }) }
	t.Cleanup(release)
	runDone := make(chan runResult, 1)
	go func() {
		execution, err := fixture.service.RunNext(runContext)
		runDone <- runResult{execution: execution, err: err}
	}()
	awaitTestSignal(t, issueEntered, "durable issuance to enter the blocked dynamic issuer")
	close(heartbeatFailureEnabled)
	awaitTestSignal(t, heartbeatFailed, "a heartbeat loss while dynamic issuance is blocked")
	release()
	result := awaitTestValue(t, runDone, "RunNext to converge after the late issuer returned")
	if !errors.Is(result.err, ErrExecutionUncertain) || result.execution.Status != executionlease.StatusUncertain {
		t.Fatalf("RunNext() = %#v, %v; want UNCERTAIN after issuance heartbeat loss; events=%v",
			result.execution, result.err, fixture.events.snapshot())
	}
	if len(fixture.executors.calls) != 0 || fixture.credentials.issueCalls != 1 {
		t.Fatalf("late issuance crossed executor gate: issue=%d executors=%v", fixture.credentials.issueCalls, fixture.executors.calls)
	}
	revocations, err := fixture.credentialRepo.List(context.Background(), credential.ListFilter{
		WorkspaceID: envelope.WorkspaceID, Limit: 10,
	})
	if err != nil || len(revocations) != 1 ||
		(revocations[0].Status != credential.StatusRevocationPending && revocations[0].Status != credential.StatusRevoking) {
		t.Fatalf("credential cleanup after lost issuance heartbeat = %#v, %v", revocations, err)
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
			snapshot := nonProductionEnvironment(envelope, now)
			snapshot.Revision = "environment-2"
			return snapshot
		}(), wantErr: ErrEnvironmentDrift, status: executionlease.StatusFailed},
		"production classification drift": {snapshot: func() EnvironmentSnapshot {
			snapshot := nonProductionEnvironment(envelope, now)
			snapshot.Production = true
			return snapshot
		}(), wantErr: ErrEnvironmentDrift, status: executionlease.StatusFailed},
		"snapshot expired": {snapshot: func() EnvironmentSnapshot {
			snapshot := nonProductionEnvironment(envelope, now)
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
			fixture.environment.snapshots = []EnvironmentSnapshot{nonProductionEnvironment(envelope, now), test.snapshot}
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
	changed := nonProductionEnvironment(envelope, now)
	changed.Revision = "environment-2"
	fixture.environment.snapshots = []EnvironmentSnapshot{
		nonProductionEnvironment(envelope, now), nonProductionEnvironment(envelope, now), changed,
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
		Scope:         testRunnerScope(t, "runner-2", RunnerScopeBinding{WorkspaceID: "workspace-1", EnvironmentID: "PROD"}),
		LeaseDuration: time.Minute,
	}); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("permanently denied action was redelivered: %v", err)
	}
	if fixture.credentials.requestRevocationCalls != 0 {
		t.Fatalf("credential revocation requests = %d, want 0 before Prepare", fixture.credentials.requestRevocationCalls)
	}
}

func TestRunNextPermanentlyRejectsDeterministicCredentialPolicyDenial(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return now })
	service := mustService(t, Dependencies{
		Queue: queue, Keys: keys,
		Environments: &fakeEnvironmentResolver{snapshots: []EnvironmentSnapshot{nonProductionEnvironment(envelope, now)}},
		Safety:       &fakeSafetyGate{snapshots: []ClaimSafetySnapshot{validSafety(now)}},
		Credentials:  &fakeCredentialBroker{err: credential.ErrCredentialDenied},
		Policy:       &fakePreExecutionGate{}, Executors: noOpExecutors(),
	}, Options{
		RunnerID: "runner-1", LeaseDuration: time.Minute, Clock: func() time.Time { return now },
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

	now := credential.CanonicalCredentialExpiry(time.Now().UTC())
	unsigned := restartEnvelope(now)
	unsigned.Verification.TimeoutSeconds = 1
	calculated, err := boundedExecutionDeadline(context.Background(), unsigned, now.Add(5*time.Minute), now)
	if err != nil || !calculated.Equal(now.Add(time.Second)) {
		t.Fatalf("boundedExecutionDeadline(1s signed timeout) = %s, %v", calculated, err)
	}

	// The end-to-end assertion uses a comfortable signed timeout and the real
	// clock. The exact one-second arithmetic is proven above without requiring
	// the entire durable issuance path to beat a one-second CI scheduling race.
	unsigned.Verification.TimeoutSeconds = 30
	envelope, keys := signedEnvelope(t, unsigned)
	fixture := newRunnerFixtureWithClock(t, time.Now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if _, err := fixture.service.RunNext(context.Background()); err != nil {
		t.Fatalf("RunNext() error = %v", err)
	}
	deadline, enteredAt := fixture.executors.capturedDeadline, fixture.executors.enteredAt
	remaining := deadline.Sub(enteredAt)
	if deadline.IsZero() || enteredAt.IsZero() || remaining <= 0 || remaining > 30*time.Second {
		t.Fatalf("executor entered/deadline = %s/%s (remaining %s), want within signed 30s timeout; events=%v",
			enteredAt, deadline, remaining, fixture.events.snapshot())
	}
}

func TestMappedExecutionDeadlinePreservesShortLogicalWindowWithoutMovingLater(t *testing.T) {
	t.Parallel()

	logicalNow := time.Date(2026, 7, 11, 6, 40, 0, 0, time.UTC)
	localNow := time.Now()
	for _, test := range []struct {
		name            string
		logicalDeadline time.Time
		wantRemaining   time.Duration
		valid           bool
	}{
		{name: "zero deadline"},
		{name: "expired", logicalDeadline: logicalNow},
		{name: "one second remains", logicalDeadline: logicalNow.Add(time.Second), wantRemaining: time.Second, valid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			deadline, valid := mappedExecutionDeadline(test.logicalDeadline, logicalNow, localNow)
			remaining := time.Duration(0)
			if !deadline.IsZero() {
				remaining = deadline.Sub(localNow)
			}
			if remaining != test.wantRemaining || valid != test.valid {
				t.Fatalf("mappedExecutionDeadline() = %s (%s), %v; want remaining %s, %v",
					deadline, remaining, valid, test.wantRemaining, test.valid)
			}
		})
	}
}

func TestRunNextBoundsExecutorContextByTheActualDurableCredentialExpiry(t *testing.T) {
	now := credential.CanonicalCredentialExpiry(time.Now().UTC())
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixtureWithClock(t, time.Now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	// This remains materially shorter than the five-minute policy deadline, but
	// does not require a loaded CI runner to finish activation and dispatch in a
	// 250ms scheduling window. The executor returns immediately after capturing
	// the context deadline; cancellation behavior is covered by the explicit
	// entered-then-cancel test below.
	fixture.issuer.dynamicTTL = 30 * time.Second
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}

	completed, err := fixture.service.RunNext(context.Background())
	if err != nil || completed.Status != executionlease.StatusSucceeded {
		t.Fatalf("RunNext(short credential TTL) = %#v, %v; events=%v", completed, err, fixture.events.snapshot())
	}
	credentialExpiry := fixture.executors.capturedCredential.ExpiresAt()
	deadline, enteredAt := fixture.executors.capturedDeadline, fixture.executors.enteredAt
	remaining := deadline.Sub(enteredAt)
	if deadline.IsZero() || enteredAt.IsZero() || credentialExpiry.IsZero() || deadline.After(credentialExpiry) ||
		remaining <= 0 || remaining > 30*time.Second {
		t.Fatalf("executor entered/deadline/credential expiry = %s/%s/%s (remaining %s)",
			enteredAt, deadline, credentialExpiry, remaining)
	}
	if fixture.credentials.requestRevocationCalls != 1 || fixture.executors.capturedCredential.Secret() != nil {
		t.Fatalf("credential cleanup = requests %d secret %v",
			fixture.credentials.requestRevocationCalls, fixture.executors.capturedCredential.Secret())
	}
}

func TestRunNextActualCredentialExpiryCancelsExecutionAndRequestsCleanup(t *testing.T) {
	now := credential.CanonicalCredentialExpiry(time.Now().UTC())
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixtureWithClock(t, time.Now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "MUST_NOT_SURVIVE_CREDENTIAL_EXPIRY", Verification: VerificationPassed, Changed: true,
	})
	// This test intentionally exercises real timer behavior. First synchronize on
	// executor entry, then let the materially-shorter dynamic credential deadline
	// fire. Five seconds is long enough for race-enabled CI dispatch while still
	// keeping the test bounded by the shared watchdog.
	fixture.issuer.dynamicTTL = 5 * time.Second
	fixture.executors.waitForCancellation = true
	executorEntered := make(chan struct{}, 1)
	fixture.executors.entered = executorEntered
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}

	type runResult struct {
		execution executionlease.Execution
		err       error
	}
	runContext, cancelRun := context.WithTimeout(context.Background(), asynchronousTestWatchdog)
	defer cancelRun()
	runDone := make(chan runResult, 1)
	go func() {
		execution, err := fixture.service.RunNext(runContext)
		runDone <- runResult{execution: execution, err: err}
	}()
	awaitTestSignal(t, executorEntered, "executor entry before dynamic credential expiry")
	result := awaitTestValue(t, runDone, "dynamic credential expiry to stop execution")
	if !errors.Is(result.err, ErrExecutionUncertain) || result.execution.Status != executionlease.StatusUncertain {
		t.Fatalf("RunNext(actual credential expiry) = %#v, %v; events=%v",
			result.execution, result.err, fixture.events.snapshot())
	}
	credentialExpiry := fixture.executors.capturedCredential.ExpiresAt()
	if fixture.executors.capturedDeadline.IsZero() || credentialExpiry.IsZero() ||
		fixture.executors.capturedDeadline.After(credentialExpiry) {
		t.Fatalf("executor deadline = %s, credential expiry = %s",
			fixture.executors.capturedDeadline, credentialExpiry)
	}
	if fixture.credentials.requestRevocationCalls != 1 || fixture.executors.capturedCredential.Secret() != nil {
		t.Fatalf("credential expiry cleanup = requests %d secret %v",
			fixture.credentials.requestRevocationCalls, fixture.executors.capturedCredential.Secret())
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
	if fixture.credentials.requestRevocationCalls != 1 {
		t.Fatalf("credential revocation requests = %d, want 1", fixture.credentials.requestRevocationCalls)
	}
}

func TestRunNextCredentialRevokeFailureLeavesDurableFinalizingState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	fixture.credentials.requestRevocationErr = errors.New("credential persistence unavailable")
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}

	result, err := fixture.service.RunNext(context.Background())
	if !errors.Is(err, ErrCredentialCleanupPending) || result.Status != executionlease.StatusFinalizing ||
		result.CompletionStatus != executionlease.StatusSucceeded {
		t.Fatalf("RunNext() = %#v, %v; want durable FINALIZING revoke failure", result, err)
	}
	persisted, getErr := fixture.leases.Get(context.Background(), envelope.ActionID)
	if getErr != nil || persisted.Status != executionlease.StatusFinalizing {
		t.Fatalf("Get() = %#v, %v; want FINALIZING", persisted, getErr)
	}
	for _, event := range fixture.events.snapshot() {
		if event == "lease:finalize" {
			t.Fatalf("revoke failure invoked Finalize: %v", fixture.events.snapshot())
		}
	}
}

func TestRunNextSuccessfulExecutorKeepsOriginalCompletionWhileCleanupPending(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	fixture.credentials.terminalOnRequest = false
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}

	result, err := fixture.service.RunNext(context.Background())
	if !errors.Is(err, ErrCredentialCleanupPending) || errors.Is(err, ErrExecutionFailed) ||
		result.Status != executionlease.StatusFinalizing || result.CompletionStatus != executionlease.StatusSucceeded {
		t.Fatalf("RunNext(cleanup pending) = %#v, %v", result, err)
	}
	if len(result.ResultHash) != 64 || fixture.credentials.requestRevocationCalls != 1 ||
		fixture.executors.capturedCredential.Secret() != nil {
		t.Fatalf("pending cleanup lost result or secret hygiene: result=%#v requests=%d",
			result, fixture.credentials.requestRevocationCalls)
	}
	if contains(fixture.events.snapshot(), "lease:finalize") {
		t.Fatalf("nonterminal cleanup invoked Finalize: %v", fixture.events.snapshot())
	}
}

func TestRunNextFinalizeFailureLeavesRecoverableFinalizingState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixtureWithClock(t, func() time.Time { return clock }, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	fixture.leases.finalizeErr = errors.New("finalize response lost")
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}

	result, err := fixture.service.RunNext(context.Background())
	if !errors.Is(err, ErrExecutionUncertain) || result.Status != executionlease.StatusFinalizing {
		t.Fatalf("RunNext() = %#v, %v; want recoverable FINALIZING", result, err)
	}
	persisted, getErr := fixture.leases.Get(context.Background(), envelope.ActionID)
	if getErr != nil || persisted.Status != executionlease.StatusFinalizing {
		t.Fatalf("Get() = %#v, %v; want FINALIZING", persisted, getErr)
	}
	clock = envelope.ExpiresAt
	if err := fixture.leases.memory.SweepExpired(context.Background()); err != nil {
		t.Fatalf("SweepExpired() error = %v", err)
	}
	recovered, getErr := fixture.leases.Get(context.Background(), envelope.ActionID)
	if getErr != nil || recovered.Status != executionlease.StatusSucceeded {
		t.Fatalf("Get(recovered) = %#v, %v", recovered, getErr)
	}
}

func TestRunNextInitialHeartbeatScopeChangePreventsIssuerAndExecutor(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "SHOULD_NOT_COMPLETE", Verification: VerificationPassed, Changed: true,
	})
	base := RunnerRegistration{
		RunnerID: "runner-1", TenantID: "tenant-test", Pool: executionlease.PoolWrite, Enabled: true, ScopeRevision: 1, MaxConcurrency: 1,
		ScopeBindings: []RunnerScopeBinding{{WorkspaceID: "workspace-1", EnvironmentID: "PROD"}},
	}
	changed := base
	changed.ScopeRevision = 2
	fixture.service.dependencies.RunnerRegistrations = &sequenceRunnerRegistrationRepository{
		registrations: []RunnerRegistration{base, base, changed},
	}
	fixture.service.heartbeatInterval = 2 * time.Second
	fixture.service.finalizeTimeout = 5 * time.Second
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}

	result, err := fixture.service.RunNext(context.Background())
	if !errors.Is(err, ErrExecutionUncertain) || result.Status != executionlease.StatusRunning {
		t.Fatalf("RunNext(scope revision changed) = %#v, %v", result, err)
	}
	if fixture.credentials.issueCalls != 0 || fixture.credentials.recordNoCredentialCalls != 1 || len(fixture.executors.calls) != 0 {
		t.Fatalf("scope change crossed issuance boundary: issue=%d no-credential=%d executors=%v",
			fixture.credentials.issueCalls, fixture.credentials.recordNoCredentialCalls, fixture.executors.calls)
	}
}

func TestRunNextBoundsInitialHeartbeatRegistryResolutionBeforeIssuer(t *testing.T) {
	now := time.Now().UTC()
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	registration := RunnerRegistration{
		RunnerID: "runner-1", TenantID: "tenant-test", Pool: executionlease.PoolWrite, Enabled: true, ScopeRevision: 1, MaxConcurrency: 1,
		ScopeBindings: []RunnerScopeBinding{{WorkspaceID: "workspace-1", EnvironmentID: "PROD"}},
	}
	heartbeatResolveEntered := make(chan struct{}, 1)
	fixture.service.dependencies.RunnerRegistrations = &blockingHeartbeatRunnerRegistrationRepository{
		registration: registration, heartbeatResolveEntered: heartbeatResolveEntered,
	}
	// This test intentionally verifies the heartbeat RPC timeout. The registry
	// fake first signals entry, then waits for the bounded context to expire.
	fixture.service.heartbeatInterval = 100 * time.Millisecond
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	type runResult struct {
		execution executionlease.Execution
		err       error
	}
	runDone := make(chan runResult, 1)
	go func() {
		execution, err := fixture.service.RunNext(context.Background())
		runDone <- runResult{execution: execution, err: err}
	}()
	awaitTestSignal(t, heartbeatResolveEntered, "heartbeat registry resolution to block")
	result := awaitTestValue(t, runDone, "RunNext to fail closed after heartbeat timeout")
	if !errors.Is(result.err, ErrExecutionUncertain) || result.execution.Status != executionlease.StatusRunning {
		t.Fatalf("RunNext() = %#v, %v; blocked initial heartbeat must fail closed", result.execution, result.err)
	}
	if fixture.credentials.issueCalls != 0 || fixture.credentials.recordNoCredentialCalls != 1 || len(fixture.executors.calls) != 0 {
		t.Fatalf("blocked initial heartbeat crossed issuance boundary: issue=%d no-credential=%d executors=%v",
			fixture.credentials.issueCalls, fixture.credentials.recordNoCredentialCalls, fixture.executors.calls)
	}
}

func TestRunNextExecutorCannotTamperWithCredentialRevocationMetadata(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, keys := signedEnvelope(t, restartEnvelope(now))
	fixture := newRunnerFixture(t, now, envelope, keys, ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true,
	})
	fixture.executors.destroyCredential = true
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if _, err := fixture.service.RunNext(context.Background()); err != nil {
		t.Fatalf("RunNext() error = %v", err)
	}
	if fixture.credentials.requestRevocationCalls != 1 {
		t.Fatalf("credential revocation requests = %d, want 1", fixture.credentials.requestRevocationCalls)
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
	entered := make(chan struct{}, 1)
	fixture.executors.ignoreCancellation = true
	fixture.executors.release = release
	fixture.executors.finished = finished
	fixture.executors.entered = entered
	if _, err := fixture.service.Submit(context.Background(), envelope); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var releaseExecutor sync.Once
	releaseLateExecutor := func() { releaseExecutor.Do(func() { close(release) }) }
	t.Cleanup(releaseLateExecutor)
	type runResult struct {
		execution executionlease.Execution
		err       error
	}
	completed := make(chan runResult, 1)
	go func() {
		execution, err := fixture.service.RunNext(ctx)
		completed <- runResult{execution: execution, err: err}
	}()
	awaitTestSignal(t, entered, "the context-ignoring executor to enter")
	cancel()
	result := awaitTestValue(t, completed, "RunNext to stop after cancellation")
	if !errors.Is(result.err, ErrExecutionUncertain) || result.execution.LeaseToken != "" {
		t.Fatalf("RunNext(cancelled executor) = %#v, %v; events=%v",
			result.execution, result.err, fixture.events.snapshot())
	}
	select {
	case <-finished:
		t.Fatal("context-ignoring executor exited before its explicit release")
	default:
	}
	releaseLateExecutor()
	awaitTestSignal(t, finished, "the late executor to exit after explicit release")
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
		wantCode    string
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
		"malformed external operation reference hash": {
			result: ExecutorResult{
				Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed,
				Changed: true, ExternalOperationRefHash: "not-a-sha256",
			},
			wantStatus: executionlease.StatusUncertain, wantError: ErrExecutionUncertain, wantCode: "INVALID_EXECUTOR_RESULT",
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
			if test.wantCode != "" {
				fixture.leases.memory.mu.Lock()
				receipt := fixture.leases.memory.records[envelope.ActionID].receipt
				fixture.leases.memory.mu.Unlock()
				if receipt == nil || receipt.CompletionStatus != executionlease.StatusUncertain || receipt.Summary.Code != test.wantCode {
					t.Fatalf("persisted receipt = %#v, want UNCERTAIN code %q", receipt, test.wantCode)
				}
			}
		})
	}
}

func TestValidExecutorResultRequiresEmptyOrLowercaseSHA256ExternalOperationReference(t *testing.T) {
	t.Parallel()

	base := ExecutorResult{Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed}
	tests := map[string]struct {
		hash string
		want bool
	}{
		"empty":            {want: true},
		"lowercase SHA256": {hash: strings.Repeat("a", 64), want: true},
		"uppercase SHA256": {hash: strings.Repeat("A", 64), want: false},
		"malformed":        {hash: "not-a-sha256", want: false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			result := base
			result.ExternalOperationRefHash = test.hash
			if got := validExecutorResult(result); got != test.want {
				t.Fatalf("validExecutorResult(hash=%q) = %t, want %t", test.hash, got, test.want)
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
	if fixture.credentials.prepareCalls != 1 || fixture.credentials.recordNoCredentialCalls != 1 ||
		fixture.credentials.issueCalls != 0 || fixture.issuer.createCalls != 0 {
		t.Fatalf("Start failure cleanup = prepare/no-credential/issue/create %d/%d/%d/%d",
			fixture.credentials.prepareCalls, fixture.credentials.recordNoCredentialCalls,
			fixture.credentials.issueCalls, fixture.issuer.createCalls)
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

type forcedClaimFixture struct {
	service      *Service
	queue        *forcedClaimActionQueue
	keys         *countingKeyResolver
	environment  *fakeEnvironmentResolver
	credentials  *countingCredentialBroker
	policyEvents *eventLog
	executors    *recordingExecutors
}

func newForcedClaimFixture(t *testing.T, now time.Time, claimed ClaimedAction) *forcedClaimFixture {
	t.Helper()
	queue := &forcedClaimActionQueue{claimed: claimed}
	keys := &countingKeyResolver{}
	environment := &fakeEnvironmentResolver{snapshots: []EnvironmentSnapshot{validEnvironment(claimed.Envelope, now)}}
	credentials := &countingCredentialBroker{}
	policyEvents := &eventLog{}
	executors := &recordingExecutors{result: ExecutorResult{
		Outcome: ExecutorSucceeded, Code: "MUST_NOT_RUN", Verification: VerificationPassed,
	}}
	service := mustService(t, Dependencies{
		Queue: queue, Keys: keys, Environments: environment,
		Safety:      &fakeSafetyGate{snapshots: []ClaimSafetySnapshot{validSafety(now)}},
		Credentials: credentials,
		Policy:      &fakePreExecutionGate{events: policyEvents},
		Executors:   executors.asDependencies(),
	}, Options{RunnerID: "runner-1", LeaseDuration: time.Minute, FinalizeTimeout: time.Second, Clock: func() time.Time { return now }})
	return &forcedClaimFixture{
		service: service, queue: queue, keys: keys, environment: environment,
		credentials: credentials, policyEvents: policyEvents, executors: executors,
	}
}

type runnerFixture struct {
	service        *Service
	leases         *recordingActionQueue
	environment    *fakeEnvironmentResolver
	safety         *fakeSafetyGate
	preExecution   *fakePreExecutionGate
	credentialGate *fakePreExecutionGate
	credentials    *serviceDurableCredentialBroker
	credentialRepo *credential.MemoryRepository
	issuer         *serviceDurableIssuer
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
	actionSource := &serviceActionFenceSource{}
	protector, err := credential.NewAESGCMProtector(credential.KeyRing{
		ActiveKeyID: "execution-test-key",
		Keys: map[string]credential.ProtectionKey{
			"execution-test-key": {
				EncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
				HMACKey:       []byte("abcdef0123456789abcdef0123456789"),
			},
		},
	})
	if err != nil {
		t.Fatalf("credential.NewAESGCMProtector() error = %v", err)
	}
	credentialRepo, err := credential.NewMemoryRepository(actionSource, protector, credential.MemoryRepositoryOptions{
		Clock: clock,
		TokenSource: func() (string, error) {
			return "execution-revocation-claim-token", nil
		},
		PermitSource: func() (string, error) {
			return "execution-child-create-permit", nil
		},
	})
	if err != nil {
		t.Fatalf("credential.NewMemoryRepository() error = %v", err)
	}
	memoryQueue, err := NewMemoryActionQueue(MemoryActionQueueOptions{
		Clock: clock, CredentialFinalizationGate: credentialRepo,
		TokenSource: func() (string, error) { return "queue-lease-token", nil },
	})
	if err != nil {
		t.Fatalf("NewMemoryActionQueue() error = %v", err)
	}
	leases := &recordingActionQueue{ActionQueue: memoryQueue, memory: memoryQueue, events: events, actionSource: actionSource}
	environment := &fakeEnvironmentResolver{snapshots: []EnvironmentSnapshot{nonProductionEnvironment(envelope, clock()), nonProductionEnvironment(envelope, clock())}, events: events}
	safety := &fakeSafetyGate{snapshots: []ClaimSafetySnapshot{validSafety(clock()), validStartSafety(envelope, clock())}, events: events}
	preExecution := &fakePreExecutionGate{
		decision: preExecutionDecision(envelope, clock()), credentialDecision: credentialDecision(envelope, clock()), events: events,
	}
	issuer := &serviceDurableIssuer{clock: clock, events: events}
	registry, err := credential.NewIssuerRegistry([]credential.IssuerRegistration{{
		Selection: credential.DurableIssuerResolveRequest{
			TenantID: "tenant-test", WorkspaceID: envelope.WorkspaceID, EnvironmentID: envelope.Target.EnvironmentID,
			Production: false, ActionType: string(envelope.ActionType), ConnectorID: envelope.CredentialScope.ConnectorID,
			Permission: envelope.CredentialScope.Permission, Resource: envelope.CredentialScope.Resource,
		},
		Profile: credential.DurableIssuerProfile{
			IssuerID: issuer.IssuerID(), Revision: issuer.IssuerRevision(), CredentialTTL: 5 * time.Minute,
		},
		Issuer: issuer,
	}})
	if err != nil {
		t.Fatalf("credential.NewIssuerRegistry() error = %v", err)
	}
	broker, err := credential.NewDurableBroker(credentialRepo, registry, credential.DurableBrokerOptions{
		Clock: clock,
		UUIDSource: func() (string, error) {
			return "11111111-1111-4111-8111-111111111111", nil
		},
	})
	if err != nil {
		t.Fatalf("credential.NewDurableBroker() error = %v", err)
	}
	credentials := &serviceDurableCredentialBroker{
		broker: broker, repository: credentialRepo, events: events, terminalOnRequest: true,
	}
	executors := &recordingExecutors{result: result, events: events}
	service := mustService(t, Dependencies{
		Queue: leases, Keys: keys, Environments: environment, Safety: safety,
		Credentials: credentials, Policy: preExecution, Executors: executors.asDependencies(),
	}, Options{RunnerID: "runner-1", LeaseDuration: time.Minute, FinalizeTimeout: time.Second, Clock: clock})
	return &runnerFixture{
		service: service, leases: leases, environment: environment, safety: safety,
		preExecution: preExecution, credentialGate: preExecution, credentials: credentials,
		credentialRepo: credentialRepo, issuer: issuer,
		executors: executors, events: events,
	}
}

func mustService(t *testing.T, dependencies Dependencies, options Options) *Service {
	t.Helper()
	if dependencies.RunnerRegistrations == nil {
		dependencies.RunnerRegistrations = fakeRunnerRegistrationRepository{
			registration: RunnerRegistration{
				RunnerID: options.RunnerID, TenantID: "tenant-test", Pool: executionlease.PoolWrite, Enabled: true, ScopeRevision: 1, MaxConcurrency: 1,
				ScopeBindings: []RunnerScopeBinding{{WorkspaceID: "workspace-1", EnvironmentID: "PROD"}},
			},
		}
	}
	service, err := NewService(dependencies, options)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

type fakeRunnerRegistrationRepository struct {
	registration RunnerRegistration
	err          error
}

type sequenceRunnerRegistrationRepository struct {
	mu            sync.Mutex
	registrations []RunnerRegistration
	calls         int
}

type blockingHeartbeatRunnerRegistrationRepository struct {
	mu                      sync.Mutex
	registration            RunnerRegistration
	calls                   int
	heartbeatResolveEntered chan<- struct{}
}

func (repository *blockingHeartbeatRunnerRegistrationRepository) Resolve(ctx context.Context, runnerID string) (RunnerRegistration, error) {
	repository.mu.Lock()
	repository.calls++
	call := repository.calls
	registration := repository.registration
	repository.mu.Unlock()
	if call <= 2 {
		return registration, nil
	}
	select {
	case repository.heartbeatResolveEntered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return RunnerRegistration{}, ctx.Err()
}

func (repository *sequenceRunnerRegistrationRepository) Resolve(ctx context.Context, runnerID string) (RunnerRegistration, error) {
	if err := ctx.Err(); err != nil {
		return RunnerRegistration{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if len(repository.registrations) == 0 {
		return RunnerRegistration{}, executionlease.ErrNotFound
	}
	index := repository.calls
	if index >= len(repository.registrations) {
		index = len(repository.registrations) - 1
	}
	repository.calls++
	registration := repository.registrations[index]
	if registration.RunnerID != runnerID {
		return RunnerRegistration{}, executionlease.ErrNotFound
	}
	registration.ScopeBindings = append([]RunnerScopeBinding(nil), registration.ScopeBindings...)
	return registration, nil
}

func (repository fakeRunnerRegistrationRepository) Resolve(ctx context.Context, runnerID string) (RunnerRegistration, error) {
	if err := ctx.Err(); err != nil {
		return RunnerRegistration{}, err
	}
	if repository.err != nil {
		return RunnerRegistration{}, repository.err
	}
	if repository.registration.RunnerID != runnerID {
		return RunnerRegistration{}, executionlease.ErrNotFound
	}
	registration := repository.registration
	registration.ScopeBindings = append([]RunnerScopeBinding(nil), registration.ScopeBindings...)
	return registration, nil
}

type recordingActionQueue struct {
	ActionQueue
	memory                *MemoryActionQueue
	events                *eventLog
	actionSource          *serviceActionFenceSource
	startErr              error
	heartbeatErr          error
	heartbeatErrAfter     int
	heartbeatErrGate      <-chan struct{}
	heartbeatCalls        int
	heartbeatFailed       chan<- struct{}
	heartbeatSequences    chan<- int64
	heartbeatSequenceGate <-chan struct{}
	completeErr           error
	finalizeErr           error
	heartbeatObserved     chan<- struct{}
}

type forcedClaimActionQueue struct {
	ActionQueue
	claimed    ClaimedAction
	claimCalls int
	mutations  []string
}

func (queue *forcedClaimActionQueue) Claim(context.Context, ActionClaimRequest) (ClaimedAction, error) {
	queue.claimCalls++
	return queue.claimed, nil
}

func (queue *forcedClaimActionQueue) Start(context.Context, executionlease.LeaseIdentity) (executionlease.Execution, error) {
	queue.mutations = append(queue.mutations, "start")
	return executionlease.Execution{}, errors.New("unexpected Start call")
}

func (queue *forcedClaimActionQueue) Reject(context.Context, ActionRejectRequest) (executionlease.Execution, error) {
	queue.mutations = append(queue.mutations, "reject")
	return executionlease.Execution{}, errors.New("unexpected Reject call")
}

func (queue *forcedClaimActionQueue) Nack(context.Context, ActionNackRequest) (executionlease.Execution, error) {
	queue.mutations = append(queue.mutations, "nack")
	return executionlease.Execution{}, errors.New("unexpected Nack call")
}

func (repository *recordingActionQueue) Claim(ctx context.Context, request ActionClaimRequest) (ClaimedAction, error) {
	repository.events.add("lease:claim")
	claimed, err := repository.ActionQueue.Claim(ctx, request)
	if err == nil && repository.actionSource != nil {
		repository.actionSource.update(claimed.Execution, claimed.Envelope)
	}
	return claimed, err
}

func (repository *recordingActionQueue) Start(ctx context.Context, lease executionlease.LeaseIdentity) (executionlease.Execution, error) {
	repository.events.add("lease:start")
	if repository.startErr != nil {
		return executionlease.Execution{}, repository.startErr
	}
	started, err := repository.ActionQueue.Start(ctx, lease)
	if err == nil && repository.actionSource != nil {
		repository.actionSource.updateExecution(started)
	}
	return started, err
}

func (repository *recordingActionQueue) Complete(ctx context.Context, request ActionCompleteRequest) (executionlease.Execution, error) {
	repository.events.add("lease:complete")
	if repository.completeErr != nil {
		return executionlease.Execution{}, repository.completeErr
	}
	return repository.ActionQueue.Complete(ctx, request)
}

func (repository *recordingActionQueue) Finalize(ctx context.Context, lease executionlease.LeaseIdentity) (executionlease.Execution, error) {
	repository.events.add("lease:finalize")
	if repository.finalizeErr != nil {
		return executionlease.Execution{}, repository.finalizeErr
	}
	return repository.ActionQueue.Finalize(ctx, lease)
}

func (repository *recordingActionQueue) Heartbeat(ctx context.Context, request ActionHeartbeatRequest) (ActionHeartbeatResult, error) {
	repository.events.add("lease:heartbeat")
	repository.heartbeatCalls++
	notifySequence := repository.heartbeatSequences != nil
	if notifySequence && repository.heartbeatSequenceGate != nil {
		select {
		case <-repository.heartbeatSequenceGate:
		default:
			notifySequence = false
		}
	}
	if notifySequence {
		select {
		case repository.heartbeatSequences <- request.Sequence:
		default:
		}
	}
	if repository.heartbeatObserved != nil {
		select {
		case repository.heartbeatObserved <- struct{}{}:
		default:
		}
	}
	shouldFail := repository.heartbeatErr != nil &&
		(repository.heartbeatErrAfter == 0 || repository.heartbeatCalls >= repository.heartbeatErrAfter)
	if shouldFail && repository.heartbeatErrGate != nil {
		select {
		case <-repository.heartbeatErrGate:
		default:
			shouldFail = false
		}
	}
	if shouldFail {
		if repository.heartbeatFailed != nil {
			select {
			case repository.heartbeatFailed <- struct{}{}:
			default:
			}
		}
		return ActionHeartbeatResult{}, repository.heartbeatErr
	}
	result, err := repository.ActionQueue.Heartbeat(ctx, request)
	if err == nil && repository.actionSource != nil {
		repository.actionSource.updateExecution(result.Execution)
	}
	return result, err
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

type fakeCredentialBroker struct{ err error }

type serviceActionFenceSource struct {
	mu         sync.Mutex
	execution  executionlease.Execution
	envelope   action.Envelope
	leaseToken string
}

func (source *serviceActionFenceSource) update(execution executionlease.Execution, envelope action.Envelope) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.execution = execution
	source.envelope = cloneEnvelope(envelope)
	source.leaseToken = execution.LeaseToken
}

func (source *serviceActionFenceSource) updateExecution(execution executionlease.Execution) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if execution.ExecutionID == source.execution.ExecutionID {
		leaseToken := source.leaseToken
		source.execution = execution
		source.leaseToken = leaseToken
	}
}

func (source *serviceActionFenceSource) ResolveActionFence(ctx context.Context, fence credential.ActionFence) (credential.ActionMetadata, error) {
	if err := ctx.Err(); err != nil {
		return credential.ActionMetadata{}, err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if !source.matchesFence(fence) {
		return credential.ActionMetadata{}, credential.ErrStaleActionFence
	}
	return source.metadata(), nil
}

func (source *serviceActionFenceSource) InspectAction(ctx context.Context, actionID string) (credential.ActionInspection, error) {
	if err := ctx.Err(); err != nil {
		return credential.ActionInspection{}, err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.execution.ExecutionID != actionID {
		return credential.ActionInspection{}, credential.ErrStaleActionFence
	}
	return credential.ActionInspection{
		Metadata: source.metadata(), LeaseTokenSHA256: credential.SHA256Hex([]byte(source.leaseToken)),
	}, nil
}

func (source *serviceActionFenceSource) WithLockedActionInspection(
	ctx context.Context,
	actionID string,
	operation func(credential.ActionInspection) error,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.execution.ExecutionID != actionID {
		return credential.ErrStaleActionFence
	}
	return operation(credential.ActionInspection{
		Metadata: source.metadata(), LeaseTokenSHA256: credential.SHA256Hex([]byte(source.leaseToken)),
	})
}

func (source *serviceActionFenceSource) matchesFence(fence credential.ActionFence) bool {
	return source.execution.ExecutionID == fence.ActionID && source.execution.RunnerID == fence.RunnerID &&
		source.execution.LeaseEpoch == fence.Epoch && source.leaseToken == fence.Token
}

func (source *serviceActionFenceSource) metadata() credential.ActionMetadata {
	value := source.execution
	return credential.ActionMetadata{
		ActionID: value.ExecutionID, TenantID: value.RunnerTenantID, WorkspaceID: value.RunnerWorkspaceID,
		EnvironmentID: value.RunnerEnvironmentID, TargetKey: value.TargetKey, Production: value.Production,
		RunnerID: value.RunnerID, LeaseEpoch: value.LeaseEpoch, Status: credential.ActionStatus(value.Status),
		LeaseExpiresAt: value.LeaseExpiresAt, AuthorizationExpiresAt: source.envelope.ExpiresAt,
		CancelRequestedAt: value.CancelRequestedAt, RunnerEnabled: true, RunnerPool: string(value.Pool),
		ScopeRevision: value.ScopeRevision, RunnerScopeRevision: value.ScopeRevision, ExactScopeAuthorized: true,
		ActionType: string(source.envelope.ActionType), CredentialTTLSeconds: source.envelope.CredentialScope.TTLSeconds,
		ConnectorID: source.envelope.CredentialScope.ConnectorID,
		Permission:  source.envelope.CredentialScope.Permission,
		Resource:    source.envelope.CredentialScope.Resource,
	}
}

type serviceDurableIssuer struct {
	clock              func() time.Time
	events             *eventLog
	validateCalls      int
	createCalls        int
	inspectCalls       int
	issueCalls         int
	validateErr        error
	createErr          error
	inspectErr         error
	issueErr           error
	issueEntered       chan<- struct{}
	issueRelease       <-chan struct{}
	ignoreCancellation bool
	dynamicTTL         time.Duration
}

func (*serviceDurableIssuer) IssuerID() string       { return "execution-vault-nonprod" }
func (*serviceDurableIssuer) IssuerRevision() string { return "revision-1" }

func (issuer *serviceDurableIssuer) ValidateManager(ctx context.Context) error {
	issuer.validateCalls++
	if issuer.events != nil {
		issuer.events.add("credential:validate-manager")
	}
	if issuer.validateErr != nil {
		return issuer.validateErr
	}
	return ctx.Err()
}

func (issuer *serviceDurableIssuer) CreateChild(
	ctx context.Context,
	request credential.DurableChildCreateRequest,
) (credential.DurableChild, error) {
	issuer.createCalls++
	if issuer.events != nil {
		issuer.events.add("credential:create-child")
	}
	if issuer.createErr != nil {
		return credential.DurableChild{}, issuer.createErr
	}
	token, err := credential.NewSensitiveValue([]byte("execution-child-token"))
	if err != nil {
		return credential.DurableChild{}, err
	}
	accessor, err := credential.NewSensitiveReference([]byte("execution-child-accessor"))
	if err != nil {
		token.Destroy()
		return credential.DurableChild{}, err
	}
	return credential.DurableChild{
		Token: token, Accessor: accessor,
		ExpiresAt: credential.CanonicalCredentialExpiry(request.DatabaseAuthorizedAt.Add(request.TTL)),
	}, ctx.Err()
}

func (issuer *serviceDurableIssuer) InspectChild(
	ctx context.Context,
	_ *credential.SensitiveReference,
	_ credential.DurableChildInspectionRequest,
) error {
	issuer.inspectCalls++
	if issuer.events != nil {
		issuer.events.add("credential:inspect-child")
	}
	if issuer.inspectErr != nil {
		return issuer.inspectErr
	}
	return ctx.Err()
}

func (issuer *serviceDurableIssuer) IssueDynamic(
	ctx context.Context,
	_ credential.SensitiveValue,
	request credential.DurableDynamicIssueRequest,
) (credential.DurableDynamicSecret, error) {
	issuer.issueCalls++
	if issuer.events != nil {
		issuer.events.add("credential:issue-dynamic")
	}
	if issuer.issueEntered != nil {
		select {
		case issuer.issueEntered <- struct{}{}:
		default:
		}
	}
	if issuer.issueRelease != nil {
		if issuer.ignoreCancellation {
			<-issuer.issueRelease
		} else {
			select {
			case <-ctx.Done():
				return credential.DurableDynamicSecret{}, ctx.Err()
			case <-issuer.issueRelease:
			}
		}
	}
	if issuer.issueErr != nil {
		return credential.DurableDynamicSecret{}, issuer.issueErr
	}
	secret, err := credential.NewSensitiveValue([]byte("execution-dynamic-secret"))
	if err != nil {
		return credential.DurableDynamicSecret{}, err
	}
	dynamicTTL := issuer.dynamicTTL
	if dynamicTTL == 0 {
		dynamicTTL = 2 * time.Minute
	}
	expiresAt := credential.CanonicalCredentialExpiry(issuer.clock().Add(dynamicTTL))
	if request.CredentialExpiresAt.Before(expiresAt) {
		expiresAt = request.CredentialExpiresAt
	}
	return credential.DurableDynamicSecret{Secret: secret, ExpiresAt: expiresAt}, nil
}

type serviceDurableCredentialBroker struct {
	broker                  *credential.DurableBroker
	repository              credential.Repository
	events                  *eventLog
	terminalOnRequest       bool
	prepareCalls            int
	issueCalls              int
	recordNoCredentialCalls int
	requestRevocationCalls  int
	requestRevocationErr    error
	preparedRequest         credential.PrepareDurableCredentialRequest
}

func (broker *serviceDurableCredentialBroker) Prepare(
	ctx context.Context,
	request credential.PrepareDurableCredentialRequest,
) (credential.PreparedDurableCredential, error) {
	broker.prepareCalls++
	broker.preparedRequest = request
	if broker.events != nil {
		broker.events.add("credential:prepare")
	}
	return broker.broker.Prepare(ctx, request)
}

func (broker *serviceDurableCredentialBroker) Issue(
	ctx context.Context,
	prepared credential.PreparedDurableCredential,
) (credential.DurableCredential, error) {
	broker.issueCalls++
	if broker.events != nil {
		broker.events.add("credential:issue")
	}
	return broker.broker.Issue(ctx, prepared)
}

func (broker *serviceDurableCredentialBroker) RecordNoCredential(
	ctx context.Context,
	prepared credential.PreparedDurableCredential,
) (credential.Revocation, error) {
	broker.recordNoCredentialCalls++
	if broker.events != nil {
		broker.events.add("credential:no-credential")
	}
	return broker.broker.RecordNoCredential(ctx, prepared)
}

func (broker *serviceDurableCredentialBroker) RequestRevocation(
	ctx context.Context,
	executionCredential credential.DurableCredential,
) (credential.Revocation, error) {
	broker.requestRevocationCalls++
	if broker.events != nil {
		broker.events.add("credential:request-revocation")
	}
	if broker.requestRevocationErr != nil {
		executionCredential.Destroy()
		return credential.Revocation{}, broker.requestRevocationErr
	}
	revocation, err := broker.broker.RequestRevocation(ctx, executionCredential)
	if err != nil || !broker.terminalOnRequest || revocation.Terminal() {
		return revocation, err
	}
	claims, err := broker.repository.ClaimRevocations(ctx, credential.ClaimRevocationsRequest{
		WorkerID: "execution-test-worker", Limit: 1, LeaseDuration: credential.RevocationClaimLease,
	})
	if err != nil {
		return credential.Revocation{}, err
	}
	if len(claims) != 1 || claims[0].Revocation.ID != revocation.ID {
		return credential.Revocation{}, errors.New("unexpected credential revocation claim")
	}
	defer claims[0].Accessor.Destroy()
	return broker.repository.CompleteRevocation(ctx, credential.CompleteRevocationRequest{Fence: claims[0].Fence})
}

func (broker *fakeCredentialBroker) Prepare(context.Context, credential.PrepareDurableCredentialRequest) (credential.PreparedDurableCredential, error) {
	return credential.PreparedDurableCredential{}, broker.err
}

func (broker *fakeCredentialBroker) Issue(context.Context, credential.PreparedDurableCredential) (credential.DurableCredential, error) {
	return credential.DurableCredential{}, broker.err
}

func (broker *fakeCredentialBroker) RecordNoCredential(context.Context, credential.PreparedDurableCredential) (credential.Revocation, error) {
	return credential.Revocation{}, broker.err
}

func (broker *fakeCredentialBroker) RequestRevocation(context.Context, credential.DurableCredential) (credential.Revocation, error) {
	return credential.Revocation{}, broker.err
}

type countingCredentialBroker struct {
	prepareCalls            int
	issueCalls              int
	recordNoCredentialCalls int
	requestRevocationCalls  int
}

func (broker *countingCredentialBroker) Prepare(context.Context, credential.PrepareDurableCredentialRequest) (credential.PreparedDurableCredential, error) {
	broker.prepareCalls++
	return credential.PreparedDurableCredential{}, errors.New("unexpected credential prepare")
}

func (broker *countingCredentialBroker) Issue(context.Context, credential.PreparedDurableCredential) (credential.DurableCredential, error) {
	broker.issueCalls++
	return credential.DurableCredential{}, errors.New("unexpected credential issue")
}

func (broker *countingCredentialBroker) RecordNoCredential(context.Context, credential.PreparedDurableCredential) (credential.Revocation, error) {
	broker.recordNoCredentialCalls++
	return credential.Revocation{}, errors.New("unexpected no-credential transition")
}

func (broker *countingCredentialBroker) RequestRevocation(context.Context, credential.DurableCredential) (credential.Revocation, error) {
	broker.requestRevocationCalls++
	return credential.Revocation{}, errors.New("unexpected credential revocation request")
}

type countingKeyResolver struct{ calls int }

func (resolver *countingKeyResolver) Resolve(context.Context, string) (action.KeyRecord, error) {
	resolver.calls++
	return action.KeyRecord{}, errors.New("unexpected action verification")
}

type fakePreExecutionGate struct {
	decision           policy.Decision
	credentialDecision policy.Decision
	after              func()
	events             *eventLog
}

func (gate *fakePreExecutionGate) EvaluateCredentialIssue(context.Context, action.Envelope) (policy.Decision, error) {
	if gate.events != nil {
		gate.events.add("policy:credential-issue")
	}
	return gate.credentialDecision, nil
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
	result              ExecutorResult
	err                 error
	calls               []string
	events              *eventLog
	capturedCredential  credential.DurableCredential
	credentialCaptured  bool
	release             <-chan struct{}
	waitForCancellation bool
	capturedDeadline    time.Time
	enteredAt           time.Time
	entered             chan<- struct{}
	destroyCredential   bool
	ignoreCancellation  bool
	finished            chan<- struct{}
}

func (executors *recordingExecutors) asDependencies() Executors {
	return Executors{
		KubernetesRolloutRestart: executors,
		KubernetesScale:          executors,
		GitOpsRevert:             executors,
		AWXServiceRestart:        executors,
	}
}

func (executors *recordingExecutors) record(ctx context.Context, name string, executionCredential credential.DurableCredential) (ExecutorResult, error) {
	executors.calls = append(executors.calls, name)
	executors.capturedCredential = executionCredential
	executors.credentialCaptured = true
	executors.enteredAt = time.Now()
	if executors.entered != nil {
		select {
		case executors.entered <- struct{}{}:
		default:
		}
	}
	if executors.destroyCredential {
		executionCredential.Destroy()
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

const asynchronousTestWatchdog = 10 * time.Second

func awaitTestSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	awaitTestValue(t, signal, description)
}

func awaitTestValue[T any](t *testing.T, values <-chan T, description string) T {
	t.Helper()
	timer := time.NewTimer(asynchronousTestWatchdog)
	defer timer.Stop()
	select {
	case value := <-values:
		return value
	case <-timer.C:
		t.Fatalf("timed out after %s waiting for %s", asynchronousTestWatchdog, description)
		var zero T
		return zero
	}
}

func (executors *recordingExecutors) ExecuteRolloutRestart(ctx context.Context, command KubernetesRolloutRestartCommand, executionCredential credential.DurableCredential) (ExecutorResult, error) {
	if command.Target.Name == "" || command.Parameters.Reason == "" {
		return ExecutorResult{}, errors.New("missing typed restart command")
	}
	return executors.record(ctx, "kubernetes-rollout-restart", executionCredential)
}

func (executors *recordingExecutors) ExecuteScale(ctx context.Context, command KubernetesScaleCommand, executionCredential credential.DurableCredential) (ExecutorResult, error) {
	if command.Target.Name == "" || command.Parameters.Replicas < 0 {
		return ExecutorResult{}, errors.New("missing typed scale command")
	}
	return executors.record(ctx, "kubernetes-scale", executionCredential)
}

func (executors *recordingExecutors) ExecuteGitOpsRevert(ctx context.Context, command GitOpsRevertCommand, executionCredential credential.DurableCredential) (ExecutorResult, error) {
	if command.Target.RepositoryID == "" || command.Parameters.RevertCommit == "" {
		return ExecutorResult{}, errors.New("missing typed GitOps command")
	}
	return executors.record(ctx, "gitops-revert", executionCredential)
}

func (executors *recordingExecutors) ExecuteAWXServiceRestart(ctx context.Context, command AWXServiceRestartCommand, executionCredential credential.DurableCredential) (ExecutorResult, error) {
	if command.Target.InventoryID == 0 || command.Parameters.JobTemplateID == 0 {
		return ExecutorResult{}, errors.New("missing typed AWX command")
	}
	return executors.record(ctx, "awx-service-restart", executionCredential)
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

func nonProductionEnvironment(envelope action.Envelope, now time.Time) EnvironmentSnapshot {
	snapshot := validEnvironment(envelope, now)
	snapshot.Production = false
	return snapshot
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
