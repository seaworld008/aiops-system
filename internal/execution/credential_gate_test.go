package execution

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/executionlease"
)

type testCredentialFinalizationGate struct {
	present  bool
	terminal bool
	err      error
	calls    []credentialFinalizationRequest
}

type credentialFinalizationRequest struct {
	actionID string
	epoch    int64
}

func (gate *testCredentialFinalizationGate) InspectCleanup(_ context.Context, actionID string, epoch int64) (bool, bool, error) {
	gate.calls = append(gate.calls, credentialFinalizationRequest{actionID: actionID, epoch: epoch})
	return gate.present, gate.terminal, gate.err
}

func TestMemoryActionQueueWriteFinalizeRequiresExactCredentialTerminalGate(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		gate CredentialFinalizationGate
	}{
		{name: "missing gate"},
		{name: "pending credential", gate: &testCredentialFinalizationGate{present: true}},
		{name: "gate unavailable", gate: &testCredentialFinalizationGate{err: errors.New("credential-store-canary")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			now := time.Date(2026, 7, 11, 17, 0, 0, 0, time.UTC)
			queue, fence := finalizingMemoryWrite(t, now, test.gate, ExecutorSucceeded)

			finalized, err := queue.Finalize(context.Background(), fence)
			if !errors.Is(err, ErrCredentialCleanupPending) || finalized != (executionlease.Execution{}) {
				t.Fatalf("Finalize(nonterminal credential) = %#v, %v", finalized, err)
			}
			persisted, getErr := queue.Get(context.Background(), fence.ExecutionID)
			if getErr != nil || persisted.Status != executionlease.StatusFinalizing {
				t.Fatalf("Get(after blocked Finalize) = %#v, %v", persisted, getErr)
			}
		})
	}
}

func TestMemoryActionQueueCredentialGateAllowsTerminalAndDoesNotBlockUncertain(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 17, 30, 0, 0, time.UTC)
	gate := &testCredentialFinalizationGate{present: true, terminal: true}
	queue, fence := finalizingMemoryWrite(t, now, gate, ExecutorSucceeded)
	finalized, err := queue.Finalize(context.Background(), fence)
	if err != nil || finalized.Status != executionlease.StatusSucceeded || len(gate.calls) != 1 ||
		gate.calls[0] != (credentialFinalizationRequest{actionID: fence.ExecutionID, epoch: fence.Epoch}) {
		t.Fatalf("Finalize(terminal credential) = %#v, %v; calls=%#v", finalized, err, gate.calls)
	}

	uncertainQueue, uncertainFence := finalizingMemoryWrite(t, now, nil, ExecutorUncertain)
	uncertain, err := uncertainQueue.Finalize(context.Background(), uncertainFence)
	if err != nil || uncertain.Status != executionlease.StatusUncertain {
		t.Fatalf("Finalize(UNCERTAIN retains lock) = %#v, %v", uncertain, err)
	}
}

func TestMemoryActionQueueReconcileAndSweepKeepWriteLockUntilCredentialTerminal(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 18, 0, 0, 0, time.UTC)
	clock := now
	gate := &testCredentialFinalizationGate{}
	queue, fence := finalizingMemoryWriteWithClock(t, &clock, gate, ExecutorSucceeded)
	clock = now.Add(24 * time.Hour)
	if err := queue.SweepExpired(context.Background()); err != nil {
		t.Fatalf("SweepExpired() error = %v", err)
	}
	blocked, err := queue.Get(context.Background(), fence.ExecutionID)
	if err != nil || blocked.Status != executionlease.StatusFinalizing {
		t.Fatalf("Get(after blocked sweep) = %#v, %v", blocked, err)
	}

	uncertainQueue, uncertainFence := finalizingMemoryWrite(t, now, nil, ExecutorUncertain)
	if _, err := uncertainQueue.Finalize(context.Background(), uncertainFence); err != nil {
		t.Fatal(err)
	}
	resolved, err := uncertainQueue.Reconcile(context.Background(), executionlease.ReconcileRequest{
		ExecutionID: uncertainFence.ExecutionID, ReconciliationID: "reconcile-credential-pending",
		ActorID: "oidc:operator", Status: executionlease.StatusSucceeded,
		ResultHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if !errors.Is(err, ErrCredentialCleanupPending) || resolved != (executionlease.Execution{}) {
		t.Fatalf("Reconcile(nonterminal credential) = %#v, %v", resolved, err)
	}
}

func TestMemoryActionQueueClaimHonorsPoolAndProductionBoundary(t *testing.T) {
	t.Parallel()
	// Exercise a real submission and a registration for the same trusted pool;
	// no fabricated ClaimedAction can hide a submission/runner pool mismatch.
	for _, test := range []struct {
		name       string
		pool       executionlease.Pool
		production bool
		wantErr    error
	}{
		{name: "READ production remains claimable", pool: executionlease.PoolRead, production: true},
		{name: "WRITE non-production remains claimable", pool: executionlease.PoolWrite},
		{name: "WRITE production is hard disabled", pool: executionlease.PoolWrite, production: true, wantErr: executionlease.ErrNoLeaseAvailable},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			now := time.Date(2026, 7, 11, 18, 30, 0, 0, time.UTC)
			unsigned := restartEnvelope(now)
			unsigned.ActionID = "claim-matrix-" + string(test.pool)
			unsigned.IdempotencyKey = "idem-claim-matrix-" + string(test.pool)
			if test.production {
				unsigned.ActionID += "-production"
				unsigned.IdempotencyKey += "-production"
			}
			envelope, _ := signedEnvelope(t, unsigned)
			targetKey, err := deriveTargetKey(envelope)
			if err != nil {
				t.Fatalf("deriveTargetKey() error = %v", err)
			}
			tokenCalls := 0
			queue, err := NewMemoryActionQueue(MemoryActionQueueOptions{
				Clock: func() time.Time { return now },
				TokenSource: func() (string, error) {
					tokenCalls++
					return "claim-matrix-lease-token", nil
				},
				CredentialFinalizationGate: &testCredentialFinalizationGate{present: true, terminal: true},
			})
			if err != nil {
				t.Fatalf("NewMemoryActionQueue() error = %v", err)
			}
			if _, err := queue.Submit(context.Background(), ActionSubmission{
				Envelope: envelope, PlanHash: envelope.PlanHash, TargetKey: targetKey,
				EnvironmentRevision: "environment-1", Production: test.production, Pool: test.pool,
			}); err != nil {
				t.Fatalf("Submit(%s production=%v) error = %v", test.pool, test.production, err)
			}
			scope, err := (RunnerRegistration{
				RunnerID: "runner-" + string(test.pool), TenantID: "tenant-test", Pool: test.pool,
				Enabled: true, ScopeRevision: 1, MaxConcurrency: 1,
				ScopeBindings: []RunnerScopeBinding{{WorkspaceID: envelope.WorkspaceID, EnvironmentID: envelope.Target.EnvironmentID}},
			}).Scope()
			if err != nil {
				t.Fatalf("RunnerRegistration.Scope(%s) error = %v", test.pool, err)
			}
			claimed, err := queue.Claim(context.Background(), ActionClaimRequest{Scope: scope, LeaseDuration: time.Minute})
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) || claimed.Execution != (executionlease.Execution{}) ||
					claimed.Envelope.ActionID != "" || claimed.PlanHash != "" || claimed.TargetKey != "" {
					t.Fatalf("Claim(%s production=%v) = %#v, %v; want %v", test.pool, test.production, claimed, err, test.wantErr)
				}
				if tokenCalls != 0 {
					t.Fatalf("Claim(%s production=%v) generated %d lease tokens before denial", test.pool, test.production, tokenCalls)
				}
				return
			}
			if err != nil || claimed.Execution.ExecutionID != envelope.ActionID || claimed.Envelope.ActionID != envelope.ActionID ||
				claimed.Execution.Pool != test.pool || claimed.Execution.Production != test.production || claimed.Execution.Status != executionlease.StatusLeased {
				t.Fatalf("Claim(%s production=%v) = %#v, %v", test.pool, test.production, claimed, err)
			}
			if tokenCalls != 1 {
				t.Fatalf("Claim(%s production=%v) token calls = %d, want 1", test.pool, test.production, tokenCalls)
			}
		})
	}
}

func TestMemoryActionQueueRunningCancelAndTerminateHeartbeatBypassCredentialTerminalGate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 18, 45, 0, 0, time.UTC)
	clock := now
	gate := &testCredentialFinalizationGate{present: true}
	queue, fence := runningMemoryWrite(t, gate, &clock)

	cancelled, err := queue.Cancel(context.Background(), fence.ExecutionID)
	if err != nil || cancelled.Status != executionlease.StatusRunning || cancelled.CancelRequestedAt.IsZero() {
		t.Fatalf("Cancel(RUNNING with pending credential) = %#v, %v", cancelled, err)
	}
	clock = clock.Add(10 * time.Second)
	heartbeat, err := queue.Heartbeat(context.Background(), ActionHeartbeatRequest{
		Lease: fence, Sequence: 1, Extension: time.Minute,
	})
	if err != nil || heartbeat.Directive != HeartbeatTerminate || heartbeat.Execution.Status != executionlease.StatusRunning {
		t.Fatalf("Heartbeat(cancel intent with pending credential) = %#v, %v", heartbeat, err)
	}
	if len(gate.calls) != 0 {
		t.Fatalf("RUNNING cancel/terminate inspected credential cleanup: %#v", gate.calls)
	}
	assertSameTargetLocked(t, queue, now, "runner-after-cancel-intent")
	if len(gate.calls) != 0 {
		t.Fatalf("RUNNING target-lock check inspected credential cleanup: %#v", gate.calls)
	}
}

func TestMemoryActionQueueRunningExpiryBecomesUncertainWithoutCredentialTerminalGate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 18, 50, 0, 0, time.UTC)
	clock := now
	gate := &testCredentialFinalizationGate{present: true}
	queue, fence := runningMemoryWrite(t, gate, &clock)
	clock = clock.Add(2 * time.Minute)

	if err := queue.SweepExpired(context.Background()); err != nil {
		t.Fatalf("SweepExpired(RUNNING with pending credential) error = %v", err)
	}
	persisted, err := queue.Get(context.Background(), fence.ExecutionID)
	if err != nil || persisted.Status != executionlease.StatusUncertain || persisted.CompletionStatus != executionlease.StatusUncertain ||
		len(persisted.ResultHash) != 64 {
		t.Fatalf("Get(expired RUNNING with pending credential) = %#v, %v", persisted, err)
	}
	if len(gate.calls) != 0 {
		t.Fatalf("RUNNING expiry inspected credential cleanup: %#v", gate.calls)
	}
	assertSameTargetLocked(t, queue, now, "runner-after-running-expiry")
	if len(gate.calls) != 0 {
		t.Fatalf("UNCERTAIN target-lock check inspected credential cleanup: %#v", gate.calls)
	}
}

func TestMemoryActionQueuePreStartReleaseRequiresAbsentOrTerminalCredential(t *testing.T) {
	t.Parallel()
	operations := []struct {
		name string
		run  func(*MemoryActionQueue, executionlease.LeaseIdentity) error
	}{
		{name: "reject", run: func(queue *MemoryActionQueue, fence executionlease.LeaseIdentity) error {
			_, err := queue.Reject(context.Background(), ActionRejectRequest{
				Lease: fence, Reason: ActionQueueReason{Code: "PRESTART_REJECT", DetailHash: zeroSHA256()},
			})
			return err
		}},
		{name: "nack", run: func(queue *MemoryActionQueue, fence executionlease.LeaseIdentity) error {
			_, err := queue.Nack(context.Background(), ActionNackRequest{
				Lease: fence, Reason: ActionQueueReason{Code: "PRESTART_NACK", DetailHash: zeroSHA256()}, RetryAfter: time.Second,
			})
			return err
		}},
		{name: "cancel", run: func(queue *MemoryActionQueue, fence executionlease.LeaseIdentity) error {
			_, err := queue.Cancel(context.Background(), fence.ExecutionID)
			return err
		}},
	}
	for _, operation := range operations {
		operation := operation
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()
			gate := &testCredentialFinalizationGate{present: true}
			queue, fence := leasedMemoryWrite(t, gate, nil)
			if err := operation.run(queue, fence); !errors.Is(err, ErrCredentialCleanupPending) {
				t.Fatalf("%s(nonterminal credential) error = %v", operation.name, err)
			}
			persisted, err := queue.Get(context.Background(), fence.ExecutionID)
			if err != nil || persisted.Status != executionlease.StatusLeased {
				t.Fatalf("Get(after blocked %s) = %#v, %v", operation.name, persisted, err)
			}

			gate.present = false
			if err := operation.run(queue, fence); err != nil {
				t.Fatalf("%s(no credential) error = %v", operation.name, err)
			}
		})
	}
}

func TestMemoryActionQueueExpiredLeaseDoesNotReleasePendingCredential(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 19, 0, 0, 0, time.UTC)
	clock := now
	gate := &testCredentialFinalizationGate{present: true}
	queue, fence := leasedMemoryWrite(t, gate, &clock)
	clock = now.Add(2 * time.Minute)
	if err := queue.SweepExpired(context.Background()); err != nil {
		t.Fatal(err)
	}
	blocked, err := queue.Get(context.Background(), fence.ExecutionID)
	if err != nil || blocked.Status != executionlease.StatusLeased {
		t.Fatalf("Get(pending credential after expiry) = %#v, %v", blocked, err)
	}
	gate.present = false
	if err := queue.SweepExpired(context.Background()); err != nil {
		t.Fatal(err)
	}
	released, err := queue.Get(context.Background(), fence.ExecutionID)
	if err != nil || released.Status != executionlease.StatusQueued {
		t.Fatalf("Get(absent credential after expiry) = %#v, %v", released, err)
	}
}

func TestMemoryActionQueueExpiredLeaseInspectorErrorFailsClosed(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 19, 15, 0, 0, time.UTC)
	clock := now
	gate := &testCredentialFinalizationGate{err: errors.New("credential-store-unavailable")}
	queue, fence := leasedMemoryWrite(t, gate, &clock)
	clock = clock.Add(2 * time.Minute)

	if err := queue.SweepExpired(context.Background()); err != nil {
		t.Fatalf("SweepExpired(inspector error) error = %v", err)
	}
	persisted, err := queue.Get(context.Background(), fence.ExecutionID)
	if err != nil || persisted.Status != executionlease.StatusLeased || persisted.RunnerID != fence.RunnerID || persisted.LeaseEpoch != fence.Epoch {
		t.Fatalf("Get(after inspector error) = %#v, %v; want original LEASED fence retained", persisted, err)
	}
	if len(gate.calls) == 0 {
		t.Fatal("expired LEASED action never inspected credential cleanup")
	}
}

func finalizingMemoryWrite(
	t *testing.T,
	now time.Time,
	gate CredentialFinalizationGate,
	outcome ExecutorOutcome,
) (*MemoryActionQueue, executionlease.LeaseIdentity) {
	t.Helper()
	clock := now
	return finalizingMemoryWriteWithClock(t, &clock, gate, outcome)
}

func leasedMemoryWrite(
	t *testing.T,
	gate CredentialFinalizationGate,
	clockOverride *time.Time,
) (*MemoryActionQueue, executionlease.LeaseIdentity) {
	t.Helper()
	now := time.Date(2026, 7, 11, 19, 0, 0, 0, time.UTC)
	clock := &now
	if clockOverride != nil {
		clock = clockOverride
	}
	queue, err := NewMemoryActionQueue(MemoryActionQueueOptions{
		Clock: func() time.Time { return *clock }, CredentialFinalizationGate: gate,
		TokenSource: func() (string, error) { return "prestart-credential-gate-token", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := signedEnvelope(t, restartEnvelope(*clock))
	submitAction(t, queue, envelope, "environment-1", false)
	claimed := claimAction(t, queue, "runner-prestart-gate", []string{envelope.WorkspaceID}, []string{envelope.Target.EnvironmentID})
	return queue, claimed.Execution.Fence()
}

func runningMemoryWrite(
	t *testing.T,
	gate CredentialFinalizationGate,
	clock *time.Time,
) (*MemoryActionQueue, executionlease.LeaseIdentity) {
	t.Helper()
	queue, fence := leasedMemoryWrite(t, gate, clock)
	if _, err := queue.Start(context.Background(), fence); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	return queue, fence
}

func assertSameTargetLocked(t *testing.T, queue *MemoryActionQueue, now time.Time, runnerID string) {
	t.Helper()
	unsigned := restartEnvelope(now)
	unsigned.ActionID = "blocked-" + runnerID
	unsigned.IdempotencyKey = "idem-blocked-" + runnerID
	envelope, _ := signedEnvelope(t, unsigned)
	submitAction(t, queue, envelope, "environment-1", false)
	_, err := queue.Claim(context.Background(), ActionClaimRequest{
		Scope: testRunnerScope(t, runnerID, RunnerScopeBinding{
			WorkspaceID: envelope.WorkspaceID, EnvironmentID: envelope.Target.EnvironmentID,
		}),
		LeaseDuration: time.Minute,
	})
	if !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("Claim(same target while lock retained) error = %v, want %v", err, executionlease.ErrNoLeaseAvailable)
	}
}

func zeroSHA256() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"
}

func finalizingMemoryWriteWithClock(
	t *testing.T,
	clock *time.Time,
	gate CredentialFinalizationGate,
	outcome ExecutorOutcome,
) (*MemoryActionQueue, executionlease.LeaseIdentity) {
	t.Helper()
	queue, err := NewMemoryActionQueue(MemoryActionQueueOptions{
		Clock: func() time.Time { return *clock }, CredentialFinalizationGate: gate,
		TokenSource: func() (string, error) { return "credential-gate-lease-token", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := signedEnvelope(t, restartEnvelope(*clock))
	submitAction(t, queue, envelope, "environment-1", false)
	claimed := claimAction(t, queue, "runner-credential-gate", []string{envelope.WorkspaceID}, []string{envelope.Target.EnvironmentID})
	fence := claimed.Execution.Fence()
	if _, err := queue.Start(context.Background(), fence); err != nil {
		t.Fatal(err)
	}
	verification := VerificationPassed
	if outcome == ExecutorUncertain {
		verification = VerificationUnknown
	}
	if _, err := queue.Complete(context.Background(), ActionCompleteRequest{
		Lease: fence, Summary: ExecutorResult{Outcome: outcome, Code: "CREDENTIAL_GATE_RESULT", Verification: verification},
	}); err != nil {
		t.Fatal(err)
	}
	return queue, fence
}
