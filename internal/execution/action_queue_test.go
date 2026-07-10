package execution

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/executionlease"
)

func TestMemoryActionQueueSubmitAndClaimReturnsImmutableActionWithinRunnerScope(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	targetKey, err := deriveTargetKey(envelope)
	if err != nil {
		t.Fatalf("deriveTargetKey() error = %v", err)
	}
	queue := mustMemoryActionQueue(t, func() time.Time { return now })
	_, err = queue.Submit(context.Background(), ActionSubmission{
		Envelope: envelope, PlanHash: envelope.PlanHash, TargetKey: targetKey,
		EnvironmentRevision: "environment-1", Production: true, Pool: executionlease.PoolWrite,
	})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}

	envelope.Target.KubernetesDeployment.Name = "mutated-after-submit"
	envelope.Risk.ReasonCodes[0] = "MUTATED"
	claimed, err := queue.Claim(context.Background(), ActionClaimRequest{
		Scope: RunnerScope{
			RunnerID: "runner-1", Pool: executionlease.PoolWrite,
			AllowedWorkspaceIDs: []string{"workspace-1"}, AllowedEnvironmentIDs: []string{"PROD"},
		},
		LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if claimed.Execution.ExecutionID != "action-restart" || claimed.Execution.Status != executionlease.StatusLeased {
		t.Fatalf("Claim() execution = %#v", claimed.Execution)
	}
	if claimed.PlanHash != claimed.Envelope.PlanHash || claimed.TargetKey != targetKey || claimed.EnvironmentRevision != "environment-1" || !claimed.Production {
		t.Fatalf("Claim() metadata = %#v", claimed)
	}
	if got := claimed.Envelope.Target.KubernetesDeployment.Name; got != "payments-api" {
		t.Fatalf("claimed deployment name = %q, want immutable original", got)
	}
	if got := claimed.Envelope.Risk.ReasonCodes[0]; got != "PRODUCTION_CHANGE" {
		t.Fatalf("claimed risk reason = %q, want immutable original", got)
	}
	idempotent, err := queue.Submit(context.Background(), ActionSubmission{
		Envelope: claimed.Envelope, PlanHash: claimed.PlanHash, TargetKey: claimed.TargetKey,
		EnvironmentRevision: claimed.EnvironmentRevision, Production: claimed.Production, Pool: executionlease.PoolWrite,
	})
	if err != nil {
		t.Fatalf("idempotent Submit() error = %v", err)
	}
	queried, err := queue.Get(context.Background(), claimed.Execution.ExecutionID)
	if err != nil {
		t.Fatalf("Get(active) error = %v", err)
	}
	if idempotent.LeaseToken != "" || queried.LeaseToken != "" {
		t.Fatalf("non-Claim boundary leaked token: Submit=%q Get=%q", idempotent.LeaseToken, queried.LeaseToken)
	}
}

func TestMemoryActionQueueRejectsAnActionIDBoundToADifferentPlan(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	first, _ := signedEnvelope(t, restartEnvelope(now))
	changed := restartEnvelope(now)
	changed.Parameters.KubernetesRolloutRestart.Reason = "different approved plan"
	second, _ := signedEnvelope(t, changed)
	queue := mustMemoryActionQueue(t, func() time.Time { return now })
	targetKey, err := deriveTargetKey(first)
	if err != nil {
		t.Fatalf("deriveTargetKey() error = %v", err)
	}
	request := ActionSubmission{
		Envelope: first, PlanHash: first.PlanHash, TargetKey: targetKey,
		EnvironmentRevision: "environment-1", Production: true, Pool: executionlease.PoolWrite,
	}
	if _, err := queue.Submit(context.Background(), request); err != nil {
		t.Fatalf("first Submit() error = %v", err)
	}
	request.Envelope = second
	request.PlanHash = second.PlanHash
	if _, err := queue.Submit(context.Background(), request); !errors.Is(err, ErrJobConflict) {
		t.Fatalf("second Submit() error = %v, want %v", err, ErrJobConflict)
	}
}

func TestMemoryActionQueueFiltersRunnerScopeBeforeTakingProductionSlot(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	stagingUnsigned := restartEnvelope(now)
	stagingUnsigned.ActionID = "action-staging"
	stagingUnsigned.IdempotencyKey = "idem-action-staging"
	stagingUnsigned.Target.EnvironmentID = "STAGING"
	staging, _ := signedEnvelope(t, stagingUnsigned)
	productionUnsigned := restartEnvelope(now)
	productionUnsigned.ActionID = "action-production"
	productionUnsigned.IdempotencyKey = "idem-action-production"
	production, _ := signedEnvelope(t, productionUnsigned)
	queue := mustMemoryActionQueue(t, func() time.Time { return now })

	for _, envelope := range []action.Envelope{staging, production} {
		targetKey, err := deriveTargetKey(envelope)
		if err != nil {
			t.Fatalf("deriveTargetKey() error = %v", err)
		}
		if _, err := queue.Submit(context.Background(), ActionSubmission{
			Envelope: envelope, PlanHash: envelope.PlanHash, TargetKey: targetKey,
			EnvironmentRevision: "environment-1", Production: true, Pool: executionlease.PoolWrite,
		}); err != nil {
			t.Fatalf("Submit(%s) error = %v", envelope.ActionID, err)
		}
	}

	claimed, err := queue.Claim(context.Background(), ActionClaimRequest{
		Scope: RunnerScope{
			RunnerID: "runner-prod", Pool: executionlease.PoolWrite,
			AllowedWorkspaceIDs: []string{"workspace-1"}, AllowedEnvironmentIDs: []string{"PROD"},
		},
		LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if claimed.Envelope.ActionID != "action-production" {
		t.Fatalf("Claim() action id = %q, want action-production", claimed.Envelope.ActionID)
	}
}

func TestMemoryActionQueuePermanentlyRejectsPoisonedPreStartAction(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return now })
	submitAction(t, queue, envelope, "environment-1", true)
	claimed := claimAction(t, queue, "runner-1", []string{"workspace-1"}, []string{"PROD"})

	rejected, err := queue.Reject(context.Background(), ActionRejectRequest{
		Lease:  claimed.Execution.Fence(),
		Reason: ActionQueueReason{Code: "INVALID_VERIFIED_ACTION", DetailHash: strings.Repeat("a", 64)},
	})
	if err != nil {
		t.Fatalf("Reject() error = %v", err)
	}
	if rejected.Status != executionlease.StatusFailed || len(rejected.ResultHash) != 64 {
		t.Fatalf("Reject() = %#v", rejected)
	}
	if _, err := queue.Claim(context.Background(), ActionClaimRequest{
		Scope: RunnerScope{
			RunnerID: "runner-2", Pool: executionlease.PoolWrite,
			AllowedWorkspaceIDs: []string{"workspace-1"}, AllowedEnvironmentIDs: []string{"PROD"},
		},
		LeaseDuration: time.Minute,
	}); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("poisoned action was redelivered: %v", err)
	}
}

func TestMemoryActionQueueNackUsesFencedBackoffBeforeRedelivery(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return clock })
	submitAction(t, queue, envelope, "environment-1", true)
	first := claimAction(t, queue, "runner-1", []string{"workspace-1"}, []string{"PROD"})

	released, err := queue.Nack(context.Background(), ActionNackRequest{
		Lease:      first.Execution.Fence(),
		Reason:     ActionQueueReason{Code: "CREDENTIAL_TEMPORARILY_UNAVAILABLE", DetailHash: strings.Repeat("b", 64)},
		RetryAfter: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Nack() error = %v", err)
	}
	if released.Status != executionlease.StatusQueued || !released.LeaseExpiresAt.IsZero() || released.LeaseToken != "" {
		t.Fatalf("Nack() = %#v", released)
	}
	claim := ActionClaimRequest{
		Scope: RunnerScope{
			RunnerID: "runner-2", Pool: executionlease.PoolWrite,
			AllowedWorkspaceIDs: []string{"workspace-1"}, AllowedEnvironmentIDs: []string{"PROD"},
		},
		LeaseDuration: time.Minute,
	}
	if _, err := queue.Claim(context.Background(), claim); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("Nack() allowed immediate redelivery: %v", err)
	}
	clock = clock.Add(30 * time.Second)
	second, err := queue.Claim(context.Background(), claim)
	if err != nil {
		t.Fatalf("Claim() after backoff error = %v", err)
	}
	if second.Execution.LeaseEpoch != first.Execution.LeaseEpoch+1 {
		t.Fatalf("second lease epoch = %d, want %d", second.Execution.LeaseEpoch, first.Execution.LeaseEpoch+1)
	}
	if _, err := queue.Start(context.Background(), first.Execution.Fence()); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("old fence Start() error = %v, want stale lease", err)
	}
}

func TestMemoryActionQueueStartHeartbeatAndCompleteRequireCurrentFence(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return clock })
	submitAction(t, queue, envelope, "environment-1", true)
	claimed := claimAction(t, queue, "runner-1", []string{"workspace-1"}, []string{"PROD"})
	fence := claimed.Execution.Fence()
	started, err := queue.Start(context.Background(), fence)
	if err != nil || started.Status != executionlease.StatusRunning {
		t.Fatalf("Start() = %#v, %v", started, err)
	}
	if started.LeaseToken != "" {
		t.Fatalf("Start() leaked lease token %q", started.LeaseToken)
	}

	stale := claimed.Execution.Fence()
	stale.Epoch++
	if _, err := queue.Heartbeat(context.Background(), executionlease.HeartbeatRequest{
		Lease: stale, Extension: time.Minute,
	}); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("stale Heartbeat() error = %v, want stale lease", err)
	}
	clock = clock.Add(10 * time.Second)
	heartbeated, err := queue.Heartbeat(context.Background(), executionlease.HeartbeatRequest{
		Lease: fence, Extension: time.Minute,
	})
	if err != nil || !heartbeated.LeaseExpiresAt.Equal(clock.Add(time.Minute)) {
		t.Fatalf("Heartbeat() = %#v, %v", heartbeated, err)
	}
	if heartbeated.LeaseToken != "" {
		t.Fatalf("Heartbeat() leaked lease token %q", heartbeated.LeaseToken)
	}
	completed, err := queue.Complete(context.Background(), executionlease.CompleteRequest{
		Lease: fence, Status: executionlease.StatusSucceeded, ResultHash: strings.Repeat("c", 64),
	})
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if completed.Status != executionlease.StatusSucceeded || completed.LeaseToken != "" {
		t.Fatalf("Complete() = %#v", completed)
	}
}

func TestMemoryActionQueueClaimSweepsExpiredLeasesAndFencesExpiredRunner(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return clock })
	submitAction(t, queue, envelope, "environment-1", false)
	first := claimAction(t, queue, "runner-old", []string{"workspace-1"}, []string{"PROD"})
	clock = clock.Add(time.Minute)
	second := claimAction(t, queue, "runner-new", []string{"workspace-1"}, []string{"PROD"})
	if second.Execution.LeaseEpoch != first.Execution.LeaseEpoch+1 {
		t.Fatalf("reclaimed epoch = %d, want %d", second.Execution.LeaseEpoch, first.Execution.LeaseEpoch+1)
	}

	secondFence := second.Execution.Fence()
	secondRunning, err := queue.Start(context.Background(), secondFence)
	if err != nil {
		t.Fatalf("Start(second) error = %v", err)
	}
	clock = clock.Add(time.Minute)
	if err := queue.SweepExpired(context.Background()); err != nil {
		t.Fatalf("SweepExpired() error = %v", err)
	}
	uncertain, err := queue.Get(context.Background(), secondRunning.ExecutionID)
	if err != nil {
		t.Fatalf("Get(UNCERTAIN) error = %v", err)
	}
	if uncertain.Status != executionlease.StatusUncertain || uncertain.RunnerID != "runner-new" || uncertain.LeaseToken != "" {
		t.Fatalf("expired RUNNING execution = %#v", uncertain)
	}
	if _, err := queue.Complete(context.Background(), executionlease.CompleteRequest{
		Lease: secondFence, Status: executionlease.StatusSucceeded, ResultHash: strings.Repeat("d", 64),
	}); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("Complete(expired runner) error = %v, want ErrStaleLease", err)
	}
}

func TestMemoryActionQueueReconcileReleasesUncertainProductionSlotAndPreservesBothHashes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	firstEnvelope, _ := signedEnvelope(t, restartEnvelope(now))
	secondUnsigned := restartEnvelope(now)
	secondUnsigned.ActionID = "action-after-reconciliation"
	secondUnsigned.IdempotencyKey = "idem-after-reconciliation"
	secondUnsigned.Target.KubernetesDeployment.Name = "payments-worker"
	secondUnsigned.Target.KubernetesDeployment.UID = "uid-worker"
	secondUnsigned.CredentialScope.Resource = "cluster-a/payments/deployment/payments-worker"
	secondEnvelope, _ := signedEnvelope(t, secondUnsigned)
	queue := mustMemoryActionQueue(t, func() time.Time { return clock })
	submitAction(t, queue, firstEnvelope, "environment-1", true)
	submitAction(t, queue, secondEnvelope, "environment-1", true)
	first := claimAction(t, queue, "runner-old", []string{"workspace-1"}, []string{"PROD"})
	if _, err := queue.Start(context.Background(), first.Execution.Fence()); err != nil {
		t.Fatalf("Start(first) error = %v", err)
	}
	clock = clock.Add(time.Minute)
	if err := queue.SweepExpired(context.Background()); err != nil {
		t.Fatalf("SweepExpired() error = %v", err)
	}
	if _, err := queue.Claim(context.Background(), ActionClaimRequest{
		Scope: RunnerScope{RunnerID: "runner-blocked", Pool: executionlease.PoolWrite,
			AllowedWorkspaceIDs: []string{"workspace-1"}, AllowedEnvironmentIDs: []string{"PROD"}},
		LeaseDuration: time.Minute,
	}); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("UNCERTAIN did not retain production slot: %v", err)
	}
	request := executionlease.ReconcileRequest{
		ExecutionID: first.Execution.ExecutionID, ReconciliationID: "reconcile/action-old",
		ActorID: "operator/alice", Status: executionlease.StatusFailed, ResultHash: strings.Repeat("e", 64),
	}
	resolved, err := queue.Reconcile(context.Background(), request)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if resolved.ResultHash == "" || resolved.ReconciliationResultHash != request.ResultHash || resolved.LeaseToken != "" {
		t.Fatalf("Reconcile() = %#v", resolved)
	}
	claimed := claimAction(t, queue, "runner-new", []string{"workspace-1"}, []string{"PROD"})
	if claimed.Execution.ExecutionID != secondEnvelope.ActionID {
		t.Fatalf("post-reconcile claim = %q, want %q", claimed.Execution.ExecutionID, secondEnvelope.ActionID)
	}
}

func TestMemoryActionQueueCancelIsIdempotentAndFencesActiveRunner(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return now })
	submitAction(t, queue, envelope, "environment-1", true)
	claimed := claimAction(t, queue, "runner-cancelled", []string{"workspace-1"}, []string{"PROD"})
	cancelled, err := queue.Cancel(context.Background(), claimed.Execution.ExecutionID)
	if err != nil || cancelled.Status != executionlease.StatusCancelled || cancelled.LeaseToken != "" {
		t.Fatalf("Cancel(LEASED) = %#v, %v", cancelled, err)
	}
	second, err := queue.Cancel(context.Background(), claimed.Execution.ExecutionID)
	if err != nil || second != cancelled {
		t.Fatalf("Cancel(idempotent) = %#v, %v", second, err)
	}
	if _, err := queue.Start(context.Background(), claimed.Execution.Fence()); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("Start(cancelled fence) error = %v, want ErrStaleLease", err)
	}
}

func TestMemoryActionQueueSubmitAndProductionClaimAreAtomicUnderConcurrency(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	t.Run("same action id cannot split metadata and lease", func(t *testing.T) {
		first, _ := signedEnvelope(t, restartEnvelope(now))
		secondUnsigned := restartEnvelope(now)
		secondUnsigned.Parameters.KubernetesRolloutRestart.Reason = "a different plan"
		second, _ := signedEnvelope(t, secondUnsigned)
		queue := mustMemoryActionQueue(t, func() time.Time { return now })
		targetKey, err := deriveTargetKey(first)
		if err != nil {
			t.Fatalf("deriveTargetKey() error = %v", err)
		}
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, envelope := range []action.Envelope{first, second} {
			envelope := envelope
			go func() {
				<-start
				_, err := queue.Submit(context.Background(), ActionSubmission{
					Envelope: envelope, PlanHash: envelope.PlanHash, TargetKey: targetKey,
					EnvironmentRevision: "environment-1", Production: true, Pool: executionlease.PoolWrite,
				})
				results <- err
			}()
		}
		close(start)
		var succeeded, conflicted int
		for range 2 {
			err := <-results
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrJobConflict):
				conflicted++
			default:
				t.Fatalf("concurrent Submit() error = %v", err)
			}
		}
		if succeeded != 1 || conflicted != 1 {
			t.Fatalf("concurrent Submit() succeeded=%d conflicted=%d", succeeded, conflicted)
		}
	})

	t.Run("global production write slot has one winner", func(t *testing.T) {
		first, _ := signedEnvelope(t, restartEnvelope(now))
		secondUnsigned := restartEnvelope(now)
		secondUnsigned.ActionID = "action-worker-restart"
		secondUnsigned.IdempotencyKey = "idem-action-worker-restart"
		secondUnsigned.Target.KubernetesDeployment.Name = "payments-worker"
		secondUnsigned.Target.KubernetesDeployment.UID = "uid-2"
		secondUnsigned.CredentialScope.Resource = "cluster-a/payments/deployment/payments-worker"
		second, _ := signedEnvelope(t, secondUnsigned)
		queue := mustMemoryActionQueue(t, func() time.Time { return now })
		submitAction(t, queue, first, "environment-1", true)
		submitAction(t, queue, second, "environment-1", true)

		start := make(chan struct{})
		results := make(chan error, 2)
		for _, runnerID := range []string{"runner-1", "runner-2"} {
			runnerID := runnerID
			go func() {
				<-start
				_, err := queue.Claim(context.Background(), ActionClaimRequest{
					Scope: RunnerScope{
						RunnerID: runnerID, Pool: executionlease.PoolWrite,
						AllowedWorkspaceIDs: []string{"workspace-1"}, AllowedEnvironmentIDs: []string{"PROD"},
					},
					LeaseDuration: time.Minute,
				})
				results <- err
			}()
		}
		close(start)
		var succeeded, blocked int
		for range 2 {
			err := <-results
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, executionlease.ErrNoLeaseAvailable):
				blocked++
			default:
				t.Fatalf("concurrent Claim() error = %v", err)
			}
		}
		if succeeded != 1 || blocked != 1 {
			t.Fatalf("concurrent Claim() succeeded=%d blocked=%d", succeeded, blocked)
		}
	})
}

func submitAction(t *testing.T, queue *MemoryActionQueue, envelope action.Envelope, environmentRevision string, production bool) executionlease.Execution {
	t.Helper()
	targetKey, err := deriveTargetKey(envelope)
	if err != nil {
		t.Fatalf("deriveTargetKey() error = %v", err)
	}
	execution, err := queue.Submit(context.Background(), ActionSubmission{
		Envelope: envelope, PlanHash: envelope.PlanHash, TargetKey: targetKey,
		EnvironmentRevision: environmentRevision, Production: production, Pool: executionlease.PoolWrite,
	})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	return execution
}

func claimAction(t *testing.T, queue *MemoryActionQueue, runnerID string, workspaces, environments []string) ClaimedAction {
	t.Helper()
	claimed, err := queue.Claim(context.Background(), ActionClaimRequest{
		Scope: RunnerScope{
			RunnerID: runnerID, Pool: executionlease.PoolWrite,
			AllowedWorkspaceIDs: workspaces, AllowedEnvironmentIDs: environments,
		},
		LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	return claimed
}

func mustMemoryActionQueue(t *testing.T, clock func() time.Time) *MemoryActionQueue {
	t.Helper()
	queue, err := NewMemoryActionQueue(MemoryActionQueueOptions{
		Clock: clock,
		TokenSource: func() (string, error) {
			return "queue-lease-token", nil
		},
	})
	if err != nil {
		t.Fatalf("NewMemoryActionQueue() error = %v", err)
	}
	return queue
}
