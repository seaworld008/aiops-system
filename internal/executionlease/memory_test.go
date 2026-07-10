package executionlease_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/executionlease"
)

func TestMemoryProductionWriteGlobalConcurrencyAndPoolIsolation(t *testing.T) {
	repository, _ := newMemoryRepository(t)
	ctx := context.Background()
	for index := 0; index < 32; index++ {
		enqueue(t, repository, executionlease.EnqueueRequest{
			ExecutionID: fmt.Sprintf("write-%02d", index), TargetKey: fmt.Sprintf("prod/target-%02d", index),
			Pool: executionlease.PoolWrite, Production: true,
		})
	}
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "read-01", TargetKey: "prod/read-target", Pool: executionlease.PoolRead, Production: true,
	})

	start := make(chan struct{})
	var successes atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			_, err := repository.Claim(ctx, executionlease.ClaimRequest{
				Pool: executionlease.PoolWrite, RunnerID: fmt.Sprintf("writer-%02d", index),
				LeaseDuration: time.Minute, ClaimsEnabled: true,
			})
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, executionlease.ErrNoLeaseAvailable):
			default:
				t.Errorf("Claim(WRITE) error = %v", err)
			}
		}(index)
	}
	close(start)
	wait.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful production WRITE claims = %d, want 1", got)
	}

	readLease, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolRead, RunnerID: "reader-01", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Claim(READ) while WRITE active: %v", err)
	}
	if readLease.Pool != executionlease.PoolRead || readLease.ExecutionID != "read-01" {
		t.Fatalf("READ lease = %+v", readLease)
	}
}

func TestMemoryAllowsOnlyOneActiveLeasePerTargetAcrossPools(t *testing.T) {
	repository, _ := newMemoryRepository(t)
	ctx := context.Background()
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "read-same", TargetKey: "cluster/ns/deployment/api", Pool: executionlease.PoolRead,
	})
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "write-same", TargetKey: "cluster/ns/deployment/api", Pool: executionlease.PoolWrite,
	})
	if _, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolRead, RunnerID: "reader", LeaseDuration: time.Minute, ClaimsEnabled: true,
	}); err != nil {
		t.Fatalf("first target claim: %v", err)
	}
	if _, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "writer", LeaseDuration: time.Minute, ClaimsEnabled: true,
	}); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("second same-target claim error = %v, want ErrNoLeaseAvailable", err)
	}
}

func TestMemoryLifecycleHeartbeatAndCompletionIdempotency(t *testing.T) {
	repository, clock := newMemoryRepository(t)
	ctx := context.Background()
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "execution-01", TargetKey: "cluster/ns/deployment/api", Pool: executionlease.PoolWrite,
	})
	lease, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-01", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if lease.Status != executionlease.StatusLeased || lease.LeaseEpoch != 1 || lease.LeaseToken == "" {
		t.Fatalf("lease = %+v", lease)
	}
	fence := lease.Fence()

	clock.Advance(20 * time.Second)
	heartbeat, err := repository.Heartbeat(ctx, executionlease.HeartbeatRequest{Lease: fence, Extension: 2 * time.Minute})
	if err != nil {
		t.Fatalf("Heartbeat() error = %v", err)
	}
	if want := clock.Now().Add(2 * time.Minute); !heartbeat.LeaseExpiresAt.Equal(want) {
		t.Fatalf("lease expiry = %s, want %s", heartbeat.LeaseExpiresAt, want)
	}
	if _, err := repository.Heartbeat(ctx, executionlease.HeartbeatRequest{
		Lease: executionlease.LeaseIdentity{
			ExecutionID: fence.ExecutionID, RunnerID: fence.RunnerID, Token: "stale-token", Epoch: fence.Epoch,
		},
		Extension: time.Minute,
	}); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("stale Heartbeat() error = %v", err)
	}

	running, err := repository.Start(ctx, fence)
	if err != nil || running.Status != executionlease.StatusRunning {
		t.Fatalf("Start() = %+v, %v", running, err)
	}
	resultHash := strings.Repeat("a", 64)
	completed, err := repository.Complete(ctx, executionlease.CompleteRequest{
		Lease: fence, Status: executionlease.StatusSucceeded, ResultHash: resultHash,
	})
	if err != nil || completed.Status != executionlease.StatusSucceeded || completed.ResultHash != resultHash {
		t.Fatalf("Complete() = %+v, %v", completed, err)
	}
	if completed.LeaseToken != "" {
		t.Fatalf("Complete() leaked terminal lease token %q", completed.LeaseToken)
	}
	idempotent, err := repository.Complete(ctx, executionlease.CompleteRequest{
		Lease: fence, Status: executionlease.StatusSucceeded, ResultHash: resultHash,
	})
	if err != nil || idempotent != completed {
		t.Fatalf("idempotent Complete() = %+v, %v; first = %+v", idempotent, err, completed)
	}
	if _, err := repository.Complete(ctx, executionlease.CompleteRequest{
		Lease: fence, Status: executionlease.StatusSucceeded, ResultHash: strings.Repeat("b", 64),
	}); !errors.Is(err, executionlease.ErrCompletionConflict) {
		t.Fatalf("conflicting Complete() error = %v", err)
	}
	if _, err := repository.Heartbeat(ctx, executionlease.HeartbeatRequest{Lease: fence, Extension: time.Minute}); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("post-completion Heartbeat() error = %v", err)
	}
}

func TestMemoryExpiredLeaseReclaimsWithHigherEpochAndFencesOldRunner(t *testing.T) {
	repository, clock := newMemoryRepository(t)
	ctx := context.Background()
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "execution-01", TargetKey: "cluster/ns/deployment/api", Pool: executionlease.PoolWrite,
	})
	first, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-old", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("first Claim(): %v", err)
	}
	clock.Advance(time.Minute)
	second, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-new", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("reclaim expired lease: %v", err)
	}
	if second.ExecutionID != first.ExecutionID || second.LeaseEpoch != first.LeaseEpoch+1 || second.LeaseToken == first.LeaseToken {
		t.Fatalf("reclaimed lease = %+v, first = %+v", second, first)
	}
	if _, err := repository.Heartbeat(ctx, executionlease.HeartbeatRequest{Lease: first.Fence(), Extension: time.Minute}); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("old heartbeat error = %v", err)
	}
	if _, err := repository.Complete(ctx, executionlease.CompleteRequest{
		Lease: first.Fence(), Status: executionlease.StatusFailed, ResultHash: strings.Repeat("c", 64),
	}); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("old complete error = %v", err)
	}
}

func TestMemoryExpiredRunningLeaseBecomesUncertainAndIsNotBlindlyRetried(t *testing.T) {
	repository, clock := newMemoryRepository(t)
	ctx := context.Background()
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "execution-running", TargetKey: "cluster/ns/deployment/api", Pool: executionlease.PoolWrite,
	})
	lease, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-old", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Claim(): %v", err)
	}
	if _, err := repository.Start(ctx, lease.Fence()); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	clock.Advance(time.Minute)
	if _, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-new", LeaseDuration: time.Minute, ClaimsEnabled: true,
	}); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("claim after running expiry error = %v", err)
	}
	uncertain, err := repository.Get(ctx, lease.ExecutionID)
	if err != nil || uncertain.Status != executionlease.StatusUncertain || uncertain.RunnerID != lease.RunnerID {
		t.Fatalf("expired running execution = %+v, %v", uncertain, err)
	}

	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "same-target-retry", TargetKey: lease.TargetKey, Pool: executionlease.PoolWrite,
	})
	if _, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-new", LeaseDuration: time.Minute, ClaimsEnabled: true,
	}); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("same-target blind retry error = %v", err)
	}
	if _, err := repository.Complete(ctx, executionlease.CompleteRequest{
		Lease: lease.Fence(), Status: executionlease.StatusSucceeded, ResultHash: strings.Repeat("d", 64),
	}); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("expired runner complete error = %v", err)
	}
}

func TestMemoryCancelAndKillSwitchPreventClaim(t *testing.T) {
	repository, _ := newMemoryRepository(t)
	ctx := context.Background()
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "execution-cancelled", TargetKey: "cluster/ns/deployment/cancelled", Pool: executionlease.PoolWrite,
	})
	if _, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner", LeaseDuration: time.Minute, ClaimsEnabled: false,
	}); !errors.Is(err, executionlease.ErrClaimBlocked) {
		t.Fatalf("disabled kill switch Claim() error = %v", err)
	}
	cancelled, err := repository.Cancel(ctx, "execution-cancelled")
	if err != nil || cancelled.Status != executionlease.StatusCancelled {
		t.Fatalf("Cancel() = %+v, %v", cancelled, err)
	}
	if _, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner", LeaseDuration: time.Minute, ClaimsEnabled: true,
	}); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("claim cancelled execution error = %v", err)
	}
}

func TestMemoryCancelFencesLeasedAndRunningExecutions(t *testing.T) {
	repository, _ := newMemoryRepository(t)
	ctx := context.Background()
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "leased-cancel", TargetKey: "cluster/ns/deployment/leased", Pool: executionlease.PoolWrite,
	})
	leased, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-leased", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Claim(leased-cancel): %v", err)
	}
	cancelled, err := repository.Cancel(ctx, leased.ExecutionID)
	if err != nil || cancelled.Status != executionlease.StatusCancelled {
		t.Fatalf("Cancel(LEASED) = %+v, %v", cancelled, err)
	}
	if _, err := repository.Start(ctx, leased.Fence()); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("Start() with cancelled lease error = %v", err)
	}

	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "running-cancel", TargetKey: "cluster/ns/deployment/running", Pool: executionlease.PoolWrite,
	})
	runningLease, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-running", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Claim(running-cancel): %v", err)
	}
	if _, err := repository.Start(ctx, runningLease.Fence()); err != nil {
		t.Fatalf("Start(running-cancel): %v", err)
	}
	uncertain, err := repository.Cancel(ctx, runningLease.ExecutionID)
	if err != nil || uncertain.Status != executionlease.StatusUncertain || uncertain.RunnerID != runningLease.RunnerID {
		t.Fatalf("Cancel(RUNNING) = %+v, %v", uncertain, err)
	}
	if _, err := repository.Heartbeat(ctx, executionlease.HeartbeatRequest{
		Lease: runningLease.Fence(), Extension: time.Minute,
	}); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("Heartbeat() after running cancellation error = %v", err)
	}
	if _, err := repository.Complete(ctx, executionlease.CompleteRequest{
		Lease: runningLease.Fence(), Status: executionlease.StatusSucceeded, ResultHash: strings.Repeat("e", 64),
	}); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("Complete() after running cancellation error = %v", err)
	}
}

func TestMemoryUncertainProductionWriteKeepsGlobalWriteSlot(t *testing.T) {
	repository, clock := newMemoryRepository(t)
	ctx := context.Background()
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "production-write-old", TargetKey: "prod/cluster-a/deployment/api",
		Pool: executionlease.PoolWrite, Production: true,
	})
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "production-write-next", TargetKey: "prod/cluster-b/deployment/worker",
		Pool: executionlease.PoolWrite, Production: true,
	})
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "read-after-uncertain", TargetKey: "prod/cluster-c/deployment/observer",
		Pool: executionlease.PoolRead, Production: true,
	})

	lease, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-old", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Claim(production WRITE): %v", err)
	}
	if _, err := repository.Start(ctx, lease.Fence()); err != nil {
		t.Fatalf("Start(production WRITE): %v", err)
	}
	clock.Advance(time.Minute)

	if _, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-next", LeaseDuration: time.Minute, ClaimsEnabled: true,
	}); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("Claim(WRITE) behind UNCERTAIN production write error = %v", err)
	}
	if _, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolRead, RunnerID: "reader", LeaseDuration: time.Minute, ClaimsEnabled: true,
	}); err != nil {
		t.Fatalf("Claim(READ) behind UNCERTAIN production write: %v", err)
	}
}

func TestMemoryReconcileResolvesUncertainAndReleasesReservationsIdempotently(t *testing.T) {
	repository, clock := newMemoryRepository(t)
	ctx := context.Background()
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "production-write-uncertain", TargetKey: "prod/cluster-a/deployment/api",
		Pool: executionlease.PoolWrite, Production: true,
	})
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "production-write-waiting", TargetKey: "prod/cluster-b/deployment/worker",
		Pool: executionlease.PoolWrite, Production: true,
	})
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "same-target-read-waiting", TargetKey: "prod/cluster-a/deployment/api",
		Pool: executionlease.PoolRead, Production: true,
	})
	lease, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-old", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Claim(): %v", err)
	}
	if _, err := repository.Start(ctx, lease.Fence()); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	clock.Advance(time.Minute)
	if _, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-blocked", LeaseDuration: time.Minute, ClaimsEnabled: true,
	}); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("Claim() before reconciliation error = %v", err)
	}
	if _, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolRead, RunnerID: "reader-blocked", LeaseDuration: time.Minute, ClaimsEnabled: true,
	}); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("same-target READ before reconciliation error = %v", err)
	}

	request := executionlease.ReconcileRequest{
		ExecutionID:      lease.ExecutionID,
		ReconciliationID: "reconciliation-20260710-0001",
		ActorID:          "operator/sre-oncall@example.com",
		Status:           executionlease.StatusSucceeded,
		ResultHash:       strings.Repeat("f", 64),
	}
	resolved, err := repository.Reconcile(ctx, request)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if resolved.Status != request.Status || resolved.ResultHash != "" || resolved.ReconciliationResultHash != request.ResultHash ||
		resolved.ReconciliationID != request.ReconciliationID || resolved.ReconciliationActor != request.ActorID ||
		!resolved.ReconciledAt.Equal(clock.Now()) {
		t.Fatalf("Reconcile() = %+v", resolved)
	}
	idempotent, err := repository.Reconcile(ctx, request)
	if err != nil || idempotent != resolved {
		t.Fatalf("idempotent Reconcile() = %+v, %v; first = %+v", idempotent, err, resolved)
	}

	conflict := request
	conflict.ResultHash = strings.Repeat("0", 64)
	if _, err := repository.Reconcile(ctx, conflict); !errors.Is(err, executionlease.ErrReconciliationConflict) {
		t.Fatalf("conflicting Reconcile() error = %v", err)
	}
	readClaim, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolRead, RunnerID: "reader-next", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil || readClaim.ExecutionID != "same-target-read-waiting" {
		t.Fatalf("same-target READ after reconciliation = %+v, %v", readClaim, err)
	}
	claimed, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-next", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil || claimed.ExecutionID != "production-write-waiting" {
		t.Fatalf("Claim() after reconciliation = %+v, %v", claimed, err)
	}
}

func TestMemoryReconcileRequiresUncertainAndGloballyUniqueAuditReference(t *testing.T) {
	repository, clock := newMemoryRepository(t)
	ctx := context.Background()
	makeUncertain := func(executionID, targetKey string) executionlease.Execution {
		t.Helper()
		enqueue(t, repository, executionlease.EnqueueRequest{
			ExecutionID: executionID, TargetKey: targetKey, Pool: executionlease.PoolWrite,
		})
		lease, err := repository.Claim(ctx, executionlease.ClaimRequest{
			Pool: executionlease.PoolWrite, RunnerID: "runner-" + executionID,
			LeaseDuration: time.Minute, ClaimsEnabled: true,
		})
		if err != nil {
			t.Fatalf("Claim(%s): %v", executionID, err)
		}
		if _, err := repository.Start(ctx, lease.Fence()); err != nil {
			t.Fatalf("Start(%s): %v", executionID, err)
		}
		clock.Advance(time.Minute)
		if _, err := repository.Claim(ctx, executionlease.ClaimRequest{
			Pool: executionlease.PoolWrite, RunnerID: "expiry-observer",
			LeaseDuration: time.Minute, ClaimsEnabled: true,
		}); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
			t.Fatalf("materialize expiry for %s: %v", executionID, err)
		}
		return lease
	}

	first := makeUncertain("execution-first", "cluster/ns/deployment/first")
	request := executionlease.ReconcileRequest{
		ExecutionID: first.ExecutionID, ReconciliationID: "audit/reconciliation/42",
		ActorID: "operator/alice", Status: executionlease.StatusFailed, ResultHash: strings.Repeat("1", 64),
	}
	if _, err := repository.Reconcile(ctx, request); err != nil {
		t.Fatalf("Reconcile(first): %v", err)
	}

	second := makeUncertain("execution-second", "cluster/ns/deployment/second")
	reused := request
	reused.ExecutionID = second.ExecutionID
	if _, err := repository.Reconcile(ctx, reused); !errors.Is(err, executionlease.ErrReconciliationConflict) {
		t.Fatalf("Reconcile() with reused audit reference error = %v", err)
	}

	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "still-running", TargetKey: "cluster/ns/deployment/running", Pool: executionlease.PoolWrite,
	})
	running, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-current", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Claim(still-running): %v", err)
	}
	if _, err := repository.Start(ctx, running.Fence()); err != nil {
		t.Fatalf("Start(still-running): %v", err)
	}
	invalid := request
	invalid.ExecutionID = running.ExecutionID
	invalid.ReconciliationID = "audit/reconciliation/43"
	if _, err := repository.Reconcile(ctx, invalid); !errors.Is(err, executionlease.ErrInvalidTransition) {
		t.Fatalf("Reconcile(RUNNING) error = %v", err)
	}
}

func TestMemoryFenceBindsRunnerAndRejectsInvalidIdentities(t *testing.T) {
	repository, _ := newMemoryRepository(t)
	ctx := context.Background()
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "runner-bound", TargetKey: "cluster/ns/deployment/runner-bound", Pool: executionlease.PoolWrite,
	})
	lease, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-a", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Claim(): %v", err)
	}
	fence := lease.Fence()
	if fence.RunnerID != lease.RunnerID || fence.RunnerID != "runner-a" {
		t.Fatalf("Fence() = %+v, lease runner = %q", fence, lease.RunnerID)
	}

	wrongRunner := fence
	wrongRunner.RunnerID = "runner-b"
	if _, err := repository.Start(ctx, wrongRunner); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("Start() with wrong runner error = %v", err)
	}
	if _, err := repository.Heartbeat(ctx, executionlease.HeartbeatRequest{
		Lease: wrongRunner, Extension: time.Minute,
	}); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("Heartbeat() with wrong runner error = %v", err)
	}
	if _, err := repository.Complete(ctx, executionlease.CompleteRequest{
		Lease: wrongRunner, Status: executionlease.StatusSucceeded, ResultHash: strings.Repeat("2", 64),
	}); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("Complete() with wrong runner error = %v", err)
	}

	invalid := fence
	invalid.RunnerID = ""
	if _, err := repository.Start(ctx, invalid); !errors.Is(err, executionlease.ErrInvalidRequest) {
		t.Fatalf("Start() with invalid fence error = %v", err)
	}
	if _, err := repository.Heartbeat(ctx, executionlease.HeartbeatRequest{
		Lease: invalid, Extension: time.Minute,
	}); !errors.Is(err, executionlease.ErrInvalidRequest) {
		t.Fatalf("Heartbeat() with invalid fence error = %v", err)
	}
	if _, err := repository.Complete(ctx, executionlease.CompleteRequest{
		Lease: invalid, Status: executionlease.StatusSucceeded, ResultHash: strings.Repeat("3", 64),
	}); !errors.Is(err, executionlease.ErrInvalidRequest) {
		t.Fatalf("Complete() with invalid fence error = %v", err)
	}
	if _, err := repository.Start(ctx, fence); err != nil {
		t.Fatalf("Start() with current runner: %v", err)
	}
	resultHash := strings.Repeat("8", 64)
	if _, err := repository.Complete(ctx, executionlease.CompleteRequest{
		Lease: fence, Status: executionlease.StatusSucceeded, ResultHash: resultHash,
	}); err != nil {
		t.Fatalf("Complete() with current runner: %v", err)
	}
	if _, err := repository.Complete(ctx, executionlease.CompleteRequest{
		Lease: wrongRunner, Status: executionlease.StatusSucceeded, ResultHash: resultHash,
	}); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("idempotent Complete() with wrong runner error = %v", err)
	}
}

func TestMemoryReconcilePreservesRunnerUncertainResultHash(t *testing.T) {
	repository, _ := newMemoryRepository(t)
	ctx := context.Background()
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "runner-uncertain", TargetKey: "cluster/ns/deployment/uncertain", Pool: executionlease.PoolWrite,
	})
	lease, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-a", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Claim(): %v", err)
	}
	if _, err := repository.Start(ctx, lease.Fence()); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	runnerHash := strings.Repeat("4", 64)
	uncertain, err := repository.Complete(ctx, executionlease.CompleteRequest{
		Lease: lease.Fence(), Status: executionlease.StatusUncertain, ResultHash: runnerHash,
	})
	if err != nil || uncertain.ResultHash != runnerHash {
		t.Fatalf("Complete(UNCERTAIN) = %+v, %v", uncertain, err)
	}
	reconciliationHash := strings.Repeat("5", 64)
	request := executionlease.ReconcileRequest{
		ExecutionID: lease.ExecutionID, ReconciliationID: "audit/reconciliation/preserve-hash",
		ActorID: "operator/alice", Status: executionlease.StatusSucceeded, ResultHash: reconciliationHash,
	}
	resolved, err := repository.Reconcile(ctx, request)
	if err != nil {
		t.Fatalf("Reconcile(): %v", err)
	}
	if resolved.ResultHash != runnerHash || resolved.ReconciliationResultHash != reconciliationHash {
		t.Fatalf("resolved hashes = runner %q, reconciliation %q", resolved.ResultHash, resolved.ReconciliationResultHash)
	}
	if resolved.LeaseToken != "" {
		t.Fatalf("Reconcile() leaked completed lease token %q", resolved.LeaseToken)
	}
	idempotent, err := repository.Reconcile(ctx, request)
	if err != nil || idempotent != resolved {
		t.Fatalf("idempotent Reconcile() = %+v, %v", idempotent, err)
	}
	cancelled, err := repository.Cancel(ctx, lease.ExecutionID)
	if err != nil || cancelled.LeaseToken != "" {
		t.Fatalf("Cancel(terminal) = %+v, %v; lease token must stay hidden", cancelled, err)
	}
}

func TestMemorySweepExpiredMaterializesLeasedAndRunningStates(t *testing.T) {
	repository, clock := newMemoryRepository(t)
	ctx := context.Background()
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "sweep-running", TargetKey: "cluster/ns/deployment/running", Pool: executionlease.PoolWrite,
	})
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "sweep-leased", TargetKey: "cluster/ns/deployment/leased", Pool: executionlease.PoolRead,
	})
	running, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-running", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Claim(RUNNING): %v", err)
	}
	if _, err := repository.Start(ctx, running.Fence()); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	if _, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolRead, RunnerID: "runner-leased", LeaseDuration: time.Minute, ClaimsEnabled: true,
	}); err != nil {
		t.Fatalf("Claim(LEASED): %v", err)
	}
	clock.Advance(time.Minute)
	if err := repository.SweepExpired(ctx); err != nil {
		t.Fatalf("SweepExpired(): %v", err)
	}
	clock.Advance(-time.Minute)
	gotRunning, err := repository.Get(ctx, "sweep-running")
	if err != nil || gotRunning.Status != executionlease.StatusUncertain || gotRunning.RunnerID != running.RunnerID {
		t.Fatalf("swept RUNNING = %+v, %v", gotRunning, err)
	}
	gotLeased, err := repository.Get(ctx, "sweep-leased")
	if err != nil || gotLeased.Status != executionlease.StatusQueued || gotLeased.LeaseEpoch != 1 {
		t.Fatalf("swept LEASED = %+v, %v", gotLeased, err)
	}
}

func TestMemoryDisabledClaimStillMaterializesExpiredRunning(t *testing.T) {
	repository, clock := newMemoryRepository(t)
	ctx := context.Background()
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "disabled-sweep", TargetKey: "cluster/ns/deployment/disabled", Pool: executionlease.PoolWrite,
	})
	lease, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-old", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Claim(): %v", err)
	}
	if _, err := repository.Start(ctx, lease.Fence()); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	clock.Advance(time.Minute)
	if _, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-disabled", LeaseDuration: time.Minute, ClaimsEnabled: false,
	}); !errors.Is(err, executionlease.ErrClaimBlocked) {
		t.Fatalf("disabled Claim() error = %v", err)
	}
	clock.Advance(-time.Minute)
	got, err := repository.Get(ctx, lease.ExecutionID)
	if err != nil || got.Status != executionlease.StatusUncertain {
		t.Fatalf("state after disabled Claim() = %+v, %v", got, err)
	}
}

func TestMemoryDisabledClaimValidatesBeforeSweeping(t *testing.T) {
	repository, clock := newMemoryRepository(t)
	ctx := context.Background()
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "disabled-invalid", TargetKey: "cluster/ns/deployment/disabled-invalid", Pool: executionlease.PoolWrite,
	})
	lease, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-old", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Claim(): %v", err)
	}
	if _, err := repository.Start(ctx, lease.Fence()); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	clock.Advance(time.Minute)
	if _, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner invalid", LeaseDuration: time.Minute, ClaimsEnabled: false,
	}); !errors.Is(err, executionlease.ErrInvalidRequest) {
		t.Fatalf("disabled invalid Claim() error = %v", err)
	}
	clock.Advance(-time.Minute)
	got, err := repository.Get(ctx, lease.ExecutionID)
	if err != nil || got.Status != executionlease.StatusRunning {
		t.Fatalf("invalid disabled Claim() must not sweep: %+v, %v", got, err)
	}
}

func TestMemoryGetDoesNotExposeLeaseToken(t *testing.T) {
	repository, _ := newMemoryRepository(t)
	ctx := context.Background()
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "get-redacts-token", TargetKey: "cluster/ns/deployment/redact", Pool: executionlease.PoolWrite,
	})
	lease, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-redact", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Claim(): %v", err)
	}
	got, err := repository.Get(ctx, lease.ExecutionID)
	if err != nil {
		t.Fatalf("Get(): %v", err)
	}
	if got.LeaseToken != "" || got.RunnerID != lease.RunnerID || got.LeaseEpoch != lease.LeaseEpoch {
		t.Fatalf("Get() = %+v; token must be redacted while metadata remains", got)
	}
	if _, err := repository.Start(ctx, lease.Fence()); err != nil {
		t.Fatalf("redacted Get() must not alter stored fence: %v", err)
	}
}

func TestMemoryGetAndReconcileMaterializeExpiredRunning(t *testing.T) {
	t.Run("get", func(t *testing.T) {
		repository, clock := newMemoryRepository(t)
		ctx := context.Background()
		enqueue(t, repository, executionlease.EnqueueRequest{
			ExecutionID: "get-expired", TargetKey: "cluster/ns/deployment/get", Pool: executionlease.PoolWrite,
		})
		lease, err := repository.Claim(ctx, executionlease.ClaimRequest{
			Pool: executionlease.PoolWrite, RunnerID: "runner-get", LeaseDuration: time.Minute, ClaimsEnabled: true,
		})
		if err != nil {
			t.Fatalf("Claim(): %v", err)
		}
		if _, err := repository.Start(ctx, lease.Fence()); err != nil {
			t.Fatalf("Start(): %v", err)
		}
		clock.Advance(time.Minute)
		got, err := repository.Get(ctx, lease.ExecutionID)
		if err != nil || got.Status != executionlease.StatusUncertain {
			t.Fatalf("Get(expired) = %+v, %v", got, err)
		}
	})

	t.Run("reconcile", func(t *testing.T) {
		repository, clock := newMemoryRepository(t)
		ctx := context.Background()
		enqueue(t, repository, executionlease.EnqueueRequest{
			ExecutionID: "reconcile-expired", TargetKey: "cluster/ns/deployment/reconcile", Pool: executionlease.PoolWrite,
		})
		lease, err := repository.Claim(ctx, executionlease.ClaimRequest{
			Pool: executionlease.PoolWrite, RunnerID: "runner-reconcile", LeaseDuration: time.Minute, ClaimsEnabled: true,
		})
		if err != nil {
			t.Fatalf("Claim(): %v", err)
		}
		if _, err := repository.Start(ctx, lease.Fence()); err != nil {
			t.Fatalf("Start(): %v", err)
		}
		clock.Advance(time.Minute)
		reconciliationHash := strings.Repeat("6", 64)
		got, err := repository.Reconcile(ctx, executionlease.ReconcileRequest{
			ExecutionID: lease.ExecutionID, ReconciliationID: "audit/reconciliation/expired",
			ActorID: "operator/alice", Status: executionlease.StatusFailed, ResultHash: reconciliationHash,
		})
		if err != nil || got.Status != executionlease.StatusFailed || got.RunnerID != lease.RunnerID || got.ResultHash != "" ||
			got.ReconciliationResultHash != reconciliationHash {
			t.Fatalf("Reconcile(expired RUNNING) = %+v, %v", got, err)
		}
	})
}

func TestMemoryIdentifiersRequirePrintableActionTokenASCII(t *testing.T) {
	repository, _ := newMemoryRepository(t)
	ctx := context.Background()
	invalid := []string{"_leading", "has space", "unicode-é", "plus+sign", "line\nbreak"}
	for index, value := range invalid {
		_, err := repository.Enqueue(ctx, executionlease.EnqueueRequest{
			ExecutionID: value, TargetKey: fmt.Sprintf("target/%d", index), Pool: executionlease.PoolWrite,
		})
		if !errors.Is(err, executionlease.ErrInvalidRequest) {
			t.Errorf("Enqueue(ExecutionID=%q) error = %v", value, err)
		}
	}
	validID := "A0._:/@-"
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: validID, TargetKey: "Target/A0._:/@-", Pool: executionlease.PoolWrite,
	})
	for _, runnerID := range invalid {
		if _, err := repository.Claim(ctx, executionlease.ClaimRequest{
			Pool: executionlease.PoolWrite, RunnerID: runnerID, LeaseDuration: time.Minute, ClaimsEnabled: true,
		}); !errors.Is(err, executionlease.ErrInvalidRequest) {
			t.Errorf("Claim(RunnerID=%q) error = %v", runnerID, err)
		}
	}
	if _, err := repository.Reconcile(ctx, executionlease.ReconcileRequest{
		ExecutionID: validID, ReconciliationID: "audit+invalid", ActorID: "operator/alice",
		Status: executionlease.StatusSucceeded, ResultHash: strings.Repeat("7", 64),
	}); !errors.Is(err, executionlease.ErrInvalidRequest) {
		t.Fatalf("Reconcile(invalid ID) error = %v", err)
	}

	invalidTokenRepository, err := executionlease.NewMemory(executionlease.MemoryOptions{
		TokenSource: func() (string, error) { return "token+invalid", nil },
	})
	if err != nil {
		t.Fatalf("NewMemory(invalid token source): %v", err)
	}
	enqueue(t, invalidTokenRepository, executionlease.EnqueueRequest{
		ExecutionID: "invalid-token", TargetKey: "target/invalid-token", Pool: executionlease.PoolWrite,
	})
	if _, err := invalidTokenRepository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-valid", LeaseDuration: time.Minute, ClaimsEnabled: true,
	}); !errors.Is(err, executionlease.ErrInvalidRequest) {
		t.Fatalf("Claim(invalid generated token) error = %v", err)
	}
}

func TestMemoryRejectsSubsecondLeaseAndHeartbeatDurations(t *testing.T) {
	repository, _ := newMemoryRepository(t)
	ctx := context.Background()
	enqueue(t, repository, executionlease.EnqueueRequest{
		ExecutionID: "duration-bounds", TargetKey: "target/duration-bounds", Pool: executionlease.PoolWrite,
	})
	if _, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-duration", LeaseDuration: time.Second - time.Nanosecond, ClaimsEnabled: true,
	}); !errors.Is(err, executionlease.ErrInvalidRequest) {
		t.Fatalf("Claim(subsecond) error = %v, want ErrInvalidRequest", err)
	}
	lease, err := repository.Claim(ctx, executionlease.ClaimRequest{
		Pool: executionlease.PoolWrite, RunnerID: "runner-duration", LeaseDuration: time.Second, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Claim(1s): %v", err)
	}
	if _, err := repository.Heartbeat(ctx, executionlease.HeartbeatRequest{
		Lease: lease.Fence(), Extension: time.Second - time.Nanosecond,
	}); !errors.Is(err, executionlease.ErrInvalidRequest) {
		t.Fatalf("Heartbeat(subsecond) error = %v, want ErrInvalidRequest", err)
	}
}

func newMemoryRepository(t *testing.T) (*executionlease.MemoryRepository, *fakeClock) {
	t.Helper()
	clock := &fakeClock{now: time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)}
	var sequence atomic.Uint64
	repository, err := executionlease.NewMemory(executionlease.MemoryOptions{
		Clock: clock.Now,
		TokenSource: func() (string, error) {
			return fmt.Sprintf("%032x", sequence.Add(1)), nil
		},
	})
	if err != nil {
		t.Fatalf("NewMemory() error = %v", err)
	}
	return repository, clock
}

func enqueue(t *testing.T, repository executionlease.Repository, request executionlease.EnqueueRequest) executionlease.Execution {
	t.Helper()
	execution, err := repository.Enqueue(context.Background(), request)
	if err != nil {
		t.Fatalf("Enqueue(%s) error = %v", request.ExecutionID, err)
	}
	return execution
}

type fakeClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *fakeClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}
