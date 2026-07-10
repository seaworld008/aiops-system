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
		Lease:     executionlease.LeaseIdentity{ExecutionID: fence.ExecutionID, Token: "stale-token", Epoch: fence.Epoch},
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
	if err != nil || uncertain.Status != executionlease.StatusUncertain {
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
	if err != nil || uncertain.Status != executionlease.StatusUncertain {
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
	if resolved.Status != request.Status || resolved.ResultHash != request.ResultHash ||
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
