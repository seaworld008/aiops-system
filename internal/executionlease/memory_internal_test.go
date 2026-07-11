package executionlease

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMemoryStoresOnlyLeaseFenceDigestFromClaimThroughCompletion(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	const rawToken = "raw-token-secret-0001"
	repository, err := NewMemory(MemoryOptions{
		Clock:       func() time.Time { return now },
		TokenSource: func() (string, error) { return rawToken, nil },
	})
	if err != nil {
		t.Fatalf("NewMemory() error = %v", err)
	}
	const executionID = "digest-completion"
	enqueued, err := repository.Enqueue(ctx, EnqueueRequest{
		ExecutionID: executionID,
		TargetKey:   "nonprod/cluster/deployment/digest-completion",
		Pool:        PoolWrite,
	})
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	if enqueued.LeaseToken != "" {
		t.Fatalf("Enqueue() leaked lease token %q", enqueued.LeaseToken)
	}
	repository.leaseFences[executionID] = leaseFence{
		runnerID: "stale-runner",
		epoch:    99,
	}

	claimed, err := repository.Claim(ctx, ClaimRequest{
		Pool:          PoolWrite,
		RunnerID:      "runner-digest",
		LeaseDuration: time.Minute,
		ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if claimed.LeaseToken != rawToken {
		t.Fatalf("Claim() token = %q, want the one raw-token response", claimed.LeaseToken)
	}
	if stored := repository.executions[executionID].LeaseToken; stored != "" {
		t.Fatalf("Claim() persisted raw token %q in the execution", stored)
	}
	activeFence, exists := repository.leaseFences[executionID]
	if !exists {
		t.Fatal("Claim() did not persist a hashed lease fence")
	}
	if activeFence.runnerID != claimed.RunnerID || activeFence.epoch != claimed.LeaseEpoch ||
		activeFence.tokenSHA256 != sha256.Sum256([]byte(rawToken)) {
		t.Fatalf("Claim() lease fence = %+v; want current runner, epoch, and SHA-256 token binding", activeFence)
	}
	if got, err := repository.Get(ctx, executionID); err != nil || got.LeaseToken != "" {
		t.Fatalf("Get() = %+v, %v; token must be redacted", got, err)
	}

	fence := claimed.Fence()
	running, err := repository.Start(ctx, fence)
	if err != nil || running.LeaseToken != "" {
		t.Fatalf("Start() = %+v, %v; token must be redacted", running, err)
	}
	heartbeat, err := repository.Heartbeat(ctx, HeartbeatRequest{Lease: fence, Extension: 2 * time.Minute})
	if err != nil || heartbeat.LeaseToken != "" {
		t.Fatalf("Heartbeat() = %+v, %v; token must be redacted", heartbeat, err)
	}
	if stored := repository.executions[executionID].LeaseToken; stored != "" {
		t.Fatalf("active execution retained raw token %q after Start/Heartbeat", stored)
	}
	if got := repository.leaseFences[executionID]; got != activeFence {
		t.Fatalf("Start/Heartbeat changed lease fence = %+v; want %+v", got, activeFence)
	}

	resultHash := strings.Repeat("a", 64)
	completed, err := repository.Complete(ctx, CompleteRequest{
		Lease: fence, Status: StatusSucceeded, ResultHash: resultHash,
	})
	if err != nil || completed.LeaseToken != "" {
		t.Fatalf("Complete() = %+v, %v; token must be redacted", completed, err)
	}
	if stored := repository.executions[executionID].LeaseToken; stored != "" {
		t.Fatalf("terminal execution retained raw token %q", stored)
	}
	completedFence, exists := repository.leaseFences[executionID]
	if !exists {
		t.Fatal("terminal execution did not retain a hashed idempotency fence")
	}
	if completedFence != activeFence {
		t.Fatalf("completed fence = %+v; want unchanged active fence %+v", completedFence, activeFence)
	}
	idempotent, err := repository.Complete(ctx, CompleteRequest{
		Lease: fence, Status: StatusSucceeded, ResultHash: resultHash,
	})
	if err != nil || idempotent.LeaseToken != "" || idempotent != completed {
		t.Fatalf("idempotent Complete() = %+v, %v; first = %+v", idempotent, err, completed)
	}
	wrongToken := fence
	wrongToken.Token = "raw-token-secret-wrong"
	if _, err := repository.Complete(ctx, CompleteRequest{
		Lease: wrongToken, Status: StatusSucceeded, ResultHash: resultHash,
	}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("Complete(wrong token) error = %v, want ErrStaleLease", err)
	}
	cancelled, err := repository.Cancel(ctx, executionID)
	if err != nil || cancelled.LeaseToken != "" {
		t.Fatalf("Cancel(terminal) = %+v, %v; token must be redacted", cancelled, err)
	}
	if got, exists := repository.leaseFences[executionID]; !exists || got != activeFence {
		t.Fatalf("Cancel(terminal) lease fence = %+v, exists %t; want unchanged %+v", got, exists, activeFence)
	}
	retried, err := repository.Complete(ctx, CompleteRequest{
		Lease: fence, Status: StatusSucceeded, ResultHash: resultHash,
	})
	if err != nil || retried.LeaseToken != "" || retried != completed {
		t.Fatalf("Complete() after terminal Cancel = %+v, %v; want idempotent %+v without token", retried, err, completed)
	}
}

func TestMemoryReconcileDeletesLeaseFence(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 11, 9, 30, 0, 0, time.UTC)
	repository, err := NewMemory(MemoryOptions{
		Clock:       func() time.Time { return now },
		TokenSource: func() (string, error) { return "raw-token-for-reconcile", nil },
	})
	if err != nil {
		t.Fatalf("NewMemory() error = %v", err)
	}
	const executionID = "reconcile-destroys-fence"
	if _, err := repository.Enqueue(ctx, EnqueueRequest{
		ExecutionID: executionID,
		TargetKey:   "nonprod/cluster/deployment/reconcile",
		Pool:        PoolWrite,
	}); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	claimed, err := repository.Claim(ctx, ClaimRequest{
		Pool: PoolWrite, RunnerID: "runner-reconcile", LeaseDuration: time.Minute, ClaimsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if _, err := repository.Start(ctx, claimed.Fence()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := repository.Complete(ctx, CompleteRequest{
		Lease: claimed.Fence(), Status: StatusUncertain, ResultHash: strings.Repeat("c", 64),
	}); err != nil {
		t.Fatalf("Complete(UNCERTAIN) error = %v", err)
	}
	if _, exists := repository.leaseFences[executionID]; !exists {
		t.Fatal("Complete(UNCERTAIN) removed the fence required for idempotency")
	}
	reconciled, err := repository.Reconcile(ctx, ReconcileRequest{
		ExecutionID: executionID, ReconciliationID: "audit/reconcile/fence", ActorID: "operator/alice",
		Status: StatusFailed, ResultHash: strings.Repeat("d", 64),
	})
	if err != nil || reconciled.LeaseToken != "" {
		t.Fatalf("Reconcile() = %+v, %v; token must be redacted", reconciled, err)
	}
	if _, exists := repository.leaseFences[executionID]; exists {
		t.Fatal("Reconcile() retained a lease fence")
	}
}

func TestMemoryCancelAndExpiryDestroyRawLeaseTokens(t *testing.T) {
	testCases := []struct {
		name       string
		start      bool
		transition func(context.Context, *MemoryRepository, *time.Time, string) error
		wantStatus Status
	}{
		{
			name: "cancel leased",
			transition: func(ctx context.Context, repository *MemoryRepository, _ *time.Time, executionID string) error {
				_, err := repository.Cancel(ctx, executionID)
				return err
			},
			wantStatus: StatusCancelled,
		},
		{
			name:  "cancel running",
			start: true,
			transition: func(ctx context.Context, repository *MemoryRepository, _ *time.Time, executionID string) error {
				_, err := repository.Cancel(ctx, executionID)
				return err
			},
			wantStatus: StatusUncertain,
		},
		{
			name: "expire leased",
			transition: func(ctx context.Context, repository *MemoryRepository, now *time.Time, _ string) error {
				*now = now.Add(time.Minute)
				return repository.SweepExpired(ctx)
			},
			wantStatus: StatusQueued,
		},
		{
			name:  "expire running",
			start: true,
			transition: func(ctx context.Context, repository *MemoryRepository, now *time.Time, _ string) error {
				*now = now.Add(time.Minute)
				return repository.SweepExpired(ctx)
			},
			wantStatus: StatusUncertain,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
			repository, err := NewMemory(MemoryOptions{
				Clock:       func() time.Time { return now },
				TokenSource: func() (string, error) { return "raw-token-to-destroy", nil },
			})
			if err != nil {
				t.Fatalf("NewMemory() error = %v", err)
			}
			executionID := strings.ReplaceAll(testCase.name, " ", "-")
			if _, err := repository.Enqueue(ctx, EnqueueRequest{
				ExecutionID: executionID,
				TargetKey:   "nonprod/target/" + executionID,
				Pool:        PoolWrite,
			}); err != nil {
				t.Fatalf("Enqueue() error = %v", err)
			}
			claimed, err := repository.Claim(ctx, ClaimRequest{
				Pool:          PoolWrite,
				RunnerID:      "runner-destroy",
				LeaseDuration: time.Minute,
				ClaimsEnabled: true,
			})
			if err != nil {
				t.Fatalf("Claim() error = %v", err)
			}
			if testCase.start {
				if _, err := repository.Start(ctx, claimed.Fence()); err != nil {
					t.Fatalf("Start() error = %v", err)
				}
			}
			if err := testCase.transition(ctx, repository, &now, executionID); err != nil {
				t.Fatalf("transition error = %v", err)
			}
			stored := repository.executions[executionID]
			if stored.Status != testCase.wantStatus || stored.LeaseToken != "" {
				t.Fatalf("stored execution = %+v; want status %s and no raw token", stored, testCase.wantStatus)
			}
			if _, exists := repository.leaseFences[executionID]; exists {
				t.Fatal("cancelled or expired execution retained a lease fence")
			}
			if testCase.wantStatus != StatusQueued {
				if _, err := repository.Complete(ctx, CompleteRequest{
					Lease: claimed.Fence(), Status: StatusFailed, ResultHash: strings.Repeat("b", 64),
				}); !errors.Is(err, ErrStaleLease) {
					t.Fatalf("Complete() after token destruction error = %v, want ErrStaleLease", err)
				}
			}
		})
	}
}
