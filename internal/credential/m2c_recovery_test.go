package credential

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestM2CRevocationTimingPolicyIsFixed(t *testing.T) {
	if RevocationClaimLease != 30*time.Second || RevocationHeartbeatInterval != 10*time.Second ||
		RevocationRemoteTimeout != 20*time.Second || MinRevocationRetryDelay != 5*time.Second ||
		MaxRevocationRetryDelay != 15*time.Minute || MaxRevocationAttempts != 12 ||
		MaxRevocationElapsed != 2*time.Hour || ManagedAnchorRecoveryGrace != 2*time.Minute {
		t.Fatalf("unexpected M2C revocation timing policy")
	}
}

func TestMemoryRetryRevocationUsesAttemptAndElapsedExhaustionBoundaries(t *testing.T) {
	t.Run("twelfth attempt requires manual intervention", func(t *testing.T) {
		ctx := context.Background()
		now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
		fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 1}
		tokens := make([]string, MaxRevocationAttempts)
		for index := range tokens {
			tokens[index] = fmt.Sprintf("claim-token-%02d", index+1)
		}
		repository := newTestMemoryRepository(t,
			&fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)},
			func() time.Time { return now }, sequenceTokens(tokens...))
		prepareActivePending(t, ctx, repository, now, fence, testRevocationID, "attempt-boundary-accessor")

		for attempt := 1; attempt <= MaxRevocationAttempts; attempt++ {
			claims, err := repository.ClaimRevocations(ctx, ClaimRevocationsRequest{
				WorkerID: "revoker-attempt-boundary", Limit: 1, LeaseDuration: RevocationClaimLease,
			})
			if err != nil || len(claims) != 1 || claims[0].Revocation.Attempt != attempt {
				t.Fatalf("claim attempt %d = %#v, %v", attempt, claims, err)
			}
			claims[0].Accessor.Destroy()
			failed, err := repository.RetryRevocation(ctx, RetryRevocationRequest{
				Fence: claims[0].Fence, Delay: MinRevocationRetryDelay,
				FailureCode: FailureIssuerUnavailable, FailureDetail: []byte("worker.resolve.issuer_unavailable"),
			})
			if err != nil {
				t.Fatalf("RetryRevocation(attempt %d) error = %v", attempt, err)
			}
			if attempt < MaxRevocationAttempts && failed.Status != StatusRevocationPending {
				t.Fatalf("attempt %d status = %s, want pending", attempt, failed.Status)
			}
			if attempt == MaxRevocationAttempts &&
				(failed.Status != StatusManualRequired || failed.ManualRequiredAt.IsZero()) {
				t.Fatalf("attempt %d result = %#v, want manual", attempt, failed)
			}
			now = now.Add(MinRevocationRetryDelay)
		}
	})

	t.Run("two hour database-time boundary requires manual intervention", func(t *testing.T) {
		ctx := context.Background()
		base := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
		now := base
		fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 2}
		repository := newTestMemoryRepository(t,
			&fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(base, fence)},
			func() time.Time { return now }, sequenceTokens("elapsed-boundary-claim"))
		prepareActivePending(t, ctx, repository, base, fence, testRevocationID, "elapsed-boundary-accessor")

		now = base.Add(MaxRevocationElapsed - time.Nanosecond)
		claims, err := repository.ClaimRevocations(ctx, ClaimRevocationsRequest{
			WorkerID: "revoker-elapsed-boundary", Limit: 1, LeaseDuration: RevocationClaimLease,
		})
		if err != nil || len(claims) != 1 {
			t.Fatalf("claim before elapsed boundary = %#v, %v", claims, err)
		}
		claims[0].Accessor.Destroy()
		now = base.Add(MaxRevocationElapsed)
		failed, err := repository.RetryRevocation(ctx, RetryRevocationRequest{
			Fence: claims[0].Fence, Delay: MinRevocationRetryDelay,
			FailureCode: FailureTimeout, FailureDetail: []byte("worker.remote.timeout"),
		})
		if err != nil || failed.Status != StatusManualRequired || failed.ManualRequiredAt.IsZero() {
			t.Fatalf("RetryRevocation(at elapsed boundary) = %#v, %v", failed, err)
		}
	})
}

func TestMemoryRecoverExhaustedHandlesCrashWithoutFailureAck(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 3}
	tokens := make([]string, MaxRevocationAttempts+1)
	for index := range tokens {
		tokens[index] = fmt.Sprintf("crash-claim-%02d", index+1)
	}
	repository := newTestMemoryRepository(t,
		&fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)},
		func() time.Time { return now }, sequenceTokens(tokens...))
	prepareActivePending(t, ctx, repository, now, fence, testRevocationID, "crash-recovery-accessor")

	for attempt := 1; attempt <= MaxRevocationAttempts; attempt++ {
		claims, err := repository.ClaimRevocations(ctx, ClaimRevocationsRequest{
			WorkerID: "crashing-revoker", Limit: 1, LeaseDuration: RevocationClaimLease,
		})
		if err != nil || len(claims) != 1 {
			t.Fatalf("crash claim %d = %#v, %v", attempt, claims, err)
		}
		claims[0].Accessor.Destroy()
		now = now.Add(RevocationClaimLease)
	}

	recovered, err := repository.RecoverExhausted(ctx, RecoverExhaustedRequest{Limit: 10})
	if err != nil || len(recovered) != 1 || recovered[0].Status != StatusManualRequired ||
		recovered[0].FailureCode != FailureUnknown || recovered[0].ManualRequiredAt.IsZero() {
		t.Fatalf("RecoverExhausted() = %#v, %v", recovered, err)
	}
	second, err := repository.RecoverExhausted(ctx, RecoverExhaustedRequest{Limit: 10})
	if err != nil || len(second) != 0 {
		t.Fatalf("RecoverExhausted(replay) = %#v, %v", second, err)
	}
	requeued, err := repository.RequeueManual(ctx, RequeueManualRequest{
		RevocationID: testRevocationID, ActorSubject: "oidc:platform-admin-retry",
	})
	if err != nil || requeued.Status != StatusRevocationPending {
		t.Fatalf("RequeueManual(exhausted) = %#v, %v", requeued, err)
	}
	reclaimed, err := repository.ClaimRevocations(ctx, ClaimRevocationsRequest{
		WorkerID: "repaired-revoker", Limit: 1, LeaseDuration: RevocationClaimLease,
	})
	if err != nil || len(reclaimed) != 1 || reclaimed[0].Revocation.Attempt != MaxRevocationAttempts+1 {
		t.Fatalf("ClaimRevocations(after manual repair) = %#v, %v", reclaimed, err)
	}
	reclaimed[0].Accessor.Destroy()
}

func TestMemoryRecoverManagedRevokesInvalidOrStalledCredentials(t *testing.T) {
	t.Run("current active remains until cancellation", func(t *testing.T) {
		ctx := context.Background()
		now := time.Date(2026, 7, 11, 11, 0, 0, 0, time.UTC)
		fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4}
		source := &fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)}
		repository := newTestMemoryRepository(t, source, func() time.Time { return now }, sequenceTokens("unused"))
		prepareManagedCredential(t, ctx, repository, now, fence, testRevocationID, "active-recovery-accessor", true)

		before, err := repository.RecoverManaged(ctx, RecoverManagedRequest{Limit: 10})
		if err != nil || len(before) != 0 {
			t.Fatalf("RecoverManaged(current ACTIVE) = %#v, %v", before, err)
		}
		source.metadata.CancelRequestedAt = now
		recovered, err := repository.RecoverManaged(ctx, RecoverManagedRequest{Limit: 10})
		if err != nil || len(recovered) != 1 || recovered[0].Status != StatusRevocationPending {
			t.Fatalf("RecoverManaged(cancelled ACTIVE) = %#v, %v", recovered, err)
		}
	})

	t.Run("current anchored crosses fixed issuance-stall grace", func(t *testing.T) {
		ctx := context.Background()
		base := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
		now := base
		fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 5}
		source := &fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(base, fence)}
		source.metadata.LeaseExpiresAt = base.Add(10 * time.Minute)
		repository := newTestMemoryRepository(t, source, func() time.Time { return now }, sequenceTokens("unused"))
		prepareManagedCredential(t, ctx, repository, base, fence, testRevocationID, "anchored-recovery-accessor", false)

		now = base.Add(ManagedAnchorRecoveryGrace - time.Nanosecond)
		before, err := repository.RecoverManaged(ctx, RecoverManagedRequest{Limit: 10})
		if err != nil || len(before) != 0 {
			t.Fatalf("RecoverManaged(before ANCHORED grace) = %#v, %v", before, err)
		}
		now = base.Add(ManagedAnchorRecoveryGrace)
		recovered, err := repository.RecoverManaged(ctx, RecoverManagedRequest{Limit: 10})
		if err != nil || len(recovered) != 1 || recovered[0].Status != StatusRevocationPending {
			t.Fatalf("RecoverManaged(at ANCHORED grace) = %#v, %v", recovered, err)
		}
	})
}

func TestMemoryRecoverManagedLimitCountsTransitionsNotCurrentRows(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 11, 12, 30, 0, 0, time.UTC)
	currentFence := ActionFence{
		ActionID: testActionID, RunnerID: "runner-write-1", Token: "current-action-token", Epoch: 6,
	}
	invalidFence := ActionFence{
		ActionID: "20000000-0000-4000-8000-000000000011",
		RunnerID: "runner-write-1", Token: "invalid-action-token", Epoch: 1,
	}
	currentMetadata := activeActionMetadata(now, currentFence)
	invalidMetadata := activeActionMetadata(now, invalidFence)
	source := &fakeActionFenceSource{fences: map[ActionFence]ActionMetadata{
		currentFence: currentMetadata,
		invalidFence: invalidMetadata,
	}}
	repository := newTestMemoryRepository(t, source, func() time.Time { return now }, sequenceTokens("unused"))
	prepareManagedCredential(t, ctx, repository, now, currentFence, testRevocationID, "current-accessor", true)
	invalidID := "10000000-0000-4000-8000-000000000011"
	prepareManagedCredential(t, ctx, repository, now, invalidFence, invalidID, "invalid-accessor", true)
	invalidMetadata.CancelRequestedAt = now
	source.fences[invalidFence] = invalidMetadata

	recovered, err := repository.RecoverManaged(ctx, RecoverManagedRequest{Limit: 1})
	if err != nil || len(recovered) != 1 || recovered[0].ID != invalidID ||
		recovered[0].Status != StatusRevocationPending {
		t.Fatalf("RecoverManaged(limit excludes current rows) = %#v, %v", recovered, err)
	}
	current, err := repository.Get(ctx, testRevocationID)
	if err != nil || current.Status != StatusActive {
		t.Fatalf("current credential = %#v, %v", current, err)
	}
}

func TestMemoryClaimQuarantinesCorruptAccessorWithoutStarvingValidWork(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 11, 13, 0, 0, 0, time.UTC)
	poisonFence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token-a", Epoch: 6}
	validFence := ActionFence{
		ActionID: "20000000-0000-4000-8000-000000000011", RunnerID: "runner-write-1", Token: "action-token-b", Epoch: 1,
	}
	source := &fakeActionFenceSource{fences: map[ActionFence]ActionMetadata{
		poisonFence: activeActionMetadata(now, poisonFence),
		validFence:  activeActionMetadata(now, validFence),
	}}
	repository := newTestMemoryRepository(t, source, func() time.Time { return now },
		sequenceTokens("poison-claim-token", "valid-claim-token"))
	prepareActivePending(t, ctx, repository, now, poisonFence, testRevocationID, "poison-accessor")
	validID := "10000000-0000-4000-8000-000000000011"
	prepareActivePending(t, ctx, repository, now, validFence, validID, "valid-accessor")

	repository.mu.Lock()
	repository.records[testRevocationID].protected.Ciphertext[0] ^= 0xff
	repository.mu.Unlock()

	claims, err := repository.ClaimRevocations(ctx, ClaimRevocationsRequest{
		WorkerID: "revoker-poison-isolation", Limit: 2, LeaseDuration: RevocationClaimLease,
	})
	if err != nil || len(claims) != 1 || claims[0].Revocation.ID != validID {
		t.Fatalf("ClaimRevocations(with poison) = %#v, %v", claims, err)
	}
	accessor := claims[0].Accessor.Bytes()
	if !bytes.Equal(accessor, []byte("valid-accessor")) {
		clear(accessor)
		t.Fatalf("valid claim accessor mismatch")
	}
	clear(accessor)
	claims[0].Accessor.Destroy()
	poison, err := repository.Get(ctx, testRevocationID)
	if err != nil || poison.Status != StatusManualRequired || poison.FailureCode != FailureInvalidReference ||
		poison.ClaimedBy != "" || poison.FailureDetailSHA256 == "" {
		t.Fatalf("poison quarantine = %#v, %v", poison, err)
	}
}

func TestRetryRevocationRejectsDelayOutsideFixedJitterBounds(t *testing.T) {
	for _, delay := range []time.Duration{0, MinRevocationRetryDelay - time.Nanosecond, MaxRevocationRetryDelay + time.Nanosecond} {
		request := RetryRevocationRequest{
			Fence: ClaimFence{RevocationID: testRevocationID, WorkerID: "revoker", Token: "claim-token", Epoch: 1},
			Delay: delay, FailureCode: FailureUnknown, FailureDetail: []byte("worker.remote.unknown"),
		}
		repository := (*MemoryRepository)(nil)
		if _, err := repository.RetryRevocation(context.Background(), request); !errors.Is(err, ErrInvalidRevocationRequest) {
			t.Fatalf("RetryRevocation(delay %s) error = %v", delay, err)
		}
	}
}

func prepareManagedCredential(
	t *testing.T,
	ctx context.Context,
	repository Repository,
	now time.Time,
	fence ActionFence,
	id, accessorValue string,
	activate bool,
) {
	t.Helper()
	prepared, err := repository.Prepare(ctx, PrepareRequest{
		RevocationID: id, Fence: fence, Issuer: "vault-production", IssuerRevision: "rev-1",
		CredentialExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	authorizePrepared(t, ctx, repository, prepared, fence)
	accessor, err := NewSensitiveReference([]byte(accessorValue))
	if err != nil {
		t.Fatal(err)
	}
	defer accessor.Destroy()
	if _, err := repository.RecordAnchor(ctx, RecordAnchorRequest{RevocationID: id, Fence: fence, Accessor: accessor}); err != nil {
		t.Fatal(err)
	}
	if activate {
		if _, err := repository.Activate(ctx, ActionTransitionRequest{RevocationID: id, Fence: fence}); err != nil {
			t.Fatal(err)
		}
	}
}
