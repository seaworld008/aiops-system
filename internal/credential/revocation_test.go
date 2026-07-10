package credential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

const (
	testRevocationID = "10000000-0000-4000-8000-000000000010"
	testActionID     = "20000000-0000-4000-8000-000000000010"
	testTenantID     = "30000000-0000-4000-8000-000000000010"
	testWorkspaceID  = "40000000-0000-4000-8000-000000000010"
	testEnvironment  = "50000000-0000-4000-8000-000000000010"
)

func TestMemoryRevocationLifecycleIsRedactedAndCompletionIsFenced(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-lease-token", Epoch: 9}
	source := &fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)}
	repository := newTestMemoryRepository(t, source, func() time.Time { return now }, sequenceTokens("claim-token-one"))

	prepared, err := repository.Prepare(ctx, PrepareRequest{
		RevocationID:        testRevocationID,
		Fence:               fence,
		Issuer:              "vault-production",
		CredentialExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if !prepared.Created || prepared.Revocation.Status != StatusPrepared || prepared.Revocation.WorkspaceID != testWorkspaceID ||
		prepared.Revocation.EnvironmentID != testEnvironment || prepared.Revocation.TargetKey != "cluster-a/payments" || !prepared.Revocation.Production ||
		prepared.Revocation.ConnectorID != "kubernetes-prod" || prepared.Revocation.Permission != "PATCH_DEPLOYMENT_RESTART" {
		t.Fatalf("prepared derived metadata = %#v", prepared)
	}
	accessor, err := NewSensitiveReference([]byte("vault lease/accessor 123"))
	if err != nil {
		t.Fatal(err)
	}
	anchored, err := repository.RecordAnchor(ctx, RecordAnchorRequest{RevocationID: testRevocationID, Fence: fence, Accessor: accessor})
	if err != nil {
		t.Fatalf("RecordAnchor() error = %v", err)
	}
	if anchored.Status != StatusAnchored || !anchored.AccessorPresent || len(anchored.AccessorHMAC) != 64 {
		t.Fatalf("anchored = %#v", anchored)
	}
	if _, err := repository.Activate(ctx, ActionTransitionRequest{RevocationID: testRevocationID, Fence: fence}); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if _, err := repository.RequestRevocation(ctx, ActionTransitionRequest{RevocationID: testRevocationID, Fence: fence}); err != nil {
		t.Fatalf("RequestRevocation() error = %v", err)
	}

	listed, err := repository.List(ctx, ListFilter{WorkspaceID: testWorkspaceID, Limit: 10})
	if err != nil || len(listed) != 1 || listed[0].Status != StatusRevocationPending {
		t.Fatalf("List() = %#v, %v", listed, err)
	}
	encoded, err := json.Marshal(listed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("vault lease/accessor 123")) || bytes.Contains(encoded, []byte("claim-token")) {
		t.Fatalf("List JSON leaked protected material: %s", encoded)
	}

	claims, err := repository.ClaimRevocations(ctx, ClaimRevocationsRequest{
		WorkerID: "revoker-1", Limit: 1, LeaseDuration: 30 * time.Second,
	})
	if err != nil || len(claims) != 1 {
		t.Fatalf("ClaimRevocations() = %#v, %v", claims, err)
	}
	claim := claims[0]
	if claim.Revocation.Status != StatusRevoking || claim.Fence.Token != "claim-token-one" || claim.Fence.Epoch != 1 ||
		string(claim.Accessor.Bytes()) != "vault lease/accessor 123" {
		t.Fatalf("claim = %#v", claim)
	}
	claimJSON, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(claimJSON, []byte("vault lease/accessor 123")) || bytes.Contains(claimJSON, []byte("claim-token-one")) {
		t.Fatalf("claim JSON leaked material: %s", claimJSON)
	}

	if _, err := repository.Heartbeat(ctx, HeartbeatRequest{Fence: claim.Fence, Extension: 30 * time.Second}); err != nil {
		t.Fatalf("Heartbeat() error = %v", err)
	}
	completed, err := repository.CompleteRevocation(ctx, CompleteRevocationRequest{Fence: claim.Fence})
	if err != nil {
		t.Fatalf("CompleteRevocation() error = %v", err)
	}
	if completed.Status != StatusRevoked || completed.AccessorPresent || completed.EncryptionKeyID != "" || completed.AccessorHMAC == "" {
		t.Fatalf("completed = %#v", completed)
	}
	if _, err := repository.CompleteRevocation(ctx, CompleteRevocationRequest{Fence: claim.Fence}); err != nil {
		t.Fatalf("idempotent CompleteRevocation() error = %v", err)
	}
	stale := claim.Fence
	stale.Token = "stale-claim-token"
	if _, err := repository.CompleteRevocation(ctx, CompleteRevocationRequest{Fence: stale}); !errors.Is(err, ErrStaleClaim) {
		t.Fatalf("CompleteRevocation(stale) error = %v, want ErrStaleClaim", err)
	}
}

func TestMemoryRevocationPrepareIsImmutableAndNoCredentialIsTerminal(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 10, 11, 0, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 2}
	source := &fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)}
	repository := newTestMemoryRepository(t, source, func() time.Time { return now }, sequenceTokens("unused"))
	request := PrepareRequest{
		RevocationID: testRevocationID, Fence: fence, Issuer: "vault-production", CredentialExpiresAt: now.Add(time.Minute),
	}

	first, err := repository.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := repository.Prepare(ctx, request)
	if err != nil || !first.Created || second.Created || second.Revocation.ID != first.Revocation.ID ||
		second.Revocation.Version != first.Revocation.Version {
		t.Fatalf("idempotent Prepare() = %#v, %v", second, err)
	}
	rotatedFenceRequest := request
	rotatedFenceRequest.Fence.Token = "different-token-for-same-epoch"
	source.fence = rotatedFenceRequest.Fence
	if _, err := repository.Prepare(ctx, rotatedFenceRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Prepare(same epoch different action token) error = %v", err)
	}
	source.fence = fence
	conflict := request
	conflict.Issuer = "different-issuer"
	if _, err := repository.Prepare(ctx, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Prepare(conflict) error = %v", err)
	}
	sameEpochDifferentID := request
	sameEpochDifferentID.RevocationID = "10000000-0000-4000-8000-000000000011"
	replayed, err := repository.Prepare(ctx, sameEpochDifferentID)
	if err != nil || replayed.Created || replayed.Revocation.ID != first.Revocation.ID {
		t.Fatalf("Prepare(same action epoch new candidate ID) = %#v, %v", replayed, err)
	}
	source.metadata.Permission = "TAMPERED_SCOPE"
	if _, err := repository.RecordNoCredential(ctx, ActionTransitionRequest{RevocationID: testRevocationID, Fence: fence}); !errors.Is(err, ErrStaleActionFence) {
		t.Fatalf("RecordNoCredential(changed trusted credential scope) error = %v", err)
	}
	source.metadata.Permission = "PATCH_DEPLOYMENT_RESTART"

	noCredential, err := repository.RecordNoCredential(ctx, ActionTransitionRequest{RevocationID: testRevocationID, Fence: fence})
	if err != nil || noCredential.Status != StatusNoCredential || noCredential.AccessorPresent || noCredential.AccessorHMAC != "" {
		t.Fatalf("RecordNoCredential() = %#v, %v", noCredential, err)
	}
	if _, err := repository.RecordNoCredential(ctx, ActionTransitionRequest{RevocationID: testRevocationID, Fence: fence}); err != nil {
		t.Fatalf("idempotent RecordNoCredential() error = %v", err)
	}
	accessor, _ := NewSensitiveReference([]byte("late-accessor"))
	if _, err := repository.RecordAnchor(ctx, RecordAnchorRequest{RevocationID: testRevocationID, Fence: fence, Accessor: accessor}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("RecordAnchor(after NO_CREDENTIAL) error = %v", err)
	}

	staleFence := fence
	staleFence.Token = "wrong-token"
	staleRequest := request
	staleRequest.RevocationID = "10000000-0000-4000-8000-000000000012"
	staleRequest.Fence = staleFence
	if _, err := repository.Prepare(ctx, staleRequest); !errors.Is(err, ErrStaleActionFence) {
		t.Fatalf("Prepare(stale action fence) error = %v", err)
	}
}

func TestMemoryPrepareReportsExactlyOneCreatedWinner(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 10, 11, 15, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 2}
	source := &fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)}
	repository := newTestMemoryRepository(t, source, func() time.Time { return now }, sequenceTokens("unused"))
	request := PrepareRequest{
		RevocationID: testRevocationID, Fence: fence, Issuer: "vault-production", CredentialExpiresAt: now.Add(time.Minute),
	}
	retryRequest := request
	retryRequest.RevocationID = "10000000-0000-4000-8000-000000000011"

	start := make(chan struct{})
	results := make(chan PrepareResult, 2)
	errors := make(chan error, 2)
	for _, candidate := range []PrepareRequest{request, retryRequest} {
		candidate := candidate
		go func() {
			<-start
			result, err := repository.Prepare(ctx, candidate)
			results <- result
			errors <- err
		}()
	}
	close(start)

	created := 0
	canonicalID := ""
	for range 2 {
		if err := <-errors; err != nil {
			t.Fatalf("concurrent Prepare() error = %v", err)
		}
		result := <-results
		if result.Created {
			created++
		}
		if canonicalID == "" {
			canonicalID = result.Revocation.ID
		}
		if result.Revocation.ID != canonicalID || result.Revocation.Status != StatusPrepared {
			t.Fatalf("concurrent Prepare() result = %#v", result)
		}
	}
	if created != 1 {
		t.Fatalf("concurrent Prepare() Created winners = %d, want 1", created)
	}
	if canonicalID != request.RevocationID && canonicalID != retryRequest.RevocationID {
		t.Fatalf("concurrent Prepare() canonical ID = %q", canonicalID)
	}
}

func TestMemoryPrepareCanonicalizesNanosecondExpiryAcrossConcurrentReplay(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 10, 11, 16, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 2}
	source := &fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)}
	repository := newTestMemoryRepository(t, source, func() time.Time { return now }, sequenceTokens("unused"))
	baseExpiry := now.Add(5 * time.Minute)
	requests := []PrepareRequest{
		{
			RevocationID: testRevocationID, Fence: fence, Issuer: "vault-production",
			CredentialExpiresAt: baseExpiry.Add(111 * time.Nanosecond),
		},
		{
			RevocationID: "10000000-0000-4000-8000-000000000011", Fence: fence, Issuer: "vault-production",
			CredentialExpiresAt: baseExpiry.Add(999 * time.Nanosecond),
		},
	}
	wantExpiry := time.UnixMicro(baseExpiry.UnixMicro()).UTC()
	start := make(chan struct{})
	results := make(chan PrepareResult, len(requests))
	errors := make(chan error, len(requests))
	for _, request := range requests {
		request := request
		go func() {
			<-start
			result, err := repository.Prepare(ctx, request)
			results <- result
			errors <- err
		}()
	}
	close(start)

	created := 0
	canonicalID := ""
	for range requests {
		if err := <-errors; err != nil {
			t.Fatalf("Prepare(nanosecond replay) error = %v", err)
		}
		result := <-results
		if result.Created {
			created++
		}
		if canonicalID == "" {
			canonicalID = result.Revocation.ID
		}
		if result.Revocation.ID != canonicalID || !result.Revocation.CredentialExpiresAt.Equal(wantExpiry) {
			t.Fatalf("Prepare(nanosecond replay) result = %#v, want expiry %s", result, wantExpiry)
		}
	}
	if created != 1 {
		t.Fatalf("Prepare(nanosecond replay) Created winners = %d, want 1", created)
	}
}

func TestMemoryPrepareRejectsReplayCandidateAlreadyBoundToAnotherAction(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 10, 11, 18, 0, 0, time.UTC)
	firstFence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token-one", Epoch: 2}
	secondFence := ActionFence{
		ActionID: "20000000-0000-4000-8000-000000000011", RunnerID: "runner-write-1", Token: "action-token-two", Epoch: 3,
	}
	secondID := "10000000-0000-4000-8000-000000000011"
	source := &fakeActionFenceSource{fences: map[ActionFence]ActionMetadata{
		firstFence:  activeActionMetadata(now, firstFence),
		secondFence: activeActionMetadata(now, secondFence),
	}}
	repository := newTestMemoryRepository(t, source, func() time.Time { return now }, sequenceTokens("unused"))
	firstRequest := PrepareRequest{
		RevocationID: testRevocationID, Fence: firstFence, Issuer: "vault-production", CredentialExpiresAt: now.Add(time.Minute),
	}
	if _, err := repository.Prepare(ctx, firstRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Prepare(ctx, PrepareRequest{
		RevocationID: secondID, Fence: secondFence, Issuer: "vault-production", CredentialExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	replay := firstRequest
	replay.RevocationID = secondID
	if _, err := repository.Prepare(ctx, replay); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Prepare(replay with occupied candidate ID) error = %v", err)
	}
}

func TestMemoryRecordAnchorIdempotencyNeverDecryptsStoredAccessor(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 10, 11, 20, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 2}
	source := &fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)}
	spy := newCountingReferenceProtector(t)
	repository, err := NewMemoryRepository(source, spy, MemoryRepositoryOptions{
		Clock: func() time.Time { return now }, TokenSource: sequenceTokens("unused"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Prepare(ctx, PrepareRequest{
		RevocationID: testRevocationID, Fence: fence, Issuer: "vault-production", CredentialExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	accessor, _ := NewSensitiveReference([]byte("idempotent-accessor"))
	defer accessor.Destroy()
	request := RecordAnchorRequest{RevocationID: testRevocationID, Fence: fence, Accessor: accessor}
	if _, err := repository.RecordAnchor(ctx, request); err != nil {
		t.Fatalf("RecordAnchor(first) error = %v", err)
	}
	if _, err := repository.RecordAnchor(ctx, request); err != nil {
		t.Fatalf("RecordAnchor(idempotent) error = %v", err)
	}
	if calls := spy.UnprotectCalls(); calls != 0 {
		t.Fatalf("RecordAnchor() Unprotect calls = %d, want 0", calls)
	}
}

func TestMemoryRecordAnchorPersistsFrozenFenceAfterLiveResolverExpires(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 10, 11, 25, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 2}
	source := &fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)}
	repository := newTestMemoryRepository(t, source, func() time.Time { return now }, sequenceTokens("unused"))
	if _, err := repository.Prepare(ctx, PrepareRequest{
		RevocationID: testRevocationID, Fence: fence, Issuer: "vault-production", CredentialExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	resolveCalls := source.ResolveCalls()
	source.resolveErr = ErrStaleActionFence
	source.metadata.LeaseExpiresAt = now.Add(-time.Second)
	accessor, _ := NewSensitiveReference([]byte("expired-action-accessor"))
	defer accessor.Destroy()

	anchored, err := repository.RecordAnchor(ctx, RecordAnchorRequest{
		RevocationID: testRevocationID, Fence: fence, Accessor: accessor,
	})
	if err != nil || anchored.Status != StatusRevocationPending || !anchored.AccessorPresent ||
		anchored.AnchoredAt.IsZero() || anchored.RevocationRequestedAt.IsZero() {
		t.Fatalf("RecordAnchor(expired live fence) = %#v, %v", anchored, err)
	}
	if calls := source.ResolveCalls(); calls != resolveCalls {
		t.Fatalf("RecordAnchor called bearer resolver: before=%d after=%d", resolveCalls, calls)
	}
}

func TestMemoryRecordAnchorImmediatelyRequestsWhenCredentialTTLHasElapsed(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 10, 11, 27, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 2}
	source := &fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)}
	repository := newTestMemoryRepository(t, source, func() time.Time { return now }, sequenceTokens("unused"))
	if _, err := repository.Prepare(ctx, PrepareRequest{
		RevocationID: testRevocationID, Fence: fence, Issuer: "vault-production",
		CredentialExpiresAt: now.Add(2 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(3 * time.Second)
	accessor, _ := NewSensitiveReference([]byte("elapsed-credential-accessor"))
	defer accessor.Destroy()
	anchored, err := repository.RecordAnchor(ctx, RecordAnchorRequest{
		RevocationID: testRevocationID, Fence: fence, Accessor: accessor,
	})
	if err != nil || anchored.Status != StatusRevocationPending {
		t.Fatalf("RecordAnchor(elapsed credential TTL) = %#v, %v", anchored, err)
	}
}

func TestMemoryRecordAnchorRechecksCommitWindowForNewAndIdempotentPaths(t *testing.T) {
	for _, idempotent := range []bool{false, true} {
		name := "new"
		if idempotent {
			name = "idempotent"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			base := time.Date(2026, 7, 10, 11, 28, 0, 0, time.UTC)
			fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 2}
			metadata := activeActionMetadata(base, fence)
			metadata.LeaseExpiresAt = base.Add(time.Minute)
			source := &fakeActionFenceSource{fence: fence, metadata: metadata}
			repository := newTestMemoryRepository(t, source, func() time.Time { return base }, sequenceTokens("unused"))
			if _, err := repository.Prepare(ctx, PrepareRequest{
				RevocationID: testRevocationID, Fence: fence, Issuer: "vault-production",
				CredentialExpiresAt: base.Add(10 * time.Minute),
			}); err != nil {
				t.Fatal(err)
			}
			accessor, _ := NewSensitiveReference([]byte("commit-window-accessor"))
			defer accessor.Destroy()
			request := RecordAnchorRequest{RevocationID: testRevocationID, Fence: fence, Accessor: accessor}
			if idempotent {
				if _, err := repository.RecordAnchor(ctx, request); err != nil {
					t.Fatal(err)
				}
			}
			repository.clock = sequenceTimes(base, base.Add(59*time.Second+500*time.Millisecond))

			anchored, err := repository.RecordAnchor(ctx, request)
			if err != nil || anchored.Status != StatusRevocationPending || !anchored.AccessorPresent ||
				anchored.RevocationRequestedAt.IsZero() {
				t.Fatalf("RecordAnchor(%s commit window) = %#v, %v", name, anchored, err)
			}
		})
	}
}

func TestMemoryActivateUsesFrozenInspectionAndRechecksCommitWindow(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 7, 10, 11, 29, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 2}
	metadata := activeActionMetadata(base, fence)
	metadata.LeaseExpiresAt = base.Add(time.Minute)
	source := &fakeActionFenceSource{fence: fence, metadata: metadata}
	repository := newTestMemoryRepository(t, source, func() time.Time { return base }, sequenceTokens("unused"))
	if _, err := repository.Prepare(ctx, PrepareRequest{
		RevocationID: testRevocationID, Fence: fence, Issuer: "vault-production",
		CredentialExpiresAt: base.Add(10 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	accessor, _ := NewSensitiveReference([]byte("activate-commit-window-accessor"))
	defer accessor.Destroy()
	if _, err := repository.RecordAnchor(ctx, RecordAnchorRequest{
		RevocationID: testRevocationID, Fence: fence, Accessor: accessor,
	}); err != nil {
		t.Fatal(err)
	}
	resolveCalls := source.ResolveCalls()
	source.resolveErr = ErrStaleActionFence
	repository.clock = sequenceTimes(base, base.Add(59*time.Second+500*time.Millisecond))

	activated, err := repository.Activate(ctx, ActionTransitionRequest{RevocationID: testRevocationID, Fence: fence})
	if err != nil || activated.Status != StatusRevocationPending || activated.RevocationRequestedAt.IsZero() {
		t.Fatalf("Activate(commit window elapsed) = %#v, %v", activated, err)
	}
	if calls := source.ResolveCalls(); calls != resolveCalls {
		t.Fatalf("Activate called bearer resolver: before=%d after=%d", resolveCalls, calls)
	}
}

func TestMemoryActivateImmediatelyRequestsWhenActionWasNacked(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 10, 11, 29, 30, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 2}
	source := &fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)}
	repository := newTestMemoryRepository(t, source, func() time.Time { return now }, sequenceTokens("unused"))
	if _, err := repository.Prepare(ctx, PrepareRequest{
		RevocationID: testRevocationID, Fence: fence, Issuer: "vault-production",
		CredentialExpiresAt: now.Add(10 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	accessor, _ := NewSensitiveReference([]byte("activate-nack-accessor"))
	defer accessor.Destroy()
	if _, err := repository.RecordAnchor(ctx, RecordAnchorRequest{
		RevocationID: testRevocationID, Fence: fence, Accessor: accessor,
	}); err != nil {
		t.Fatal(err)
	}
	source.resolveErr = ErrStaleActionFence
	source.metadata.Status = ActionStatusQueued
	source.metadata.RunnerID = ""
	source.metadata.LeaseExpiresAt = time.Time{}

	activated, err := repository.Activate(ctx, ActionTransitionRequest{RevocationID: testRevocationID, Fence: fence})
	if err != nil || activated.Status != StatusRevocationPending || activated.RevocationRequestedAt.IsZero() {
		t.Fatalf("Activate(after Nack) = %#v, %v", activated, err)
	}
}

func TestMemoryRevocationCanRequestAnchoredRecoveryWithoutPersistedActionBearer(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 10, 11, 30, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "short-lived-action-token", Epoch: 3}
	source := &fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)}
	repository := newTestMemoryRepository(t, source, func() time.Time { return now }, sequenceTokens("unused"))
	if _, err := repository.Prepare(ctx, PrepareRequest{
		RevocationID: testRevocationID, Fence: fence, Issuer: "vault-production", CredentialExpiresAt: now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	accessor, _ := NewSensitiveReference([]byte("crash-recovery-accessor"))
	if _, err := repository.RecordAnchor(ctx, RecordAnchorRequest{
		RevocationID: testRevocationID, Fence: fence, Accessor: accessor,
	}); err != nil {
		t.Fatal(err)
	}

	// Simulate a restart after the action lease and its plaintext bearer are gone.
	now = now.Add(2 * time.Minute)
	source.metadata.LeaseExpiresAt = now.Add(-time.Second)
	recovered, err := repository.RequestRevocation(ctx, ActionTransitionRequest{RevocationID: testRevocationID})
	if err != nil || recovered.Status != StatusRevocationPending {
		t.Fatalf("RequestRevocation(recovery) = %#v, %v", recovered, err)
	}
}

func TestMemoryRevocationRejectsMissingOrExpiredActionAuthorization(t *testing.T) {
	now := time.Date(2026, 7, 10, 11, 45, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4}
	for name, authorizationExpiry := range map[string]time.Time{
		"missing": {},
		"expired": now.Add(-time.Second),
	} {
		t.Run(name, func(t *testing.T) {
			metadata := activeActionMetadata(now, fence)
			metadata.AuthorizationExpiresAt = authorizationExpiry
			repository := newTestMemoryRepository(t, &fakeActionFenceSource{fence: fence, metadata: metadata},
				func() time.Time { return now }, sequenceTokens("unused"))
			_, err := repository.Prepare(context.Background(), PrepareRequest{
				RevocationID: testRevocationID, Fence: fence, Issuer: "vault-production", CredentialExpiresAt: now.Add(time.Minute),
			})
			if !errors.Is(err, ErrStaleActionFence) {
				t.Fatalf("Prepare(%s authorization) error = %v", name, err)
			}
		})
	}
	metadata := activeActionMetadata(now, fence)
	metadata.AuthorizationExpiresAt = now.Add(30 * time.Second)
	repository := newTestMemoryRepository(t, &fakeActionFenceSource{fence: fence, metadata: metadata},
		func() time.Time { return now }, sequenceTokens("unused"))
	_, err := repository.Prepare(context.Background(), PrepareRequest{
		RevocationID: testRevocationID, Fence: fence, Issuer: "vault-production",
		CredentialExpiresAt: metadata.AuthorizationExpiresAt.Add(time.Microsecond),
	})
	if !errors.Is(err, ErrInvalidRevocationRequest) {
		t.Fatalf("Prepare(expiry beyond authorization) error = %v", err)
	}
}

func TestMemoryPrepareRejectsCredentialTTLBeyondFifteenMinutes(t *testing.T) {
	now := time.Date(2026, 7, 10, 11, 50, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4}
	metadata := activeActionMetadata(now, fence)
	metadata.AuthorizationExpiresAt = now.Add(30 * time.Minute)
	repository := newTestMemoryRepository(t, &fakeActionFenceSource{fence: fence, metadata: metadata},
		func() time.Time { return now }, sequenceTokens("unused"))

	_, err := repository.Prepare(context.Background(), PrepareRequest{
		RevocationID: testRevocationID, Fence: fence, Issuer: "vault-production",
		CredentialExpiresAt: now.Add(MaxCredentialTTL + time.Microsecond),
	})
	if !errors.Is(err, ErrInvalidRevocationRequest) {
		t.Fatalf("Prepare(TTL beyond 15 minutes) error = %v", err)
	}
}

func TestMemoryPrepareRevalidatesOneSecondFenceWindowBeforeCreation(t *testing.T) {
	base := time.Date(2026, 7, 10, 11, 55, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4}
	metadata := activeActionMetadata(base, fence)
	metadata.LeaseExpiresAt = base.Add(2 * time.Second)
	metadata.AuthorizationExpiresAt = base.Add(2 * time.Second)
	repository := newTestMemoryRepository(t, &fakeActionFenceSource{fence: fence, metadata: metadata},
		sequenceTimes(base, base, base.Add(1500*time.Millisecond)), sequenceTokens("unused"))

	result, err := repository.Prepare(context.Background(), PrepareRequest{
		RevocationID: testRevocationID, Fence: fence, Issuer: "vault-production",
		CredentialExpiresAt: base.Add(1800 * time.Millisecond),
	})
	if !errors.Is(err, ErrStaleActionFence) || result.Created {
		t.Fatalf("Prepare(commit window elapsed) = %#v, %v", result, err)
	}
	listed, listErr := repository.List(context.Background(), ListFilter{WorkspaceID: testWorkspaceID, Limit: 10})
	if listErr != nil || len(listed) != 0 {
		t.Fatalf("List(after rejected Prepare) = %#v, %v", listed, listErr)
	}
}

func TestMemoryRecoverPreparedUsesFixedTTLGraceBoundaryAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 10, 11, 58, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4}
	source := &fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)}
	repository := newTestMemoryRepository(t, source, func() time.Time { return now }, sequenceTokens("unused"))
	prepared, err := repository.Prepare(ctx, PrepareRequest{
		RevocationID: testRevocationID, Fence: fence, Issuer: "vault-production",
		CredentialExpiresAt: now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	boundary := prepared.Revocation.CredentialExpiresAt.Add(PreparedRecoveryGrace)
	if oldMaximumBoundary := prepared.Revocation.CreatedAt.Add(MaxCredentialTTL + PreparedRecoveryGrace); !boundary.Before(oldMaximumBoundary) {
		t.Fatalf("short-TTL recovery boundary = %s, want before old maximum boundary %s", boundary, oldMaximumBoundary)
	}
	now = boundary.Add(-time.Nanosecond)
	before, err := repository.RecoverPrepared(ctx, RecoverPreparedRequest{Limit: 10})
	if err != nil || len(before) != 0 {
		t.Fatalf("RecoverPrepared(before boundary) = %#v, %v", before, err)
	}
	now = boundary
	recovered, err := repository.RecoverPrepared(ctx, RecoverPreparedRequest{Limit: 10})
	if err != nil || len(recovered) != 1 || recovered[0].ID != testRevocationID ||
		recovered[0].Status != StatusNoCredential || recovered[0].AccessorPresent {
		t.Fatalf("RecoverPrepared(at boundary) = %#v, %v", recovered, err)
	}
	replayed, err := repository.RecoverPrepared(ctx, RecoverPreparedRequest{Limit: 10})
	if err != nil || len(replayed) != 0 {
		t.Fatalf("RecoverPrepared(replay) = %#v, %v", replayed, err)
	}
}

func TestMemoryRecoverPreparedOrdersByAbsoluteDeadlineThenIDAndHonorsLimit(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 7, 10, 11, 59, 0, 0, time.UTC)
	now := base
	inputs := []struct {
		id     string
		fence  ActionFence
		expiry time.Time
	}{
		{
			id:     testRevocationID,
			fence:  ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token-1", Epoch: 1},
			expiry: base.Add(2 * time.Minute),
		},
		{
			id:     "10000000-0000-4000-8000-000000000011",
			fence:  ActionFence{ActionID: "20000000-0000-4000-8000-000000000011", RunnerID: "runner-write-1", Token: "action-token-2", Epoch: 1},
			expiry: base.Add(2 * time.Minute),
		},
		{
			id:     "10000000-0000-4000-8000-000000000012",
			fence:  ActionFence{ActionID: "20000000-0000-4000-8000-000000000012", RunnerID: "runner-write-1", Token: "action-token-3", Epoch: 1},
			expiry: base.Add(time.Minute),
		},
	}
	fences := make(map[ActionFence]ActionMetadata, len(inputs))
	for _, input := range inputs {
		fences[input.fence] = activeActionMetadata(base, input.fence)
	}
	repository := newTestMemoryRepository(t, &fakeActionFenceSource{fences: fences},
		func() time.Time { return now }, sequenceTokens("unused"))
	for _, input := range inputs {
		if _, err := repository.Prepare(ctx, PrepareRequest{
			RevocationID: input.id, Fence: input.fence, Issuer: "vault-production", CredentialExpiresAt: input.expiry,
		}); err != nil {
			t.Fatalf("Prepare(%s): %v", input.id, err)
		}
	}
	now = base.Add(4 * time.Minute)

	first, err := repository.RecoverPrepared(ctx, RecoverPreparedRequest{Limit: 2})
	if err != nil || len(first) != 2 || first[0].ID != inputs[2].id || first[1].ID != inputs[0].id {
		t.Fatalf("RecoverPrepared(first limited batch) = %#v, %v", first, err)
	}
	second, err := repository.RecoverPrepared(ctx, RecoverPreparedRequest{Limit: 2})
	if err != nil || len(second) != 1 || second[0].ID != inputs[1].id {
		t.Fatalf("RecoverPrepared(second limited batch) = %#v, %v", second, err)
	}
}

func TestMemoryRevocationExpiredClaimRequeuesWithNewEpochAndRetrySanitizesFailure(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 5}
	source := &fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)}
	repository := newTestMemoryRepository(t, source, func() time.Time { return now }, sequenceTokens("claim-one", "claim-two", "claim-three"))
	prepareActivePending(t, ctx, repository, now, fence, testRevocationID, "durable-accessor")

	firstClaims, err := repository.ClaimRevocations(ctx, ClaimRevocationsRequest{WorkerID: "revoker-a", Limit: 1, LeaseDuration: 10 * time.Second})
	if err != nil || len(firstClaims) != 1 {
		t.Fatalf("first claim = %#v, %v", firstClaims, err)
	}
	now = now.Add(11 * time.Second)
	secondClaims, err := repository.ClaimRevocations(ctx, ClaimRevocationsRequest{WorkerID: "revoker-b", Limit: 1, LeaseDuration: 10 * time.Second})
	if err != nil || len(secondClaims) != 1 {
		t.Fatalf("reclaim = %#v, %v", secondClaims, err)
	}
	if secondClaims[0].Fence.Epoch != 2 || secondClaims[0].Fence.Token == firstClaims[0].Fence.Token {
		t.Fatalf("reclaim fence = %#v, first = %#v", secondClaims[0].Fence, firstClaims[0].Fence)
	}
	if _, err := repository.Heartbeat(ctx, HeartbeatRequest{Fence: firstClaims[0].Fence, Extension: 10 * time.Second}); !errors.Is(err, ErrStaleClaim) {
		t.Fatalf("Heartbeat(old fence) error = %v", err)
	}

	upstreamBody := []byte("permission denied: secret response body must not persist")
	detailSum := sha256.Sum256(upstreamBody)
	retried, err := repository.RetryRevocation(ctx, RetryRevocationRequest{
		Fence: secondClaims[0].Fence, Delay: 45 * time.Second,
		FailureCode: FailureIssuerUnavailable, FailureDetail: upstreamBody,
	})
	if err != nil {
		t.Fatalf("RetryRevocation() error = %v", err)
	}
	if retried.Status != StatusRevocationPending || retried.FailureCode != FailureIssuerUnavailable ||
		retried.FailureDetailSHA256 != hex.EncodeToString(detailSum[:]) || !retried.AvailableAt.Equal(now.Add(45*time.Second)) {
		t.Fatalf("retried = %#v", retried)
	}
	retriedJSON, _ := json.Marshal(retried)
	if bytes.Contains(retriedJSON, upstreamBody) {
		t.Fatalf("retry record leaked upstream body: %s", retriedJSON)
	}
	if _, err := repository.ClaimRevocations(ctx, ClaimRevocationsRequest{WorkerID: "revoker-c", Limit: 1, LeaseDuration: 10 * time.Second}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(45 * time.Second)
	thirdClaims, err := repository.ClaimRevocations(ctx, ClaimRevocationsRequest{WorkerID: "revoker-c", Limit: 1, LeaseDuration: 10 * time.Second})
	if err != nil || len(thirdClaims) != 1 {
		t.Fatalf("claim after retry delay = %#v, %v", thirdClaims, err)
	}
	manual, err := repository.RequireManual(ctx, RequireManualRequest{
		Fence: thirdClaims[0].Fence, FailureCode: FailurePermissionDenied, FailureDetail: []byte("redacted permanent detail"),
	})
	if err != nil || manual.Status != StatusManualRequired {
		t.Fatalf("RequireManual() = %#v, %v", manual, err)
	}
	requeued, err := repository.RequeueManual(ctx, RequeueManualRequest{RevocationID: testRevocationID, ActorSubject: "oidc:platform-admin-1"})
	if err != nil || requeued.Status != StatusRevocationPending || !requeued.AvailableAt.Equal(now) {
		t.Fatalf("RequeueManual() = %#v, %v", requeued, err)
	}
}

func TestMemoryRevocationConcurrentClaimHasOneWinner(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 10, 13, 0, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 6}
	source := &fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)}
	repository := newTestMemoryRepository(t, source, func() time.Time { return now }, nil)
	prepareActivePending(t, ctx, repository, now, fence, testRevocationID, "concurrent-accessor")

	start := make(chan struct{})
	results := make(chan []ClaimedRevocation, 2)
	errorsByWorker := make(chan error, 2)
	var wait sync.WaitGroup
	for _, worker := range []string{"revoker-1", "revoker-2"} {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			claims, err := repository.ClaimRevocations(ctx, ClaimRevocationsRequest{WorkerID: worker, Limit: 1, LeaseDuration: 30 * time.Second})
			results <- claims
			errorsByWorker <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsByWorker)
	claimed := 0
	for claims := range results {
		claimed += len(claims)
	}
	for err := range errorsByWorker {
		if err != nil {
			t.Errorf("concurrent ClaimRevocations() error = %v", err)
		}
	}
	if claimed != 1 {
		t.Fatalf("concurrent claim winners = %d, want 1", claimed)
	}
}

func TestMemoryRevocationRequiresTwoDistinctMatchingExternalConfirmations(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 10, 14, 0, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 8}
	source := &fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)}
	repository := newTestMemoryRepository(t, source, func() time.Time { return now }, sequenceTokens("manual-claim"))
	prepareActivePending(t, ctx, repository, now, fence, testRevocationID, "manual-accessor")
	claims, _ := repository.ClaimRevocations(ctx, ClaimRevocationsRequest{WorkerID: "revoker", Limit: 1, LeaseDuration: 30 * time.Second})
	if _, err := repository.RequireManual(ctx, RequireManualRequest{
		Fence: claims[0].Fence, FailureCode: FailurePermissionDenied, FailureDetail: []byte("permanent"),
	}); err != nil {
		t.Fatal(err)
	}
	evidence := hex.EncodeToString(bytes.Repeat([]byte{0x91}, 32))
	if _, err := repository.SubmitExternalConfirmation(ctx, ExternalConfirmationRequest{
		RevocationID: testRevocationID, Subject: "raw-unscoped-subject", EvidenceHash: evidence,
	}); !errors.Is(err, ErrInvalidRevocationRequest) {
		t.Fatalf("non-OIDC confirmation subject error = %v", err)
	}

	first, err := repository.SubmitExternalConfirmation(ctx, ExternalConfirmationRequest{
		RevocationID: testRevocationID, Subject: "oidc:operator-1", EvidenceHash: evidence, PlatformAdmin: false,
	})
	if err != nil || first.Revocation.Status != StatusManualRequired || len(first.Confirmations) != 1 {
		t.Fatalf("first confirmation = %#v, %v", first, err)
	}
	duplicate, err := repository.SubmitExternalConfirmation(ctx, ExternalConfirmationRequest{
		RevocationID: testRevocationID, Subject: "oidc:operator-1", EvidenceHash: evidence, PlatformAdmin: false,
	})
	if err != nil || len(duplicate.Confirmations) != 1 || duplicate.Revocation.Status != StatusManualRequired {
		t.Fatalf("duplicate confirmation = %#v, %v", duplicate, err)
	}
	if _, err := repository.SubmitExternalConfirmation(ctx, ExternalConfirmationRequest{
		RevocationID: testRevocationID, Subject: "oidc:platform-admin", EvidenceHash: hex.EncodeToString(bytes.Repeat([]byte{0x92}, 32)), PlatformAdmin: true,
	}); !errors.Is(err, ErrEvidenceConflict) {
		t.Fatalf("mismatched evidence error = %v", err)
	}
	if _, err := repository.SubmitExternalConfirmation(ctx, ExternalConfirmationRequest{
		RevocationID: testRevocationID, Subject: "oidc:operator-2", EvidenceHash: evidence, PlatformAdmin: false,
	}); !errors.Is(err, ErrPlatformAdminRequired) {
		t.Fatalf("second non-admin error = %v", err)
	}
	second, err := repository.SubmitExternalConfirmation(ctx, ExternalConfirmationRequest{
		RevocationID: testRevocationID, Subject: "oidc:platform-admin", EvidenceHash: evidence, PlatformAdmin: true,
	})
	if err != nil || second.Revocation.Status != StatusRevoked || len(second.Confirmations) != 2 || second.Revocation.AccessorPresent {
		t.Fatalf("second confirmation = %#v, %v", second, err)
	}
	if second.Revocation.Version != first.Revocation.Version+1 {
		t.Fatalf("second confirmation version = %d, want %d", second.Revocation.Version, first.Revocation.Version+1)
	}
}

func prepareActivePending(t *testing.T, ctx context.Context, repository Repository, now time.Time, fence ActionFence, id, accessorValue string) {
	t.Helper()
	if _, err := repository.Prepare(ctx, PrepareRequest{
		RevocationID: id, Fence: fence, Issuer: "vault-production", CredentialExpiresAt: now.Add(10 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	accessor, err := NewSensitiveReference([]byte(accessorValue))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.RecordAnchor(ctx, RecordAnchorRequest{RevocationID: id, Fence: fence, Accessor: accessor}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Activate(ctx, ActionTransitionRequest{RevocationID: id, Fence: fence}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.RequestRevocation(ctx, ActionTransitionRequest{RevocationID: id, Fence: fence}); err != nil {
		t.Fatal(err)
	}
}

func newTestMemoryRepository(t *testing.T, source ActionFenceSource, clock func() time.Time, tokens func() (string, error)) *MemoryRepository {
	t.Helper()
	protector := testProtector(t, "memory-key", map[string]ProtectionKey{
		"memory-key": {
			EncryptionKey: bytes.Repeat([]byte{0x61}, 32),
			HMACKey:       bytes.Repeat([]byte{0x62}, 32),
		},
	})
	repository, err := NewMemoryRepository(source, protector, MemoryRepositoryOptions{Clock: clock, TokenSource: tokens})
	if err != nil {
		t.Fatalf("NewMemoryRepository() error = %v", err)
	}
	return repository
}

func activeActionMetadata(now time.Time, fence ActionFence) ActionMetadata {
	return ActionMetadata{
		ActionID: fence.ActionID, TenantID: testTenantID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironment,
		TargetKey: "cluster-a/payments", Production: true, RunnerID: fence.RunnerID, LeaseEpoch: fence.Epoch,
		Status: ActionStatusRunning, LeaseExpiresAt: now.Add(time.Minute), AuthorizationExpiresAt: now.Add(15 * time.Minute), ConnectorID: "kubernetes-prod",
		Permission: "PATCH_DEPLOYMENT_RESTART", Resource: "cluster-a/payments/deployment/api",
	}
}

type fakeActionFenceSource struct {
	mu           sync.Mutex
	fence        ActionFence
	metadata     ActionMetadata
	fences       map[ActionFence]ActionMetadata
	resolveErr   error
	resolveCalls int
	inspection   *ActionInspection
	inspectErr   error
	inspectCalls int
}

type countingReferenceProtector struct {
	delegate ReferenceProtector
	mu       sync.Mutex
	opens    int
}

func newCountingReferenceProtector(t *testing.T) *countingReferenceProtector {
	t.Helper()
	protector, err := NewAESGCMProtector(KeyRing{
		ActiveKeyID: "spy-key",
		Keys: map[string]ProtectionKey{
			"spy-key": {EncryptionKey: bytes.Repeat([]byte{0x81}, 32), HMACKey: bytes.Repeat([]byte{0x82}, 32)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(protector.Destroy)
	return &countingReferenceProtector{delegate: protector}
}

func (protector *countingReferenceProtector) Protect(ctx ReferenceContext, reference *SensitiveReference) (ProtectedReference, error) {
	return protector.delegate.Protect(ctx, reference)
}

func (protector *countingReferenceProtector) Matches(ctx ReferenceContext, protected ProtectedReference, reference *SensitiveReference) (bool, error) {
	return protector.delegate.Matches(ctx, protected, reference)
}

func (protector *countingReferenceProtector) Unprotect(ctx ReferenceContext, reference ProtectedReference) (*SensitiveReference, error) {
	protector.mu.Lock()
	protector.opens++
	protector.mu.Unlock()
	return protector.delegate.Unprotect(ctx, reference)
}

func (protector *countingReferenceProtector) UnprotectCalls() int {
	protector.mu.Lock()
	defer protector.mu.Unlock()
	return protector.opens
}

func (source *fakeActionFenceSource) ResolveActionFence(_ context.Context, fence ActionFence) (ActionMetadata, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.resolveCalls++
	if source.resolveErr != nil {
		return ActionMetadata{}, source.resolveErr
	}
	if metadata, ok := source.fences[fence]; ok {
		return metadata, nil
	}
	if fence != source.fence {
		return ActionMetadata{}, ErrStaleActionFence
	}
	return source.metadata, nil
}

func (source *fakeActionFenceSource) ResolveCalls() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.resolveCalls
}

func (source *fakeActionFenceSource) InspectAction(_ context.Context, actionID string) (ActionInspection, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.inspectCalls++
	if source.inspectErr != nil {
		return ActionInspection{}, source.inspectErr
	}
	if source.inspection != nil {
		return *source.inspection, nil
	}
	if source.metadata.ActionID == actionID {
		return ActionInspection{Metadata: source.metadata, LeaseTokenSHA256: SHA256Hex([]byte(source.fence.Token))}, nil
	}
	for fence, metadata := range source.fences {
		if metadata.ActionID == actionID {
			return ActionInspection{Metadata: metadata, LeaseTokenSHA256: SHA256Hex([]byte(fence.Token))}, nil
		}
	}
	return ActionInspection{}, ErrRevocationNotFound
}

func sequenceTokens(tokens ...string) func() (string, error) {
	var mu sync.Mutex
	index := 0
	return func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if index >= len(tokens) {
			return "", errors.New("token sequence exhausted")
		}
		token := tokens[index]
		index++
		return token, nil
	}
}

func sequenceTimes(values ...time.Time) func() time.Time {
	var mu sync.Mutex
	index := 0
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		if index >= len(values) {
			return values[len(values)-1]
		}
		value := values[index]
		index++
		return value
	}
}
