package credential

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMemoryCleanupInspectorReportsMissingActionEpoch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 3}
	repository := newTestMemoryRepository(t,
		&fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)},
		func() time.Time { return now }, sequenceTokens("unused"))

	present, terminal, err := repository.InspectCleanup(context.Background(), fence.ActionID, fence.Epoch)
	if err != nil || present || terminal {
		t.Fatalf("InspectCleanup() = (%t, %t, %v), want (false, false, nil)", present, terminal, err)
	}
}

func TestMemoryCleanupInspectorRequiresExactActionAndEpochPair(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 7, 11, 10, 2, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 31}
	metadata := activeActionMetadata(now, fence)
	metadata.Production = false
	repository := newTestMemoryRepository(t,
		&fakeActionFenceSource{fence: fence, metadata: metadata},
		func() time.Time { return now }, sequenceTokens("unused"))
	if _, err := repository.Prepare(ctx, PrepareRequest{
		RevocationID: testRevocationID, Fence: fence, Issuer: "vault-non-production", IssuerRevision: "rev-1",
		CredentialExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	for _, test := range []struct {
		name     string
		actionID string
		epoch    int64
	}{
		{name: "same action different epoch", actionID: fence.ActionID, epoch: fence.Epoch + 1},
		{name: "different valid action same epoch", actionID: "20000000-0000-4000-8000-000000000099", epoch: fence.Epoch},
	} {
		t.Run(test.name, func(t *testing.T) {
			present, terminal, err := repository.InspectCleanup(ctx, test.actionID, test.epoch)
			if err != nil || present || terminal {
				t.Fatalf("InspectCleanup(%s) = (%t, %t, %v), want (false, false, nil)",
					test.name, present, terminal, err)
			}
		})
	}
}

func TestMemoryCleanupInspectorTracksNonTerminalAndNoCredentialLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 7, 11, 10, 5, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4}
	metadata := activeActionMetadata(now, fence)
	metadata.Production = false
	repository := newTestMemoryRepository(t,
		&fakeActionFenceSource{fence: fence, metadata: metadata},
		func() time.Time { return now }, sequenceTokens("unused"))

	if _, err := repository.Prepare(ctx, PrepareRequest{
		RevocationID: testRevocationID, Fence: fence, Issuer: "vault-non-production", IssuerRevision: "rev-1",
		CredentialExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	present, terminal, err := repository.InspectCleanup(ctx, fence.ActionID, fence.Epoch)
	if err != nil || !present || terminal {
		t.Fatalf("InspectCleanup(PREPARED) = (%t, %t, %v), want (true, false, nil)", present, terminal, err)
	}

	if _, err := repository.RecordNoCredential(ctx, ActionTransitionRequest{RevocationID: testRevocationID, Fence: fence}); err != nil {
		t.Fatalf("RecordNoCredential() error = %v", err)
	}
	present, terminal, err = repository.InspectCleanup(ctx, fence.ActionID, fence.Epoch)
	if err != nil || !present || !terminal {
		t.Fatalf("InspectCleanup(NO_CREDENTIAL) = (%t, %t, %v), want (true, true, nil)", present, terminal, err)
	}
}

func TestMemoryCleanupInspectorKeepsEveryRevocationWorkStateNonTerminal(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 7, 11, 10, 7, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 32}
	metadata := activeActionMetadata(now, fence)
	metadata.Production = false
	repository := newTestMemoryRepository(t,
		&fakeActionFenceSource{fence: fence, metadata: metadata},
		func() time.Time { return now }, sequenceTokens("revocation-claim-token"))

	prepared, err := repository.Prepare(ctx, PrepareRequest{
		RevocationID: testRevocationID, Fence: fence, Issuer: "vault-non-production", IssuerRevision: "rev-1",
		CredentialExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	assertMemoryCleanupNonTerminal(t, ctx, repository, fence, StatusPrepared)

	authorizePrepared(t, ctx, repository, prepared, fence)
	accessor, err := NewSensitiveReference([]byte("vault-accessor"))
	if err != nil {
		t.Fatalf("NewSensitiveReference() error = %v", err)
	}
	defer accessor.Destroy()
	if _, err := repository.RecordAnchor(ctx, RecordAnchorRequest{
		RevocationID: testRevocationID, Fence: fence, Accessor: accessor,
	}); err != nil {
		t.Fatalf("RecordAnchor() error = %v", err)
	}
	assertMemoryCleanupNonTerminal(t, ctx, repository, fence, StatusAnchored)

	if _, err := repository.Activate(ctx, ActionTransitionRequest{RevocationID: testRevocationID, Fence: fence}); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	assertMemoryCleanupNonTerminal(t, ctx, repository, fence, StatusActive)

	if _, err := repository.RequestRevocation(ctx, ActionTransitionRequest{RevocationID: testRevocationID, Fence: fence}); err != nil {
		t.Fatalf("RequestRevocation() error = %v", err)
	}
	assertMemoryCleanupNonTerminal(t, ctx, repository, fence, StatusRevocationPending)

	claims, err := repository.ClaimRevocations(ctx, ClaimRevocationsRequest{
		WorkerID: "revoker-1", Limit: 1, LeaseDuration: RevocationClaimLease,
	})
	if err != nil || len(claims) != 1 {
		t.Fatalf("ClaimRevocations() = %#v, %v", claims, err)
	}
	assertMemoryCleanupNonTerminal(t, ctx, repository, fence, StatusRevoking)

	if _, err := repository.RequireManual(ctx, RequireManualRequest{
		Fence: claims[0].Fence, FailureCode: FailureUnknown, FailureDetail: []byte("manual intervention required"),
	}); err != nil {
		t.Fatalf("RequireManual() error = %v", err)
	}
	assertMemoryCleanupNonTerminal(t, ctx, repository, fence, StatusManualRequired)
}

func TestMemoryCleanupInspectorReportsCompletedRevocationTerminal(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 7, 11, 10, 10, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 5}
	metadata := activeActionMetadata(now, fence)
	metadata.Production = false
	repository := newTestMemoryRepository(t,
		&fakeActionFenceSource{fence: fence, metadata: metadata},
		func() time.Time { return now }, sequenceTokens("revocation-claim-token"))
	prepareActivePending(t, ctx, repository, now, fence, testRevocationID, "vault-accessor")
	claims, err := repository.ClaimRevocations(ctx, ClaimRevocationsRequest{
		WorkerID: "revoker-1", Limit: 1, LeaseDuration: RevocationClaimLease,
	})
	if err != nil || len(claims) != 1 {
		t.Fatalf("ClaimRevocations() = %#v, %v", claims, err)
	}
	if _, err := repository.CompleteRevocation(ctx, CompleteRevocationRequest{Fence: claims[0].Fence}); err != nil {
		t.Fatalf("CompleteRevocation() error = %v", err)
	}

	present, terminal, err := repository.InspectCleanup(ctx, fence.ActionID, fence.Epoch)
	if err != nil || !present || !terminal {
		t.Fatalf("InspectCleanup(REVOKED) = (%t, %t, %v), want (true, true, nil)", present, terminal, err)
	}
}

func TestMemoryCleanupInspectorValidatesFenceIdentityAndPreservesContextError(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 11, 10, 15, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 6}
	repository := newTestMemoryRepository(t,
		&fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)},
		func() time.Time { return now }, sequenceTokens("unused"))

	for _, test := range []struct {
		name     string
		actionID string
		epoch    int64
	}{
		{name: "empty action", actionID: "", epoch: 1},
		{name: "invalid action", actionID: " action", epoch: 1},
		{name: "zero epoch", actionID: testActionID, epoch: 0},
		{name: "negative epoch", actionID: testActionID, epoch: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			present, terminal, err := repository.InspectCleanup(context.Background(), test.actionID, test.epoch)
			if !errors.Is(err, ErrInvalidRevocationRequest) || present || terminal {
				t.Fatalf("InspectCleanup() = (%t, %t, %v), want invalid request", present, terminal, err)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	present, terminal, err := repository.InspectCleanup(ctx, fence.ActionID, fence.Epoch)
	if err != context.Canceled || present || terminal {
		t.Fatalf("InspectCleanup(canceled) = (%t, %t, %v), want context.Canceled", present, terminal, err)
	}
}

func TestMemoryCleanupInspectorWrapsInconsistentStorageWithoutLeakingIdentifier(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 11, 10, 20, 0, 0, time.UTC)
	fence := ActionFence{ActionID: testActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 7}
	repository := newTestMemoryRepository(t,
		&fakeActionFenceSource{fence: fence, metadata: activeActionMetadata(now, fence)},
		func() time.Time { return now }, sequenceTokens("unused"))
	const missingRevocationID = "10000000-0000-4000-8000-000000000099"
	repository.actionEpochs[actionEpochKey(fence.ActionID, fence.Epoch)] = missingRevocationID

	present, terminal, err := repository.InspectCleanup(context.Background(), fence.ActionID, fence.Epoch)
	if !errors.Is(err, ErrRevocationPersistence) || present || terminal {
		t.Fatalf("InspectCleanup(inconsistent storage) = (%t, %t, %v), want safe persistence error", present, terminal, err)
	}
	if strings.Contains(err.Error(), missingRevocationID) {
		t.Fatalf("InspectCleanup(inconsistent storage) leaked identifier: %v", err)
	}
}

func assertMemoryCleanupNonTerminal(
	t *testing.T,
	ctx context.Context,
	repository *MemoryRepository,
	fence ActionFence,
	wantStatus RevocationStatus,
) {
	t.Helper()
	revocation, err := repository.Get(ctx, testRevocationID)
	if err != nil || revocation.Status != wantStatus {
		t.Fatalf("Get() = %#v, %v, want status %s", revocation, err, wantStatus)
	}
	present, terminal, err := repository.InspectCleanup(ctx, fence.ActionID, fence.Epoch)
	if err != nil || !present || terminal {
		t.Fatalf("InspectCleanup(%s) = (%t, %t, %v), want (true, false, nil)",
			wantStatus, present, terminal, err)
	}
}
