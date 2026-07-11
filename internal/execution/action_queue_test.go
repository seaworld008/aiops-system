package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
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
		EnvironmentRevision: "environment-1", Production: false, Pool: executionlease.PoolWrite,
	})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}

	envelope.Target.KubernetesDeployment.Name = "mutated-after-submit"
	envelope.Risk.ReasonCodes[0] = "MUTATED"
	claimed, err := queue.Claim(context.Background(), ActionClaimRequest{
		Scope:         testRunnerScope(t, "runner-1", RunnerScopeBinding{WorkspaceID: "workspace-1", EnvironmentID: "PROD"}),
		LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if claimed.Execution.ExecutionID != "action-restart" || claimed.Execution.Status != executionlease.StatusLeased {
		t.Fatalf("Claim() execution = %#v", claimed.Execution)
	}
	if claimed.PlanHash != claimed.Envelope.PlanHash || claimed.TargetKey != targetKey || claimed.EnvironmentRevision != "environment-1" || claimed.Production {
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
		EnvironmentRevision: "environment-1", Production: false, Pool: executionlease.PoolWrite,
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

func TestMemoryActionQueueIdempotencyKeyReturnsOriginalOrConflictsByRequestSemantics(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	first, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return now })
	firstExecution := submitAction(t, queue, first, "environment-1", false)

	retryUnsigned := restartEnvelope(now)
	retryUnsigned.ActionID = "action-semantic-idempotency-retry"
	retryUnsigned.TraceID = strings.Repeat("b", 32)
	retry, _ := signedEnvelope(t, retryUnsigned)
	retried, err := queue.Submit(context.Background(), ActionSubmission{
		Envelope: retry, PlanHash: retry.PlanHash,
		TargetKey: firstExecution.TargetKey, EnvironmentRevision: "environment-1",
		Production: false, Pool: executionlease.PoolWrite,
	})
	if err != nil || retried.ExecutionID != firstExecution.ExecutionID {
		t.Fatalf("Submit(same semantics with new action identity) = %#v, %v", retried, err)
	}

	conflictingUnsigned := restartEnvelope(now)
	conflictingUnsigned.ActionID = "action-conflicting-idempotency"
	conflictingUnsigned.Parameters.KubernetesRolloutRestart.Reason = "different request semantics"
	conflicting, _ := signedEnvelope(t, conflictingUnsigned)
	_, err = queue.Submit(context.Background(), ActionSubmission{
		Envelope: conflicting, PlanHash: conflicting.PlanHash,
		TargetKey: firstExecution.TargetKey, EnvironmentRevision: "environment-1",
		Production: false, Pool: executionlease.PoolWrite,
	})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Submit(same idempotency key, different request) error = %v, want %v", err, ErrIdempotencyConflict)
	}
}

func TestMemoryActionQueueSameActionIDAllowsValidResignWithSameSemantics(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	unsigned := restartEnvelope(now)
	first, _ := signedEnvelope(t, unsigned)
	resigned, _ := signedEnvelope(t, unsigned)
	if first.Signature.Value == resigned.Signature.Value {
		t.Fatal("test setup produced identical signatures")
	}
	queue := mustMemoryActionQueue(t, func() time.Time { return now })
	original := submitAction(t, queue, first, "environment-1", false)
	retried, err := queue.Submit(context.Background(), ActionSubmission{
		Envelope: resigned, PlanHash: resigned.PlanHash, TargetKey: original.TargetKey,
		EnvironmentRevision: "environment-1", Production: false, Pool: executionlease.PoolWrite,
	})
	if err != nil || retried.ExecutionID != original.ExecutionID {
		t.Fatalf("Submit(valid resign) = %#v, %v; want original execution", retried, err)
	}
}

func TestMemoryActionQueueFiltersRunnerScopeBeforeClaiming(t *testing.T) {
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
			EnvironmentRevision: "environment-1", Production: false, Pool: executionlease.PoolWrite,
		}); err != nil {
			t.Fatalf("Submit(%s) error = %v", envelope.ActionID, err)
		}
	}

	claimed, err := queue.Claim(context.Background(), ActionClaimRequest{
		Scope:         testRunnerScope(t, "runner-prod", RunnerScopeBinding{WorkspaceID: "workspace-1", EnvironmentID: "PROD"}),
		LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if claimed.Envelope.ActionID != "action-production" {
		t.Fatalf("Claim() action id = %q, want action-production", claimed.Envelope.ActionID)
	}
}

func TestMemoryActionQueueRunnerScopeAuthorizesExactWorkspaceEnvironmentPairs(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	unauthorizedUnsigned := restartEnvelope(now)
	unauthorizedUnsigned.ActionID = "action-cross-product"
	unauthorizedUnsigned.IdempotencyKey = "idem-action-cross-product"
	unauthorizedUnsigned.Target.EnvironmentID = "STAGING"
	unauthorized, _ := signedEnvelope(t, unauthorizedUnsigned)
	authorizedUnsigned := restartEnvelope(now)
	authorizedUnsigned.ActionID = "action-authorized-pair"
	authorizedUnsigned.IdempotencyKey = "idem-action-authorized-pair"
	authorizedUnsigned.Target.KubernetesDeployment.Name = "payments-worker"
	authorizedUnsigned.Target.KubernetesDeployment.UID = "uid-authorized"
	authorizedUnsigned.CredentialScope.Resource = "cluster-a/payments/deployment/payments-worker"
	authorized, _ := signedEnvelope(t, authorizedUnsigned)
	queue := mustMemoryActionQueue(t, func() time.Time { return now })
	for _, envelope := range []action.Envelope{unauthorized, authorized} {
		submitAction(t, queue, envelope, "environment-1", false)
	}

	registration := RunnerRegistration{
		RunnerID: "runner-exact-pairs", TenantID: "tenant-1", Pool: executionlease.PoolWrite, Enabled: true, ScopeRevision: 7, MaxConcurrency: 1,
		ScopeBindings: []RunnerScopeBinding{
			{WorkspaceID: "workspace-1", EnvironmentID: "PROD"},
			{WorkspaceID: "workspace-2", EnvironmentID: "STAGING"},
		},
	}
	scope, err := registration.Scope()
	if err != nil {
		t.Fatalf("RunnerRegistration.Scope() error = %v", err)
	}
	claimed, err := queue.Claim(context.Background(), ActionClaimRequest{Scope: scope, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if claimed.Execution.ExecutionID != authorized.ActionID {
		t.Fatalf("Claim() execution = %q, want exact authorized pair %q", claimed.Execution.ExecutionID, authorized.ActionID)
	}
	if claimed.Execution.ScopeRevision != registration.ScopeRevision {
		t.Fatalf("Claim() scope revision = %d, want %d", claimed.Execution.ScopeRevision, registration.ScopeRevision)
	}
	if claimed.Execution.RunnerTenantID != registration.TenantID || claimed.Execution.RunnerWorkspaceID != "workspace-1" ||
		claimed.Execution.RunnerEnvironmentID != "PROD" {
		t.Fatalf("Claim() runner scope identity = %#v", claimed.Execution)
	}
}

func TestMemoryActionQueueRunnerMaxConcurrencyBlocksSecondLease(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	firstEnvelope, _ := signedEnvelope(t, restartEnvelope(now))
	secondUnsigned := restartEnvelope(now)
	secondUnsigned.ActionID = "action-runner-concurrency-2"
	secondUnsigned.IdempotencyKey = "idem-runner-concurrency-2"
	secondUnsigned.Target.KubernetesDeployment.Name = "payments-worker"
	secondUnsigned.Target.KubernetesDeployment.UID = "uid-runner-concurrency-2"
	secondUnsigned.CredentialScope.Resource = "cluster-a/payments/deployment/payments-worker"
	secondEnvelope, _ := signedEnvelope(t, secondUnsigned)
	queue := mustMemoryActionQueue(t, func() time.Time { return now })
	submitAction(t, queue, firstEnvelope, "environment-1", false)
	submitAction(t, queue, secondEnvelope, "environment-1", false)
	scope, err := (RunnerRegistration{
		RunnerID: "runner-concurrency", TenantID: "tenant-test", Pool: executionlease.PoolWrite, Enabled: true,
		ScopeRevision: 1, MaxConcurrency: 1,
		ScopeBindings: []RunnerScopeBinding{{WorkspaceID: "workspace-1", EnvironmentID: "PROD"}},
	}).Scope()
	if err != nil {
		t.Fatalf("RunnerRegistration.Scope() error = %v", err)
	}
	first, err := queue.Claim(context.Background(), ActionClaimRequest{Scope: scope, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatalf("Claim(first) error = %v", err)
	}
	if _, err := queue.Claim(context.Background(), ActionClaimRequest{Scope: scope, LeaseDuration: time.Minute}); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("Claim(over max concurrency) error = %v, want %v", err, executionlease.ErrNoLeaseAvailable)
	}
	if _, err := queue.Cancel(context.Background(), first.Execution.ExecutionID); err != nil {
		t.Fatalf("Cancel(first) error = %v", err)
	}
	if _, err := queue.Claim(context.Background(), ActionClaimRequest{Scope: scope, LeaseDuration: time.Minute}); err != nil {
		t.Fatalf("Claim(after slot release) error = %v", err)
	}
}

func TestMemoryActionQueuePermanentlyRejectsPoisonedPreStartAction(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return now })
	submitAction(t, queue, envelope, "environment-1", false)
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
		Scope:         testRunnerScope(t, "runner-2", RunnerScopeBinding{WorkspaceID: "workspace-1", EnvironmentID: "PROD"}),
		LeaseDuration: time.Minute,
	}); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("poisoned action was redelivered: %v", err)
	}
}

func TestMemoryActionQueueRejectConsumesFenceAndKeepsOnlyTokenHashForIdempotency(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return now })
	submitted := submitAction(t, queue, envelope, "environment-1", false)
	claimed := claimAction(t, queue, "runner-1", []string{"workspace-1"}, []string{"PROD"})
	fence := claimed.Execution.Fence()
	reason := ActionQueueReason{Code: "INVALID_VERIFIED_ACTION", DetailHash: strings.Repeat("a", 64)}

	rejected, err := queue.Reject(context.Background(), ActionRejectRequest{Lease: fence, Reason: reason})
	if err != nil {
		t.Fatalf("Reject() error = %v", err)
	}
	if rejected.Status != executionlease.StatusFailed || rejected.LeaseToken != "" {
		t.Fatalf("Reject() = %#v", rejected)
	}

	queue.mu.Lock()
	record := queue.records[submitted.ExecutionID]
	queue.mu.Unlock()
	if record.execution.LeaseToken != "" {
		t.Fatalf("stored plaintext lease token = %q, want empty", record.execution.LeaseToken)
	}
	if record.completedTokenHash != hashLeaseToken(fence.Token) || record.completedEpoch != fence.Epoch {
		t.Fatalf("stored completion fence = (%q, %d), want (%q, %d)",
			record.completedTokenHash, record.completedEpoch, hashLeaseToken(fence.Token), fence.Epoch)
	}

	if _, err := queue.Reject(context.Background(), ActionRejectRequest{Lease: fence, Reason: reason}); err != nil {
		t.Fatalf("Reject(idempotent replay) error = %v", err)
	}
	differentReason := reason
	differentReason.DetailHash = strings.Repeat("b", 64)
	if _, err := queue.Reject(context.Background(), ActionRejectRequest{Lease: fence, Reason: differentReason}); !errors.Is(err, executionlease.ErrCompletionConflict) {
		t.Fatalf("Reject(conflicting replay) error = %v, want %v", err, executionlease.ErrCompletionConflict)
	}
	wrongToken := fence
	wrongToken.Token = "wrong-token"
	if _, err := queue.Reject(context.Background(), ActionRejectRequest{Lease: wrongToken, Reason: reason}); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("Reject(stale replay) error = %v, want %v", err, executionlease.ErrStaleLease)
	}
}

func TestMemoryActionQueueNackUsesFencedBackoffBeforeRedelivery(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return clock })
	submitAction(t, queue, envelope, "environment-1", false)
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
		Scope:         testRunnerScope(t, "runner-2", RunnerScopeBinding{WorkspaceID: "workspace-1", EnvironmentID: "PROD"}),
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
	submitAction(t, queue, envelope, "environment-1", false)
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
	if _, err := queue.Heartbeat(context.Background(), ActionHeartbeatRequest{
		Lease: stale, Sequence: 1, Extension: time.Minute,
	}); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("stale Heartbeat() error = %v, want stale lease", err)
	}
	clock = clock.Add(10 * time.Second)
	heartbeated, err := queue.Heartbeat(context.Background(), ActionHeartbeatRequest{
		Lease: fence, Sequence: 1, Extension: time.Minute,
	})
	if err != nil || !heartbeated.Execution.LeaseExpiresAt.Equal(clock.Add(time.Minute)) {
		t.Fatalf("Heartbeat() = %#v, %v", heartbeated, err)
	}
	if heartbeated.Execution.LeaseToken != "" {
		t.Fatalf("Heartbeat() leaked lease token %q", heartbeated.Execution.LeaseToken)
	}
	finalizing, err := queue.Complete(context.Background(), ActionCompleteRequest{
		Lease: fence, Summary: ExecutorResult{Outcome: ExecutorSucceeded, Code: "COMPLETED", Verification: VerificationPassed},
	})
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	completed, err := queue.Finalize(context.Background(), fence)
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if completed.Status != executionlease.StatusSucceeded || completed.LeaseToken != "" {
		t.Fatalf("Complete()/Finalize() = %#v then %#v", finalizing, completed)
	}
}

func TestMemoryActionQueueHeartbeatSequenceRejectsReplayWithoutExtendingLease(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return clock })
	submitAction(t, queue, envelope, "environment-1", false)
	claimed := claimAction(t, queue, "runner-sequenced", []string{"workspace-1"}, []string{"PROD"})
	if _, err := queue.Start(context.Background(), claimed.Execution.Fence()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := queue.Heartbeat(context.Background(), ActionHeartbeatRequest{
		Lease: claimed.Execution.Fence(), Sequence: 0, Extension: time.Minute,
	}); !errors.Is(err, ErrHeartbeatSequence) {
		t.Fatalf("Heartbeat(initial seq=0) error = %v, want %v", err, ErrHeartbeatSequence)
	}

	clock = clock.Add(10 * time.Second)
	first, err := queue.Heartbeat(context.Background(), ActionHeartbeatRequest{
		Lease: claimed.Execution.Fence(), Sequence: 1, Extension: time.Minute,
	})
	if err != nil || first.Directive != HeartbeatContinue || first.Execution.HeartbeatSeq != 1 {
		t.Fatalf("Heartbeat(seq=1) = %#v, %v", first, err)
	}
	firstExpiry := first.Execution.LeaseExpiresAt
	clock = clock.Add(10 * time.Second)
	replayed, err := queue.Heartbeat(context.Background(), ActionHeartbeatRequest{
		Lease: claimed.Execution.Fence(), Sequence: 1, Extension: time.Minute,
	})
	if err != nil || !replayed.Execution.LeaseExpiresAt.Equal(firstExpiry) {
		t.Fatalf("Heartbeat(replay seq=1) = %#v, %v; expiry changed from %s", replayed, err, firstExpiry)
	}
	for _, sequence := range []int64{0, 3} {
		if _, err := queue.Heartbeat(context.Background(), ActionHeartbeatRequest{
			Lease: claimed.Execution.Fence(), Sequence: sequence, Extension: time.Minute,
		}); !errors.Is(err, ErrHeartbeatSequence) {
			t.Fatalf("Heartbeat(seq=%d) error = %v, want %v", sequence, err, ErrHeartbeatSequence)
		}
	}
}

func TestMemoryActionQueueReclaimResetsHeartbeatSequenceForNewEpoch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return clock })
	submitAction(t, queue, envelope, "environment-1", false)
	first := claimAction(t, queue, "runner-first-epoch", []string{"workspace-1"}, []string{"PROD"})
	if _, err := queue.Heartbeat(context.Background(), ActionHeartbeatRequest{
		Lease: first.Execution.Fence(), Sequence: 1, Extension: time.Minute,
	}); err != nil {
		t.Fatalf("Heartbeat(first epoch) error = %v", err)
	}

	clock = clock.Add(2 * time.Minute)
	second := claimAction(t, queue, "runner-second-epoch", []string{"workspace-1"}, []string{"PROD"})
	if second.Execution.LeaseEpoch != first.Execution.LeaseEpoch+1 || second.Execution.HeartbeatSeq != 0 {
		t.Fatalf("reclaimed execution = %#v", second.Execution)
	}
	secondExpiry := second.Execution.LeaseExpiresAt
	clock = clock.Add(10 * time.Second)
	heartbeat, err := queue.Heartbeat(context.Background(), ActionHeartbeatRequest{
		Lease: second.Execution.Fence(), Sequence: 1, Extension: time.Minute,
	})
	if err != nil || !heartbeat.Execution.LeaseExpiresAt.After(secondExpiry) {
		t.Fatalf("Heartbeat(new epoch seq=1) = %#v, %v; old expiry %s", heartbeat, err, secondExpiry)
	}
}

func TestMemoryActionQueueHeartbeatTerminatesWithoutExtensionAtAuthorizationExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return clock })
	submitAction(t, queue, envelope, "environment-1", false)
	clock = clock.Add(10 * time.Minute)
	scope := testRunnerScope(t, "runner-expired-authorization", RunnerScopeBinding{WorkspaceID: "workspace-1", EnvironmentID: "PROD"})
	claimed, err := queue.Claim(context.Background(), ActionClaimRequest{Scope: scope, LeaseDuration: 30 * time.Minute})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if _, err := queue.Start(context.Background(), claimed.Execution.Fence()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	originalExpiry := claimed.Execution.LeaseExpiresAt
	clock = envelope.ExpiresAt
	heartbeat, err := queue.Heartbeat(context.Background(), ActionHeartbeatRequest{
		Lease: claimed.Execution.Fence(), Sequence: 1, Extension: 5 * time.Minute,
	})
	if err != nil || heartbeat.Directive != HeartbeatTerminate || !heartbeat.Execution.LeaseExpiresAt.Equal(originalExpiry) {
		t.Fatalf("Heartbeat(at authorization expiry) = %#v, %v; want TERMINATE and expiry %s", heartbeat, err, originalExpiry)
	}
}

func TestMemoryActionQueueClaimSkipsExpiredQueuedCandidateWithoutReleasingItsIdentity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	expiredUnsigned := restartEnvelope(now)
	expiredUnsigned.ExpiresAt = now.Add(2 * time.Minute)
	expiredUnsigned.CredentialScope.TTLSeconds = 60
	expired, _ := signedEnvelope(t, expiredUnsigned)
	validUnsigned := restartEnvelope(now)
	validUnsigned.ActionID = "action-valid-after-expired"
	validUnsigned.IdempotencyKey = "idem-valid-after-expired"
	valid, _ := signedEnvelope(t, validUnsigned)
	queue := mustMemoryActionQueue(t, func() time.Time { return clock })
	expiredExecution := submitAction(t, queue, expired, "environment-1", false)
	submitAction(t, queue, valid, "environment-1", false)
	clock = expired.ExpiresAt

	claimed := claimAction(t, queue, "runner-skip-expired", []string{"workspace-1"}, []string{"PROD"})
	if claimed.Execution.ExecutionID != valid.ActionID {
		t.Fatalf("Claim() execution = %q, want valid candidate %q", claimed.Execution.ExecutionID, valid.ActionID)
	}
	storedExpired, err := queue.Get(context.Background(), expired.ActionID)
	if err != nil || storedExpired.Status != executionlease.StatusQueued {
		t.Fatalf("Get(expired queued) = %#v, %v; want retained QUEUED record", storedExpired, err)
	}
	retried := submitAction(t, queue, expired, "environment-1", false)
	if retried.ExecutionID != expiredExecution.ExecutionID || retried.Status != executionlease.StatusQueued {
		t.Fatalf("Submit(expired retry) = %#v, want original %#v", retried, expiredExecution)
	}
}

func TestMemoryActionQueueClaimCapsInitialLeaseAtAuthorizationExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return clock })
	submitAction(t, queue, envelope, "environment-1", false)
	clock = envelope.ExpiresAt.Add(-time.Minute)
	claimed, err := queue.Claim(context.Background(), ActionClaimRequest{
		Scope:         testRunnerScope(t, "runner-short-authorization", RunnerScopeBinding{WorkspaceID: "workspace-1", EnvironmentID: "PROD"}),
		LeaseDuration: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if !claimed.Execution.LeaseExpiresAt.Equal(envelope.ExpiresAt) {
		t.Fatalf("Claim() lease expiry = %s, want authorization cap %s", claimed.Execution.LeaseExpiresAt, envelope.ExpiresAt)
	}
}

func TestMemoryActionQueueClaimRechecksAuthorizationAfterSlowTokenSource(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	tokenCalls := 0
	queue, err := NewMemoryActionQueue(MemoryActionQueueOptions{
		Clock: func() time.Time { return clock },
		TokenSource: func() (string, error) {
			tokenCalls++
			if tokenCalls == 1 {
				clock = now.Add(3 * time.Minute)
			}
			return fmt.Sprintf("queue-lease-token-%d", tokenCalls), nil
		},
	})
	if err != nil {
		t.Fatalf("NewMemoryActionQueue() error = %v", err)
	}
	expiringUnsigned := restartEnvelope(now)
	expiringUnsigned.ExpiresAt = now.Add(2 * time.Minute)
	expiringUnsigned.CredentialScope.TTLSeconds = 60
	expiring, _ := signedEnvelope(t, expiringUnsigned)
	validUnsigned := restartEnvelope(now)
	validUnsigned.ActionID = "action-valid-after-slow-token"
	validUnsigned.IdempotencyKey = "idem-valid-after-slow-token"
	valid, _ := signedEnvelope(t, validUnsigned)
	submitAction(t, queue, expiring, "environment-1", false)
	submitAction(t, queue, valid, "environment-1", false)

	claimed, err := queue.Claim(context.Background(), ActionClaimRequest{
		Scope:         testRunnerScope(t, "runner-slow-token", RunnerScopeBinding{WorkspaceID: "workspace-1", EnvironmentID: "PROD"}),
		LeaseDuration: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if claimed.Execution.ExecutionID != valid.ActionID || tokenCalls != 2 || !claimed.Execution.LeaseAcquiredAt.Equal(clock) {
		t.Fatalf("Claim(slow token) = %#v, token calls=%d, want valid action acquired at %s", claimed.Execution, tokenCalls, clock)
	}
	storedExpiring, err := queue.Get(context.Background(), expiring.ActionID)
	if err != nil || storedExpiring.Status != executionlease.StatusQueued {
		t.Fatalf("Get(expired during token generation) = %#v, %v", storedExpiring, err)
	}
}

func TestMemoryActionQueueHeartbeatCapsExtensionAtAuthorizationExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return clock })
	submitAction(t, queue, envelope, "environment-1", false)
	clock = clock.Add(10 * time.Minute)
	scope := testRunnerScope(t, "runner-capped-authorization", RunnerScopeBinding{WorkspaceID: "workspace-1", EnvironmentID: "PROD"})
	claimed, err := queue.Claim(context.Background(), ActionClaimRequest{Scope: scope, LeaseDuration: 30 * time.Minute})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if _, err := queue.Start(context.Background(), claimed.Execution.Fence()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	clock = envelope.ExpiresAt.Add(-time.Minute)
	heartbeat, err := queue.Heartbeat(context.Background(), ActionHeartbeatRequest{
		Lease: claimed.Execution.Fence(), Sequence: 1, Extension: 5 * time.Minute,
	})
	if err != nil || heartbeat.Directive != HeartbeatContinue || !heartbeat.Execution.LeaseExpiresAt.Equal(envelope.ExpiresAt) {
		t.Fatalf("Heartbeat(before authorization expiry) = %#v, %v; want capped expiry %s", heartbeat, err, envelope.ExpiresAt)
	}
	clock = envelope.ExpiresAt
	heartbeat, err = queue.Heartbeat(context.Background(), ActionHeartbeatRequest{
		Lease: claimed.Execution.Fence(), Sequence: 2, Extension: 5 * time.Minute,
	})
	if err != nil || heartbeat.Directive != HeartbeatTerminate || heartbeat.Execution.HeartbeatSeq != 1 ||
		!heartbeat.Execution.LeaseExpiresAt.Equal(envelope.ExpiresAt) {
		t.Fatalf("Heartbeat(at capped authorization expiry) = %#v, %v; want unchanged TERMINATE", heartbeat, err)
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
	if _, err := queue.Complete(context.Background(), ActionCompleteRequest{
		Lease: secondFence, Summary: ExecutorResult{Outcome: ExecutorSucceeded, Code: "COMPLETED", Verification: VerificationPassed},
	}); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("Complete(expired runner) error = %v, want ErrStaleLease", err)
	}
}

func TestMemoryActionQueueStartFailsClosedAtAuthorizationExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return clock })
	submitAction(t, queue, envelope, "environment-1", false)
	clock = clock.Add(10 * time.Minute)
	scope := testRunnerScope(t, "runner-authorization-boundary", RunnerScopeBinding{WorkspaceID: "workspace-1", EnvironmentID: "PROD"})
	claimed, err := queue.Claim(context.Background(), ActionClaimRequest{Scope: scope, LeaseDuration: 30 * time.Minute})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	clock = envelope.ExpiresAt
	if _, err := queue.Start(context.Background(), claimed.Execution.Fence()); !errors.Is(err, executionlease.ErrStaleLease) {
		t.Fatalf("Start(at authorization expiry) error = %v, want %v", err, executionlease.ErrStaleLease)
	}
	persisted, err := queue.Get(context.Background(), envelope.ActionID)
	if err != nil || persisted.Status != executionlease.StatusQueued || persisted.ExecutionID != envelope.ActionID {
		t.Fatalf("Get(after denied Start) = %#v, %v; want retained QUEUED record", persisted, err)
	}
}

func TestMemoryActionQueueReconcileReleasesUncertainTargetLockAndPreservesBothHashes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	firstEnvelope, _ := signedEnvelope(t, restartEnvelope(now))
	secondUnsigned := restartEnvelope(now)
	secondUnsigned.ActionID = "action-after-reconciliation"
	secondUnsigned.IdempotencyKey = "idem-after-reconciliation"
	secondEnvelope, _ := signedEnvelope(t, secondUnsigned)
	queue := mustMemoryActionQueue(t, func() time.Time { return clock })
	submitAction(t, queue, firstEnvelope, "environment-1", false)
	submitAction(t, queue, secondEnvelope, "environment-1", false)
	first := claimAction(t, queue, "runner-old", []string{"workspace-1"}, []string{"PROD"})
	if _, err := queue.Start(context.Background(), first.Execution.Fence()); err != nil {
		t.Fatalf("Start(first) error = %v", err)
	}
	clock = clock.Add(time.Minute)
	if err := queue.SweepExpired(context.Background()); err != nil {
		t.Fatalf("SweepExpired() error = %v", err)
	}
	if _, err := queue.Claim(context.Background(), ActionClaimRequest{
		Scope:         testRunnerScope(t, "runner-blocked", RunnerScopeBinding{WorkspaceID: "workspace-1", EnvironmentID: "PROD"}),
		LeaseDuration: time.Minute,
	}); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("UNCERTAIN did not retain target lock: %v", err)
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

func TestMemoryActionQueueCompletePersistsStructuredReceiptAndFinalizingRetainsLocks(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	firstEnvelope, _ := signedEnvelope(t, restartEnvelope(now))
	secondUnsigned := restartEnvelope(now)
	secondUnsigned.ActionID = "action-after-finalizing"
	secondUnsigned.IdempotencyKey = "idem-after-finalizing"
	secondEnvelope, _ := signedEnvelope(t, secondUnsigned)
	queue := mustMemoryActionQueue(t, func() time.Time { return now })
	submitAction(t, queue, firstEnvelope, "environment-1", false)
	submitAction(t, queue, secondEnvelope, "environment-1", false)
	first := claimAction(t, queue, "runner-finalizing", []string{"workspace-1"}, []string{"PROD"})
	fence := first.Execution.Fence()
	if _, err := queue.Start(context.Background(), fence); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	summary := ExecutorResult{Outcome: ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: VerificationPassed, Changed: true}
	finalizing, err := queue.Complete(context.Background(), ActionCompleteRequest{Lease: fence, Summary: summary})
	if err != nil || finalizing.Status != executionlease.StatusFinalizing || len(finalizing.ResultHash) != 64 {
		t.Fatalf("Complete() = %#v, %v", finalizing, err)
	}
	if _, err := queue.Complete(context.Background(), ActionCompleteRequest{Lease: fence, Summary: summary}); err != nil {
		t.Fatalf("Complete(idempotent receipt) error = %v", err)
	}
	conflicting := summary
	conflicting.Code = "DIFFERENT_RESULT"
	if _, err := queue.Complete(context.Background(), ActionCompleteRequest{Lease: fence, Summary: conflicting}); !errors.Is(err, executionlease.ErrCompletionConflict) {
		t.Fatalf("Complete(conflicting receipt) error = %v, want %v", err, executionlease.ErrCompletionConflict)
	}
	if _, err := queue.Claim(context.Background(), ActionClaimRequest{
		Scope:         testRunnerScope(t, "runner-blocked-finalizing", RunnerScopeBinding{WorkspaceID: "workspace-1", EnvironmentID: "PROD"}),
		LeaseDuration: time.Minute,
	}); !errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		t.Fatalf("FINALIZING released target lock: %v", err)
	}
	completed, err := queue.Finalize(context.Background(), fence)
	if err != nil || completed.Status != executionlease.StatusSucceeded || completed.ResultHash != finalizing.ResultHash {
		t.Fatalf("Finalize() = %#v, %v", completed, err)
	}
	second := claimAction(t, queue, "runner-after-finalize", []string{"workspace-1"}, []string{"PROD"})
	if second.Execution.ExecutionID != secondEnvelope.ActionID {
		t.Fatalf("post-Finalize claim = %q, want %q", second.Execution.ExecutionID, secondEnvelope.ActionID)
	}
}

func TestRunnerResultReceiptHashesBigintFencesBeyondIJSONSafeIntegerAsStrings(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	const firstEpoch = int64(1<<53 + 1)
	claimed := ClaimedAction{
		Execution: executionlease.Execution{
			ExecutionID: envelope.ActionID, RunnerID: "runner-bigint", RunnerTenantID: "tenant-test",
			RunnerWorkspaceID: envelope.WorkspaceID, RunnerEnvironmentID: envelope.Target.EnvironmentID, LeaseEpoch: firstEpoch,
			ScopeRevision: firstEpoch + 2,
		},
		Envelope: envelope, PlanHash: envelope.PlanHash,
	}
	summary := ExecutorResult{Outcome: ExecutorSucceeded, Code: "BIGINT_FENCE_VERIFIED", Verification: VerificationPassed}
	first, err := BuildRunnerResultReceipt(claimed, ActionCompleteRequest{
		Lease:   executionlease.LeaseIdentity{ExecutionID: envelope.ActionID, RunnerID: "runner-bigint", Epoch: firstEpoch},
		Summary: summary,
	}, executionlease.StatusSucceeded, now)
	if err != nil {
		t.Fatalf("BuildRunnerResultReceipt(bigint) error = %v", err)
	}
	expectedJSON, err := json.Marshal(struct {
		SchemaVersion    string                `json:"schema_version"`
		ActionID         string                `json:"action_id"`
		TenantID         string                `json:"tenant_id"`
		WorkspaceID      string                `json:"workspace_id"`
		EnvironmentID    string                `json:"environment_id"`
		PlanHash         string                `json:"plan_hash"`
		RunnerID         string                `json:"runner_id"`
		LeaseEpoch       string                `json:"lease_epoch"`
		ScopeRevision    string                `json:"scope_revision"`
		CompletionStatus executionlease.Status `json:"completion_status"`
		Outcome          ExecutorOutcome       `json:"outcome"`
		Code             string                `json:"code"`
		Verification     Verification          `json:"verification"`
		Changed          bool                  `json:"changed"`
	}{
		SchemaVersion: "runner-result.v1", ActionID: envelope.ActionID, TenantID: "tenant-test", WorkspaceID: envelope.WorkspaceID,
		EnvironmentID: envelope.Target.EnvironmentID, PlanHash: envelope.PlanHash, RunnerID: "runner-bigint",
		LeaseEpoch: strconv.FormatInt(firstEpoch, 10), ScopeRevision: strconv.FormatInt(firstEpoch+2, 10),
		CompletionStatus: executionlease.StatusSucceeded, Outcome: summary.Outcome, Code: summary.Code,
		Verification: summary.Verification, Changed: summary.Changed,
	})
	if err != nil {
		t.Fatalf("json.Marshal(expected receipt) error = %v", err)
	}
	expectedCanonical, err := jsoncanonicalizer.Transform(expectedJSON)
	if err != nil {
		t.Fatalf("canonicalize expected receipt error = %v", err)
	}
	expectedDigest := sha256.Sum256(append([]byte("runner-result.v1\x00"), expectedCanonical...))
	if want := hex.EncodeToString(expectedDigest[:]); first.ResultHash != want {
		t.Fatalf("bigint receipt hash = %s, want string-fence JCS hash %s", first.ResultHash, want)
	}
	second, err := BuildRunnerResultReceipt(claimed, ActionCompleteRequest{
		Lease:   executionlease.LeaseIdentity{ExecutionID: envelope.ActionID, RunnerID: "runner-bigint", Epoch: firstEpoch + 1},
		Summary: summary,
	}, executionlease.StatusSucceeded, now)
	if err != nil {
		t.Fatalf("BuildRunnerResultReceipt(adjacent bigint) error = %v", err)
	}
	if first.ResultHash == second.ResultHash {
		t.Fatalf("adjacent bigint fences collided: %s", first.ResultHash)
	}
}

func TestRunnerResultReceiptV2BindsAuthenticatedCertificateIntoServerJCSHash(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	claimed := ClaimedAction{
		Execution: executionlease.Execution{
			ExecutionID: envelope.ActionID, RunnerID: "runner-v2", RunnerTenantID: "tenant-test",
			RunnerWorkspaceID: envelope.WorkspaceID, RunnerEnvironmentID: envelope.Target.EnvironmentID,
			LeaseEpoch: 7, ScopeRevision: 9,
		},
		Envelope: envelope, PlanHash: envelope.PlanHash,
	}
	request := ActionCompleteRequest{
		Lease: executionlease.LeaseIdentity{ExecutionID: envelope.ActionID, RunnerID: "runner-v2", Epoch: 7},
		Summary: ExecutorResult{
			Outcome: ExecutorSucceeded, Code: "V2_CERT_BOUND", Verification: VerificationPassed, Changed: true,
		},
	}
	certificateA := strings.Repeat("a", 64)
	first, err := BuildRunnerResultReceiptV2(claimed, request, executionlease.StatusSucceeded, certificateA, now)
	if err != nil {
		t.Fatalf("BuildRunnerResultReceiptV2() error = %v", err)
	}
	if first.CertificateSHA256 != certificateA || !actionQueueSHA256Pattern.MatchString(first.ResultHash) {
		t.Fatalf("v2 receipt = %#v", first)
	}
	second, err := BuildRunnerResultReceiptV2(claimed, request, executionlease.StatusSucceeded, strings.Repeat("b", 64), now)
	if err != nil {
		t.Fatalf("BuildRunnerResultReceiptV2(second cert) error = %v", err)
	}
	if first.ResultHash == second.ResultHash {
		t.Fatalf("different certificate fingerprints collided: %s", first.ResultHash)
	}
	legacy, err := BuildRunnerResultReceipt(claimed, request, executionlease.StatusSucceeded, now)
	if err != nil {
		t.Fatalf("BuildRunnerResultReceipt(v1) error = %v", err)
	}
	if first.ResultHash == legacy.ResultHash {
		t.Fatal("runner-result.v1 and authenticated runner-result.v2 hashes collided")
	}
	if _, err := BuildRunnerResultReceiptV2(claimed, request, executionlease.StatusSucceeded, strings.Repeat("A", 64), now); !errors.Is(err, executionlease.ErrInvalidRequest) {
		t.Fatalf("BuildRunnerResultReceiptV2(invalid certificate) error = %v", err)
	}
}

func TestMemoryActionQueueSweepRecoversFinalizingAfterSignedCredentialBoundary(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return clock })
	submitAction(t, queue, envelope, "environment-1", false)
	claimed := claimAction(t, queue, "runner-finalizing-recovery", []string{"workspace-1"}, []string{"PROD"})
	fence := claimed.Execution.Fence()
	if _, err := queue.Start(context.Background(), fence); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	finalizing, err := queue.Complete(context.Background(), ActionCompleteRequest{
		Lease: fence,
		Summary: ExecutorResult{
			Outcome: ExecutorSucceeded, Code: "RECOVERY_RECEIPT_VERIFIED", Verification: VerificationPassed, Changed: true,
		},
	})
	if err != nil || finalizing.Status != executionlease.StatusFinalizing {
		t.Fatalf("Complete() = %#v, %v", finalizing, err)
	}

	clock = envelope.ExpiresAt.Add(-time.Nanosecond)
	if err := queue.SweepExpired(context.Background()); err != nil {
		t.Fatalf("SweepExpired(before signed boundary) error = %v", err)
	}
	beforeBoundary, err := queue.Get(context.Background(), envelope.ActionID)
	if err != nil || beforeBoundary.Status != executionlease.StatusFinalizing {
		t.Fatalf("Get(before signed boundary) = %#v, %v", beforeBoundary, err)
	}

	clock = envelope.ExpiresAt
	if err := queue.SweepExpired(context.Background()); err != nil {
		t.Fatalf("SweepExpired(at signed boundary) error = %v", err)
	}
	recovered, err := queue.Get(context.Background(), envelope.ActionID)
	if err != nil || recovered.Status != executionlease.StatusSucceeded || recovered.CompletedAt.IsZero() {
		t.Fatalf("Get(recovered FINALIZING) = %#v, %v", recovered, err)
	}
}

func TestMemoryActionQueueCancelIsIdempotentAndFencesActiveRunner(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return now })
	submitAction(t, queue, envelope, "environment-1", false)
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

func TestMemoryActionQueueRunningCancelPersistsIntentAndHeartbeatTerminatesWithoutClearingFence(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	clock := now
	envelope, _ := signedEnvelope(t, restartEnvelope(now))
	queue := mustMemoryActionQueue(t, func() time.Time { return clock })
	submitAction(t, queue, envelope, "environment-1", false)
	claimed := claimAction(t, queue, "runner-cancel-intent", []string{"workspace-1"}, []string{"PROD"})
	fence := claimed.Execution.Fence()
	if _, err := queue.Start(context.Background(), fence); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	originalExpiry := claimed.Execution.LeaseExpiresAt

	cancelled, err := queue.Cancel(context.Background(), claimed.Execution.ExecutionID)
	if err != nil || cancelled.Status != executionlease.StatusRunning || cancelled.CancelRequestedAt.IsZero() {
		t.Fatalf("Cancel(RUNNING) = %#v, %v; want running cancel intent", cancelled, err)
	}
	clock = clock.Add(10 * time.Second)
	heartbeat, err := queue.Heartbeat(context.Background(), ActionHeartbeatRequest{
		Lease: fence, Sequence: 1, Extension: 2 * time.Minute,
	})
	if err != nil || heartbeat.Directive != HeartbeatTerminate {
		t.Fatalf("Heartbeat(after cancel) = %#v, %v", heartbeat, err)
	}
	if !heartbeat.Execution.LeaseExpiresAt.Equal(originalExpiry) {
		t.Fatalf("terminate heartbeat extended lease from %s to %s", originalExpiry, heartbeat.Execution.LeaseExpiresAt)
	}
}

func TestMemoryActionQueueSubmitAndClaimAreAtomicUnderConcurrency(t *testing.T) {
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
					EnvironmentRevision: "environment-1", Production: false, Pool: executionlease.PoolWrite,
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

	t.Run("production write claims are hard disabled for every concurrent runner", func(t *testing.T) {
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
					Scope:         testRunnerScope(t, runnerID, RunnerScopeBinding{WorkspaceID: "workspace-1", EnvironmentID: "PROD"}),
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
		if succeeded != 0 || blocked != 2 {
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
	if len(workspaces) != len(environments) {
		t.Fatal("claimAction requires exact workspace/environment pairs")
	}
	bindings := make([]RunnerScopeBinding, len(workspaces))
	for index := range workspaces {
		bindings[index] = RunnerScopeBinding{WorkspaceID: workspaces[index], EnvironmentID: environments[index]}
	}
	claimed, err := queue.Claim(context.Background(), ActionClaimRequest{
		Scope:         testRunnerScope(t, runnerID, bindings...),
		LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	return claimed
}

func testRunnerScope(t *testing.T, runnerID string, bindings ...RunnerScopeBinding) RunnerScope {
	t.Helper()
	scope, err := (RunnerRegistration{
		RunnerID: runnerID, TenantID: "tenant-test", Pool: executionlease.PoolWrite, Enabled: true,
		ScopeRevision: 1, MaxConcurrency: 1, ScopeBindings: bindings,
	}).Scope()
	if err != nil {
		t.Fatalf("RunnerRegistration.Scope() error = %v", err)
	}
	return scope
}

func mustMemoryActionQueue(t *testing.T, clock func() time.Time) *MemoryActionQueue {
	t.Helper()
	queue, err := NewMemoryActionQueue(MemoryActionQueueOptions{
		Clock:                      clock,
		CredentialFinalizationGate: &testCredentialFinalizationGate{present: true, terminal: true},
		TokenSource: func() (string, error) {
			return "queue-lease-token", nil
		},
	})
	if err != nil {
		t.Fatalf("NewMemoryActionQueue() error = %v", err)
	}
	return queue
}
