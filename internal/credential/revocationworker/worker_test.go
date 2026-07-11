package revocationworker

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/credential/vault"
)

type fakeRevoker struct{}

func (fakeRevoker) RevokeAccessor(context.Context, *credential.SensitiveReference) error { return nil }

type fakeRepository struct {
	mu sync.Mutex

	calls          []string
	claims         []credential.ClaimedRevocation
	claimRequest   credential.ClaimRevocationsRequest
	heartbeatCalls []credential.HeartbeatRequest
	completeCalls  []credential.CompleteRevocationRequest
	retryCalls     []credential.RetryRevocationRequest
	manualCalls    []credential.RequireManualRequest
	heartbeatErr   error
	completeErr    error
	retryErr       error
	retryStatus    credential.RevocationStatus
	manualErr      error
	recoverErr     error
	claimErr       error
	heartbeatSeen  chan struct{}
	completeStart  chan struct{}
	completeBlock  <-chan struct{}
}

func (repository *fakeRepository) RecoverPrepared(context.Context, credential.RecoverPreparedRequest) ([]credential.Revocation, error) {
	repository.record("recover-prepared")
	return []credential.Revocation{{ID: "prepared"}}, repository.recoverErr
}

func (repository *fakeRepository) RecoverManaged(context.Context, credential.RecoverManagedRequest) ([]credential.Revocation, error) {
	repository.record("recover-managed")
	return []credential.Revocation{{ID: "managed"}}, nil
}

func (repository *fakeRepository) RecoverExhausted(context.Context, credential.RecoverExhaustedRequest) ([]credential.Revocation, error) {
	repository.record("recover-exhausted")
	return []credential.Revocation{{ID: "exhausted"}}, nil
}

func (repository *fakeRepository) ClaimRevocations(_ context.Context, request credential.ClaimRevocationsRequest) ([]credential.ClaimedRevocation, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.calls = append(repository.calls, "claim")
	repository.claimRequest = request
	return append([]credential.ClaimedRevocation(nil), repository.claims...), repository.claimErr
}

func (repository *fakeRepository) Heartbeat(_ context.Context, request credential.HeartbeatRequest) (credential.Revocation, error) {
	repository.mu.Lock()
	repository.calls = append(repository.calls, "heartbeat")
	repository.heartbeatCalls = append(repository.heartbeatCalls, request)
	failure := repository.heartbeatErr
	seen := repository.heartbeatSeen
	repository.mu.Unlock()
	if seen != nil {
		select {
		case seen <- struct{}{}:
		default:
		}
	}
	return requestRevocation(request.Fence), failure
}

func (repository *fakeRepository) CompleteRevocation(_ context.Context, request credential.CompleteRevocationRequest) (credential.Revocation, error) {
	repository.mu.Lock()
	repository.calls = append(repository.calls, "complete")
	repository.completeCalls = append(repository.completeCalls, request)
	failure := repository.completeErr
	started := repository.completeStart
	block := repository.completeBlock
	repository.mu.Unlock()
	if started != nil {
		close(started)
	}
	if block != nil {
		<-block
	}
	return requestRevocation(request.Fence), failure
}

func (repository *fakeRepository) RetryRevocation(_ context.Context, request credential.RetryRevocationRequest) (credential.Revocation, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.calls = append(repository.calls, "retry")
	repository.retryCalls = append(repository.retryCalls, request)
	revocation := requestRevocation(request.Fence)
	revocation.Status = repository.retryStatus
	return revocation, repository.retryErr
}

func (repository *fakeRepository) RequireManual(_ context.Context, request credential.RequireManualRequest) (credential.Revocation, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.calls = append(repository.calls, "manual")
	repository.manualCalls = append(repository.manualCalls, request)
	return requestRevocation(request.Fence), repository.manualErr
}

func (repository *fakeRepository) record(call string) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.calls = append(repository.calls, call)
}

func (repository *fakeRepository) snapshotCalls() []string {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return append([]string(nil), repository.calls...)
}

func (repository *fakeRepository) heartbeatSnapshot() []credential.HeartbeatRequest {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return append([]credential.HeartbeatRequest(nil), repository.heartbeatCalls...)
}

func requestRevocation(fence credential.ClaimFence) credential.Revocation {
	return credential.Revocation{ID: fence.RevocationID}
}

func newClaim(t *testing.T, attempt int) (credential.ClaimedRevocation, *credential.SensitiveReference) {
	t.Helper()
	accessor, err := credential.NewSensitiveReference([]byte("accessor-canary"))
	if err != nil {
		t.Fatal(err)
	}
	return credential.ClaimedRevocation{
		Revocation: credential.Revocation{
			ID: "00000000-0000-4000-8000-000000000001", TenantID: "tenant-1",
			WorkspaceID: "workspace-1", EnvironmentID: "environment-1",
			Issuer: "vault-database-nonprod", IssuerRevision: "rev-1", Attempt: attempt,
		},
		Fence: credential.ClaimFence{
			RevocationID: "00000000-0000-4000-8000-000000000001", WorkerID: "revoker-1",
			Token: "claim-token", Epoch: int64(attempt),
		},
		Accessor: accessor,
	}, accessor
}

func TestRunOnceRecoversInOrderAndCompletesClaimWithFixedLease(t *testing.T) {
	t.Parallel()

	claim, accessor := newClaim(t, 1)
	repository := &fakeRepository{claims: []credential.ClaimedRevocation{claim}}
	identity := RevokerIdentity{
		TenantID: claim.Revocation.TenantID, WorkspaceID: claim.Revocation.WorkspaceID,
		EnvironmentID: claim.Revocation.EnvironmentID, IssuerID: claim.Revocation.Issuer,
		IssuerRevision: claim.Revocation.IssuerRevision,
	}
	registry, err := NewRegistry([]Registration{{Identity: identity, Revoker: fakeRevoker{}}})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := New(repository, registry, Options{WorkerID: "revoker-1", RecoveryLimit: 7})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if result.PreparedRecovered != 1 || result.ManagedRecovered != 1 || result.ExhaustedRecovered != 1 ||
		result.Claimed != 1 || result.Revoked != 1 {
		t.Fatalf("RunOnce() result = %#v", result)
	}
	if got, want := repository.snapshotCalls(), []string{"recover-prepared", "recover-managed", "recover-exhausted", "claim", "complete"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("repository calls = %#v, want %#v", got, want)
	}
	if repository.claimRequest.WorkerID != "revoker-1" || repository.claimRequest.Limit != 1 ||
		repository.claimRequest.LeaseDuration != credential.RevocationClaimLease {
		t.Fatalf("claim request = %#v", repository.claimRequest)
	}
	if len(repository.completeCalls) != 1 || repository.completeCalls[0].Fence != claim.Fence {
		t.Fatalf("complete calls = %#v", repository.completeCalls)
	}
	if bytes := accessor.Bytes(); len(bytes) != 0 {
		t.Fatalf("accessor retained %d bytes", len(bytes))
	}
	if worker.claimLease != 30*time.Second || worker.heartbeatInterval != 10*time.Second || worker.remoteTimeout != 20*time.Second {
		t.Fatalf("worker timing = claim %s heartbeat %s remote %s", worker.claimLease, worker.heartbeatInterval, worker.remoteTimeout)
	}
}

type blockingRevoker struct {
	started chan struct{}
	release <-chan struct{}
	failure error
	seenCtx chan error
}

func (revoker *blockingRevoker) RevokeAccessor(ctx context.Context, _ *credential.SensitiveReference) error {
	close(revoker.started)
	select {
	case <-revoker.release:
		return revoker.failure
	case <-ctx.Done():
		if revoker.seenCtx != nil {
			revoker.seenCtx <- ctx.Err()
		}
		return ctx.Err()
	}
}

type manualTicker struct {
	ch      chan time.Time
	stopped chan struct{}
}

func (ticker *manualTicker) Chan() <-chan time.Time { return ticker.ch }
func (ticker *manualTicker) Stop()                  { close(ticker.stopped) }

func TestHeartbeatCoversRemoteCallAndFinalRepositoryAck(t *testing.T) {
	t.Parallel()

	claim, _ := newClaim(t, 1)
	remoteStarted := make(chan struct{})
	remoteRelease := make(chan struct{})
	completeStarted := make(chan struct{})
	completeRelease := make(chan struct{})
	heartbeatSeen := make(chan struct{}, 2)
	repository := &fakeRepository{
		claims: claimSlice(claim), heartbeatSeen: heartbeatSeen,
		completeStart: completeStarted, completeBlock: completeRelease,
	}
	revoker := &blockingRevoker{started: remoteStarted, release: remoteRelease}
	worker := newTestWorker(t, repository, claim, revoker)
	ticker := &manualTicker{ch: make(chan time.Time, 2), stopped: make(chan struct{})}
	worker.newTicker = func(interval time.Duration) heartbeatTicker {
		if interval != credential.RevocationHeartbeatInterval {
			t.Errorf("heartbeat interval = %s", interval)
		}
		return ticker
	}

	done := make(chan error, 1)
	go func() {
		_, err := worker.RunOnce(context.Background())
		done <- err
	}()
	waitSignal(t, remoteStarted, "remote start")
	ticker.ch <- time.Now()
	waitSignal(t, heartbeatSeen, "remote heartbeat")
	close(remoteRelease)
	waitSignal(t, completeStarted, "complete start")
	ticker.ch <- time.Now()
	waitSignal(t, heartbeatSeen, "complete heartbeat")
	close(completeRelease)
	if err := waitError(t, done, "worker completion"); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	waitSignal(t, ticker.stopped, "ticker stop")

	heartbeats := repository.heartbeatSnapshot()
	if len(heartbeats) != 2 {
		t.Fatalf("heartbeat calls = %#v", heartbeats)
	}
	for _, request := range heartbeats {
		if request.Fence != claim.Fence || request.Extension != credential.RevocationClaimLease {
			t.Fatalf("heartbeat request = %#v", request)
		}
	}
}

func TestHeartbeatLossCancelsRemoteAndLeavesClaimForExpiry(t *testing.T) {
	t.Parallel()

	claim, accessor := newClaim(t, 1)
	upstream := errors.New("database-canary-secret")
	heartbeatSeen := make(chan struct{}, 1)
	repository := &fakeRepository{claims: claimSlice(claim), heartbeatErr: upstream, heartbeatSeen: heartbeatSeen}
	remoteStarted := make(chan struct{})
	neverRelease := make(chan struct{})
	remoteCanceled := make(chan error, 1)
	revoker := &blockingRevoker{started: remoteStarted, release: neverRelease, seenCtx: remoteCanceled}
	worker := newTestWorker(t, repository, claim, revoker)
	ticker := &manualTicker{ch: make(chan time.Time, 1), stopped: make(chan struct{})}
	worker.newTicker = func(time.Duration) heartbeatTicker { return ticker }

	type response struct {
		result RunResult
		err    error
	}
	done := make(chan response, 1)
	go func() {
		result, err := worker.RunOnce(context.Background())
		done <- response{result: result, err: err}
	}()
	waitSignal(t, remoteStarted, "remote start")
	ticker.ch <- time.Now()
	waitSignal(t, heartbeatSeen, "failed heartbeat")
	select {
	case err := <-remoteCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("remote context error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("remote context was not canceled")
	}
	var got response
	select {
	case got = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not return after heartbeat loss")
	}
	if !errors.Is(got.err, ErrClaimDeferred) || got.result.Deferred != 1 || got.result.Revoked != 0 {
		t.Fatalf("RunOnce() = %#v, %v", got.result, got.err)
	}
	if bytes.Contains([]byte(got.err.Error()), []byte("canary")) {
		t.Fatalf("worker error leaked upstream detail: %v", got.err)
	}
	if len(repository.completeCalls) != 0 || len(repository.retryCalls) != 0 || len(repository.manualCalls) != 0 {
		t.Fatalf("claim was acknowledged after heartbeat loss: complete=%d retry=%d manual=%d",
			len(repository.completeCalls), len(repository.retryCalls), len(repository.manualCalls))
	}
	if got := accessor.Bytes(); len(got) != 0 {
		t.Fatalf("accessor retained %d bytes", len(got))
	}
}

type ignoringRevoker struct {
	started chan struct{}
	release <-chan struct{}
	done    chan struct{}
}

func (revoker *ignoringRevoker) RevokeAccessor(context.Context, *credential.SensitiveReference) error {
	close(revoker.started)
	<-revoker.release
	close(revoker.done)
	return nil
}

func TestRemoteTimeoutDoesNotWaitForContextIgnoringRevoker(t *testing.T) {
	t.Parallel()

	claim, accessor := newClaim(t, 1)
	repository := &fakeRepository{claims: claimSlice(claim)}
	remoteStarted := make(chan struct{})
	remoteRelease := make(chan struct{})
	remoteDone := make(chan struct{})
	revoker := &ignoringRevoker{started: remoteStarted, release: remoteRelease, done: remoteDone}
	worker := newTestWorker(t, repository, claim, revoker)
	ticker := &manualTicker{ch: make(chan time.Time), stopped: make(chan struct{})}
	worker.newTicker = func(time.Duration) heartbeatTicker { return ticker }
	timeout := make(chan time.Time, 1)
	worker.after = func(duration time.Duration) <-chan time.Time {
		if duration != credential.RevocationRemoteTimeout {
			t.Errorf("remote timeout = %s", duration)
		}
		return timeout
	}

	type response struct {
		result RunResult
		err    error
	}
	done := make(chan response, 1)
	go func() {
		result, err := worker.RunOnce(context.Background())
		done <- response{result: result, err: err}
	}()
	waitSignal(t, remoteStarted, "context-ignoring remote start")
	timeout <- time.Now()

	var got response
	select {
	case got = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker waited for context-ignoring revoker")
	}
	if got.err != nil || got.result.Retried != 1 || got.result.Deferred != 0 {
		t.Fatalf("RunOnce() = %#v, %v", got.result, got.err)
	}
	if len(repository.retryCalls) != 1 {
		t.Fatalf("retry calls = %#v", repository.retryCalls)
	}
	retry := repository.retryCalls[0]
	if retry.Fence != claim.Fence || retry.FailureCode != credential.FailureTimeout ||
		string(retry.FailureDetail) != "credential.revocation.worker.timeout.v1" ||
		retry.Delay != credential.MinRevocationRetryDelay {
		t.Fatalf("retry request = %#v", retry)
	}
	if got := accessor.Bytes(); len(got) != 0 {
		t.Fatalf("accessor retained after timeout: %d bytes", len(got))
	}
	secondClaim, secondAccessor := newClaim(t, 2)
	repository.mu.Lock()
	repository.claims = claimSlice(secondClaim)
	repository.mu.Unlock()
	secondTicker := &manualTicker{ch: make(chan time.Time), stopped: make(chan struct{})}
	worker.newTicker = func(time.Duration) heartbeatTicker { return secondTicker }
	secondResult, secondErr := worker.RunOnce(context.Background())
	if !errors.Is(secondErr, ErrClaimDeferred) || secondResult.Deferred != 1 || len(repository.retryCalls) != 1 {
		t.Fatalf("RunOnce(with detached remote) = %#v, %v; retry calls=%d",
			secondResult, secondErr, len(repository.retryCalls))
	}
	if got := secondAccessor.Bytes(); len(got) != 0 {
		t.Fatalf("deferred accessor retained while remote slot occupied: %d bytes", len(got))
	}

	close(remoteRelease)
	waitSignal(t, remoteDone, "late remote completion")
}

type errorRevoker struct{ err error }

func (revoker errorRevoker) RevokeAccessor(context.Context, *credential.SensitiveReference) error {
	return revoker.err
}

func TestRunOnceClassifiesRemoteFailuresWithoutPersistingUpstreamDetails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		failure error
		code    credential.FailureCode
		detail  string
		manual  bool
	}{
		{name: "authentication", failure: &vault.ClientError{Class: vault.ErrorAuthentication}, code: credential.FailureAuthentication, detail: "credential.revocation.worker.authentication_failed.v1"},
		{name: "permission", failure: &vault.ClientError{Class: vault.ErrorPermission}, code: credential.FailurePermissionDenied, detail: "credential.revocation.worker.permission_denied.v1"},
		{name: "rate limited", failure: &vault.ClientError{Class: vault.ErrorRateLimited}, code: credential.FailureRateLimited, detail: "credential.revocation.worker.rate_limited.v1"},
		{name: "unavailable", failure: &vault.ClientError{Class: vault.ErrorUnavailable}, code: credential.FailureIssuerUnavailable, detail: "credential.revocation.worker.issuer_unavailable.v1"},
		{name: "timeout", failure: &vault.ClientError{Class: vault.ErrorTimeout}, code: credential.FailureTimeout, detail: "credential.revocation.worker.timeout.v1"},
		{name: "invalid reference", failure: &vault.ClientError{Class: vault.ErrorInvalidReference}, code: credential.FailureInvalidReference, detail: "credential.revocation.worker.invalid_reference.v1", manual: true},
		{name: "protocol", failure: &vault.ClientError{Class: vault.ErrorProtocol}, code: credential.FailureUnknown, detail: "credential.revocation.worker.unknown.v1"},
		{name: "opaque upstream", failure: errors.New("upstream-body-canary-secret"), code: credential.FailureUnknown, detail: "credential.revocation.worker.unknown.v1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			claim, _ := newClaim(t, 2)
			repository := &fakeRepository{claims: claimSlice(claim)}
			worker := newTestWorker(t, repository, claim, errorRevoker{err: test.failure})
			result, err := worker.RunOnce(context.Background())
			if err != nil {
				t.Fatalf("RunOnce() error = %v", err)
			}
			if test.manual {
				if result.ManualRequired != 1 || len(repository.manualCalls) != 1 || len(repository.retryCalls) != 0 {
					t.Fatalf("manual result = %#v calls=%#v", result, repository.manualCalls)
				}
				request := repository.manualCalls[0]
				if request.FailureCode != test.code || string(request.FailureDetail) != test.detail {
					t.Fatalf("manual request = %#v", request)
				}
				return
			}
			if result.Retried != 1 || len(repository.retryCalls) != 1 || len(repository.manualCalls) != 0 {
				t.Fatalf("retry result = %#v calls=%#v", result, repository.retryCalls)
			}
			request := repository.retryCalls[0]
			if request.FailureCode != test.code || string(request.FailureDetail) != test.detail ||
				request.Delay < credential.MinRevocationRetryDelay || request.Delay > credential.MaxRevocationRetryDelay {
				t.Fatalf("retry request = %#v", request)
			}
			if bytes.Contains(request.FailureDetail, []byte("canary")) {
				t.Fatalf("failure detail leaked upstream data: %q", request.FailureDetail)
			}
		})
	}
}

func TestRemoteSuccessWithLostCompletionAckLeavesClaimForIdempotentReclaim(t *testing.T) {
	t.Parallel()

	claim, accessor := newClaim(t, 1)
	repository := &fakeRepository{claims: claimSlice(claim), completeErr: errors.New("completion-ack-canary-secret")}
	worker := newTestWorker(t, repository, claim, fakeRevoker{})
	result, err := worker.RunOnce(context.Background())
	if !errors.Is(err, ErrClaimDeferred) || result.Deferred != 1 || result.Revoked != 0 {
		t.Fatalf("RunOnce() = %#v, %v", result, err)
	}
	if bytes.Contains([]byte(err.Error()), []byte("canary")) {
		t.Fatalf("worker error leaked completion failure: %v", err)
	}
	if len(repository.completeCalls) != 1 || len(repository.retryCalls) != 0 || len(repository.manualCalls) != 0 {
		t.Fatalf("lost completion ACK mutated claim: complete=%d retry=%d manual=%d",
			len(repository.completeCalls), len(repository.retryCalls), len(repository.manualCalls))
	}
	if got := accessor.Bytes(); len(got) != 0 {
		t.Fatalf("accessor retained after lost completion ACK: %d bytes", len(got))
	}
}

func TestCanceledRunDoesNotAcknowledgeClaim(t *testing.T) {
	t.Parallel()

	claim, accessor := newClaim(t, 1)
	repository := &fakeRepository{claims: claimSlice(claim)}
	worker := newTestWorker(t, repository, claim, fakeRevoker{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := worker.RunOnce(ctx)
	if !errors.Is(err, ErrClaimDeferred) || result.Deferred != 1 {
		t.Fatalf("RunOnce(canceled) = %#v, %v", result, err)
	}
	if len(repository.completeCalls) != 0 || len(repository.retryCalls) != 0 || len(repository.manualCalls) != 0 {
		t.Fatalf("canceled run acknowledged claim")
	}
	if got := accessor.Bytes(); len(got) != 0 {
		t.Fatalf("canceled run retained accessor: %d bytes", len(got))
	}
}

func TestRunOnceReturnsOnlyFixedErrorsForRepositoryFailures(t *testing.T) {
	t.Parallel()

	t.Run("recovery", func(t *testing.T) {
		repository := &fakeRepository{recoverErr: errors.New("recovery-canary-secret")}
		registry, err := NewRegistry([]Registration{{
			Identity: RevokerIdentity{
				TenantID: "tenant-1", WorkspaceID: "workspace-1", EnvironmentID: "environment-1",
				IssuerID: "vault-database-nonprod", IssuerRevision: "rev-1",
			},
			Revoker: fakeRevoker{},
		}})
		if err != nil {
			t.Fatal(err)
		}
		worker, err := New(repository, registry, Options{WorkerID: "revoker-1"})
		if err != nil {
			t.Fatal(err)
		}
		_, runErr := worker.RunOnce(context.Background())
		if !errors.Is(runErr, ErrRecoveryFailed) || bytes.Contains([]byte(runErr.Error()), []byte("canary")) {
			t.Fatalf("RunOnce(recovery failure) error = %v", runErr)
		}
	})

	t.Run("claim", func(t *testing.T) {
		claim, accessor := newClaim(t, 1)
		repository := &fakeRepository{claims: claimSlice(claim), claimErr: errors.New("claim-canary-secret")}
		worker := newTestWorker(t, repository, claim, fakeRevoker{})
		_, runErr := worker.RunOnce(context.Background())
		if !errors.Is(runErr, ErrClaimFailed) || bytes.Contains([]byte(runErr.Error()), []byte("canary")) {
			t.Fatalf("RunOnce(claim failure) error = %v", runErr)
		}
		if got := accessor.Bytes(); len(got) != 0 {
			t.Fatalf("claim error retained accessor: %d bytes", len(got))
		}
	})
}

func TestNewRejectsMultiClaimConfigurationUntilConcurrentIsolationExists(t *testing.T) {
	t.Parallel()
	claim, accessor := newClaim(t, 1)
	defer accessor.Destroy()
	registry, err := NewRegistry([]Registration{{Identity: identityFrom(claim.Revocation), Revoker: fakeRevoker{}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(&fakeRepository{}, registry, Options{WorkerID: "revoker-1", ClaimLimit: 2}); !errors.Is(err, ErrInvalidWorker) {
		t.Fatalf("New(ClaimLimit=2) error = %v", err)
	}
}

func TestRetryDelayStaysWithinFixedFullJitterEnvelope(t *testing.T) {
	t.Parallel()

	claim, _ := newClaim(t, 1)
	worker := newTestWorker(t, &fakeRepository{}, claim, fakeRevoker{})
	tests := []struct {
		attempt int
		upper   time.Duration
	}{
		{attempt: -1, upper: 5 * time.Second},
		{attempt: 1, upper: 5 * time.Second},
		{attempt: 2, upper: 10 * time.Second},
		{attempt: 12, upper: 15 * time.Minute},
		{attempt: 1_000, upper: 15 * time.Minute},
	}
	for _, test := range tests {
		for iteration := 0; iteration < 100; iteration++ {
			delay := worker.retryDelay(test.attempt)
			if delay < credential.MinRevocationRetryDelay || delay > test.upper || delay > credential.MaxRevocationRetryDelay {
				t.Fatalf("retryDelay(attempt=%d) = %s, want [%s,%s]", test.attempt, delay,
					credential.MinRevocationRetryDelay, test.upper)
			}
		}
	}
}

func TestRepositoryExhaustionDecisionOverridesWorkerRetryOutcome(t *testing.T) {
	t.Parallel()

	claim, _ := newClaim(t, credential.MaxRevocationAttempts)
	repository := &fakeRepository{claims: claimSlice(claim), retryStatus: credential.StatusManualRequired}
	worker := newTestWorker(t, repository, claim, errorRevoker{err: errors.New("retryable")})
	result, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if result.ManualRequired != 1 || result.Retried != 0 || len(repository.retryCalls) != 1 {
		t.Fatalf("RunOnce() = %#v retry calls=%d", result, len(repository.retryCalls))
	}
}

func claimSlice(claim credential.ClaimedRevocation) []credential.ClaimedRevocation {
	return []credential.ClaimedRevocation{claim}
}

func newTestWorker(t *testing.T, repository *fakeRepository, claim credential.ClaimedRevocation, revoker Revoker) *Worker {
	t.Helper()
	registry, err := NewRegistry([]Registration{{Identity: identityFrom(claim.Revocation), Revoker: revoker}})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := New(repository, registry, Options{
		WorkerID: "revoker-1", RecoveryLimit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	worker.random = bytes.NewReader(make([]byte, 128))
	return worker
}

func waitSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func waitError(t *testing.T, signal <-chan error, description string) error {
	t.Helper()
	select {
	case err := <-signal:
		return err
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
		return nil
	}
}

func TestRegistryResolvesOnlyExactPersistedIdentity(t *testing.T) {
	t.Parallel()

	identity := RevokerIdentity{
		TenantID: "tenant-1", WorkspaceID: "workspace-1", EnvironmentID: "environment-1",
		IssuerID: "vault-database-nonprod", IssuerRevision: "rev-1",
	}
	revoker := fakeRevoker{}
	registry, err := NewRegistry([]Registration{{Identity: identity, Revoker: revoker}})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	got, err := registry.ResolveRevoker(context.Background(), identity)
	if err != nil || got == nil {
		t.Fatalf("ResolveRevoker(exact) = %#v, %v", got, err)
	}

	for name, mutate := range map[string]func(*RevokerIdentity){
		"tenant":      func(value *RevokerIdentity) { value.TenantID = "tenant-2" },
		"workspace":   func(value *RevokerIdentity) { value.WorkspaceID = "workspace-2" },
		"environment": func(value *RevokerIdentity) { value.EnvironmentID = "environment-2" },
		"issuer":      func(value *RevokerIdentity) { value.IssuerID = "vault-other" },
		"revision":    func(value *RevokerIdentity) { value.IssuerRevision = "rev-2" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := identity
			mutate(&candidate)
			if _, resolveErr := registry.ResolveRevoker(context.Background(), candidate); !errors.Is(resolveErr, ErrRevokerNotRegistered) {
				t.Fatalf("ResolveRevoker(%s mismatch) error = %v", name, resolveErr)
			}
		})
	}
}

func TestRegistryRejectsWildcardOrPathProfileKeys(t *testing.T) {
	t.Parallel()

	valid := RevokerIdentity{
		TenantID: "tenant-1", WorkspaceID: "workspace-1", EnvironmentID: "environment-1",
		IssuerID: "vault-database-nonprod", IssuerRevision: "rev-1",
	}
	for name, mutate := range map[string]func(*RevokerIdentity){
		"wildcard":         func(value *RevokerIdentity) { value.IssuerID = "*" },
		"issuer url":       func(value *RevokerIdentity) { value.IssuerID = "https://vault.invalid" },
		"revision path":    func(value *RevokerIdentity) { value.IssuerRevision = "profiles/rev-1" },
		"workspace url":    func(value *RevokerIdentity) { value.WorkspaceID = "https://workspace.invalid" },
		"environment path": func(value *RevokerIdentity) { value.EnvironmentID = "environments/nonprod" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := NewRegistry([]Registration{{Identity: candidate, Revoker: fakeRevoker{}}}); !errors.Is(err, ErrInvalidRegistry) {
				t.Fatalf("NewRegistry(%s) error = %v", name, err)
			}
		})
	}
}

func TestRegistryIdentityLengthMatchesDurableIdentifierBoundary(t *testing.T) {
	t.Parallel()
	identity := RevokerIdentity{
		TenantID: "tenant-1", WorkspaceID: "workspace-1", EnvironmentID: "environment-1",
		IssuerID: "vault-database-nonprod", IssuerRevision: strings.Repeat("a", 256),
	}
	if _, err := NewRegistry([]Registration{{Identity: identity, Revoker: fakeRevoker{}}}); err != nil {
		t.Fatalf("NewRegistry(256-byte revision) error = %v", err)
	}
	identity.IssuerRevision += "a"
	if _, err := NewRegistry([]Registration{{Identity: identity, Revoker: fakeRevoker{}}}); !errors.Is(err, ErrInvalidRegistry) {
		t.Fatalf("NewRegistry(257-byte revision) error = %v", err)
	}
}

func TestConstructorsRejectTypedNilDependencies(t *testing.T) {
	t.Parallel()

	identity := RevokerIdentity{
		TenantID: "tenant-1", WorkspaceID: "workspace-1", EnvironmentID: "environment-1",
		IssuerID: "vault-database-nonprod", IssuerRevision: "rev-1",
	}
	var nilRevoker *blockingRevoker
	if _, err := NewRegistry([]Registration{{Identity: identity, Revoker: nilRevoker}}); !errors.Is(err, ErrInvalidRegistry) {
		t.Fatalf("NewRegistry(typed nil revoker) error = %v", err)
	}
	registry, err := NewRegistry([]Registration{{Identity: identity, Revoker: fakeRevoker{}}})
	if err != nil {
		t.Fatal(err)
	}
	var nilRepository *fakeRepository
	if _, err := New(nilRepository, registry, Options{WorkerID: "revoker-1"}); !errors.Is(err, ErrInvalidWorker) {
		t.Fatalf("New(typed nil repository) error = %v", err)
	}
	var nilRegistry *Registry
	if _, err := New(&fakeRepository{}, nilRegistry, Options{WorkerID: "revoker-1"}); !errors.Is(err, ErrInvalidWorker) {
		t.Fatalf("New(typed nil resolver) error = %v", err)
	}
}
