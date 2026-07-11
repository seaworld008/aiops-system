package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/config"
	"github.com/seaworld008/aiops-system/internal/credential"
	credentialpostgres "github.com/seaworld008/aiops-system/internal/credential/postgres"
	"github.com/seaworld008/aiops-system/internal/execution"
	executionpostgres "github.com/seaworld008/aiops-system/internal/execution/postgres"
	"github.com/seaworld008/aiops-system/internal/executionlease"
	"github.com/seaworld008/aiops-system/internal/runnergateway"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
)

const (
	testTenantID      = "10000000-0000-4000-8000-000000000001"
	testWorkspaceID   = "20000000-0000-4000-8000-000000000002"
	testEnvironmentID = "30000000-0000-4000-8000-000000000003"
	testRevocationID  = "40000000-0000-4000-8000-000000000004"
	testRunnerID      = "write-runner-01"
	testJobID         = "action-01"
	testToken         = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testClaimToken    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testReceiptHash   = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

var testNow = time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)

type testPrincipal struct {
	runnerID       string
	tenantID       string
	pool           runneridentity.Pool
	scopeRevision  int64
	maxConcurrency int
	revocation     bool
	certificate    string
	notAfter       time.Time
	bindings       []execution.RunnerScopeBinding
}

func (principal testPrincipal) Valid() bool {
	_, err := principal.RunnerScope()
	return err == nil && principal.certificate != "" && !principal.notAfter.IsZero()
}
func (principal testPrincipal) RunnerID() string                  { return principal.runnerID }
func (principal testPrincipal) TenantID() string                  { return principal.tenantID }
func (principal testPrincipal) Pool() runneridentity.Pool         { return principal.pool }
func (principal testPrincipal) ScopeRevision() int64              { return principal.scopeRevision }
func (principal testPrincipal) MaxConcurrency() int               { return principal.maxConcurrency }
func (principal testPrincipal) CredentialRevocationCapable() bool { return principal.revocation }
func (principal testPrincipal) CertificateSHA256() string         { return principal.certificate }
func (principal testPrincipal) CertificateNotAfter() time.Time    { return principal.notAfter }
func (principal testPrincipal) Allows(workspaceID, environmentID string) bool {
	for _, binding := range principal.bindings {
		if binding.WorkspaceID == workspaceID && binding.EnvironmentID == environmentID {
			return true
		}
	}
	return false
}
func (principal testPrincipal) RunnerScope() (execution.RunnerScope, error) {
	pool := executionlease.Pool(principal.pool)
	return (execution.RunnerRegistration{
		RunnerID: principal.runnerID, TenantID: principal.tenantID, Pool: pool, Enabled: true,
		ScopeRevision: principal.scopeRevision, MaxConcurrency: principal.maxConcurrency,
		ScopeBindings: append([]execution.RunnerScopeBinding(nil), principal.bindings...),
	}).Scope()
}

type fakeRevocationTicket struct{ discarded bool }

func (ticket *fakeRevocationTicket) Discard() { ticket.discarded = true }

func TestDisabledModeAuthenticatesThenBlocksOnlyNewJobClaims(t *testing.T) {
	backend, database, identity, _ := newBackendFixture(t, config.WriteExecutionModeDisabled)
	defer database.Close()
	claimJobCalled := false
	backend.operations.claimJobTx = func(context.Context, pgx.Tx, execution.RunnerScope, time.Duration) (execution.ClaimedAction, error) {
		claimJobCalled = true
		return execution.ClaimedAction{}, nil
	}
	database.ExpectBegin()
	database.ExpectRollback()
	response, err := backend.LeaseJob(context.Background(), identity, runnergateway.JobLeaseRequest{})
	if response != nil || !errors.Is(err, runnergateway.ErrClaimsDisabled) || claimJobCalled {
		t.Fatalf("LeaseJob(disabled) = %#v, %v; claim called=%t", response, err, claimJobCalled)
	}

	revocationCalled := false
	backend.operations.claimRevocationTx = func(_ context.Context, _ pgx.Tx, scope execution.RunnerScope, certificate string) (revocationClaimTicket, error) {
		revocationCalled = true
		assertTrustedScope(t, scope)
		if certificate != identity.Evidence().LeafSHA256() {
			t.Fatalf("certificate = %q, want authenticated leaf", certificate)
		}
		return nil, nil
	}
	database.ExpectBegin()
	database.ExpectCommit()
	responseRevocation, err := backend.LeaseRevocation(context.Background(), identity, runnergateway.RevocationLeaseRequest{})
	if err != nil || responseRevocation != nil || !revocationCalled {
		t.Fatalf("LeaseRevocation(disabled) = %#v, %v; called=%t", responseRevocation, err, revocationCalled)
	}
	assertExpectations(t, database)
}

func TestLeaseRevocationCommitsBeforeReleasingAndDestroysSecrets(t *testing.T) {
	backend, database, identity, _ := newBackendFixture(t, config.WriteExecutionModeDisabled)
	defer database.Close()
	ticket := &fakeRevocationTicket{}
	accessor, err := credential.NewSensitiveReference([]byte("vault-accessor-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveReference() error = %v", err)
	}
	database.ExpectBegin()
	database.ExpectCommit()
	backend.operations.claimRevocationTx = func(_ context.Context, _ pgx.Tx, scope execution.RunnerScope, certificate string) (revocationClaimTicket, error) {
		assertTrustedScope(t, scope)
		if certificate != identity.Evidence().LeafSHA256() {
			t.Fatalf("certificate = %q", certificate)
		}
		return ticket, nil
	}
	backend.operations.finalizeRevocation = func(_ context.Context, got revocationClaimTicket) (credential.ClaimedRevocation, error) {
		if got != ticket {
			t.Fatal("finalizer received a different ticket")
		}
		// A finalizer is forbidden before the caller-owned claim transaction
		// has unambiguously committed.
		assertExpectations(t, database)
		return credential.ClaimedRevocation{
			Revocation: credential.Revocation{
				ID: testRevocationID, TenantID: testTenantID, WorkspaceID: testWorkspaceID,
				EnvironmentID: testEnvironmentID, Issuer: "vault-non-production", IssuerRevision: "rev-1",
				Status: credential.StatusRevoking, ClaimEpoch: 3, ClaimExpiresAt: testNow.Add(30 * time.Second),
			},
			Fence: credential.ClaimFence{
				RevocationID: testRevocationID, WorkerID: testRunnerID, Token: testClaimToken, Epoch: 3,
			},
			Accessor: accessor,
		}, nil
	}
	response, err := backend.LeaseRevocation(context.Background(), identity, runnergateway.RevocationLeaseRequest{})
	if err != nil || response == nil {
		t.Fatalf("LeaseRevocation() = %#v, %v", response, err)
	}
	if response.ClaimToken != testClaimToken || response.RevokeAccessorB64U != "dmF1bHQtYWNjZXNzb3ItY2FuYXJ5" ||
		response.HeartbeatAfterSeconds != 10 || response.TenantID != testTenantID || response.WorkspaceID != testWorkspaceID {
		t.Fatalf("LeaseRevocation() response = %#v", response)
	}
	if !ticket.discarded || len(accessor.Bytes()) != 0 {
		t.Fatalf("sensitive claim not destroyed: ticket=%#v accessor=%q", ticket, accessor.Bytes())
	}
}

func TestLeaseRevocationCommitFailureDiscardsWithoutFinalizing(t *testing.T) {
	backend, database, identity, _ := newBackendFixture(t, config.WriteExecutionModeDisabled)
	defer database.Close()
	ticket := &fakeRevocationTicket{}
	commitFailure := errors.New("ambiguous commit canary")
	database.ExpectBegin()
	database.ExpectCommit().WillReturnError(commitFailure)
	database.ExpectRollback()
	backend.operations.claimRevocationTx = func(context.Context, pgx.Tx, execution.RunnerScope, string) (revocationClaimTicket, error) {
		return ticket, nil
	}
	finalized := false
	backend.operations.finalizeRevocation = func(context.Context, revocationClaimTicket) (credential.ClaimedRevocation, error) {
		finalized = true
		return credential.ClaimedRevocation{}, nil
	}
	response, err := backend.LeaseRevocation(context.Background(), identity, runnergateway.RevocationLeaseRequest{})
	if response != nil || !errors.Is(err, runnergateway.ErrUnavailable) || finalized || !ticket.discarded {
		t.Fatalf("LeaseRevocation(commit failure) = %#v, %v; finalized=%t discarded=%t", response, err, finalized, ticket.discarded)
	}
	if strings.Contains(err.Error(), "canary") {
		t.Fatalf("commit detail leaked: %v", err)
	}
	assertExpectations(t, database)
}

func TestRevocationHeartbeatAndCompletionUseAuthenticatedFenceAndFixedPolicy(t *testing.T) {
	backend, database, identity, principal := newBackendFixture(t, config.WriteExecutionModeDisabled)
	defer database.Close()
	database.ExpectBegin()
	database.ExpectCommit()
	backend.operations.heartbeatRevocation = func(_ context.Context, _ pgx.Tx, scope execution.RunnerScope, fence credential.ClaimFence, sequence int64) (credential.RunnerRevocationHeartbeatResult, error) {
		assertTrustedScope(t, scope)
		assertClaimFence(t, fence, 7)
		if sequence != 9 {
			t.Fatalf("sequence = %d", sequence)
		}
		return credential.RunnerRevocationHeartbeatResult{
			RevocationID: testRevocationID, ClaimEpoch: 7, AcceptedSequence: 9,
			Directive: credential.RunnerRevocationTerminate, ClaimExpiresAt: testNow.Add(12 * time.Second),
		}, nil
	}
	heartbeat, err := backend.HeartbeatRevocation(context.Background(), identity, testRevocationID, testClaimToken,
		runnergateway.RevocationHeartbeatRequest{ClaimEpoch: 7, Sequence: 9})
	if err != nil || heartbeat.Directive != "TERMINATE" || heartbeat.AcceptedSequence != 9 || heartbeat.HeartbeatAfterSeconds != 10 {
		t.Fatalf("HeartbeatRevocation() = %#v, %v", heartbeat, err)
	}

	database.ExpectBegin()
	database.ExpectCommit()
	backend.operations.completeRevocationTx = func(
		_ context.Context, _ pgx.Tx, scope execution.RunnerScope, fence credential.ClaimFence,
		outcome credential.RunnerRevocationOutcome, code credential.FailureCode, certificate string,
	) (credential.RunnerRevocationCompletionResult, error) {
		assertTrustedScope(t, scope)
		assertClaimFence(t, fence, 7)
		if outcome != credential.RunnerRevocationFailed || code != credential.FailureTimeout || certificate != principal.certificate {
			t.Fatalf("completion binding = %q %q %q", outcome, code, certificate)
		}
		return credential.RunnerRevocationCompletionResult{Revocation: credential.Revocation{
			ID: testRevocationID, Status: credential.StatusRevocationPending, AvailableAt: testNow.Add(time.Minute),
		}}, nil
	}
	completion, err := backend.CompleteRevocation(context.Background(), identity, testRevocationID, testClaimToken,
		runnergateway.RevocationCompleteRequest{ClaimEpoch: 7, Outcome: "FAILED", FailureCode: "TIMEOUT"})
	if err != nil || completion.Status != "REVOCATION_PENDING" || completion.AvailableAt == nil ||
		!completion.AvailableAt.Equal(testNow.Add(time.Minute)) {
		t.Fatalf("CompleteRevocation() = %#v, %v", completion, err)
	}
	assertExpectations(t, database)
}

func TestJobLeaseHeartbeatAndReleaseInjectServerOwnedValues(t *testing.T) {
	backend, database, identity, _ := newBackendFixture(t, config.WriteExecutionModeNonProduction)
	defer database.Close()
	backend.startAuthorizer = func(context.Context, execution.ClaimedAction) (StartAuthorization, error) {
		return StartAuthorization{}, nil
	}
	database.ExpectBegin()
	database.ExpectCommit()
	backend.operations.claimJobTx = func(_ context.Context, _ pgx.Tx, scope execution.RunnerScope, duration time.Duration) (execution.ClaimedAction, error) {
		assertTrustedScope(t, scope)
		if duration != 30*time.Second {
			t.Fatalf("claim duration = %s", duration)
		}
		return execution.ClaimedAction{
			Execution: executionlease.Execution{
				ExecutionID: testJobID, Pool: executionlease.PoolWrite, Status: executionlease.StatusLeased,
				RunnerID: testRunnerID, LeaseToken: testToken, LeaseEpoch: 4,
				LeaseExpiresAt: testNow.Add(30 * time.Second), ScopeRevision: 5,
			},
			PlanHash: testReceiptHash, EnvironmentRevision: "env-rev-1",
		}, nil
	}
	lease, err := backend.LeaseJob(context.Background(), identity, runnergateway.JobLeaseRequest{})
	if err != nil || lease == nil || lease.LeaseToken != testToken || lease.HeartbeatAfterSeconds != 10 || lease.ScopeRevision != 5 {
		t.Fatalf("LeaseJob() = %#v, %v", lease, err)
	}

	database.ExpectBegin()
	database.ExpectCommit()
	backend.operations.heartbeatJobTx = func(_ context.Context, _ pgx.Tx, scope execution.RunnerScope, request execution.ActionHeartbeatRequest) (execution.ActionHeartbeatResult, error) {
		assertTrustedScope(t, scope)
		assertJobFence(t, request.Lease, 4)
		if request.Sequence != 6 || request.Extension != 30*time.Second {
			t.Fatalf("heartbeat = %#v", request)
		}
		return execution.ActionHeartbeatResult{Execution: executionlease.Execution{
			ExecutionID: testJobID, HeartbeatSeq: 5, LeaseExpiresAt: testNow.Add(20 * time.Second),
		}, Directive: execution.HeartbeatTerminate}, nil
	}
	heartbeat, err := backend.HeartbeatJob(context.Background(), identity, testJobID, testToken,
		runnergateway.JobHeartbeatRequest{LeaseEpoch: 4, Sequence: 6})
	if err != nil || heartbeat.AcceptedSequence != 6 || heartbeat.Directive != "TERMINATE" || heartbeat.HeartbeatAfterSeconds != 10 {
		t.Fatalf("HeartbeatJob() = %#v, %v", heartbeat, err)
	}

	database.ExpectBegin()
	database.ExpectCommit()
	backend.operations.releaseJobTx = func(_ context.Context, _ pgx.Tx, scope execution.RunnerScope, fence executionlease.LeaseIdentity, reason string, retry time.Duration) (executionlease.Execution, error) {
		assertTrustedScope(t, scope)
		assertJobFence(t, fence, 4)
		if reason != "EXECUTOR_NOT_READY" || retry != 5*time.Second {
			t.Fatalf("release policy = %q %s", reason, retry)
		}
		return executionlease.Execution{ExecutionID: testJobID, Status: executionlease.StatusQueued, LeaseEpoch: 4}, nil
	}
	released, err := backend.ReleaseJob(context.Background(), identity, testJobID, testToken,
		runnergateway.JobReleaseRequest{LeaseEpoch: 4, ReasonCode: "EXECUTOR_NOT_READY"})
	if err != nil || released.Status != "QUEUED" || released.LeaseEpoch != 4 {
		t.Fatalf("ReleaseJob() = %#v, %v", released, err)
	}
	assertExpectations(t, database)
}

func TestStartIsAtomicAndNeverReissuesPreparedPermit(t *testing.T) {
	backend, database, identity, _ := newBackendFixture(t, config.WriteExecutionModeNonProduction)
	defer database.Close()
	credentialExpiry := testNow.Add(5 * time.Minute)
	backend.revocationIDSource = func() string { return testRevocationID }
	backend.startAuthorizer = func(_ context.Context, claimed execution.ClaimedAction) (StartAuthorization, error) {
		if claimed.Execution.LeaseToken != "" {
			t.Fatal("final authorizer received a reusable action token")
		}
		return StartAuthorization{IssuerID: "vault-non-production", IssuerRevision: "rev-1", CredentialExpiresAt: credentialExpiry}, nil
	}
	database.ExpectBegin()
	database.ExpectCommit()
	backend.operations.startJobTx = func(
		ctx context.Context, _ pgx.Tx, scope execution.RunnerScope, fence executionlease.LeaseIdentity,
		authorizer executionpostgres.RunnerStartAuthorizer,
	) (executionlease.Execution, error) {
		assertTrustedScope(t, scope)
		assertJobFence(t, fence, 4)
		if err := authorizer(ctx, execution.ClaimedAction{Execution: executionlease.Execution{ExecutionID: testJobID}}); err != nil {
			return executionlease.Execution{}, err
		}
		return executionlease.Execution{
			ExecutionID: testJobID, Status: executionlease.StatusRunning, LeaseEpoch: 4, StartedAt: testNow,
		}, nil
	}
	var returnedPermit *credential.ChildCreatePermit
	backend.operations.prepareJobTx = func(_ context.Context, _ pgx.Tx, scope execution.RunnerScope, request credential.PrepareRequest) (credential.PrepareResult, error) {
		assertTrustedScope(t, scope)
		if request.RevocationID != testRevocationID || request.Fence.RunnerID != testRunnerID ||
			request.Fence.Token != testToken || request.Issuer != "vault-non-production" ||
			request.IssuerRevision != "rev-1" || !request.CredentialExpiresAt.Equal(credentialExpiry) {
			t.Fatalf("PrepareRunnerTx request = %#v", request)
		}
		returnedPermit = &credential.ChildCreatePermit{RevocationID: testRevocationID, Token: testToken}
		return credential.PrepareResult{Created: true, Permit: returnedPermit, Revocation: credential.Revocation{
			ID: testRevocationID, Status: credential.StatusPrepared, CredentialExpiresAt: credentialExpiry,
		}}, nil
	}
	response, err := backend.StartJob(context.Background(), identity, testJobID, testToken,
		runnergateway.JobStartRequest{LeaseEpoch: 4})
	if err != nil || response.Status != "RUNNING" || response.CredentialPrepare.ChildCreatePermit != testToken ||
		response.CredentialPrepare.IssuerID != "vault-non-production" || response.CredentialPrepare.IssuerRevision != "rev-1" {
		t.Fatalf("StartJob() = %#v, %v", response, err)
	}
	if returnedPermit == nil || returnedPermit.Token != "" {
		t.Fatalf("local permit was not cleared: %#v", returnedPermit)
	}

	database.ExpectBegin()
	database.ExpectRollback()
	backend.operations.prepareJobTx = func(context.Context, pgx.Tx, execution.RunnerScope, credential.PrepareRequest) (credential.PrepareResult, error) {
		return credential.PrepareResult{Created: false, Revocation: credential.Revocation{
			ID: testRevocationID, Status: credential.StatusPrepared,
		}}, nil
	}
	response, err = backend.StartJob(context.Background(), identity, testJobID, testToken,
		runnergateway.JobStartRequest{LeaseEpoch: 4})
	if !errors.Is(err, runnergateway.ErrStateConflict) || response != (runnergateway.JobStartResponse{}) {
		t.Fatalf("StartJob(replay) = %#v, %v", response, err)
	}
	assertExpectations(t, database)
}

func TestStartWithoutAuthorizerAuthenticatesAndFailsClosed(t *testing.T) {
	backend, database, identity, _ := newBackendFixture(t, config.WriteExecutionModeNonProduction)
	defer database.Close()
	database.ExpectBegin()
	database.ExpectRollback()
	called := false
	backend.operations.startJobTx = func(context.Context, pgx.Tx, execution.RunnerScope, executionlease.LeaseIdentity, executionpostgres.RunnerStartAuthorizer) (executionlease.Execution, error) {
		called = true
		return executionlease.Execution{}, nil
	}
	_, err := backend.StartJob(context.Background(), identity, testJobID, testToken,
		runnergateway.JobStartRequest{LeaseEpoch: 4})
	if !errors.Is(err, runnergateway.ErrClaimsDisabled) || called {
		t.Fatalf("StartJob(no authorizer) error = %v; called=%t", err, called)
	}
	assertExpectations(t, database)
}

func TestDisabledModeCannotStartEvenWhenAuthorizerIsInjected(t *testing.T) {
	backend, database, identity, _ := newBackendFixture(t, config.WriteExecutionModeDisabled)
	defer database.Close()
	backend.startAuthorizer = func(context.Context, execution.ClaimedAction) (StartAuthorization, error) {
		t.Fatal("disabled mode invoked final start authorizer")
		return StartAuthorization{}, nil
	}
	startCalled := false
	backend.operations.startJobTx = func(context.Context, pgx.Tx, execution.RunnerScope, executionlease.LeaseIdentity, executionpostgres.RunnerStartAuthorizer) (executionlease.Execution, error) {
		startCalled = true
		return executionlease.Execution{}, nil
	}
	database.ExpectBegin()
	database.ExpectRollback()
	response, err := backend.StartJob(context.Background(), identity, testJobID, testToken,
		runnergateway.JobStartRequest{LeaseEpoch: 4})
	if !errors.Is(err, runnergateway.ErrClaimsDisabled) || startCalled || response.JobID != "" {
		t.Fatalf("StartJob(disabled) = %#v, %v; start called=%t", response, err, startCalled)
	}
	assertExpectations(t, database)
}

func TestCredentialAnchorFinalizesAuthorizationAfterCommitAndCommitsLateCleanup(t *testing.T) {
	backend, database, identity, _ := newBackendFixture(t, config.WriteExecutionModeDisabled)
	defer database.Close()
	ticket := &struct{}{}
	database.ExpectBegin()
	database.ExpectCommit()
	backend.operations.authorizeChild = func(_ context.Context, _ pgx.Tx, scope execution.RunnerScope, request credential.AuthorizeChildCreateRequest) (any, error) {
		assertTrustedScope(t, scope)
		if request.Permit.Token != testToken || request.Fence.RunnerID != testRunnerID {
			t.Fatalf("authorize request = %#v", request)
		}
		return ticket, nil
	}
	backend.operations.finalizeChild = func(got any) (credential.ChildCreateAuthorization, error) {
		if got != ticket {
			t.Fatal("finalizeChild received different ticket")
		}
		assertExpectations(t, database)
		return credential.ChildCreateAuthorization{
			Revocation:           credential.Revocation{ID: testRevocationID, Status: credential.StatusPrepared},
			DatabaseAuthorizedAt: testNow, CredentialExpiresAt: testNow.Add(time.Minute), TTL: 30 * time.Second,
		}, nil
	}
	response, err := backend.AnchorCredential(context.Background(), identity, testJobID, testToken,
		runnergateway.CredentialAnchorRequest{
			Phase: "AUTHORIZE_CHILD_CREATE", LeaseEpoch: 4, RevocationID: testRevocationID, ChildCreatePermit: testToken,
		})
	if err != nil || response.Status != "PREPARED" || response.ChildTTLSeconds != 30 || response.DatabaseAuthorizedAt == nil {
		t.Fatalf("AnchorCredential(authorize) = %#v, %v", response, err)
	}

	database.ExpectBegin()
	database.ExpectCommit()
	backend.operations.activateTx = func(_ context.Context, _ pgx.Tx, scope execution.RunnerScope, request credential.ActionTransitionRequest) (credential.Revocation, error) {
		assertTrustedScope(t, scope)
		if request.Fence.RunnerID != testRunnerID || request.Fence.Token != testToken {
			t.Fatalf("activate fence = %s", request.Fence.String())
		}
		return credential.Revocation{ID: testRevocationID, Status: credential.StatusRevocationPending}, nil
	}
	_, err = backend.AnchorCredential(context.Background(), identity, testJobID, testToken,
		runnergateway.CredentialAnchorRequest{Phase: "ACTIVATE", LeaseEpoch: 4, RevocationID: testRevocationID})
	if !errors.Is(err, runnergateway.ErrCredentialConflict) {
		t.Fatalf("AnchorCredential(late activation) error = %v", err)
	}
	assertExpectations(t, database)
}

func TestRecordAnchorDestroysDecodedAccessorBeforeCommit(t *testing.T) {
	backend, database, identity, _ := newBackendFixture(t, config.WriteExecutionModeDisabled)
	defer database.Close()
	database.ExpectBegin()
	database.ExpectCommit()
	var accessor *credential.SensitiveReference
	backend.operations.recordAnchorTx = func(_ context.Context, _ pgx.Tx, _ execution.RunnerScope, request credential.RecordAnchorRequest) (credential.Revocation, error) {
		accessor = request.Accessor
		if string(accessor.Bytes()) != "anchor-canary" {
			t.Fatalf("decoded accessor = %q", accessor.Bytes())
		}
		return credential.Revocation{ID: testRevocationID, Status: credential.StatusAnchored}, nil
	}
	response, err := backend.AnchorCredential(context.Background(), identity, testJobID, testToken,
		runnergateway.CredentialAnchorRequest{
			Phase: "RECORD_ANCHOR", LeaseEpoch: 4, RevocationID: testRevocationID,
			RevokeAccessorB64U: "YW5jaG9yLWNhbmFyeQ",
		})
	if err != nil || response.Status != "ANCHORED" {
		t.Fatalf("AnchorCredential(record) = %#v, %v", response, err)
	}
	if accessor == nil || len(accessor.Bytes()) != 0 {
		t.Fatalf("accessor retained after repository call: %q", accessor.Bytes())
	}
	assertExpectations(t, database)
}

func TestCompleteJobKeepsFinalizingUntilCleanupAndFinalizesUncertain(t *testing.T) {
	backend, database, identity, principal := newBackendFixture(t, config.WriteExecutionModeDisabled)
	defer database.Close()
	events := make([]string, 0, 3)
	backend.operations.completeJobTx = func(_ context.Context, _ pgx.Tx, scope execution.RunnerScope, fence executionlease.LeaseIdentity, _ execution.ExecutorResult, certificate string) (executionpostgres.RunnerCompletion, error) {
		assertTrustedScope(t, scope)
		assertJobFence(t, fence, 4)
		if certificate != principal.certificate {
			t.Fatalf("certificate = %q", certificate)
		}
		events = append(events, "receipt")
		return executionpostgres.RunnerCompletion{
			Execution: executionlease.Execution{ExecutionID: testJobID, Status: executionlease.StatusFinalizing, CompletionStatus: executionlease.StatusSucceeded},
			Receipt:   execution.RunnerResultReceipt{ResultHash: testReceiptHash},
		}, nil
	}
	backend.operations.cleanupJobTx = func(context.Context, pgx.Tx, execution.RunnerScope, executionlease.LeaseIdentity) (credentialpostgres.RunnerCompletionCleanup, error) {
		events = append(events, "cleanup")
		return credentialpostgres.RunnerCompletionCleanup{Revocation: credential.Revocation{
			ID: testRevocationID, Status: credential.StatusRevocationPending,
		}}, nil
	}
	backend.operations.finalizeJobTx = func(context.Context, pgx.Tx, execution.RunnerScope, executionlease.LeaseIdentity) (executionlease.Execution, error) {
		events = append(events, "finalize")
		return executionlease.Execution{}, nil
	}
	database.ExpectBegin()
	database.ExpectCommit()
	response, err := backend.CompleteJob(context.Background(), identity, testJobID, testToken,
		runnergateway.JobCompleteRequest{LeaseEpoch: 4, Result: execution.ExecutorResult{Outcome: execution.ExecutorSucceeded}})
	if err != nil || response.Status != "FINALIZING" || response.CredentialCleanupStatus != "PENDING" || strings.Join(events, ",") != "receipt,cleanup" {
		t.Fatalf("CompleteJob(pending) = %#v, %v; events=%v", response, err, events)
	}

	events = events[:0]
	backend.operations.completeJobTx = func(context.Context, pgx.Tx, execution.RunnerScope, executionlease.LeaseIdentity, execution.ExecutorResult, string) (executionpostgres.RunnerCompletion, error) {
		events = append(events, "receipt")
		return executionpostgres.RunnerCompletion{
			Execution: executionlease.Execution{ExecutionID: testJobID, Status: executionlease.StatusFinalizing, CompletionStatus: executionlease.StatusUncertain},
			Receipt:   execution.RunnerResultReceipt{ResultHash: testReceiptHash},
		}, nil
	}
	backend.operations.finalizeJobTx = func(context.Context, pgx.Tx, execution.RunnerScope, executionlease.LeaseIdentity) (executionlease.Execution, error) {
		events = append(events, "finalize")
		return executionlease.Execution{ExecutionID: testJobID, Status: executionlease.StatusUncertain, CompletionStatus: executionlease.StatusUncertain}, nil
	}
	database.ExpectBegin()
	database.ExpectCommit()
	response, err = backend.CompleteJob(context.Background(), identity, testJobID, testToken,
		runnergateway.JobCompleteRequest{LeaseEpoch: 4, Result: execution.ExecutorResult{Outcome: execution.ExecutorUncertain}})
	if err != nil || response.Status != "UNCERTAIN" || strings.Join(events, ",") != "receipt,cleanup,finalize" {
		t.Fatalf("CompleteJob(uncertain) = %#v, %v; events=%v", response, err, events)
	}
	assertExpectations(t, database)
}

func TestIdentityReauthenticatesInItsOwnTransaction(t *testing.T) {
	backend, database, identity, principal := newBackendFixture(t, config.WriteExecutionModeDisabled)
	defer database.Close()
	database.ExpectBegin()
	database.ExpectCommit()
	response, err := backend.Identity(context.Background(), identity)
	if err != nil || response.RunnerID != testRunnerID || response.ScopeRevision != 5 ||
		len(response.Capabilities) != 1 || response.Capabilities[0] != "CREDENTIAL_REVOCATION" ||
		response.CertificateSHA256 != principal.certificate {
		t.Fatalf("Identity() = %#v, %v", response, err)
	}
	assertExpectations(t, database)
}

func TestBackendErrorMappingIsBoundedAndDoesNotWrapDetails(t *testing.T) {
	tests := []struct {
		input error
		want  error
	}{
		{executionlease.ErrInvalidRequest, runnergateway.ErrInvalidRequest},
		{executionlease.ErrNotFound, runnergateway.ErrNotFound},
		{credential.ErrStaleClaim, runnergateway.ErrStaleLease},
		{execution.ErrHeartbeatSequence, runnergateway.ErrHeartbeatConflict},
		{credential.ErrCompletionConflict, runnergateway.ErrResultConflict},
		{credential.ErrInvalidTransition, runnergateway.ErrCredentialConflict},
		{execution.ErrCredentialCleanupPending, runnergateway.ErrStateConflict},
		{errors.New("SQL token accessor certificate canary"), runnergateway.ErrUnavailable},
		{errors.Join(errors.New("wrapped detail canary"), runnergateway.ErrForbidden), runnergateway.ErrForbidden},
	}
	for _, test := range tests {
		got := mapBackendError(test.input)
		if got != test.want || errors.Is(got, test.input) && test.input != test.want || strings.Contains(got.Error(), "canary") {
			t.Fatalf("mapBackendError(%v) = %v, want exact %v", test.input, got, test.want)
		}
	}
}

func newBackendFixture(
	t *testing.T,
	mode config.WriteExecutionMode,
) (*Backend, pgxmock.PgxPoolIface, runneridentity.Identity, testPrincipal) {
	t.Helper()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	identity := newTestIdentity(t)
	principal := testPrincipal{
		runnerID: testRunnerID, tenantID: testTenantID, pool: runneridentity.PoolWrite,
		scopeRevision: 5, maxConcurrency: 2, revocation: true,
		certificate: identity.Evidence().LeafSHA256(), notAfter: identity.Evidence().NotAfter(),
		bindings: []execution.RunnerScopeBinding{{WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID}},
	}
	backend := &Backend{
		database: database, mode: mode, revocationIDSource: func() string { return testRevocationID },
		operations: operations{authenticateTx: func(_ context.Context, tx pgx.Tx, got runneridentity.Identity) (authenticatedPrincipal, error) {
			if tx == nil || got.SPIFFEURI() != identity.SPIFFEURI() || got.Evidence().LeafSHA256() != identity.Evidence().LeafSHA256() {
				t.Fatal("backend authentication did not receive the certificate identity and caller-owned transaction")
			}
			return principal, nil
		}},
	}
	return backend, database, identity, principal
}

func newTestIdentity(t *testing.T) runneridentity.Identity {
	t.Helper()
	readCA, err := testpki.NewAuthority("read-root", testNow)
	if err != nil {
		t.Fatalf("NewAuthority(read) error = %v", err)
	}
	writeCA, err := testpki.NewAuthority("write-root", testNow)
	if err != nil {
		t.Fatalf("NewAuthority(write) error = %v", err)
	}
	spiffeURI, err := url.Parse("spiffe://aiops.example/runner/write/write-runner-01")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	client, err := writeCA.IssueClient(testpki.ClientOptions{URIs: []*url.URL{spiffeURI}}, testNow)
	if err != nil {
		t.Fatalf("IssueClient() error = %v", err)
	}
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readCA.Certificate},
		WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	chains, err := client.Leaf.Verify(x509.VerifyOptions{
		Roots: writeCA.CertPool(), CurrentTime: testNow, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("verify client error = %v", err)
	}
	identity, err := verifier.IdentityFromConnectionState(tls.ConnectionState{
		Version: tls.VersionTLS13, HandshakeComplete: true,
		PeerCertificates: []*x509.Certificate{client.Leaf, writeCA.Certificate}, VerifiedChains: chains,
	})
	if err != nil {
		t.Fatalf("IdentityFromConnectionState() error = %v", err)
	}
	return identity
}

func assertTrustedScope(t *testing.T, scope execution.RunnerScope) {
	t.Helper()
	if scope.RunnerID() != testRunnerID || scope.TenantID() != testTenantID || scope.ScopeRevision() != 5 ||
		scope.Pool() != executionlease.PoolWrite || len(scope.Bindings()) != 1 ||
		scope.Bindings()[0] != (execution.RunnerScopeBinding{WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID}) {
		t.Fatalf("scope = %#v", scope)
	}
}

func assertClaimFence(t *testing.T, fence credential.ClaimFence, epoch int64) {
	t.Helper()
	if fence.RevocationID != testRevocationID || fence.WorkerID != testRunnerID || fence.Token != testClaimToken || fence.Epoch != epoch {
		t.Fatalf("claim fence = %s", fence.String())
	}
}

func assertJobFence(t *testing.T, fence executionlease.LeaseIdentity, epoch int64) {
	t.Helper()
	if fence.ExecutionID != testJobID || fence.RunnerID != testRunnerID || fence.Token != testToken || fence.Epoch != epoch {
		t.Fatalf("job fence = %#v", fence)
	}
}

func assertExpectations(t *testing.T, database pgxmock.PgxPoolIface) {
	t.Helper()
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet PostgreSQL expectations: %v", err)
	}
}
