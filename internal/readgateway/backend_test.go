package readgateway

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executionlease"
	"github.com/seaworld008/aiops-system/internal/readtask"
	readtaskpostgres "github.com/seaworld008/aiops-system/internal/readtask/postgres"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
	runneridentitypostgres "github.com/seaworld008/aiops-system/internal/runneridentity/postgres"
)

const (
	testTenantID      = "10000000-0000-4000-8000-000000000001"
	testWorkspaceID   = "20000000-0000-4000-8000-000000000002"
	testEnvironmentID = "30000000-0000-4000-8000-000000000003"
	testServiceID     = "35000000-0000-4000-8000-000000000003"
	testTaskID        = "60000000-0000-4000-8000-000000000006"
	testIncidentID    = "40000000-0000-4000-8000-000000000004"
	testInvestigation = "50000000-0000-4000-8000-000000000005"
	testRunnerID      = "read-runner-01"
	testCertificate   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var testCertificateNotAfter = time.Date(2026, time.July, 12, 13, 0, 0, 0, time.UTC)

type recordingDB struct {
	events *[]string
	tx     pgx.Tx
	err    error
}

func (database *recordingDB) Begin(context.Context) (pgx.Tx, error) {
	*database.events = append(*database.events, "begin")
	return database.tx, database.err
}

type recordingTx struct {
	pgx.Tx
	events      *[]string
	commitError error
}

func (transaction *recordingTx) Commit(context.Context) error {
	*transaction.events = append(*transaction.events, "commit")
	return transaction.commitError
}

func (transaction *recordingTx) Rollback(context.Context) error {
	*transaction.events = append(*transaction.events, "rollback")
	return nil
}

type testPrincipal struct {
	pool        runneridentity.Pool
	scope       execution.RunnerScope
	certificate string
	notAfter    time.Time
}

func (principal testPrincipal) Valid() bool               { return true }
func (principal testPrincipal) Pool() runneridentity.Pool { return principal.pool }
func (principal testPrincipal) RunnerID() string          { return principal.scope.RunnerID() }
func (principal testPrincipal) TenantID() string          { return principal.scope.TenantID() }
func (principal testPrincipal) ScopeRevision() int64      { return principal.scope.ScopeRevision() }
func (principal testPrincipal) MaxConcurrency() int       { return principal.scope.MaxConcurrency() }
func (testPrincipal) CredentialRevocationCapable() bool   { return false }
func (principal testPrincipal) Allows(workspaceID, environmentID string) bool {
	for _, binding := range principal.scope.Bindings() {
		if binding.WorkspaceID == workspaceID && binding.EnvironmentID == environmentID {
			return true
		}
	}
	return false
}
func (principal testPrincipal) RunnerScope() (execution.RunnerScope, error) {
	return principal.scope, nil
}
func (principal testPrincipal) CertificateSHA256() string      { return principal.certificate }
func (principal testPrincipal) CertificateNotAfter() time.Time { return principal.notAfter }

func TestClaimAuthenticatesAndMutatesInOneTransaction(t *testing.T) {
	events := make([]string, 0, 4)
	tx := &recordingTx{events: &events}
	principal := newTestPrincipal(t, runneridentity.PoolRead)
	backend := &Backend{
		database: &recordingDB{events: &events, tx: tx}, claimsEnabled: true,
		operations: operations{
			authenticateTx: func(context.Context, pgx.Tx, runneridentity.Identity) (authenticatedRunner, error) {
				events = append(events, "authenticate")
				return principal, nil
			},
			claimTx: func(
				_ context.Context,
				gotTx pgx.Tx,
				scope execution.RunnerScope,
				certificate readtask.CertificateBinding,
				taskID string,
				duration time.Duration,
			) (readtask.Claim, error) {
				events = append(events, "claim")
				if gotTx != tx {
					t.Fatal("Claim 使用了不同事务")
				}
				assertDerivedIdentity(t, scope, certificate)
				if taskID != testTaskID || duration != claimLeaseDuration {
					t.Fatalf("Claim 参数 = task %q, duration %s", taskID, duration)
				}
				return newTestClaim(t), nil
			},
		},
	}

	claim, binding, err := backend.Claim(context.Background(), runneridentity.Identity{}, testTaskID)
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	defer claim.Destroy()
	if binding == nil || binding.RunnerID() != testRunnerID || binding.ScopeRevision() != 7 {
		t.Fatalf("Claim() response binding = %#v", binding)
	}
	if want := []string{"begin", "authenticate", "claim", "commit"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("事件顺序 = %v，期望 %v", events, want)
	}
}

func TestNewBindsOnlyAuthorizedRepositoryEntrypoints(t *testing.T) {
	events := make([]string, 0)
	database := &recordingDB{events: &events, tx: &recordingTx{events: &events}}
	identities, err := runneridentitypostgres.New(database)
	if err != nil {
		t.Fatalf("runneridentitypostgres.New() error = %v", err)
	}
	tasks, err := readtaskpostgres.New(database, readtaskpostgres.Options{
		TokenSource: func() ([]byte, error) { return make([]byte, 32), nil },
		IDSource:    func() string { return testTaskID },
	})
	if err != nil {
		t.Fatalf("readtaskpostgres.New() error = %v", err)
	}
	dependencies := Dependencies{
		Database: database, Identities: identities, Tasks: tasks, ClaimsEnabled: true,
		StartAuthorizer:      func(context.Context, readtask.Descriptor) error { return nil },
		CompletionAuthorizer: func(context.Context, readtask.Descriptor, readtask.EvidenceCompletion) error { return nil },
	}
	backend, err := New(dependencies)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if backend.operations.authenticateTx == nil || backend.operations.claimTx == nil || backend.operations.startTx == nil ||
		backend.operations.heartbeatTx == nil || backend.operations.releaseTx == nil || backend.operations.completeTx == nil {
		t.Fatal("New() 未绑定全部 authenticated/authorized Tx 入口")
	}

	withoutStart := dependencies
	withoutStart.StartAuthorizer = nil
	if candidate, candidateErr := New(withoutStart); candidate != nil || !errors.Is(candidateErr, ErrInvalidConfiguration) {
		t.Fatalf("New(without StartAuthorizer) = %#v, %v", candidate, candidateErr)
	}
	withoutCompletion := dependencies
	withoutCompletion.CompletionAuthorizer = nil
	if candidate, candidateErr := New(withoutCompletion); candidate != nil || !errors.Is(candidateErr, ErrInvalidConfiguration) {
		t.Fatalf("New(without CompletionAuthorizer) = %#v, %v", candidate, candidateErr)
	}
}

func TestStartUsesTrustedAuthorizerInAuthenticatedTransaction(t *testing.T) {
	events := make([]string, 0, 5)
	tx := &recordingTx{events: &events}
	principal := newTestPrincipal(t, runneridentity.PoolRead)
	authorizer := func(context.Context, readtask.Descriptor) error {
		events = append(events, "authorize")
		return nil
	}
	backend := &Backend{
		database:        &recordingDB{events: &events, tx: tx},
		startAuthorizer: authorizer,
		operations: operations{
			authenticateTx: func(context.Context, pgx.Tx, runneridentity.Identity) (authenticatedRunner, error) {
				events = append(events, "authenticate")
				return principal, nil
			},
			startTx: func(
				_ context.Context,
				gotTx pgx.Tx,
				scope execution.RunnerScope,
				certificate readtask.CertificateBinding,
				_ readtask.Start,
				gotAuthorizer StartAuthorizer,
			) (readtask.Attempt, error) {
				events = append(events, "start")
				if gotTx != tx {
					t.Fatal("Start 使用了不同事务")
				}
				assertDerivedIdentity(t, scope, certificate)
				if gotAuthorizer == nil {
					t.Fatal("Start 未收到可信 authorizer")
				}
				if err := gotAuthorizer(context.Background(), readtask.Descriptor{}); err != nil {
					t.Fatalf("authorizer error = %v", err)
				}
				return readtask.Attempt{}, nil
			},
		},
	}

	if _, _, err := backend.Start(context.Background(), runneridentity.Identity{}, readtask.Start{}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if want := []string{"begin", "authenticate", "start", "authorize", "commit"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("事件顺序 = %v，期望 %v", events, want)
	}
}

func TestHeartbeatUsesGatewayLeaseExtensionInAuthenticatedTransaction(t *testing.T) {
	events := make([]string, 0, 4)
	tx := &recordingTx{events: &events}
	principal := newTestPrincipal(t, runneridentity.PoolRead)
	backend := &Backend{
		database: &recordingDB{events: &events, tx: tx}, claimsEnabled: true,
		operations: operations{
			authenticateTx: func(context.Context, pgx.Tx, runneridentity.Identity) (authenticatedRunner, error) {
				events = append(events, "authenticate")
				return principal, nil
			},
			heartbeatTx: func(
				_ context.Context,
				gotTx pgx.Tx,
				scope execution.RunnerScope,
				certificate readtask.CertificateBinding,
				_ readtask.Heartbeat,
				extension time.Duration,
			) (readtask.HeartbeatResult, error) {
				events = append(events, "heartbeat")
				if gotTx != tx {
					t.Fatal("Heartbeat 使用了不同事务")
				}
				assertDerivedIdentity(t, scope, certificate)
				if extension != heartbeatLeaseExtension {
					t.Fatalf("Heartbeat extension = %s", extension)
				}
				return readtask.HeartbeatResult{}, nil
			},
		},
	}

	if _, _, err := backend.Heartbeat(context.Background(), runneridentity.Identity{}, readtask.Heartbeat{}); err != nil {
		t.Fatalf("Heartbeat() error = %v", err)
	}
	if want := []string{"begin", "authenticate", "heartbeat", "commit"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("事件顺序 = %v，期望 %v", events, want)
	}
}

func TestReleaseUsesOnlyAuthenticatedIdentitySnapshot(t *testing.T) {
	events := make([]string, 0, 4)
	tx := &recordingTx{events: &events}
	principal := newTestPrincipal(t, runneridentity.PoolRead)
	backend := &Backend{
		database: &recordingDB{events: &events, tx: tx},
		operations: operations{
			authenticateTx: func(context.Context, pgx.Tx, runneridentity.Identity) (authenticatedRunner, error) {
				events = append(events, "authenticate")
				return principal, nil
			},
			releaseTx: func(
				_ context.Context,
				gotTx pgx.Tx,
				scope execution.RunnerScope,
				certificate readtask.CertificateBinding,
				_ readtask.Release,
			) (readtask.Attempt, error) {
				events = append(events, "release")
				if gotTx != tx {
					t.Fatal("Release 使用了不同事务")
				}
				assertDerivedIdentity(t, scope, certificate)
				return readtask.Attempt{}, nil
			},
		},
	}

	if _, _, err := backend.Release(context.Background(), runneridentity.Identity{}, readtask.Release{}); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if want := []string{"begin", "authenticate", "release", "commit"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("事件顺序 = %v，期望 %v", events, want)
	}
}

func TestCompleteUsesTrustedTypedOutputAuthorizerInAuthenticatedTransaction(t *testing.T) {
	events := make([]string, 0, 5)
	tx := &recordingTx{events: &events}
	principal := newTestPrincipal(t, runneridentity.PoolRead)
	authorizer := func(context.Context, readtask.Descriptor, readtask.EvidenceCompletion) error {
		events = append(events, "authorize-output")
		return nil
	}
	backend := &Backend{
		database:             &recordingDB{events: &events, tx: tx},
		completionAuthorizer: authorizer,
		operations: operations{
			authenticateTx: func(context.Context, pgx.Tx, runneridentity.Identity) (authenticatedRunner, error) {
				events = append(events, "authenticate")
				return principal, nil
			},
			completeTx: func(
				_ context.Context,
				gotTx pgx.Tx,
				scope execution.RunnerScope,
				certificate readtask.CertificateBinding,
				_ readtask.Completion,
				gotAuthorizer CompletionAuthorizer,
			) (readtask.CompletionResult, error) {
				events = append(events, "complete")
				if gotTx != tx {
					t.Fatal("Complete 使用了不同事务")
				}
				assertDerivedIdentity(t, scope, certificate)
				if gotAuthorizer == nil {
					t.Fatal("Complete 未收到可信 typed-output authorizer")
				}
				if err := gotAuthorizer(context.Background(), readtask.Descriptor{}, readtask.EvidenceCompletion{}); err != nil {
					t.Fatalf("completion authorizer error = %v", err)
				}
				return readtask.CompletionResult{}, nil
			},
		},
	}

	if _, _, err := backend.Complete(context.Background(), runneridentity.Identity{}, readtask.Completion{}); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if want := []string{"begin", "authenticate", "complete", "authorize-output", "commit"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("事件顺序 = %v，期望 %v", events, want)
	}
}

func TestWriteIdentityRollsBackBeforeReadTaskOperation(t *testing.T) {
	events := make([]string, 0, 3)
	tx := &recordingTx{events: &events}
	principal := newTestPrincipal(t, runneridentity.PoolWrite)
	called := false
	backend := &Backend{
		database: &recordingDB{events: &events, tx: tx},
		operations: operations{
			authenticateTx: func(context.Context, pgx.Tx, runneridentity.Identity) (authenticatedRunner, error) {
				events = append(events, "authenticate")
				return principal, nil
			},
			claimTx: func(context.Context, pgx.Tx, execution.RunnerScope, readtask.CertificateBinding, string, time.Duration) (readtask.Claim, error) {
				called = true
				return readtask.Claim{}, nil
			},
		},
	}

	claim, _, err := backend.Claim(context.Background(), runneridentity.Identity{}, testTaskID)
	if claim.Valid() || !errors.Is(err, ErrForbidden) || called {
		t.Fatalf("Claim(WRITE) = %v, %v；operation called=%t", claim, err, called)
	}
	if want := []string{"begin", "authenticate", "rollback"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("事件顺序 = %v，期望 %v", events, want)
	}
}

func TestAuthenticationFailureRollsBackAndDoesNotLeakCause(t *testing.T) {
	events := make([]string, 0, 3)
	tx := &recordingTx{events: &events}
	backend := &Backend{
		database: &recordingDB{events: &events, tx: tx},
		operations: operations{
			authenticateTx: func(context.Context, pgx.Tx, runneridentity.Identity) (authenticatedRunner, error) {
				events = append(events, "authenticate")
				return nil, fmt.Errorf("certificate canary: %w", runneridentity.ErrAuthenticationFailed)
			},
		},
	}

	_, _, err := backend.Claim(context.Background(), runneridentity.Identity{}, testTaskID)
	if !errors.Is(err, ErrForbidden) || err.Error() != ErrForbidden.Error() {
		t.Fatalf("Claim(authentication failure) error = %v", err)
	}
	if want := []string{"begin", "authenticate", "rollback"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("事件顺序 = %v，期望 %v", events, want)
	}
}

func TestTaskErrorRollsBackAndPreservesBoundedDomainError(t *testing.T) {
	events := make([]string, 0, 4)
	tx := &recordingTx{events: &events}
	principal := newTestPrincipal(t, runneridentity.PoolRead)
	backend := &Backend{
		database: &recordingDB{events: &events, tx: tx}, claimsEnabled: true,
		operations: operations{
			authenticateTx: func(context.Context, pgx.Tx, runneridentity.Identity) (authenticatedRunner, error) {
				events = append(events, "authenticate")
				return principal, nil
			},
			claimTx: func(context.Context, pgx.Tx, execution.RunnerScope, readtask.CertificateBinding, string, time.Duration) (readtask.Claim, error) {
				events = append(events, "claim")
				return readtask.Claim{}, fmt.Errorf("safe wrapper: %w", readtask.ErrNoClaimAvailable)
			},
		},
	}

	_, _, err := backend.Claim(context.Background(), runneridentity.Identity{}, testTaskID)
	if !errors.Is(err, readtask.ErrNoClaimAvailable) || err.Error() != readtask.ErrNoClaimAvailable.Error() {
		t.Fatalf("Claim() error = %v", err)
	}
	if want := []string{"begin", "authenticate", "claim", "rollback"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("事件顺序 = %v，期望 %v", events, want)
	}
}

func TestClaimFailsClosedWhenContractsAreNotEnabled(t *testing.T) {
	events := make([]string, 0, 3)
	tx := &recordingTx{events: &events}
	principal := newTestPrincipal(t, runneridentity.PoolRead)
	called := false
	backend := &Backend{
		database: &recordingDB{events: &events, tx: tx},
		operations: operations{
			authenticateTx: func(context.Context, pgx.Tx, runneridentity.Identity) (authenticatedRunner, error) {
				events = append(events, "authenticate")
				return principal, nil
			},
			claimTx: func(context.Context, pgx.Tx, execution.RunnerScope, readtask.CertificateBinding, string, time.Duration) (readtask.Claim, error) {
				called = true
				return newTestClaim(t), nil
			},
		},
	}

	claim, _, err := backend.Claim(context.Background(), runneridentity.Identity{}, testTaskID)
	if claim.Valid() || !errors.Is(err, readtask.ErrClaimsDisabled) || called {
		t.Fatalf("Claim(disabled) = %v, %v; operation called=%t", claim, err, called)
	}
	if want := []string{"begin", "authenticate", "rollback"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("事件顺序 = %v，期望 %v", events, want)
	}
}

func TestClaimRejectsInvalidRepositoryProjectionBeforeCommit(t *testing.T) {
	events := make([]string, 0, 4)
	tx := &recordingTx{events: &events}
	principal := newTestPrincipal(t, runneridentity.PoolRead)
	backend := &Backend{
		database: &recordingDB{events: &events, tx: tx}, claimsEnabled: true,
		operations: operations{
			authenticateTx: func(context.Context, pgx.Tx, runneridentity.Identity) (authenticatedRunner, error) {
				events = append(events, "authenticate")
				return principal, nil
			},
			claimTx: func(context.Context, pgx.Tx, execution.RunnerScope, readtask.CertificateBinding, string, time.Duration) (readtask.Claim, error) {
				events = append(events, "claim")
				return readtask.Claim{}, nil
			},
		},
	}

	claim, _, err := backend.Claim(context.Background(), runneridentity.Identity{}, testTaskID)
	if claim.Valid() || !errors.Is(err, ErrInternal) {
		t.Fatalf("Claim(invalid projection) = %v, %v", claim, err)
	}
	if want := []string{"begin", "authenticate", "claim", "rollback"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("事件顺序 = %v，期望 %v", events, want)
	}
}

func TestTaskErrorSeparatesDependencyFailureFromIntegrityFailure(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{"database dependency", fmt.Errorf("database canary: %w", readtask.ErrPersistence), ErrUnavailable},
		{"repository integrity", fmt.Errorf("projection canary: %w", readtask.ErrIntegrity), ErrInternal},
		{"integrity wrapper wins over invalid cause", errors.Join(readtask.ErrIntegrity, readtask.ErrInvalidRequest), ErrInternal},
		{"unknown invariant", errors.New("unexpected invariant canary"), ErrInternal},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := mapTaskError(test.err)
			if !errors.Is(got, test.want) || got.Error() != test.want.Error() {
				t.Fatalf("mapTaskError(%v) = %v, want exact %v", test.err, got, test.want)
			}
			if strings.Contains(got.Error(), "canary") {
				t.Fatalf("mapTaskError leaked cause: %v", got)
			}
		})
	}
}

func TestClaimCommitFailureRollsBackAndDestroysBearer(t *testing.T) {
	events := make([]string, 0, 5)
	tx := &recordingTx{events: &events, commitError: errors.New("ambiguous commit canary")}
	principal := newTestPrincipal(t, runneridentity.PoolRead)
	claim := newTestClaim(t)
	backend := &Backend{
		database: &recordingDB{events: &events, tx: tx}, claimsEnabled: true,
		operations: operations{
			authenticateTx: func(context.Context, pgx.Tx, runneridentity.Identity) (authenticatedRunner, error) {
				events = append(events, "authenticate")
				return principal, nil
			},
			claimTx: func(context.Context, pgx.Tx, execution.RunnerScope, readtask.CertificateBinding, string, time.Duration) (readtask.Claim, error) {
				events = append(events, "claim")
				return claim, nil
			},
		},
	}

	returned, _, err := backend.Claim(context.Background(), runneridentity.Identity{}, testTaskID)
	if returned.Valid() || !errors.Is(err, ErrUnavailable) || claim.Valid() {
		t.Fatalf("Claim(commit failure) = %v, %v；source valid=%t", returned, err, claim.Valid())
	}
	if want := []string{"begin", "authenticate", "claim", "commit", "rollback"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("事件顺序 = %v，期望 %v", events, want)
	}
}

func newTestPrincipal(t *testing.T, pool runneridentity.Pool) testPrincipal {
	t.Helper()
	scopePool := executionlease.PoolRead
	if pool == runneridentity.PoolWrite {
		scopePool = executionlease.PoolWrite
	}
	scope, err := (execution.RunnerRegistration{
		RunnerID: testRunnerID, TenantID: testTenantID, Pool: scopePool, Enabled: true,
		ScopeRevision: 7, MaxConcurrency: 3,
		ScopeBindings: []execution.RunnerScopeBinding{{WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID}},
	}).Scope()
	if err != nil {
		t.Fatalf("RunnerRegistration.Scope() error = %v", err)
	}
	return testPrincipal{
		pool: pool, scope: scope, certificate: testCertificate, notAfter: testCertificateNotAfter,
	}
}

func assertDerivedIdentity(t *testing.T, scope execution.RunnerScope, certificate readtask.CertificateBinding) {
	t.Helper()
	if scope.RunnerID() != testRunnerID || scope.TenantID() != testTenantID ||
		scope.Pool() != executionlease.PoolRead || scope.ScopeRevision() != 7 || scope.MaxConcurrency() != 3 {
		t.Fatalf("scope = %#v", scope)
	}
	if certificate.SHA256 != testCertificate || !certificate.NotAfter.Equal(testCertificateNotAfter) {
		t.Fatalf("certificate = %#v", certificate)
	}
}

func newTestClaim(t *testing.T) readtask.Claim {
	t.Helper()
	input := []byte(`{"query":"health"}`)
	inputDigest := sha256.Sum256(input)
	descriptor := readtask.Descriptor{
		TenantID: testTenantID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID,
		ServiceID:  testServiceID,
		IncidentID: testIncidentID, InvestigationID: testInvestigation, TaskID: testTaskID,
		TaskKey: "health", Position: 1, ConnectorID: "prometheus", Operation: "query",
		Input: input, InputHash: hex.EncodeToString(inputDigest[:]),
	}
	raw := make([]byte, 32)
	token := []byte(base64.RawURLEncoding.EncodeToString(raw))
	tokenDigest := sha256.Sum256(token)
	now := testCertificateNotAfter.Add(-time.Hour)
	attempt := readtask.Attempt{
		TaskID: testTaskID, RunnerID: testRunnerID, ScopeRevision: 7,
		Certificate: readtask.CertificateBinding{SHA256: testCertificate, NotAfter: testCertificateNotAfter},
		TokenSHA256: hex.EncodeToString(tokenDigest[:]), Epoch: 1, Status: readtask.AttemptLeased,
		LeaseAcquiredAt: now, LastHeartbeatAt: now, LeaseExpiresAt: now.Add(30 * time.Second), UpdatedAt: now,
	}
	claim, err := readtask.NewClaim(descriptor, attempt, token)
	clear(raw)
	clear(token)
	if err != nil {
		t.Fatalf("readtask.NewClaim() error = %v", err)
	}
	return claim
}
