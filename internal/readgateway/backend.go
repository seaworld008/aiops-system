// Package readgateway composes authenticated READ Runner identity and task
// persistence inside one caller-owned PostgreSQL transaction.
package readgateway

import (
	"context"
	"errors"
	"reflect"
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
	claimLeaseDuration      = 30 * time.Second
	heartbeatLeaseExtension = 30 * time.Second
	rollbackTimeout         = 5 * time.Second
)

var (
	ErrInvalidConfiguration = errors.New("invalid read runner gateway configuration")
	ErrForbidden            = errors.New("read runner request forbidden")
	ErrUnavailable          = errors.New("read runner gateway unavailable")
	ErrInternal             = errors.New("read runner gateway internal failure")
)

// DB starts the transaction that owns both request authentication and the
// corresponding READ task mutation.
type DB interface {
	Begin(context.Context) (pgx.Tx, error)
}

type authenticatedRunner interface {
	ResponseBinding
	Valid() bool
	Pool() runneridentity.Pool
	RunnerScope() (execution.RunnerScope, error)
}

// ResponseBinding is the immutable authentication snapshot produced by the
// same transaction that performs a READ task operation. The HTTP layer uses
// it only to bind a successful response; request bodies cannot implement or
// replace the Backend's actual value.
type ResponseBinding interface {
	Valid() bool
	RunnerID() string
	TenantID() string
	Pool() runneridentity.Pool
	ScopeRevision() int64
	MaxConcurrency() int
	CredentialRevocationCapable() bool
	CertificateSHA256() string
	CertificateNotAfter() time.Time
	Allows(workspaceID, environmentID string) bool
}

// StartAuthorizer is the trusted server-side connector/operation/input check.
// It never receives a lease Fence or certificate material.
type StartAuthorizer = readtaskpostgres.StartAuthorizer

// CompletionAuthorizer validates connector-specific typed Evidence while the
// task remains locked. Its fence-free input prevents lease-token exposure.
type CompletionAuthorizer = readtaskpostgres.CompletionAuthorizer

// Dependencies bind the Backend to concrete PostgreSQL repositories. All
// three dependencies must point at the same database because Backend owns the
// one transaction shared by authentication and mutation.
type Dependencies struct {
	Database             DB
	Identities           *runneridentitypostgres.Repository
	Tasks                *readtaskpostgres.Repository
	ClaimsEnabled        bool
	StartAuthorizer      StartAuthorizer
	CompletionAuthorizer CompletionAuthorizer
}

type operations struct {
	authenticateTx func(context.Context, pgx.Tx, runneridentity.Identity) (authenticatedRunner, error)
	claimTx        func(context.Context, pgx.Tx, execution.RunnerScope, readtask.CertificateBinding, string, time.Duration) (readtask.Claim, error)
	startTx        func(context.Context, pgx.Tx, execution.RunnerScope, readtask.CertificateBinding, readtask.Start, StartAuthorizer) (readtask.Attempt, error)
	heartbeatTx    func(context.Context, pgx.Tx, execution.RunnerScope, readtask.CertificateBinding, readtask.Heartbeat, time.Duration) (readtask.HeartbeatResult, error)
	releaseTx      func(context.Context, pgx.Tx, execution.RunnerScope, readtask.CertificateBinding, readtask.Release) (readtask.Attempt, error)
	completeTx     func(context.Context, pgx.Tx, execution.RunnerScope, readtask.CertificateBinding, readtask.Completion, CompletionAuthorizer) (readtask.CompletionResult, error)
}

// Backend is the transaction boundary used by the READ Runner protocol.
type Backend struct {
	database             DB
	claimsEnabled        bool
	startAuthorizer      StartAuthorizer
	completionAuthorizer CompletionAuthorizer
	operations           operations
}

// New binds only transaction-scoped repository entrypoints. In particular,
// completion is wired to CompleteRunnerAuthorizedTx, so typed output admission
// cannot be bypassed.
func New(dependencies Dependencies) (*Backend, error) {
	if nilInterface(dependencies.Database) || dependencies.Identities == nil || dependencies.Tasks == nil ||
		dependencies.StartAuthorizer == nil || dependencies.CompletionAuthorizer == nil {
		return nil, ErrInvalidConfiguration
	}
	identities := dependencies.Identities
	tasks := dependencies.Tasks
	backend := &Backend{
		database: dependencies.Database, claimsEnabled: dependencies.ClaimsEnabled,
		startAuthorizer:      dependencies.StartAuthorizer,
		completionAuthorizer: dependencies.CompletionAuthorizer,
	}
	backend.operations = operations{
		authenticateTx: func(ctx context.Context, tx pgx.Tx, identity runneridentity.Identity) (authenticatedRunner, error) {
			principal, err := identities.AuthenticateTx(ctx, tx, identity)
			if err != nil {
				return nil, err
			}
			return principal, nil
		},
		claimTx:     tasks.ClaimRunnerTx,
		startTx:     tasks.StartRunnerAuthorizedTx,
		heartbeatTx: tasks.HeartbeatRunnerTx,
		releaseTx:   tasks.ReleaseRunnerTx,
		completeTx:  tasks.CompleteRunnerAuthorizedTx,
	}
	return backend, nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

type requestTransaction struct {
	tx          pgx.Tx
	scope       execution.RunnerScope
	certificate readtask.CertificateBinding
	binding     ResponseBinding
	committed   bool
}

func (transaction *requestTransaction) rollback(_ context.Context) {
	if transaction != nil && transaction.tx != nil && !transaction.committed {
		rollbackContext, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
		defer cancel()
		_ = transaction.tx.Rollback(rollbackContext)
	}
}

func (transaction *requestTransaction) commit(ctx context.Context) error {
	if transaction == nil || transaction.tx == nil || transaction.committed {
		return ErrUnavailable
	}
	if err := transaction.tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	transaction.committed = true
	return nil
}

func (backend *Backend) authenticatedTransaction(
	ctx context.Context,
	identity runneridentity.Identity,
) (*requestTransaction, error) {
	if backend == nil || backend.database == nil || backend.operations.authenticateTx == nil || ctx == nil {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrUnavailable
	}
	tx, err := backend.database.Begin(ctx)
	if err != nil {
		return nil, ErrUnavailable
	}
	if nilInterface(tx) {
		return nil, ErrUnavailable
	}
	transaction := &requestTransaction{tx: tx}
	principal, err := backend.operations.authenticateTx(ctx, tx, identity)
	if err != nil {
		transaction.rollback(ctx)
		if errors.Is(err, runneridentity.ErrAuthenticationFailed) {
			return nil, ErrForbidden
		}
		return nil, ErrUnavailable
	}
	if nilInterface(principal) || !principal.Valid() || principal.Pool() != runneridentity.PoolRead {
		transaction.rollback(ctx)
		return nil, ErrForbidden
	}
	scope, err := principal.RunnerScope()
	if err != nil || scope.Pool() != executionlease.PoolRead {
		transaction.rollback(ctx)
		return nil, ErrForbidden
	}
	certificate := readtask.CertificateBinding{
		SHA256: principal.CertificateSHA256(), NotAfter: principal.CertificateNotAfter().UTC(),
	}
	if certificate.Validate() != nil {
		transaction.rollback(ctx)
		return nil, ErrForbidden
	}
	transaction.scope = scope
	transaction.certificate = certificate
	transaction.binding = principal
	return transaction, nil
}

// Claim authenticates the mTLS identity and claims exactly the server-side
// task named by taskID. Lease duration, scope, Runner, and certificate are not
// caller-controlled.
func (backend *Backend) Claim(
	ctx context.Context,
	identity runneridentity.Identity,
	taskID string,
) (readtask.Claim, ResponseBinding, error) {
	transaction, err := backend.authenticatedTransaction(ctx, identity)
	if err != nil {
		return readtask.Claim{}, nil, err
	}
	defer transaction.rollback(ctx)
	if !backend.claimsEnabled {
		return readtask.Claim{}, nil, readtask.ErrClaimsDisabled
	}
	if backend.operations.claimTx == nil {
		return readtask.Claim{}, nil, ErrUnavailable
	}
	claim, err := backend.operations.claimTx(
		ctx, transaction.tx, transaction.scope, transaction.certificate, taskID, claimLeaseDuration,
	)
	if err != nil {
		claim.Destroy()
		return readtask.Claim{}, nil, mapTaskError(err)
	}
	if !claim.Valid() {
		claim.Destroy()
		return readtask.Claim{}, nil, ErrInternal
	}
	if err := transaction.commit(ctx); err != nil {
		claim.Destroy()
		return readtask.Claim{}, nil, err
	}
	return claim, transaction.binding, nil
}

// Start reruns the server-owned connector authorizer while the authenticated
// task transaction remains locked. A Runner cannot supply or replace it.
func (backend *Backend) Start(
	ctx context.Context,
	identity runneridentity.Identity,
	start readtask.Start,
) (readtask.Attempt, ResponseBinding, error) {
	transaction, err := backend.authenticatedTransaction(ctx, identity)
	if err != nil {
		return readtask.Attempt{}, nil, err
	}
	defer transaction.rollback(ctx)
	if backend.operations.startTx == nil || backend.startAuthorizer == nil {
		return readtask.Attempt{}, nil, ErrUnavailable
	}
	attempt, err := backend.operations.startTx(
		ctx, transaction.tx, transaction.scope, transaction.certificate, start, backend.startAuthorizer,
	)
	if err != nil {
		return readtask.Attempt{}, nil, mapTaskError(err)
	}
	if err := transaction.commit(ctx); err != nil {
		return readtask.Attempt{}, nil, err
	}
	return attempt, transaction.binding, nil
}

// Heartbeat applies the Gateway-owned extension; a Runner can submit only its
// fenced sequence, never an arbitrary lease duration.
func (backend *Backend) Heartbeat(
	ctx context.Context,
	identity runneridentity.Identity,
	heartbeat readtask.Heartbeat,
) (readtask.HeartbeatResult, ResponseBinding, error) {
	transaction, err := backend.authenticatedTransaction(ctx, identity)
	if err != nil {
		return readtask.HeartbeatResult{}, nil, err
	}
	defer transaction.rollback(ctx)
	if backend.operations.heartbeatTx == nil {
		return readtask.HeartbeatResult{}, nil, ErrUnavailable
	}
	result, err := backend.operations.heartbeatTx(
		ctx, transaction.tx, transaction.scope, transaction.certificate, heartbeat, heartbeatLeaseExtension,
	)
	if err != nil {
		return readtask.HeartbeatResult{}, nil, mapTaskError(err)
	}
	if err := transaction.commit(ctx); err != nil {
		return readtask.HeartbeatResult{}, nil, err
	}
	return result, transaction.binding, nil
}

// Release ends a pre-start attempt using only the freshly authenticated
// identity snapshot and the request's opaque Fence.
func (backend *Backend) Release(
	ctx context.Context,
	identity runneridentity.Identity,
	release readtask.Release,
) (readtask.Attempt, ResponseBinding, error) {
	transaction, err := backend.authenticatedTransaction(ctx, identity)
	if err != nil {
		return readtask.Attempt{}, nil, err
	}
	defer transaction.rollback(ctx)
	if backend.operations.releaseTx == nil {
		return readtask.Attempt{}, nil, ErrUnavailable
	}
	attempt, err := backend.operations.releaseTx(
		ctx, transaction.tx, transaction.scope, transaction.certificate, release,
	)
	if err != nil {
		return readtask.Attempt{}, nil, mapTaskError(err)
	}
	if err := transaction.commit(ctx); err != nil {
		return readtask.Attempt{}, nil, err
	}
	return attempt, transaction.binding, nil
}

// Complete validates typed Evidence through a server-owned authorizer and
// atomically persists the resulting terminal projection and receipt.
func (backend *Backend) Complete(
	ctx context.Context,
	identity runneridentity.Identity,
	completion readtask.Completion,
) (readtask.CompletionResult, ResponseBinding, error) {
	transaction, err := backend.authenticatedTransaction(ctx, identity)
	if err != nil {
		return readtask.CompletionResult{}, nil, err
	}
	defer transaction.rollback(ctx)
	if backend.operations.completeTx == nil || backend.completionAuthorizer == nil {
		return readtask.CompletionResult{}, nil, ErrUnavailable
	}
	result, err := backend.operations.completeTx(
		ctx, transaction.tx, transaction.scope, transaction.certificate, completion, backend.completionAuthorizer,
	)
	if err != nil {
		return readtask.CompletionResult{}, nil, mapTaskError(err)
	}
	if err := transaction.commit(ctx); err != nil {
		return readtask.CompletionResult{}, nil, err
	}
	return result, transaction.binding, nil
}

// mapTaskError strips repository, SQL, connector, and certificate detail while
// retaining the bounded domain condition needed by the protocol layer.
func mapTaskError(err error) error {
	switch {
	case err == nil:
		return nil
	// Repository class wrappers must win over their underlying causes. An
	// integrity wrapper can intentionally retain ErrInvalidRequest as its
	// diagnostic cause; exposing that cause as a Runner 400 would misclassify
	// a server-side invariant failure and encourage unsafe client correction.
	case errors.Is(err, readtask.ErrIntegrity):
		return ErrInternal
	case errors.Is(err, readtask.ErrPersistence), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return ErrUnavailable
	case errors.Is(err, readtask.ErrInvalidRequest):
		return readtask.ErrInvalidRequest
	case errors.Is(err, readtask.ErrNotFound):
		return readtask.ErrNotFound
	case errors.Is(err, readtask.ErrNoClaimAvailable):
		return readtask.ErrNoClaimAvailable
	case errors.Is(err, readtask.ErrClaimsDisabled):
		return readtask.ErrClaimsDisabled
	case errors.Is(err, readtask.ErrStaleFence):
		return readtask.ErrStaleFence
	case errors.Is(err, readtask.ErrInvalidTransition):
		return readtask.ErrInvalidTransition
	case errors.Is(err, readtask.ErrHeartbeatConflict):
		return readtask.ErrHeartbeatConflict
	case errors.Is(err, readtask.ErrCompletionConflict):
		return readtask.ErrCompletionConflict
	case errors.Is(err, readtask.ErrProjectionRejected):
		return readtask.ErrProjectionRejected
	case errors.Is(err, readtask.ErrSensitiveDestroyed):
		return readtask.ErrInvalidRequest
	default:
		return ErrInternal
	}
}
