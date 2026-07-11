// Package postgres binds the Runner Gateway protocol to the PostgreSQL
// repositories. Request identity is re-authenticated inside every transaction;
// no identity, scope, duration, issuer, or retry value is accepted from a
// Runner request body.
package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/seaworld008/aiops-system/internal/config"
	"github.com/seaworld008/aiops-system/internal/credential"
	credentialpostgres "github.com/seaworld008/aiops-system/internal/credential/postgres"
	"github.com/seaworld008/aiops-system/internal/execution"
	executionpostgres "github.com/seaworld008/aiops-system/internal/execution/postgres"
	"github.com/seaworld008/aiops-system/internal/executionlease"
	"github.com/seaworld008/aiops-system/internal/ids"
	"github.com/seaworld008/aiops-system/internal/runnergateway"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
	runneridentitypostgres "github.com/seaworld008/aiops-system/internal/runneridentity/postgres"
)

const (
	jobLeaseDuration      = 30 * time.Second
	jobHeartbeatExtension = 30 * time.Second
	jobHeartbeatInterval  = 10 * time.Second
	jobReleaseRetryDelay  = 5 * time.Second
)

// DB begins the caller-owned transaction used to authenticate and mutate one
// Runner request atomically. pgxpool.Pool satisfies this interface.
type DB interface {
	Begin(context.Context) (pgx.Tx, error)
}

// StartAuthorization is the non-secret issuer plan produced by a trusted,
// server-side final policy/target check. The absolute expiry is frozen in the
// same transaction as RUNNING and PREPARED.
type StartAuthorization struct {
	IssuerID            string
	IssuerRevision      string
	CredentialExpiresAt time.Time
}

// StartAuthorizer is invoked by StartRunnerAuthorizedTx while its action lock
// remains held. Implementations must be side-effect-free and must derive their
// result only from trusted control-plane state and the supplied signed action.
type StartAuthorizer func(context.Context, execution.ClaimedAction) (StartAuthorization, error)

// Dependencies are the concrete repositories sharing one PostgreSQL database.
// StartAuthorizer may be nil; in that state new job leases and starts fail
// closed while revocation recovery and draining existing jobs remain enabled.
type Dependencies struct {
	Database           DB
	Identities         *runneridentitypostgres.Repository
	Executions         *executionpostgres.Repository
	Credentials        *credentialpostgres.Repository
	WriteExecutionMode config.WriteExecutionMode
	StartAuthorizer    StartAuthorizer
	RevocationIDSource func() string
}

type authenticatedPrincipal interface {
	runnergateway.RequestPrincipal
	RunnerScope() (execution.RunnerScope, error)
}

type revocationClaimTicket interface {
	Discard()
}

type operations struct {
	authenticateTx func(context.Context, pgx.Tx, runneridentity.Identity) (authenticatedPrincipal, error)

	claimJobTx      func(context.Context, pgx.Tx, execution.RunnerScope, time.Duration) (execution.ClaimedAction, error)
	startJobTx      func(context.Context, pgx.Tx, execution.RunnerScope, executionlease.LeaseIdentity, executionpostgres.RunnerStartAuthorizer) (executionlease.Execution, error)
	heartbeatJobTx  func(context.Context, pgx.Tx, execution.RunnerScope, execution.ActionHeartbeatRequest) (execution.ActionHeartbeatResult, error)
	releaseJobTx    func(context.Context, pgx.Tx, execution.RunnerScope, executionlease.LeaseIdentity, string, time.Duration) (executionlease.Execution, error)
	completeJobTx   func(context.Context, pgx.Tx, execution.RunnerScope, executionlease.LeaseIdentity, execution.ExecutorResult, string) (executionpostgres.RunnerCompletion, error)
	finalizeJobTx   func(context.Context, pgx.Tx, execution.RunnerScope, executionlease.LeaseIdentity) (executionlease.Execution, error)
	prepareJobTx    func(context.Context, pgx.Tx, execution.RunnerScope, credential.PrepareRequest) (credential.PrepareResult, error)
	authorizeChild  func(context.Context, pgx.Tx, execution.RunnerScope, credential.AuthorizeChildCreateRequest) (any, error)
	finalizeChild   func(any) (credential.ChildCreateAuthorization, error)
	recordAnchorTx  func(context.Context, pgx.Tx, execution.RunnerScope, credential.RecordAnchorRequest) (credential.Revocation, error)
	activateTx      func(context.Context, pgx.Tx, execution.RunnerScope, credential.ActionTransitionRequest) (credential.Revocation, error)
	noCredentialTx  func(context.Context, pgx.Tx, execution.RunnerScope, credential.ActionTransitionRequest) (credential.Revocation, error)
	requestRevokeTx func(context.Context, pgx.Tx, execution.RunnerScope, credential.ActionTransitionRequest) (credential.Revocation, error)
	cleanupJobTx    func(context.Context, pgx.Tx, execution.RunnerScope, executionlease.LeaseIdentity) (credentialpostgres.RunnerCompletionCleanup, error)

	claimRevocationTx    func(context.Context, pgx.Tx, execution.RunnerScope, string) (revocationClaimTicket, error)
	finalizeRevocation   func(context.Context, revocationClaimTicket) (credential.ClaimedRevocation, error)
	heartbeatRevocation  func(context.Context, pgx.Tx, execution.RunnerScope, credential.ClaimFence, int64) (credential.RunnerRevocationHeartbeatResult, error)
	completeRevocationTx func(context.Context, pgx.Tx, execution.RunnerScope, credential.ClaimFence, credential.RunnerRevocationOutcome, credential.FailureCode, string) (credential.RunnerRevocationCompletionResult, error)
}

// Backend is the concrete PostgreSQL Runner Gateway backend.
type Backend struct {
	database           DB
	mode               config.WriteExecutionMode
	startAuthorizer    StartAuthorizer
	revocationIDSource func() string
	operations         operations
}

var _ runnergateway.Backend = (*Backend)(nil)

// New constructs a Backend from the concrete M3 repositories. All repository
// mutations continue to use the transaction begun by Backend.
func New(dependencies Dependencies) (*Backend, error) {
	if dependencies.Database == nil || dependencies.Identities == nil || dependencies.Executions == nil ||
		dependencies.Credentials == nil || !validMode(dependencies.WriteExecutionMode) {
		return nil, fmt.Errorf("invalid PostgreSQL Runner Gateway dependencies")
	}
	if dependencies.RevocationIDSource == nil {
		dependencies.RevocationIDSource = ids.NewUUID
	}

	identities := dependencies.Identities
	executions := dependencies.Executions
	credentials := dependencies.Credentials
	backend := &Backend{
		database: dependencies.Database, mode: dependencies.WriteExecutionMode,
		startAuthorizer: dependencies.StartAuthorizer, revocationIDSource: dependencies.RevocationIDSource,
	}
	backend.operations = operations{
		authenticateTx: func(ctx context.Context, tx pgx.Tx, identity runneridentity.Identity) (authenticatedPrincipal, error) {
			principal, err := identities.AuthenticateTx(ctx, tx, identity)
			if err != nil {
				return nil, err
			}
			return principal, nil
		},
		claimJobTx:     executions.ClaimRunnerTx,
		startJobTx:     executions.StartRunnerAuthorizedTx,
		heartbeatJobTx: executions.HeartbeatRunnerTx,
		releaseJobTx:   executions.ReleaseRunnerTx,
		completeJobTx:  executions.CompleteRunnerTx,
		finalizeJobTx:  executions.FinalizeRunnerTx,
		prepareJobTx:   credentials.PrepareRunnerTx,
		authorizeChild: func(ctx context.Context, tx pgx.Tx, scope execution.RunnerScope, request credential.AuthorizeChildCreateRequest) (any, error) {
			return credentials.AuthorizeChildCreateRunnerTx(ctx, tx, scope, request)
		},
		finalizeChild: func(ticket any) (credential.ChildCreateAuthorization, error) {
			typed, ok := ticket.(*credentialpostgres.RunnerChildCreateAuthorizationTicket)
			if !ok {
				return credential.ChildCreateAuthorization{}, credential.ErrInvalidRevocationRequest
			}
			return credentials.FinalizeChildCreateAuthorizationAfterCommit(typed)
		},
		recordAnchorTx:  credentials.RecordAnchorRunnerTx,
		activateTx:      credentials.ActivateRunnerTx,
		noCredentialTx:  credentials.RecordNoCredentialRunnerTx,
		requestRevokeTx: credentials.RequestRevocationRunnerTx,
		cleanupJobTx:    credentials.EnsureCompletionCleanupRunnerTx,
		claimRevocationTx: func(ctx context.Context, tx pgx.Tx, scope execution.RunnerScope, certificateSHA256 string) (revocationClaimTicket, error) {
			return credentials.ClaimRevocationRunnerTx(ctx, tx, scope, certificateSHA256)
		},
		finalizeRevocation: func(ctx context.Context, ticket revocationClaimTicket) (credential.ClaimedRevocation, error) {
			typed, ok := ticket.(*credentialpostgres.RunnerRevocationClaimTicket)
			if !ok {
				ticket.Discard()
				return credential.ClaimedRevocation{}, credential.ErrInvalidRevocationRequest
			}
			return credentials.FinalizeRevocationClaimAfterCommit(ctx, typed)
		},
		heartbeatRevocation:  credentials.HeartbeatRevocationRunnerTx,
		completeRevocationTx: credentials.CompleteRevocationRunnerTx,
	}
	return backend, nil
}

func validMode(mode config.WriteExecutionMode) bool {
	return mode == config.WriteExecutionModeDisabled || mode == config.WriteExecutionModeNonProduction
}

type requestTransaction struct {
	tx        pgx.Tx
	principal authenticatedPrincipal
	scope     execution.RunnerScope
	committed bool
}

func (transaction *requestTransaction) rollback(ctx context.Context) {
	if transaction != nil && transaction.tx != nil && !transaction.committed {
		_ = transaction.tx.Rollback(ctx)
	}
}

func (transaction *requestTransaction) commit(ctx context.Context) error {
	if transaction == nil || transaction.tx == nil || transaction.committed {
		return runnergateway.ErrUnavailable
	}
	if err := transaction.tx.Commit(ctx); err != nil {
		return runnergateway.ErrUnavailable
	}
	transaction.committed = true
	return nil
}

func (backend *Backend) authenticatedTransaction(
	ctx context.Context,
	identity runneridentity.Identity,
) (*requestTransaction, error) {
	if backend == nil || backend.database == nil || backend.operations.authenticateTx == nil || ctx == nil || !identity.Valid() {
		return nil, runnergateway.ErrForbidden
	}
	if err := ctx.Err(); err != nil {
		return nil, runnergateway.ErrUnavailable
	}
	tx, err := backend.database.Begin(ctx)
	if err != nil {
		return nil, runnergateway.ErrUnavailable
	}
	transaction := &requestTransaction{tx: tx}
	principal, err := backend.operations.authenticateTx(ctx, tx, identity)
	if err != nil {
		transaction.rollback(ctx)
		return nil, mapAuthenticationError(err)
	}
	if principal == nil || !principal.Valid() {
		transaction.rollback(ctx)
		return nil, runnergateway.ErrForbidden
	}
	scope, err := principal.RunnerScope()
	if err != nil {
		transaction.rollback(ctx)
		return nil, runnergateway.ErrForbidden
	}
	transaction.principal = principal
	transaction.scope = scope
	return transaction, nil
}

func (backend *Backend) AuthenticateRequest(
	ctx context.Context,
	identity runneridentity.Identity,
) (runnergateway.RequestPrincipal, error) {
	transaction, err := backend.authenticatedTransaction(ctx, identity)
	if err != nil {
		return nil, err
	}
	defer transaction.rollback(ctx)
	if err := transaction.commit(ctx); err != nil {
		return nil, err
	}
	return transaction.principal, nil
}

func (backend *Backend) Identity(
	ctx context.Context,
	identity runneridentity.Identity,
) (runnergateway.RunnerIdentityResponse, error) {
	transaction, err := backend.authenticatedTransaction(ctx, identity)
	if err != nil {
		return runnergateway.RunnerIdentityResponse{}, err
	}
	defer transaction.rollback(ctx)
	capabilities := make([]string, 0, 1)
	if transaction.principal.CredentialRevocationCapable() {
		capabilities = append(capabilities, "CREDENTIAL_REVOCATION")
	}
	response := runnergateway.RunnerIdentityResponse{
		SchemaVersion: "runner-identity-response.v1", RunnerID: transaction.principal.RunnerID(),
		Pool:           string(transaction.principal.Pool()),
		ScopeRevision:  runnergateway.DecimalInt64(transaction.principal.ScopeRevision()),
		MaxConcurrency: transaction.principal.MaxConcurrency(), Capabilities: capabilities,
		CertificateSHA256:   transaction.principal.CertificateSHA256(),
		CertificateNotAfter: transaction.principal.CertificateNotAfter().UTC(),
	}
	if err := transaction.commit(ctx); err != nil {
		return runnergateway.RunnerIdentityResponse{}, err
	}
	return response, nil
}

func (backend *Backend) LeaseJob(
	ctx context.Context,
	identity runneridentity.Identity,
	_ runnergateway.JobLeaseRequest,
) (*runnergateway.JobLeaseResponse, error) {
	transaction, err := backend.authenticatedTransaction(ctx, identity)
	if err != nil {
		return nil, err
	}
	defer transaction.rollback(ctx)
	if err := requireWrite(transaction.principal); err != nil {
		return nil, err
	}
	if backend.mode != config.WriteExecutionModeNonProduction || backend.startAuthorizer == nil {
		return nil, runnergateway.ErrClaimsDisabled
	}
	claimed, err := backend.operations.claimJobTx(ctx, transaction.tx, transaction.scope, jobLeaseDuration)
	if errors.Is(err, executionlease.ErrNoLeaseAvailable) {
		return nil, nil
	}
	if err != nil {
		return nil, mapBackendError(err)
	}
	if claimed.Production || claimed.Execution.Production || claimed.Execution.LeaseToken == "" {
		return nil, runnergateway.ErrStateConflict
	}
	response := &runnergateway.JobLeaseResponse{
		SchemaVersion: "runner-job-lease-response.v1",
		Job: runnergateway.JobDescriptor{
			ID: claimed.Execution.ExecutionID, Kind: "WRITE_ACTION", Payload: claimed.Envelope,
			PlanHash: claimed.PlanHash, EnvironmentRevision: claimed.EnvironmentRevision, Production: false,
		},
		LeaseToken: claimed.Execution.LeaseToken, LeaseEpoch: runnergateway.DecimalInt64(claimed.Execution.LeaseEpoch),
		ScopeRevision:         runnergateway.DecimalInt64(transaction.scope.ScopeRevision()),
		LeaseExpiresAt:        claimed.Execution.LeaseExpiresAt.UTC(),
		HeartbeatAfterSeconds: int(jobHeartbeatInterval / time.Second),
	}
	if err := transaction.commit(ctx); err != nil {
		response.LeaseToken = ""
		return nil, err
	}
	return response, nil
}

func (backend *Backend) StartJob(
	ctx context.Context,
	identity runneridentity.Identity,
	jobID, token string,
	request runnergateway.JobStartRequest,
) (runnergateway.JobStartResponse, error) {
	transaction, err := backend.authenticatedTransaction(ctx, identity)
	if err != nil {
		return runnergateway.JobStartResponse{}, err
	}
	defer transaction.rollback(ctx)
	if err := requireWrite(transaction.principal); err != nil {
		return runnergateway.JobStartResponse{}, err
	}
	if backend.mode != config.WriteExecutionModeNonProduction || backend.startAuthorizer == nil ||
		backend.revocationIDSource == nil {
		return runnergateway.JobStartResponse{}, runnergateway.ErrClaimsDisabled
	}
	revocationID := backend.revocationIDSource()
	if !credential.ValidRevocationID(revocationID) {
		return runnergateway.JobStartResponse{}, runnergateway.ErrUnavailable
	}
	fence := executionlease.LeaseIdentity{
		ExecutionID: jobID, RunnerID: transaction.scope.RunnerID(), Token: token, Epoch: request.LeaseEpoch.Int64(),
	}
	var authorization StartAuthorization
	started, err := backend.operations.startJobTx(ctx, transaction.tx, transaction.scope, fence,
		func(callbackContext context.Context, claimed execution.ClaimedAction) error {
			candidate, authorizeErr := backend.startAuthorizer(callbackContext, claimed)
			if authorizeErr != nil {
				return authorizeErr
			}
			if !validStartAuthorization(candidate) {
				return executionlease.ErrInvalidRequest
			}
			authorization = candidate
			return nil
		})
	if err != nil {
		return runnergateway.JobStartResponse{}, mapBackendError(err)
	}
	if !validStartAuthorization(authorization) {
		return runnergateway.JobStartResponse{}, runnergateway.ErrUnavailable
	}
	prepared, err := backend.operations.prepareJobTx(ctx, transaction.tx, transaction.scope, credential.PrepareRequest{
		RevocationID: revocationID,
		Fence: credential.ActionFence{
			ActionID: jobID, RunnerID: transaction.scope.RunnerID(), Token: token, Epoch: request.LeaseEpoch.Int64(),
		},
		Issuer: authorization.IssuerID, IssuerRevision: authorization.IssuerRevision,
		CredentialExpiresAt: authorization.CredentialExpiresAt,
	})
	if err != nil {
		return runnergateway.JobStartResponse{}, mapBackendError(err)
	}
	// A retry after a committed-but-lost start response observes Created=false.
	// It must never receive another child-create permit.
	if !prepared.Created || prepared.Permit == nil || prepared.Permit.Token == "" ||
		prepared.Revocation.Status != credential.StatusPrepared {
		return runnergateway.JobStartResponse{}, runnergateway.ErrStateConflict
	}
	response := runnergateway.JobStartResponse{
		SchemaVersion: "runner-job-start-response.v1", JobID: jobID, Status: string(started.Status),
		LeaseEpoch:    runnergateway.DecimalInt64(started.LeaseEpoch),
		ScopeRevision: runnergateway.DecimalInt64(transaction.scope.ScopeRevision()), StartedAt: started.StartedAt.UTC(),
		CredentialPrepare: runnergateway.CredentialPrepare{
			RevocationID: prepared.Revocation.ID, ChildCreatePermit: prepared.Permit.Token,
			IssuerID: authorization.IssuerID, IssuerRevision: authorization.IssuerRevision,
			CredentialExpiresAt: prepared.Revocation.CredentialExpiresAt.UTC(),
		},
	}
	if err := transaction.commit(ctx); err != nil {
		prepared.Permit.Token = ""
		prepared.Permit = nil
		response.CredentialPrepare.ChildCreatePermit = ""
		return runnergateway.JobStartResponse{}, err
	}
	prepared.Permit.Token = ""
	prepared.Permit = nil
	return response, nil
}

func validStartAuthorization(authorization StartAuthorization) bool {
	return credential.ValidIdentifier(authorization.IssuerID, 256) &&
		credential.ValidIdentifier(authorization.IssuerRevision, 256) &&
		!authorization.CredentialExpiresAt.IsZero() && authorization.CredentialExpiresAt.Year() >= 1 &&
		authorization.CredentialExpiresAt.Year() <= 9999
}

func (backend *Backend) HeartbeatJob(
	ctx context.Context,
	identity runneridentity.Identity,
	jobID, token string,
	request runnergateway.JobHeartbeatRequest,
) (runnergateway.JobHeartbeatResponse, error) {
	transaction, err := backend.authenticatedTransaction(ctx, identity)
	if err != nil {
		return runnergateway.JobHeartbeatResponse{}, err
	}
	defer transaction.rollback(ctx)
	if err := requireWrite(transaction.principal); err != nil {
		return runnergateway.JobHeartbeatResponse{}, err
	}
	result, err := backend.operations.heartbeatJobTx(ctx, transaction.tx, transaction.scope, execution.ActionHeartbeatRequest{
		Lease: executionlease.LeaseIdentity{
			ExecutionID: jobID, RunnerID: transaction.scope.RunnerID(), Token: token, Epoch: request.LeaseEpoch.Int64(),
		},
		Sequence: request.Sequence.Int64(), Extension: jobHeartbeatExtension,
	})
	if err != nil {
		return runnergateway.JobHeartbeatResponse{}, mapBackendError(err)
	}
	response := runnergateway.JobHeartbeatResponse{
		SchemaVersion: "runner-job-heartbeat-response.v1", JobID: jobID,
		AcceptedSequence: runnergateway.DecimalInt64(request.Sequence.Int64()), Directive: string(result.Directive),
		LeaseExpiresAt:        result.Execution.LeaseExpiresAt.UTC(),
		HeartbeatAfterSeconds: int(jobHeartbeatInterval / time.Second),
	}
	if err := transaction.commit(ctx); err != nil {
		return runnergateway.JobHeartbeatResponse{}, err
	}
	return response, nil
}

func (backend *Backend) ReleaseJob(
	ctx context.Context,
	identity runneridentity.Identity,
	jobID, token string,
	request runnergateway.JobReleaseRequest,
) (runnergateway.JobStateResponse, error) {
	transaction, err := backend.authenticatedTransaction(ctx, identity)
	if err != nil {
		return runnergateway.JobStateResponse{}, err
	}
	defer transaction.rollback(ctx)
	if err := requireWrite(transaction.principal); err != nil {
		return runnergateway.JobStateResponse{}, err
	}
	released, err := backend.operations.releaseJobTx(ctx, transaction.tx, transaction.scope, executionlease.LeaseIdentity{
		ExecutionID: jobID, RunnerID: transaction.scope.RunnerID(), Token: token, Epoch: request.LeaseEpoch.Int64(),
	}, request.ReasonCode, jobReleaseRetryDelay)
	if err != nil {
		return runnergateway.JobStateResponse{}, mapBackendError(err)
	}
	response := runnergateway.JobStateResponse{
		SchemaVersion: "runner-job-state-response.v1", JobID: jobID,
		Status: string(released.Status), LeaseEpoch: runnergateway.DecimalInt64(released.LeaseEpoch),
	}
	if err := transaction.commit(ctx); err != nil {
		return runnergateway.JobStateResponse{}, err
	}
	return response, nil
}

func (backend *Backend) CompleteJob(
	ctx context.Context,
	identity runneridentity.Identity,
	jobID, token string,
	request runnergateway.JobCompleteRequest,
) (runnergateway.JobCompletionResponse, error) {
	transaction, err := backend.authenticatedTransaction(ctx, identity)
	if err != nil {
		return runnergateway.JobCompletionResponse{}, err
	}
	defer transaction.rollback(ctx)
	if err := requireWrite(transaction.principal); err != nil {
		return runnergateway.JobCompletionResponse{}, err
	}
	fence := executionlease.LeaseIdentity{
		ExecutionID: jobID, RunnerID: transaction.scope.RunnerID(), Token: token, Epoch: request.LeaseEpoch.Int64(),
	}
	completion, err := backend.operations.completeJobTx(
		ctx, transaction.tx, transaction.scope, fence, request.Result, transaction.principal.CertificateSHA256(),
	)
	if err != nil {
		return runnergateway.JobCompletionResponse{}, mapBackendError(err)
	}
	state := completion.Execution
	cleanupStatus := "TERMINAL"
	if state.Terminal() && state.Status == executionlease.StatusUncertain {
		// UNCERTAIN deliberately remains a target lock even after action
		// finalization; credential cleanup can still be pending asynchronously.
		cleanupStatus = "PENDING"
	}
	if !state.Terminal() {
		cleanup, cleanupErr := backend.operations.cleanupJobTx(ctx, transaction.tx, transaction.scope, fence)
		if cleanupErr != nil {
			return runnergateway.JobCompletionResponse{}, mapBackendError(cleanupErr)
		}
		cleanupStatus = runnerCleanupStatus(cleanup)
		if cleanup.Terminal || state.CompletionStatus == executionlease.StatusUncertain {
			state, err = backend.operations.finalizeJobTx(ctx, transaction.tx, transaction.scope, fence)
			if err != nil {
				return runnergateway.JobCompletionResponse{}, mapBackendError(err)
			}
		}
	}
	response := runnergateway.JobCompletionResponse{
		SchemaVersion: "runner-job-completion-response.v1", JobID: jobID,
		Status: string(state.Status), CompletionStatus: string(completion.Execution.CompletionStatus),
		ReceiptHash: completion.Receipt.ResultHash, CredentialCleanupStatus: cleanupStatus,
	}
	if err := transaction.commit(ctx); err != nil {
		return runnergateway.JobCompletionResponse{}, err
	}
	return response, nil
}

func runnerCleanupStatus(cleanup credentialpostgres.RunnerCompletionCleanup) string {
	if cleanup.Terminal {
		return "TERMINAL"
	}
	if cleanup.Revocation.ID == "" {
		return "NOT_REQUIRED"
	}
	if cleanup.Revocation.Status == credential.StatusManualRequired {
		return "MANUAL_REQUIRED"
	}
	return "PENDING"
}

func (backend *Backend) AnchorCredential(
	ctx context.Context,
	identity runneridentity.Identity,
	jobID, token string,
	request runnergateway.CredentialAnchorRequest,
) (runnergateway.CredentialAnchorResponse, error) {
	transaction, err := backend.authenticatedTransaction(ctx, identity)
	if err != nil {
		return runnergateway.CredentialAnchorResponse{}, err
	}
	defer transaction.rollback(ctx)
	if err := requireWrite(transaction.principal); err != nil {
		return runnergateway.CredentialAnchorResponse{}, err
	}
	fence := credential.ActionFence{
		ActionID: jobID, RunnerID: transaction.scope.RunnerID(), Token: token, Epoch: request.LeaseEpoch.Int64(),
	}
	transition := credential.ActionTransitionRequest{RevocationID: request.RevocationID, Fence: fence}
	response := runnergateway.CredentialAnchorResponse{
		SchemaVersion: "runner-credential-anchor-response.v1", JobID: jobID, RevocationID: request.RevocationID,
	}

	switch request.Phase {
	case "AUTHORIZE_CHILD_CREATE":
		ticket, authorizeErr := backend.operations.authorizeChild(ctx, transaction.tx, transaction.scope,
			credential.AuthorizeChildCreateRequest{
				Permit: credential.ChildCreatePermit{RevocationID: request.RevocationID, Token: request.ChildCreatePermit},
				Fence:  fence,
			})
		request.ChildCreatePermit = ""
		if authorizeErr != nil {
			return runnergateway.CredentialAnchorResponse{}, mapBackendError(authorizeErr)
		}
		if err := transaction.commit(ctx); err != nil {
			return runnergateway.CredentialAnchorResponse{}, err
		}
		authorization, finalizeErr := backend.operations.finalizeChild(ticket)
		if finalizeErr != nil {
			return runnergateway.CredentialAnchorResponse{}, mapBackendError(finalizeErr)
		}
		databaseAuthorizedAt := authorization.DatabaseAuthorizedAt.UTC()
		credentialExpiresAt := authorization.CredentialExpiresAt.UTC()
		response.Status = string(authorization.Revocation.Status)
		response.DatabaseAuthorizedAt = &databaseAuthorizedAt
		response.ChildTTLSeconds = int(authorization.TTL / time.Second)
		response.CredentialExpiresAt = &credentialExpiresAt
		return response, nil

	case "RECORD_ANCHOR":
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(request.RevokeAccessorB64U)
		request.RevokeAccessorB64U = ""
		if decodeErr != nil {
			clear(decoded)
			return runnergateway.CredentialAnchorResponse{}, runnergateway.ErrInvalidRequest
		}
		accessor, referenceErr := credential.NewSensitiveReference(decoded)
		clear(decoded)
		if referenceErr != nil {
			return runnergateway.CredentialAnchorResponse{}, runnergateway.ErrInvalidRequest
		}
		defer accessor.Destroy()
		revocation, anchorErr := backend.operations.recordAnchorTx(ctx, transaction.tx, transaction.scope,
			credential.RecordAnchorRequest{RevocationID: request.RevocationID, Fence: fence, Accessor: accessor})
		if anchorErr != nil {
			return runnergateway.CredentialAnchorResponse{}, mapBackendError(anchorErr)
		}
		if err := transaction.commit(ctx); err != nil {
			return runnergateway.CredentialAnchorResponse{}, err
		}
		if revocation.Status != credential.StatusAnchored && revocation.Status != credential.StatusActive {
			return runnergateway.CredentialAnchorResponse{}, runnergateway.ErrCredentialConflict
		}
		response.Status = string(revocation.Status)
		return response, nil

	case "ACTIVATE":
		revocation, transitionErr := backend.operations.activateTx(ctx, transaction.tx, transaction.scope, transition)
		if transitionErr != nil {
			return runnergateway.CredentialAnchorResponse{}, mapBackendError(transitionErr)
		}
		if err := transaction.commit(ctx); err != nil {
			return runnergateway.CredentialAnchorResponse{}, err
		}
		if revocation.Status != credential.StatusActive {
			return runnergateway.CredentialAnchorResponse{}, runnergateway.ErrCredentialConflict
		}
		response.Status = string(revocation.Status)
		return response, nil

	case "NO_CREDENTIAL":
		revocation, transitionErr := backend.operations.noCredentialTx(ctx, transaction.tx, transaction.scope, transition)
		if transitionErr != nil {
			return runnergateway.CredentialAnchorResponse{}, mapBackendError(transitionErr)
		}
		response.Status = string(revocation.Status)

	case "REQUEST_REVOCATION":
		revocation, transitionErr := backend.operations.requestRevokeTx(ctx, transaction.tx, transaction.scope, transition)
		if transitionErr != nil {
			return runnergateway.CredentialAnchorResponse{}, mapBackendError(transitionErr)
		}
		response.Status = string(revocation.Status)

	default:
		return runnergateway.CredentialAnchorResponse{}, runnergateway.ErrInvalidRequest
	}
	if err := transaction.commit(ctx); err != nil {
		return runnergateway.CredentialAnchorResponse{}, err
	}
	return response, nil
}

func (backend *Backend) LeaseRevocation(
	ctx context.Context,
	identity runneridentity.Identity,
	_ runnergateway.RevocationLeaseRequest,
) (*runnergateway.RevocationLeaseResponse, error) {
	transaction, err := backend.authenticatedTransaction(ctx, identity)
	if err != nil {
		return nil, err
	}
	defer transaction.rollback(ctx)
	if err := requireRevocation(transaction.principal); err != nil {
		return nil, err
	}
	ticket, err := backend.operations.claimRevocationTx(
		ctx, transaction.tx, transaction.scope, transaction.principal.CertificateSHA256(),
	)
	if err != nil {
		return nil, mapBackendError(err)
	}
	if ticket != nil {
		defer ticket.Discard()
	}
	// A nil ticket can still contain a durable poison-reference alert and claim;
	// it must be committed instead of treated as a read-only miss.
	if err := transaction.commit(ctx); err != nil {
		return nil, err
	}
	if ticket == nil {
		return nil, nil
	}
	claim, err := backend.operations.finalizeRevocation(ctx, ticket)
	if err != nil {
		return nil, mapBackendError(err)
	}
	if claim.Accessor == nil || !validRevocationClaim(transaction.principal, claim) {
		if claim.Accessor != nil {
			claim.Accessor.Destroy()
		}
		claim.Fence.Token = ""
		return nil, runnergateway.ErrUnavailable
	}
	defer claim.Accessor.Destroy()
	accessorBytes := claim.Accessor.Bytes()
	if len(accessorBytes) == 0 || len(accessorBytes) > 4096 {
		clear(accessorBytes)
		claim.Fence.Token = ""
		return nil, runnergateway.ErrUnavailable
	}
	encodedAccessor := base64.RawURLEncoding.EncodeToString(accessorBytes)
	clear(accessorBytes)
	response := &runnergateway.RevocationLeaseResponse{
		SchemaVersion: "runner-revocation-lease-response.v1",
		RevocationID:  claim.Revocation.ID, ClaimToken: claim.Fence.Token,
		ClaimEpoch: runnergateway.DecimalInt64(claim.Fence.Epoch), ClaimExpiresAt: claim.Revocation.ClaimExpiresAt.UTC(),
		HeartbeatAfterSeconds: int(credential.RevocationHeartbeatInterval / time.Second),
		TenantID:              claim.Revocation.TenantID, WorkspaceID: claim.Revocation.WorkspaceID,
		EnvironmentID: claim.Revocation.EnvironmentID, IssuerID: claim.Revocation.Issuer,
		IssuerRevision: claim.Revocation.IssuerRevision, RevokeAccessorB64U: encodedAccessor,
	}
	claim.Fence.Token = ""
	return response, nil
}

func (backend *Backend) HeartbeatRevocation(
	ctx context.Context,
	identity runneridentity.Identity,
	revocationID, token string,
	request runnergateway.RevocationHeartbeatRequest,
) (runnergateway.RevocationHeartbeatResponse, error) {
	transaction, err := backend.authenticatedTransaction(ctx, identity)
	if err != nil {
		return runnergateway.RevocationHeartbeatResponse{}, err
	}
	defer transaction.rollback(ctx)
	if err := requireRevocation(transaction.principal); err != nil {
		return runnergateway.RevocationHeartbeatResponse{}, err
	}
	result, err := backend.operations.heartbeatRevocation(ctx, transaction.tx, transaction.scope, credential.ClaimFence{
		RevocationID: revocationID, WorkerID: transaction.scope.RunnerID(), Token: token, Epoch: request.ClaimEpoch.Int64(),
	}, request.Sequence.Int64())
	if err != nil {
		return runnergateway.RevocationHeartbeatResponse{}, mapBackendError(err)
	}
	response := runnergateway.RevocationHeartbeatResponse{
		SchemaVersion: "runner-revocation-heartbeat-response.v1", RevocationID: revocationID,
		AcceptedSequence: runnergateway.DecimalInt64(request.Sequence.Int64()), Directive: string(result.Directive),
		ClaimExpiresAt:        result.ClaimExpiresAt.UTC(),
		HeartbeatAfterSeconds: int(credential.RevocationHeartbeatInterval / time.Second),
	}
	if err := transaction.commit(ctx); err != nil {
		return runnergateway.RevocationHeartbeatResponse{}, err
	}
	return response, nil
}

func (backend *Backend) CompleteRevocation(
	ctx context.Context,
	identity runneridentity.Identity,
	revocationID, token string,
	request runnergateway.RevocationCompleteRequest,
) (runnergateway.RevocationCompletionResponse, error) {
	transaction, err := backend.authenticatedTransaction(ctx, identity)
	if err != nil {
		return runnergateway.RevocationCompletionResponse{}, err
	}
	defer transaction.rollback(ctx)
	if err := requireRevocation(transaction.principal); err != nil {
		return runnergateway.RevocationCompletionResponse{}, err
	}
	result, err := backend.operations.completeRevocationTx(ctx, transaction.tx, transaction.scope, credential.ClaimFence{
		RevocationID: revocationID, WorkerID: transaction.scope.RunnerID(), Token: token, Epoch: request.ClaimEpoch.Int64(),
	}, credential.RunnerRevocationOutcome(request.Outcome), credential.FailureCode(request.FailureCode),
		transaction.principal.CertificateSHA256())
	if err != nil {
		return runnergateway.RevocationCompletionResponse{}, mapBackendError(err)
	}
	response := runnergateway.RevocationCompletionResponse{
		SchemaVersion: "runner-revocation-completion-response.v1", RevocationID: revocationID,
		Status: string(result.Revocation.Status), ClaimEpoch: runnergateway.DecimalInt64(request.ClaimEpoch.Int64()),
	}
	if result.Revocation.Status == credential.StatusRevocationPending {
		availableAt := result.Revocation.AvailableAt.UTC()
		response.AvailableAt = &availableAt
	}
	if err := transaction.commit(ctx); err != nil {
		return runnergateway.RevocationCompletionResponse{}, err
	}
	return response, nil
}

func requireWrite(principal authenticatedPrincipal) error {
	if principal == nil || !principal.Valid() || principal.Pool() != runneridentity.PoolWrite {
		return runnergateway.ErrForbidden
	}
	return nil
}

func requireRevocation(principal authenticatedPrincipal) error {
	if err := requireWrite(principal); err != nil || !principal.CredentialRevocationCapable() {
		return runnergateway.ErrForbidden
	}
	return nil
}

func validRevocationClaim(principal authenticatedPrincipal, claim credential.ClaimedRevocation) bool {
	return principal != nil && principal.Valid() && claim.Revocation.ID == claim.Fence.RevocationID &&
		claim.Revocation.TenantID == principal.TenantID() &&
		principal.Allows(claim.Revocation.WorkspaceID, claim.Revocation.EnvironmentID) &&
		claim.Revocation.Status == credential.StatusRevoking && claim.Revocation.ClaimEpoch == claim.Fence.Epoch &&
		claim.Fence.WorkerID == principal.RunnerID() && claim.Fence.Token != "" && claim.Fence.Epoch > 0 &&
		claim.Revocation.Issuer != "" && claim.Revocation.IssuerRevision != "" &&
		!claim.Revocation.ClaimExpiresAt.IsZero()
}

func mapAuthenticationError(err error) error {
	if errors.Is(err, runneridentity.ErrAuthenticationFailed) {
		return runnergateway.ErrForbidden
	}
	return runnergateway.ErrUnavailable
}

// mapBackendError collapses repository and database detail into the bounded
// protocol error set. It intentionally never wraps the source error because it
// may contain SQL, certificate, token, or upstream detail.
func mapBackendError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, runnergateway.ErrInvalidRequest):
		return runnergateway.ErrInvalidRequest
	case errors.Is(err, runnergateway.ErrLeaseAuthentication):
		return runnergateway.ErrLeaseAuthentication
	case errors.Is(err, runnergateway.ErrForbidden):
		return runnergateway.ErrForbidden
	case errors.Is(err, runnergateway.ErrNotFound):
		return runnergateway.ErrNotFound
	case errors.Is(err, runnergateway.ErrStaleLease):
		return runnergateway.ErrStaleLease
	case errors.Is(err, runnergateway.ErrStateConflict):
		return runnergateway.ErrStateConflict
	case errors.Is(err, runnergateway.ErrHeartbeatConflict):
		return runnergateway.ErrHeartbeatConflict
	case errors.Is(err, runnergateway.ErrCredentialConflict):
		return runnergateway.ErrCredentialConflict
	case errors.Is(err, runnergateway.ErrResultConflict):
		return runnergateway.ErrResultConflict
	case errors.Is(err, runnergateway.ErrRateLimited):
		return runnergateway.ErrRateLimited
	case errors.Is(err, runnergateway.ErrClaimsDisabled):
		return runnergateway.ErrClaimsDisabled
	case errors.Is(err, runnergateway.ErrUnavailable):
		return runnergateway.ErrUnavailable
	case errors.Is(err, executionlease.ErrInvalidRequest),
		errors.Is(err, credential.ErrInvalidRevocationRequest):
		return runnergateway.ErrInvalidRequest
	case errors.Is(err, executionlease.ErrNotFound),
		errors.Is(err, execution.ErrJobNotFound),
		errors.Is(err, credential.ErrRevocationNotFound):
		return runnergateway.ErrNotFound
	case errors.Is(err, executionlease.ErrStaleLease),
		errors.Is(err, credential.ErrStaleActionFence),
		errors.Is(err, credential.ErrStaleClaim),
		errors.Is(err, credential.ErrStaleChildCreatePermit):
		return runnergateway.ErrStaleLease
	case errors.Is(err, execution.ErrHeartbeatSequence):
		return runnergateway.ErrHeartbeatConflict
	case errors.Is(err, executionlease.ErrCompletionConflict),
		errors.Is(err, credential.ErrCompletionConflict):
		return runnergateway.ErrResultConflict
	case errors.Is(err, executionlease.ErrInvalidTransition),
		errors.Is(err, execution.ErrJobConflict),
		errors.Is(err, execution.ErrCredentialCleanupPending):
		return runnergateway.ErrStateConflict
	case errors.Is(err, credential.ErrIdempotencyConflict),
		errors.Is(err, credential.ErrInvalidTransition),
		errors.Is(err, credential.ErrChildCreateAlreadyAuthorized),
		errors.Is(err, credential.ErrChildCreateWindowExpired):
		return runnergateway.ErrCredentialConflict
	case errors.Is(err, execution.ErrClaimsDisabled), errors.Is(err, executionlease.ErrClaimBlocked):
		return runnergateway.ErrClaimsDisabled
	default:
		return runnergateway.ErrUnavailable
	}
}
