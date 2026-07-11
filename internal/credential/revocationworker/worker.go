// Package revocationworker drains durable child-credential revocations without
// exposing issuer credentials or accepting caller-selected revocation targets.
package revocationworker

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"io"
	"math/big"
	"reflect"
	"regexp"
	"time"

	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/credential/vault"
)

var (
	ErrInvalidRegistry      = errors.New("invalid credential revoker registry")
	ErrRevokerNotRegistered = errors.New("credential revoker is not registered")
	ErrInvalidWorker        = errors.New("invalid credential revocation worker")
	ErrRecoveryFailed       = errors.New("credential revocation recovery failed")
	ErrClaimFailed          = errors.New("credential revocation claim failed")
	ErrClaimDeferred        = errors.New("credential revocation claim deferred")

	exactIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$`)
)

const (
	defaultRecoveryLimit = 100
	// The worker processes revocations serially. Claiming more than one would
	// leave later plaintext accessors idle while their leases age, so the batch
	// size is intentionally fixed at one until concurrent isolated workers exist.
	defaultClaimLimit = 1
)

// Revoker has only the revoke-accessor capability. Implementations must make
// repeated calls for an already revoked accessor succeed.
type Revoker interface {
	RevokeAccessor(context.Context, *credential.SensitiveReference) error
}

var _ Revoker = (*vault.RevocationClient)(nil)

// RevokerIdentity is built exclusively from the durable revocation record.
// It deliberately has no address, namespace, path, or request-body field.
type RevokerIdentity struct {
	TenantID       string
	WorkspaceID    string
	EnvironmentID  string
	IssuerID       string
	IssuerRevision string
}

type Registration struct {
	Identity RevokerIdentity
	Revoker  Revoker
}

// Repository is intentionally narrower than credential.Repository so the
// worker process cannot issue, activate, or manually requeue credentials.
type Repository interface {
	RecoverPrepared(context.Context, credential.RecoverPreparedRequest) ([]credential.Revocation, error)
	RecoverManaged(context.Context, credential.RecoverManagedRequest) ([]credential.Revocation, error)
	RecoverExhausted(context.Context, credential.RecoverExhaustedRequest) ([]credential.Revocation, error)
	ClaimRevocations(context.Context, credential.ClaimRevocationsRequest) ([]credential.ClaimedRevocation, error)
	Heartbeat(context.Context, credential.HeartbeatRequest) (credential.Revocation, error)
	CompleteRevocation(context.Context, credential.CompleteRevocationRequest) (credential.Revocation, error)
	RetryRevocation(context.Context, credential.RetryRevocationRequest) (credential.Revocation, error)
	RequireManual(context.Context, credential.RequireManualRequest) (credential.Revocation, error)
}

type Options struct {
	WorkerID      string
	RecoveryLimit int
	ClaimLimit    int
}

// RunResult is deliberately low-cardinality and contains no action, profile,
// claim, failure-body, or credential material.
type RunResult struct {
	PreparedRecovered  int `json:"prepared_recovered"`
	ManagedRecovered   int `json:"managed_recovered"`
	ExhaustedRecovered int `json:"exhausted_recovered"`
	Claimed            int `json:"claimed"`
	Revoked            int `json:"revoked"`
	Retried            int `json:"retried"`
	ManualRequired     int `json:"manual_required"`
	Deferred           int `json:"deferred"`
}

type Worker struct {
	repository Repository
	registry   *Registry
	workerID   string

	recoveryLimit     int
	claimLimit        int
	claimLease        time.Duration
	heartbeatInterval time.Duration
	remoteTimeout     time.Duration
	remoteSlot        chan struct{}
	random            io.Reader
	newTicker         func(time.Duration) heartbeatTicker
	after             func(time.Duration) <-chan time.Time
}

type heartbeatTicker interface {
	Chan() <-chan time.Time
	Stop()
}

type systemTicker struct {
	ticker *time.Ticker
}

func (ticker systemTicker) Chan() <-chan time.Time { return ticker.ticker.C }
func (ticker systemTicker) Stop()                  { ticker.ticker.Stop() }

func New(repository Repository, registry *Registry, options Options) (*Worker, error) {
	if nilDependency(repository) || nilDependency(registry) || !credential.ValidIdentifier(options.WorkerID, 128) {
		return nil, ErrInvalidWorker
	}
	if options.RecoveryLimit == 0 {
		options.RecoveryLimit = defaultRecoveryLimit
	}
	if options.ClaimLimit == 0 {
		options.ClaimLimit = defaultClaimLimit
	}
	if options.RecoveryLimit < 1 || options.RecoveryLimit > credential.MaxRevocationClaimBatch ||
		options.ClaimLimit != defaultClaimLimit {
		return nil, ErrInvalidWorker
	}
	return &Worker{
		repository: repository, registry: registry, workerID: options.WorkerID,
		recoveryLimit: options.RecoveryLimit, claimLimit: options.ClaimLimit,
		claimLease:        credential.RevocationClaimLease,
		heartbeatInterval: credential.RevocationHeartbeatInterval,
		remoteTimeout:     credential.RevocationRemoteTimeout,
		remoteSlot:        make(chan struct{}, 1),
		random:            cryptorand.Reader,
		newTicker: func(interval time.Duration) heartbeatTicker {
			return systemTicker{ticker: time.NewTicker(interval)}
		},
		after: time.After,
	}, nil
}

func (worker *Worker) RunOnce(ctx context.Context) (RunResult, error) {
	if ctx == nil || worker == nil {
		return RunResult{}, ErrInvalidWorker
	}
	result := RunResult{}
	prepared, err := worker.repository.RecoverPrepared(ctx, credential.RecoverPreparedRequest{Limit: worker.recoveryLimit})
	if err != nil {
		return result, ErrRecoveryFailed
	}
	result.PreparedRecovered = len(prepared)
	managed, err := worker.repository.RecoverManaged(ctx, credential.RecoverManagedRequest{Limit: worker.recoveryLimit})
	if err != nil {
		return result, ErrRecoveryFailed
	}
	result.ManagedRecovered = len(managed)
	exhausted, err := worker.repository.RecoverExhausted(ctx, credential.RecoverExhaustedRequest{Limit: worker.recoveryLimit})
	if err != nil {
		return result, ErrRecoveryFailed
	}
	result.ExhaustedRecovered = len(exhausted)
	claims, err := worker.repository.ClaimRevocations(ctx, credential.ClaimRevocationsRequest{
		WorkerID: worker.workerID, Limit: worker.claimLimit, LeaseDuration: worker.claimLease,
	})
	if err != nil {
		destroyClaims(claims)
		return result, ErrClaimFailed
	}
	result.Claimed = len(claims)
	defer destroyClaims(claims)
	hadDeferred := false
	for _, claim := range claims {
		outcome, processErr := worker.processClaim(ctx, claim)
		if processErr != nil {
			if errors.Is(processErr, ErrClaimDeferred) {
				result.Deferred++
				hadDeferred = true
				if ctx.Err() != nil {
					break
				}
				continue
			}
			result.Deferred++
			hadDeferred = true
			continue
		}
		switch outcome {
		case claimRevoked:
			result.Revoked++
		case claimRetried:
			result.Retried++
		case claimManual:
			result.ManualRequired++
		}
	}
	if hadDeferred {
		return result, ErrClaimDeferred
	}
	return result, nil
}

func destroyClaims(claims []credential.ClaimedRevocation) {
	for index := range claims {
		if claims[index].Accessor != nil {
			claims[index].Accessor.Destroy()
		}
	}
}

type claimOutcome uint8

const (
	claimRevoked claimOutcome = iota + 1
	claimRetried
	claimManual
)

func (worker *Worker) processClaim(ctx context.Context, claim credential.ClaimedRevocation) (claimOutcome, error) {
	if claim.Accessor != nil {
		defer claim.Accessor.Destroy()
	}
	operationCtx, cancelOperation := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	heartbeatLost := make(chan error, 1)
	ticker := worker.newTicker(worker.heartbeatInterval)
	go func() {
		defer close(heartbeatDone)
		defer ticker.Stop()
		for {
			select {
			case <-operationCtx.Done():
				return
			case <-ticker.Chan():
				if _, err := worker.repository.Heartbeat(operationCtx, credential.HeartbeatRequest{
					Fence: claim.Fence, Extension: worker.claimLease,
				}); err != nil {
					select {
					case heartbeatLost <- err:
					default:
					}
					cancelOperation()
					return
				}
			}
		}
	}()
	defer func() {
		cancelOperation()
		<-heartbeatDone
	}()

	revoker, err := worker.registry.ResolveRevoker(operationCtx, identityFrom(claim.Revocation))
	if err != nil {
		if operationCtx.Err() != nil {
			return 0, ErrClaimDeferred
		}
		return worker.ackFailure(operationCtx, claim, credential.FailureIssuerUnavailable, false)
	}
	if claim.Accessor == nil {
		return worker.ackFailure(operationCtx, claim, credential.FailureInvalidReference, true)
	}
	select {
	case worker.remoteSlot <- struct{}{}:
	default:
		return 0, ErrClaimDeferred
	}

	remoteCtx, cancelRemote := context.WithCancel(operationCtx)
	defer cancelRemote()
	remoteResult := make(chan error, 1)
	go func() {
		defer func() { <-worker.remoteSlot }()
		remoteResult <- revoker.RevokeAccessor(remoteCtx, claim.Accessor)
	}()
	var remoteErr error
	select {
	case remoteErr = <-remoteResult:
	case <-worker.after(worker.remoteTimeout):
		cancelRemote()
		return worker.ackFailure(operationCtx, claim, credential.FailureTimeout, false)
	case <-heartbeatLost:
		cancelRemote()
		return 0, ErrClaimDeferred
	case <-ctx.Done():
		cancelRemote()
		return 0, ErrClaimDeferred
	}
	if remoteErr != nil {
		select {
		case <-heartbeatLost:
			return 0, ErrClaimDeferred
		default:
		}
		if ctx.Err() != nil {
			return 0, ErrClaimDeferred
		}
		code, manual := classifyFailure(remoteErr)
		return worker.ackFailure(operationCtx, claim, code, manual)
	}
	select {
	case <-heartbeatLost:
		return 0, ErrClaimDeferred
	default:
	}
	_, err = worker.repository.CompleteRevocation(operationCtx, credential.CompleteRevocationRequest{Fence: claim.Fence})
	if err != nil {
		return 0, ErrClaimDeferred
	}
	return claimRevoked, nil
}

func (worker *Worker) ackFailure(
	ctx context.Context,
	claim credential.ClaimedRevocation,
	code credential.FailureCode,
	manual bool,
) (claimOutcome, error) {
	detail := failureDetail(code)
	if manual {
		_, err := worker.repository.RequireManual(ctx, credential.RequireManualRequest{
			Fence: claim.Fence, FailureCode: code, FailureDetail: detail,
		})
		if err != nil {
			return 0, ErrClaimDeferred
		}
		return claimManual, nil
	}
	revocation, err := worker.repository.RetryRevocation(ctx, credential.RetryRevocationRequest{
		Fence: claim.Fence, Delay: worker.retryDelay(claim.Revocation.Attempt),
		FailureCode: code, FailureDetail: detail,
	})
	if err != nil {
		return 0, ErrClaimDeferred
	}
	if revocation.Status == credential.StatusManualRequired {
		return claimManual, nil
	}
	return claimRetried, nil
}

func (worker *Worker) retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	upper := credential.MinRevocationRetryDelay
	for current := 1; current < attempt && upper < credential.MaxRevocationRetryDelay; current++ {
		if upper > credential.MaxRevocationRetryDelay/2 {
			upper = credential.MaxRevocationRetryDelay
			break
		}
		upper *= 2
	}
	if upper <= credential.MinRevocationRetryDelay {
		return credential.MinRevocationRetryDelay
	}
	span := int64(upper-credential.MinRevocationRetryDelay) + 1
	offset, err := cryptorand.Int(worker.random, big.NewInt(span))
	if err != nil {
		return credential.MinRevocationRetryDelay
	}
	return credential.MinRevocationRetryDelay + time.Duration(offset.Int64())
}

func classifyFailure(err error) (credential.FailureCode, bool) {
	if errors.Is(err, context.DeadlineExceeded) {
		return credential.FailureTimeout, false
	}
	if errors.Is(err, ErrRevokerNotRegistered) {
		return credential.FailureIssuerUnavailable, false
	}
	var vaultFailure *vault.ClientError
	if errors.As(err, &vaultFailure) {
		switch vaultFailure.Class {
		case vault.ErrorAuthentication:
			return credential.FailureAuthentication, false
		case vault.ErrorPermission:
			return credential.FailurePermissionDenied, false
		case vault.ErrorRateLimited:
			return credential.FailureRateLimited, false
		case vault.ErrorUnavailable:
			return credential.FailureIssuerUnavailable, false
		case vault.ErrorTimeout:
			return credential.FailureTimeout, false
		case vault.ErrorInvalidReference:
			return credential.FailureInvalidReference, true
		default:
			return credential.FailureUnknown, false
		}
	}
	return credential.FailureUnknown, false
}

func failureDetail(code credential.FailureCode) []byte {
	switch code {
	case credential.FailureIssuerUnavailable:
		return []byte("credential.revocation.worker.issuer_unavailable.v1")
	case credential.FailureRateLimited:
		return []byte("credential.revocation.worker.rate_limited.v1")
	case credential.FailureTimeout:
		return []byte("credential.revocation.worker.timeout.v1")
	case credential.FailureAuthentication:
		return []byte("credential.revocation.worker.authentication_failed.v1")
	case credential.FailurePermissionDenied:
		return []byte("credential.revocation.worker.permission_denied.v1")
	case credential.FailureReferenceMissing:
		return []byte("credential.revocation.worker.reference_not_found.v1")
	case credential.FailureInvalidReference:
		return []byte("credential.revocation.worker.invalid_reference.v1")
	default:
		return []byte("credential.revocation.worker.unknown.v1")
	}
}

func identityFrom(revocation credential.Revocation) RevokerIdentity {
	return RevokerIdentity{
		TenantID: revocation.TenantID, WorkspaceID: revocation.WorkspaceID,
		EnvironmentID: revocation.EnvironmentID, IssuerID: revocation.Issuer,
		IssuerRevision: revocation.IssuerRevision,
	}
}

// Registry is immutable after construction and performs exact key lookup. It
// has no wildcard, default, prefix, or cross-scope fallback behavior.
type Registry struct {
	revokers map[RevokerIdentity]Revoker
}

func NewRegistry(registrations []Registration) (*Registry, error) {
	if len(registrations) == 0 {
		return nil, ErrInvalidRegistry
	}
	revokers := make(map[RevokerIdentity]Revoker, len(registrations))
	for _, registration := range registrations {
		if !validIdentity(registration.Identity) || nilRevoker(registration.Revoker) {
			return nil, ErrInvalidRegistry
		}
		if _, duplicate := revokers[registration.Identity]; duplicate {
			return nil, ErrInvalidRegistry
		}
		revokers[registration.Identity] = registration.Revoker
	}
	return &Registry{revokers: revokers}, nil
}

func (registry *Registry) ResolveRevoker(ctx context.Context, identity RevokerIdentity) (Revoker, error) {
	if ctx == nil || ctx.Err() != nil || registry == nil || !validIdentity(identity) {
		return nil, ErrRevokerNotRegistered
	}
	revoker, ok := registry.revokers[identity]
	if !ok || nilRevoker(revoker) {
		return nil, ErrRevokerNotRegistered
	}
	return revoker, nil
}

func validIdentity(identity RevokerIdentity) bool {
	return exactIdentifierPattern.MatchString(identity.TenantID) &&
		exactIdentifierPattern.MatchString(identity.WorkspaceID) &&
		exactIdentifierPattern.MatchString(identity.EnvironmentID) &&
		exactIdentifierPattern.MatchString(identity.IssuerID) &&
		exactIdentifierPattern.MatchString(identity.IssuerRevision)
}

func nilRevoker(revoker Revoker) bool {
	return nilDependency(revoker)
}

func nilDependency(value any) bool {
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
