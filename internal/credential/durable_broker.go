package credential

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
)

var (
	ErrInvalidDurableBrokerConfiguration = errors.New("invalid durable credential broker configuration")
	ErrInvalidDurableCredentialRequest   = errors.New("invalid durable credential request")
	ErrDurableCredentialIssuance         = errors.New("durable credential issuance failed")
	ErrDurableCredentialState            = errors.New("invalid durable credential state")
)

const PostDispatchPersistenceTimeout = 20 * time.Second

// DurableIssuerResolveRequest is a trusted, server-built policy snapshot. It
// deliberately has no URL, HTTP method, request body, command, or arbitrary
// issuer parameters. A resolver binds these values to an immutable profile.
type DurableIssuerResolveRequest struct {
	ProfileID     string `json:"profile_id"`
	WorkspaceID   string `json:"workspace_id"`
	EnvironmentID string `json:"environment_id"`
	Production    bool   `json:"production"`
	ActionType    string `json:"action_type"`
	ConnectorID   string `json:"connector_id"`
	Permission    string `json:"permission"`
	Resource      string `json:"resource"`
}

// DurableIssuerProfile is the non-secret portion of an immutable server-side
// issuer profile. Issuer implementations retain endpoint and request details.
type DurableIssuerProfile struct {
	IssuerID      string
	Revision      string
	CredentialTTL time.Duration
}

type ResolvedDurableIssuer struct {
	Profile DurableIssuerProfile
	Issuer  DurableIssuer
}

type DurableChildCreateRequest struct {
	RevocationID         string
	ProfileRevision      string
	DatabaseAuthorizedAt time.Time
	TTL                  time.Duration
	CredentialExpiresAt  time.Time
}

type DurableChild struct {
	Token     SensitiveValue
	Accessor  *SensitiveReference
	ExpiresAt time.Time
}

type DurableChildInspectionRequest struct {
	RevocationID        string
	ProfileRevision     string
	ExpectedTTL         time.Duration
	CredentialExpiresAt time.Time
}

type DurableDynamicIssueRequest struct {
	RevocationID        string
	ProfileRevision     string
	CredentialExpiresAt time.Time
}

type DurableDynamicSecret struct {
	Secret    SensitiveValue
	ExpiresAt time.Time
}

type DurableIssuerResolver interface {
	ResolveDurableIssuer(context.Context, DurableIssuerResolveRequest) (ResolvedDurableIssuer, error)
}

// DurableIssuer contains issuance operations only. Revocation is deliberately
// absent: foreground failure handling persists revocation intent and a
// separate worker owns remote revoke-accessor calls.
type DurableIssuer interface {
	ValidateManager(context.Context) error
	CreateChild(context.Context, DurableChildCreateRequest) (DurableChild, error)
	// InspectChild must use the manager identity and lookup-accessor. A child
	// token must never be used for lookup-self or capability preflight.
	InspectChild(context.Context, *SensitiveReference, DurableChildInspectionRequest) error
	IssueDynamic(context.Context, SensitiveValue, DurableDynamicIssueRequest) (DurableDynamicSecret, error)
}

type IssueDurableCredentialRequest struct {
	Fence     ActionFence
	Selection DurableIssuerResolveRequest
}

func (request IssueDurableCredentialRequest) String() string {
	return fmt.Sprintf(
		"IssueDurableCredentialRequest{ActionID:%q RunnerID:%q Epoch:%d ProfileID:%q WorkspaceID:%q EnvironmentID:%q Production:%t ActionType:%q ConnectorID:%q Permission:%q Resource:%q FenceToken:[REDACTED]}",
		request.Fence.ActionID, request.Fence.RunnerID, request.Fence.Epoch, request.Selection.ProfileID,
		request.Selection.WorkspaceID, request.Selection.EnvironmentID, request.Selection.Production, request.Selection.ActionType,
		request.Selection.ConnectorID, request.Selection.Permission, request.Selection.Resource,
	)
}

func (request IssueDurableCredentialRequest) GoString() string { return request.String() }

func (request IssueDurableCredentialRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ActionID  string                      `json:"action_id"`
		RunnerID  string                      `json:"runner_id"`
		Epoch     int64                       `json:"epoch"`
		Selection DurableIssuerResolveRequest `json:"selection"`
		Redacted  bool                        `json:"fence_token_redacted"`
	}{
		ActionID: request.Fence.ActionID, RunnerID: request.Fence.RunnerID, Epoch: request.Fence.Epoch,
		Selection: request.Selection, Redacted: true,
	})
}

// Issue requests are constructed only after the trusted action/policy lookup.
// They are deliberately not a wire payload that can supply issuer behavior.
func (*IssueDurableCredentialRequest) UnmarshalJSON([]byte) error {
	return ErrInvalidDurableCredentialRequest
}

type DurableBrokerOptions struct {
	UUIDSource            func() (string, error)
	Clock                 func() time.Time
	TimeoutSource         BoundedContextSource
	FinalizeContextSource BoundedContextSource
}

type BoundedContextSource func(context.Context, time.Duration) (context.Context, context.CancelFunc)

type DurableBroker struct {
	repository            Repository
	resolver              DurableIssuerResolver
	uuidSource            func() (string, error)
	clock                 func() time.Time
	timeoutSource         BoundedContextSource
	finalizeContextSource BoundedContextSource
}

func NewDurableBroker(
	repository Repository,
	resolver DurableIssuerResolver,
	options DurableBrokerOptions,
) (*DurableBroker, error) {
	if nilInterface(repository) || nilInterface(resolver) {
		return nil, ErrInvalidDurableBrokerConfiguration
	}
	if options.UUIDSource == nil {
		options.UUIDSource = randomUUID
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.TimeoutSource == nil {
		options.TimeoutSource = context.WithTimeout
	}
	if options.FinalizeContextSource == nil {
		options.FinalizeContextSource = func(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.WithoutCancel(parent), timeout)
		}
	}
	if options.Clock().IsZero() {
		return nil, ErrInvalidDurableBrokerConfiguration
	}
	return &DurableBroker{
		repository: repository, resolver: resolver, uuidSource: options.UUIDSource,
		clock: options.Clock, timeoutSource: options.TimeoutSource,
		finalizeContextSource: options.FinalizeContextSource,
	}, nil
}

func (broker *DurableBroker) Issue(
	ctx context.Context,
	request IssueDurableCredentialRequest,
) (DurableCredential, error) {
	if broker == nil || ctx == nil || contextError(ctx) != nil || !validActionFence(request.Fence) ||
		!validDurableSelection(request.Selection) {
		return DurableCredential{}, ErrInvalidDurableCredentialRequest
	}
	resolved, err := broker.resolver.ResolveDurableIssuer(ctx, request.Selection)
	if err != nil || !validDurableResolution(resolved) {
		return DurableCredential{}, durableIssuanceError("resolve issuer")
	}
	if err := resolved.Issuer.ValidateManager(ctx); err != nil {
		return DurableCredential{}, durableIssuanceError("validate manager")
	}
	if !broker.preflightFinalizeContext(ctx) {
		return DurableCredential{}, durableIssuanceError("validate post-dispatch persistence context")
	}

	revocationID, err := broker.uuidSource()
	if err != nil || !ValidRevocationID(revocationID) {
		return DurableCredential{}, durableIssuanceError("allocate revocation identifier")
	}
	now := broker.clock()
	if now.IsZero() {
		return DurableCredential{}, durableIssuanceError("observe credential deadline")
	}
	credentialExpiresAt := CanonicalCredentialExpiry(now.Add(resolved.Profile.CredentialTTL))
	prepared, err := broker.repository.Prepare(ctx, PrepareRequest{
		RevocationID: revocationID, Fence: request.Fence, Issuer: resolved.Profile.IssuerID,
		CredentialExpiresAt: credentialExpiresAt,
	})
	if err != nil {
		return DurableCredential{}, durableIssuanceError("prepare revocation")
	}
	if !prepared.Created || prepared.Permit == nil {
		return DurableCredential{}, durableIssuanceError("prepare creator election")
	}
	if !validPreparedResult(prepared, revocationID, request, resolved.Profile, credentialExpiresAt) {
		return DurableCredential{}, durableIssuanceError("validate prepared revocation")
	}

	createCtx, cancel, validCreateContext := newBoundedContext(
		ctx, broker.timeoutSource, ChildCreateVaultCallBudget,
	)
	if !validCreateContext {
		prepared.Permit.Token = ""
		return DurableCredential{}, durableIssuanceError("create bounded issuer context")
	}
	permit := *prepared.Permit
	authorized, err := broker.repository.AuthorizeChildCreate(createCtx, AuthorizeChildCreateRequest{
		Permit: permit,
		Fence:  request.Fence,
	})
	permit.Token = ""
	prepared.Permit.Token = ""
	if err != nil {
		cancel()
		return DurableCredential{}, durableIssuanceError("authorize child creation")
	}
	if !validChildCreateAuthorization(authorized, prepared.Revocation, revocationID, request, resolved.Profile, credentialExpiresAt) {
		cancel()
		return DurableCredential{}, durableIssuanceError("validate child creation authorization")
	}
	child, createErr := resolved.Issuer.CreateChild(createCtx, DurableChildCreateRequest{
		RevocationID: revocationID, ProfileRevision: resolved.Profile.Revision,
		DatabaseAuthorizedAt: authorized.DatabaseAuthorizedAt, TTL: authorized.TTL,
		CredentialExpiresAt: credentialExpiresAt,
	})
	cancel()
	defer child.Token.Destroy()
	if child.Accessor == nil {
		return DurableCredential{}, durableIssuanceError("create child without durable accessor")
	}
	defer child.Accessor.Destroy()

	anchorCtx, anchorCancel, validAnchorContext := broker.newFinalizeContext(ctx)
	if !validAnchorContext {
		destroyDurableChild(child)
		return DurableCredential{}, durableIssuanceError("create bounded anchor context")
	}
	anchored, anchorErr := broker.repository.RecordAnchor(anchorCtx, RecordAnchorRequest{
		RevocationID: revocationID, Fence: request.Fence, Accessor: child.Accessor,
	})
	anchorCancel()
	if anchorErr != nil {
		destroyDurableChild(child)
		broker.persistRevocationIntent(ctx, revocationID)
		return DurableCredential{}, durableIssuanceError("anchor child accessor")
	}
	if !validAnchoredResult(anchored, authorized.Revocation, revocationID, request, resolved.Profile, credentialExpiresAt) {
		destroyDurableChild(child)
		broker.persistRevocationIntent(ctx, revocationID)
		return DurableCredential{}, durableIssuanceError("validate anchored revocation")
	}
	if ctx.Err() != nil {
		destroyDurableChild(child)
		broker.persistRevocationIntent(ctx, revocationID)
		return DurableCredential{}, durableIssuanceError("caller canceled after child dispatch")
	}
	if createErr != nil || !validDurableChild(child, authorized) {
		destroyDurableChild(child)
		broker.persistRevocationIntent(ctx, revocationID)
		return DurableCredential{}, durableIssuanceError("validate child credential")
	}
	if err := resolved.Issuer.InspectChild(ctx, child.Accessor, DurableChildInspectionRequest{
		RevocationID: revocationID, ProfileRevision: resolved.Profile.Revision,
		ExpectedTTL: authorized.TTL, CredentialExpiresAt: credentialExpiresAt,
	}); err != nil {
		destroyDurableChild(child)
		broker.persistRevocationIntent(ctx, revocationID)
		return DurableCredential{}, durableIssuanceError("inspect child accessor")
	}
	child.Accessor.Destroy()
	if ctx.Err() != nil {
		child.Token.Destroy()
		broker.persistRevocationIntent(ctx, revocationID)
		return DurableCredential{}, durableIssuanceError("caller canceled after child inspection")
	}

	dynamic, issueErr := resolved.Issuer.IssueDynamic(ctx, child.Token, DurableDynamicIssueRequest{
		RevocationID: revocationID, ProfileRevision: resolved.Profile.Revision,
		CredentialExpiresAt: credentialExpiresAt,
	})
	child.Token.Destroy()
	if issueErr != nil || !broker.validDynamicSecret(dynamic, authorized, child.ExpiresAt) {
		dynamic.Secret.Destroy()
		broker.persistRevocationIntent(ctx, revocationID)
		return DurableCredential{}, durableIssuanceError("issue dynamic credential")
	}
	if ctx.Err() != nil {
		dynamic.Secret.Destroy()
		broker.persistRevocationIntent(ctx, revocationID)
		return DurableCredential{}, durableIssuanceError("caller canceled after dynamic credential")
	}

	activateCtx, activateCancel, validActivateContext := broker.newFinalizeContext(ctx)
	if !validActivateContext {
		dynamic.Secret.Destroy()
		broker.persistRevocationIntent(ctx, revocationID)
		return DurableCredential{}, durableIssuanceError("create bounded activation context")
	}
	activated, activateErr := broker.repository.Activate(activateCtx, ActionTransitionRequest{
		RevocationID: revocationID, Fence: request.Fence,
	})
	activateCancel()
	if activateErr != nil || !validActiveResult(activated, anchored, revocationID, request, resolved.Profile, credentialExpiresAt) {
		dynamic.Secret.Destroy()
		broker.persistRevocationIntent(ctx, revocationID)
		return DurableCredential{}, durableIssuanceError("activate credential")
	}
	if ctx.Err() != nil {
		dynamic.Secret.Destroy()
		broker.persistRevocationIntent(ctx, revocationID)
		return DurableCredential{}, durableIssuanceError("caller canceled before credential handoff")
	}
	return newDurableCredential(broker, activated, dynamic), nil
}

func (broker *DurableBroker) preflightFinalizeContext(parent context.Context) bool {
	if broker == nil || parent == nil {
		return false
	}
	_, cancel, valid := newBoundedContext(
		context.WithoutCancel(parent), broker.finalizeContextSource, PostDispatchPersistenceTimeout,
	)
	if !valid {
		return false
	}
	cancel()
	return true
}

// newFinalizeContext tries the preflighted source again for each durable
// operation. A stateful source can still fail after Vault dispatch, so the
// post-dispatch path must fall back to a non-injectable detached context while
// the only accessor is still available.
func (broker *DurableBroker) newFinalizeContext(parent context.Context) (context.Context, context.CancelFunc, bool) {
	if broker == nil || parent == nil {
		return nil, nil, false
	}
	detached := context.WithoutCancel(parent)
	finalize, cancel, valid := newBoundedContext(
		detached, broker.finalizeContextSource, PostDispatchPersistenceTimeout,
	)
	if valid {
		return finalize, cancel, true
	}
	return newBoundedContext(detached, context.WithTimeout, PostDispatchPersistenceTimeout)
}

// newBoundedContext validates the injected context before it can authorize an
// external side effect, then caps it to an absolute deadline measured before
// source invocation. The cap preserves the monotonic component of time.Now.
func newBoundedContext(
	parent context.Context,
	source BoundedContextSource,
	maximum time.Duration,
) (context.Context, context.CancelFunc, bool) {
	if parent == nil || source == nil || maximum <= 0 {
		return nil, nil, false
	}
	startedAt := time.Now()
	candidate, candidateCancel := source(parent, maximum)
	if candidate == nil || candidateCancel == nil {
		if candidateCancel != nil {
			candidateCancel()
		}
		return nil, nil, false
	}
	observedAt := time.Now()
	deadline, hasDeadline := candidate.Deadline()
	if !hasDeadline || candidate.Done() == nil || candidate.Err() != nil ||
		!hasMonotonicReading(deadline) || !deadline.After(observedAt) || deadline.Sub(observedAt) > maximum {
		candidateCancel()
		return nil, nil, false
	}
	hardDeadline := startedAt.Add(maximum)
	bounded, hardCancel := context.WithDeadline(candidate, hardDeadline)
	boundedDeadline, boundedHasDeadline := bounded.Deadline()
	if !boundedHasDeadline || bounded.Done() == nil || bounded.Err() != nil ||
		!hasMonotonicReading(boundedDeadline) || !boundedDeadline.After(time.Now()) || boundedDeadline.After(hardDeadline) {
		hardCancel()
		candidateCancel()
		return nil, nil, false
	}
	return bounded, func() {
		hardCancel()
		candidateCancel()
	}, true
}

func hasMonotonicReading(value time.Time) bool {
	// time.Time.Round strips the monotonic reading. Equality therefore proves
	// that the injected deadline was reconstructed from wall time only.
	return value != value.Round(0)
}

func destroyDurableChild(child DurableChild) {
	child.Token.Destroy()
	if child.Accessor != nil {
		child.Accessor.Destroy()
	}
}

type durableCredentialState struct {
	mu               sync.Mutex
	broker           *DurableBroker
	revocationID     string
	expiresAt        time.Time
	secret           SensitiveValue
	activeSnapshot   Revocation
	revocationFlight chan struct{}
	revocationResult *Revocation
}

// DurableCredential is a shared-ownership in-memory handle. Copies share the
// same secret state; destroying any copy clears all of them.
type DurableCredential struct {
	revocationID string
	expiresAt    time.Time
	state        *durableCredentialState
}

func newDurableCredential(
	broker *DurableBroker,
	revocation Revocation,
	dynamic DurableDynamicSecret,
) DurableCredential {
	state := &durableCredentialState{
		broker: broker, revocationID: revocation.ID, expiresAt: dynamic.ExpiresAt,
		secret: dynamic.Secret, activeSnapshot: revocation,
	}
	return DurableCredential{revocationID: state.revocationID, expiresAt: state.expiresAt, state: state}
}

func (credential DurableCredential) RevocationID() string { return credential.revocationID }

func (credential DurableCredential) ExpiresAt() time.Time { return credential.expiresAt }

func (credential DurableCredential) Secret() []byte {
	if !credential.validMetadata() || credential.state.broker == nil || credential.state.broker.clock == nil {
		return nil
	}
	now := credential.state.broker.clock()
	if now.IsZero() || !credential.expiresAt.After(now) {
		credential.state.secret.Destroy()
		return nil
	}
	return credential.state.secret.Bytes()
}

func (credential DurableCredential) Destroy() {
	if credential.state != nil {
		credential.state.secret.Destroy()
	}
}

func (credential DurableCredential) String() string {
	return fmt.Sprintf("DurableCredential{RevocationID:%q ExpiresAt:%s}", credential.revocationID, credential.expiresAt.UTC().Format(time.RFC3339Nano))
}

func (credential DurableCredential) GoString() string { return credential.String() }

func (credential DurableCredential) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RevocationID string    `json:"revocation_id"`
		ExpiresAt    time.Time `json:"expires_at"`
	}{RevocationID: credential.revocationID, ExpiresAt: credential.expiresAt})
}

func (*DurableCredential) UnmarshalJSON([]byte) error { return ErrDurableCredentialState }

func (credential DurableCredential) validMetadata() bool {
	return credential.state != nil && credential.revocationID == credential.state.revocationID &&
		credential.expiresAt == credential.state.expiresAt && ValidRevocationID(credential.revocationID) &&
		!credential.expiresAt.IsZero()
}

// RequestRevocation destroys the local secret before any validation or
// persistence. Calls across credential copies serialize; a successful result
// is cached, while persistence failures remain retryable. The repository call
// uses its system-recovery form because credential cleanup must outlive the
// action lease that originally authorized creation.
func (broker *DurableBroker) RequestRevocation(ctx context.Context, credential DurableCredential) (Revocation, error) {
	credential.Destroy()
	if broker == nil || ctx == nil || !credential.validMetadata() || credential.state.broker != broker {
		return Revocation{}, ErrDurableCredentialState
	}
	state := credential.state
	for {
		state.mu.Lock()
		if state.revocationResult != nil {
			result := *state.revocationResult
			state.mu.Unlock()
			return result, nil
		}
		if state.revocationFlight != nil {
			flight := state.revocationFlight
			state.mu.Unlock()
			select {
			case <-ctx.Done():
				return Revocation{}, ctx.Err()
			case <-flight:
				continue
			}
		}
		if err := ctx.Err(); err != nil {
			state.mu.Unlock()
			return Revocation{}, err
		}
		flight := make(chan struct{})
		state.revocationFlight = flight
		state.mu.Unlock()

		revocation, err := broker.repository.RequestRevocation(ctx, ActionTransitionRequest{
			RevocationID: state.revocationID,
		})
		valid := err == nil && validRequestedRevocation(revocation, state)
		state.mu.Lock()
		if valid {
			copy := revocation
			state.revocationResult = &copy
		}
		state.revocationFlight = nil
		close(flight)
		state.mu.Unlock()
		if !valid {
			return Revocation{}, durableIssuanceError("persist revocation request")
		}
		return revocation, nil
	}
}

func (broker *DurableBroker) persistRevocationIntent(ctx context.Context, revocationID string) bool {
	finalizeCtx, cancel, validFinalizeContext := broker.newFinalizeContext(ctx)
	if !validFinalizeContext {
		return false
	}
	defer cancel()
	_, err := broker.repository.RequestRevocation(
		finalizeCtx,
		ActionTransitionRequest{RevocationID: revocationID},
	)
	return err == nil
}

func (broker *DurableBroker) validDynamicSecret(
	secret DurableDynamicSecret,
	authorization ChildCreateAuthorization,
	childExpiresAt time.Time,
) bool {
	material := secret.Secret.Bytes()
	now := broker.clock()
	valid := len(material) > 0 && !now.IsZero() && !secret.ExpiresAt.IsZero() &&
		secret.ExpiresAt == CanonicalCredentialExpiry(secret.ExpiresAt) && secret.ExpiresAt.After(now) &&
		!secret.ExpiresAt.After(childExpiresAt) && !secret.ExpiresAt.After(authorization.CredentialExpiresAt)
	clear(material)
	return valid
}

func validDurableSelection(request DurableIssuerResolveRequest) bool {
	return !request.Production && ValidIdentifier(request.ProfileID, 256) && ValidIdentifier(request.WorkspaceID, 256) &&
		ValidIdentifier(request.EnvironmentID, 256) && ValidIdentifier(request.ActionType, 256) &&
		ValidIdentifier(request.ConnectorID, 256) && ValidIdentifier(request.Permission, 256) &&
		ValidOpaqueText(request.Resource, 2048)
}

func validDurableResolution(resolved ResolvedDurableIssuer) bool {
	profile := resolved.Profile
	return !nilInterface(resolved.Issuer) && ValidIdentifier(profile.IssuerID, 256) &&
		ValidIdentifier(profile.Revision, 256) && profile.CredentialTTL >= ChildCreateExpiryReserve+MinChildCreateTTL &&
		profile.CredentialTTL <= MaxCredentialTTL && profile.CredentialTTL%VaultTTLQuantum == 0
}

func validPreparedResult(
	result PrepareResult,
	revocationID string,
	request IssueDurableCredentialRequest,
	profile DurableIssuerProfile,
	expiresAt time.Time,
) bool {
	return result.Revocation.Version == 1 && result.Permit != nil && result.Permit.RevocationID == revocationID &&
		ValidOpaqueText(result.Permit.Token, 4096) && validFrozenRevocation(
		result.Revocation, revocationID, request, profile, expiresAt, StatusPrepared, false,
	)
}

func validChildCreateAuthorization(
	authorization ChildCreateAuthorization,
	prepared Revocation,
	revocationID string,
	request IssueDurableCredentialRequest,
	profile DurableIssuerProfile,
	expiresAt time.Time,
) bool {
	return validFrozenRevocation(authorization.Revocation, revocationID, request, profile, expiresAt, StatusPrepared, false) &&
		sameDurableFrozenRevocation(authorization.Revocation, prepared) && authorization.Revocation.Version == prepared.Version+1 &&
		!authorization.DatabaseAuthorizedAt.IsZero() && authorization.CredentialExpiresAt == expiresAt &&
		!authorization.Revocation.UpdatedAt.Before(authorization.DatabaseAuthorizedAt) &&
		authorization.TTL >= MinChildCreateTTL && authorization.TTL <= MaxCredentialTTL &&
		authorization.TTL%VaultTTLQuantum == 0 && authorization.VaultCallBudget == ChildCreateVaultCallBudget &&
		!authorization.DatabaseAuthorizedAt.Add(authorization.TTL+ChildCreateExpiryReserve).After(expiresAt)
}

func validDurableChild(child DurableChild, authorization ChildCreateAuthorization) bool {
	value := child.Token.Bytes()
	valid := len(value) > 0 && !child.ExpiresAt.IsZero() &&
		child.ExpiresAt == CanonicalCredentialExpiry(child.ExpiresAt) &&
		child.ExpiresAt.After(authorization.DatabaseAuthorizedAt) &&
		!child.ExpiresAt.After(authorization.CredentialExpiresAt)
	clear(value)
	return valid
}

func validAnchoredResult(
	revocation Revocation,
	authorized Revocation,
	revocationID string,
	request IssueDurableCredentialRequest,
	profile DurableIssuerProfile,
	expiresAt time.Time,
) bool {
	return validFrozenRevocation(revocation, revocationID, request, profile, expiresAt, StatusAnchored, true) &&
		sameDurableFrozenRevocation(revocation, authorized) && revocation.Version == authorized.Version+1
}

func validActiveResult(
	revocation Revocation,
	anchored Revocation,
	revocationID string,
	request IssueDurableCredentialRequest,
	profile DurableIssuerProfile,
	expiresAt time.Time,
) bool {
	return validFrozenRevocation(revocation, revocationID, request, profile, expiresAt, StatusActive, true) &&
		sameDurableFrozenRevocation(revocation, anchored) && revocation.Version == anchored.Version+1
}

func validFrozenRevocation(
	revocation Revocation,
	revocationID string,
	request IssueDurableCredentialRequest,
	profile DurableIssuerProfile,
	expiresAt time.Time,
	status RevocationStatus,
	accessorPresent bool,
) bool {
	if revocation.ID != revocationID || revocation.WorkspaceID != request.Selection.WorkspaceID ||
		revocation.EnvironmentID != request.Selection.EnvironmentID || revocation.ActionID != request.Fence.ActionID ||
		revocation.Production != request.Selection.Production ||
		revocation.RunnerID != request.Fence.RunnerID || revocation.ActionLeaseEpoch != request.Fence.Epoch ||
		revocation.Issuer != profile.IssuerID || revocation.ConnectorID != request.Selection.ConnectorID ||
		revocation.Permission != request.Selection.Permission || revocation.Resource != request.Selection.Resource ||
		revocation.CredentialExpiresAt != expiresAt || revocation.Status != status ||
		revocation.AccessorPresent != accessorPresent || !ValidIdentifier(revocation.TenantID, 256) ||
		!ValidOpaqueText(revocation.TargetKey, 1024) || revocation.Version < 1 || revocation.CreatedAt.IsZero() ||
		revocation.UpdatedAt.Before(revocation.CreatedAt) || revocation.AvailableAt.IsZero() ||
		revocation.CredentialExpiresAt != CanonicalCredentialExpiry(revocation.CredentialExpiresAt) {
		return false
	}
	switch status {
	case StatusPrepared:
		return revocation.AnchoredAt.IsZero() && revocation.ActivatedAt.IsZero()
	case StatusAnchored:
		return !revocation.AnchoredAt.IsZero() && revocation.ActivatedAt.IsZero() &&
			!revocation.UpdatedAt.Before(revocation.AnchoredAt)
	case StatusActive:
		return !revocation.AnchoredAt.IsZero() && !revocation.ActivatedAt.IsZero() &&
			!revocation.ActivatedAt.Before(revocation.AnchoredAt) && !revocation.UpdatedAt.Before(revocation.ActivatedAt)
	default:
		return false
	}
}

func sameDurableFrozenRevocation(left, right Revocation) bool {
	return left.ID == right.ID && left.TenantID == right.TenantID && left.WorkspaceID == right.WorkspaceID &&
		left.EnvironmentID == right.EnvironmentID && left.ActionID == right.ActionID && left.TargetKey == right.TargetKey &&
		left.Production == right.Production && left.RunnerID == right.RunnerID &&
		left.ActionLeaseEpoch == right.ActionLeaseEpoch && left.Issuer == right.Issuer &&
		left.ConnectorID == right.ConnectorID && left.Permission == right.Permission && left.Resource == right.Resource &&
		left.CredentialExpiresAt == right.CredentialExpiresAt && left.CreatedAt == right.CreatedAt
}

func validRequestedRevocation(revocation Revocation, state *durableCredentialState) bool {
	if revocation.ID != state.revocationID || !sameDurableFrozenRevocation(revocation, state.activeSnapshot) ||
		revocation.Version <= state.activeSnapshot.Version {
		return false
	}
	switch revocation.Status {
	case StatusRevocationPending, StatusRevoking:
		return revocation.AccessorPresent && !revocation.RevocationRequestedAt.IsZero() &&
			!revocation.UpdatedAt.Before(revocation.RevocationRequestedAt)
	case StatusManualRequired:
		return revocation.AccessorPresent && !revocation.RevocationRequestedAt.IsZero() &&
			!revocation.ManualRequiredAt.IsZero() && !revocation.UpdatedAt.Before(revocation.ManualRequiredAt)
	case StatusRevoked:
		return !revocation.AccessorPresent && !revocation.RevocationRequestedAt.IsZero() &&
			!revocation.RevokedAt.IsZero() && !revocation.UpdatedAt.Before(revocation.RevokedAt)
	default:
		return false
	}
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

func durableIssuanceError(operation string) error {
	return fmt.Errorf("%w: %s", ErrDurableCredentialIssuance, operation)
}

func randomUUID() (string, error) {
	var value [16]byte
	if _, err := cryptorand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}
