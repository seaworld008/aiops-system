package credential

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	TenantID      string `json:"tenant_id"`
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

type durableIssuerResolver interface {
	ResolveDurableIssuer(context.Context, DurableIssuerResolveRequest) (ResolvedDurableIssuer, error)
}

// DurableIssuer contains issuance operations only. Revocation is deliberately
// absent: foreground failure handling persists revocation intent and a
// separate worker owns remote revoke-accessor calls.
type DurableIssuer interface {
	IssuerID() string
	IssuerRevision() string
	ValidateManager(context.Context) error
	CreateChild(context.Context, DurableChildCreateRequest) (DurableChild, error)
	// InspectChild must use the manager identity and lookup-accessor. A child
	// token must never be used for lookup-self or capability preflight.
	InspectChild(context.Context, *SensitiveReference, DurableChildInspectionRequest) error
	IssueDynamic(context.Context, SensitiveValue, DurableDynamicIssueRequest) (DurableDynamicSecret, error)
}

type PrepareDurableCredentialRequest struct {
	Fence           ActionFence
	Selection       DurableIssuerResolveRequest
	RequestedTTL    time.Duration
	PolicyExpiresAt time.Time
}

func (request PrepareDurableCredentialRequest) String() string {
	return fmt.Sprintf(
		"PrepareDurableCredentialRequest{ActionID:%q RunnerID:%q Epoch:%d TenantID:%q WorkspaceID:%q EnvironmentID:%q Production:%t ActionType:%q ConnectorID:%q Permission:%q Resource:%q RequestedTTL:%s PolicyExpiresAt:%s FenceToken:[REDACTED]}",
		request.Fence.ActionID, request.Fence.RunnerID, request.Fence.Epoch, request.Selection.TenantID,
		request.Selection.WorkspaceID, request.Selection.EnvironmentID, request.Selection.Production,
		request.Selection.ActionType, request.Selection.ConnectorID, request.Selection.Permission,
		request.Selection.Resource, request.RequestedTTL, request.PolicyExpiresAt.UTC().Format(time.RFC3339Nano),
	)
}

func (request PrepareDurableCredentialRequest) GoString() string { return request.String() }

func (request PrepareDurableCredentialRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ActionID           string                      `json:"action_id"`
		RunnerID           string                      `json:"runner_id"`
		Epoch              int64                       `json:"epoch"`
		Selection          DurableIssuerResolveRequest `json:"selection"`
		RequestedTTLSecond int64                       `json:"requested_ttl_seconds"`
		PolicyExpiresAt    time.Time                   `json:"policy_expires_at"`
		Redacted           bool                        `json:"fence_token_redacted"`
	}{
		ActionID: request.Fence.ActionID, RunnerID: request.Fence.RunnerID, Epoch: request.Fence.Epoch,
		Selection: request.Selection, RequestedTTLSecond: int64(request.RequestedTTL / time.Second),
		PolicyExpiresAt: request.PolicyExpiresAt, Redacted: true,
	})
}

// Prepare requests are constructed only after the trusted action/policy lookup.
// They are deliberately not a wire payload that can supply issuer behavior.
func (*PrepareDurableCredentialRequest) UnmarshalJSON([]byte) error {
	return ErrInvalidDurableCredentialRequest
}

type preparedDurableCredentialPhase uint8

const (
	preparedDurableCredentialReady preparedDurableCredentialPhase = iota
	preparedDurableCredentialIssuing
	preparedDurableCredentialNoCredential
)

type preparedDurableCredentialState struct {
	mu           sync.Mutex
	broker       *DurableBroker
	phase        preparedDurableCredentialPhase
	request      PrepareDurableCredentialRequest
	resolved     ResolvedDurableIssuer
	prepared     Revocation
	permit       ChildCreatePermit
	revocationID string
	expiresAt    time.Time
}

// PreparedDurableCredential is an opaque, Broker-owned, single-use handle.
// Copies share one state and therefore cannot authorize duplicate issuance.
type PreparedDurableCredential struct {
	revocationID string
	state        *preparedDurableCredentialState
}

func (PreparedDurableCredential) String() string {
	return "[REDACTED PREPARED DURABLE CREDENTIAL]"
}

func (PreparedDurableCredential) GoString() string {
	return "[REDACTED PREPARED DURABLE CREDENTIAL]"
}

func (PreparedDurableCredential) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED PREPARED DURABLE CREDENTIAL]")
}

func (PreparedDurableCredential) MarshalJSON() ([]byte, error) {
	return nil, ErrDurableCredentialState
}

func (*PreparedDurableCredential) UnmarshalJSON([]byte) error {
	return ErrDurableCredentialState
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
	resolver              durableIssuerResolver
	uuidSource            func() (string, error)
	clock                 func() time.Time
	timeoutSource         BoundedContextSource
	finalizeContextSource BoundedContextSource
}

func NewDurableBroker(
	repository Repository,
	registry *IssuerRegistry,
	options DurableBrokerOptions,
) (*DurableBroker, error) {
	return newDurableBroker(repository, registry, options)
}

// newDurableBroker is the package-local test seam for exercising hostile or
// failing resolver behavior. Runtime callers must use the exact immutable
// IssuerRegistry accepted by NewDurableBroker.
func newDurableBroker(
	repository Repository,
	resolver durableIssuerResolver,
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

func (broker *DurableBroker) Prepare(
	ctx context.Context,
	request PrepareDurableCredentialRequest,
) (PreparedDurableCredential, error) {
	if broker == nil || ctx == nil || contextError(ctx) != nil || !validActionFence(request.Fence) ||
		!validDurableSelection(request.Selection) || !validDurableCredentialWindow(request) {
		return PreparedDurableCredential{}, ErrInvalidDurableCredentialRequest
	}
	resolved, err := broker.resolver.ResolveDurableIssuer(ctx, request.Selection)
	if err != nil || !validDurableResolution(resolved) {
		return PreparedDurableCredential{}, durableIssuanceError("resolve issuer")
	}
	if !broker.preflightFinalizeContext(ctx) {
		return PreparedDurableCredential{}, durableIssuanceError("validate post-dispatch persistence context")
	}

	revocationID, err := broker.uuidSource()
	if err != nil || !ValidRevocationID(revocationID) {
		return PreparedDurableCredential{}, durableIssuanceError("allocate revocation identifier")
	}
	now := broker.clock().UTC()
	if now.IsZero() {
		return PreparedDurableCredential{}, durableIssuanceError("observe credential deadline")
	}
	credentialExpiresAt, ok := durableCredentialExpiry(now, request, resolved.Profile)
	if !ok {
		return PreparedDurableCredential{}, ErrInvalidDurableCredentialRequest
	}
	prepared, err := broker.repository.Prepare(ctx, PrepareRequest{
		RevocationID: revocationID, Fence: request.Fence, Issuer: resolved.Profile.IssuerID,
		IssuerRevision:      resolved.Profile.Revision,
		CredentialExpiresAt: credentialExpiresAt,
	})
	if prepared.Permit != nil {
		defer func() { prepared.Permit.Token = "" }()
	}
	if err != nil {
		return PreparedDurableCredential{}, durableIssuanceError("prepare revocation")
	}
	if !prepared.Created || prepared.Permit == nil {
		return PreparedDurableCredential{}, durableIssuanceError("prepare creator election")
	}
	if !validPreparedResult(prepared, revocationID, request, resolved.Profile, credentialExpiresAt) {
		return PreparedDurableCredential{}, durableIssuanceError("validate prepared revocation")
	}
	permit := *prepared.Permit
	state := &preparedDurableCredentialState{
		broker: broker, phase: preparedDurableCredentialReady, request: request,
		resolved: resolved, prepared: prepared.Revocation, permit: permit,
		revocationID: revocationID, expiresAt: credentialExpiresAt,
	}
	return PreparedDurableCredential{revocationID: revocationID, state: state}, nil
}

type consumedPreparedCredential struct {
	request      PrepareDurableCredentialRequest
	resolved     ResolvedDurableIssuer
	prepared     Revocation
	permit       ChildCreatePermit
	revocationID string
	expiresAt    time.Time
}

func (broker *DurableBroker) consumePrepared(
	prepared PreparedDurableCredential,
	phase preparedDurableCredentialPhase,
) (consumedPreparedCredential, error) {
	if broker == nil || prepared.state == nil {
		return consumedPreparedCredential{}, ErrDurableCredentialState
	}
	state := prepared.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.broker != broker || state.phase != preparedDurableCredentialReady ||
		prepared.revocationID != state.revocationID || state.prepared.ID != state.revocationID ||
		state.permit.RevocationID != state.revocationID || !ValidOpaqueText(state.permit.Token, 4096) ||
		state.expiresAt.IsZero() || !validDurableResolution(state.resolved) {
		return consumedPreparedCredential{}, ErrDurableCredentialState
	}
	consumed := consumedPreparedCredential{
		request: state.request, resolved: state.resolved, prepared: state.prepared,
		permit: state.permit, revocationID: state.revocationID, expiresAt: state.expiresAt,
	}
	state.phase = phase
	state.request = PrepareDurableCredentialRequest{}
	state.resolved = ResolvedDurableIssuer{}
	state.prepared = Revocation{}
	state.permit.Token = ""
	state.expiresAt = time.Time{}
	return consumed, nil
}

func (broker *DurableBroker) Issue(
	ctx context.Context,
	preparedHandle PreparedDurableCredential,
) (DurableCredential, error) {
	if ctx == nil {
		return DurableCredential{}, ErrInvalidDurableCredentialRequest
	}
	if err := ctx.Err(); err != nil {
		return DurableCredential{}, err
	}
	prepared, err := broker.consumePrepared(preparedHandle, preparedDurableCredentialIssuing)
	if err != nil {
		return DurableCredential{}, err
	}
	defer func() { prepared.permit.Token = "" }()
	request, resolved := prepared.request, prepared.resolved
	revocationID, credentialExpiresAt := prepared.revocationID, prepared.expiresAt
	if err := resolved.Issuer.ValidateManager(ctx); err != nil {
		return DurableCredential{}, durableIssuanceError("validate manager")
	}

	createCtx, cancel, validCreateContext := newBoundedContext(
		ctx, broker.timeoutSource, ChildCreateVaultCallBudget,
	)
	if !validCreateContext {
		return DurableCredential{}, durableIssuanceError("create bounded issuer context")
	}
	authorized, err := broker.repository.AuthorizeChildCreate(createCtx, AuthorizeChildCreateRequest{
		Permit: prepared.permit,
		Fence:  request.Fence,
	})
	prepared.permit.Token = ""
	if err != nil {
		cancel()
		return DurableCredential{}, durableIssuanceError("authorize child creation")
	}
	if !validChildCreateAuthorization(authorized, prepared.prepared, revocationID, request, resolved.Profile, credentialExpiresAt) {
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

func (broker *DurableBroker) RecordNoCredential(
	ctx context.Context,
	preparedHandle PreparedDurableCredential,
) (Revocation, error) {
	if ctx == nil {
		return Revocation{}, ErrInvalidDurableCredentialRequest
	}
	if err := ctx.Err(); err != nil {
		return Revocation{}, err
	}
	prepared, err := broker.consumePrepared(preparedHandle, preparedDurableCredentialNoCredential)
	if err != nil {
		return Revocation{}, err
	}
	prepared.permit.Token = ""
	revocation, err := broker.repository.RecordNoCredential(ctx, ActionTransitionRequest{
		RevocationID: prepared.revocationID,
		Fence:        prepared.request.Fence,
	})
	if err != nil || !validNoCredentialResult(revocation, prepared) {
		return Revocation{}, durableIssuanceError("record no credential")
	}
	return revocation, nil
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
	return !request.Production && ValidIdentifier(request.TenantID, 256) && ValidIdentifier(request.WorkspaceID, 256) &&
		ValidIdentifier(request.EnvironmentID, 256) && ValidIdentifier(request.ActionType, 256) &&
		ValidIdentifier(request.ConnectorID, 256) && ValidIdentifier(request.Permission, 256) &&
		ValidIdentifier(request.Resource, 256)
}

func validDurableCredentialWindow(request PrepareDurableCredentialRequest) bool {
	return request.RequestedTTL >= ChildCreateExpiryReserve+MinChildCreateTTL &&
		request.RequestedTTL <= MaxCredentialTTL && request.RequestedTTL%VaultTTLQuantum == 0 &&
		!request.PolicyExpiresAt.IsZero()
}

func durableCredentialExpiry(
	now time.Time,
	request PrepareDurableCredentialRequest,
	profile DurableIssuerProfile,
) (time.Time, bool) {
	if now.IsZero() || !validDurableCredentialWindow(request) {
		return time.Time{}, false
	}
	expiresAt := now.Add(profile.CredentialTTL)
	if requested := now.Add(request.RequestedTTL); requested.Before(expiresAt) {
		expiresAt = requested
	}
	if policy := request.PolicyExpiresAt.UTC(); policy.Before(expiresAt) {
		expiresAt = policy
	}
	expiresAt = CanonicalCredentialExpiry(expiresAt)
	minimum := now.Add(ChildCreateExpiryReserve + MinChildCreateTTL)
	if expiresAt.Before(minimum) {
		return time.Time{}, false
	}
	return expiresAt, true
}

func validDurableResolution(resolved ResolvedDurableIssuer) bool {
	profile := resolved.Profile
	return !nilInterface(resolved.Issuer) && ValidIdentifier(profile.IssuerID, 256) &&
		ValidIdentifier(profile.Revision, 256) && profile.CredentialTTL >= ChildCreateExpiryReserve+MinChildCreateTTL &&
		profile.CredentialTTL <= MaxCredentialTTL && profile.CredentialTTL%VaultTTLQuantum == 0 &&
		resolved.Issuer.IssuerID() == profile.IssuerID && resolved.Issuer.IssuerRevision() == profile.Revision
}

func validPreparedResult(
	result PrepareResult,
	revocationID string,
	request PrepareDurableCredentialRequest,
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
	request PrepareDurableCredentialRequest,
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
	request PrepareDurableCredentialRequest,
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
	request PrepareDurableCredentialRequest,
	profile DurableIssuerProfile,
	expiresAt time.Time,
) bool {
	return validFrozenRevocation(revocation, revocationID, request, profile, expiresAt, StatusActive, true) &&
		sameDurableFrozenRevocation(revocation, anchored) && revocation.Version == anchored.Version+1
}

func validFrozenRevocation(
	revocation Revocation,
	revocationID string,
	request PrepareDurableCredentialRequest,
	profile DurableIssuerProfile,
	expiresAt time.Time,
	status RevocationStatus,
	accessorPresent bool,
) bool {
	if revocation.ID != revocationID || revocation.TenantID != request.Selection.TenantID ||
		revocation.WorkspaceID != request.Selection.WorkspaceID ||
		revocation.EnvironmentID != request.Selection.EnvironmentID || revocation.ActionID != request.Fence.ActionID ||
		revocation.Production != request.Selection.Production ||
		revocation.RunnerID != request.Fence.RunnerID || revocation.ActionLeaseEpoch != request.Fence.Epoch ||
		revocation.Issuer != profile.IssuerID || revocation.IssuerRevision != profile.Revision ||
		revocation.ActionType != request.Selection.ActionType ||
		revocation.ConnectorID != request.Selection.ConnectorID ||
		revocation.Permission != request.Selection.Permission || revocation.Resource != request.Selection.Resource ||
		revocation.CredentialTTLSeconds != int32(request.RequestedTTL/time.Second) ||
		revocation.CredentialExpiresAt != expiresAt || revocation.Status != status ||
		revocation.AccessorPresent != accessorPresent || !ValidIdentifier(revocation.TenantID, 256) ||
		!ValidOpaqueText(revocation.TargetKey, 1024) || revocation.Version < 1 || revocation.CreatedAt.IsZero() ||
		revocation.UpdatedAt.Before(revocation.CreatedAt) || revocation.AvailableAt.IsZero() ||
		revocation.CredentialExpiresAt != CanonicalCredentialExpiry(revocation.CredentialExpiresAt) {
		return false
	}
	switch status {
	case StatusPrepared, StatusNoCredential:
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
		left.IssuerRevision == right.IssuerRevision && left.ActionType == right.ActionType &&
		left.ConnectorID == right.ConnectorID && left.Permission == right.Permission && left.Resource == right.Resource &&
		left.CredentialTTLSeconds == right.CredentialTTLSeconds &&
		left.CredentialExpiresAt == right.CredentialExpiresAt && left.CreatedAt == right.CreatedAt
}

func validNoCredentialResult(revocation Revocation, prepared consumedPreparedCredential) bool {
	return validFrozenRevocation(
		revocation, prepared.revocationID, prepared.request, prepared.resolved.Profile,
		prepared.expiresAt, StatusNoCredential, false,
	) && sameDurableFrozenRevocation(revocation, prepared.prepared) &&
		revocation.Version == prepared.prepared.Version+1
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
