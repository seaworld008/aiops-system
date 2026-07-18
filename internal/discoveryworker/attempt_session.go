package discoveryworker

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"sync"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

const (
	attemptSessionDigestDomain       = "discovery-attempt-runtime-binding.v1"
	attemptSessionAuthorityRedaction = "[REDACTED_ATTEMPT_SESSION_AUTHORITY]"
	initialRuntimeRequestRedaction   = "[REDACTED_INITIAL_RUNTIME_REQUEST]"
	initialRuntimeTupleRedaction     = "[REDACTED_INITIAL_RUNTIME_TUPLE]"
	sessionBoundRuntimeRedaction     = "[REDACTED_SESSION_BOUND_RUNTIME]"
	attemptSessionAuthoritySeal      = uint64(0x5f92a614c37bd8e1)
	initialRuntimeTupleSeal          = uint64(0x8a43c90e72f15bd6)
)

var ErrAttemptSessionAuthority = errors.New(
	"discovery worker attempt session authority rejected",
)

// AttemptProfileDescriptor is the provider-neutral, immutable profile identity
// included in every runtime-binding digest.
type AttemptProfileDescriptor interface {
	Valid() bool
	SourceKind() assetcatalog.SourceKind
	ProviderKind() string
	ProfileCode() assetcatalog.ProfileCode
	DigestSHA256() string
}

// AttemptRuntimeFactory resolves immutable binding facts, creates the initial
// session's runtime through an unforgeable request, and supplies only
// Provider-owned policy to the already-opened claim capability.
type AttemptRuntimeFactory interface {
	ResolveRuntimeBinding(
		context.Context,
		discoverycleanup.OpenAttemptRequest,
	) (discoverysource.RuntimeBinding, error)
	OpenInitialRuntime(
		context.Context,
		*InitialRuntimeRequest,
	) (*SessionBoundRuntime, error)
	ResolveClaimRuntime(
		context.Context,
		ResolveOpenedAttemptRequest,
	) (
		discoverysource.Provider,
		*discoverysource.Checkpoint,
		discoverysource.Limits,
		assetdiscovery.FactPolicy,
		error,
	)
}

// InitialRuntimeLifecycle is the non-serializable lifecycle paired with the
// runtime material minted by one InitialRuntimeRequest callback. Revoke is
// included in the Broker handle result; Destroy must release and zero every
// remaining process-local owner without claiming successful revocation.
type InitialRuntimeLifecycle interface {
	Revoke(context.Context) error
	Destroy()
}

// InitialRuntimeResolver receives a one-use tuple that can only be minted from
// the exact internal attempt cell. It returns runtime material and its
// lifecycle together, so no independent opener or resolver can be paired with
// the Broker handle.
type InitialRuntimeResolver func(
	context.Context,
	*InitialRuntimeTuple,
) (
	discoverysource.BoundRuntime,
	InitialRuntimeLifecycle,
	error,
)

// AttemptSessionAuthority implements both Broker SessionOpener and Worker
// ClaimRuntimeResolver. The shared object is the process-local authority that
// joins one external attempt lease to exactly one runtime cell.
type AttemptSessionAuthority struct {
	self  *AttemptSessionAuthority
	seal  uint64
	state *attemptSessionAuthorityState
}

type attemptSessionAuthorityState struct {
	mu          sync.Mutex
	transport   *discoverycleanup.SessionTransport
	profile     attemptProfileSnapshot
	factory     AttemptRuntimeFactory
	sessions    map[string]*attemptSessionCell
	recoveries  map[*recoveryAttemptSessionCell]struct{}
	lifetime    context.Context
	cancel      context.CancelFunc
	operations  sync.WaitGroup
	destroyDone chan struct{}
	destroyed   bool
}

type attemptProfileSnapshot struct {
	sourceKind   assetcatalog.SourceKind
	providerKind string
	profileCode  assetcatalog.ProfileCode
	digest       string
}

type attemptSessionCell struct {
	mu         sync.Mutex
	owner      *attemptSessionAuthorityState
	transport  *discoverycleanup.SessionTransport
	lease      *discoverycleanup.SessionLease
	request    discoverycleanup.OpenAttemptRequest
	binding    discoverysource.RuntimeBinding
	digest     string
	runtime    discoverysource.BoundRuntime
	lifecycle  InitialRuntimeLifecycle
	handle     *initialAttemptSessionHandle
	revokeDone chan struct{}
	revokeErr  error
	revoking   bool
	active     bool
}

// InitialRuntimeRequest is a one-use, same-cell capability. ResolveRuntime
// invokes one callback with an unforgeable exact tuple and accepts runtime plus
// lifecycle ownership only for this request's internal attempt cell.
type InitialRuntimeRequest struct {
	state *initialRuntimeRequestState
}

type initialRuntimeRequestState struct {
	mu      sync.Mutex
	issued  *InitialRuntimeRequest
	cell    *attemptSessionCell
	binding discoverysource.RuntimeBinding
	bound   *sessionBoundRuntimeState
	used    bool
	active  bool
}

// InitialRuntimeTuple is a callback-scoped capability containing only the
// server-derived exact attempt tuple and immutable RuntimeBinding. A struct
// copy or reconstructed value is inert; the originating callback invalidates
// the tuple before returning.
type InitialRuntimeTuple struct {
	self  *InitialRuntimeTuple
	seal  uint64
	state *initialRuntimeTupleState
}

type initialRuntimeTupleState struct {
	mu          sync.Mutex
	issued      *InitialRuntimeTuple
	coordinates discoveryqueue.RunCoordinates
	attempt     discoveryqueue.CleanupAttempt
	binding     discoverysource.RuntimeBinding
	active      bool
}

// SessionBoundRuntime is the factory's proof that its runtime was bound
// through the exact InitialRuntimeRequest. It is consumed immediately by the
// authority and never crosses the Broker ABI.
type SessionBoundRuntime struct {
	state *sessionBoundRuntimeState
}

type sessionBoundRuntimeState struct {
	issued    *SessionBoundRuntime
	request   *initialRuntimeRequestState
	cell      *attemptSessionCell
	runtime   discoverysource.BoundRuntime
	lifecycle InitialRuntimeLifecycle
	active    bool
}

type initialRuntimeOwnership struct {
	runtime   discoverysource.BoundRuntime
	lifecycle InitialRuntimeLifecycle
}

type initialAttemptSessionHandle struct {
	cell *attemptSessionCell
}

type recoveryAttemptSessionHandle struct {
	cell *recoveryAttemptSessionCell
}

type recoveryAttemptSessionCell struct {
	mu         sync.Mutex
	owner      *attemptSessionAuthorityState
	transport  *discoverycleanup.SessionTransport
	lease      *discoverycleanup.SessionLease
	handle     *recoveryAttemptSessionHandle
	revokeDone chan struct{}
	revokeErr  error
	revoking   bool
	active     bool
}

func NewAttemptSessionAuthority(
	transport *discoverycleanup.SessionTransport,
	descriptor AttemptProfileDescriptor,
	factory AttemptRuntimeFactory,
) (*AttemptSessionAuthority, error) {
	if transport == nil || nilDependency(descriptor) || nilDependency(factory) {
		return nil, ErrAttemptSessionAuthority
	}
	profile := attemptProfileSnapshot{
		sourceKind: descriptor.SourceKind(), providerKind: descriptor.ProviderKind(),
		profileCode: descriptor.ProfileCode(), digest: descriptor.DigestSHA256(),
	}
	if !descriptor.Valid() || !profile.valid() {
		return nil, ErrAttemptSessionAuthority
	}
	lifetime, cancel := context.WithCancel(context.Background())
	private := &attemptSessionAuthorityState{
		transport: transport, profile: profile, factory: factory,
		sessions:   make(map[string]*attemptSessionCell),
		recoveries: make(map[*recoveryAttemptSessionCell]struct{}),
		lifetime:   lifetime, cancel: cancel,
		destroyDone: make(chan struct{}),
	}
	authority := &AttemptSessionAuthority{
		seal: attemptSessionAuthoritySeal, state: private,
	}
	authority.self = authority
	return authority, nil
}

func (authority *AttemptSessionAuthority) OpenSession(
	ctx context.Context,
	request discoverycleanup.OpenAttemptRequest,
) (discoverycleanup.SessionHandle, error) {
	if ctx == nil || request.Validate() != nil || !authority.authentic() {
		return nil, ErrAttemptSessionAuthority
	}
	private, operationContext, release, err := authority.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	binding, err := private.factory.ResolveRuntimeBinding(operationContext, request)
	if err != nil {
		return nil, boundedAttemptAuthorityError(err)
	}
	if !attemptBindingMatches(request, binding, private.profile) {
		return nil, discoverycleanup.ErrSessionAuthentication
	}
	digest := runtimeBindingDigest(private.profile, binding)
	lease, err := private.transport.OpenOrRecover(
		operationContext,
		discoverycleanup.SessionOpenRequest{
			Coordinates: request.Coordinates, Attempt: request.Attempt,
			RuntimeBindingDigest: digest,
		},
	)
	if err != nil {
		return nil, mapSessionTransportError(err)
	}
	initial, err := lease.Initial()
	if err != nil {
		lease.Destroy()
		return nil, ErrAttemptSessionAuthority
	}
	if !initial {
		handle := newRecoveryAttemptSessionHandle(private, private.transport, lease)
		if err := private.installRecovery(handle.cell); err != nil {
			handle.Destroy()
			return nil, err
		}
		return handle, nil
	}

	cell := &attemptSessionCell{
		owner: private, transport: private.transport, lease: lease,
		request: request, binding: binding, digest: digest, active: true,
	}
	handle := &initialAttemptSessionHandle{cell: cell}
	cell.handle = handle
	if err := private.install(cell); err != nil {
		lease.Destroy()
		return nil, err
	}

	initialRequest := newInitialRuntimeRequest(cell, binding)
	result, openErr := private.factory.OpenInitialRuntime(operationContext, initialRequest)
	if openErr != nil {
		releaseInitialRuntime(
			operationContext,
			invalidateInitialRuntimeRequest(initialRequest),
		)
		return handle, boundedAttemptAuthorityError(openErr)
	}
	ownership, consumeErr := consumeSessionBoundRuntime(initialRequest, result)
	if consumeErr != nil {
		releaseInitialRuntime(operationContext, ownership)
		return handle, ErrAttemptSessionAuthority
	}
	cell.mu.Lock()
	if !cell.active || cell.handle != handle ||
		cell.binding != ownership.runtime.Binding() ||
		nilDependency(ownership.lifecycle) {
		cell.mu.Unlock()
		releaseInitialRuntime(operationContext, ownership)
		return handle, ErrAttemptSessionAuthority
	}
	cell.runtime = ownership.runtime
	cell.lifecycle = ownership.lifecycle
	cell.mu.Unlock()
	return handle, nil
}

func (authority *AttemptSessionAuthority) ResolveOpenedAttempt(
	ctx context.Context,
	request ResolveOpenedAttemptRequest,
) (ClaimRuntime, error) {
	if ctx == nil || request.validate() != nil || !authority.authentic() {
		return ClaimRuntime{}, ErrAttemptSessionAuthority
	}
	private, operationContext, release, err := authority.begin(ctx)
	if err != nil {
		return ClaimRuntime{}, err
	}
	defer release()

	cell := private.lookup(request.Attempt().AttemptID)
	if cell == nil || !cell.matchesResolveRequest(request) {
		return ClaimRuntime{}, ErrAttemptSessionAuthority
	}
	provider, checkpoint, limits, policy, err :=
		private.factory.ResolveClaimRuntime(operationContext, request)
	if err != nil {
		if checkpoint != nil {
			checkpoint.Clear()
		}
		return ClaimRuntime{}, boundedAttemptAuthorityError(err)
	}
	if nilDependency(provider) || provider.Kind() != private.profile.sourceKind ||
		private.lookup(request.Attempt().AttemptID) != cell {
		if checkpoint != nil {
			checkpoint.Clear()
		}
		return ClaimRuntime{}, ErrAttemptSessionAuthority
	}
	runtime, minted := cell.newClaimRuntime(request, provider, checkpoint, limits, policy)
	if !minted {
		if checkpoint != nil {
			checkpoint.Clear()
		}
		return ClaimRuntime{}, ErrAttemptSessionAuthority
	}
	return runtime, nil
}

func (request *InitialRuntimeRequest) ResolveRuntime(
	ctx context.Context,
	resolve InitialRuntimeResolver,
) (*SessionBoundRuntime, error) {
	if ctx == nil || resolve == nil || request == nil || request.state == nil {
		return nil, ErrAttemptSessionAuthority
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	private := request.state
	private.mu.Lock()
	if !private.active || private.issued != request || private.cell == nil ||
		private.used || private.bound != nil ||
		private.binding != private.cell.binding {
		private.mu.Unlock()
		return nil, ErrAttemptSessionAuthority
	}
	private.used = true
	cell, binding := private.cell, private.binding
	private.mu.Unlock()

	tuple := newInitialRuntimeTuple(cell.request, binding)
	runtime, lifecycle, resolveErr := resolve(ctx, tuple)
	tuple.destroy()
	if resolveErr != nil || runtime.Binding() != binding ||
		nilDependency(lifecycle) {
		releaseInitialRuntime(
			ctx,
			initialRuntimeOwnership{runtime: runtime, lifecycle: lifecycle},
		)
		invalidateInitialRuntimeRequest(request)
		if resolveErr != nil {
			return nil, resolveErr
		}
		return nil, ErrAttemptSessionAuthority
	}

	private.mu.Lock()
	if !private.active || private.issued != request || private.cell != cell ||
		!private.used || private.bound != nil || private.binding != binding {
		private.mu.Unlock()
		releaseInitialRuntime(
			ctx,
			initialRuntimeOwnership{runtime: runtime, lifecycle: lifecycle},
		)
		invalidateInitialRuntimeRequest(request)
		return nil, ErrAttemptSessionAuthority
	}
	boundState := &sessionBoundRuntimeState{
		request: private, cell: cell, runtime: runtime,
		lifecycle: lifecycle, active: true,
	}
	result := &SessionBoundRuntime{state: boundState}
	boundState.issued = result
	private.bound = boundState
	private.mu.Unlock()
	return result, nil
}

func (tuple *InitialRuntimeTuple) Coordinates() discoveryqueue.RunCoordinates {
	private := tuple.private()
	if private == nil {
		return discoveryqueue.RunCoordinates{}
	}
	private.mu.Lock()
	defer private.mu.Unlock()
	if !private.active || private.issued != tuple {
		return discoveryqueue.RunCoordinates{}
	}
	return private.coordinates
}

func (tuple *InitialRuntimeTuple) Attempt() discoveryqueue.CleanupAttempt {
	private := tuple.private()
	if private == nil {
		return discoveryqueue.CleanupAttempt{}
	}
	private.mu.Lock()
	defer private.mu.Unlock()
	if !private.active || private.issued != tuple {
		return discoveryqueue.CleanupAttempt{}
	}
	return private.attempt
}

func (tuple *InitialRuntimeTuple) RuntimeBinding() discoverysource.RuntimeBinding {
	private := tuple.private()
	if private == nil {
		return discoverysource.RuntimeBinding{}
	}
	private.mu.Lock()
	defer private.mu.Unlock()
	if !private.active || private.issued != tuple {
		return discoverysource.RuntimeBinding{}
	}
	return private.binding
}

func (tuple *InitialRuntimeTuple) private() *initialRuntimeTupleState {
	if tuple == nil || tuple.self != tuple ||
		tuple.seal != initialRuntimeTupleSeal || tuple.state == nil {
		return nil
	}
	return tuple.state
}

func (handle *initialAttemptSessionHandle) BindRuntime(
	ctx context.Context,
	expected discoverysource.RuntimeBinding,
) (discoverysource.BoundRuntime, error) {
	if ctx == nil || handle == nil || handle.cell == nil {
		return discoverysource.BoundRuntime{}, ErrAttemptSessionAuthority
	}
	if err := ctx.Err(); err != nil {
		return discoverysource.BoundRuntime{}, err
	}
	cell := handle.cell
	cell.mu.Lock()
	defer cell.mu.Unlock()
	if !cell.active || cell.handle != handle || cell.binding != expected ||
		cell.runtime.Binding() != expected {
		return discoverysource.BoundRuntime{}, ErrAttemptSessionAuthority
	}
	return cell.runtime, nil
}

func (handle *initialAttemptSessionHandle) Revoke(ctx context.Context) error {
	if ctx == nil || handle == nil || handle.cell == nil {
		return ErrAttemptSessionAuthority
	}
	return handle.cell.revoke(ctx, handle)
}

func (handle *initialAttemptSessionHandle) Destroy() {
	if handle == nil || handle.cell == nil {
		return
	}
	handle.cell.destroy(handle)
}

func (handle *recoveryAttemptSessionHandle) Revoke(ctx context.Context) error {
	if ctx == nil || handle == nil || handle.cell == nil {
		return ErrAttemptSessionAuthority
	}
	return handle.cell.revoke(ctx, handle)
}

func (handle *recoveryAttemptSessionHandle) Destroy() {
	if handle == nil || handle.cell == nil {
		return
	}
	handle.cell.destroy(handle)
}

func (authority *AttemptSessionAuthority) Destroy() {
	if !authority.authentic() {
		return
	}
	private := authority.state
	private.mu.Lock()
	if private.destroyed {
		done := private.destroyDone
		private.mu.Unlock()
		<-done
		return
	}
	private.destroyed = true
	private.cancel()
	private.mu.Unlock()
	private.operations.Wait()

	private.mu.Lock()
	cells := make([]*attemptSessionCell, 0, len(private.sessions))
	for _, cell := range private.sessions {
		cells = append(cells, cell)
	}
	recoveries := make([]*recoveryAttemptSessionCell, 0, len(private.recoveries))
	for cell := range private.recoveries {
		recoveries = append(recoveries, cell)
	}
	private.sessions = nil
	private.recoveries = nil
	private.transport = nil
	private.factory = nil
	private.profile = attemptProfileSnapshot{}
	private.mu.Unlock()
	for _, cell := range cells {
		cell.destroy(nil)
	}
	for _, cell := range recoveries {
		cell.destroy(nil)
	}
	close(private.destroyDone)
}

func (authority *AttemptSessionAuthority) authentic() bool {
	return authority != nil && authority.self == authority &&
		authority.seal == attemptSessionAuthoritySeal && authority.state != nil
}

func (authority *AttemptSessionAuthority) begin(
	ctx context.Context,
) (*attemptSessionAuthorityState, context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	private := authority.state
	private.mu.Lock()
	if private.destroyed || private.transport == nil || nilDependency(private.factory) {
		private.mu.Unlock()
		return nil, nil, nil, ErrAttemptSessionAuthority
	}
	private.operations.Add(1)
	private.mu.Unlock()
	operationContext, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(private.lifetime, cancel)
	release := func() {
		_ = stop()
		cancel()
		private.operations.Done()
	}
	return private, operationContext, release, nil
}

func (private *attemptSessionAuthorityState) install(cell *attemptSessionCell) error {
	private.mu.Lock()
	defer private.mu.Unlock()
	if private.destroyed || cell == nil || !cell.request.Attempt.Valid() {
		return ErrAttemptSessionAuthority
	}
	if _, exists := private.sessions[cell.request.Attempt.AttemptID]; exists {
		return discoverycleanup.ErrSessionAuthentication
	}
	private.sessions[cell.request.Attempt.AttemptID] = cell
	return nil
}

func (private *attemptSessionAuthorityState) lookup(
	attemptID string,
) *attemptSessionCell {
	private.mu.Lock()
	defer private.mu.Unlock()
	if private.destroyed {
		return nil
	}
	return private.sessions[attemptID]
}

func (private *attemptSessionAuthorityState) remove(cell *attemptSessionCell) {
	if private == nil || cell == nil {
		return
	}
	private.mu.Lock()
	if private.sessions != nil &&
		private.sessions[cell.request.Attempt.AttemptID] == cell {
		delete(private.sessions, cell.request.Attempt.AttemptID)
	}
	private.mu.Unlock()
}

func (private *attemptSessionAuthorityState) installRecovery(
	cell *recoveryAttemptSessionCell,
) error {
	private.mu.Lock()
	defer private.mu.Unlock()
	if private.destroyed || cell == nil || private.recoveries == nil {
		return ErrAttemptSessionAuthority
	}
	private.recoveries[cell] = struct{}{}
	return nil
}

func (private *attemptSessionAuthorityState) removeRecovery(
	cell *recoveryAttemptSessionCell,
) {
	if private == nil || cell == nil {
		return
	}
	private.mu.Lock()
	if private.recoveries != nil {
		delete(private.recoveries, cell)
	}
	private.mu.Unlock()
}

func (cell *attemptSessionCell) matchesResolveRequest(
	request ResolveOpenedAttemptRequest,
) bool {
	if cell == nil || request.cell == nil {
		return false
	}
	cell.mu.Lock()
	defer cell.mu.Unlock()
	return cell.matchesResolveRequestLocked(request)
}

func (cell *attemptSessionCell) matchesResolveRequestLocked(
	request ResolveOpenedAttemptRequest,
) bool {
	return cell.active && !cell.revoking && cell.handle != nil &&
		cell.request.Coordinates == request.cell.coordinates &&
		cell.request.Attempt == request.cell.attempt &&
		cell.binding == request.cell.binding &&
		!nilDependency(cell.lifecycle) &&
		cell.runtime == request.cell.runtime &&
		cell.runtime.Binding() == cell.binding
}

func (cell *attemptSessionCell) newClaimRuntime(
	request ResolveOpenedAttemptRequest,
	provider discoverysource.Provider,
	checkpoint *discoverysource.Checkpoint,
	limits discoverysource.Limits,
	policy assetdiscovery.FactPolicy,
) (ClaimRuntime, bool) {
	cell.mu.Lock()
	defer cell.mu.Unlock()
	if !cell.matchesResolveRequestLocked(request) {
		return ClaimRuntime{}, false
	}
	runtime, err := request.NewClaimRuntime(provider, checkpoint, limits, policy)
	return runtime, err == nil
}

func (cell *attemptSessionCell) revoke(
	ctx context.Context,
	handle *initialAttemptSessionHandle,
) error {
	for {
		cell.mu.Lock()
		if !cell.active || cell.handle != handle || cell.transport == nil ||
			cell.lease == nil {
			cell.mu.Unlock()
			return ErrAttemptSessionAuthority
		}
		if cell.revoking {
			done := cell.revokeDone
			cell.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-done:
			}
			continue
		}
		if cell.revokeErr != nil {
			result := cell.revokeErr
			cell.mu.Unlock()
			return result
		}
		cell.revoking = true
		cell.revokeDone = make(chan struct{})
		transport, lease := cell.transport, cell.lease
		cell.mu.Unlock()

		transportErr := transport.Revoke(ctx, lease)
		lifecycleErr := cell.revokeRuntimeLifecycle(ctx)
		revokeErr := errors.Join(transportErr, lifecycleErr)
		var runtime discoverysource.BoundRuntime
		var lifecycle InitialRuntimeLifecycle
		var owner *attemptSessionAuthorityState
		cell.mu.Lock()
		cell.revokeErr = revokeErr
		if revokeErr != nil {
			cell.revoking = false
			close(cell.revokeDone)
			cell.mu.Unlock()
			return revokeErr
		}
		cell.active = false
		runtime = cell.runtime
		cell.runtime = discoverysource.BoundRuntime{}
		lifecycle = cell.lifecycle
		cell.lifecycle = nil
		owner = cell.owner
		cell.owner = nil
		cell.transport = nil
		cell.lease = nil
		cell.binding = discoverysource.RuntimeBinding{}
		cell.digest = ""
		revokeDone := cell.revokeDone
		cell.mu.Unlock()

		runtime.Clear()
		if !nilDependency(lifecycle) {
			lifecycle.Destroy()
		}
		lease.Destroy()
		owner.remove(cell)

		cell.mu.Lock()
		cell.handle = nil
		cell.revoking = false
		close(revokeDone)
		cell.mu.Unlock()
		return nil
	}
}

func (cell *attemptSessionCell) destroy(handle *initialAttemptSessionHandle) {
	if cell == nil {
		return
	}
	for {
		cell.mu.Lock()
		if handle != nil && cell.handle != handle {
			cell.mu.Unlock()
			return
		}
		if cell.revoking {
			done := cell.revokeDone
			cell.mu.Unlock()
			<-done
			continue
		}
		if !cell.active {
			cell.mu.Unlock()
			return
		}
		cell.active = false
		runtime, lease, owner := cell.runtime, cell.lease, cell.owner
		lifecycle := cell.lifecycle
		cell.runtime = discoverysource.BoundRuntime{}
		cell.lifecycle = nil
		cell.owner = nil
		cell.transport = nil
		cell.lease = nil
		cell.handle = nil
		cell.binding = discoverysource.RuntimeBinding{}
		cell.digest = ""
		cell.mu.Unlock()
		runtime.Clear()
		if lifecycle != nil {
			lifecycle.Destroy()
		}
		if lease != nil {
			lease.Destroy()
		}
		owner.remove(cell)
		return
	}
}

func (cell *attemptSessionCell) revokeRuntimeLifecycle(ctx context.Context) error {
	cell.mu.Lock()
	lifecycle := cell.lifecycle
	cell.mu.Unlock()
	if nilDependency(lifecycle) {
		return nil
	}
	return lifecycle.Revoke(ctx)
}

func newRecoveryAttemptSessionHandle(
	owner *attemptSessionAuthorityState,
	transport *discoverycleanup.SessionTransport,
	lease *discoverycleanup.SessionLease,
) *recoveryAttemptSessionHandle {
	cell := &recoveryAttemptSessionCell{
		owner: owner, transport: transport, lease: lease, active: true,
	}
	handle := &recoveryAttemptSessionHandle{cell: cell}
	cell.handle = handle
	return handle
}

func (cell *recoveryAttemptSessionCell) revoke(
	ctx context.Context,
	handle *recoveryAttemptSessionHandle,
) error {
	for {
		cell.mu.Lock()
		if !cell.active || cell.handle != handle || cell.transport == nil ||
			cell.lease == nil {
			cell.mu.Unlock()
			return ErrAttemptSessionAuthority
		}
		if cell.revoking {
			done := cell.revokeDone
			cell.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-done:
			}
			continue
		}
		if cell.revokeErr != nil {
			result := cell.revokeErr
			cell.mu.Unlock()
			return result
		}
		cell.revoking = true
		cell.revokeDone = make(chan struct{})
		transport, lease := cell.transport, cell.lease
		cell.mu.Unlock()

		revokeErr := transport.Revoke(ctx, lease)
		var owner *attemptSessionAuthorityState
		cell.mu.Lock()
		cell.revoking = false
		cell.revokeErr = revokeErr
		if revokeErr == nil {
			cell.active = false
			owner = cell.owner
			cell.owner = nil
			cell.transport = nil
			cell.lease = nil
			cell.handle = nil
		}
		close(cell.revokeDone)
		cell.mu.Unlock()
		if revokeErr == nil {
			lease.Destroy()
			owner.removeRecovery(cell)
		}
		return revokeErr
	}
}

func (cell *recoveryAttemptSessionCell) destroy(
	handle *recoveryAttemptSessionHandle,
) {
	if cell == nil {
		return
	}
	for {
		cell.mu.Lock()
		if handle != nil && cell.handle != handle {
			cell.mu.Unlock()
			return
		}
		if cell.revoking {
			done := cell.revokeDone
			cell.mu.Unlock()
			<-done
			continue
		}
		if !cell.active {
			cell.mu.Unlock()
			return
		}
		cell.active = false
		lease := cell.lease
		owner := cell.owner
		cell.owner = nil
		cell.transport = nil
		cell.lease = nil
		cell.handle = nil
		cell.mu.Unlock()
		if lease != nil {
			lease.Destroy()
		}
		owner.removeRecovery(cell)
		return
	}
}

func newInitialRuntimeRequest(
	cell *attemptSessionCell,
	binding discoverysource.RuntimeBinding,
) *InitialRuntimeRequest {
	private := &initialRuntimeRequestState{
		cell: cell, binding: binding, active: true,
	}
	request := &InitialRuntimeRequest{state: private}
	private.issued = request
	return request
}

func newInitialRuntimeTuple(
	request discoverycleanup.OpenAttemptRequest,
	binding discoverysource.RuntimeBinding,
) *InitialRuntimeTuple {
	private := &initialRuntimeTupleState{
		coordinates: request.Coordinates,
		attempt:     request.Attempt,
		binding:     binding,
		active:      true,
	}
	tuple := &InitialRuntimeTuple{
		seal:  initialRuntimeTupleSeal,
		state: private,
	}
	tuple.self = tuple
	private.issued = tuple
	return tuple
}

func (tuple *InitialRuntimeTuple) destroy() {
	private := tuple.private()
	if private == nil {
		return
	}
	private.mu.Lock()
	if private.issued == tuple {
		private.active = false
		private.issued = nil
		private.coordinates = discoveryqueue.RunCoordinates{}
		private.attempt = discoveryqueue.CleanupAttempt{}
		private.binding = discoverysource.RuntimeBinding{}
	}
	private.mu.Unlock()
}

func consumeSessionBoundRuntime(
	request *InitialRuntimeRequest,
	result *SessionBoundRuntime,
) (initialRuntimeOwnership, error) {
	if request == nil || request.state == nil {
		return initialRuntimeOwnership{}, ErrAttemptSessionAuthority
	}
	private := request.state
	private.mu.Lock()
	defer private.mu.Unlock()
	bound := private.bound
	if !private.active || private.issued != request || !private.used ||
		bound == nil || result == nil || result.state != bound ||
		bound.issued != result || !bound.active ||
		bound.request != private || bound.cell != private.cell ||
		bound.runtime.Binding() != private.binding ||
		nilDependency(bound.lifecycle) {
		ownership := invalidateInitialRuntimeState(private)
		return ownership, ErrAttemptSessionAuthority
	}
	ownership := initialRuntimeOwnership{
		runtime: bound.runtime, lifecycle: bound.lifecycle,
	}
	bound.active = false
	bound.runtime = discoverysource.BoundRuntime{}
	bound.lifecycle = nil
	bound.request = nil
	bound.cell = nil
	bound.issued = nil
	private.active = false
	private.issued = nil
	private.cell = nil
	private.binding = discoverysource.RuntimeBinding{}
	private.bound = nil
	return ownership, nil
}

func invalidateInitialRuntimeRequest(
	request *InitialRuntimeRequest,
) initialRuntimeOwnership {
	if request == nil || request.state == nil {
		return initialRuntimeOwnership{}
	}
	private := request.state
	private.mu.Lock()
	defer private.mu.Unlock()
	return invalidateInitialRuntimeState(private)
}

func invalidateInitialRuntimeState(
	private *initialRuntimeRequestState,
) initialRuntimeOwnership {
	if private == nil {
		return initialRuntimeOwnership{}
	}
	var ownership initialRuntimeOwnership
	if private.bound != nil {
		ownership.runtime = private.bound.runtime
		ownership.lifecycle = private.bound.lifecycle
		private.bound.active = false
		private.bound.runtime = discoverysource.BoundRuntime{}
		private.bound.lifecycle = nil
		private.bound.request = nil
		private.bound.cell = nil
		private.bound.issued = nil
	}
	private.active = false
	private.issued = nil
	private.cell = nil
	private.binding = discoverysource.RuntimeBinding{}
	private.bound = nil
	return ownership
}

func releaseInitialRuntime(
	ctx context.Context,
	ownership initialRuntimeOwnership,
) {
	if !nilDependency(ownership.lifecycle) {
		revokeContext := ctx
		if revokeContext == nil {
			revokeContext = context.Background()
		}
		_ = ownership.lifecycle.Revoke(revokeContext)
	}
	ownership.runtime.Clear()
	if !nilDependency(ownership.lifecycle) {
		ownership.lifecycle.Destroy()
	}
}

func (profile attemptProfileSnapshot) valid() bool {
	return profile.sourceKind.Valid() &&
		profile.sourceKind != assetcatalog.SourceKindManual &&
		validAttemptProviderKind(profile.providerKind) &&
		profile.profileCode.Valid() &&
		validAttemptDigest(profile.digest)
}

func attemptBindingMatches(
	request discoverycleanup.OpenAttemptRequest,
	binding discoverysource.RuntimeBinding,
	profile attemptProfileSnapshot,
) bool {
	return validRuntimeBinding(binding) &&
		binding.Locator.Scope == request.Coordinates.Scope &&
		binding.ProviderKind == profile.providerKind &&
		binding.ProfileCode == profile.profileCode
}

func runtimeBindingDigest(
	profile attemptProfileSnapshot,
	binding discoverysource.RuntimeBinding,
) string {
	digest := sha256.Sum256(frameAttemptSessionTuple(
		attemptSessionDigestDomain,
		string(profile.sourceKind),
		profile.providerKind,
		string(profile.profileCode),
		profile.digest,
		binding.Locator.Scope.TenantID,
		binding.Locator.Scope.WorkspaceID,
		binding.Locator.SourceID,
		strconv.FormatInt(binding.SourceRevision, 10),
		binding.SourceRevisionDigest,
		string(binding.RevisionStatus),
		binding.ProviderKind,
		string(binding.ProfileCode),
	))
	return fmt.Sprintf("%x", digest)
}

func frameAttemptSessionTuple(fields ...string) []byte {
	size := 0
	for _, field := range fields {
		size += 4 + len(field)
	}
	result := make([]byte, 0, size)
	for _, field := range fields {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		result = append(result, length[:]...)
		result = append(result, field...)
	}
	return result
}

func validAttemptProviderKind(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for _, character := range []byte(value[1:]) {
		if (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validAttemptDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range []byte(value) {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func mapSessionTransportError(err error) error {
	switch {
	case errors.Is(err, discoverycleanup.ErrSessionTransportAuthentication),
		errors.Is(err, discoverycleanup.ErrSessionTransportDrift):
		return discoverycleanup.ErrSessionAuthentication
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return ErrAttemptSessionAuthority
	}
}

func boundedAttemptAuthorityError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return ErrAttemptSessionAuthority
}

func (AttemptSessionAuthority) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*AttemptSessionAuthority) UnmarshalJSON([]byte) error {
	return ErrSensitiveSerialization
}
func (AttemptSessionAuthority) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*AttemptSessionAuthority) UnmarshalText([]byte) error {
	return ErrSensitiveSerialization
}
func (AttemptSessionAuthority) MarshalBinary() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*AttemptSessionAuthority) UnmarshalBinary([]byte) error {
	return ErrSensitiveSerialization
}
func (AttemptSessionAuthority) String() string   { return attemptSessionAuthorityRedaction }
func (AttemptSessionAuthority) GoString() string { return attemptSessionAuthorityRedaction }
func (AttemptSessionAuthority) LogValue() slog.Value {
	return slog.StringValue(attemptSessionAuthorityRedaction)
}
func (AttemptSessionAuthority) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, attemptSessionAuthorityRedaction)
}

func (InitialRuntimeRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*InitialRuntimeRequest) UnmarshalJSON([]byte) error {
	return ErrSensitiveSerialization
}
func (InitialRuntimeRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*InitialRuntimeRequest) UnmarshalText([]byte) error {
	return ErrSensitiveSerialization
}
func (InitialRuntimeRequest) MarshalBinary() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*InitialRuntimeRequest) UnmarshalBinary([]byte) error {
	return ErrSensitiveSerialization
}
func (InitialRuntimeRequest) String() string   { return initialRuntimeRequestRedaction }
func (InitialRuntimeRequest) GoString() string { return initialRuntimeRequestRedaction }
func (InitialRuntimeRequest) LogValue() slog.Value {
	return slog.StringValue(initialRuntimeRequestRedaction)
}
func (InitialRuntimeRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, initialRuntimeRequestRedaction)
}

func (InitialRuntimeTuple) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*InitialRuntimeTuple) UnmarshalJSON([]byte) error {
	return ErrSensitiveSerialization
}
func (InitialRuntimeTuple) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*InitialRuntimeTuple) UnmarshalText([]byte) error {
	return ErrSensitiveSerialization
}
func (InitialRuntimeTuple) MarshalBinary() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*InitialRuntimeTuple) UnmarshalBinary([]byte) error {
	return ErrSensitiveSerialization
}
func (InitialRuntimeTuple) String() string   { return initialRuntimeTupleRedaction }
func (InitialRuntimeTuple) GoString() string { return initialRuntimeTupleRedaction }
func (InitialRuntimeTuple) LogValue() slog.Value {
	return slog.StringValue(initialRuntimeTupleRedaction)
}
func (InitialRuntimeTuple) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, initialRuntimeTupleRedaction)
}

func (SessionBoundRuntime) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*SessionBoundRuntime) UnmarshalJSON([]byte) error {
	return ErrSensitiveSerialization
}
func (SessionBoundRuntime) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*SessionBoundRuntime) UnmarshalText([]byte) error {
	return ErrSensitiveSerialization
}
func (SessionBoundRuntime) MarshalBinary() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*SessionBoundRuntime) UnmarshalBinary([]byte) error {
	return ErrSensitiveSerialization
}
func (SessionBoundRuntime) String() string   { return sessionBoundRuntimeRedaction }
func (SessionBoundRuntime) GoString() string { return sessionBoundRuntimeRedaction }
func (SessionBoundRuntime) LogValue() slog.Value {
	return slog.StringValue(sessionBoundRuntimeRedaction)
}
func (SessionBoundRuntime) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, sessionBoundRuntimeRedaction)
}

var (
	_ discoverycleanup.SessionOpener        = (*AttemptSessionAuthority)(nil)
	_ ClaimRuntimeResolver                  = (*AttemptSessionAuthority)(nil)
	_ discoverycleanup.RuntimeSessionHandle = (*initialAttemptSessionHandle)(nil)
	_ discoverycleanup.SessionHandle        = (*recoveryAttemptSessionHandle)(nil)
)
