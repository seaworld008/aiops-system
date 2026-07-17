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
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

const (
	attemptSessionDigestDomain       = "discovery-attempt-runtime-binding.v1"
	attemptSessionAuthorityRedaction = "[REDACTED_ATTEMPT_SESSION_AUTHORITY]"
	initialRuntimeRequestRedaction   = "[REDACTED_INITIAL_RUNTIME_REQUEST]"
	sessionBoundRuntimeRedaction     = "[REDACTED_SESSION_BOUND_RUNTIME]"
	attemptSessionAuthoritySeal      = uint64(0x5f92a614c37bd8e1)
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
	handle     *initialAttemptSessionHandle
	revokeDone chan struct{}
	revokeErr  error
	revoking   bool
	active     bool
}

// InitialRuntimeRequest is a one-use, same-cell capability. RuntimeBinding
// exposes only immutable safe metadata; BindRuntime accepts a BoundRuntime only
// for this exact request and can be called once.
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

// SessionBoundRuntime is the factory's proof that its runtime was bound
// through the exact InitialRuntimeRequest. It is consumed immediately by the
// authority and never crosses the Broker ABI.
type SessionBoundRuntime struct {
	state *sessionBoundRuntimeState
}

type sessionBoundRuntimeState struct {
	issued  *SessionBoundRuntime
	request *initialRuntimeRequestState
	cell    *attemptSessionCell
	runtime discoverysource.BoundRuntime
	active  bool
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
		runtime := invalidateInitialRuntimeRequest(initialRequest)
		runtime.Clear()
		return handle, boundedAttemptAuthorityError(openErr)
	}
	runtime, consumeErr := consumeSessionBoundRuntime(initialRequest, result)
	if consumeErr != nil {
		runtime.Clear()
		return handle, ErrAttemptSessionAuthority
	}
	cell.mu.Lock()
	if !cell.active || cell.handle != handle || cell.binding != runtime.Binding() {
		cell.mu.Unlock()
		runtime.Clear()
		return handle, ErrAttemptSessionAuthority
	}
	cell.runtime = runtime
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

func (request *InitialRuntimeRequest) RuntimeBinding() discoverysource.RuntimeBinding {
	if request == nil || request.state == nil {
		return discoverysource.RuntimeBinding{}
	}
	private := request.state
	private.mu.Lock()
	defer private.mu.Unlock()
	if !private.active || private.issued != request || private.cell == nil {
		return discoverysource.RuntimeBinding{}
	}
	return private.binding
}

func (request *InitialRuntimeRequest) BindRuntime(
	runtime discoverysource.BoundRuntime,
) (*SessionBoundRuntime, error) {
	if request == nil || request.state == nil {
		return nil, ErrAttemptSessionAuthority
	}
	private := request.state
	private.mu.Lock()
	defer private.mu.Unlock()
	if !private.active || private.issued != request || private.cell == nil ||
		private.used || runtime.Binding() != private.binding {
		return nil, ErrAttemptSessionAuthority
	}
	private.used = true
	boundState := &sessionBoundRuntimeState{
		request: private, cell: private.cell, runtime: runtime, active: true,
	}
	result := &SessionBoundRuntime{state: boundState}
	boundState.issued = result
	private.bound = boundState
	return result, nil
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

		revokeErr := transport.Revoke(ctx, lease)
		var runtime discoverysource.BoundRuntime
		var owner *attemptSessionAuthorityState
		cell.mu.Lock()
		cell.revoking = false
		cell.revokeErr = revokeErr
		if revokeErr == nil {
			cell.active = false
			runtime = cell.runtime
			cell.runtime = discoverysource.BoundRuntime{}
			owner = cell.owner
			cell.owner = nil
			cell.transport = nil
			cell.lease = nil
			cell.handle = nil
			cell.binding = discoverysource.RuntimeBinding{}
			cell.digest = ""
		}
		close(cell.revokeDone)
		cell.mu.Unlock()
		if revokeErr == nil {
			runtime.Clear()
			lease.Destroy()
			owner.remove(cell)
		}
		return revokeErr
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
		cell.runtime = discoverysource.BoundRuntime{}
		cell.owner = nil
		cell.transport = nil
		cell.lease = nil
		cell.handle = nil
		cell.binding = discoverysource.RuntimeBinding{}
		cell.digest = ""
		cell.mu.Unlock()
		runtime.Clear()
		if lease != nil {
			lease.Destroy()
		}
		owner.remove(cell)
		return
	}
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

func consumeSessionBoundRuntime(
	request *InitialRuntimeRequest,
	result *SessionBoundRuntime,
) (discoverysource.BoundRuntime, error) {
	if request == nil || request.state == nil {
		return discoverysource.BoundRuntime{}, ErrAttemptSessionAuthority
	}
	private := request.state
	private.mu.Lock()
	defer private.mu.Unlock()
	bound := private.bound
	if !private.active || private.issued != request || !private.used ||
		bound == nil || result == nil || result.state != bound ||
		bound.issued != result || !bound.active ||
		bound.request != private || bound.cell != private.cell ||
		bound.runtime.Binding() != private.binding {
		runtime := invalidateInitialRuntimeState(private)
		return runtime, ErrAttemptSessionAuthority
	}
	runtime := bound.runtime
	bound.active = false
	bound.runtime = discoverysource.BoundRuntime{}
	bound.request = nil
	bound.cell = nil
	bound.issued = nil
	private.active = false
	private.issued = nil
	private.cell = nil
	private.binding = discoverysource.RuntimeBinding{}
	private.bound = nil
	return runtime, nil
}

func invalidateInitialRuntimeRequest(
	request *InitialRuntimeRequest,
) discoverysource.BoundRuntime {
	if request == nil || request.state == nil {
		return discoverysource.BoundRuntime{}
	}
	private := request.state
	private.mu.Lock()
	defer private.mu.Unlock()
	return invalidateInitialRuntimeState(private)
}

func invalidateInitialRuntimeState(
	private *initialRuntimeRequestState,
) discoverysource.BoundRuntime {
	if private == nil {
		return discoverysource.BoundRuntime{}
	}
	var runtime discoverysource.BoundRuntime
	if private.bound != nil {
		runtime = private.bound.runtime
		private.bound.active = false
		private.bound.runtime = discoverysource.BoundRuntime{}
		private.bound.request = nil
		private.bound.cell = nil
		private.bound.issued = nil
	}
	private.active = false
	private.issued = nil
	private.cell = nil
	private.binding = discoverysource.RuntimeBinding{}
	private.bound = nil
	return runtime
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
