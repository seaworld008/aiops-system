package vsphere

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/methods"
	"github.com/vmware/govmomi/vim25/types"
)

const (
	maxFullInventoryPageObjects = int32(500)
	fullInventoryAttemptRedact  = "[REDACTED_VSPHERE_FULL_INVENTORY_ATTEMPT]"
)

var (
	errInventoryContinuity       = errors.New("vsphere full inventory continuity unavailable")
	errInventoryIdentityDrift    = errors.New("vsphere inventory identity drift")
	errInventoryRejected         = errors.New("vsphere inventory rejected")
	errInventoryCleanupUncertain = errors.New("vsphere inventory cleanup uncertain")
	ignoredInventoryObjectTypes  = []string{
		"DistributedVirtualSwitch",
		"DistributedVirtualPortgroup",
		"VmwareDistributedVirtualSwitch",
	}
)

const (
	inventoryTopologyFolderChild      = "FOLDER_CHILD"
	inventoryTopologyDatacenterVMRoot = "DATACENTER_VM_ROOT"
)

type inventoryPageClient interface {
	validationClient
	RetrieveInventoryPage(
		context.Context,
		types.ManagedObjectReference,
		int32,
	) (types.RetrieveResult, error)
	ContinueInventoryPage(context.Context, string) (types.RetrieveResult, error)
	CollectorReference() types.ManagedObjectReference
}

// FullInventoryAttempt is an opaque, process-local same-attempt session cell.
// It intentionally has no cross-Run recovery method: a persisted token hash
// cannot reconstruct the live login session or PropertyCollector.
type FullInventoryAttempt struct {
	state *fullInventoryAttemptState
}

// fullInventoryStateBarrier preserves the Lock/Unlock contract consumed by
// rollover_handoff.go while allowing terminal cleanup to cancel an in-flight
// SOAP operation through the raw state lock. A normal locker keeps turnstile
// ownership while waiting for operationDone, so a later Discover cannot
// overtake an already waiting handoff.
type fullInventoryStateBarrier struct {
	turnstile     sync.Mutex
	raw           sync.Mutex
	operationDone chan struct{}
}

func (barrier *fullInventoryStateBarrier) Lock() {
	barrier.turnstile.Lock()
	for {
		barrier.raw.Lock()
		done := barrier.operationDone
		if done == nil {
			return
		}
		barrier.raw.Unlock()
		<-done
	}
}

func (barrier *fullInventoryStateBarrier) Unlock() {
	barrier.raw.Unlock()
	barrier.turnstile.Unlock()
}

func (barrier *fullInventoryStateBarrier) rawLock() {
	barrier.raw.Lock()
}

func (barrier *fullInventoryStateBarrier) rawUnlock() {
	barrier.raw.Unlock()
}

func (barrier *fullInventoryStateBarrier) beginOperationLocked(done chan struct{}) {
	barrier.operationDone = done
}

func (barrier *fullInventoryStateBarrier) finishOperationLocked(done chan struct{}) {
	if barrier.operationDone == done {
		barrier.operationDone = nil
		close(done)
	}
}

type fullInventoryOperation struct {
	generation uint64
	context    context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	client     inventoryPageClient
	root       types.ManagedObjectReference
	token      string
	rawMode    bool
}

type fullInventoryAttemptState struct {
	mu fullInventoryStateBarrier

	resolved           resolvedRuntime
	authority          authoritySnapshot
	rolloverSeed       fullInventoryCheckpoint
	rolloverAuthorized bool
	rolloverBinding    discoverysource.RuntimeBinding
	rolloverGoverned   bool
	rolloverRecord     *fullInventoryRolloverRegistration
	rolloverRevocation *fullInventoryRolloverRevocation
	lastCheckpoint     fullInventoryCheckpoint
	hasLastCheckpoint  bool
	lastBinding        discoverysource.RuntimeBinding
	lastAuthority      authoritySnapshot
	emittedObjects     map[string]struct{}
	emittedRelations   map[string]struct{}
	rolloverObjects    map[string]struct{}
	rolloverRelations  map[string]struct{}
	replay             fullInventoryReplayCell
	binding            discoverysource.RuntimeBinding
	runtime            discoverysource.BoundRuntime
	client             inventoryPageClient
	collector          types.ManagedObjectReference

	sequence          int64
	fullSnapshotID    string
	successorID       string
	pageToken         []byte
	checkpointToken   []byte
	soapContinuation  bool
	rootIndex         int
	seenObjects       map[types.ManagedObjectReference]types.ManagedObjectReference
	transparentNodes  map[types.ManagedObjectReference]types.ManagedObjectReference
	topologyRelations map[string]inventoryRelation
	relationKeys      map[string]struct{}
	pending           map[string]inventoryRelation
	items             []inventoryObject
	relations         []inventoryRelation
	operation         *fullInventoryOperation
	generation        uint64

	started       bool
	completed     bool
	failed        bool
	handoffFrozen bool
	revokeStart   bool
	revokeDone    chan struct{}
	revokeErr     error
	destroyed     bool
}

type fullInventoryReplayCell struct {
	input      fullInventoryCheckpoint
	inputEmpty bool
	output     fullInventoryCheckpoint
	limits     discoverysource.Limits
	binding    discoverysource.RuntimeBinding
	authority  authoritySnapshot
	page       discoverysource.Page
	active     bool
}

type fullInventoryRuntimeView struct {
	attempt *FullInventoryAttempt
	binding discoverysource.RuntimeBinding
}

func NewFullInventoryAttempt(material *RuntimeMaterial) (*FullInventoryAttempt, error) {
	return newFullInventoryAttempt(
		material,
		fullInventoryCheckpoint{},
		false,
		discoverysource.RuntimeBinding{},
		authoritySnapshot{},
		nil,
		nil,
	)
}

// NewRolloverSuccessor is a permanently fail-closed compatibility surface.
// A raw attempt cannot prove Queue admission, the current fence/attempt tuple,
// or the Broker Revoke+Destroy lifecycle. The only legal successor path is
// FullInventoryRolloverHandoff.NewSuccessor after BeginHandoff succeeds.
func (*FullInventoryAttempt) NewRolloverSuccessor(
	material *RuntimeMaterial,
	_ discoverysource.Checkpoint,
) (*FullInventoryAttempt, error) {
	if material != nil {
		material.Clear()
	}
	return nil, errInventoryContinuity
}

func newFullInventoryAttempt(
	material *RuntimeMaterial,
	rolloverSeed fullInventoryCheckpoint,
	rolloverAuthorized bool,
	rolloverBinding discoverysource.RuntimeBinding,
	rolloverAuthority authoritySnapshot,
	emittedObjects map[string]struct{},
	emittedRelations map[string]struct{},
) (*FullInventoryAttempt, error) {
	if material == nil {
		rolloverAuthority.Clear()
		clear(emittedObjects)
		clear(emittedRelations)
		return nil, errInventoryRejected
	}
	resolved, ok := material.snapshot()
	material.Clear()
	if !ok || !resolved.valid() {
		resolved.Clear()
		rolloverAuthority.Clear()
		clear(emittedObjects)
		clear(emittedRelations)
		return nil, errInventoryRejected
	}
	authority := authoritySnapshot{
		instanceUUID:  resolved.authority.instanceUUID,
		environmentID: resolved.authority.environmentID,
		roots:         slices.Clone(resolved.authority.roots),
		rootDigest:    resolved.authority.rootDigest,
	}
	if !authority.valid() {
		resolved.Clear()
		authority.Clear()
		rolloverAuthority.Clear()
		clear(emittedObjects)
		clear(emittedRelations)
		return nil, errInventoryRejected
	}
	if rolloverAuthorized &&
		(rolloverSeed.instanceUUID != authority.instanceUUID ||
			rolloverBinding.ProviderKind != providerKind ||
			rolloverBinding.ProfileCode != profileCode ||
			rolloverBinding.RevisionStatus != assetcatalog.SourceRevisionPublished ||
			!sameAuthoritySnapshot(rolloverAuthority, authority)) {
		resolved.Clear()
		authority.Clear()
		rolloverAuthority.Clear()
		clear(emittedObjects)
		clear(emittedRelations)
		return nil, errInventoryIdentityDrift
	}
	rolloverAuthority.Clear()
	if emittedObjects == nil {
		emittedObjects = make(map[string]struct{})
	}
	if emittedRelations == nil {
		emittedRelations = make(map[string]struct{})
	}
	return &FullInventoryAttempt{state: &fullInventoryAttemptState{
		resolved: resolved, authority: authority,
		rolloverSeed: rolloverSeed, rolloverAuthorized: rolloverAuthorized,
		rolloverBinding: rolloverBinding,
		lastCheckpoint:  rolloverSeed, hasLastCheckpoint: rolloverAuthorized,
		lastBinding:    rolloverBinding,
		lastAuthority:  cloneAuthoritySnapshot(authority),
		emittedObjects: emittedObjects, emittedRelations: emittedRelations,
		rolloverObjects:   cloneInventoryObjects(emittedObjects),
		rolloverRelations: cloneInventoryRelations(emittedRelations),
		revokeDone:        make(chan struct{}),
	}}, nil
}

func cloneAuthoritySnapshot(source authoritySnapshot) authoritySnapshot {
	return authoritySnapshot{
		instanceUUID:  source.instanceUUID,
		environmentID: source.environmentID,
		roots:         slices.Clone(source.roots),
		rootDigest:    source.rootDigest,
	}
}

func sameAuthoritySnapshot(left, right authoritySnapshot) bool {
	return left.valid() &&
		right.valid() &&
		left.instanceUUID == right.instanceUUID &&
		left.environmentID == right.environmentID &&
		left.rootDigest == right.rootDigest &&
		slices.Equal(left.roots, right.roots)
}

func cloneInventoryDiscoverPage(source discoverysource.Page) discoverysource.Page {
	result := discoverysource.Page{
		Items:            slices.Clone(source.Items),
		Relations:        slices.Clone(source.Relations),
		NextCheckpoint:   source.NextCheckpoint.Clone(),
		FinalPage:        source.FinalPage,
		CompleteSnapshot: source.CompleteSnapshot,
	}
	for index := range result.Items {
		result.Items[index].Document = bytes.Clone(source.Items[index].Document)
		result.Items[index].FieldProvenance = slices.Clone(
			source.Items[index].FieldProvenance,
		)
		result.Items[index].Fingerprints = maps.Clone(
			source.Items[index].Fingerprints,
		)
		result.Items[index].Freshness = cloneInventoryFreshness(
			source.Items[index].Freshness,
		)
	}
	for index := range result.Relations {
		result.Relations[index].Freshness = cloneInventoryFreshness(
			source.Relations[index].Freshness,
		)
	}
	return result
}

func cloneInventoryFreshness(
	source assetdiscovery.FreshnessCandidate,
) assetdiscovery.FreshnessCandidate {
	result := source
	if source.OrderTime != nil {
		value := *source.OrderTime
		result.OrderTime = &value
	}
	return result
}

func clearInventoryDiscoverPage(page *discoverysource.Page) {
	if page == nil {
		return
	}
	for index := range page.Items {
		clear(page.Items[index].Document)
		clear(page.Items[index].FieldProvenance)
		clear(page.Items[index].Fingerprints)
		page.Items[index] = assetdiscovery.NormalizedItem{}
	}
	for index := range page.Relations {
		page.Relations[index] = assetdiscovery.ObservedRelation{}
	}
	clear(page.Items)
	clear(page.Relations)
	page.NextCheckpoint.Clear()
	*page = discoverysource.Page{}
}

func (replay *fullInventoryReplayCell) Clear() {
	if replay == nil {
		return
	}
	clearInventoryDiscoverPage(&replay.page)
	replay.authority.Clear()
	replay.input = fullInventoryCheckpoint{}
	replay.inputEmpty = false
	replay.output = fullInventoryCheckpoint{}
	replay.limits = discoverysource.Limits{}
	replay.binding = discoverysource.RuntimeBinding{}
	replay.active = false
}

func cloneInventoryObjects(
	source map[string]struct{},
) map[string]struct{} {
	result := make(map[string]struct{}, len(source))
	for digest := range source {
		result[digest] = struct{}{}
	}
	return result
}

func cloneInventoryRelations(
	source map[string]struct{},
) map[string]struct{} {
	result := make(map[string]struct{}, len(source))
	for digest := range source {
		result[digest] = struct{}{}
	}
	return result
}

func (attempt *FullInventoryAttempt) BindRuntime(
	ctx context.Context,
	binding discoverysource.RuntimeBinding,
) (discoverysource.BoundRuntime, error) {
	if ctx == nil {
		return discoverysource.BoundRuntime{}, errInventoryRejected
	}
	if err := ctx.Err(); err != nil {
		return discoverysource.BoundRuntime{}, err
	}
	if attempt == nil || attempt.state == nil ||
		binding.ProviderKind != providerKind ||
		binding.ProfileCode != profileCode ||
		binding.RevisionStatus != assetcatalog.SourceRevisionPublished {
		return discoverysource.BoundRuntime{}, errInventoryRejected
	}
	private := attempt.state
	private.mu.Lock()
	if private.handoffFrozen {
		private.mu.Unlock()
		return discoverysource.BoundRuntime{}, errInventoryContinuity
	}
	if private.destroyed || private.revokeStart || private.failed ||
		!private.authority.valid() ||
		private.rolloverAuthorized && private.rolloverBinding != binding {
		private.mu.Unlock()
		return discoverysource.BoundRuntime{}, errInventoryRejected
	}
	if private.binding != (discoverysource.RuntimeBinding{}) {
		if private.binding != binding {
			private.mu.Unlock()
			return discoverysource.BoundRuntime{}, errInventoryContinuity
		}
		runtime := private.runtime
		private.mu.Unlock()
		if runtime.Binding() != binding {
			return discoverysource.BoundRuntime{}, errInventoryContinuity
		}
		private.mu.Lock()
		stillBound := !private.destroyed &&
			!private.revokeStart &&
			!private.failed &&
			!private.handoffFrozen &&
			private.binding == binding
		private.mu.Unlock()
		if !stillBound {
			return discoverysource.BoundRuntime{}, errInventoryContinuity
		}
		return runtime, nil
	}
	view := fullInventoryRuntimeView{attempt: attempt, binding: binding}
	runtime, err := discoverysource.BindRuntime(
		binding,
		&view,
		func(*fullInventoryRuntimeView) error { return nil },
		func(value *fullInventoryRuntimeView) {
			if value == nil {
				return
			}
			boundAttempt := value.attempt
			value.attempt = nil
			value.binding = discoverysource.RuntimeBinding{}
			if boundAttempt != nil {
				boundAttempt.revokeFromRuntimeClear()
			}
		},
	)
	if err != nil {
		private.mu.Unlock()
		return discoverysource.BoundRuntime{}, errInventoryRejected
	}
	private.binding = binding
	private.runtime = runtime
	private.mu.Unlock()
	return runtime, nil
}

func (attempt *FullInventoryAttempt) Revoke(ctx context.Context) error {
	if ctx == nil {
		return errInventoryRejected
	}
	if attempt == nil || attempt.state == nil {
		return errInventoryRejected
	}
	private := attempt.state
	_, done := private.startRevoke(false)
	select {
	case <-done:
		return private.revokeErr
	case <-ctx.Done():
		contextErr := ctx.Err()
		private.sealCanceledRolloverRevocation()
		return contextErr
	}
}

// sealCanceledRolloverRevocation makes a caller-visible cleanup timeout
// permanently fail closed before CleanupBroker can call Destroy. The eventual
// finalizer retains sole ownership of the raw client, but it cannot later
// overwrite this safe receipt with a successful rollover prerequisite.
func (private *fullInventoryAttemptState) sealCanceledRolloverRevocation() {
	private.mu.rawLock()
	revocation := private.rolloverRevocation
	private.mu.rawUnlock()
	if revocation == nil {
		return
	}
	revocation.mu.Lock()
	revocation.revoked = true
	revocation.err = errInventoryRejected
	revocation.mu.Unlock()
}

func (attempt *FullInventoryAttempt) revokeFromRuntimeClear() {
	if attempt == nil || attempt.state == nil {
		return
	}
	private := attempt.state
	started, done := private.startRevoke(true)
	if !started {
		return
	}
	timer := time.NewTimer(sessionCleanupTimeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}

func (private *fullInventoryAttemptState) startRevoke(
	fromRuntimeClear bool,
) (bool, <-chan struct{}) {
	private.mu.rawLock()
	if private.revokeStart {
		done := private.revokeDone
		private.mu.rawUnlock()
		return false, done
	}
	private.revokeStart = true
	if private.operation != nil && private.operation.cancel != nil {
		private.operation.cancel()
	}
	done := private.revokeDone
	private.mu.rawUnlock()
	go private.finalizeRevoke(fromRuntimeClear)
	return true, done
}

func (private *fullInventoryAttemptState) finalizeRevoke(runtimeClearing bool) {
	var (
		revokeErr         error
		timedOutOperation *fullInventoryOperation
	)
	defer func() {
		if recover() != nil {
			revokeErr = errInventoryCleanupUncertain
		}
		_ = private.finishRevoke(revokeErr, timedOutOperation)
	}()

	private.mu.rawLock()
	operation := private.operation
	var operationDone <-chan struct{}
	if operation != nil {
		operationDone = operation.done
	}
	private.mu.rawUnlock()
	operationTimedOut := false
	if operationDone != nil {
		timer := time.NewTimer(sessionCleanupTimeout)
		select {
		case <-operationDone:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
			operationTimedOut = true
		}
	}

	private.mu.rawLock()
	if operationTimedOut &&
		private.operation == operation &&
		private.mu.operationDone == operation.done {
		private.seedCleanupUncertaintyLocked()
		timedOutOperation = operation
	}
	client, runtime := private.detachForRevokeLocked()
	private.mu.rawUnlock()
	if !runtimeClearing {
		if clearErr := clearInventoryRuntime(runtime); clearErr != nil {
			revokeErr = clearErr
		}
	}
	if closeErr := closeLocalInventoryClient(client); closeErr != nil {
		revokeErr = closeErr
	}
}

func (private *fullInventoryAttemptState) detachForRevokeLocked() (
	inventoryPageClient,
	discoverysource.BoundRuntime,
) {
	client := private.client
	runtime := private.runtime
	private.client = nil
	clear(private.pageToken)
	private.pageToken = nil
	clear(private.checkpointToken)
	private.checkpointToken = nil
	private.soapContinuation = false
	private.items = nil
	private.relations = nil
	private.pending = nil
	private.seenObjects = nil
	private.transparentNodes = nil
	private.topologyRelations = nil
	private.relationKeys = nil
	clear(private.rolloverObjects)
	clear(private.rolloverRelations)
	private.rolloverObjects = nil
	private.rolloverRelations = nil
	private.replay.Clear()
	private.failed = true
	private.resolved.Clear()
	private.authority.Clear()
	private.rolloverSeed = fullInventoryCheckpoint{}
	private.rolloverAuthorized = false
	private.rolloverBinding = discoverysource.RuntimeBinding{}
	private.binding = discoverysource.RuntimeBinding{}
	private.runtime = discoverysource.BoundRuntime{}
	return client, runtime
}

func (private *fullInventoryAttemptState) finishRevoke(
	revokeErr error,
	timedOutOperation *fullInventoryOperation,
) error {
	if revokeErr != nil {
		revokeErr = errInventoryRejected
	}
	private.mu.rawLock()
	select {
	case <-private.revokeDone:
		revokeErr = private.revokeErr
		private.mu.rawUnlock()
		return revokeErr
	default:
	}
	if private.revokeErr != nil {
		revokeErr = errInventoryRejected
	}
	private.revokeErr = revokeErr
	revocation := private.rolloverRevocation
	private.mu.rawUnlock()

	if revocation != nil {
		revocation.finish(revokeErr)
	}

	private.mu.rawLock()
	if timedOutOperation != nil &&
		private.operation == timedOutOperation {
		private.mu.finishOperationLocked(timedOutOperation.done)
	}
	select {
	case <-private.revokeDone:
	default:
		close(private.revokeDone)
	}
	private.mu.rawUnlock()
	return revokeErr
}

func (private *fullInventoryAttemptState) seedCleanupUncertaintyLocked() {
	select {
	case <-private.revokeDone:
		return
	default:
	}
	private.revokeErr = errInventoryRejected
}

func (attempt *FullInventoryAttempt) Destroy() {
	attempt.destroyWithBarrier(nil)
}

func (attempt *FullInventoryAttempt) destroyWithBarrier(afterRevoke func()) {
	if attempt == nil || attempt.state == nil {
		return
	}
	private := attempt.state
	private.mu.rawLock()
	private.destroyed = true
	if private.operation != nil && private.operation.cancel != nil {
		private.operation.cancel()
	}
	record := private.rolloverRecord
	private.rolloverRecord = nil
	private.mu.rawUnlock()
	if record != nil {
		record.remove(attempt)
	}

	ctx, cancel := context.WithTimeout(context.Background(), sessionCleanupTimeout)
	_ = attempt.Revoke(ctx)
	cancel()
	if afterRevoke != nil {
		afterRevoke()
	}
	private.mu.rawLock()
	clear(private.emittedObjects)
	clear(private.emittedRelations)
	private.emittedObjects = nil
	private.emittedRelations = nil
	private.lastCheckpoint = fullInventoryCheckpoint{}
	private.hasLastCheckpoint = false
	private.lastBinding = discoverysource.RuntimeBinding{}
	private.lastAuthority.Clear()
	private.replay.Clear()
	private.successorID = ""
	revocation := private.rolloverRevocation
	private.mu.rawUnlock()
	if revocation != nil {
		revocation.finishDestroy()
	}
}

func (FullInventoryAttempt) MarshalJSON() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*FullInventoryAttempt) UnmarshalJSON([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (FullInventoryAttempt) MarshalText() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*FullInventoryAttempt) UnmarshalText([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (FullInventoryAttempt) MarshalBinary() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*FullInventoryAttempt) UnmarshalBinary([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (FullInventoryAttempt) String() string   { return fullInventoryAttemptRedact }
func (FullInventoryAttempt) GoString() string { return fullInventoryAttemptRedact }
func (FullInventoryAttempt) LogValue() slog.Value {
	return slog.StringValue(fullInventoryAttemptRedact)
}
func (FullInventoryAttempt) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, fullInventoryAttemptRedact)
}

func (value *provider) discover(
	ctx context.Context,
	runtime discoverysource.BoundRuntime,
	request discoverysource.DiscoverRequest,
) (discoverysource.DiscoverOutcome, error) {
	if value == nil || ctx == nil {
		return nil, errInventoryRejected
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	binding := value.factory.binding
	if binding.RevisionStatus != assetcatalog.SourceRevisionPublished ||
		request.Locator != binding.Locator ||
		request.SourceRevision != binding.SourceRevision ||
		request.SourceRevisionDigest != binding.SourceRevisionDigest {
		return nil, errInventoryRejected
	}
	var attempt *FullInventoryAttempt
	err := discoverysource.WithRuntime(
		runtime,
		binding,
		func(view *fullInventoryRuntimeView) error {
			if view == nil || view.attempt == nil || view.binding != binding {
				return errInventoryContinuity
			}
			attempt = view.attempt
			return nil
		},
	)
	if err == nil && attempt != nil {
		var outcome discoverysource.DiscoverOutcome
		outcome, err = attempt.discover(ctx, value.factory, request)
		return normalizeInventoryDiscoverOutcome(outcome, err)
	}
	if err == nil {
		err = errInventoryContinuity
	}
	return normalizeInventoryDiscoverOutcome(nil, err)
}

func normalizeInventoryDiscoverOutcome(
	outcome discoverysource.DiscoverOutcome,
	err error,
) (discoverysource.DiscoverOutcome, error) {
	if err != nil {
		if errors.Is(err, errInventoryIdentityDrift) {
			return nil, errInventoryIdentityDrift
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		if errors.Is(err, errInventoryContinuity) ||
			errors.Is(err, discoverysource.ErrRuntimeBindingMismatch) {
			return nil, errInventoryContinuity
		}
		return nil, errInventoryRejected
	}
	return outcome, nil
}

func (private *fullInventoryAttemptState) runOperationLocked(
	invoke func() (any, error),
	apply func(any, error) error,
	discard func(any) error,
) (operationErr error) {
	operation := private.operation
	if operation == nil || operation.context == nil ||
		operation.done == nil || invoke == nil || apply == nil ||
		private.mu.operationDone != operation.done {
		return errInventoryContinuity
	}
	if operation.rawMode {
		private.mu.rawUnlock()
	} else {
		operation.rawMode = true
		private.mu.Unlock()
	}

	var (
		result            any
		callErr           error
		panicValue        any
		operationPanicked bool
	)
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				panicValue = recovered
				operationPanicked = true
			}
		}()
		result, callErr = invoke()
	}()

	private.mu.rawLock()
	if errors.Is(callErr, errInventoryCleanupUncertain) {
		private.seedCleanupUncertaintyLocked()
	}
	current := private.operation == operation &&
		private.generation == operation.generation
	terminal := !current ||
		private.destroyed ||
		private.revokeStart ||
		private.failed ||
		private.handoffFrozen
	if operationPanicked {
		private.failed = true
		terminal = true
	}
	if terminal && discard != nil {
		cleanupErr := func() (cleanupErr error) {
			private.mu.rawUnlock()
			defer private.mu.rawLock()
			defer func() {
				if recover() != nil {
					cleanupErr = errInventoryCleanupUncertain
				}
			}()
			return discard(result)
		}()
		if cleanupErr != nil {
			private.seedCleanupUncertaintyLocked()
		}
		current = private.operation == operation &&
			private.generation == operation.generation
	}
	switch {
	case !current:
		operationErr = errInventoryContinuity
	case terminal:
		operationErr = errInventoryContinuity
	default:
		operationErr = apply(result, callErr)
		if errors.Is(operationErr, errInventoryCleanupUncertain) {
			private.seedCleanupUncertaintyLocked()
		}
	}
	if operationPanicked {
		panic(panicValue)
	}
	return operationErr
}

func (private *fullInventoryAttemptState) beginOperationLocked(
	ctx context.Context,
) error {
	if ctx == nil || private.operation != nil || private.mu.operationDone != nil {
		return errInventoryContinuity
	}
	operationContext, cancel := context.WithCancel(ctx)
	private.generation++
	operation := &fullInventoryOperation{
		generation: private.generation,
		context:    operationContext,
		cancel:     cancel,
		done:       make(chan struct{}),
	}
	private.operation = operation
	private.mu.beginOperationLocked(operation.done)
	return nil
}

func (private *fullInventoryAttemptState) finishOperationLocked(
	operation *fullInventoryOperation,
) {
	if operation == nil || private.operation != operation {
		return
	}
	if operation.cancel != nil {
		operation.cancel()
	}
	operation.context = nil
	operation.cancel = nil
	operation.client = nil
	operation.root = types.ManagedObjectReference{}
	operation.token = ""
	private.operation = nil
	private.mu.finishOperationLocked(operation.done)
}

func (private *fullInventoryAttemptState) unlockAfterDiscover(
	operation *fullInventoryOperation,
) {
	private.finishOperationLocked(operation)
	if operation != nil && operation.rawMode {
		private.mu.rawUnlock()
		return
	}
	private.mu.Unlock()
}

func (attempt *FullInventoryAttempt) discover(
	ctx context.Context,
	factory ClientFactory,
	request discoverysource.DiscoverRequest,
) (discoverysource.DiscoverOutcome, error) {
	if attempt == nil || attempt.state == nil {
		return nil, errInventoryContinuity
	}
	private := attempt.state
	private.mu.Lock()
	var operation *fullInventoryOperation
	defer func() {
		private.unlockAfterDiscover(operation)
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if private.destroyed || private.revokeStart || private.failed ||
		private.handoffFrozen ||
		private.binding != factory.binding {
		return nil, errInventoryContinuity
	}
	if err := private.beginOperationLocked(ctx); err != nil {
		return nil, err
	}
	operation = private.operation
	opened, empty, err := openFullInventoryCheckpoint(request.Checkpoint)
	if err != nil {
		private.failed = true
		return nil, errInventoryContinuity
	}
	if private.replay.matchesInput(factory.binding, request.Limits, opened, empty) {
		page, replayErr := private.replayPage()
		if replayErr != nil {
			private.failed = true
			private.replay.Clear()
			return nil, replayErr
		}
		return page, nil
	}
	if private.completed {
		return nil, errInventoryContinuity
	}
	if !private.started {
		if err := private.start(ctx, factory, opened, empty); err != nil {
			private.failed = true
			if contextErr := ctx.Err(); contextErr != nil {
				return nil, contextErr
			}
			return nil, err
		}
	} else if empty || !private.checkpointMatches(opened) {
		private.failed = true
		return nil, errInventoryContinuity
	}
	if !inventoryClientIdentityMatches(
		private.client,
		private.authority,
		private.collector,
	) {
		private.failed = true
		private.replay.Clear()
		return nil, errInventoryIdentityDrift
	}

	for len(private.items) == 0 && len(private.relations) == 0 &&
		(private.rootIndex < len(private.authority.roots) || len(private.pageToken) > 0) {
		if err := private.retrieve(ctx, request.Limits); err != nil {
			private.failed = true
			if contextErr := ctx.Err(); contextErr != nil {
				return nil, contextErr
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			return nil, errInventoryContinuity
		}
	}
	if err := ctx.Err(); err != nil {
		private.failed = true
		return nil, err
	}
	page, err := private.buildPage(request)
	if err != nil {
		private.failed = true
		return nil, errInventoryRejected
	}
	if err := private.rememberReplay(
		factory.binding,
		request.Limits,
		opened,
		empty,
		page,
	); err != nil {
		page.NextCheckpoint.Clear()
		private.failed = true
		return nil, errInventoryContinuity
	}
	if page.FinalPage {
		private.completed = true
	}
	return page, nil
}

func (replay *fullInventoryReplayCell) matchesInput(
	binding discoverysource.RuntimeBinding,
	limits discoverysource.Limits,
	opened fullInventoryCheckpoint,
	empty bool,
) bool {
	if replay == nil || !replay.active ||
		replay.binding != binding ||
		replay.limits != limits ||
		replay.inputEmpty != empty {
		return false
	}
	return empty || replay.input == opened
}

func (private *fullInventoryAttemptState) replayPage() (
	discoverysource.Page,
	error,
) {
	replay := &private.replay
	if !replay.active {
		return discoverysource.Page{}, errInventoryContinuity
	}
	if !private.authority.valid() ||
		!sameAuthoritySnapshot(replay.authority, private.authority) ||
		private.client == nil ||
		!inventoryClientIdentityMatches(
			private.client,
			private.authority,
			private.collector,
		) {
		return discoverysource.Page{}, errInventoryIdentityDrift
	}
	if !private.checkpointMatches(replay.output) {
		return discoverysource.Page{}, errInventoryContinuity
	}
	return cloneInventoryDiscoverPage(replay.page), nil
}

func (private *fullInventoryAttemptState) rememberReplay(
	binding discoverysource.RuntimeBinding,
	limits discoverysource.Limits,
	opened fullInventoryCheckpoint,
	empty bool,
	page discoverysource.Page,
) error {
	output, outputEmpty, err := openFullInventoryCheckpoint(page.NextCheckpoint)
	if err != nil || outputEmpty {
		return errInventoryContinuity
	}
	replay := fullInventoryReplayCell{
		input:      opened,
		inputEmpty: empty,
		output:     output,
		limits:     limits,
		binding:    binding,
		authority:  cloneAuthoritySnapshot(private.authority),
		page:       cloneInventoryDiscoverPage(page),
		active:     true,
	}
	private.replay.Clear()
	private.replay = replay
	return nil
}

func (private *fullInventoryAttemptState) start(
	ctx context.Context,
	factory ClientFactory,
	opened fullInventoryCheckpoint,
	empty bool,
) error {
	switch {
	case empty && private.rolloverAuthorized:
		return errInventoryContinuity
	case !empty:
		if opened.instanceUUID != private.authority.instanceUUID {
			return errInventoryIdentityDrift
		}
		if opened.pageTokenHash != "" {
			if !private.rolloverAuthorized || opened != private.rolloverSeed {
				return errInventoryContinuity
			}
		} else if private.rolloverAuthorized {
			return errInventoryContinuity
		}
		sequence, err := opened.sequence()
		if err != nil {
			return errInventoryContinuity
		}
		private.sequence = sequence
		private.rolloverSeed = fullInventoryCheckpoint{}
		private.rolloverAuthorized = false
		private.rolloverBinding = discoverysource.RuntimeBinding{}
	}
	if !private.resolved.valid() || factory.binding != private.binding {
		return errInventoryContinuity
	}
	resolved := cloneResolvedInventoryRuntime(private.resolved)
	authority := cloneAuthoritySnapshot(private.authority)
	operationContext := private.operation.context
	return private.runOperationLocked(
		func() (any, error) {
			defer resolved.Clear()
			defer authority.Clear()
			return openInventoryPageClient(
				operationContext,
				factory,
				resolved,
				authority,
			)
		},
		func(result any, operationErr error) error {
			opened, ok := result.(openedInventoryPageClient)
			if operationErr != nil {
				return operationErr
			}
			if !ok || opened.client == nil {
				return errInventoryRejected
			}
			private.client = opened.client
			private.collector = opened.collector
			private.resolved.Clear()
			private.fullSnapshotID = private.successorID
			private.successorID = ""
			if private.fullSnapshotID == "" {
				private.fullSnapshotID = uuid.NewString()
			}
			private.rootIndex = 0
			private.seenObjects = make(map[types.ManagedObjectReference]types.ManagedObjectReference)
			private.transparentNodes = make(map[types.ManagedObjectReference]types.ManagedObjectReference)
			private.topologyRelations = make(map[string]inventoryRelation)
			private.relationKeys = make(map[string]struct{})
			private.pending = make(map[string]inventoryRelation)
			private.started = true
			return nil
		},
		func(result any) error {
			opened, ok := result.(openedInventoryPageClient)
			if !ok || opened.client == nil {
				return nil
			}
			return closeLocalInventoryClient(opened.client)
		},
	)
}

type openedInventoryPageClient struct {
	client    inventoryPageClient
	collector types.ManagedObjectReference
}

func openInventoryPageClient(
	ctx context.Context,
	factory ClientFactory,
	resolved resolvedRuntime,
	authority authoritySnapshot,
) (
	result openedInventoryPageClient,
	resultErr error,
) {
	var owned validationClient
	closeOwned := func() error {
		client := owned
		owned = nil
		return closeLocalInventoryClient(client)
	}
	defer func() {
		if recover() != nil {
			result = openedInventoryPageClient{}
			resultErr = errors.Join(
				errInventoryRejected,
				errInventoryCleanupUncertain,
				closeOwned(),
			)
		}
	}()

	opener := factory.openClient
	if opener == nil {
		opener = func(
			ctx context.Context,
			runtime resolvedRuntime,
		) (validationClient, error) {
			return openGovmomiValidationClient(ctx, runtime, factory.observeMethod)
		}
	}
	candidate, err := opener(ctx, resolved)
	owned = candidate
	if err != nil {
		cleanupErr := closeOwned()
		if contextErr := ctx.Err(); contextErr != nil {
			return openedInventoryPageClient{}, errors.Join(contextErr, cleanupErr)
		}
		return openedInventoryPageClient{}, errors.Join(
			errInventoryRejected,
			cleanupErr,
		)
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return openedInventoryPageClient{}, errors.Join(
			contextErr,
			closeOwned(),
		)
	}
	client, ok := owned.(inventoryPageClient)
	if !ok || client == nil {
		return openedInventoryPageClient{}, errors.Join(
			errInventoryRejected,
			closeOwned(),
		)
	}
	snapshot, captured := snapshotInventoryClientIdentity(client)
	if !captured {
		return openedInventoryPageClient{}, errors.Join(
			errInventoryRejected,
			errInventoryCleanupUncertain,
			closeOwned(),
		)
	}
	if !validVCenterIdentity(snapshot.identity, authority) ||
		!validServiceReference(snapshot.collector, "PropertyCollector") {
		return openedInventoryPageClient{}, errors.Join(
			errInventoryIdentityDrift,
			closeOwned(),
		)
	}
	owned = nil
	return openedInventoryPageClient{
		client:    client,
		collector: snapshot.collector,
	}, nil
}

type inventoryClientIdentitySnapshot struct {
	identity  vcenterIdentity
	collector types.ManagedObjectReference
}

func snapshotInventoryClientIdentity(
	client inventoryPageClient,
) (
	snapshot inventoryClientIdentitySnapshot,
	captured bool,
) {
	if client == nil {
		return inventoryClientIdentitySnapshot{}, false
	}
	defer func() {
		if recover() != nil {
			snapshot = inventoryClientIdentitySnapshot{}
			captured = false
		}
	}()
	return inventoryClientIdentitySnapshot{
		identity:  client.Identity(),
		collector: client.CollectorReference(),
	}, true
}

func inventoryClientIdentityMatches(
	client inventoryPageClient,
	authority authoritySnapshot,
	collector types.ManagedObjectReference,
) bool {
	snapshot, captured := snapshotInventoryClientIdentity(client)
	return captured &&
		validVCenterIdentity(snapshot.identity, authority) &&
		compareManagedObjectReference(snapshot.collector, collector) == 0
}

func closeLocalInventoryClient(client validationClient) (cleanupErr error) {
	if client == nil {
		return nil
	}
	closeContext, cancel := context.WithTimeout(
		context.Background(),
		sessionCleanupTimeout,
	)
	defer cancel()
	defer func() {
		if recover() != nil {
			cleanupErr = errInventoryCleanupUncertain
		}
	}()
	if err := client.Close(closeContext); err != nil {
		return errInventoryCleanupUncertain
	}
	return nil
}

func clearInventoryRuntime(runtime discoverysource.BoundRuntime) (
	cleanupErr error,
) {
	defer func() {
		if recover() != nil {
			cleanupErr = errInventoryCleanupUncertain
		}
	}()
	runtime.Clear()
	return nil
}

func cloneResolvedInventoryRuntime(value resolvedRuntime) resolvedRuntime {
	return resolvedRuntime{
		endpoint: endpointSnapshot{endpoint: cloneURL(value.endpoint.endpoint)},
		credential: credentialSnapshot{
			userName: value.credential.userName,
			password: append([]byte(nil), value.credential.password...),
		},
		trust: trustSnapshot{
			config:        clonePinnedTLSConfig(value.trust.config),
			compatibility: value.trust.compatibility,
		},
		authority: authoritySnapshot{
			instanceUUID:  value.authority.instanceUUID,
			environmentID: value.authority.environmentID,
			roots:         slices.Clone(value.authority.roots),
			rootDigest:    value.authority.rootDigest,
		},
	}
}

func (value authoritySnapshot) normalizationScope() normalizationScope {
	return normalizationScope{
		InstanceUUID:        value.instanceUUID,
		EnvironmentID:       value.environmentID,
		AuthorityRoots:      slices.Clone(value.roots),
		AuthorityRootDigest: value.rootDigest,
	}
}

func (private *fullInventoryAttemptState) checkpointMatches(
	opened fullInventoryCheckpoint,
) bool {
	sequence, err := opened.sequence()
	return err == nil &&
		opened.instanceUUID == private.authority.instanceUUID &&
		opened.mode == fullInventoryMode &&
		opened.fullSnapshotID == private.fullSnapshotID &&
		sequence == private.sequence &&
		opened.pageTokenHash == inventoryPageTokenHash(
			private.fullSnapshotID,
			private.checkpointToken,
		) &&
		(!private.soapContinuation ||
			len(private.pageToken) > 0 &&
				bytes.Equal(private.pageToken, private.checkpointToken))
}

func (private *fullInventoryAttemptState) retrieve(
	ctx context.Context,
	limits discoverysource.Limits,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if private.client == nil || private.rootIndex >= len(private.authority.roots) {
		return errInventoryContinuity
	}
	root := private.authority.roots[private.rootIndex]
	maxObjects := int32(min(int64(maxFullInventoryPageObjects), limits.MaxPageItems))
	if maxObjects <= 0 {
		return errInventoryRejected
	}
	if private.soapContinuation != (len(private.pageToken) > 0) {
		return errInventoryContinuity
	}
	token := ""
	if private.soapContinuation {
		token = string(private.pageToken)
	}
	continued := token != ""
	clear(private.pageToken)
	private.pageToken = nil
	clear(private.checkpointToken)
	private.checkpointToken = nil
	private.soapContinuation = false
	operation := private.operation
	operation.client = private.client
	operation.root = root
	operation.token = token
	operationContext := operation.context
	operationClient := operation.client
	operationRoot := operation.root
	operationToken := operation.token
	return private.runOperationLocked(
		func() (any, error) {
			if operationToken == "" {
				return operationClient.RetrieveInventoryPage(
					operationContext,
					operationRoot,
					maxObjects,
				)
			}
			return operationClient.ContinueInventoryPage(
				operationContext,
				operationToken,
			)
		},
		func(value any, operationErr error) error {
			if operationErr != nil {
				if contextErr := ctx.Err(); contextErr != nil {
					return contextErr
				}
				return operationErr
			}
			if contextErr := ctx.Err(); contextErr != nil {
				return contextErr
			}
			result, ok := value.(types.RetrieveResult)
			if !ok {
				return errInventoryContinuity
			}
			if continued && len(result.Objects) == 0 && result.Token == "" {
				return errInventoryContinuity
			}
			if !validInventoryPageToken(result.Token) {
				return errInventoryRejected
			}
			objects, relations, decodeErr := decodeInventoryResult(root, result.Objects)
			if decodeErr != nil {
				return decodeErr
			}
			if acceptErr := private.acceptResult(root, objects, relations); acceptErr != nil {
				return acceptErr
			}
			private.pageToken = append([]byte(nil), result.Token...)
			if len(private.pageToken) > 0 {
				private.checkpointToken = append([]byte(nil), private.pageToken...)
				private.soapContinuation = true
			} else {
				private.checkpointToken = []byte(uuid.NewString())
			}
			result.Token = ""
			if len(private.pageToken) == 0 {
				if observedRoot, exists := private.seenObjects[root]; !exists ||
					compareManagedObjectReference(observedRoot, root) != 0 ||
					private.hasPendingForRoot(root) {
					return errInventoryRejected
				}
				if topologyErr := private.finalizeTransparentTopology(root); topologyErr != nil {
					return topologyErr
				}
				private.rootIndex++
			}
			return nil
		},
		nil,
	)
}

func validInventoryPageToken(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 4096 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character == utf8.RuneError || character == 0 ||
			unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return false
		}
	}
	return true
}

func (private *fullInventoryAttemptState) acceptResult(
	root types.ManagedObjectReference,
	objects []inventoryObject,
	relations []inventoryRelation,
) error {
	pageObjects := make(map[types.ManagedObjectReference]struct{}, len(objects))
	for _, object := range objects {
		if _, exists := pageObjects[object.Reference]; exists {
			return errInventoryRejected
		}
		pageObjects[object.Reference] = struct{}{}
		if existingRoot, exists := private.seenObjects[object.Reference]; exists {
			if compareManagedObjectReference(existingRoot, root) != 0 {
				return errInventoryRejected
			}
			return errInventoryRejected
		}
	}
	for _, object := range objects {
		private.seenObjects[object.Reference] = root
		if object.Reference.Type == "ComputeResource" {
			private.transparentNodes[object.Reference] = root
			continue
		}
		digest := inventoryObjectRolloverDigest(object)
		if _, exists := private.rolloverObjects[digest]; exists {
			delete(private.rolloverObjects, digest)
			continue
		}
		private.items = append(private.items, object)
	}
	for _, relation := range relations {
		key := inventoryRelationIdentity(relation)
		if _, exists := private.relationKeys[key]; exists {
			continue
		}
		private.relationKeys[key] = struct{}{}
		private.pending[key] = relation
	}
	for key, relation := range private.pending {
		fromRoot, fromExists := private.seenObjects[relation.FromReference]
		toRoot, toExists := private.seenObjects[relation.ToReference]
		if !fromExists || !toExists {
			continue
		}
		if compareManagedObjectReference(fromRoot, relation.FromRoot) != 0 ||
			compareManagedObjectReference(toRoot, relation.ToRoot) != 0 {
			return errInventoryRejected
		}
		private.topologyRelations[key] = relation
		if isTransparentInventoryObjectType(relation.FromReference.Type) ||
			isTransparentInventoryObjectType(relation.ToReference.Type) {
			delete(private.pending, key)
			continue
		}
		digest := inventoryRelationRolloverDigest(relation)
		if _, exists := private.rolloverRelations[digest]; exists {
			delete(private.rolloverRelations, digest)
		} else {
			private.relations = append(private.relations, relation)
		}
		delete(private.pending, key)
	}
	return nil
}

func (private *fullInventoryAttemptState) finalizeTransparentTopology(
	root types.ManagedObjectReference,
) error {
	if err := private.validateContainmentTopology(root); err != nil {
		return err
	}

	for node, nodeRoot := range private.transparentNodes {
		if compareManagedObjectReference(nodeRoot, root) != 0 {
			continue
		}
		var parent *types.ManagedObjectReference
		children := make([]types.ManagedObjectReference, 0, 2)
		for _, relation := range private.topologyRelations {
			switch {
			case compareManagedObjectReference(relation.ToReference, node) == 0:
				if relation.Type != assetcatalog.RelationshipContains ||
					relation.FromReference.Type != "Folder" ||
					parent != nil {
					return errInventoryRejected
				}
				value := relation.FromReference
				parent = &value
			case compareManagedObjectReference(relation.FromReference, node) == 0:
				if relation.Type != assetcatalog.RelationshipContains ||
					relation.ToReference.Type != "HostSystem" &&
						relation.ToReference.Type != "ResourcePool" {
					return errInventoryRejected
				}
				children = append(children, relation.ToReference)
			}
		}
		if parent == nil || len(children) == 0 {
			return errInventoryRejected
		}
		slices.SortFunc(children, compareManagedObjectReference)
		for _, child := range children {
			relation := inventoryRelation{
				FromReference: *parent,
				ToReference:   child,
				FromRoot:      root,
				ToRoot:        root,
				Type:          assetcatalog.RelationshipContains,
			}
			key := inventoryRelationIdentity(relation)
			if _, exists := private.relationKeys[key]; exists {
				return errInventoryRejected
			}
			private.relationKeys[key] = struct{}{}
			private.topologyRelations[key] = relation
			digest := inventoryRelationRolloverDigest(relation)
			if _, exists := private.rolloverRelations[digest]; exists {
				delete(private.rolloverRelations, digest)
			} else {
				private.relations = append(private.relations, relation)
			}
		}
	}
	return private.finalizeDatacenterVMTopology(root)
}

func (private *fullInventoryAttemptState) validateContainmentTopology(
	root types.ManagedObjectReference,
) error {
	folderOwners := make(
		map[types.ManagedObjectReference]types.ManagedObjectReference,
	)
	computeOwners := make(
		map[types.ManagedObjectReference]types.ManagedObjectReference,
	)
	resourcePoolOwners := make(
		map[types.ManagedObjectReference]types.ManagedObjectReference,
	)
	folderGraph := make(
		map[types.ManagedObjectReference][]types.ManagedObjectReference,
	)
	resourcePoolGraph := make(
		map[types.ManagedObjectReference][]types.ManagedObjectReference,
	)
	for _, relation := range private.topologyRelations {
		if compareManagedObjectReference(relation.FromRoot, root) != 0 ||
			relation.Type != assetcatalog.RelationshipContains {
			continue
		}
		from := relation.FromReference
		to := relation.ToReference
		if relation.TopologyPath == inventoryTopologyFolderChild &&
			from.Type == "Folder" {
			if !recordUniqueInventoryOwner(folderOwners, to, from) {
				return errInventoryRejected
			}
			if to.Type == "Folder" {
				folderGraph[from] = append(folderGraph[from], to)
				if _, exists := folderGraph[to]; !exists {
					folderGraph[to] = nil
				}
			}
		}
		if (from.Type == "ComputeResource" ||
			from.Type == "ClusterComputeResource") &&
			(to.Type == "HostSystem" || to.Type == "ResourcePool") {
			if !recordUniqueInventoryOwner(computeOwners, to, from) {
				return errInventoryRejected
			}
		}
		if to.Type == "ResourcePool" &&
			(from.Type == "ComputeResource" ||
				from.Type == "ClusterComputeResource" ||
				from.Type == "ResourcePool") {
			if !recordUniqueInventoryOwner(resourcePoolOwners, to, from) {
				return errInventoryRejected
			}
			if from.Type == "ResourcePool" {
				resourcePoolGraph[from] = append(resourcePoolGraph[from], to)
				if _, exists := resourcePoolGraph[to]; !exists {
					resourcePoolGraph[to] = nil
				}
			}
		}
	}
	for target := range folderOwners {
		if _, computeOwned := computeOwners[target]; computeOwned &&
			(target.Type == "HostSystem" || target.Type == "ResourcePool") {
			return errInventoryRejected
		}
	}
	if !inventoryDirectedGraphAcyclic(folderGraph) ||
		!inventoryDirectedGraphAcyclic(resourcePoolGraph) {
		return errInventoryRejected
	}
	return nil
}

func recordUniqueInventoryOwner(
	owners map[types.ManagedObjectReference]types.ManagedObjectReference,
	target types.ManagedObjectReference,
	owner types.ManagedObjectReference,
) bool {
	existing, exists := owners[target]
	if exists && compareManagedObjectReference(existing, owner) != 0 {
		return false
	}
	owners[target] = owner
	return true
}

func inventoryDirectedGraphAcyclic[Node comparable](
	graph map[Node][]Node,
) bool {
	const (
		inventoryGraphVisiting = uint8(1)
		inventoryGraphVisited  = uint8(2)
	)
	type frame struct {
		node Node
		next int
	}
	colors := make(map[Node]uint8, len(graph))
	for start := range graph {
		if colors[start] != 0 {
			continue
		}
		colors[start] = inventoryGraphVisiting
		stack := []frame{{node: start}}
		for len(stack) > 0 {
			current := &stack[len(stack)-1]
			children := graph[current.node]
			if current.next == len(children) {
				colors[current.node] = inventoryGraphVisited
				stack = stack[:len(stack)-1]
				continue
			}
			child := children[current.next]
			current.next++
			switch colors[child] {
			case inventoryGraphVisiting:
				return false
			case inventoryGraphVisited:
				continue
			default:
				colors[child] = inventoryGraphVisiting
				stack = append(stack, frame{node: child})
			}
		}
	}
	return true
}

func (private *fullInventoryAttemptState) finalizeDatacenterVMTopology(
	root types.ManagedObjectReference,
) error {
	type datacenterVMRoot struct {
		datacenter types.ManagedObjectReference
		folder     types.ManagedObjectReference
	}
	vmRoots := make([]datacenterVMRoot, 0)
	vmRootOwners := make(map[types.ManagedObjectReference]types.ManagedObjectReference)
	folderChildren := make(map[types.ManagedObjectReference][]types.ManagedObjectReference)
	folderParents := make(map[types.ManagedObjectReference]types.ManagedObjectReference)
	for _, relation := range private.topologyRelations {
		if compareManagedObjectReference(relation.FromRoot, root) != 0 {
			continue
		}
		switch relation.TopologyPath {
		case inventoryTopologyDatacenterVMRoot:
			if relation.FromReference.Type != "Datacenter" ||
				relation.ToReference.Type != "Folder" {
				return errInventoryRejected
			}
			if owner, exists := vmRootOwners[relation.ToReference]; exists &&
				compareManagedObjectReference(owner, relation.FromReference) != 0 {
				return errInventoryRejected
			}
			vmRootOwners[relation.ToReference] = relation.FromReference
			vmRoots = append(vmRoots, datacenterVMRoot{
				datacenter: relation.FromReference,
				folder:     relation.ToReference,
			})
		case inventoryTopologyFolderChild:
			if relation.FromReference.Type != "Folder" {
				return errInventoryRejected
			}
			switch relation.ToReference.Type {
			case "Folder":
				folderParents[relation.ToReference] = relation.FromReference
			}
			folderChildren[relation.FromReference] = append(
				folderChildren[relation.FromReference],
				relation.ToReference,
			)
		}
	}
	slices.SortFunc(vmRoots, func(left, right datacenterVMRoot) int {
		if comparison := compareManagedObjectReference(
			left.datacenter,
			right.datacenter,
		); comparison != 0 {
			return comparison
		}
		return compareManagedObjectReference(left.folder, right.folder)
	})
	for folder := range folderChildren {
		slices.SortFunc(folderChildren[folder], compareManagedObjectReference)
	}

	folderMembership := make(map[types.ManagedObjectReference]types.ManagedObjectReference)
	vmMembership := make(map[types.ManagedObjectReference]types.ManagedObjectReference)
	visitState := make(map[types.ManagedObjectReference]uint8)
	type folderFrame struct {
		folder types.ManagedObjectReference
		next   int
	}
	for _, vmRoot := range vmRoots {
		if _, hasFolderParent := folderParents[vmRoot.folder]; hasFolderParent {
			return errInventoryRejected
		}
		if owner, exists := folderMembership[vmRoot.folder]; exists &&
			compareManagedObjectReference(owner, vmRoot.datacenter) != 0 {
			return errInventoryRejected
		}
		if observedRoot, exists := private.seenObjects[vmRoot.folder]; !exists ||
			compareManagedObjectReference(observedRoot, root) != 0 {
			return errInventoryRejected
		}
		folderMembership[vmRoot.folder] = vmRoot.datacenter
		if visitState[vmRoot.folder] == 2 {
			continue
		}
		visitState[vmRoot.folder] = 1
		stack := []folderFrame{{folder: vmRoot.folder}}
		for len(stack) > 0 {
			frame := &stack[len(stack)-1]
			children := folderChildren[frame.folder]
			if frame.next >= len(children) {
				visitState[frame.folder] = 2
				stack = stack[:len(stack)-1]
				continue
			}
			child := children[frame.next]
			frame.next++
			if childRoot, exists := private.seenObjects[child]; !exists ||
				compareManagedObjectReference(childRoot, root) != 0 {
				return errInventoryRejected
			}
			switch child.Type {
			case "Folder":
				if owner, exists := folderMembership[child]; exists &&
					compareManagedObjectReference(owner, vmRoot.datacenter) != 0 {
					return errInventoryRejected
				}
				folderMembership[child] = vmRoot.datacenter
				switch visitState[child] {
				case 1:
					return errInventoryRejected
				case 2:
					continue
				}
				visitState[child] = 1
				stack = append(stack, folderFrame{folder: child})
			case "VirtualMachine":
				if owner, exists := vmMembership[child]; exists &&
					compareManagedObjectReference(owner, vmRoot.datacenter) != 0 {
					return errInventoryRejected
				}
				vmMembership[child] = vmRoot.datacenter
			default:
				return errInventoryRejected
			}
		}
	}
	for virtualMachine, datacenter := range vmMembership {
		derived := inventoryRelation{
			FromReference: datacenter,
			ToReference:   virtualMachine,
			FromRoot:      root,
			ToRoot:        root,
			Type:          assetcatalog.RelationshipContains,
		}
		key := inventoryRelationIdentity(derived)
		if _, exists := private.relationKeys[key]; exists {
			continue
		}
		private.relationKeys[key] = struct{}{}
		private.topologyRelations[key] = derived
		digest := inventoryRelationRolloverDigest(derived)
		if _, exists := private.rolloverRelations[digest]; exists {
			delete(private.rolloverRelations, digest)
		} else {
			private.relations = append(private.relations, derived)
		}
	}
	return nil
}

func (private *fullInventoryAttemptState) hasPendingForRoot(
	root types.ManagedObjectReference,
) bool {
	for _, relation := range private.pending {
		if compareManagedObjectReference(relation.FromRoot, root) == 0 ||
			compareManagedObjectReference(relation.ToRoot, root) == 0 {
			return true
		}
	}
	return false
}

func (private *fullInventoryAttemptState) buildPage(
	request discoverysource.DiscoverRequest,
) (discoverysource.Page, error) {
	nextSequence := private.sequence + 1
	slices.SortFunc(private.items, func(left, right inventoryObject) int {
		return compareManagedObjectReference(left.Reference, right.Reference)
	})
	slices.SortFunc(private.relations, compareInventoryRelations)

	itemCount := min(len(private.items), int(request.Limits.MaxPageItems))
	relationCount := 0
	if itemCount == 0 {
		relationCount = min(len(private.relations), int(request.Limits.MaxPageRelations))
	}
	normalizedItems := make([]assetdiscovery.NormalizedItem, 0, itemCount)
	for _, object := range private.items[:itemCount] {
		item, normalizeErr := normalizeFullInventoryObject(
			private.authority.normalizationScope(),
			object,
			nextSequence,
		)
		if normalizeErr != nil {
			return discoverysource.Page{}, normalizeErr
		}
		normalizedItems = append(normalizedItems, item)
	}
	normalizedRelations := make([]assetdiscovery.ObservedRelation, 0, relationCount)
	for _, relation := range private.relations[:relationCount] {
		normalized, normalizeErr := normalizeFullInventoryRelation(
			private.authority.normalizationScope(),
			relation,
			nextSequence,
		)
		if normalizeErr != nil {
			return discoverysource.Page{}, normalizeErr
		}
		normalizedRelations = append(normalizedRelations, normalized)
	}

	enumerationComplete := private.rootIndex == len(private.authority.roots) &&
		len(private.pageToken) == 0
	if enumerationComplete &&
		(len(private.rolloverObjects) != 0 || len(private.rolloverRelations) != 0) {
		return discoverysource.Page{}, errInventoryRejected
	}
	for {
		final := enumerationComplete &&
			itemCount == len(private.items) &&
			relationCount == len(private.relations) &&
			len(private.pending) == 0
		checkpointToken := private.checkpointToken
		if final {
			checkpointToken = nil
		}
		checkpoint, openedCheckpoint, checkpointErr := newFullInventoryCheckpoint(
			private.authority.instanceUUID,
			nextSequence,
			private.fullSnapshotID,
			checkpointToken,
		)
		if checkpointErr != nil {
			return discoverysource.Page{}, checkpointErr
		}
		page := discoverysource.Page{
			Items:            slices.Clone(normalizedItems[:itemCount]),
			Relations:        slices.Clone(normalizedRelations[:relationCount]),
			NextCheckpoint:   checkpoint,
			FinalPage:        final,
			CompleteSnapshot: final,
		}
		validateErr := discoverysource.ValidateDiscoverResult(
			request,
			inventoryFactPolicy(private.authority.environmentID),
			page,
			nil,
		)
		if validateErr == nil {
			for _, object := range private.items[:itemCount] {
				private.emittedObjects[inventoryObjectRolloverDigest(object)] = struct{}{}
			}
			for _, relation := range private.relations[:relationCount] {
				private.emittedRelations[inventoryRelationRolloverDigest(relation)] = struct{}{}
			}
			private.lastCheckpoint = openedCheckpoint
			private.hasLastCheckpoint = true
			private.lastBinding = private.binding
			private.lastAuthority.Clear()
			private.lastAuthority = cloneAuthoritySnapshot(private.authority)
			private.items = private.items[itemCount:]
			private.relations = private.relations[relationCount:]
			private.sequence = nextSequence
			if final {
				clear(private.checkpointToken)
				private.checkpointToken = nil
			}
			return page, nil
		}
		checkpoint.Clear()
		switch {
		case relationCount > 0:
			relationCount--
		case itemCount > 1:
			itemCount--
		default:
			return discoverysource.Page{}, errInventoryRejected
		}
	}
}

func normalizeFullInventoryObject(
	scope normalizationScope,
	object inventoryObject,
	orderSequence int64,
) (assetdiscovery.NormalizedItem, error) {
	item, err := normalizeObject(scope, object, orderSequence)
	if err != nil {
		return assetdiscovery.NormalizedItem{}, err
	}
	item.Freshness.ProviderVersionSHA256 = digestFramedStrings(
		"vsphere-object-version.v1",
		scope.InstanceUUID,
		strconv.FormatInt(orderSequence, 10),
		inventoryObjectIdentity(object.Reference),
	)
	return item, nil
}

func normalizeFullInventoryRelation(
	scope normalizationScope,
	relation inventoryRelation,
	orderSequence int64,
) (assetdiscovery.ObservedRelation, error) {
	normalized, err := normalizeRelation(scope, relation, orderSequence)
	if err != nil {
		return assetdiscovery.ObservedRelation{}, err
	}
	normalized.Freshness.ProviderVersionSHA256 = digestFramedStrings(
		"vsphere-relation-version.v1",
		scope.InstanceUUID,
		strconv.FormatInt(orderSequence, 10),
		inventoryObjectIdentity(relation.FromReference),
		inventoryObjectIdentity(relation.ToReference),
		string(relation.Type),
	)
	return normalized, nil
}

func inventoryObjectIdentity(reference types.ManagedObjectReference) string {
	return reference.Type + ":" + reference.Value
}

func compareInventoryRelations(left, right inventoryRelation) int {
	for _, comparison := range []int{
		compareManagedObjectReference(left.FromReference, right.FromReference),
		compareManagedObjectReference(left.ToReference, right.ToReference),
		compareManagedObjectReference(left.FromRoot, right.FromRoot),
		compareManagedObjectReference(left.ToRoot, right.ToRoot),
	} {
		if comparison != 0 {
			return comparison
		}
	}
	return cmpString(string(left.Type), string(right.Type))
}

func compareNormalizedInventoryItems(
	left assetdiscovery.NormalizedItem,
	right assetdiscovery.NormalizedItem,
) int {
	if comparison := cmpString(left.ProviderKind, right.ProviderKind); comparison != 0 {
		return comparison
	}
	return cmpString(left.ExternalID, right.ExternalID)
}

func compareNormalizedInventoryRelations(
	left assetdiscovery.ObservedRelation,
	right assetdiscovery.ObservedRelation,
) int {
	for _, comparison := range []int{
		cmpString(left.SourceEnvironmentID, right.SourceEnvironmentID),
		cmpString(left.TargetEnvironmentID, right.TargetEnvironmentID),
		cmpString(left.FromExternalID, right.FromExternalID),
		cmpString(left.ToExternalID, right.ToExternalID),
		cmpString(string(left.Type), string(right.Type)),
		cmpString(left.ProviderPathCode, right.ProviderPathCode),
		cmpString(string(left.CrossEnvironmentPolicyReferenceID), string(right.CrossEnvironmentPolicyReferenceID)),
	} {
		if comparison != 0 {
			return comparison
		}
	}
	return 0
}

func cmpString(left, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func inventoryRelationIdentity(relation inventoryRelation) string {
	return digestFramedStrings(
		"vsphere-inventory-relation.v1",
		inventoryObjectIdentity(relation.FromReference),
		inventoryObjectIdentity(relation.ToReference),
		inventoryObjectIdentity(relation.FromRoot),
		inventoryObjectIdentity(relation.ToRoot),
		string(relation.Type),
	)
}

func inventoryObjectRolloverDigest(object inventoryObject) string {
	return digestFramedStrings(
		"vsphere-rollover-object.v1",
		inventoryObjectIdentity(object.Reference),
		inventoryObjectIdentity(object.AuthorityRoot),
		object.Name,
		object.GuestID,
		object.PowerState,
		object.ConnectionState,
		strconv.FormatInt(object.CPUCount, 10),
		strconv.FormatInt(object.MemoryMB, 10),
	)
}

func inventoryRelationRolloverDigest(relation inventoryRelation) string {
	return digestFramedStrings(
		"vsphere-rollover-relation.v1",
		inventoryRelationIdentity(relation),
	)
}

func inventoryFactPolicy(environmentID string) assetdiscovery.FactPolicy {
	allObjectFields := slices.Clone(normalizedDocumentFieldAllowlist)
	slices.Sort(allObjectFields)
	return assetdiscovery.FactPolicy{
		ProviderKind:            providerKind,
		FreshnessKind:           assetcatalog.FreshnessCheckpointSequence,
		EnvironmentMapping:      assetcatalog.EnvironmentMappingSingle,
		AuthorityEnvironmentIDs: []string{environmentID},
		TrustedPathCodes:        slices.Clone(trustedPathCodes),
		RelationshipTypes: []assetcatalog.RelationshipType{
			assetcatalog.RelationshipContains,
			assetcatalog.RelationshipRunsOn,
		},
		AllowedDocumentFields: map[assetcatalog.Kind][]string{
			assetcatalog.KindCloudResource: slices.Clone(allObjectFields),
			assetcatalog.KindBareMetalHost: slices.Clone(allObjectFields),
			assetcatalog.KindLinuxVM:       slices.Clone(allObjectFields),
			assetcatalog.KindWindowsVM:     slices.Clone(allObjectFields),
		},
	}
}

func decodeInventoryResult(
	root types.ManagedObjectReference,
	contents []types.ObjectContent,
) ([]inventoryObject, []inventoryRelation, error) {
	if !validAuthorityRoot(root) || len(contents) > int(maxFullInventoryPageObjects) {
		return nil, nil, errInventoryRejected
	}
	objects := make([]inventoryObject, 0, len(contents))
	relations := make([]inventoryRelation, 0, len(contents)*2)
	for _, content := range contents {
		if isIgnoredInventoryObjectType(content.Obj.Type) {
			if len(content.MissingSet) != 0 || !validManagedObjectReference(content.Obj) {
				return nil, nil, errInventoryRejected
			}
			continue
		}
		object, objectRelations, err := decodeInventoryObject(root, content)
		if err != nil {
			return nil, nil, err
		}
		objects = append(objects, object)
		relations = append(relations, objectRelations...)
	}
	return objects, relations, nil
}

func decodeInventoryObject(
	root types.ManagedObjectReference,
	content types.ObjectContent,
) (inventoryObject, []inventoryRelation, error) {
	if len(content.MissingSet) != 0 ||
		!validManagedObjectReference(content.Obj) ||
		!slices.Contains(allowedObjectTypes, content.Obj.Type) &&
			!isTransparentInventoryObjectType(content.Obj.Type) {
		return inventoryObject{}, nil, errInventoryRejected
	}
	properties := make(map[string]any, len(content.PropSet))
	for _, property := range content.PropSet {
		if _, duplicate := properties[property.Name]; duplicate ||
			!inventoryPropertyAllowed(content.Obj.Type, property.Name) {
			return inventoryObject{}, nil, errInventoryRejected
		}
		properties[property.Name] = property.Val
	}
	object := inventoryObject{
		Reference: content.Obj, AuthorityRoot: root,
	}
	if content.Obj.Type != "ComputeResource" {
		name, ok := inventoryString(properties["name"])
		if !ok {
			return inventoryObject{}, nil, errInventoryRejected
		}
		object.Name = name
	}
	relations := make([]inventoryRelation, 0, 4)
	addContains := func(
		from types.ManagedObjectReference,
		values any,
	) error {
		references, valid := inventoryReferences(values)
		if !valid {
			return errInventoryRejected
		}
		for _, reference := range references {
			relations = append(relations, inventoryRelation{
				FromReference: from, ToReference: reference,
				FromRoot: root, ToRoot: root, Type: assetcatalog.RelationshipContains,
			})
		}
		return nil
	}
	switch content.Obj.Type {
	case "ComputeResource":
		if value, exists := properties["host"]; exists {
			if err := addContains(content.Obj, value); err != nil {
				return inventoryObject{}, nil, err
			}
		}
		if value, exists := properties["resourcePool"]; exists {
			reference, valid := inventoryReference(value)
			if !valid {
				return inventoryObject{}, nil, errInventoryRejected
			}
			relations = append(relations, inventoryRelation{
				FromReference: content.Obj, ToReference: reference,
				FromRoot: root, ToRoot: root, Type: assetcatalog.RelationshipContains,
			})
		}
	case "Folder":
		if value, exists := properties["childEntity"]; exists {
			firstRelation := len(relations)
			if err := addContains(content.Obj, value); err != nil {
				return inventoryObject{}, nil, err
			}
			for index := firstRelation; index < len(relations); index++ {
				relations[index].TopologyPath = inventoryTopologyFolderChild
			}
		}
	case "Datacenter":
		for _, field := range []string{"vmFolder", "hostFolder", "datastoreFolder", "networkFolder"} {
			if value, exists := properties[field]; exists {
				reference, valid := inventoryReference(value)
				if !valid {
					return inventoryObject{}, nil, errInventoryRejected
				}
				relation := inventoryRelation{
					FromReference: content.Obj, ToReference: reference,
					FromRoot: root, ToRoot: root, Type: assetcatalog.RelationshipContains,
				}
				if field == "vmFolder" {
					relation.TopologyPath = inventoryTopologyDatacenterVMRoot
				}
				relations = append(relations, relation)
			}
		}
	case "ClusterComputeResource":
		if value, exists := properties["host"]; exists {
			if err := addContains(content.Obj, value); err != nil {
				return inventoryObject{}, nil, err
			}
		}
		if value, exists := properties["resourcePool"]; exists {
			reference, valid := inventoryReference(value)
			if !valid {
				return inventoryObject{}, nil, errInventoryRejected
			}
			relations = append(relations, inventoryRelation{
				FromReference: content.Obj, ToReference: reference,
				FromRoot: root, ToRoot: root, Type: assetcatalog.RelationshipContains,
			})
		}
	case "ResourcePool":
		for _, field := range []string{"resourcePool", "vm"} {
			if value, exists := properties[field]; exists {
				if err := addContains(content.Obj, value); err != nil {
					return inventoryObject{}, nil, err
				}
			}
		}
	case "HostSystem":
		connection, connectionOK := inventoryString(properties["runtime.connectionState"])
		cpuCount, cpuOK := inventoryInt64(properties["summary.hardware.numCpuCores"])
		memoryBytes, memoryOK := inventoryInt64(properties["summary.hardware.memorySize"])
		if !connectionOK || !cpuOK || !memoryOK ||
			memoryBytes < 1<<20 {
			return inventoryObject{}, nil, errInventoryRejected
		}
		object.ConnectionState = connection
		object.CPUCount = cpuCount
		object.MemoryMB = memoryBytes / (1 << 20)
	case "VirtualMachine":
		guestID, guestOK := inventoryString(properties["config.guestId"])
		power, powerOK := inventoryString(properties["runtime.powerState"])
		connection, connectionOK := inventoryString(properties["runtime.connectionState"])
		cpuCount, cpuOK := inventoryInt64(properties["config.hardware.numCPU"])
		memoryMB, memoryOK := inventoryInt64(properties["config.hardware.memoryMB"])
		if !guestOK || !powerOK || !connectionOK || !cpuOK || !memoryOK {
			return inventoryObject{}, nil, errInventoryRejected
		}
		object.GuestID = guestID
		object.PowerState = power
		object.ConnectionState = connection
		object.CPUCount = cpuCount
		object.MemoryMB = memoryMB
		if value, exists := properties["runtime.host"]; exists {
			host, valid := inventoryReference(value)
			if !valid {
				return inventoryObject{}, nil, errInventoryRejected
			}
			relations = append(relations, inventoryRelation{
				FromReference: content.Obj, ToReference: host,
				FromRoot: root, ToRoot: root, Type: assetcatalog.RelationshipRunsOn,
			})
		}
		if value, exists := properties["resourcePool"]; exists {
			pool, valid := inventoryReference(value)
			if !valid {
				return inventoryObject{}, nil, errInventoryRejected
			}
			relations = append(relations, inventoryRelation{
				FromReference: pool, ToReference: content.Obj,
				FromRoot: root, ToRoot: root, Type: assetcatalog.RelationshipContains,
			})
		}
	case "Datastore", "Network":
	default:
		return inventoryObject{}, nil, errInventoryRejected
	}
	return object, relations, nil
}

func inventoryPropertyAllowed(objectType string, name string) bool {
	var allowed []string
	switch objectType {
	case "ComputeResource":
		allowed = []string{"host", "resourcePool"}
	case "Folder":
		allowed = []string{"name", "childEntity"}
	case "Datacenter":
		allowed = []string{"name", "vmFolder", "hostFolder", "datastoreFolder", "networkFolder"}
	case "ClusterComputeResource":
		allowed = []string{"name", "host", "resourcePool"}
	case "ResourcePool":
		allowed = []string{"name", "resourcePool", "vm"}
	case "Datastore", "Network":
		allowed = []string{"name"}
	case "HostSystem":
		allowed = []string{
			"name", "runtime.connectionState",
			"summary.hardware.numCpuCores", "summary.hardware.memorySize",
		}
	case "VirtualMachine":
		allowed = []string{
			"name", "config.guestId", "runtime.powerState", "runtime.connectionState",
			"config.hardware.numCPU", "config.hardware.memoryMB", "runtime.host", "resourcePool",
		}
	default:
		return false
	}
	return slices.Contains(allowed, name)
}

func inventoryString(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case types.HostSystemConnectionState:
		return string(typed), true
	case types.VirtualMachineConnectionState:
		return string(typed), true
	case types.VirtualMachinePowerState:
		return string(typed), true
	default:
		return "", false
	}
}

func inventoryInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int8:
		return int64(typed), true
	case int16:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case uint:
		if uint64(typed) <= uint64(^uint64(0)>>1) {
			return int64(typed), true
		}
	case uint8:
		return int64(typed), true
	case uint16:
		return int64(typed), true
	case uint32:
		return int64(typed), true
	case uint64:
		if typed <= uint64(^uint64(0)>>1) {
			return int64(typed), true
		}
	}
	return 0, false
}

func inventoryReference(value any) (types.ManagedObjectReference, bool) {
	var reference types.ManagedObjectReference
	switch typed := value.(type) {
	case types.ManagedObjectReference:
		reference = typed
	case *types.ManagedObjectReference:
		if typed == nil {
			return types.ManagedObjectReference{}, false
		}
		reference = *typed
	default:
		return types.ManagedObjectReference{}, false
	}
	return reference, validManagedObjectReference(reference) &&
		(slices.Contains(allowedObjectTypes, reference.Type) ||
			isTransparentInventoryObjectType(reference.Type))
}

func inventoryReferences(value any) ([]types.ManagedObjectReference, bool) {
	var references []types.ManagedObjectReference
	switch typed := value.(type) {
	case []types.ManagedObjectReference:
		references = slices.Clone(typed)
	case types.ArrayOfManagedObjectReference:
		references = slices.Clone(typed.ManagedObjectReference)
	case *types.ArrayOfManagedObjectReference:
		if typed == nil {
			return nil, false
		}
		references = slices.Clone(typed.ManagedObjectReference)
	default:
		return nil, false
	}
	filtered := references[:0]
	for _, reference := range references {
		if !validManagedObjectReference(reference) {
			return nil, false
		}
		switch {
		case slices.Contains(allowedObjectTypes, reference.Type),
			isTransparentInventoryObjectType(reference.Type):
			filtered = append(filtered, reference)
		case isIgnoredInventoryObjectType(reference.Type):
			continue
		default:
			return nil, false
		}
	}
	return filtered, true
}

func isTransparentInventoryObjectType(objectType string) bool {
	return objectType == "ComputeResource"
}

func isIgnoredInventoryObjectType(objectType string) bool {
	return slices.Contains(ignoredInventoryObjectTypes, objectType)
}

func inventoryPropertyFilter(
	root types.ManagedObjectReference,
) types.PropertyFilterSpec {
	all := func(names ...string) []types.BaseSelectionSpec {
		values := make([]types.BaseSelectionSpec, 0, len(names))
		for _, name := range names {
			values = append(values, &types.SelectionSpec{Name: name})
		}
		return values
	}
	traversals := []types.BaseSelectionSpec{
		&types.TraversalSpec{
			SelectionSpec: types.SelectionSpec{Name: "folderChildren"},
			Type:          "Folder", Path: "childEntity", Skip: types.NewBool(false),
			SelectSet: all(
				"folderChildren", "datacenterVMFolder", "datacenterHostFolder",
				"datacenterDatastoreFolder", "datacenterNetworkFolder",
				"computeHosts", "computeResourcePool", "resourcePoolChildren",
				"resourcePoolVMs", "hostVMs",
			),
		},
		&types.TraversalSpec{
			SelectionSpec: types.SelectionSpec{Name: "datacenterVMFolder"},
			Type:          "Datacenter", Path: "vmFolder", Skip: types.NewBool(false),
			SelectSet: all("folderChildren"),
		},
		&types.TraversalSpec{
			SelectionSpec: types.SelectionSpec{Name: "datacenterHostFolder"},
			Type:          "Datacenter", Path: "hostFolder", Skip: types.NewBool(false),
			SelectSet: all("folderChildren"),
		},
		&types.TraversalSpec{
			SelectionSpec: types.SelectionSpec{Name: "datacenterDatastoreFolder"},
			Type:          "Datacenter", Path: "datastoreFolder", Skip: types.NewBool(false),
			SelectSet: all("folderChildren"),
		},
		&types.TraversalSpec{
			SelectionSpec: types.SelectionSpec{Name: "datacenterNetworkFolder"},
			Type:          "Datacenter", Path: "networkFolder", Skip: types.NewBool(false),
			SelectSet: all("folderChildren"),
		},
		&types.TraversalSpec{
			SelectionSpec: types.SelectionSpec{Name: "computeHosts"},
			Type:          "ComputeResource", Path: "host", Skip: types.NewBool(false),
			SelectSet: all("hostVMs"),
		},
		&types.TraversalSpec{
			SelectionSpec: types.SelectionSpec{Name: "computeResourcePool"},
			Type:          "ComputeResource", Path: "resourcePool", Skip: types.NewBool(false),
			SelectSet: all("resourcePoolChildren", "resourcePoolVMs"),
		},
		&types.TraversalSpec{
			SelectionSpec: types.SelectionSpec{Name: "resourcePoolChildren"},
			Type:          "ResourcePool", Path: "resourcePool", Skip: types.NewBool(false),
			SelectSet: all("resourcePoolChildren", "resourcePoolVMs"),
		},
		&types.TraversalSpec{
			SelectionSpec: types.SelectionSpec{Name: "resourcePoolVMs"},
			Type:          "ResourcePool", Path: "vm", Skip: types.NewBool(false),
		},
		&types.TraversalSpec{
			SelectionSpec: types.SelectionSpec{Name: "hostVMs"},
			Type:          "HostSystem", Path: "vm", Skip: types.NewBool(false),
		},
	}
	return types.PropertyFilterSpec{
		PropSet: []types.PropertySpec{
			{Type: "Folder", PathSet: []string{"name", "childEntity"}},
			{Type: "Datacenter", PathSet: []string{
				"name", "vmFolder", "hostFolder", "datastoreFolder", "networkFolder",
			}},
			{Type: "ClusterComputeResource", PathSet: []string{"name", "host", "resourcePool"}},
			{Type: "ComputeResource", PathSet: []string{"host", "resourcePool"}},
			{Type: "ResourcePool", PathSet: []string{"name", "resourcePool", "vm"}},
			{Type: "Datastore", PathSet: []string{"name"}},
			{Type: "Network", PathSet: []string{"name"}},
			{Type: "HostSystem", PathSet: []string{
				"name", "runtime.connectionState",
				"summary.hardware.numCpuCores", "summary.hardware.memorySize",
			}},
			{Type: "VirtualMachine", PathSet: []string{
				"name", "config.guestId", "runtime.powerState", "runtime.connectionState",
				"config.hardware.numCPU", "config.hardware.memoryMB", "runtime.host", "resourcePool",
			}},
		},
		ObjectSet: []types.ObjectSpec{{
			Obj: root, Skip: types.NewBool(false), SelectSet: traversals,
		}},
	}
}

func (client *govmomiValidationClient) RetrieveInventoryPage(
	ctx context.Context,
	root types.ManagedObjectReference,
	maxObjects int32,
) (types.RetrieveResult, error) {
	vimClient, collector, err := client.inventoryClientSnapshot()
	if err != nil || !validAuthorityRoot(root) ||
		maxObjects <= 0 || maxObjects > maxFullInventoryPageObjects {
		return types.RetrieveResult{}, errInventoryRejected
	}
	callContext, cancel := context.WithTimeout(ctx, soapCallTimeout)
	defer cancel()
	response, err := methods.RetrievePropertiesEx(
		callContext,
		vimClient,
		&types.RetrievePropertiesEx{
			This:    collector,
			SpecSet: []types.PropertyFilterSpec{inventoryPropertyFilter(root)},
			Options: types.RetrieveOptions{MaxObjects: maxObjects},
		},
	)
	if err != nil || response == nil || response.Returnval == nil {
		return types.RetrieveResult{}, errInventoryContinuity
	}
	return *response.Returnval, nil
}

func (client *govmomiValidationClient) ContinueInventoryPage(
	ctx context.Context,
	token string,
) (types.RetrieveResult, error) {
	vimClient, collector, err := client.inventoryClientSnapshot()
	if err != nil || !validInventoryPageToken(token) || token == "" {
		return types.RetrieveResult{}, errInventoryContinuity
	}
	callContext, cancel := context.WithTimeout(ctx, soapCallTimeout)
	defer cancel()
	response, err := methods.ContinueRetrievePropertiesEx(
		callContext,
		vimClient,
		&types.ContinueRetrievePropertiesEx{This: collector, Token: token},
	)
	if err != nil || response == nil {
		return types.RetrieveResult{}, errInventoryContinuity
	}
	return response.Returnval, nil
}

func (client *govmomiValidationClient) CollectorReference() types.ManagedObjectReference {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed || client.client == nil {
		return types.ManagedObjectReference{}
	}
	return client.client.ServiceContent.PropertyCollector
}

func (client *govmomiValidationClient) inventoryClientSnapshot() (
	*vim25.Client,
	types.ManagedObjectReference,
	error,
) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed || client.client == nil {
		return nil, types.ManagedObjectReference{}, errInventoryContinuity
	}
	collector := client.client.ServiceContent.PropertyCollector
	if !validServiceReference(collector, "PropertyCollector") {
		return nil, types.ManagedObjectReference{}, errInventoryContinuity
	}
	return client.client, collector, nil
}

var _ inventoryPageClient = (*govmomiValidationClient)(nil)
