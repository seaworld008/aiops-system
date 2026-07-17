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
	errInventoryContinuity      = errors.New("vsphere full inventory continuity unavailable")
	errInventoryIdentityDrift   = errors.New("vsphere inventory identity drift")
	errInventoryRejected        = errors.New("vsphere inventory rejected")
	ignoredInventoryObjectTypes = []string{
		"DistributedVirtualPortgroup",
	}
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

type fullInventoryAttemptState struct {
	mu sync.Mutex

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

	sequence         int64
	fullSnapshotID   string
	successorID      string
	pageToken        []byte
	checkpointToken  []byte
	soapContinuation bool
	rootIndex        int
	seenObjects      map[types.ManagedObjectReference]types.ManagedObjectReference
	relationKeys     map[string]struct{}
	pending          map[string]inventoryRelation
	items            []inventoryObject
	relations        []inventoryRelation

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
	private.mu.Lock()
	if private.revokeStart {
		done := private.revokeDone
		private.mu.Unlock()
		select {
		case <-done:
			private.mu.Lock()
			err := private.revokeErr
			private.mu.Unlock()
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	private.revokeStart = true
	client, runtime := private.detachForRevokeLocked()
	private.mu.Unlock()

	runtime.Clear()
	var revokeErr error
	if client != nil {
		revokeErr = client.Close(ctx)
	}
	return private.finishRevoke(revokeErr)
}

func (attempt *FullInventoryAttempt) revokeFromRuntimeClear() {
	if attempt == nil || attempt.state == nil {
		return
	}
	private := attempt.state
	private.mu.Lock()
	if private.revokeStart {
		private.mu.Unlock()
		return
	}
	private.revokeStart = true
	client, _ := private.detachForRevokeLocked()
	private.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), sessionCleanupTimeout)
	var revokeErr error
	if client != nil {
		revokeErr = client.Close(ctx)
	}
	cancel()
	_ = private.finishRevoke(revokeErr)
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

func (private *fullInventoryAttemptState) finishRevoke(revokeErr error) error {
	if revokeErr != nil {
		revokeErr = errInventoryRejected
	}
	private.mu.Lock()
	private.revokeErr = revokeErr
	revocation := private.rolloverRevocation
	close(private.revokeDone)
	private.mu.Unlock()
	if revocation != nil {
		revocation.finish(revokeErr)
	}
	return revokeErr
}

func (attempt *FullInventoryAttempt) Destroy() {
	attempt.destroyWithBarrier(nil)
}

func (attempt *FullInventoryAttempt) destroyWithBarrier(afterRevoke func()) {
	if attempt == nil || attempt.state == nil {
		return
	}
	private := attempt.state
	private.mu.Lock()
	private.destroyed = true
	record := private.rolloverRecord
	private.rolloverRecord = nil
	private.mu.Unlock()
	if record != nil {
		record.remove(attempt)
	}

	ctx, cancel := context.WithTimeout(context.Background(), sessionCleanupTimeout)
	_ = attempt.Revoke(ctx)
	cancel()
	if afterRevoke != nil {
		afterRevoke()
	}
	private.mu.Lock()
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
	private.mu.Unlock()
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
	var outcome discoverysource.DiscoverOutcome
	err := discoverysource.WithRuntime(
		runtime,
		binding,
		func(view *fullInventoryRuntimeView) error {
			if view == nil || view.attempt == nil || view.binding != binding {
				return errInventoryContinuity
			}
			var discoverErr error
			outcome, discoverErr = view.attempt.discover(ctx, value.factory, request)
			return discoverErr
		},
	)
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
	defer private.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if private.destroyed || private.revokeStart || private.failed ||
		private.handoffFrozen ||
		private.binding != factory.binding {
		return nil, errInventoryContinuity
	}
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
	if !validVCenterIdentity(private.client.Identity(), private.authority) ||
		compareManagedObjectReference(private.client.CollectorReference(), private.collector) != 0 {
		private.failed = true
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
		!validVCenterIdentity(private.client.Identity(), private.authority) ||
		compareManagedObjectReference(
			private.client.CollectorReference(),
			private.collector,
		) != 0 {
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
	client, collector, err := private.openClient(ctx, factory)
	if err != nil {
		return err
	}
	private.client = client
	private.collector = collector
	private.fullSnapshotID = private.successorID
	private.successorID = ""
	if private.fullSnapshotID == "" {
		private.fullSnapshotID = uuid.NewString()
	}
	private.rootIndex = 0
	private.seenObjects = make(map[types.ManagedObjectReference]types.ManagedObjectReference)
	private.relationKeys = make(map[string]struct{})
	private.pending = make(map[string]inventoryRelation)
	private.started = true
	return nil
}

func (private *fullInventoryAttemptState) openClient(
	ctx context.Context,
	factory ClientFactory,
) (inventoryPageClient, types.ManagedObjectReference, error) {
	if !private.resolved.valid() || factory.binding != private.binding {
		return nil, types.ManagedObjectReference{}, errInventoryContinuity
	}
	resolved := cloneResolvedInventoryRuntime(private.resolved)
	defer resolved.Clear()
	opener := factory.openClient
	if opener == nil {
		opener = func(
			ctx context.Context,
			runtime resolvedRuntime,
		) (validationClient, error) {
			return openGovmomiValidationClient(ctx, runtime, factory.observeMethod)
		}
	}
	opened, err := opener(ctx, resolved)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, types.ManagedObjectReference{}, contextErr
		}
		return nil, types.ManagedObjectReference{}, errInventoryRejected
	}
	if contextErr := ctx.Err(); contextErr != nil {
		if opened != nil {
			_ = opened.Close(context.WithoutCancel(ctx))
		}
		return nil, types.ManagedObjectReference{}, contextErr
	}
	client, ok := opened.(inventoryPageClient)
	if !ok || client == nil {
		if opened != nil {
			_ = opened.Close(context.WithoutCancel(ctx))
		}
		return nil, types.ManagedObjectReference{}, errInventoryRejected
	}
	collector := client.CollectorReference()
	if !validVCenterIdentity(client.Identity(), private.authority) ||
		!validServiceReference(collector, "PropertyCollector") {
		_ = client.Close(context.WithoutCancel(ctx))
		return nil, types.ManagedObjectReference{}, errInventoryIdentityDrift
	}
	private.resolved.Clear()
	return client, collector, nil
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
	maxObjects := min(maxFullInventoryPageObjects, int32(limits.MaxPageItems))
	if maxObjects <= 0 {
		return errInventoryRejected
	}
	var (
		result types.RetrieveResult
		err    error
	)
	if private.soapContinuation != (len(private.pageToken) > 0) {
		return errInventoryContinuity
	}
	token := ""
	if private.soapContinuation {
		token = string(private.pageToken)
	}
	clear(private.pageToken)
	private.pageToken = nil
	clear(private.checkpointToken)
	private.checkpointToken = nil
	private.soapContinuation = false
	if token == "" {
		result, err = private.client.RetrieveInventoryPage(ctx, root, maxObjects)
	} else {
		result, err = private.client.ContinueInventoryPage(ctx, token)
		token = ""
	}
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validInventoryPageToken(result.Token) {
		return errInventoryRejected
	}
	objects, relations, err := decodeInventoryResult(root, result.Objects)
	if err != nil {
		return err
	}
	if err := private.acceptResult(root, objects, relations); err != nil {
		return err
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
		if observedRoot, ok := private.seenObjects[root]; !ok ||
			compareManagedObjectReference(observedRoot, root) != 0 ||
			private.hasPendingForRoot(root) {
			return errInventoryRejected
		}
		private.rootIndex++
	}
	return nil
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
		if slices.Contains(ignoredInventoryObjectTypes, content.Obj.Type) {
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
		!slices.Contains(allowedObjectTypes, content.Obj.Type) {
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
	name, ok := inventoryString(properties["name"])
	if !ok {
		return inventoryObject{}, nil, errInventoryRejected
	}
	object := inventoryObject{
		Reference: content.Obj, AuthorityRoot: root, Name: name,
	}
	relations := make([]inventoryRelation, 0, 4)
	addContains := func(from types.ManagedObjectReference, values any) error {
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
	case "Folder":
		if value, exists := properties["childEntity"]; exists {
			if err := addContains(content.Obj, value); err != nil {
				return inventoryObject{}, nil, err
			}
		}
	case "Datacenter":
		for _, field := range []string{"vmFolder", "hostFolder", "datastoreFolder", "networkFolder"} {
			if value, exists := properties[field]; exists {
				reference, valid := inventoryReference(value)
				if !valid {
					return inventoryObject{}, nil, errInventoryRejected
				}
				relations = append(relations, inventoryRelation{
					FromReference: content.Obj, ToReference: reference,
					FromRoot: root, ToRoot: root, Type: assetcatalog.RelationshipContains,
				})
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
		slices.Contains(allowedObjectTypes, reference.Type)
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
		if slices.Contains(allowedObjectTypes, reference.Type) {
			filtered = append(filtered, reference)
		}
	}
	return filtered, true
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
