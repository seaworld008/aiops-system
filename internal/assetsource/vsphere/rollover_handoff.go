package vsphere

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

const (
	fullInventoryRolloverAuthorityRedact = "[REDACTED_VSPHERE_ROLLOVER_AUTHORITY]"
	fullInventoryRolloverHandoffRedact   = "[REDACTED_VSPHERE_ROLLOVER_HANDOFF]"
	fullInventoryRolloverAuthoritySeal   = uint64(0xb7f29d8c413e605a)
)

// FullInventoryRolloverAuthority is the vSphere-private boundary that joins a
// real Queue admission to one Broker-owned full-inventory attempt. It retains
// no runtime material: the registered attempt remains exclusively owned and
// terminally destroyed by CleanupBroker.
type FullInventoryRolloverAuthority struct {
	self  *FullInventoryRolloverAuthority
	seal  uint64
	state *fullInventoryRolloverAuthorityState
}

type fullInventoryRolloverAuthorityState struct {
	mu        sync.Mutex
	attempts  map[string]*fullInventoryRolloverRegistration
	pending   map[string]*fullInventoryRolloverPending
	destroyed bool
}

type fullInventoryRolloverRegistration struct {
	authority *fullInventoryRolloverAuthorityState
	attemptID string
	request   discoverycleanup.OpenAttemptRequest
	attempt   *FullInventoryAttempt
	closed    bool
}

type fullInventoryRolloverPending struct {
	registration *fullInventoryRolloverRegistration
	request      discoverycleanup.OpenAttemptRequest
	command      discoveryqueue.RolloverCommand
	accepted     discoverysource.PageCommitResult
	checkpoint   fullInventoryCheckpoint
	binding      discoverysource.RuntimeBinding
	authority    authoritySnapshot
	objects      map[string]struct{}
	relations    map[string]struct{}
	fence        assetcatalog.LeaseFence
	successorID  string
	verified     discoveryqueue.CheckpointLineageRolloverRequest
	verifiedOK   bool
	inFlight     bool
}

// FullInventoryRolloverHandoff contains only safe immutable binding facts and
// an independent revoke receipt. It never retains the predecessor, runtime,
// session, raw token, runtime material, or discovered facts.
type FullInventoryRolloverHandoff struct {
	self  *FullInventoryRolloverHandoff
	state *fullInventoryRolloverHandoffState
}

type fullInventoryRolloverHandoffState struct {
	mu sync.Mutex

	issued       *FullInventoryRolloverHandoff
	request      discoverycleanup.OpenAttemptRequest
	command      discoveryqueue.RolloverCommand
	accepted     discoverysource.PageCommitResult
	verified     discoveryqueue.CheckpointLineageRolloverRequest
	checkpoint   fullInventoryCheckpoint
	binding      discoverysource.RuntimeBinding
	authority    authoritySnapshot
	objects      map[string]struct{}
	relations    map[string]struct{}
	fence        assetcatalog.LeaseFence
	successorID  string
	revocation   *fullInventoryRolloverRevocation
	active       bool
	consumeStart bool
}

// fullInventoryRolloverRevocation is a safe, handle-independent receipt. It
// contains no session or runtime state and is completed only by the exact
// predecessor Revoke path that CleanupBroker invokes before Destroy.
type fullInventoryRolloverRevocation struct {
	mu        sync.Mutex
	revoked   bool
	destroyed bool
	err       error
}

func NewFullInventoryRolloverAuthority() *FullInventoryRolloverAuthority {
	private := &fullInventoryRolloverAuthorityState{
		attempts: make(map[string]*fullInventoryRolloverRegistration),
		pending:  make(map[string]*fullInventoryRolloverPending),
	}
	authority := &FullInventoryRolloverAuthority{
		seal:  fullInventoryRolloverAuthoritySeal,
		state: private,
	}
	authority.self = authority
	return authority
}

func (authority *FullInventoryRolloverAuthority) authentic() bool {
	return authority != nil &&
		authority.self == authority &&
		authority.seal == fullInventoryRolloverAuthoritySeal &&
		authority.state != nil
}

// NewAttempt creates the exact Broker-owned predecessor and registers only its
// safe cleanup coordinates. Callers must return the attempt directly from
// SessionOpener; the authority never becomes a second session owner.
func (authority *FullInventoryRolloverAuthority) NewAttempt(
	material *RuntimeMaterial,
	request discoverycleanup.OpenAttemptRequest,
) (*FullInventoryAttempt, error) {
	if !authority.authentic() || request.Validate() != nil {
		if material != nil {
			material.Clear()
		}
		return nil, errInventoryRejected
	}
	private := authority.state
	private.mu.Lock()
	defer private.mu.Unlock()
	if private.destroyed || private.attempts == nil ||
		private.attempts[request.Attempt.AttemptID] != nil {
		if material != nil {
			material.Clear()
		}
		return nil, errInventoryContinuity
	}
	attempt, err := NewFullInventoryAttempt(material)
	if err != nil {
		return nil, err
	}
	record := &fullInventoryRolloverRegistration{
		authority: private,
		attemptID: request.Attempt.AttemptID,
		request:   request,
		attempt:   attempt,
	}
	attempt.state.mu.Lock()
	attempt.state.rolloverGoverned = true
	attempt.state.rolloverRecord = record
	attempt.state.rolloverRevocation = &fullInventoryRolloverRevocation{}
	attempt.state.mu.Unlock()
	private.attempts[record.attemptID] = record
	return attempt, nil
}

// BeginHandoff invokes the real Queue operation itself. The authority is also
// the Queue's deterministic rollover verifier, so a handoff can be minted only
// after the repository has presented the exact locked checkpoint tuple and the
// same Begin call has returned a committed result or exact response-loss replay.
func (authority *FullInventoryRolloverAuthority) BeginHandoff(
	ctx context.Context,
	queue discoveryqueue.Queue,
	fence assetcatalog.LeaseFence,
	request discoverycleanup.OpenAttemptRequest,
	command discoveryqueue.RolloverCommand,
	accepted discoverysource.PageCommitResult,
	checkpoint discoverysource.Checkpoint,
) (*FullInventoryRolloverHandoff, discoveryqueue.RolloverResult, error) {
	if ctx == nil || queue == nil || !authority.authentic() ||
		request.Validate() != nil || command.Validate() != nil ||
		command.Coordinates != request.Coordinates ||
		accepted.RunID != request.Coordinates.RunID ||
		accepted.PageSequence <= 0 || accepted.CheckpointVersion <= 0 ||
		!lowercaseDigestPattern.MatchString(accepted.CheckpointSHA256) ||
		!lowercaseDigestPattern.MatchString(accepted.PageDigestSHA256) ||
		!lowercaseDigestPattern.MatchString(accepted.RelationPageDigestSHA256) ||
		accepted.FinalPage || accepted.CompleteSnapshot {
		return nil, discoveryqueue.RolloverResult{}, errInventoryContinuity
	}
	if err := ctx.Err(); err != nil {
		return nil, discoveryqueue.RolloverResult{}, err
	}
	opened, empty, err := openFullInventoryCheckpoint(checkpoint)
	if err != nil || empty || opened.pageTokenHash == "" {
		return nil, discoveryqueue.RolloverResult{}, errInventoryContinuity
	}

	private := authority.state
	private.mu.Lock()
	pending, prepareErr := private.preparePending(
		request,
		command,
		accepted,
		opened,
		fence,
	)
	if prepareErr != nil {
		private.mu.Unlock()
		return nil, discoveryqueue.RolloverResult{}, prepareErr
	}
	pending.inFlight = true
	private.mu.Unlock()

	if _, err := revalidateRolloverCleanupAttempt(
		ctx,
		queue,
		fence,
		request,
	); err != nil {
		authority.closeRegistration(request)
		return nil, discoveryqueue.RolloverResult{}, err
	}
	result, queueErr := queue.BeginCheckpointLineageRollover(ctx, fence, command)

	private.mu.Lock()
	current := private.pending[request.Coordinates.RunID]
	if queueErr != nil {
		if current == pending {
			pending.inFlight = false
		}
		private.mu.Unlock()
		return nil, discoveryqueue.RolloverResult{}, queueErr
	}
	private.mu.Unlock()
	if _, err := revalidateRolloverCleanupAttempt(
		ctx,
		queue,
		fence,
		request,
	); err != nil {
		authority.closeRegistration(request)
		return nil, discoveryqueue.RolloverResult{}, err
	}
	private.mu.Lock()
	current = private.pending[request.Coordinates.RunID]
	if private.destroyed || current != pending ||
		result.ReasonCode != command.ReasonCode ||
		result.EvidenceDigest != command.EvidenceDigest ||
		result.GateRevision <= 0 ||
		!pending.verifiedOK ||
		!pending.verificationMatches(pending.verified) {
		private.mu.Unlock()
		return nil, discoveryqueue.RolloverResult{}, errInventoryContinuity
	}
	record := pending.registration
	if record == nil || private.attempts[record.attemptID] != record ||
		record.request != request || record.attempt == nil {
		private.mu.Unlock()
		return nil, discoveryqueue.RolloverResult{}, errInventoryContinuity
	}
	attempt := record.attempt
	attempt.state.mu.Lock()
	if !pending.matchesAttemptLocked(attempt.state, record) {
		attempt.state.mu.Unlock()
		private.mu.Unlock()
		return nil, discoveryqueue.RolloverResult{}, errInventoryContinuity
	}
	handoffState := &fullInventoryRolloverHandoffState{
		request: request, command: command, accepted: accepted,
		verified: pending.verified, checkpoint: pending.checkpoint,
		binding: pending.binding, authority: cloneAuthoritySnapshot(pending.authority),
		objects:     cloneInventoryObjects(pending.objects),
		relations:   cloneInventoryRelations(pending.relations),
		fence:       pending.fence,
		successorID: pending.successorID,
		revocation:  attempt.state.rolloverRevocation,
		active:      true,
	}
	handoff := &FullInventoryRolloverHandoff{state: handoffState}
	handoff.self = handoff
	handoffState.issued = handoff

	attempt.state.rolloverRecord = nil
	record.attempt = nil
	delete(private.attempts, record.attemptID)
	delete(private.pending, request.Coordinates.RunID)
	pending.Clear()
	pending.registration = nil
	attempt.state.mu.Unlock()
	private.mu.Unlock()
	return handoff, result, nil
}

func (private *fullInventoryRolloverAuthorityState) preparePending(
	request discoverycleanup.OpenAttemptRequest,
	command discoveryqueue.RolloverCommand,
	accepted discoverysource.PageCommitResult,
	checkpoint fullInventoryCheckpoint,
	fence assetcatalog.LeaseFence,
) (*fullInventoryRolloverPending, error) {
	if private.destroyed || private.attempts == nil || private.pending == nil {
		return nil, errInventoryContinuity
	}
	record := private.attempts[request.Attempt.AttemptID]
	if record == nil || record.request != request || record.attempt == nil ||
		record.closed {
		return nil, errInventoryContinuity
	}
	attempt := record.attempt
	attempt.state.mu.Lock()
	defer attempt.state.mu.Unlock()
	if existing := private.pending[request.Coordinates.RunID]; existing != nil {
		if existing.inFlight ||
			!existing.matchesInput(request, command, accepted, checkpoint, fence) ||
			!validRolloverAttemptLocked(
				attempt.state,
				record,
				request,
				accepted,
				checkpoint,
				true,
			) {
			return nil, errInventoryContinuity
		}
		return existing, nil
	}
	if !validRolloverAttemptLocked(
		attempt.state,
		record,
		request,
		accepted,
		checkpoint,
		false,
	) {
		return nil, errInventoryContinuity
	}
	pending := &fullInventoryRolloverPending{
		registration: record,
		request:      request,
		command:      command,
		accepted:     accepted,
		checkpoint:   checkpoint,
		binding:      attempt.state.lastBinding,
		authority:    cloneAuthoritySnapshot(attempt.state.lastAuthority),
		objects:      cloneInventoryObjects(attempt.state.emittedObjects),
		relations:    cloneInventoryRelations(attempt.state.emittedRelations),
		fence:        fence,
		successorID:  uuid.NewString(),
	}
	private.pending[request.Coordinates.RunID] = pending
	attempt.state.handoffFrozen = true
	return pending, nil
}

func validRolloverAttemptLocked(
	private *fullInventoryAttemptState,
	record *fullInventoryRolloverRegistration,
	request discoverycleanup.OpenAttemptRequest,
	accepted discoverysource.PageCommitResult,
	checkpoint fullInventoryCheckpoint,
	handoffFrozen bool,
) bool {
	sequence, err := checkpoint.sequence()
	return private != nil &&
		record != nil &&
		!record.closed &&
		private.rolloverGoverned &&
		private.rolloverRecord == record &&
		private.rolloverRevocation != nil &&
		!private.destroyed &&
		!private.revokeStart &&
		private.handoffFrozen == handoffFrozen &&
		!private.completed &&
		private.hasLastCheckpoint &&
		private.lastCheckpoint == checkpoint &&
		private.lastBinding == private.binding &&
		private.lastBinding.ProviderKind == providerKind &&
		private.lastBinding.ProfileCode == profileCode &&
		private.lastBinding.RevisionStatus == assetcatalog.SourceRevisionPublished &&
		private.lastBinding.Locator.Scope == request.Coordinates.Scope &&
		private.lastAuthority.valid() &&
		sequence > 0 &&
		err == nil &&
		accepted.CheckpointVersion == sequence &&
		private.replay.active &&
		private.replay.output == checkpoint
}

func revalidateRolloverCleanupAttempt(
	ctx context.Context,
	queue discoveryqueue.Queue,
	fence assetcatalog.LeaseFence,
	request discoverycleanup.OpenAttemptRequest,
) (discoveryqueue.CleanupAttempt, error) {
	if ctx == nil || queue == nil || request.Validate() != nil {
		return discoveryqueue.CleanupAttempt{}, errInventoryContinuity
	}
	if err := ctx.Err(); err != nil {
		return discoveryqueue.CleanupAttempt{}, err
	}
	current, err := queue.ReserveCleanupAttempt(
		ctx,
		fence,
		discoveryqueue.RunCommand{Coordinates: request.Coordinates},
	)
	if err != nil {
		return discoveryqueue.CleanupAttempt{}, err
	}
	if current != request.Attempt {
		return discoveryqueue.CleanupAttempt{}, errInventoryContinuity
	}
	return current, nil
}

func (authority *FullInventoryRolloverAuthority) closeRegistration(
	request discoverycleanup.OpenAttemptRequest,
) {
	if !authority.authentic() {
		return
	}
	private := authority.state
	private.mu.Lock()
	defer private.mu.Unlock()
	if private.attempts == nil {
		return
	}
	record := private.attempts[request.Attempt.AttemptID]
	if record == nil || record.request != request {
		return
	}
	record.closed = true
	if private.pending == nil {
		return
	}
	runID := request.Coordinates.RunID
	pending := private.pending[runID]
	if pending == nil || pending.registration != record {
		return
	}
	pending.Clear()
	pending.registration = nil
	delete(private.pending, runID)
}

func (pending *fullInventoryRolloverPending) matchesInput(
	request discoverycleanup.OpenAttemptRequest,
	command discoveryqueue.RolloverCommand,
	accepted discoverysource.PageCommitResult,
	checkpoint fullInventoryCheckpoint,
	fence assetcatalog.LeaseFence,
) bool {
	return pending != nil &&
		pending.request == request &&
		pending.command == command &&
		pending.accepted == accepted &&
		pending.checkpoint == checkpoint &&
		pending.fence == fence
}

func (pending *fullInventoryRolloverPending) matchesAttemptLocked(
	private *fullInventoryAttemptState,
	record *fullInventoryRolloverRegistration,
) bool {
	return pending != nil &&
		pending.registration == record &&
		validRolloverAttemptLocked(
			private,
			record,
			pending.request,
			pending.accepted,
			pending.checkpoint,
			true,
		) &&
		private.lastBinding == pending.binding &&
		sameAuthoritySnapshot(private.lastAuthority, pending.authority) &&
		sameInventoryDigestSet(private.emittedObjects, pending.objects) &&
		sameInventoryDigestSet(private.emittedRelations, pending.relations)
}

// VerifyCheckpointLineageRollover is invoked only by Queue while BeginHandoff
// is in flight. It binds the private handoff candidate to the repository's
// locked Source/revision/checkpoint version and encrypted-envelope digest.
func (authority *FullInventoryRolloverAuthority) VerifyCheckpointLineageRollover(
	ctx context.Context,
	request discoveryqueue.CheckpointLineageRolloverRequest,
) error {
	if ctx == nil || !authority.authentic() {
		return errInventoryContinuity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	private := authority.state
	private.mu.Lock()
	defer private.mu.Unlock()
	if private.destroyed || private.pending == nil {
		return errInventoryContinuity
	}
	pending := private.pending[request.Coordinates.RunID]
	if pending == nil || !pending.inFlight ||
		!pending.verificationMatches(request) {
		return errInventoryContinuity
	}
	if pending.verifiedOK && pending.verified != request {
		return errInventoryContinuity
	}
	pending.verified = request
	pending.verifiedOK = true
	return nil
}

func (pending *fullInventoryRolloverPending) verificationMatches(
	request discoveryqueue.CheckpointLineageRolloverRequest,
) bool {
	if pending == nil || pending.registration == nil {
		return false
	}
	binding := pending.binding
	return request.Coordinates == pending.command.Coordinates &&
		request.SourceID == binding.Locator.SourceID &&
		request.ProviderKind == binding.ProviderKind &&
		request.SourceRevision == binding.SourceRevision &&
		request.SourceRevisionDigest == binding.SourceRevisionDigest &&
		lowercaseDigestPattern.MatchString(request.SourceDefinitionDigest) &&
		request.ProfileCode == binding.ProfileCode &&
		request.CheckpointVersion == pending.accepted.CheckpointVersion &&
		request.CheckpointSHA256 == pending.accepted.CheckpointSHA256 &&
		request.ReasonCode == pending.command.ReasonCode &&
		request.EvidenceDigest == pending.command.EvidenceDigest
}

func (pending *fullInventoryRolloverPending) Clear() {
	if pending == nil {
		return
	}
	pending.authority.Clear()
	clear(pending.objects)
	clear(pending.relations)
	pending.objects = nil
	pending.relations = nil
	pending.request = discoverycleanup.OpenAttemptRequest{}
	pending.command = discoveryqueue.RolloverCommand{}
	pending.fence = assetcatalog.LeaseFence{}
	pending.verified = discoveryqueue.CheckpointLineageRolloverRequest{}
	pending.verifiedOK = false
	pending.inFlight = false
	pending.successorID = ""
	pending.binding = discoverysource.RuntimeBinding{}
	pending.checkpoint = fullInventoryCheckpoint{}
	pending.accepted = discoverysource.PageCommitResult{}
}

func sameInventoryDigestSet(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for digest := range left {
		if _, exists := right[digest]; !exists {
			return false
		}
	}
	return true
}

func (record *fullInventoryRolloverRegistration) remove(
	attempt *FullInventoryAttempt,
) {
	if record == nil || record.authority == nil {
		return
	}
	private := record.authority
	private.mu.Lock()
	defer private.mu.Unlock()
	if record.attempt == attempt {
		record.attempt = nil
	}
	if private.attempts != nil && private.attempts[record.attemptID] == record {
		delete(private.attempts, record.attemptID)
	}
	if private.pending != nil {
		runID := record.request.Coordinates.RunID
		if pending := private.pending[runID]; pending != nil &&
			pending.registration == record {
			pending.Clear()
			pending.registration = nil
			delete(private.pending, runID)
		}
	}
}

func (revocation *fullInventoryRolloverRevocation) finish(revokeErr error) {
	if revocation == nil {
		return
	}
	revocation.mu.Lock()
	defer revocation.mu.Unlock()
	if revocation.revoked {
		return
	}
	revocation.revoked = true
	revocation.err = revokeErr
}

func (revocation *fullInventoryRolloverRevocation) finishDestroy() {
	if revocation == nil {
		return
	}
	revocation.mu.Lock()
	revocation.destroyed = true
	revocation.mu.Unlock()
}

func (revocation *fullInventoryRolloverRevocation) result() (bool, error) {
	if revocation == nil {
		return false, errInventoryContinuity
	}
	revocation.mu.Lock()
	defer revocation.mu.Unlock()
	return revocation.revoked && revocation.destroyed, revocation.err
}

// NewSuccessor consumes the exact handoff once. Calls made before the
// predecessor revoke completes fail without consuming the handoff, allowing
// the caller to retry only after CleanupBroker has completed Revoke+Destroy.
func (handoff *FullInventoryRolloverHandoff) NewSuccessor(
	ctx context.Context,
	queue discoveryqueue.Queue,
	fence assetcatalog.LeaseFence,
	material *RuntimeMaterial,
	checkpoint discoverysource.Checkpoint,
) (*FullInventoryAttempt, error) {
	if handoff == nil || handoff.self != handoff || handoff.state == nil {
		if material != nil {
			material.Clear()
		}
		return nil, errInventoryContinuity
	}
	private := handoff.state
	private.mu.Lock()
	if !private.active || private.issued != handoff || private.consumeStart {
		private.mu.Unlock()
		if material != nil {
			material.Clear()
		}
		return nil, errInventoryContinuity
	}
	completed, revokeErr := private.revocation.result()
	if !completed {
		private.mu.Unlock()
		if material != nil {
			material.Clear()
		}
		return nil, errInventoryContinuity
	}
	if revokeErr != nil {
		private.clearLocked()
		private.mu.Unlock()
		if material != nil {
			material.Clear()
		}
		return nil, errInventoryContinuity
	}
	if ctx == nil || queue == nil || ctx.Err() != nil ||
		private.fence != fence {
		private.clearLocked()
		private.mu.Unlock()
		if material != nil {
			material.Clear()
		}
		return nil, errInventoryContinuity
	}
	opened, empty, err := openFullInventoryCheckpoint(checkpoint)
	if err != nil || empty || opened != private.checkpoint {
		private.clearLocked()
		private.mu.Unlock()
		if material != nil {
			material.Clear()
		}
		return nil, errInventoryContinuity
	}
	private.consumeStart = true
	request := private.request
	private.mu.Unlock()

	current, revalidateErr := revalidateRolloverCleanupAttempt(
		ctx,
		queue,
		fence,
		request,
	)

	private.mu.Lock()
	if revalidateErr != nil || current != request.Attempt ||
		ctx.Err() != nil ||
		!private.active ||
		private.issued != handoff ||
		!private.consumeStart ||
		private.request != request ||
		private.fence != fence {
		private.clearLocked()
		private.mu.Unlock()
		if material != nil {
			material.Clear()
		}
		return nil, errInventoryContinuity
	}
	seed := private.checkpoint
	binding := private.binding
	authority := cloneAuthoritySnapshot(private.authority)
	objects := cloneInventoryObjects(private.objects)
	relations := cloneInventoryRelations(private.relations)
	successorID := private.successorID
	private.clearLocked()
	private.mu.Unlock()

	successor, err := newFullInventoryAttempt(
		material,
		seed,
		true,
		binding,
		authority,
		objects,
		relations,
	)
	if err != nil {
		return nil, err
	}
	successor.state.mu.Lock()
	successor.state.rolloverGoverned = true
	successor.state.successorID = successorID
	successor.state.mu.Unlock()
	return successor, nil
}

func (private *fullInventoryRolloverHandoffState) clearLocked() {
	private.request = discoverycleanup.OpenAttemptRequest{}
	private.command = discoveryqueue.RolloverCommand{}
	private.accepted = discoverysource.PageCommitResult{}
	private.verified = discoveryqueue.CheckpointLineageRolloverRequest{}
	private.checkpoint = fullInventoryCheckpoint{}
	private.binding = discoverysource.RuntimeBinding{}
	private.authority.Clear()
	clear(private.objects)
	clear(private.relations)
	private.objects = nil
	private.relations = nil
	private.fence = assetcatalog.LeaseFence{}
	private.successorID = ""
	private.revocation = nil
	private.active = false
	private.issued = nil
}

func (handoff *FullInventoryRolloverHandoff) Destroy() {
	if handoff == nil || handoff.self != handoff || handoff.state == nil {
		return
	}
	private := handoff.state
	private.mu.Lock()
	private.clearLocked()
	private.mu.Unlock()
}

func (authority *FullInventoryRolloverAuthority) Destroy() {
	if !authority.authentic() {
		return
	}
	private := authority.state
	private.mu.Lock()
	if private.destroyed {
		private.mu.Unlock()
		return
	}
	private.destroyed = true
	for _, pending := range private.pending {
		pending.Clear()
		pending.registration = nil
	}
	for _, record := range private.attempts {
		record.attempt = nil
	}
	private.pending = nil
	private.attempts = nil
	private.mu.Unlock()
}

func (FullInventoryRolloverAuthority) MarshalJSON() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*FullInventoryRolloverAuthority) UnmarshalJSON([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (FullInventoryRolloverAuthority) MarshalText() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*FullInventoryRolloverAuthority) UnmarshalText([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (FullInventoryRolloverAuthority) MarshalBinary() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*FullInventoryRolloverAuthority) UnmarshalBinary([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (FullInventoryRolloverAuthority) String() string {
	return fullInventoryRolloverAuthorityRedact
}
func (FullInventoryRolloverAuthority) GoString() string {
	return fullInventoryRolloverAuthorityRedact
}
func (FullInventoryRolloverAuthority) LogValue() slog.Value {
	return slog.StringValue(fullInventoryRolloverAuthorityRedact)
}
func (FullInventoryRolloverAuthority) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, fullInventoryRolloverAuthorityRedact)
}

func (FullInventoryRolloverHandoff) MarshalJSON() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*FullInventoryRolloverHandoff) UnmarshalJSON([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (FullInventoryRolloverHandoff) MarshalText() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*FullInventoryRolloverHandoff) UnmarshalText([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (FullInventoryRolloverHandoff) MarshalBinary() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*FullInventoryRolloverHandoff) UnmarshalBinary([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (FullInventoryRolloverHandoff) String() string {
	return fullInventoryRolloverHandoffRedact
}
func (FullInventoryRolloverHandoff) GoString() string {
	return fullInventoryRolloverHandoffRedact
}
func (FullInventoryRolloverHandoff) LogValue() slog.Value {
	return slog.StringValue(fullInventoryRolloverHandoffRedact)
}
func (FullInventoryRolloverHandoff) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, fullInventoryRolloverHandoffRedact)
}

var _ discoveryqueue.CheckpointLineageRolloverVerifier = (*FullInventoryRolloverAuthority)(nil)
