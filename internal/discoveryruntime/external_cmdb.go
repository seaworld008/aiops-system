package discoveryruntime

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/assetsource/externalcmdb"
	"github.com/seaworld008/aiops-system/internal/discoverycheckpoint"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/seaworld008/aiops-system/internal/discoveryworker"
	"github.com/seaworld008/aiops-system/internal/sourceprofile"
)

const (
	externalCMDBAuthoritySeal       = uint64(0xb8647c192f30a5de)
	externalCMDBMaterialRequestSeal = uint64(0x7d28a45c93e061bf)
	externalCMDBMaterialSeal        = uint64(0xc1749e603b82ad5f)
	externalCMDBCleanupTimeout      = 15 * time.Second

	externalCMDBAuthorityRedaction = "[REDACTED_EXTERNAL_CMDB_RUNTIME_AUTHORITY]"
	externalCMDBRequestRedaction   = "[REDACTED_EXTERNAL_CMDB_MATERIAL_REQUEST]"
	externalCMDBMaterialRedaction  = "[REDACTED_EXTERNAL_CMDB_RUNTIME_MATERIAL]"
)

var (
	ErrExternalCMDBRuntimeAuthority = errors.New(
		"external cmdb runtime authority rejected",
	)
	ErrSensitiveSerialization = discoveryworker.ErrSensitiveSerialization
)

// ExternalCMDBMaterialResolver is the sole server-side material resolver used
// by ExternalCMDBAuthority. It receives one callback-scoped capability holding
// opaque references only and transfers one process-local material owner. It
// must reject an expired context before credential or network access.
type ExternalCMDBMaterialResolver interface {
	ResolveExternalCMDB(
		context.Context,
		*ExternalCMDBMaterialRequest,
	) (*ExternalCMDBRuntimeMaterial, error)
}

type externalCMDBReferenceResolver interface {
	resolveExternalCMDBAttempt(
		context.Context,
		externalCMDBAttemptKey,
	) (externalCMDBAttemptSnapshot, error)
	admitExternalCMDBMaterial(
		context.Context,
		externalCMDBAttemptKey,
		externalCMDBAttemptSnapshot,
		func(context.Context, externalCMDBAttemptSnapshot) error,
	) error
}

// ExternalCMDBAuthority implements discoveryworker.AttemptRuntimeFactory. It
// combines a real PostgreSQL exact-fact resolver with one process-local
// material resolver; Task 28B remains the only SessionOpener/transport owner.
type ExternalCMDBAuthority struct {
	self  *ExternalCMDBAuthority
	seal  uint64
	state *externalCMDBAuthorityState
}

type externalCMDBAuthorityState struct {
	mu          sync.Mutex
	references  externalCMDBReferenceResolver
	materials   ExternalCMDBMaterialResolver
	descriptor  externalcmdb.ReconciliationDescriptor
	attempts    map[string]*externalCMDBAttemptCell
	lifetime    context.Context
	cancel      context.CancelFunc
	operations  sync.WaitGroup
	destroyDone chan struct{}
	destroyed   bool
}

type externalCMDBAttemptCell struct {
	mu          sync.Mutex
	snapshot    externalCMDBAttemptSnapshot
	material    *ExternalCMDBRuntimeMaterial
	resolving   bool
	opened      bool
	claimIssued bool
	rejected    bool
}

type externalCMDBAttemptKey struct {
	coordinates discoveryqueue.RunCoordinates
	attempt     discoveryqueue.CleanupAttempt
}

type externalCMDBReferences struct {
	integrationID            string
	credentialReferenceID    string
	trustReferenceID         string
	networkPolicyReferenceID string
}

type externalCMDBAttemptSnapshot struct {
	key                    externalCMDBAttemptKey
	binding                discoverysource.RuntimeBinding
	runKind                assetcatalog.RunKind
	references             externalCMDBReferences
	environmentID          string
	sourceDefinitionSHA256 string
	descriptorSHA256       string
	limits                 discoverysource.Limits
	sealedCheckpoint       discoverycheckpoint.SealedCheckpoint
	checkpointVersion      int64
	checkpointSHA256       string
	initialAllowed         bool
	materialDeadline       time.Time
}

// ExternalCMDBMaterialRequest is valid only during one material-resolver call.
// It contains exact safe tuple metadata and opaque reference identifiers, never
// endpoint, credential, CA, key, path, header, body, or runtime material.
type ExternalCMDBMaterialRequest struct {
	self  *ExternalCMDBMaterialRequest
	seal  uint64
	state *externalCMDBMaterialRequestState
}

type externalCMDBMaterialRequestState struct {
	mu       sync.Mutex
	issued   *ExternalCMDBMaterialRequest
	snapshot externalCMDBAttemptSnapshot
	active   bool
}

// ExternalCMDBRuntimeMaterial transfers sole ownership of one resolved
// externalcmdb.RuntimeMaterial and its opaque revoke/destroy callbacks.
type ExternalCMDBRuntimeMaterial struct {
	self  *ExternalCMDBRuntimeMaterial
	seal  uint64
	state *externalCMDBRuntimeMaterialState
}

type externalCMDBRuntimeMaterialState struct {
	mu          sync.Mutex
	issued      *ExternalCMDBRuntimeMaterial
	material    *externalcmdb.RuntimeMaterial
	runtime     discoverysource.BoundRuntime
	revoke      func(context.Context) error
	destroy     func()
	release     func()
	revokeDone  chan struct{}
	revokeErr   error
	revoking    bool
	revoked     bool
	bound       bool
	destroying  bool
	destroyed   bool
	destroyDone chan struct{}
}

// NewExternalCMDBAuthority creates the production-shaped External CMDB runtime
// authority from the sole PostgreSQL fact resolver and material resolver.
func NewExternalCMDBAuthority(
	postgres *Postgres,
	materials ExternalCMDBMaterialResolver,
) (*ExternalCMDBAuthority, error) {
	if postgres == nil {
		return nil, ErrExternalCMDBRuntimeAuthority
	}
	return newExternalCMDBAuthority(postgres, materials)
}

func newExternalCMDBAuthority(
	references externalCMDBReferenceResolver,
	materials ExternalCMDBMaterialResolver,
) (*ExternalCMDBAuthority, error) {
	if nilInterface(references) || nilInterface(materials) {
		return nil, ErrExternalCMDBRuntimeAuthority
	}
	descriptor, err := externalcmdb.NewReconciliationDescriptor(
		sourceprofile.ExternalCMDBV1(),
	)
	if err != nil || descriptor.DescriptorDigestSHA256() == "" {
		return nil, ErrExternalCMDBRuntimeAuthority
	}
	lifetime, cancel := context.WithCancel(context.Background())
	private := &externalCMDBAuthorityState{
		references:  references,
		materials:   materials,
		descriptor:  descriptor,
		attempts:    make(map[string]*externalCMDBAttemptCell),
		lifetime:    lifetime,
		cancel:      cancel,
		destroyDone: make(chan struct{}),
	}
	authority := &ExternalCMDBAuthority{
		seal:  externalCMDBAuthoritySeal,
		state: private,
	}
	authority.self = authority
	return authority, nil
}

func (authority *ExternalCMDBAuthority) ResolveRuntimeBinding(
	ctx context.Context,
	request discoverycleanup.OpenAttemptRequest,
) (discoverysource.RuntimeBinding, error) {
	if ctx == nil || request.Validate() != nil || !authority.authentic() {
		return discoverysource.RuntimeBinding{}, ErrExternalCMDBRuntimeAuthority
	}
	key, err := newExternalCMDBAttemptKey(request)
	if err != nil {
		return discoverysource.RuntimeBinding{}, err
	}
	private, operationContext, release, err := authority.begin(ctx)
	if err != nil {
		return discoverysource.RuntimeBinding{}, err
	}
	defer release()

	snapshot, err := private.references.resolveExternalCMDBAttempt(
		operationContext,
		key,
	)
	if err != nil || !snapshot.valid(private.descriptor) {
		private.rejectRelated(key)
		return discoverysource.RuntimeBinding{}, boundedRuntimeAuthorityError(err)
	}
	defer clear(snapshot.sealedCheckpoint.Envelope)
	private.mu.Lock()
	cell := private.attempts[key.attempt.AttemptID]
	if cell == nil {
		cell = &externalCMDBAttemptCell{snapshot: snapshot.clone()}
		private.attempts[key.attempt.AttemptID] = cell
		private.mu.Unlock()
		return snapshot.binding, nil
	}
	private.mu.Unlock()

	cell.mu.Lock()
	defer cell.mu.Unlock()
	if cell.rejected || !cell.snapshot.same(snapshot) {
		cell.rejected = true
		return discoverysource.RuntimeBinding{}, ErrExternalCMDBRuntimeAuthority
	}
	return cell.snapshot.binding, nil
}

func (private *externalCMDBAuthorityState) rejectRelated(
	key externalCMDBAttemptKey,
) {
	type candidate struct {
		attemptID string
		cell      *externalCMDBAttemptCell
	}
	private.mu.Lock()
	candidates := make([]candidate, 0, len(private.attempts))
	for attemptID, cell := range private.attempts {
		candidates = append(candidates, candidate{
			attemptID: attemptID,
			cell:      cell,
		})
	}
	private.mu.Unlock()
	for _, candidate := range candidates {
		candidate.cell.mu.Lock()
		if candidate.attemptID == key.attempt.AttemptID ||
			candidate.cell.snapshot.key.coordinates.RunID ==
				key.coordinates.RunID ||
			candidate.cell.snapshot.key.attempt.RunID == key.attempt.RunID {
			candidate.cell.rejected = true
		}
		candidate.cell.mu.Unlock()
	}
}

func (authority *ExternalCMDBAuthority) OpenInitialRuntime(
	ctx context.Context,
	request *discoveryworker.InitialRuntimeRequest,
) (*discoveryworker.SessionBoundRuntime, error) {
	if ctx == nil || request == nil || !authority.authentic() {
		return nil, ErrExternalCMDBRuntimeAuthority
	}
	return request.ResolveRuntime(
		ctx,
		func(
			callbackContext context.Context,
			tuple *discoveryworker.InitialRuntimeTuple,
		) (
			discoverysource.BoundRuntime,
			discoveryworker.InitialRuntimeLifecycle,
			error,
		) {
			key, err := externalCMDBAttemptKeyFromTuple(tuple)
			if err != nil {
				return discoverysource.BoundRuntime{}, nil, err
			}
			return authority.materialize(
				callbackContext,
				key,
				tuple.RuntimeBinding(),
			)
		},
	)
}

func (authority *ExternalCMDBAuthority) ResolveClaimRuntime(
	ctx context.Context,
	request discoveryworker.ResolveOpenedAttemptRequest,
) (
	discoverysource.Provider,
	*discoverysource.Checkpoint,
	discoverysource.Limits,
	assetdiscovery.FactPolicy,
	error,
) {
	key := externalCMDBAttemptKey{
		coordinates: request.Coordinates(),
		attempt:     request.Attempt(),
	}
	return authority.claimComponents(
		ctx,
		key,
		request.RuntimeBinding(),
		request.RunKind(),
		request.CheckpointVersion(),
		request.CheckpointSHA256(),
		request.CheckpointCodec(),
	)
}

func (authority *ExternalCMDBAuthority) materialize(
	ctx context.Context,
	key externalCMDBAttemptKey,
	binding discoverysource.RuntimeBinding,
) (
	discoverysource.BoundRuntime,
	discoveryworker.InitialRuntimeLifecycle,
	error,
) {
	if ctx == nil || !key.valid() || !runtimeBindingValid(binding) ||
		!authority.authentic() {
		return discoverysource.BoundRuntime{}, nil, ErrExternalCMDBRuntimeAuthority
	}
	private, operationContext, release, err := authority.begin(ctx)
	if err != nil {
		return discoverysource.BoundRuntime{}, nil, err
	}
	defer release()

	private.mu.Lock()
	cell := private.attempts[key.attempt.AttemptID]
	private.mu.Unlock()
	if cell == nil {
		return discoverysource.BoundRuntime{}, nil, ErrExternalCMDBRuntimeAuthority
	}
	cell.mu.Lock()
	if cell.rejected || cell.resolving || cell.opened ||
		!cell.snapshot.initialAllowed ||
		cell.snapshot.key != key ||
		cell.snapshot.binding != binding {
		cell.mu.Unlock()
		return discoverysource.BoundRuntime{}, nil, ErrExternalCMDBRuntimeAuthority
	}
	cell.resolving = true
	snapshot := cell.snapshot.clone()
	cell.mu.Unlock()
	defer clear(snapshot.sealedCheckpoint.Envelope)

	var bound discoverysource.BoundRuntime
	var resolved *ExternalCMDBRuntimeMaterial
	admissionErr := private.references.admitExternalCMDBMaterial(
		operationContext,
		key,
		snapshot,
		func(
			admissionContext context.Context,
			confirmed externalCMDBAttemptSnapshot,
		) error {
			if admissionContext == nil ||
				admissionContext.Err() != nil ||
				!confirmed.valid(private.descriptor) ||
				!snapshot.same(confirmed) ||
				resolved != nil {
				return ErrExternalCMDBRuntimeAuthority
			}
			materialRequest := newExternalCMDBMaterialRequest(confirmed)
			candidate, resolveErr := private.materials.ResolveExternalCMDB(
				admissionContext,
				materialRequest,
			)
			materialRequest.destroy()
			if resolveErr != nil || candidate == nil ||
				!candidate.authentic() {
				if candidate != nil {
					_ = revokeExternalCMDBMaterial(
						admissionContext,
						candidate,
					)
					candidate.Destroy()
				}
				return boundedRuntimeAuthorityError(resolveErr)
			}
			candidateBound, bindErr := candidate.bind(binding, confirmed)
			if bindErr != nil {
				_ = revokeExternalCMDBMaterial(
					admissionContext,
					candidate,
				)
				candidate.Destroy()
				return bindErr
			}
			private.mu.Lock()
			stillInstalled := !private.destroyed &&
				private.attempts[key.attempt.AttemptID] == cell
			private.mu.Unlock()
			cell.mu.Lock()
			cellValid := stillInstalled && !cell.rejected &&
				cell.resolving && !cell.opened &&
				cell.snapshot.same(confirmed)
			cell.mu.Unlock()
			if !cellValid {
				candidateBound.Clear()
				_ = revokeExternalCMDBMaterial(
					admissionContext,
					candidate,
				)
				candidate.Destroy()
				return ErrExternalCMDBRuntimeAuthority
			}
			clear(snapshot.sealedCheckpoint.Envelope)
			snapshot = confirmed.clone()
			bound = candidateBound
			resolved = candidate
			return nil
		},
	)
	if admissionErr != nil || operationContext.Err() != nil ||
		resolved == nil || !resolved.authentic() {
		operationErr := operationContext.Err()
		bound.Clear()
		if resolved != nil {
			_ = revokeExternalCMDBMaterial(operationContext, resolved)
			resolved.Destroy()
		}
		cell.mu.Lock()
		clear(cell.snapshot.sealedCheckpoint.Envelope)
		cell.snapshot = externalCMDBAttemptSnapshot{}
		cell.resolving = false
		cell.rejected = true
		cell.mu.Unlock()
		return discoverysource.BoundRuntime{}, nil,
			boundedRuntimeAuthorityError(
				errors.Join(admissionErr, operationErr),
			)
	}

	private.mu.Lock()
	stillInstalled := !private.destroyed &&
		private.attempts[key.attempt.AttemptID] == cell
	private.mu.Unlock()
	cell.mu.Lock()
	if !stillInstalled || cell.rejected || !cell.resolving || cell.opened ||
		!cell.snapshot.same(snapshot) {
		clear(cell.snapshot.sealedCheckpoint.Envelope)
		cell.snapshot = externalCMDBAttemptSnapshot{}
		cell.resolving = false
		cell.rejected = true
		cell.mu.Unlock()
		bound.Clear()
		_ = revokeExternalCMDBMaterial(operationContext, resolved)
		resolved.Destroy()
		return discoverysource.BoundRuntime{}, nil, ErrExternalCMDBRuntimeAuthority
	}
	cell.resolving = false
	cell.opened = true
	cell.material = resolved
	cell.mu.Unlock()
	if err := resolved.installRelease(func() {
		private.releaseMaterial(cell, resolved)
	}); err != nil {
		bound.Clear()
		_ = revokeExternalCMDBMaterial(operationContext, resolved)
		resolved.Destroy()
		private.releaseMaterial(cell, resolved)
		cell.mu.Lock()
		cell.rejected = true
		cell.mu.Unlock()
		return discoverysource.BoundRuntime{}, nil, err
	}
	return bound, resolved, nil
}

func (private *externalCMDBAuthorityState) releaseMaterial(
	cell *externalCMDBAttemptCell,
	material *ExternalCMDBRuntimeMaterial,
) {
	if private == nil || cell == nil || material == nil {
		return
	}
	cell.mu.Lock()
	if cell.material == material {
		clear(cell.snapshot.sealedCheckpoint.Envelope)
		cell.snapshot = externalCMDBAttemptSnapshot{}
		cell.material = nil
		cell.resolving = false
		cell.opened = false
		cell.claimIssued = false
		cell.rejected = true
	}
	cell.mu.Unlock()
}

func (authority *ExternalCMDBAuthority) claimComponents(
	ctx context.Context,
	key externalCMDBAttemptKey,
	binding discoverysource.RuntimeBinding,
	runKind assetcatalog.RunKind,
	checkpointVersion int64,
	checkpointSHA256 string,
	checkpoints *discoverycheckpoint.CheckpointCodec,
) (
	discoverysource.Provider,
	*discoverysource.Checkpoint,
	discoverysource.Limits,
	assetdiscovery.FactPolicy,
	error,
) {
	if ctx == nil || !key.valid() || !runtimeBindingValid(binding) ||
		!authority.authentic() {
		return nil, nil, discoverysource.Limits{}, assetdiscovery.FactPolicy{},
			ErrExternalCMDBRuntimeAuthority
	}
	private, operationContext, release, err := authority.begin(ctx)
	if err != nil {
		return nil, nil, discoverysource.Limits{}, assetdiscovery.FactPolicy{}, err
	}
	defer release()

	private.mu.Lock()
	cell := private.attempts[key.attempt.AttemptID]
	private.mu.Unlock()
	if cell == nil {
		return nil, nil, discoverysource.Limits{}, assetdiscovery.FactPolicy{},
			ErrExternalCMDBRuntimeAuthority
	}
	cell.mu.Lock()
	if cell.rejected || !cell.opened || cell.resolving || cell.claimIssued ||
		cell.snapshot.key != key || cell.snapshot.binding != binding ||
		cell.snapshot.runKind != runKind ||
		cell.snapshot.checkpointVersion != checkpointVersion ||
		cell.snapshot.checkpointSHA256 != checkpointSHA256 {
		cell.mu.Unlock()
		return nil, nil, discoverysource.Limits{}, assetdiscovery.FactPolicy{},
			ErrExternalCMDBRuntimeAuthority
	}
	cell.claimIssued = true
	snapshot := cell.snapshot.clone()
	cell.mu.Unlock()

	var provider discoverysource.Provider
	if runKind == assetcatalog.RunKindValidation {
		factory, factoryErr := externalcmdb.NewClientFactory(binding)
		if factoryErr == nil {
			provider, err = externalcmdb.New(factory)
		} else {
			err = factoryErr
		}
	} else {
		provider, err = private.descriptor.NewProvider(binding)
	}
	if err != nil {
		return nil, nil, discoverysource.Limits{}, assetdiscovery.FactPolicy{},
			ErrExternalCMDBRuntimeAuthority
	}
	var checkpoint discoverysource.Checkpoint
	switch {
	case runKind == assetcatalog.RunKindValidation || checkpointVersion == 0:
		checkpoint, err = private.descriptor.NewCheckpoint()
	case runKind == assetcatalog.RunKindDiscovery &&
		checkpointVersion > 0 &&
		checkpoints != nil:
		checkpoint, err = checkpoints.Open(
			operationContext,
			discoverycheckpoint.CheckpointAAD{
				TenantID:                snapshot.binding.Locator.Scope.TenantID,
				WorkspaceID:             snapshot.binding.Locator.Scope.WorkspaceID,
				SourceID:                snapshot.binding.Locator.SourceID,
				ProviderKind:            snapshot.binding.ProviderKind,
				CheckpointRevision:      snapshot.binding.SourceRevision,
				CanonicalRevisionDigest: snapshot.binding.SourceRevisionDigest,
				SourceDefinitionDigest:  snapshot.sourceDefinitionSHA256,
				CheckpointKeyID:         snapshot.sealedCheckpoint.CheckpointKeyID,
				CheckpointVersion:       snapshot.checkpointVersion,
			},
			snapshot.binding.ProfileCode,
			snapshot.sealedCheckpoint,
		)
	default:
		err = ErrExternalCMDBRuntimeAuthority
	}
	if err != nil {
		return nil, nil, discoverysource.Limits{}, assetdiscovery.FactPolicy{},
			boundedRuntimeAuthorityError(err)
	}
	policy, err := private.descriptor.FactPolicy(
		[]string{snapshot.environmentID},
	)
	if err != nil {
		checkpoint.Clear()
		return nil, nil, discoverysource.Limits{}, assetdiscovery.FactPolicy{},
			ErrExternalCMDBRuntimeAuthority
	}
	return provider, &checkpoint, snapshot.limits, policy, nil
}

func (authority *ExternalCMDBAuthority) Destroy() {
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
	cells := make([]*externalCMDBAttemptCell, 0, len(private.attempts))
	for _, cell := range private.attempts {
		cells = append(cells, cell)
	}
	private.attempts = nil
	private.references = nil
	private.materials = nil
	private.descriptor = externalcmdb.ReconciliationDescriptor{}
	private.mu.Unlock()
	for _, cell := range cells {
		cell.mu.Lock()
		material := cell.material
		cell.material = nil
		cell.snapshot = externalCMDBAttemptSnapshot{}
		cell.rejected = true
		cell.opened = false
		cell.resolving = false
		cell.mu.Unlock()
		if material != nil {
			material.Destroy()
		}
	}
	close(private.destroyDone)
}

func (authority *ExternalCMDBAuthority) authentic() bool {
	return authority != nil && authority.self == authority &&
		authority.seal == externalCMDBAuthoritySeal && authority.state != nil
}

func (authority *ExternalCMDBAuthority) begin(
	ctx context.Context,
) (*externalCMDBAuthorityState, context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	private := authority.state
	private.mu.Lock()
	if private.destroyed || nilInterface(private.references) ||
		nilInterface(private.materials) {
		private.mu.Unlock()
		return nil, nil, nil, ErrExternalCMDBRuntimeAuthority
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

func newExternalCMDBAttemptKey(
	request discoverycleanup.OpenAttemptRequest,
) (externalCMDBAttemptKey, error) {
	key := externalCMDBAttemptKey{
		coordinates: request.Coordinates,
		attempt:     request.Attempt,
	}
	if request.Validate() != nil || !key.valid() {
		return externalCMDBAttemptKey{}, ErrExternalCMDBRuntimeAuthority
	}
	return key, nil
}

func externalCMDBAttemptKeyFromTuple(
	tuple *discoveryworker.InitialRuntimeTuple,
) (externalCMDBAttemptKey, error) {
	if tuple == nil {
		return externalCMDBAttemptKey{}, ErrExternalCMDBRuntimeAuthority
	}
	key := externalCMDBAttemptKey{
		coordinates: tuple.Coordinates(),
		attempt:     tuple.Attempt(),
	}
	if !key.valid() {
		return externalCMDBAttemptKey{}, ErrExternalCMDBRuntimeAuthority
	}
	return key, nil
}

func (key externalCMDBAttemptKey) valid() bool {
	return key.coordinates.Valid() &&
		key.attempt.Valid() &&
		key.attempt.RunID == key.coordinates.RunID
}

func (snapshot externalCMDBAttemptSnapshot) clone() externalCMDBAttemptSnapshot {
	snapshot.sealedCheckpoint = snapshot.sealedCheckpoint.Clone()
	return snapshot
}

func (snapshot externalCMDBAttemptSnapshot) valid(
	descriptor externalcmdb.ReconciliationDescriptor,
) bool {
	if !snapshot.key.valid() || !runtimeBindingValid(snapshot.binding) ||
		snapshot.binding.Locator.Scope != snapshot.key.coordinates.Scope ||
		snapshot.runKind != assetcatalog.RunKindValidation &&
			snapshot.runKind != assetcatalog.RunKindDiscovery ||
		!canonicalUUID(snapshot.references.integrationID) ||
		!assetcatalog.CredentialReferenceID(
			snapshot.references.credentialReferenceID,
		).Valid() ||
		!assetcatalog.TrustReferenceID(snapshot.references.trustReferenceID).Valid() ||
		!assetcatalog.NetworkPolicyReferenceID(
			snapshot.references.networkPolicyReferenceID,
		).Valid() ||
		!canonicalUUID(snapshot.environmentID) ||
		!validDigest(snapshot.sourceDefinitionSHA256) ||
		!validDigest(snapshot.descriptorSHA256) ||
		snapshot.descriptorSHA256 != descriptor.DescriptorDigestSHA256() ||
		snapshot.limits != descriptor.Limits() {
		return false
	}
	if snapshot.materialDeadline.IsZero() ||
		!time.Now().Before(snapshot.materialDeadline) {
		return false
	}
	if snapshot.runKind == assetcatalog.RunKindValidation {
		if snapshot.binding.RevisionStatus !=
			assetcatalog.SourceRevisionValidating ||
			snapshot.checkpointVersion != 0 {
			return false
		}
		return snapshot.checkpointSHA256 == "" &&
			len(snapshot.sealedCheckpoint.Envelope) == 0
	}
	if snapshot.binding.RevisionStatus !=
		assetcatalog.SourceRevisionPublished ||
		snapshot.checkpointVersion < 0 {
		return false
	}
	if !snapshot.initialAllowed {
		return snapshot.checkpointSHA256 == "" &&
			len(snapshot.sealedCheckpoint.Envelope) == 0
	}
	if snapshot.checkpointVersion == 0 {
		return snapshot.checkpointSHA256 == "" &&
			len(snapshot.sealedCheckpoint.Envelope) == 0
	}
	return validDigest(snapshot.checkpointSHA256) &&
		snapshot.sealedCheckpoint.CheckpointVersion == snapshot.checkpointVersion &&
		snapshot.sealedCheckpoint.CheckpointSHA256 == snapshot.checkpointSHA256 &&
		snapshot.sealedCheckpoint.CheckpointKeyID != "" &&
		len(snapshot.sealedCheckpoint.Envelope) > 0
}

func (snapshot externalCMDBAttemptSnapshot) same(
	other externalCMDBAttemptSnapshot,
) bool {
	return snapshot.key == other.key &&
		snapshot.binding == other.binding &&
		snapshot.runKind == other.runKind &&
		snapshot.references == other.references &&
		snapshot.environmentID == other.environmentID &&
		snapshot.sourceDefinitionSHA256 == other.sourceDefinitionSHA256 &&
		snapshot.descriptorSHA256 == other.descriptorSHA256 &&
		snapshot.limits == other.limits &&
		snapshot.checkpointVersion == other.checkpointVersion &&
		snapshot.checkpointSHA256 == other.checkpointSHA256 &&
		snapshot.initialAllowed == other.initialAllowed &&
		snapshot.sealedCheckpoint.CheckpointKeyID ==
			other.sealedCheckpoint.CheckpointKeyID &&
		snapshot.sealedCheckpoint.CheckpointSHA256 ==
			other.sealedCheckpoint.CheckpointSHA256 &&
		snapshot.sealedCheckpoint.CheckpointVersion ==
			other.sealedCheckpoint.CheckpointVersion &&
		bytes.Equal(
			snapshot.sealedCheckpoint.Envelope,
			other.sealedCheckpoint.Envelope,
		)
}

func newExternalCMDBMaterialRequest(
	snapshot externalCMDBAttemptSnapshot,
) *ExternalCMDBMaterialRequest {
	private := &externalCMDBMaterialRequestState{
		snapshot: snapshot.clone(),
		active:   true,
	}
	request := &ExternalCMDBMaterialRequest{
		seal:  externalCMDBMaterialRequestSeal,
		state: private,
	}
	request.self = request
	private.issued = request
	return request
}

func (request *ExternalCMDBMaterialRequest) Coordinates() discoveryqueue.RunCoordinates {
	snapshot, ok := request.snapshot()
	if !ok {
		return discoveryqueue.RunCoordinates{}
	}
	return snapshot.key.coordinates
}

func (request *ExternalCMDBMaterialRequest) Attempt() discoveryqueue.CleanupAttempt {
	snapshot, ok := request.snapshot()
	if !ok {
		return discoveryqueue.CleanupAttempt{}
	}
	return snapshot.key.attempt
}

func (request *ExternalCMDBMaterialRequest) RuntimeBinding() discoverysource.RuntimeBinding {
	snapshot, ok := request.snapshot()
	if !ok {
		return discoverysource.RuntimeBinding{}
	}
	return snapshot.binding
}

func (request *ExternalCMDBMaterialRequest) IntegrationID() string {
	snapshot, ok := request.snapshot()
	if !ok {
		return ""
	}
	return snapshot.references.integrationID
}

func (request *ExternalCMDBMaterialRequest) CredentialReferenceID() string {
	snapshot, ok := request.snapshot()
	if !ok {
		return ""
	}
	return snapshot.references.credentialReferenceID
}

func (request *ExternalCMDBMaterialRequest) TrustReferenceID() string {
	snapshot, ok := request.snapshot()
	if !ok {
		return ""
	}
	return snapshot.references.trustReferenceID
}

func (request *ExternalCMDBMaterialRequest) NetworkPolicyReferenceID() string {
	snapshot, ok := request.snapshot()
	if !ok {
		return ""
	}
	return snapshot.references.networkPolicyReferenceID
}

func (request *ExternalCMDBMaterialRequest) EnvironmentID() string {
	snapshot, ok := request.snapshot()
	if !ok {
		return ""
	}
	return snapshot.environmentID
}

func (request *ExternalCMDBMaterialRequest) snapshot() (
	externalCMDBAttemptSnapshot,
	bool,
) {
	if request == nil || request.self != request ||
		request.seal != externalCMDBMaterialRequestSeal ||
		request.state == nil {
		return externalCMDBAttemptSnapshot{}, false
	}
	private := request.state
	private.mu.Lock()
	defer private.mu.Unlock()
	if !private.active || private.issued != request {
		return externalCMDBAttemptSnapshot{}, false
	}
	return private.snapshot.clone(), true
}

func (request *ExternalCMDBMaterialRequest) destroy() {
	if request == nil || request.self != request ||
		request.seal != externalCMDBMaterialRequestSeal ||
		request.state == nil {
		return
	}
	private := request.state
	private.mu.Lock()
	if private.issued == request {
		private.active = false
		private.issued = nil
		clear(private.snapshot.sealedCheckpoint.Envelope)
		private.snapshot = externalCMDBAttemptSnapshot{}
	}
	private.mu.Unlock()
}

// NewExternalCMDBRuntimeMaterial transfers one resolved RuntimeMaterial and its
// revoke/destroy lifecycle into a non-copyable process-local capability.
// Revoke callbacks must return when their context is done; destroy callbacks
// must be synchronous and non-blocking.
func NewExternalCMDBRuntimeMaterial(
	material *externalcmdb.RuntimeMaterial,
	revoke func(context.Context) error,
	destroy func(),
) (*ExternalCMDBRuntimeMaterial, error) {
	if !validExternalCMDBMaterial(material) || revoke == nil || destroy == nil {
		return nil, ErrExternalCMDBRuntimeAuthority
	}
	clonedTLSConfig, cloned := cloneExternalCMDBTLSConfig(
		material.TLSConfig,
	)
	if !cloned {
		return nil, ErrExternalCMDBRuntimeAuthority
	}
	owned := &externalcmdb.RuntimeMaterial{
		BaseURL:             material.BaseURL,
		TLSConfig:           clonedTLSConfig,
		BearerToken:         bytes.Clone(material.BearerToken),
		ExpectedAuthorityID: material.ExpectedAuthorityID,
		EnvironmentID:       material.EnvironmentID,
	}
	if !validExternalCMDBMaterial(owned) {
		clearExternalCMDBRuntimeMaterial(owned)
		return nil, ErrExternalCMDBRuntimeAuthority
	}
	clearExternalCMDBTLSConfigSecrets(material.TLSConfig)
	material.Clear()
	private := &externalCMDBRuntimeMaterialState{
		material:    owned,
		revoke:      revoke,
		destroy:     destroy,
		destroyDone: make(chan struct{}),
	}
	resolved := &ExternalCMDBRuntimeMaterial{
		seal:  externalCMDBMaterialSeal,
		state: private,
	}
	resolved.self = resolved
	private.issued = resolved
	return resolved, nil
}

func cloneExternalCMDBTLSConfig(source *tls.Config) (*tls.Config, bool) {
	if !safeExternalCMDBTLSConfig(source) {
		return nil, false
	}
	cloned := source.Clone()
	if source.RootCAs != nil {
		cloned.RootCAs = source.RootCAs.Clone()
	}
	if source.ClientCAs != nil {
		cloned.ClientCAs = source.ClientCAs.Clone()
	}
	cloned.NextProtos = append([]string(nil), source.NextProtos...)
	cloned.CipherSuites = append([]uint16(nil), source.CipherSuites...)
	cloned.CurvePreferences = append(
		[]tls.CurveID(nil),
		source.CurvePreferences...,
	)
	cloned.EncryptedClientHelloConfigList = bytes.Clone(
		source.EncryptedClientHelloConfigList,
	)
	cloned.Certificates = make(
		[]tls.Certificate,
		len(source.Certificates),
	)
	for index := range source.Certificates {
		certificate, ok := cloneExternalCMDBTLSCertificate(
			source.Certificates[index],
		)
		if !ok {
			clearExternalCMDBTLSConfigSecrets(cloned)
			return nil, false
		}
		cloned.Certificates[index] = certificate
	}
	cloned.Rand = nil
	cloned.Time = nil
	cloned.NameToCertificate = nil
	cloned.GetCertificate = nil
	cloned.GetClientCertificate = nil
	cloned.GetConfigForClient = nil
	cloned.VerifyPeerCertificate = nil
	cloned.VerifyConnection = nil
	cloned.ClientSessionCache = nil
	cloned.UnwrapSession = nil
	cloned.WrapSession = nil
	cloned.KeyLogWriter = nil
	cloned.EncryptedClientHelloRejectionVerify = nil
	cloned.GetEncryptedClientHelloKeys = nil
	cloned.EncryptedClientHelloKeys = nil
	return cloned, true
}

func cloneExternalCMDBTLSCertificate(
	source tls.Certificate,
) (tls.Certificate, bool) {
	cloned := source
	cloned.PrivateKey = nil
	cloned.Certificate = cloneExternalCMDBByteSlices(source.Certificate)
	cloned.SupportedSignatureAlgorithms = append(
		[]tls.SignatureScheme(nil),
		source.SupportedSignatureAlgorithms...,
	)
	cloned.OCSPStaple = bytes.Clone(source.OCSPStaple)
	cloned.SignedCertificateTimestamps = cloneExternalCMDBByteSlices(
		source.SignedCertificateTimestamps,
	)
	cloned.Leaf = nil
	if source.PrivateKey == nil {
		return cloned, true
	}
	privateKey, ok := cloneExternalCMDBPrivateKey(source.PrivateKey)
	if !ok {
		clearExternalCMDBTLSCertificate(&cloned)
		return tls.Certificate{}, false
	}
	cloned.PrivateKey = privateKey
	return cloned, true
}

func cloneExternalCMDBByteSlices(source [][]byte) [][]byte {
	if source == nil {
		return nil
	}
	cloned := make([][]byte, len(source))
	for index := range source {
		cloned[index] = bytes.Clone(source[index])
	}
	return cloned
}

func cloneExternalCMDBPrivateKey(
	source crypto.PrivateKey,
) (crypto.PrivateKey, bool) {
	switch key := source.(type) {
	case *rsa.PrivateKey:
		return cloneExternalCMDBRSAPrivateKey(key)
	case *ecdsa.PrivateKey:
		return cloneExternalCMDBECDSAPrivateKey(key)
	case ed25519.PrivateKey:
		return cloneExternalCMDBEd25519PrivateKey(key)
	case *ed25519.PrivateKey:
		if key == nil {
			return nil, false
		}
		return cloneExternalCMDBEd25519PrivateKey(*key)
	default:
		return nil, false
	}
}

func cloneExternalCMDBRSAPrivateKey(
	source *rsa.PrivateKey,
) (*rsa.PrivateKey, bool) {
	if source == nil || source.N == nil || source.D == nil ||
		len(source.Primes) < 2 {
		return nil, false
	}
	cloned := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: cloneExternalCMDBBigInt(source.N),
			E: source.E,
		},
		D:      cloneExternalCMDBBigInt(source.D),
		Primes: make([]*big.Int, len(source.Primes)),
	}
	for index := range source.Primes {
		if source.Primes[index] == nil {
			clearExternalCMDBPrivateKey(cloned)
			return nil, false
		}
		cloned.Primes[index] = cloneExternalCMDBBigInt(
			source.Primes[index],
		)
	}
	if err := cloned.Validate(); err != nil {
		clearExternalCMDBPrivateKey(cloned)
		return nil, false
	}
	return cloned, true
}

func cloneExternalCMDBECDSAPrivateKey(
	source *ecdsa.PrivateKey,
) (*ecdsa.PrivateKey, bool) {
	if source == nil || source.Curve == nil || source.X == nil ||
		source.Y == nil || source.D == nil ||
		!standardExternalCMDBCurve(source.Curve) {
		return nil, false
	}
	params := source.Curve.Params()
	if params == nil || params.N == nil || source.D.Sign() <= 0 ||
		source.D.Cmp(params.N) >= 0 ||
		!source.Curve.IsOnCurve(source.X, source.Y) {
		return nil, false
	}
	expectedX, expectedY := source.Curve.ScalarBaseMult(source.D.Bytes())
	if expectedX == nil || expectedY == nil ||
		expectedX.Cmp(source.X) != 0 ||
		expectedY.Cmp(source.Y) != 0 {
		return nil, false
	}
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: source.Curve,
			X:     cloneExternalCMDBBigInt(source.X),
			Y:     cloneExternalCMDBBigInt(source.Y),
		},
		D: cloneExternalCMDBBigInt(source.D),
	}, true
}

func cloneExternalCMDBEd25519PrivateKey(
	source ed25519.PrivateKey,
) (ed25519.PrivateKey, bool) {
	if len(source) != ed25519.PrivateKeySize {
		return nil, false
	}
	seed := source.Seed()
	cloned := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	if !bytes.Equal(source, cloned) {
		clear(cloned)
		return nil, false
	}
	return cloned, true
}

func cloneExternalCMDBBigInt(source *big.Int) *big.Int {
	if source == nil {
		return nil
	}
	return new(big.Int).Set(source)
}

func standardExternalCMDBCurve(curve elliptic.Curve) bool {
	switch curve {
	case elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521():
		return true
	default:
		return false
	}
}

func safeExternalCMDBTLSConfig(config *tls.Config) bool {
	return config != nil &&
		config.Rand == nil &&
		config.Time == nil &&
		config.NameToCertificate == nil &&
		config.GetCertificate == nil &&
		config.GetClientCertificate == nil &&
		config.GetConfigForClient == nil &&
		config.VerifyPeerCertificate == nil &&
		config.VerifyConnection == nil &&
		config.ClientSessionCache == nil &&
		config.UnwrapSession == nil &&
		config.WrapSession == nil &&
		config.KeyLogWriter == nil &&
		config.EncryptedClientHelloRejectionVerify == nil &&
		config.GetEncryptedClientHelloKeys == nil &&
		len(config.EncryptedClientHelloKeys) == 0
}

func clearExternalCMDBRuntimeMaterial(
	material *externalcmdb.RuntimeMaterial,
) {
	if material == nil {
		return
	}
	clearExternalCMDBTLSConfigSecrets(material.TLSConfig)
	material.Clear()
}

func clearExternalCMDBTLSConfigSecrets(config *tls.Config) {
	if config == nil {
		return
	}
	for index := range config.Certificates {
		clearExternalCMDBTLSCertificate(&config.Certificates[index])
	}
	config.Certificates = nil
	config.KeyLogWriter = nil
	config.GetCertificate = nil
	config.GetClientCertificate = nil
	config.GetConfigForClient = nil
	config.VerifyPeerCertificate = nil
	config.VerifyConnection = nil
	config.ClientSessionCache = nil
	config.UnwrapSession = nil
	config.WrapSession = nil
	config.EncryptedClientHelloRejectionVerify = nil
	config.GetEncryptedClientHelloKeys = nil
	for index := range config.EncryptedClientHelloKeys {
		clear(config.EncryptedClientHelloKeys[index].Config)
		clear(config.EncryptedClientHelloKeys[index].PrivateKey)
	}
	config.EncryptedClientHelloKeys = nil
}

func clearExternalCMDBTLSCertificate(certificate *tls.Certificate) {
	if certificate == nil {
		return
	}
	clearExternalCMDBPrivateKey(certificate.PrivateKey)
	for index := range certificate.Certificate {
		clear(certificate.Certificate[index])
	}
	clear(certificate.OCSPStaple)
	for index := range certificate.SignedCertificateTimestamps {
		clear(certificate.SignedCertificateTimestamps[index])
	}
	*certificate = tls.Certificate{}
}

func clearExternalCMDBPrivateKey(privateKey crypto.PrivateKey) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		if key == nil {
			return
		}
		clearExternalCMDBBigInt(key.D)
		for _, prime := range key.Primes {
			clearExternalCMDBBigInt(prime)
		}
		clearExternalCMDBBigInt(key.Precomputed.Dp)
		clearExternalCMDBBigInt(key.Precomputed.Dq)
		clearExternalCMDBBigInt(key.Precomputed.Qinv)
		for index := range key.Precomputed.CRTValues {
			value := &key.Precomputed.CRTValues[index]
			clearExternalCMDBBigInt(value.Exp)
			clearExternalCMDBBigInt(value.Coeff)
			clearExternalCMDBBigInt(value.R)
		}
		*key = rsa.PrivateKey{}
	case *ecdsa.PrivateKey:
		if key == nil {
			return
		}
		clearExternalCMDBBigInt(key.D)
		*key = ecdsa.PrivateKey{}
	case ed25519.PrivateKey:
		clear(key)
	case *ed25519.PrivateKey:
		if key != nil {
			clear(*key)
			*key = nil
		}
	}
}

func clearExternalCMDBBigInt(value *big.Int) {
	if value == nil {
		return
	}
	words := value.Bits()
	clear(words)
	value.SetInt64(0)
}

func (material *ExternalCMDBRuntimeMaterial) bind(
	binding discoverysource.RuntimeBinding,
	snapshot externalCMDBAttemptSnapshot,
) (discoverysource.BoundRuntime, error) {
	if !material.authentic() || !snapshot.validMustMatch(binding) {
		return discoverysource.BoundRuntime{}, ErrExternalCMDBRuntimeAuthority
	}
	private := material.state
	private.mu.Lock()
	defer private.mu.Unlock()
	if private.destroyed || private.bound || private.issued != material ||
		!validExternalCMDBMaterial(private.material) ||
		private.material.EnvironmentID != snapshot.environmentID {
		return discoverysource.BoundRuntime{}, ErrExternalCMDBRuntimeAuthority
	}
	private.bound = true
	bound, err := discoverysource.BindRuntime(
		binding,
		private.material,
		func(*externalcmdb.RuntimeMaterial) error {
			err := revokeExternalCMDBMaterial(nil, material)
			material.destroy(true)
			return err
		},
		func(value *externalcmdb.RuntimeMaterial) {
			clearExternalCMDBRuntimeMaterial(value)
		},
	)
	if err != nil {
		private.bound = false
		return discoverysource.BoundRuntime{}, ErrExternalCMDBRuntimeAuthority
	}
	private.runtime = bound
	return bound, nil
}

func (material *ExternalCMDBRuntimeMaterial) installRelease(
	release func(),
) error {
	if release == nil || !material.authentic() {
		return ErrExternalCMDBRuntimeAuthority
	}
	private := material.state
	private.mu.Lock()
	defer private.mu.Unlock()
	if private.destroying || private.destroyed || private.release != nil ||
		private.issued != material || !private.bound {
		return ErrExternalCMDBRuntimeAuthority
	}
	private.release = release
	return nil
}

func (snapshot externalCMDBAttemptSnapshot) validMustMatch(
	binding discoverysource.RuntimeBinding,
) bool {
	return snapshot.binding == binding &&
		snapshot.key.valid() &&
		snapshot.initialAllowed
}

func (material *ExternalCMDBRuntimeMaterial) Revoke(ctx context.Context) error {
	if ctx == nil || !material.authentic() {
		return ErrExternalCMDBRuntimeAuthority
	}
	revokeContext, cancel := context.WithTimeout(
		ctx,
		externalCMDBCleanupTimeout,
	)
	defer cancel()
	for {
		private := material.state
		private.mu.Lock()
		if private.revoked {
			err := private.revokeErr
			private.mu.Unlock()
			return err
		}
		if private.destroying || private.destroyed {
			private.mu.Unlock()
			return ErrExternalCMDBRuntimeAuthority
		}
		if private.revoking {
			done := private.revokeDone
			private.mu.Unlock()
			select {
			case <-revokeContext.Done():
				return revokeContext.Err()
			case <-done:
			}
			continue
		}
		if err := revokeContext.Err(); err != nil {
			private.mu.Unlock()
			return err
		}
		private.revoking = true
		private.revokeDone = make(chan struct{})
		revoke := private.revoke
		private.mu.Unlock()

		err := revoke(revokeContext)
		private.mu.Lock()
		private.revoking = false
		private.revoked = true
		private.revokeErr = err
		close(private.revokeDone)
		private.mu.Unlock()
		return err
	}
}

func revokeExternalCMDBMaterial(
	parent context.Context,
	material *ExternalCMDBRuntimeMaterial,
) error {
	if material == nil {
		return ErrExternalCMDBRuntimeAuthority
	}
	cleanupContext, cancel := newExternalCMDBCleanupContext(parent)
	defer cancel()
	return material.Revoke(cleanupContext)
}

func newExternalCMDBCleanupContext(
	parent context.Context,
) (context.Context, context.CancelFunc) {
	base := context.Background()
	timeout := externalCMDBCleanupTimeout
	if parent != nil {
		base = context.WithoutCancel(parent)
		if deadline, ok := parent.Deadline(); ok &&
			parent.Err() == nil {
			remaining := time.Until(deadline)
			if remaining > 0 && remaining < timeout {
				timeout = remaining
			}
		}
	}
	return context.WithTimeout(base, timeout)
}

func (material *ExternalCMDBRuntimeMaterial) Destroy() {
	material.destroy(false)
}

func (material *ExternalCMDBRuntimeMaterial) destroy(runtimeLocked bool) {
	if !material.authentic() {
		return
	}
	private := material.state
	for {
		private.mu.Lock()
		if private.destroying {
			done := private.destroyDone
			private.mu.Unlock()
			if runtimeLocked {
				return
			}
			<-done
			return
		}
		if private.destroyed {
			private.mu.Unlock()
			return
		}
		if private.revoking {
			done := private.revokeDone
			private.mu.Unlock()
			<-done
			continue
		}
		private.destroying = true
		runtime := private.runtime
		private.mu.Unlock()
		if !runtimeLocked {
			runtime.Clear()
		}

		private.mu.Lock()
		private.destroyed = true
		owned := private.material
		destroy := private.destroy
		release := private.release
		private.material = nil
		private.runtime = discoverysource.BoundRuntime{}
		private.revoke = nil
		private.destroy = nil
		private.release = nil
		private.issued = nil
		private.bound = false
		private.mu.Unlock()
		if owned != nil {
			clearExternalCMDBRuntimeMaterial(owned)
		}
		func() {
			defer func() {
				_ = recover()
			}()
			destroy()
		}()
		if release != nil {
			release()
		}
		close(private.destroyDone)
		private.mu.Lock()
		private.destroying = false
		private.mu.Unlock()
		return
	}
}

func (material *ExternalCMDBRuntimeMaterial) authentic() bool {
	return material != nil && material.self == material &&
		material.seal == externalCMDBMaterialSeal && material.state != nil
}

func validExternalCMDBMaterial(material *externalcmdb.RuntimeMaterial) bool {
	if material == nil || !safeExternalCMDBTLSConfig(material.TLSConfig) ||
		material.TLSConfig.InsecureSkipVerify ||
		material.TLSConfig.MinVersion < tls.VersionTLS13 ||
		material.TLSConfig.MaxVersion != 0 &&
			material.TLSConfig.MaxVersion < tls.VersionTLS13 ||
		!canonicalUUID(material.EnvironmentID) ||
		!safeAuthorityID(material.ExpectedAuthorityID) {
		return false
	}
	parsed, err := url.Parse(material.BaseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.RawPath != "" || parsed.Path != "" && parsed.Path != "/" {
		return false
	}
	return validRuntimeToken(material.BearerToken) ||
		hasRuntimeClientCertificate(material.TLSConfig)
}

func validRuntimeToken(token []byte) bool {
	if len(token) == 0 || len(token) > 8<<10 {
		return false
	}
	for _, character := range token {
		if character <= 0x20 || character >= 0x7f {
			return false
		}
	}
	return true
}

func hasRuntimeClientCertificate(config *tls.Config) bool {
	if config == nil {
		return false
	}
	for _, certificate := range config.Certificates {
		if len(certificate.Certificate) > 0 && certificate.PrivateKey != nil {
			return true
		}
	}
	return false
}

func safeAuthorityID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune("._:-", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func runtimeBindingValid(binding discoverysource.RuntimeBinding) bool {
	return binding.Locator.Scope.Valid() &&
		canonicalUUID(binding.Locator.SourceID) &&
		binding.SourceRevision > 0 &&
		validDigest(binding.SourceRevisionDigest) &&
		(binding.RevisionStatus == assetcatalog.SourceRevisionValidating ||
			binding.RevisionStatus == assetcatalog.SourceRevisionPublished) &&
		binding.ProviderKind == sourceprofile.ExternalCMDBV1().ProviderKind() &&
		binding.ProfileCode == sourceprofile.ExternalCMDBV1().ProfileCode()
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}

func validDigest(value string) bool {
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

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func boundedRuntimeAuthorityError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return ErrExternalCMDBRuntimeAuthority
	}
}

func (ExternalCMDBAuthority) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*ExternalCMDBAuthority) UnmarshalJSON([]byte) error {
	return ErrSensitiveSerialization
}
func (ExternalCMDBAuthority) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*ExternalCMDBAuthority) UnmarshalText([]byte) error {
	return ErrSensitiveSerialization
}
func (ExternalCMDBAuthority) MarshalBinary() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*ExternalCMDBAuthority) UnmarshalBinary([]byte) error {
	return ErrSensitiveSerialization
}
func (ExternalCMDBAuthority) String() string   { return externalCMDBAuthorityRedaction }
func (ExternalCMDBAuthority) GoString() string { return externalCMDBAuthorityRedaction }
func (ExternalCMDBAuthority) LogValue() slog.Value {
	return slog.StringValue(externalCMDBAuthorityRedaction)
}
func (ExternalCMDBAuthority) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, externalCMDBAuthorityRedaction)
}

func (ExternalCMDBMaterialRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*ExternalCMDBMaterialRequest) UnmarshalJSON([]byte) error {
	return ErrSensitiveSerialization
}
func (ExternalCMDBMaterialRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*ExternalCMDBMaterialRequest) UnmarshalText([]byte) error {
	return ErrSensitiveSerialization
}
func (ExternalCMDBMaterialRequest) MarshalBinary() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*ExternalCMDBMaterialRequest) UnmarshalBinary([]byte) error {
	return ErrSensitiveSerialization
}
func (ExternalCMDBMaterialRequest) String() string   { return externalCMDBRequestRedaction }
func (ExternalCMDBMaterialRequest) GoString() string { return externalCMDBRequestRedaction }
func (ExternalCMDBMaterialRequest) LogValue() slog.Value {
	return slog.StringValue(externalCMDBRequestRedaction)
}
func (ExternalCMDBMaterialRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, externalCMDBRequestRedaction)
}

func (ExternalCMDBRuntimeMaterial) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*ExternalCMDBRuntimeMaterial) UnmarshalJSON([]byte) error {
	return ErrSensitiveSerialization
}
func (ExternalCMDBRuntimeMaterial) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*ExternalCMDBRuntimeMaterial) UnmarshalText([]byte) error {
	return ErrSensitiveSerialization
}
func (ExternalCMDBRuntimeMaterial) MarshalBinary() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*ExternalCMDBRuntimeMaterial) UnmarshalBinary([]byte) error {
	return ErrSensitiveSerialization
}
func (ExternalCMDBRuntimeMaterial) String() string   { return externalCMDBMaterialRedaction }
func (ExternalCMDBRuntimeMaterial) GoString() string { return externalCMDBMaterialRedaction }
func (ExternalCMDBRuntimeMaterial) LogValue() slog.Value {
	return slog.StringValue(externalCMDBMaterialRedaction)
}
func (ExternalCMDBRuntimeMaterial) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, externalCMDBMaterialRedaction)
}

var (
	_ discoveryworker.AttemptRuntimeFactory   = (*ExternalCMDBAuthority)(nil)
	_ discoveryworker.InitialRuntimeLifecycle = (*ExternalCMDBRuntimeMaterial)(nil)
)
