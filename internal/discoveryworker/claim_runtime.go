package discoveryworker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"sync"

	"github.com/google/uuid"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverycheckpoint"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/seaworld008/aiops-system/internal/domain"
)

const (
	resolveRequestRedaction = "[REDACTED_CLAIM_RUNTIME_REQUEST]"
	claimRuntimeRedaction   = "[REDACTED_CLAIM_RUNTIME]"
)

var (
	ErrClaimRuntimeBinding    = errors.New("discovery worker claim runtime binding rejected")
	ErrSensitiveSerialization = errors.New(
		"discovery worker process value is not serializable",
	)
)

// ClaimRuntimeResolver assembles only the Provider, checkpoint, limits, and
// fact policy after CleanupBroker has bound the exact Queue-owned attempt
// represented by request. The Broker-bound runtime is hidden in request and
// cannot be supplied or replaced by the resolver.
type ClaimRuntimeResolver interface {
	ResolveOpenedAttempt(context.Context, ResolveOpenedAttemptRequest) (ClaimRuntime, error)
}

// ResolveOpenedAttemptRequest is a process-local capability. It binds the
// Broker acknowledgement and runtime, Queue coordinates, attempt, immutable
// runtime binding, and data-run checkpoint codec in one non-serializable cell.
type ResolveOpenedAttemptRequest struct {
	cell *openedAttemptCell
}

type openedAttemptCell struct {
	session           *discoverycleanup.AttemptSession
	coordinates       discoveryqueue.RunCoordinates
	attempt           discoveryqueue.CleanupAttempt
	binding           discoverysource.RuntimeBinding
	runtime           discoverysource.BoundRuntime
	runKind           assetcatalog.RunKind
	checkpointVersion int64
	checkpointSHA256  string
	checkpoints       *discoverycheckpoint.CheckpointCodec
}

func newResolveOpenedAttemptRequest(
	session *discoverycleanup.AttemptSession,
	coordinates discoveryqueue.RunCoordinates,
	attempt discoveryqueue.CleanupAttempt,
	binding discoverysource.RuntimeBinding,
	runtime discoverysource.BoundRuntime,
	runKind assetcatalog.RunKind,
	checkpointVersion int64,
	checkpointSHA256 string,
	checkpoints *discoverycheckpoint.CheckpointCodec,
) (ResolveOpenedAttemptRequest, error) {
	request := ResolveOpenedAttemptRequest{cell: &openedAttemptCell{
		session: session, coordinates: coordinates, attempt: attempt, binding: binding,
		runtime: runtime,
		runKind: runKind, checkpointVersion: checkpointVersion,
		checkpointSHA256: checkpointSHA256, checkpoints: checkpoints,
	}}
	if err := request.validate(); err != nil {
		return ResolveOpenedAttemptRequest{}, err
	}
	return request, nil
}

func (request ResolveOpenedAttemptRequest) validate() error {
	if request.cell == nil || request.cell.session == nil ||
		!request.cell.coordinates.Valid() || !request.cell.attempt.Valid() ||
		request.cell.attempt.RunID != request.cell.coordinates.RunID ||
		!validRuntimeBinding(request.cell.binding) ||
		request.cell.binding.Locator.Scope != request.cell.coordinates.Scope ||
		request.cell.runtime.Binding() != request.cell.binding {
		return ErrClaimRuntimeBinding
	}
	opened, err := request.cell.session.Attempt()
	if err != nil || opened != request.cell.attempt {
		return ErrClaimRuntimeBinding
	}
	switch request.cell.runKind {
	case assetcatalog.RunKindValidation:
		if request.cell.binding.RevisionStatus != assetcatalog.SourceRevisionValidating ||
			request.cell.checkpointVersion != 0 || request.cell.checkpointSHA256 != "" ||
			request.cell.checkpoints != nil {
			return ErrClaimRuntimeBinding
		}
	case assetcatalog.RunKindDiscovery, assetcatalog.RunKindCSVImport, assetcatalog.RunKindAPIIngestion:
		if request.cell.binding.RevisionStatus != assetcatalog.SourceRevisionPublished ||
			request.cell.checkpointVersion < 0 || request.cell.checkpoints == nil ||
			(request.cell.checkpointVersion == 0 && request.cell.checkpointSHA256 != "") ||
			(request.cell.checkpointVersion > 0 && !domain.ValidSHA256Hex(request.cell.checkpointSHA256)) {
			return ErrClaimRuntimeBinding
		}
	default:
		return ErrClaimRuntimeBinding
	}
	return nil
}

func (request ResolveOpenedAttemptRequest) Session() *discoverycleanup.AttemptSession {
	if request.cell == nil {
		return nil
	}
	return request.cell.session
}

func (request ResolveOpenedAttemptRequest) Coordinates() discoveryqueue.RunCoordinates {
	if request.cell == nil {
		return discoveryqueue.RunCoordinates{}
	}
	return request.cell.coordinates
}

func (request ResolveOpenedAttemptRequest) Attempt() discoveryqueue.CleanupAttempt {
	if request.cell == nil {
		return discoveryqueue.CleanupAttempt{}
	}
	return request.cell.attempt
}

func (request ResolveOpenedAttemptRequest) RuntimeBinding() discoverysource.RuntimeBinding {
	if request.cell == nil {
		return discoverysource.RuntimeBinding{}
	}
	return request.cell.binding
}

func (request ResolveOpenedAttemptRequest) RunKind() assetcatalog.RunKind {
	if request.cell == nil {
		return ""
	}
	return request.cell.runKind
}

func (request ResolveOpenedAttemptRequest) CheckpointVersion() int64 {
	if request.cell == nil {
		return 0
	}
	return request.cell.checkpointVersion
}

func (request ResolveOpenedAttemptRequest) CheckpointSHA256() string {
	if request.cell == nil {
		return ""
	}
	return request.cell.checkpointSHA256
}

func (request ResolveOpenedAttemptRequest) CheckpointCodec() *discoverycheckpoint.CheckpointCodec {
	if request.cell == nil {
		return nil
	}
	return request.cell.checkpoints
}

func (ResolveOpenedAttemptRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*ResolveOpenedAttemptRequest) UnmarshalJSON([]byte) error {
	return ErrSensitiveSerialization
}
func (ResolveOpenedAttemptRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*ResolveOpenedAttemptRequest) UnmarshalText([]byte) error {
	return ErrSensitiveSerialization
}
func (ResolveOpenedAttemptRequest) MarshalBinary() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*ResolveOpenedAttemptRequest) UnmarshalBinary([]byte) error {
	return ErrSensitiveSerialization
}
func (ResolveOpenedAttemptRequest) String() string   { return resolveRequestRedaction }
func (ResolveOpenedAttemptRequest) GoString() string { return resolveRequestRedaction }
func (ResolveOpenedAttemptRequest) LogValue() slog.Value {
	return slog.StringValue(resolveRequestRedaction)
}
func (ResolveOpenedAttemptRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, resolveRequestRedaction)
}

// ClaimRuntime is the opaque, attempt-bound Provider view returned to Worker
// core. All fields remain unexported and share one destruction state.
type ClaimRuntime struct {
	state *claimRuntimeState
}

type claimRuntimeState struct {
	mu         sync.Mutex
	cell       *openedAttemptCell
	provider   discoverysource.Provider
	runtime    discoverysource.BoundRuntime
	checkpoint discoverysource.Checkpoint
	limits     discoverysource.Limits
	policy     assetdiscovery.FactPolicy
	active     bool
}

func newClaimRuntime(
	request ResolveOpenedAttemptRequest,
	provider discoverysource.Provider,
	checkpoint *discoverysource.Checkpoint,
	limits discoverysource.Limits,
	policy assetdiscovery.FactPolicy,
) (ClaimRuntime, error) {
	fail := func() (ClaimRuntime, error) {
		if request.cell != nil {
			request.cell.runtime.Clear()
		}
		if checkpoint != nil {
			checkpoint.Clear()
		}
		return ClaimRuntime{}, ErrClaimRuntimeBinding
	}
	if request.validate() != nil || nilDependency(provider) || checkpoint == nil ||
		provider.ProviderKind() != request.cell.binding.ProviderKind ||
		!provider.Kind().Valid() || provider.Kind() == assetcatalog.SourceKindManual ||
		checkpoint.ProfileCode() != request.cell.binding.ProfileCode ||
		policy.ProviderKind != request.cell.binding.ProviderKind ||
		assetdiscovery.ValidateFacts(nil, nil, policy) != nil {
		return fail()
	}
	if (request.cell.runKind == assetcatalog.RunKindValidation ||
		request.cell.checkpointVersion == 0) && !checkpoint.IsEmpty() {
		return fail()
	}
	if err := validateRuntimeLimits(request, *checkpoint, limits); err != nil {
		return fail()
	}
	ownedCheckpoint := checkpoint.Clone()
	checkpoint.Clear()
	if ownedCheckpoint.ProfileCode() == "" {
		return fail()
	}
	return ClaimRuntime{state: &claimRuntimeState{
		cell: request.cell, provider: provider, runtime: request.cell.runtime,
		checkpoint: ownedCheckpoint, limits: limits, policy: policy.Clone(), active: true,
	}}, nil
}

func (runtime ClaimRuntime) validate(request ResolveOpenedAttemptRequest) error {
	if request.validate() != nil || runtime.state == nil {
		return ErrClaimRuntimeBinding
	}
	runtime.state.mu.Lock()
	defer runtime.state.mu.Unlock()
	if !runtime.state.active || runtime.state.cell != request.cell ||
		runtime.state.runtime != request.cell.runtime ||
		runtime.state.runtime.Binding() != request.cell.binding ||
		nilDependency(runtime.state.provider) ||
		runtime.state.provider.ProviderKind() != request.cell.binding.ProviderKind ||
		runtime.state.checkpoint.ProfileCode() != request.cell.binding.ProfileCode {
		return ErrClaimRuntimeBinding
	}
	if (request.cell.runKind == assetcatalog.RunKindValidation ||
		request.cell.checkpointVersion == 0) && !runtime.state.checkpoint.IsEmpty() {
		return ErrClaimRuntimeBinding
	}
	return nil
}

func (runtime ClaimRuntime) view(
	request ResolveOpenedAttemptRequest,
) (
	discoverysource.Provider,
	discoverysource.BoundRuntime,
	discoverysource.Checkpoint,
	discoverysource.Limits,
	assetdiscovery.FactPolicy,
	error,
) {
	if err := runtime.validate(request); err != nil {
		return nil, discoverysource.BoundRuntime{}, discoverysource.Checkpoint{},
			discoverysource.Limits{}, assetdiscovery.FactPolicy{}, err
	}
	runtime.state.mu.Lock()
	defer runtime.state.mu.Unlock()
	return runtime.state.provider, runtime.state.runtime, runtime.state.checkpoint.Clone(),
		runtime.state.limits, runtime.state.policy.Clone(), nil
}

func (runtime *ClaimRuntime) destroy() {
	if runtime == nil || runtime.state == nil {
		return
	}
	private := runtime.state
	private.mu.Lock()
	if !private.active {
		private.mu.Unlock()
		runtime.state = nil
		return
	}
	private.active = false
	bound := private.runtime
	checkpoint := private.checkpoint
	private.provider = nil
	private.runtime = discoverysource.BoundRuntime{}
	private.checkpoint = discoverysource.Checkpoint{}
	private.policy = assetdiscovery.FactPolicy{}
	private.cell = nil
	private.mu.Unlock()

	bound.Clear()
	checkpoint.Clear()
	runtime.state = nil
}

func (ClaimRuntime) MarshalJSON() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (*ClaimRuntime) UnmarshalJSON([]byte) error    { return ErrSensitiveSerialization }
func (ClaimRuntime) MarshalText() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (*ClaimRuntime) UnmarshalText([]byte) error    { return ErrSensitiveSerialization }
func (ClaimRuntime) MarshalBinary() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (*ClaimRuntime) UnmarshalBinary([]byte) error  { return ErrSensitiveSerialization }
func (ClaimRuntime) String() string                 { return claimRuntimeRedaction }
func (ClaimRuntime) GoString() string               { return claimRuntimeRedaction }
func (ClaimRuntime) LogValue() slog.Value           { return slog.StringValue(claimRuntimeRedaction) }
func (ClaimRuntime) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, claimRuntimeRedaction)
}

func validateRuntimeLimits(
	request ResolveOpenedAttemptRequest,
	checkpoint discoverysource.Checkpoint,
	limits discoverysource.Limits,
) error {
	if request.cell.runKind == assetcatalog.RunKindValidation {
		return (discoverysource.ValidationRequest{
			Locator: request.cell.binding.Locator, SourceRevision: request.cell.binding.SourceRevision,
			SourceRevisionDigest: request.cell.binding.SourceRevisionDigest, Limits: limits,
		}).Validate()
	}
	return (discoverysource.DiscoverRequest{
		Locator: request.cell.binding.Locator, SourceRevision: request.cell.binding.SourceRevision,
		SourceRevisionDigest: request.cell.binding.SourceRevisionDigest,
		Checkpoint:           checkpoint, Limits: limits,
	}).Validate()
}

func validRuntimeBinding(binding discoverysource.RuntimeBinding) bool {
	parsed, err := uuid.Parse(binding.Locator.SourceID)
	return err == nil && parsed.String() == binding.Locator.SourceID &&
		binding.Locator.Scope.Valid() && binding.SourceRevision > 0 &&
		domain.ValidSHA256Hex(binding.SourceRevisionDigest) &&
		binding.ProviderKind != "" && binding.ProfileCode.Valid() &&
		(binding.RevisionStatus == assetcatalog.SourceRevisionValidating ||
			binding.RevisionStatus == assetcatalog.SourceRevisionPublished)
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
