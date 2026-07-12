package readruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync/atomic"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/readexecutor"
	"github.com/seaworld008/aiops-system/internal/readtarget"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

const BundleSchemaVersion = "read-runtime-bundle.v1"

var ErrBundleRejected = errors.New("READ runtime bundle rejected")

type bundleSeal struct{ value byte }
type preparedSeal struct{ value byte }

var (
	trustedBundleSeal   = &bundleSeal{value: 1}
	trustedPreparedSeal = &preparedSeal{value: 1}
)

// Bundle atomically owns the complete immutable READ runtime graph. A caller
// cannot construct a partially wired binder/executor pair or replace one
// registry after startup.
type Bundle struct {
	connectors *readconnector.Registry
	targets    *readtarget.Registry
	egress     *readexecutor.EgressRegistry
	profile    *readexecutor.Profile
	binder     *Binder
	executor   *readexecutor.Executor
	digest     string
	seal       *bundleSeal
	self       *Bundle
}

type preparedState struct{ claimed atomic.Bool }

// Prepared is the Bundle-owned one-shot execution capability. Its inner
// executor capability is deliberately not exposed, so material prepared by a
// different, internally consistent runtime graph cannot be swapped into this
// Bundle at Execute time.
type Prepared struct {
	owner        *Bundle
	bundleDigest string
	inner        *readexecutor.Prepared
	state        *preparedState
	seal         *preparedSeal
	self         *Prepared
}

func (prepared *Prepared) validFor(bundle *Bundle) bool {
	return prepared != nil && prepared.self == prepared && prepared.seal == trustedPreparedSeal &&
		prepared.owner == bundle && prepared.inner != nil && prepared.state != nil && !prepared.state.claimed.Load() &&
		bundle != nil && bundle.self == bundle && bundle.seal == trustedBundleSeal &&
		constantDigestEqual(prepared.bundleDigest, bundle.digest)
}

func (prepared *Prepared) claimFor(bundle *Bundle) (*readexecutor.Prepared, bool) {
	if !prepared.validFor(bundle) || !prepared.state.claimed.CompareAndSwap(false, true) {
		return nil, false
	}
	return prepared.inner, true
}

func (Prepared) String() string   { return "<aiops-prepared-read-runtime>" }
func (Prepared) GoString() string { return "<aiops-prepared-read-runtime>" }
func (Prepared) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-prepared-read-runtime>")
}
func (Prepared) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Prepared) UnmarshalJSON([]byte) error  { return ErrBundleRejected }

// Summary contains digests only. It intentionally excludes scope, target,
// endpoint, policy, query, and credential material.
type Summary struct {
	SchemaVersion           string `json:"schema_version"`
	BundleDigest            string `json:"bundle_digest"`
	ConnectorRegistryDigest string `json:"connector_registry_digest"`
	TargetRegistryDigest    string `json:"target_registry_digest"`
	EgressRegistryDigest    string `json:"egress_registry_digest"`
	ExecutorProfileDigest   string `json:"executor_profile_digest"`
}

func (summary Summary) Validate() error {
	if summary.SchemaVersion != BundleSchemaVersion || !domain.ValidSHA256Hex(summary.BundleDigest) ||
		!domain.ValidSHA256Hex(summary.ConnectorRegistryDigest) || !domain.ValidSHA256Hex(summary.TargetRegistryDigest) ||
		!domain.ValidSHA256Hex(summary.EgressRegistryDigest) || !domain.ValidSHA256Hex(summary.ExecutorProfileDigest) {
		return ErrBundleRejected
	}
	expected, err := bundleDigest(summary.ConnectorRegistryDigest, summary.TargetRegistryDigest,
		summary.EgressRegistryDigest, summary.ExecutorProfileDigest)
	if err != nil || subtle.ConstantTimeCompare([]byte(expected), []byte(summary.BundleDigest)) != 1 {
		return ErrBundleRejected
	}
	return nil
}

func (*Summary) UnmarshalJSON([]byte) error { return ErrBundleRejected }

func NewBundle(
	connectors *readconnector.Registry,
	targets *readtarget.Registry,
	egress *readexecutor.EgressRegistry,
	profile *readexecutor.Profile,
) (*Bundle, error) {
	if connectors == nil || !connectors.Ready() || targets == nil || !targets.Ready() ||
		egress == nil || !egress.Ready() || profile == nil || !profile.Ready() {
		return nil, ErrBundleRejected
	}
	binder, err := NewBinder(connectors, targets, profile)
	if err != nil || binder == nil || !binder.Ready() {
		return nil, ErrBundleRejected
	}
	executor, err := readexecutor.NewExecutor(profile)
	if err != nil || executor == nil || !executor.Ready() {
		return nil, ErrBundleRejected
	}
	if err := validateDependencyGraph(connectors, targets, egress, profile); err != nil {
		return nil, ErrBundleRejected
	}
	digest, err := bundleDigest(connectors.Digest(), targets.Digest(), egress.Digest(), profile.Digest())
	if err != nil || !domain.ValidSHA256Hex(digest) {
		return nil, ErrBundleRejected
	}
	created := &Bundle{
		connectors: connectors, targets: targets, egress: egress, profile: profile,
		binder: binder, executor: executor, digest: digest, seal: trustedBundleSeal,
	}
	created.self = created
	return created, nil
}

func (bundle *Bundle) Ready() bool {
	if bundle == nil || bundle.self != bundle || bundle.seal != trustedBundleSeal ||
		bundle.connectors == nil || !bundle.connectors.Ready() || bundle.targets == nil || !bundle.targets.Ready() ||
		bundle.egress == nil || !bundle.egress.Ready() || bundle.profile == nil || !bundle.profile.Ready() ||
		bundle.binder == nil || !bundle.binder.Ready() || bundle.executor == nil || !bundle.executor.Ready() ||
		!domain.ValidSHA256Hex(bundle.digest) {
		return false
	}
	expected, err := bundleDigest(bundle.connectors.Digest(), bundle.targets.Digest(), bundle.egress.Digest(), bundle.profile.Digest())
	return err == nil && subtle.ConstantTimeCompare([]byte(expected), []byte(bundle.digest)) == 1
}

func (bundle *Bundle) Digest() string {
	if !bundle.Ready() {
		return ""
	}
	return bundle.digest
}

func (bundle *Bundle) Summary() Summary {
	if !bundle.Ready() {
		return Summary{}
	}
	return Summary{
		SchemaVersion: BundleSchemaVersion, BundleDigest: strings.Clone(bundle.digest),
		ConnectorRegistryDigest: strings.Clone(bundle.connectors.Digest()),
		TargetRegistryDigest:    strings.Clone(bundle.targets.Digest()),
		EgressRegistryDigest:    strings.Clone(bundle.egress.Digest()),
		ExecutorProfileDigest:   strings.Clone(bundle.profile.Digest()),
	}
}

// Bind is the Bundle-owned investigation.TaskRuntimeBinder.
func (bundle *Bundle) Bind(
	ctx context.Context,
	scope investigation.TaskSpecScope,
	plan domain.InvestigationPlanBinding,
	spec investigation.TaskSpec,
) (investigation.TaskRuntimeComponents, error) {
	if !bundle.Ready() {
		return investigation.TaskRuntimeComponents{}, ErrBindingRejected
	}
	return bundle.binder.Bind(ctx, scope, plan, spec)
}

// AuthorizeStart first proves every persisted plan/runtime fence against the
// live immutable bundle, then runs typed connector admission.
func (bundle *Bundle) AuthorizeStart(ctx context.Context, descriptor readtask.Descriptor) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = ErrBundleRejected
		}
	}()
	resolved, err := bundle.resolveDescriptor(ctx, descriptor)
	if err != nil {
		return err
	}
	if err := bundle.connectors.AuthorizeStart(ctx, resolved.descriptor); err != nil {
		return err
	}
	return bundleContextError(ctx)
}

// AuthorizeCompletion performs the same full binding proof before the
// connector applies its typed, bounded evidence validator.
func (bundle *Bundle) AuthorizeCompletion(
	ctx context.Context,
	descriptor readtask.Descriptor,
	evidence readtask.EvidenceCompletion,
) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = ErrBundleRejected
		}
	}()
	resolved, err := bundle.resolveDescriptor(ctx, descriptor)
	if err != nil {
		return err
	}
	if err := bundle.connectors.AuthorizeCompletion(ctx, resolved.descriptor, evidence); err != nil {
		return err
	}
	return bundleContextError(ctx)
}

// Prepare resolves all execution material internally. Callers can supply only
// the persisted descriptor and current authenticated attempt fence numbers.
func (bundle *Bundle) Prepare(
	ctx context.Context,
	descriptor readtask.Descriptor,
	leaseEpoch int64,
	scopeRevision int64,
) (prepared *Prepared, returnedErr error) {
	defer func() {
		if recover() != nil {
			prepared = nil
			returnedErr = ErrBundleRejected
		}
	}()
	resolved, err := bundle.resolveDescriptor(ctx, descriptor)
	if err != nil {
		return nil, err
	}
	if err := bundle.connectors.AuthorizeStart(ctx, resolved.descriptor); err != nil {
		return nil, err
	}
	inner, err := bundle.executor.Prepare(ctx, resolved.descriptor, leaseEpoch, scopeRevision,
		resolved.execution, resolved.target, resolved.policy)
	if err != nil {
		return nil, err
	}
	if inner == nil || !bundle.Ready() {
		return nil, ErrBundleRejected
	}
	created := &Prepared{
		owner: bundle, bundleDigest: strings.Clone(bundle.digest), inner: inner,
		state: &preparedState{}, seal: trustedPreparedSeal,
	}
	created.self = created
	return created, nil
}

// Execute keeps the fixed executor inside the atomically validated Bundle.
func (bundle *Bundle) Execute(
	ctx context.Context,
	prepared *Prepared,
	start *readexecutor.ExecutionStart,
	credentials readexecutor.BearerSource,
) (readexecutor.Result, error) {
	if !bundle.Ready() {
		return readexecutor.Result{}, readexecutor.ErrExecutionRejected
	}
	inner, ok := prepared.claimFor(bundle)
	if !ok {
		return readexecutor.Result{}, readexecutor.ErrExecutionRejected
	}
	return bundle.executor.Execute(ctx, inner, start, credentials)
}

func (Bundle) String() string   { return "<aiops-read-runtime-bundle>" }
func (Bundle) GoString() string { return "<aiops-read-runtime-bundle>" }
func (Bundle) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-read-runtime-bundle>")
}
func (Bundle) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Bundle) UnmarshalJSON([]byte) error  { return ErrBundleRejected }

type descriptorResolution struct {
	descriptor readtask.Descriptor
	execution  readconnector.ExecutionSpec
	target     readtarget.Target
	policy     *readexecutor.EgressPolicy
}

func (bundle *Bundle) resolveDescriptor(
	ctx context.Context,
	descriptor readtask.Descriptor,
) (resolved descriptorResolution, returnedErr error) {
	defer func() {
		if recover() != nil {
			resolved = descriptorResolution{}
			returnedErr = ErrBundleRejected
		}
	}()
	if err := bundleContextError(ctx); err != nil {
		return descriptorResolution{}, err
	}
	descriptor.Input = bytes.Clone(descriptor.Input)
	if !bundle.Ready() || descriptor.Validate() != nil || descriptor.PlanBinding.Validate() != nil ||
		subtle.ConstantTimeCompare([]byte(descriptor.PlanBinding.RegistryDigest), []byte(bundle.connectors.Digest())) != 1 {
		return descriptorResolution{}, readtask.ErrIntegrity
	}
	execution, err := bundle.connectors.ResolveExecution(descriptor)
	if err != nil {
		if errors.Is(err, readtask.ErrClaimsDisabled) {
			return descriptorResolution{}, readtask.ErrClaimsDisabled
		}
		return descriptorResolution{}, readtask.ErrIntegrity
	}
	scope := investigation.TaskSpecScope{
		TenantID: descriptor.TenantID, WorkspaceID: descriptor.WorkspaceID,
		EnvironmentID: descriptor.EnvironmentID, ServiceID: descriptor.ServiceID,
		MappingStatus: domain.MappingExact,
	}
	target, err := bundle.targets.Resolve(ctx, scope, execution.Kind(), execution.TargetRef())
	if err != nil {
		return descriptorResolution{}, descriptorResolutionError(ctx)
	}
	policy, err := bundle.egress.ResolveTarget(readtarget.Scope{
		TenantID: descriptor.TenantID, WorkspaceID: descriptor.WorkspaceID, EnvironmentID: descriptor.EnvironmentID,
	}, target)
	if err != nil {
		return descriptorResolution{}, readtask.ErrIntegrity
	}
	components := investigation.TaskRuntimeComponents{
		ConnectorDigest: execution.ContractDigest(), TargetDigest: target.Digest(), ExecutorDigest: bundle.profile.Digest(),
	}
	if components.Validate() != nil || !bundle.profile.Supports(execution.Kind(), execution.Operation()) ||
		!execution.MatchesDescriptor(descriptor) || target.Kind() != execution.Kind() ||
		!constantDigestEqual(components.ConnectorDigest, descriptor.RuntimeBinding.ConnectorDigest) ||
		!constantDigestEqual(components.TargetDigest, descriptor.RuntimeBinding.TargetDigest) ||
		!constantDigestEqual(components.ExecutorDigest, descriptor.RuntimeBinding.ExecutorDigest) ||
		!referenceDigestMatches(execution.TargetRef(), components.TargetDigest) {
		return descriptorResolution{}, readtask.ErrIntegrity
	}
	spec := investigation.TaskSpec{
		Key: descriptor.TaskKey, ConnectorID: descriptor.ConnectorID,
		Operation: descriptor.Operation, Input: bytes.Clone(descriptor.Input),
	}
	expectedRuntimeDigest, err := investigation.ReadTaskRuntimeDigest(scope, descriptor.PlanBinding, spec, descriptor.Position, components)
	if err != nil || !constantDigestEqual(expectedRuntimeDigest, descriptor.RuntimeBinding.RuntimeDigest) {
		return descriptorResolution{}, readtask.ErrIntegrity
	}
	if err := bundleContextError(ctx); err != nil {
		return descriptorResolution{}, err
	}
	return descriptorResolution{descriptor: descriptor, execution: execution, target: target, policy: policy}, nil
}

func validateDependencyGraph(
	connectors *readconnector.Registry,
	targets *readtarget.Registry,
	egress *readexecutor.EgressRegistry,
	profile *readexecutor.Profile,
) error {
	dependencies, err := connectors.RuntimeDependencies()
	if err != nil || len(dependencies) == 0 {
		return ErrBundleRejected
	}
	for _, dependency := range dependencies {
		sourceScope := dependency.Scope()
		scope := investigation.TaskSpecScope{
			TenantID: sourceScope.TenantID, WorkspaceID: sourceScope.WorkspaceID,
			EnvironmentID: sourceScope.EnvironmentID, ServiceID: sourceScope.ServiceID,
			MappingStatus: domain.MappingExact,
		}
		if !profile.Supports(dependency.Kind(), dependency.Operation()) ||
			!domain.ConnectorDigestMatchesID(dependency.ConnectorID(), dependency.ContractDigest()) {
			return ErrBundleRejected
		}
		target, resolveErr := targets.Resolve(context.Background(), scope, dependency.Kind(), dependency.TargetRef())
		if resolveErr != nil || target.Kind() != dependency.Kind() || target.TargetRef() != dependency.TargetRef() ||
			!referenceDigestMatches(target.TargetRef(), target.Digest()) {
			return ErrBundleRejected
		}
		policy, policyErr := egress.ResolveTarget(readtarget.Scope{
			TenantID: sourceScope.TenantID, WorkspaceID: sourceScope.WorkspaceID,
			EnvironmentID: sourceScope.EnvironmentID,
		}, target)
		if policyErr != nil || policy == nil || !policy.Ready() ||
			!referenceDigestMatches(target.NetworkPolicyRef(), policy.Digest()) {
			return ErrBundleRejected
		}
	}
	return nil
}

func bundleDigest(connectorDigest, targetDigest, egressDigest, profileDigest string) (string, error) {
	for _, digest := range []string{connectorDigest, targetDigest, egressDigest, profileDigest} {
		if !domain.ValidSHA256Hex(digest) {
			return "", ErrBundleRejected
		}
	}
	document := struct {
		SchemaVersion           string `json:"schema_version"`
		ConnectorRegistryDigest string `json:"connector_registry_digest"`
		TargetRegistryDigest    string `json:"target_registry_digest"`
		EgressRegistryDigest    string `json:"egress_registry_digest"`
		ExecutorProfileDigest   string `json:"executor_profile_digest"`
	}{
		SchemaVersion: BundleSchemaVersion, ConnectorRegistryDigest: connectorDigest,
		TargetRegistryDigest: targetDigest, EgressRegistryDigest: egressDigest, ExecutorProfileDigest: profileDigest,
	}
	wire, err := json.Marshal(document)
	if err != nil {
		return "", ErrBundleRejected
	}
	canonical, err := jsoncanonicalizer.Transform(wire)
	if err != nil {
		return "", ErrBundleRejected
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func bundleContextError(ctx context.Context) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = ErrBundleRejected
		}
	}()
	if ctx == nil {
		return ErrBundleRejected
	}
	value := reflect.ValueOf(ctx)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return ErrBundleRejected
		}
	}
	return ctx.Err()
}

func descriptorResolutionError(ctx context.Context) error {
	if err := bundleContextError(ctx); errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return readtask.ErrIntegrity
}

func constantDigestEqual(left, right string) bool {
	return domain.ValidSHA256Hex(left) && domain.ValidSHA256Hex(right) &&
		subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
