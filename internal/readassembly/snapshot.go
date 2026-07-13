// Package readassembly constructs the single immutable READ planning and
// execution snapshot used by production process assembly.
package readassembly

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigationplan"
	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/readexecutor"
	"github.com/seaworld008/aiops-system/internal/readruntime"
	"github.com/seaworld008/aiops-system/internal/readtarget"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

const SnapshotSchemaVersion = "read-assembly-snapshot.v1"

const (
	maximumCapturedManifestBytes = 1 << 20
	maximumCapturedRootBytes     = 256 << 10
	maximumCapturedRootBundles   = 256
	maximumCapturedSourceBytes   = 5 << 20
)

var ErrSnapshotRejected = errors.New("READ assembly snapshot rejected")

// Summary is the reviewed deployment identity for one complete planning and
// execution graph. It carries digests only and grants no runtime capability.
type Summary struct {
	SchemaVersion           string `json:"schema_version"`
	PlanManifestDigest      string `json:"plan_manifest_digest"`
	ConnectorRegistryDigest string `json:"connector_registry_digest"`
	TargetRegistryDigest    string `json:"target_registry_digest"`
	EgressRegistryDigest    string `json:"egress_registry_digest"`
	ExecutorProfileDigest   string `json:"executor_profile_digest"`
	BundleDigest            string `json:"bundle_digest"`
}

func (summary Summary) Validate() error {
	if summary.SchemaVersion != SnapshotSchemaVersion || !domain.ValidSHA256Hex(summary.PlanManifestDigest) ||
		summary.runtimeSummary().Validate() != nil {
		return ErrSnapshotRejected
	}
	return nil
}

func (summary Summary) runtimeSummary() readruntime.Summary {
	return readruntime.Summary{
		SchemaVersion: readruntime.BundleSchemaVersion, BundleDigest: summary.BundleDigest,
		ConnectorRegistryDigest: summary.ConnectorRegistryDigest,
		TargetRegistryDigest:    summary.TargetRegistryDigest,
		EgressRegistryDigest:    summary.EgressRegistryDigest,
		ExecutorProfileDigest:   summary.ExecutorProfileDigest,
	}
}

func (*Summary) UnmarshalJSON([]byte) error { return ErrSnapshotRejected }

// FileOptions pins every process-owned manifest to the complete reviewed
// Summary. There is no unpinned discovery or partial-manifest mode.
type FileOptions struct {
	ConnectorManifestFile string
	PlanManifestFile      string
	TargetManifestFile    string
	EgressManifestFile    string
	Expected              Summary
}

// CapturedRootBundle is one content-addressed target trust bundle captured in
// the same reviewed source as the manifests. It is borrowed only for the
// duration of LoadCanonicalManifests and is never retained by Snapshot.
// Production callers are restricted by an architecture gate.
type CapturedRootBundle struct {
	Path     string
	Contents []byte
}

type snapshotSeal struct{ value byte }

var trustedSnapshotSeal = &snapshotSeal{value: 1}

// Snapshot privately owns the only ScopeAuthority, Planner, connector
// registry, and Bundle in one immutable graph. Narrow facade methods prevent
// process assembly from mixing raw components from different snapshots.
type Snapshot struct {
	connectors *readconnector.Registry
	authority  *investigationplan.ScopeAuthority
	planner    *investigationplan.Planner
	bundle     *readruntime.Bundle
	summary    Summary
	seal       *snapshotSeal
	self       *Snapshot
}

// LoadFiles publishes a Snapshot only after every file, dependency edge, and
// reviewed digest has been verified. Each file is a stable securemanifest
// snapshot; the complete expected Summary turns a mixed rollout read into an
// exact semantic match or a startup rejection.
func LoadFiles(ctx context.Context, options FileOptions) (snapshot *Snapshot, returnedErr error) {
	if err := snapshotContextError(ctx); err != nil {
		return nil, err
	}
	if !validManifestPaths(options) {
		return nil, ErrSnapshotRejected
	}
	return loadSnapshot(ctx, options.Expected, snapshotLoaders{
		connectors: func() (*readconnector.Registry, error) {
			return readconnector.LoadFile(options.ConnectorManifestFile)
		},
		planner: func(
			ctx context.Context,
			authority *investigationplan.ScopeAuthority,
			connectors *readconnector.Registry,
		) (*investigationplan.Planner, error) {
			return investigationplan.LoadFile(ctx, authority, options.PlanManifestFile, connectors)
		},
		targets: func() (*readtarget.Registry, error) {
			return readtarget.LoadFile(options.TargetManifestFile)
		},
		egress: func() (*readexecutor.EgressRegistry, error) {
			return readexecutor.LoadEgressRegistryFile(options.EgressManifestFile)
		},
	})
}

// LoadCanonicalManifests constructs a semantic Snapshot exclusively from
// manifest and target-root bytes already captured by one reviewed source. The
// slices are borrowed, never mutated or retained, and there is no filesystem
// fallback. Its only production caller is locked to workerbootstrap.
func LoadCanonicalManifests(
	ctx context.Context,
	connectorManifest []byte,
	planManifest []byte,
	targetManifest []byte,
	egressManifest []byte,
	targetRoots []CapturedRootBundle,
	expected Summary,
) (*Snapshot, error) {
	if err := snapshotContextError(ctx); err != nil {
		return nil, err
	}
	if !validCanonicalManifestSet(
		connectorManifest, planManifest, targetManifest, egressManifest, targetRoots,
	) {
		return nil, ErrSnapshotRejected
	}
	roots := make([]readtarget.CapturedRootBundle, len(targetRoots))
	for index := range targetRoots {
		roots[index] = readtarget.CapturedRootBundle{
			Path: targetRoots[index].Path, Contents: targetRoots[index].Contents,
		}
	}
	return loadSnapshot(ctx, expected, snapshotLoaders{
		connectors: func() (*readconnector.Registry, error) {
			return readconnector.CompileManifest(connectorManifest)
		},
		planner: func(
			ctx context.Context,
			authority *investigationplan.ScopeAuthority,
			connectors *readconnector.Registry,
		) (*investigationplan.Planner, error) {
			return investigationplan.CompileManifest(ctx, authority, planManifest, connectors)
		},
		targets: func() (*readtarget.Registry, error) {
			return readtarget.CompileCapturedManifest(targetManifest, roots)
		},
		egress: func() (*readexecutor.EgressRegistry, error) {
			return readexecutor.CompileEgressManifest(egressManifest)
		},
	})
}

func validCanonicalManifestSet(
	connectorManifest []byte,
	planManifest []byte,
	targetManifest []byte,
	egressManifest []byte,
	targetRoots []CapturedRootBundle,
) bool {
	total := 0
	for _, manifest := range [][]byte{connectorManifest, planManifest, targetManifest, egressManifest} {
		if len(manifest) == 0 || len(manifest) > maximumCapturedManifestBytes ||
			total > maximumCapturedSourceBytes-len(manifest) {
			return false
		}
		total += len(manifest)
	}
	if len(targetRoots) == 0 || len(targetRoots) > maximumCapturedRootBundles {
		return false
	}
	for _, root := range targetRoots {
		if len(root.Contents) == 0 || len(root.Contents) > maximumCapturedRootBytes ||
			total > maximumCapturedSourceBytes-len(root.Contents) {
			return false
		}
		total += len(root.Contents)
	}
	return true
}

type snapshotLoaders struct {
	connectors func() (*readconnector.Registry, error)
	planner    func(context.Context, *investigationplan.ScopeAuthority, *readconnector.Registry) (*investigationplan.Planner, error)
	targets    func() (*readtarget.Registry, error)
	egress     func() (*readexecutor.EgressRegistry, error)
}

func loadSnapshot(
	ctx context.Context,
	expected Summary,
	loaders snapshotLoaders,
) (snapshot *Snapshot, returnedErr error) {
	defer func() {
		if recover() != nil {
			snapshot = nil
			returnedErr = ErrSnapshotRejected
		}
		if returnedErr != nil {
			snapshot = nil
		}
	}()
	if err := snapshotContextError(ctx); err != nil {
		return nil, err
	}
	if expected.Validate() != nil || loaders.connectors == nil || loaders.planner == nil ||
		loaders.targets == nil || loaders.egress == nil {
		return nil, ErrSnapshotRejected
	}

	connectors, err := loaders.connectors()
	if err != nil || connectors == nil || !connectors.Ready() ||
		!sameDigest(connectors.Digest(), expected.ConnectorRegistryDigest) {
		return nil, snapshotFailure(ctx)
	}
	if err := snapshotContextError(ctx); err != nil {
		return nil, err
	}
	authority := investigationplan.NewScopeAuthority()
	planner, err := loaders.planner(ctx, authority, connectors)
	if err != nil || planner == nil || !planner.Ready() || !planner.AcceptsAuthority(authority) ||
		!sameDigest(planner.ManifestDigest(), expected.PlanManifestDigest) ||
		!sameDigest(planner.RegistryDigest(), expected.ConnectorRegistryDigest) {
		return nil, snapshotFailure(ctx)
	}
	if err := snapshotContextError(ctx); err != nil {
		return nil, err
	}
	targets, err := loaders.targets()
	if err != nil || targets == nil || !targets.Ready() ||
		!sameDigest(targets.Digest(), expected.TargetRegistryDigest) {
		return nil, snapshotFailure(ctx)
	}
	if err := snapshotContextError(ctx); err != nil {
		return nil, err
	}
	egress, err := loaders.egress()
	if err != nil || egress == nil || !egress.Ready() ||
		!sameDigest(egress.Digest(), expected.EgressRegistryDigest) {
		return nil, snapshotFailure(ctx)
	}
	profile, err := readexecutor.NewProfile()
	if err != nil || profile == nil || !profile.Ready() ||
		!sameDigest(profile.Digest(), expected.ExecutorProfileDigest) {
		return nil, snapshotFailure(ctx)
	}
	if err := snapshotContextError(ctx); err != nil {
		return nil, err
	}
	bundle, err := readruntime.NewBundle(connectors, targets, egress, profile)
	if err != nil || bundle == nil || !bundle.Ready() ||
		!sameRuntimeSummary(bundle.Summary(), expected.runtimeSummary()) {
		return nil, snapshotFailure(ctx)
	}
	actualSummary := newSummary(planner.ManifestDigest(), bundle.Summary())
	if !sameSummary(actualSummary, expected) {
		return nil, ErrSnapshotRejected
	}
	created := &Snapshot{
		connectors: connectors, authority: authority, planner: planner, bundle: bundle,
		summary: actualSummary, seal: trustedSnapshotSeal,
	}
	created.self = created
	if err := snapshotContextError(ctx); err != nil {
		return nil, err
	}
	if !created.Ready() {
		return nil, ErrSnapshotRejected
	}
	return created, nil
}

func (snapshot *Snapshot) Ready() bool {
	if snapshot == nil || snapshot.self != snapshot || snapshot.seal != trustedSnapshotSeal ||
		snapshot.connectors == nil || !snapshot.connectors.Ready() ||
		snapshot.authority == nil || snapshot.planner == nil || !snapshot.planner.Ready() ||
		!snapshot.planner.AcceptsAuthority(snapshot.authority) || snapshot.bundle == nil || !snapshot.bundle.Ready() ||
		snapshot.summary.Validate() != nil {
		return false
	}
	return sameDigest(snapshot.connectors.Digest(), snapshot.summary.ConnectorRegistryDigest) &&
		sameDigest(snapshot.planner.ManifestDigest(), snapshot.summary.PlanManifestDigest) &&
		sameDigest(snapshot.planner.RegistryDigest(), snapshot.summary.ConnectorRegistryDigest) &&
		sameRuntimeSummary(snapshot.bundle.Summary(), snapshot.summary.runtimeSummary())
}

func (snapshot *Snapshot) Summary() Summary {
	if !snapshot.Ready() {
		return Summary{}
	}
	return snapshot.summary
}

// ResolvePlan attests a trusted persistence registration with the private
// authority and resolves through the matching private Planner.
func (snapshot *Snapshot) ResolvePlan(
	ctx context.Context,
	expectedPlanDigest string,
	registration investigationplan.TrustedSignalRegistration,
	signal domain.Signal,
) (plan investigationplan.Plan, returnedErr error) {
	defer func() {
		if recover() != nil {
			plan = investigationplan.Plan{}
			returnedErr = ErrSnapshotRejected
		}
	}()
	if !snapshot.Ready() || !sameDigest(expectedPlanDigest, snapshot.summary.PlanManifestDigest) {
		return investigationplan.Plan{}, ErrSnapshotRejected
	}
	if err := snapshotContextError(ctx); err != nil {
		return investigationplan.Plan{}, err
	}
	trusted, err := snapshot.authority.Attest(registration)
	if err != nil {
		return investigationplan.Plan{}, snapshotFailure(ctx)
	}
	resolved, err := snapshot.planner.Resolve(ctx, investigationplan.ResolveRequest{
		ExpectedPlanDigest: expectedPlanDigest, TrustedScope: trusted, Signal: signal,
	})
	if err != nil {
		return investigationplan.Plan{}, snapshotFailure(ctx)
	}
	if err := snapshotContextError(ctx); err != nil {
		return investigationplan.Plan{}, snapshotFailure(ctx)
	}
	return resolved, nil
}

func (snapshot *Snapshot) AuthorizeTaskSpec(
	ctx context.Context,
	scope investigation.TaskSpecScope,
	spec investigation.TaskSpec,
) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = ErrSnapshotRejected
		}
	}()
	if !snapshot.Ready() {
		return ErrSnapshotRejected
	}
	if err := snapshotContextError(ctx); err != nil {
		return snapshotFailure(ctx)
	}
	if err := snapshot.connectors.AuthorizeTaskSpec(ctx, scope, spec); err != nil {
		return snapshotFailure(ctx)
	}
	if err := snapshotContextError(ctx); err != nil {
		return snapshotFailure(ctx)
	}
	return nil
}

func (snapshot *Snapshot) Bind(
	ctx context.Context,
	scope investigation.TaskSpecScope,
	plan domain.InvestigationPlanBinding,
	spec investigation.TaskSpec,
) (components investigation.TaskRuntimeComponents, returnedErr error) {
	defer func() {
		if recover() != nil {
			components = investigation.TaskRuntimeComponents{}
			returnedErr = readruntime.ErrBindingRejected
		}
	}()
	if !snapshot.Ready() || !snapshot.matchesPlanBinding(plan) {
		return investigation.TaskRuntimeComponents{}, readruntime.ErrBindingRejected
	}
	if err := snapshotContextError(ctx); err != nil {
		return investigation.TaskRuntimeComponents{}, snapshotRuntimeFailure(ctx, readruntime.ErrBindingRejected)
	}
	components, err := snapshot.bundle.Bind(ctx, scope, plan, spec)
	if err != nil {
		return investigation.TaskRuntimeComponents{}, snapshotRuntimeFailure(ctx, readruntime.ErrBindingRejected)
	}
	if err := snapshotContextError(ctx); err != nil {
		return investigation.TaskRuntimeComponents{}, snapshotRuntimeFailure(ctx, readruntime.ErrBindingRejected)
	}
	return components, nil
}

func (snapshot *Snapshot) AuthorizeStart(ctx context.Context, descriptor readtask.Descriptor) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = readruntime.ErrBundleRejected
		}
	}()
	if !snapshot.Ready() || !snapshot.matchesPlanBinding(descriptor.PlanBinding) {
		return readruntime.ErrBundleRejected
	}
	if err := snapshotContextError(ctx); err != nil {
		return snapshotRuntimeFailure(ctx, readruntime.ErrBundleRejected)
	}
	if err := snapshot.bundle.AuthorizeStart(ctx, descriptor); err != nil {
		return snapshotRuntimeFailure(ctx, readruntime.ErrBundleRejected)
	}
	if err := snapshotContextError(ctx); err != nil {
		return snapshotRuntimeFailure(ctx, readruntime.ErrBundleRejected)
	}
	return nil
}

func (snapshot *Snapshot) AuthorizeHeartbeat(ctx context.Context, descriptor readtask.Descriptor) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = readruntime.ErrBundleRejected
		}
	}()
	if !snapshot.Ready() || !snapshot.matchesPlanBinding(descriptor.PlanBinding) {
		return readruntime.ErrBundleRejected
	}
	if err := snapshotContextError(ctx); err != nil {
		return snapshotRuntimeFailure(ctx, readruntime.ErrBundleRejected)
	}
	if err := snapshot.bundle.AuthorizeHeartbeat(ctx, descriptor); err != nil {
		return snapshotRuntimeFailure(ctx, readruntime.ErrBundleRejected)
	}
	if err := snapshotContextError(ctx); err != nil {
		return snapshotRuntimeFailure(ctx, readruntime.ErrBundleRejected)
	}
	return nil
}

func (snapshot *Snapshot) AuthorizeCompletion(
	ctx context.Context,
	descriptor readtask.Descriptor,
	evidence readtask.EvidenceCompletion,
) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = readruntime.ErrBundleRejected
		}
	}()
	if !snapshot.Ready() || !snapshot.matchesPlanBinding(descriptor.PlanBinding) {
		return readruntime.ErrBundleRejected
	}
	if err := snapshotContextError(ctx); err != nil {
		return snapshotRuntimeFailure(ctx, readruntime.ErrBundleRejected)
	}
	if err := snapshot.bundle.AuthorizeCompletion(ctx, descriptor, evidence); err != nil {
		return snapshotRuntimeFailure(ctx, readruntime.ErrBundleRejected)
	}
	if err := snapshotContextError(ctx); err != nil {
		return snapshotRuntimeFailure(ctx, readruntime.ErrBundleRejected)
	}
	return nil
}

func (snapshot *Snapshot) matchesPlanBinding(plan domain.InvestigationPlanBinding) bool {
	return plan.Validate() == nil &&
		sameDigest(plan.ManifestDigest, snapshot.summary.PlanManifestDigest) &&
		sameDigest(plan.RegistryDigest, snapshot.summary.ConnectorRegistryDigest)
}

func validManifestPaths(options FileOptions) bool {
	paths := []string{
		options.ConnectorManifestFile, options.PlanManifestFile,
		options.TargetManifestFile, options.EgressManifestFile,
	}
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if path == "" || len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
			strings.TrimSpace(path) != path {
			return false
		}
		for _, character := range path {
			if character < 0x20 || character == 0x7f {
				return false
			}
		}
		if _, duplicate := seen[path]; duplicate {
			return false
		}
		seen[path] = struct{}{}
	}
	return true
}

func sameRuntimeSummary(left, right readruntime.Summary) bool {
	return left.Validate() == nil && right.Validate() == nil &&
		sameDigest(left.SchemaVersion, right.SchemaVersion) &&
		sameDigest(left.BundleDigest, right.BundleDigest) &&
		sameDigest(left.ConnectorRegistryDigest, right.ConnectorRegistryDigest) &&
		sameDigest(left.TargetRegistryDigest, right.TargetRegistryDigest) &&
		sameDigest(left.EgressRegistryDigest, right.EgressRegistryDigest) &&
		sameDigest(left.ExecutorProfileDigest, right.ExecutorProfileDigest)
}

func newSummary(planDigest string, runtime readruntime.Summary) Summary {
	return Summary{
		SchemaVersion:           SnapshotSchemaVersion,
		PlanManifestDigest:      strings.Clone(planDigest),
		ConnectorRegistryDigest: strings.Clone(runtime.ConnectorRegistryDigest),
		TargetRegistryDigest:    strings.Clone(runtime.TargetRegistryDigest),
		EgressRegistryDigest:    strings.Clone(runtime.EgressRegistryDigest),
		ExecutorProfileDigest:   strings.Clone(runtime.ExecutorProfileDigest),
		BundleDigest:            strings.Clone(runtime.BundleDigest),
	}
}

func sameSummary(left, right Summary) bool {
	return left.Validate() == nil && right.Validate() == nil &&
		sameDigest(left.SchemaVersion, right.SchemaVersion) &&
		sameDigest(left.PlanManifestDigest, right.PlanManifestDigest) &&
		sameRuntimeSummary(left.runtimeSummary(), right.runtimeSummary())
}

func sameDigest(left, right string) bool {
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func snapshotFailure(ctx context.Context) error {
	if err := snapshotContextError(ctx); err == context.Canceled || err == context.DeadlineExceeded {
		return err
	}
	return ErrSnapshotRejected
}

func snapshotRuntimeFailure(ctx context.Context, fallback error) error {
	if err := snapshotContextError(ctx); err == context.Canceled || err == context.DeadlineExceeded {
		return err
	}
	return fallback
}

func snapshotContextError(ctx context.Context) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = ErrSnapshotRejected
		}
	}()
	if ctx == nil {
		return ErrSnapshotRejected
	}
	value := reflect.ValueOf(ctx)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return ErrSnapshotRejected
		}
	}
	err := ctx.Err()
	if err == nil {
		return nil
	}
	if sameErrorInstance(err, context.Canceled) {
		return context.Canceled
	}
	if sameErrorInstance(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return ErrSnapshotRejected
}

func sameErrorInstance(left, right error) bool {
	leftType, rightType := reflect.TypeOf(left), reflect.TypeOf(right)
	return leftType != nil && leftType == rightType && leftType.Comparable() && left == right
}

func (Snapshot) String() string   { return "<aiops-read-assembly-snapshot>" }
func (Snapshot) GoString() string { return "<aiops-read-assembly-snapshot>" }
func (Snapshot) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-read-assembly-snapshot>")
}
func (Snapshot) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Snapshot) UnmarshalJSON([]byte) error  { return ErrSnapshotRejected }
