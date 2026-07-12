package readassembly

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigationplan"
	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/readexecutor"
	"github.com/seaworld008/aiops-system/internal/readruntime"
	"github.com/seaworld008/aiops-system/internal/readtarget"
	"github.com/seaworld008/aiops-system/internal/readtask"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
)

const (
	snapshotTenantID      = "10000000-0000-4000-8000-000000000001"
	snapshotWorkspaceID   = "20000000-0000-4000-8000-000000000002"
	snapshotEnvironmentID = "30000000-0000-4000-8000-000000000003"
	snapshotServiceID     = "40000000-0000-4000-8000-000000000004"
	snapshotIntegrationID = "50000000-0000-4000-8000-000000000005"
	snapshotSignalID      = "60000000-0000-4000-8000-000000000006"
)

func TestLoadFilesPublishesOnePinnedDetachedPlanningAndRuntimeSnapshot(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadFiles(context.Background(), fixture.options)
	if err != nil || snapshot == nil || !snapshot.Ready() {
		t.Fatalf("LoadFiles() = %#v, %v", snapshot, err)
	}
	if snapshot.Summary() != fixture.options.Expected {
		t.Fatalf("Snapshot Summary = %#v", snapshot.Summary())
	}
	plan, err := snapshot.ResolvePlan(
		context.Background(), fixture.options.Expected.PlanManifestDigest,
		investigationplan.TrustedSignalRegistration{
			TenantID: snapshotTenantID, WorkspaceID: snapshotWorkspaceID,
		},
		fixture.signal,
	)
	if err != nil {
		t.Fatalf("Snapshot.ResolvePlan() error = %v", err)
	}
	specs := plan.TaskSpecs()
	if len(specs) != 1 || specs[0].ConnectorID != fixture.connectorID {
		t.Fatalf("resolved TaskSpecs = %#v", specs)
	}
	if err := snapshot.AuthorizeTaskSpec(context.Background(), plan.Scope(), specs[0]); err != nil {
		t.Fatalf("Snapshot.AuthorizeTaskSpec() error = %v", err)
	}
	binding := domain.InvestigationPlanBinding{
		SchemaVersion:  domain.InvestigationPlanBindingSchemaVersion,
		ManifestDigest: plan.ManifestDigest(), RegistryDigest: plan.RegistryDigest(),
		ProfileDigest: plan.ProfileDigest(), TasksHash: plan.TasksHash(),
	}
	components, err := investigation.ResolveTaskRuntimeComponents(
		context.Background(), snapshot.Bind, plan.Scope(), binding, specs,
	)
	if err != nil || len(components) != 1 || components[0].ConnectorDigest == "" ||
		components[0].TargetDigest == "" || components[0].ExecutorDigest != readexecutor.CurrentProfileDigest {
		t.Fatalf("ResolveTaskRuntimeComponents() = %#v, %v", components, err)
	}
	inputDigest := sha256.Sum256(specs[0].Input)
	runtimeDigest, err := investigation.ReadTaskRuntimeDigest(plan.Scope(), binding, specs[0], 1, components[0])
	if err != nil {
		t.Fatal(err)
	}
	descriptor := readtask.Descriptor{
		TenantID: snapshotTenantID, WorkspaceID: snapshotWorkspaceID,
		EnvironmentID: snapshotEnvironmentID, ServiceID: snapshotServiceID,
		IncidentID:      "70000000-0000-4000-8000-000000000007",
		InvestigationID: "80000000-0000-4000-8000-000000000008",
		TaskID:          "90000000-0000-4000-8000-000000000009",
		TaskKey:         specs[0].Key, Position: 1, ConnectorID: specs[0].ConnectorID,
		Operation: specs[0].Operation, Input: append(json.RawMessage(nil), specs[0].Input...),
		InputHash: hex.EncodeToString(inputDigest[:]), PlanBinding: binding,
		RuntimeBinding: domain.ReadTaskRuntimeBinding{
			SchemaVersion:   domain.ReadTaskRuntimeBindingSchemaVersion,
			ConnectorDigest: components[0].ConnectorDigest, TargetDigest: components[0].TargetDigest,
			ExecutorDigest: components[0].ExecutorDigest, RuntimeDigest: runtimeDigest,
			BoundAt: time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC),
		},
	}
	if err := snapshot.AuthorizeStart(context.Background(), descriptor); err != nil {
		t.Fatalf("Snapshot.AuthorizeStart() error = %v", err)
	}
	if err := snapshot.AuthorizeHeartbeat(context.Background(), descriptor); err != nil {
		t.Fatalf("Snapshot.AuthorizeHeartbeat() error = %v", err)
	}
	collectedAt := time.Date(2026, 7, 12, 12, 1, 0, 0, time.UTC)
	evidence := readtask.EvidenceCompletion{CollectedAt: collectedAt, Items: []json.RawMessage{
		json.RawMessage(fmt.Sprintf(`{"metric":{"job":"api"},"values":[[%d,"1"]]}`, collectedAt.Add(-time.Minute).Unix())),
	}}
	if err := snapshot.AuthorizeCompletion(context.Background(), descriptor, evidence); err != nil {
		t.Fatalf("Snapshot.AuthorizeCompletion() error = %v", err)
	}
	foreignBinding := binding
	foreignBinding.ManifestDigest = strings.Repeat("a", 64)
	foreignRuntimeDigest, err := investigation.ReadTaskRuntimeDigest(
		plan.Scope(), foreignBinding, specs[0], 1, components[0],
	)
	if err != nil {
		t.Fatal(err)
	}
	foreignDescriptor := descriptor
	foreignDescriptor.Input = append(json.RawMessage(nil), descriptor.Input...)
	foreignDescriptor.PlanBinding = foreignBinding
	foreignDescriptor.RuntimeBinding.RuntimeDigest = foreignRuntimeDigest
	if got, err := snapshot.Bind(context.Background(), plan.Scope(), foreignBinding, specs[0]); got != (investigation.TaskRuntimeComponents{}) || !errors.Is(err, readruntime.ErrBindingRejected) {
		t.Fatalf("Snapshot.Bind(foreign plan) = %#v, %v", got, err)
	}
	if err := snapshot.AuthorizeStart(context.Background(), foreignDescriptor); err == nil {
		t.Fatal("Snapshot.AuthorizeStart accepted a foreign Plan snapshot")
	}
	if err := snapshot.AuthorizeHeartbeat(context.Background(), foreignDescriptor); err == nil {
		t.Fatal("Snapshot.AuthorizeHeartbeat accepted a foreign Plan snapshot")
	}
	if err := snapshot.AuthorizeCompletion(context.Background(), foreignDescriptor, evidence); err == nil {
		t.Fatal("Snapshot.AuthorizeCompletion accepted a foreign Plan snapshot")
	}

	for _, path := range []string{
		fixture.options.ConnectorManifestFile, fixture.options.PlanManifestFile,
		fixture.options.TargetManifestFile, fixture.options.EgressManifestFile, fixture.caPath,
	} {
		if err := os.WriteFile(path, []byte(`{"changed":true}`), 0o600); err != nil {
			t.Fatalf("mutate source manifest: %v", err)
		}
	}
	if !snapshot.Ready() || snapshot.Summary() != fixture.options.Expected {
		t.Fatal("source-file mutation changed an accepted Snapshot")
	}
	copy := *snapshot
	if copy.Ready() || copy.Summary() != (Summary{}) {
		t.Fatal("copied Snapshot retained authority")
	}
	if copiedPlan, copiedErr := copy.ResolvePlan(
		context.Background(), fixture.options.Expected.PlanManifestDigest,
		investigationplan.TrustedSignalRegistration{TenantID: snapshotTenantID, WorkspaceID: snapshotWorkspaceID},
		fixture.signal,
	); copiedPlan.ManifestDigest() != "" || !errors.Is(copiedErr, ErrSnapshotRejected) {
		t.Fatalf("copied Snapshot ResolvePlan = %#v, %v", copiedPlan, copiedErr)
	}
	if err := copy.AuthorizeTaskSpec(context.Background(), plan.Scope(), specs[0]); !errors.Is(err, ErrSnapshotRejected) {
		t.Fatalf("copied Snapshot AuthorizeTaskSpec error = %v", err)
	}
	if got, err := copy.Bind(context.Background(), plan.Scope(), binding, specs[0]); got != (investigation.TaskRuntimeComponents{}) || !errors.Is(err, readruntime.ErrBindingRejected) {
		t.Fatalf("copied Snapshot Bind = %#v, %v", got, err)
	}
	if err := copy.AuthorizeStart(context.Background(), descriptor); !errors.Is(err, readruntime.ErrBundleRejected) {
		t.Fatalf("copied Snapshot AuthorizeStart error = %v", err)
	}
	if err := copy.AuthorizeHeartbeat(context.Background(), descriptor); !errors.Is(err, readruntime.ErrBundleRejected) {
		t.Fatalf("copied Snapshot AuthorizeHeartbeat error = %v", err)
	}
	if err := copy.AuthorizeCompletion(context.Background(), descriptor, evidence); !errors.Is(err, readruntime.ErrBundleRejected) {
		t.Fatalf("copied Snapshot AuthorizeCompletion error = %v", err)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || string(encoded) != `{"redacted":true}` {
		t.Fatalf("json.Marshal(Snapshot) = %s, %v", encoded, err)
	}
	var decoded Snapshot
	if err := json.Unmarshal(encoded, &decoded); !errors.Is(err, ErrSnapshotRejected) || decoded.Ready() {
		t.Fatalf("json.Unmarshal(Snapshot) = %#v, %v", decoded, err)
	}
	summaryWire, err := json.Marshal(snapshot.Summary())
	if err != nil {
		t.Fatal(err)
	}
	var decodedSummary Summary
	if err := json.Unmarshal(summaryWire, &decodedSummary); !errors.Is(err, ErrSnapshotRejected) ||
		decodedSummary != (Summary{}) {
		t.Fatalf("json.Unmarshal(Summary) = %#v, %v", decodedSummary, err)
	}
	rendered := fmt.Sprintf("%s %+v %#v", snapshot, *snapshot, *snapshot)
	for _, forbidden := range []string{fixture.caPath, fixture.connectorID, "metrics.staging.internal"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("Snapshot rendering leaked %q through %q", forbidden, rendered)
		}
	}
}

func TestLoadFilesDetachesCallerOwnedExpectedDigestBackingStorage(t *testing.T) {
	fixture := newSnapshotFixture(t)
	options := fixture.options
	type digestField struct {
		name  string
		value *string
	}
	fields := []digestField{
		{name: "plan", value: &options.Expected.PlanManifestDigest},
		{name: "connector", value: &options.Expected.ConnectorRegistryDigest},
		{name: "target", value: &options.Expected.TargetRegistryDigest},
		{name: "egress", value: &options.Expected.EgressRegistryDigest},
		{name: "executor", value: &options.Expected.ExecutorProfileDigest},
		{name: "bundle", value: &options.Expected.BundleDigest},
	}
	callerPointers := make(map[string]*byte, len(fields))
	for _, field := range fields {
		backing := strings.Repeat("x", 1<<20) + *field.value
		*field.value = backing[len(backing)-64:]
		callerPointers[field.name] = unsafe.StringData(*field.value)
	}

	snapshot, err := LoadFiles(context.Background(), options)
	if err != nil || snapshot == nil || !snapshot.Ready() {
		t.Fatalf("LoadFiles() = %#v, %v", snapshot, err)
	}
	got := snapshot.Summary()
	accepted := map[string]string{
		"plan": got.PlanManifestDigest, "connector": got.ConnectorRegistryDigest,
		"target": got.TargetRegistryDigest, "egress": got.EgressRegistryDigest,
		"executor": got.ExecutorProfileDigest, "bundle": got.BundleDigest,
	}
	for name, value := range accepted {
		if unsafe.StringData(value) == callerPointers[name] {
			t.Fatalf("Snapshot retained caller-owned %s digest backing storage", name)
		}
	}
}

func TestSnapshotFacadesRejectHostileContextWithoutLeakingMaterial(t *testing.T) {
	const canary = "READ-SNAPSHOT-FACADE-CONTEXT-CANARY"
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadFiles(context.Background(), fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := snapshot.ResolvePlan(
		context.Background(), fixture.options.Expected.PlanManifestDigest,
		investigationplan.TrustedSignalRegistration{TenantID: snapshotTenantID, WorkspaceID: snapshotWorkspaceID},
		fixture.signal,
	)
	if err != nil {
		t.Fatal(err)
	}
	spec := plan.TaskSpecs()[0]
	binding := domain.InvestigationPlanBinding{
		SchemaVersion: domain.InvestigationPlanBindingSchemaVersion, ManifestDigest: plan.ManifestDigest(),
		RegistryDigest: plan.RegistryDigest(), ProfileDigest: plan.ProfileDigest(), TasksHash: plan.TasksHash(),
	}
	descriptor := readtask.Descriptor{PlanBinding: binding}
	contexts := map[string]func() context.Context{
		"arbitrary": func() context.Context { return snapshotErrorContext{err: errors.New(canary)} },
		"wrapped cancellation": func() context.Context {
			return snapshotErrorContext{err: fmt.Errorf("%s: %w", canary, context.Canceled)}
		},
		"panic": func() context.Context { return snapshotPanicContext{} },
		"changes after precheck": func() context.Context {
			return &snapshotSequenceContext{afterFirst: errors.New(canary)}
		},
	}
	for name, newContext := range contexts {
		t.Run(name, func(t *testing.T) {
			assertSnapshotLowSensitiveError(t, canary, func() error {
				_, err := snapshot.ResolvePlan(
					newContext(), fixture.options.Expected.PlanManifestDigest,
					investigationplan.TrustedSignalRegistration{
						TenantID: snapshotTenantID, WorkspaceID: snapshotWorkspaceID,
					},
					fixture.signal,
				)
				return err
			})
			assertSnapshotLowSensitiveError(t, canary, func() error {
				return snapshot.AuthorizeTaskSpec(newContext(), plan.Scope(), spec)
			})
			assertSnapshotLowSensitiveError(t, canary, func() error {
				_, err := snapshot.Bind(newContext(), plan.Scope(), binding, spec)
				return err
			})
			assertSnapshotLowSensitiveError(t, canary, func() error {
				return snapshot.AuthorizeStart(newContext(), descriptor)
			})
			assertSnapshotLowSensitiveError(t, canary, func() error {
				return snapshot.AuthorizeHeartbeat(newContext(), descriptor)
			})
			assertSnapshotLowSensitiveError(t, canary, func() error {
				return snapshot.AuthorizeCompletion(newContext(), descriptor, readtask.EvidenceCompletion{})
			})
		})
	}
}

func assertSnapshotLowSensitiveError(t *testing.T, canary string, call func() error) {
	t.Helper()
	err := call()
	if err == nil {
		t.Fatal("Snapshot facade accepted a hostile context")
	}
	if strings.Contains(fmt.Sprint(err), canary) {
		t.Fatalf("Snapshot facade leaked context material: %v", err)
	}
}

type snapshotSequenceContext struct {
	calls      int
	afterFirst error
}

func (*snapshotSequenceContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*snapshotSequenceContext) Done() <-chan struct{}       { return nil }
func (context *snapshotSequenceContext) Err() error {
	context.calls++
	if context.calls == 1 {
		return nil
	}
	return context.afterFirst
}
func (*snapshotSequenceContext) Value(any) any { return nil }

func TestSnapshotExportsNoRawComponentOrMutableState(t *testing.T) {
	snapshotType := reflect.TypeOf(Snapshot{})
	for index := 0; index < snapshotType.NumField(); index++ {
		if snapshotType.Field(index).IsExported() {
			t.Fatalf("Snapshot field %q is exported", snapshotType.Field(index).Name)
		}
	}
	pointerType := reflect.TypeOf((*Snapshot)(nil))
	for _, forbidden := range []string{"Authority", "Planner", "Bundle", "Registry", "Connectors", "Targets", "Egress"} {
		if _, found := pointerType.MethodByName(forbidden); found {
			t.Fatalf("Snapshot exports raw component getter %q", forbidden)
		}
	}
}

func TestSnapshotFacadesAreSafeForConcurrentReaders(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadFiles(context.Background(), fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 16
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 20 {
				if snapshot.Summary() != fixture.options.Expected {
					errorsChannel <- errors.New("concurrent Summary drift")
					return
				}
				plan, err := snapshot.ResolvePlan(
					context.Background(), fixture.options.Expected.PlanManifestDigest,
					investigationplan.TrustedSignalRegistration{
						TenantID: snapshotTenantID, WorkspaceID: snapshotWorkspaceID,
					},
					fixture.signal,
				)
				if err != nil {
					errorsChannel <- err
					return
				}
				specs := plan.TaskSpecs()
				if len(specs) != 1 || snapshot.AuthorizeTaskSpec(context.Background(), plan.Scope(), specs[0]) != nil {
					errorsChannel <- errors.New("concurrent plan facade rejected")
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatalf("concurrent Snapshot facade: %v", err)
	}
}

func TestLoadFilesRejectsUnpinnedPathsDigestsAndCrossManifestGraphs(t *testing.T) {
	canary := "READ-SNAPSHOT-SECRET-CANARY"
	tests := map[string]func(*testing.T, *FileOptions){
		"missing connector path": func(_ *testing.T, options *FileOptions) {
			options.ConnectorManifestFile = ""
		},
		"missing plan path": func(_ *testing.T, options *FileOptions) {
			options.PlanManifestFile = ""
		},
		"missing target path": func(_ *testing.T, options *FileOptions) {
			options.TargetManifestFile = ""
		},
		"missing egress path": func(_ *testing.T, options *FileOptions) {
			options.EgressManifestFile = ""
		},
		"missing expected summary": func(_ *testing.T, options *FileOptions) {
			options.Expected = Summary{}
		},
		"wrong expected schema": func(_ *testing.T, options *FileOptions) {
			options.Expected.SchemaVersion = SnapshotSchemaVersion + ".drift"
		},
		"relative path": func(_ *testing.T, options *FileOptions) {
			options.EgressManifestFile = canary + ".json"
		},
		"control character path": func(_ *testing.T, options *FileOptions) {
			options.EgressManifestFile += "\n" + canary
		},
		"non-clean path": func(_ *testing.T, options *FileOptions) {
			options.PlanManifestFile = filepath.Dir(options.PlanManifestFile) + "/nested/../" + filepath.Base(options.PlanManifestFile)
		},
		"duplicate path": func(_ *testing.T, options *FileOptions) {
			options.TargetManifestFile = options.ConnectorManifestFile
		},
		"plan digest": func(_ *testing.T, options *FileOptions) {
			options.Expected.PlanManifestDigest = strings.Repeat("a", 64)
		},
		"bundle digest": func(_ *testing.T, options *FileOptions) {
			options.Expected.BundleDigest = strings.Repeat("b", 64)
		},
		"connector digest": func(_ *testing.T, options *FileOptions) {
			options.Expected.ConnectorRegistryDigest = strings.Repeat("c", 64)
		},
		"target digest": func(_ *testing.T, options *FileOptions) {
			options.Expected.TargetRegistryDigest = strings.Repeat("d", 64)
		},
		"egress digest": func(_ *testing.T, options *FileOptions) {
			options.Expected.EgressRegistryDigest = strings.Repeat("e", 64)
		},
		"profile digest": func(_ *testing.T, options *FileOptions) {
			options.Expected.ExecutorProfileDigest = strings.Repeat("f", 64)
		},
		"valid foreign bundle summary": func(t *testing.T, options *FileOptions) {
			options.Expected = newSnapshotFixture(t).options.Expected
		},
		"connector content": func(t *testing.T, options *FileOptions) {
			writeSnapshotBytes(t, options.ConnectorManifestFile, []byte(`{"schema_version":"read-connector-registry.v1","definitions":[]}`))
		},
		"plan content": func(t *testing.T, options *FileOptions) {
			writeSnapshotBytes(t, options.PlanManifestFile, []byte(`{"schema_version":"investigation-plan-manifest.v1","registry_digest":"`+canary+`","profiles":[]}`))
		},
		"foreign plan and target graph": func(t *testing.T, options *FileOptions) {
			foreign := newSnapshotFixture(t)
			options.PlanManifestFile = foreign.options.PlanManifestFile
			options.TargetManifestFile = foreign.options.TargetManifestFile
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			local := newSnapshotFixture(t)
			options := local.options
			mutate(t, &options)
			snapshot, err := LoadFiles(context.Background(), options)
			if snapshot != nil || !errors.Is(err, ErrSnapshotRejected) {
				t.Fatalf("LoadFiles() = %#v, %v; want rejection", snapshot, err)
			}
			rendered := fmt.Sprint(err)
			for _, forbidden := range []string{canary, options.ConnectorManifestFile, options.PlanManifestFile,
				options.TargetManifestFile, options.EgressManifestFile} {
				if forbidden != "" && strings.Contains(rendered, forbidden) {
					t.Fatalf("LoadFiles() leaked %q through %q", forbidden, rendered)
				}
			}
		})
	}
}

func TestLoadFilesRejectsNestedCABundleDriftWithoutLeakingMaterial(t *testing.T) {
	local := newSnapshotFixture(t)
	foreign := newSnapshotFixture(t)
	foreignCA, err := os.ReadFile(foreign.caPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local.caPath, foreignCA, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := LoadFiles(context.Background(), local.options)
	if snapshot != nil || !errors.Is(err, ErrSnapshotRejected) {
		t.Fatalf("LoadFiles(CA drift) = %#v, %v", snapshot, err)
	}
	rendered := fmt.Sprint(err)
	for _, forbidden := range []string{local.caPath, foreign.caPath, "metrics.staging.internal", string(foreignCA)} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("LoadFiles(CA drift) leaked %q through %q", forbidden, rendered)
		}
	}
}

func TestLoadFilesRejectsSelfConsistentButUnreviewedExtraRuntimeEntries(t *testing.T) {
	fixture := newSnapshotFixture(t)
	extraEgress := fixture.egressDefinition
	extraEgress.Hostname = "logs.staging.internal"
	extraEgress.Port = 9443
	extraEgress.AllowedPrefixes = []string{"10.42.10.0/24"}
	extraEgress.PolicyRef = ""
	extraEgressRef, err := readexecutor.BuildEgressPolicyRef("logs-egress", extraEgress)
	if err != nil {
		t.Fatal(err)
	}
	extraEgress.PolicyRef = extraEgressRef
	extraTarget := fixture.targetDefinition
	extraTarget.Endpoint.Origin = "https://logs.staging.internal:9443"
	extraTarget.Endpoint.ServerName = "logs.staging.internal"
	extraTarget.CredentialRoleRef = "logs-reader-v1-" + strings.Repeat("b", 64)
	extraTarget.NetworkPolicyRef = extraEgressRef
	extraTarget.TargetRef = ""
	extraTargetRef, err := readtarget.BuildTargetRef("logs-staging", extraTarget)
	if err != nil {
		t.Fatal(err)
	}
	extraTarget.TargetRef = extraTargetRef
	writeSnapshotJSON(t, fixture.options.TargetManifestFile, struct {
		SchemaVersion string                  `json:"schema_version"`
		Targets       []readtarget.Definition `json:"targets"`
	}{
		SchemaVersion: readtarget.ManifestSchemaVersion,
		Targets:       []readtarget.Definition{fixture.targetDefinition, extraTarget},
	})
	writeSnapshotJSON(t, fixture.options.EgressManifestFile, struct {
		SchemaVersion string                                `json:"schema_version"`
		Policies      []readexecutor.EgressPolicyDefinition `json:"policies"`
	}{
		SchemaVersion: readexecutor.EgressRegistrySchemaVersion,
		Policies:      []readexecutor.EgressPolicyDefinition{fixture.egressDefinition, extraEgress},
	})
	connectors, err := readconnector.LoadFile(fixture.options.ConnectorManifestFile)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := readtarget.LoadFile(fixture.options.TargetManifestFile)
	if err != nil {
		t.Fatal(err)
	}
	egress, err := readexecutor.LoadEgressRegistryFile(fixture.options.EgressManifestFile)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := readexecutor.NewProfile()
	if err != nil {
		t.Fatal(err)
	}
	unreviewedBundle, err := readruntime.NewBundle(connectors, targets, egress, profile)
	if err != nil || unreviewedBundle.Summary() == fixture.options.Expected.runtimeSummary() {
		t.Fatalf("expanded graph should be self-consistent but have a new identity: %#v, %v", unreviewedBundle, err)
	}
	snapshot, err := LoadFiles(context.Background(), fixture.options)
	if snapshot != nil || !errors.Is(err, ErrSnapshotRejected) {
		t.Fatalf("LoadFiles(unreviewed extra entries) = %#v, %v", snapshot, err)
	}
}

type snapshotFixture struct {
	options          FileOptions
	connectorID      string
	signal           domain.Signal
	caPath           string
	targetDefinition readtarget.Definition
	egressDefinition readexecutor.EgressPolicyDefinition
}

func newSnapshotFixture(t *testing.T) snapshotFixture {
	t.Helper()
	directory := t.TempDir()
	now := time.Now().UTC()
	authority, err := testpki.NewAuthority("read-snapshot-test-root", now)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(directory, "target-ca.pem")
	writeSnapshotBytes(t, caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.Certificate.Raw}))

	egressDefinition := readexecutor.EgressPolicyDefinition{
		Scope: readtarget.Scope{
			TenantID: snapshotTenantID, WorkspaceID: snapshotWorkspaceID, EnvironmentID: snapshotEnvironmentID,
		},
		Hostname: "metrics.staging.internal", Port: 8443, AllowedPrefixes: []string{"10.42.9.0/24"},
	}
	egressRef, err := readexecutor.BuildEgressPolicyRef("metrics-egress", egressDefinition)
	if err != nil {
		t.Fatal(err)
	}
	egressDefinition.PolicyRef = egressRef
	targetDefinition := readtarget.Definition{
		Scope: readtarget.Scope{
			TenantID: snapshotTenantID, WorkspaceID: snapshotWorkspaceID, EnvironmentID: snapshotEnvironmentID,
		},
		Kind: readconnector.KindPrometheus,
		Endpoint: readtarget.Endpoint{
			Origin: "https://metrics.staging.internal:8443", ServerName: "metrics.staging.internal",
			CABundleFile: caPath,
		},
		CredentialRoleRef: "metrics-reader-v1-" + strings.Repeat("a", 64), NetworkPolicyRef: egressRef,
	}
	targetRef, err := readtarget.BuildTargetRef("metrics-staging", targetDefinition)
	if err != nil {
		t.Fatal(err)
	}
	targetDefinition.TargetRef = targetRef
	connectorDefinition := readconnector.Definition{
		Scope: readconnector.Scope{
			TenantID: snapshotTenantID, WorkspaceID: snapshotWorkspaceID,
			EnvironmentID: snapshotEnvironmentID, ServiceID: snapshotServiceID,
		},
		TargetRef: targetRef,
		PrometheusRangeQuery: &readconnector.PrometheusRangeQueryV1{
			Expression: "up", StepSeconds: 30, MaxLookbackMinutes: 60, MaxItems: 100, MaxSamples: 121,
		},
	}
	connectorID, err := readconnector.BuildConnectorID("metrics-staging", connectorDefinition)
	if err != nil {
		t.Fatal(err)
	}
	connectorDefinition.ConnectorID = connectorID
	connectors, err := readconnector.New([]readconnector.Definition{connectorDefinition})
	if err != nil {
		t.Fatal(err)
	}
	planDefinition := investigationplan.Definition{
		RegistryDigest: connectors.Digest(),
		Profiles: []investigationplan.ProfileDefinition{{
			Scope: investigationplan.Scope{
				TenantID: snapshotTenantID, WorkspaceID: snapshotWorkspaceID,
				EnvironmentID: snapshotEnvironmentID, ServiceID: snapshotServiceID,
			},
			Match: investigationplan.MatchDefinition{
				IntegrationID: snapshotIntegrationID, Provider: "alertmanager",
				Labels: []investigationplan.LabelMatch{{Key: "service", Value: "payments"}},
			},
			Tasks: []investigationplan.TaskDefinition{{
				Key: "metrics", ConnectorID: connectorID, Operation: readconnector.OperationPrometheusRangeQuery,
				Input: json.RawMessage(`{"lookback_minutes":15}`),
			}},
		}},
	}
	planAuthority := investigationplan.NewScopeAuthority()
	planner, err := investigationplan.New(context.Background(), planAuthority, connectors, planDefinition)
	if err != nil {
		t.Fatal(err)
	}

	connectorPath := filepath.Join(directory, "connectors.json")
	planPath := filepath.Join(directory, "plans.json")
	targetPath := filepath.Join(directory, "targets.json")
	egressPath := filepath.Join(directory, "egress.json")
	writeSnapshotJSON(t, connectorPath, struct {
		SchemaVersion string                     `json:"schema_version"`
		Definitions   []readconnector.Definition `json:"definitions"`
	}{SchemaVersion: "read-connector-registry.v1", Definitions: []readconnector.Definition{connectorDefinition}})
	writeSnapshotJSON(t, planPath, struct {
		SchemaVersion  string                                `json:"schema_version"`
		RegistryDigest string                                `json:"registry_digest"`
		Profiles       []investigationplan.ProfileDefinition `json:"profiles"`
	}{
		SchemaVersion: investigationplan.ManifestSchemaVersion, RegistryDigest: planDefinition.RegistryDigest,
		Profiles: planDefinition.Profiles,
	})
	writeSnapshotJSON(t, targetPath, struct {
		SchemaVersion string                  `json:"schema_version"`
		Targets       []readtarget.Definition `json:"targets"`
	}{SchemaVersion: readtarget.ManifestSchemaVersion, Targets: []readtarget.Definition{targetDefinition}})
	writeSnapshotJSON(t, egressPath, struct {
		SchemaVersion string                                `json:"schema_version"`
		Policies      []readexecutor.EgressPolicyDefinition `json:"policies"`
	}{SchemaVersion: readexecutor.EgressRegistrySchemaVersion, Policies: []readexecutor.EgressPolicyDefinition{egressDefinition}})

	targets, err := readtarget.LoadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	egress, err := readexecutor.LoadEgressRegistryFile(egressPath)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := readexecutor.NewProfile()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := readruntime.NewBundle(connectors, targets, egress, profile)
	if err != nil {
		t.Fatal(err)
	}
	return snapshotFixture{
		options: FileOptions{
			ConnectorManifestFile: connectorPath, PlanManifestFile: planPath,
			TargetManifestFile: targetPath, EgressManifestFile: egressPath,
			Expected: snapshotSummary(planner.ManifestDigest(), bundle.Summary()),
		},
		connectorID: connectorID,
		caPath:      caPath, targetDefinition: targetDefinition, egressDefinition: egressDefinition,
		signal: domain.Signal{
			ID: snapshotSignalID, WorkspaceID: snapshotWorkspaceID, IntegrationID: snapshotIntegrationID,
			Provider: "alertmanager", ProviderEventID: "snapshot-event-1", PayloadHash: strings.Repeat("f", 64),
			Fingerprint: "payments-staging", Status: "firing", Labels: map[string]string{"service": "payments"},
			ObservedAt: now,
		},
	}
}

func writeSnapshotJSON(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writeSnapshotBytes(t, path, encoded)
}

func writeSnapshotBytes(t *testing.T, path string, value []byte) {
	t.Helper()
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
}

func snapshotSummary(planDigest string, runtime readruntime.Summary) Summary {
	return Summary{
		SchemaVersion: SnapshotSchemaVersion, PlanManifestDigest: planDigest,
		ConnectorRegistryDigest: runtime.ConnectorRegistryDigest,
		TargetRegistryDigest:    runtime.TargetRegistryDigest,
		EgressRegistryDigest:    runtime.EgressRegistryDigest,
		ExecutorProfileDigest:   runtime.ExecutorProfileDigest,
		BundleDigest:            runtime.BundleDigest,
	}
}
