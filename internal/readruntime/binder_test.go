package readruntime_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/readexecutor"
	"github.com/seaworld008/aiops-system/internal/readruntime"
	"github.com/seaworld008/aiops-system/internal/readtarget"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
)

const (
	tenantID      = "10000000-0000-4000-8000-000000000001"
	workspaceID   = "20000000-0000-4000-8000-000000000002"
	environmentID = "30000000-0000-4000-8000-000000000003"
	serviceID     = "40000000-0000-4000-8000-000000000004"
)

func TestBinderResolvesOnlyServerOwnedRuntimeComponentDigests(t *testing.T) {
	fixture := newBinderFixture(t, readconnector.KindPrometheus)
	binder, err := readruntime.NewBinder(fixture.connectors, fixture.targets, fixture.profile)
	if err != nil || binder == nil || !binder.Ready() {
		t.Fatalf("NewBinder() = %#v, %v", binder, err)
	}

	resolved, err := investigation.ResolveTaskRuntimeComponents(
		context.Background(), binder.Bind, fixture.scope, fixture.plan,
		[]investigation.TaskSpec{fixture.spec},
	)
	if err != nil || len(resolved) != 1 {
		t.Fatalf("ResolveTaskRuntimeComponents() = %#v, %v", resolved, err)
	}
	components := resolved[0]
	if components.ConnectorDigest != fixture.connectorID[len(fixture.connectorID)-64:] ||
		components.TargetDigest != fixture.targetRef[len(fixture.targetRef)-64:] ||
		components.ExecutorDigest != readexecutor.CurrentProfileDigest || components.Validate() != nil {
		t.Fatalf("resolved components = %#v", components)
	}
	boundAt := time.Date(2026, 7, 12, 13, 14, 15, 123456000, time.UTC)
	binding, err := investigation.BuildReadTaskRuntimeBinding(
		fixture.scope, fixture.plan, fixture.spec, 1, components, boundAt,
	)
	if err != nil || binding.Validate() != nil || binding.TargetDigest != components.TargetDigest ||
		binding.ExecutorDigest != components.ExecutorDigest {
		t.Fatalf("BuildReadTaskRuntimeBinding() = %#v, %v", binding, err)
	}

	encoded, err := json.Marshal(binder)
	if err != nil || string(encoded) != `{"redacted":true}` {
		t.Fatalf("json.Marshal(Binder) = %s, %v", encoded, err)
	}
	rendered := fmt.Sprintf("%+v %#v", binder, binder)
	for _, forbidden := range []string{
		fixture.targetDefinition.Endpoint.Origin,
		fixture.targetDefinition.CredentialRoleRef,
		fixture.targetDefinition.NetworkPolicyRef,
		fixture.targetDefinition.Endpoint.CABundleFile,
	} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("Binder rendering leaked target material %q: %s", forbidden, rendered)
		}
	}
}

func TestBinderResolvesVictoriaLogsRuntimeComponents(t *testing.T) {
	fixture := newBinderFixture(t, readconnector.KindVictoriaLogs)
	binder, err := readruntime.NewBinder(fixture.connectors, fixture.targets, fixture.profile)
	if err != nil {
		t.Fatalf("NewBinder() error = %v", err)
	}

	resolved, err := investigation.ResolveTaskRuntimeComponents(
		context.Background(), binder.Bind, fixture.scope, fixture.plan,
		[]investigation.TaskSpec{fixture.spec},
	)
	if err != nil || len(resolved) != 1 || resolved[0].ConnectorDigest != fixture.connectorID[len(fixture.connectorID)-64:] ||
		resolved[0].TargetDigest != fixture.targetRef[len(fixture.targetRef)-64:] ||
		resolved[0].ExecutorDigest != readexecutor.CurrentProfileDigest {
		t.Fatalf("ResolveTaskRuntimeComponents(VictoriaLogs) = %#v, %v", resolved, err)
	}
}

func TestBinderFailsClosedOnDependencyAndPersistedFactDrift(t *testing.T) {
	fixture := newBinderFixture(t, readconnector.KindPrometheus)
	for name, dependencies := range map[string]struct {
		connectors *readconnector.Registry
		targets    *readtarget.Registry
		profile    *readexecutor.Profile
	}{
		"nil connectors": {nil, fixture.targets, fixture.profile},
		"nil targets":    {fixture.connectors, nil, fixture.profile},
		"nil profile":    {fixture.connectors, fixture.targets, nil},
		"copied profile": func() struct {
			connectors *readconnector.Registry
			targets    *readtarget.Registry
			profile    *readexecutor.Profile
		} {
			copy := *fixture.profile
			return struct {
				connectors *readconnector.Registry
				targets    *readtarget.Registry
				profile    *readexecutor.Profile
			}{fixture.connectors, fixture.targets, &copy}
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			binder, err := readruntime.NewBinder(dependencies.connectors, dependencies.targets, dependencies.profile)
			if binder != nil || !errors.Is(err, readruntime.ErrBindingRejected) {
				t.Fatalf("NewBinder(%s) = %#v, %v", name, binder, err)
			}
		})
	}

	binder, err := readruntime.NewBinder(fixture.connectors, fixture.targets, fixture.profile)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		scope investigation.TaskSpecScope
		plan  domain.InvestigationPlanBinding
		spec  investigation.TaskSpec
	}{
		"registry digest": {fixture.scope, mutatePlan(fixture.plan, func(plan *domain.InvestigationPlanBinding) {
			plan.RegistryDigest = strings.Repeat("f", 64)
		}), fixture.spec},
		"tenant": {mutateScope(fixture.scope, func(scope *investigation.TaskSpecScope) {
			scope.TenantID = "10000000-0000-4000-8000-000000000099"
		}), fixture.plan, fixture.spec},
		"environment": {mutateScope(fixture.scope, func(scope *investigation.TaskSpecScope) {
			scope.EnvironmentID = "30000000-0000-4000-8000-000000000099"
		}), fixture.plan, fixture.spec},
		"mapping": {mutateScope(fixture.scope, func(scope *investigation.TaskSpecScope) {
			scope.MappingStatus = domain.MappingAmbiguous
		}), fixture.plan, fixture.spec},
		"operation": {fixture.scope, fixture.plan, mutateSpec(fixture.spec, func(spec *investigation.TaskSpec) {
			spec.Operation = "query"
		})},
		"input": {fixture.scope, fixture.plan, mutateSpec(fixture.spec, func(spec *investigation.TaskSpec) {
			spec.Input = json.RawMessage(`{"lookback_minutes":15,"query":"up"}`)
		})},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			components, err := binder.Bind(context.Background(), test.scope, test.plan, test.spec)
			if components != (investigation.TaskRuntimeComponents{}) || !errors.Is(err, readruntime.ErrBindingRejected) {
				t.Fatalf("Bind(%s drift) = %#v, %v", name, components, err)
			}
		})
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if components, err := binder.Bind(cancelled, fixture.scope, fixture.plan, fixture.spec); components != (investigation.TaskRuntimeComponents{}) ||
		!errors.Is(err, context.Canceled) {
		t.Fatalf("Bind(cancelled) = %#v, %v", components, err)
	}
	if components, err := binder.Bind(nil, fixture.scope, fixture.plan, fixture.spec); components != (investigation.TaskRuntimeComponents{}) ||
		!errors.Is(err, readruntime.ErrBindingRejected) {
		t.Fatalf("Bind(nil context) = %#v, %v", components, err)
	}
	var typedNil *nilSafeContext
	if components, err := binder.Bind(typedNil, fixture.scope, fixture.plan, fixture.spec); components != (investigation.TaskRuntimeComponents{}) ||
		!errors.Is(err, readruntime.ErrBindingRejected) {
		t.Fatalf("Bind(typed nil context) = %#v, %v", components, err)
	}
	if components, err := binder.Bind(panicContext{}, fixture.scope, fixture.plan, fixture.spec); components != (investigation.TaskRuntimeComponents{}) ||
		!errors.Is(err, readruntime.ErrBindingRejected) {
		t.Fatalf("Bind(panicking context) = %#v, %v", components, err)
	}
}

type binderFixture struct {
	scope            investigation.TaskSpecScope
	spec             investigation.TaskSpec
	plan             domain.InvestigationPlanBinding
	targetDefinition readtarget.Definition
	targetRef        string
	connectorID      string
	targets          *readtarget.Registry
	connectors       *readconnector.Registry
	egress           *readexecutor.EgressRegistry
	profile          *readexecutor.Profile
}

func newBinderFixture(t *testing.T, kind readconnector.Kind) binderFixture {
	t.Helper()
	now := time.Now().UTC()
	authority, err := testpki.NewAuthority("read-runtime-test-root", now)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	caPath := filepath.Join(directory, "target-ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.Certificate.Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	targetDefinition := readtarget.Definition{
		Scope: readtarget.Scope{TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: environmentID},
		Kind:  kind,
		Endpoint: readtarget.Endpoint{
			Origin:     "https://observability.staging.example.internal:9443",
			ServerName: "observability.staging.example.internal", CABundleFile: caPath,
		},
		CredentialRoleRef: "observability-reader-v1-" + strings.Repeat("a", 64),
	}
	egressDefinition := readexecutor.EgressPolicyDefinition{
		Scope:    readtarget.Scope{TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: environmentID},
		Hostname: "observability.staging.example.internal", Port: 9443,
		AllowedPrefixes: []string{"10.42.9.0/24"},
	}
	egressRef, err := readexecutor.BuildEgressPolicyRef("observability-egress", egressDefinition)
	if err != nil {
		t.Fatal(err)
	}
	egressDefinition.PolicyRef = egressRef
	targetDefinition.NetworkPolicyRef = egressRef
	egress, err := readexecutor.NewEgressRegistry([]readexecutor.EgressPolicyDefinition{egressDefinition})
	if err != nil {
		t.Fatal(err)
	}
	targetRef, err := readtarget.BuildTargetRef("observability-staging", targetDefinition)
	if err != nil {
		t.Fatal(err)
	}
	targetDefinition.TargetRef = targetRef
	targetManifestPath := filepath.Join(directory, "targets.json")
	targetManifest, err := json.Marshal(struct {
		SchemaVersion string                  `json:"schema_version"`
		Targets       []readtarget.Definition `json:"targets"`
	}{readtarget.ManifestSchemaVersion, []readtarget.Definition{targetDefinition}})
	if err != nil {
		t.Fatalf("marshal target manifest: %v", err)
	}
	if err := os.WriteFile(targetManifestPath, targetManifest, 0o600); err != nil {
		t.Fatalf("write target manifest: %v", err)
	}
	targets, err := readtarget.LoadFile(targetManifestPath)
	if err != nil {
		t.Fatal(err)
	}

	connectorDefinition := readconnector.Definition{
		Scope: readconnector.Scope{
			TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: environmentID, ServiceID: serviceID,
		},
		TargetRef: targetRef,
	}
	operation := ""
	switch kind {
	case readconnector.KindPrometheus:
		operation = readconnector.OperationPrometheusRangeQuery
		connectorDefinition.PrometheusRangeQuery = &readconnector.PrometheusRangeQueryV1{
			Expression: "up", StepSeconds: 30, MaxLookbackMinutes: 60, MaxItems: 10, MaxSamples: 121,
		}
	case readconnector.KindVictoriaLogs:
		operation = readconnector.OperationVictoriaLogsSearch
		connectorDefinition.VictoriaLogsSearch = &readconnector.VictoriaLogsSearchV1{
			Query: "error", Limit: 10, MaxLookbackMinutes: 60,
			Fields: []readconnector.FieldSpec{
				{Name: "_time", Type: readconnector.FieldString, Required: true, MaxBytes: 64},
				{Name: "_msg", Type: readconnector.FieldString, Required: true, MaxBytes: 2048},
			},
		}
	default:
		t.Fatalf("unsupported fixture kind %q", kind)
	}
	connectorID, err := readconnector.BuildConnectorID("observability-read", connectorDefinition)
	if err != nil {
		t.Fatal(err)
	}
	connectorDefinition.ConnectorID = connectorID
	connectors, err := readconnector.New([]readconnector.Definition{connectorDefinition})
	if err != nil {
		t.Fatal(err)
	}
	scope := investigation.TaskSpecScope{
		TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: environmentID,
		ServiceID: serviceID, MappingStatus: domain.MappingExact,
	}
	spec := investigation.TaskSpec{
		Key: "primary", ConnectorID: connectorID, Operation: operation,
		Input: json.RawMessage(`{"lookback_minutes":15}`),
	}
	_, tasksHash, err := investigation.CanonicalTaskSpecs([]investigation.TaskSpec{spec})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := readexecutor.NewProfile()
	if err != nil {
		t.Fatal(err)
	}
	return binderFixture{
		scope: scope, spec: spec,
		plan: domain.InvestigationPlanBinding{
			SchemaVersion:  domain.InvestigationPlanBindingSchemaVersion,
			ManifestDigest: strings.Repeat("c", 64), RegistryDigest: connectors.Digest(),
			ProfileDigest: strings.Repeat("d", 64), TasksHash: tasksHash,
		},
		targetDefinition: targetDefinition, targetRef: targetRef, connectorID: connectorID,
		targets: targets, connectors: connectors, egress: egress, profile: profile,
	}
}

func mutateScope(source investigation.TaskSpecScope, mutate func(*investigation.TaskSpecScope)) investigation.TaskSpecScope {
	mutate(&source)
	return source
}

func mutatePlan(source domain.InvestigationPlanBinding, mutate func(*domain.InvestigationPlanBinding)) domain.InvestigationPlanBinding {
	mutate(&source)
	return source
}

func mutateSpec(source investigation.TaskSpec, mutate func(*investigation.TaskSpec)) investigation.TaskSpec {
	source.Input = append(json.RawMessage(nil), source.Input...)
	mutate(&source)
	return source
}

type nilSafeContext struct{}

func (*nilSafeContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*nilSafeContext) Done() <-chan struct{}       { return nil }
func (*nilSafeContext) Err() error                  { return nil }
func (*nilSafeContext) Value(any) any               { return nil }

type panicContext struct{}

func (panicContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (panicContext) Done() <-chan struct{}       { return nil }
func (panicContext) Err() error                  { panic("context error canary") }
func (panicContext) Value(any) any               { return nil }
