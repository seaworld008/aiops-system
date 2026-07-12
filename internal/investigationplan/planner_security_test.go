package investigationplan_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigationplan"
)

func TestNewRejectsUnsafeDefinitions(t *testing.T) {
	registry, connectorID := testRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	valid := testDefinition(registry.Digest(), connectorID)
	otherEnvironment := "30000000-0000-4000-8000-000000000013"
	tests := []struct {
		name   string
		mutate func(*investigationplan.Definition)
		want   error
	}{
		{name: "registry digest empty", mutate: func(value *investigationplan.Definition) { value.RegistryDigest = "" }, want: investigationplan.ErrRegistryMismatch},
		{name: "registry digest uppercase", mutate: func(value *investigationplan.Definition) {
			value.RegistryDigest = strings.ToUpper(value.RegistryDigest)
		}, want: investigationplan.ErrRegistryMismatch},
		{name: "registry digest mismatch", mutate: func(value *investigationplan.Definition) { value.RegistryDigest = strings.Repeat("b", 64) }, want: investigationplan.ErrRegistryMismatch},
		{name: "profiles empty", mutate: func(value *investigationplan.Definition) { value.Profiles = nil }, want: investigationplan.ErrInvalidDefinition},
		{name: "profiles over limit", mutate: func(value *investigationplan.Definition) { value.Profiles = repeatProfile(value.Profiles[0], 1001) }, want: investigationplan.ErrInvalidDefinition},
		{name: "tenant empty", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Scope.TenantID = "" }, want: investigationplan.ErrInvalidDefinition},
		{name: "tenant uppercase", mutate: func(value *investigationplan.Definition) {
			value.Profiles[0].Scope.TenantID = "A0000000-0000-4000-8000-000000000001"
		}, want: investigationplan.ErrInvalidDefinition},
		{name: "tenant uuid v0", mutate: func(value *investigationplan.Definition) {
			value.Profiles[0].Scope.TenantID = "10000000-0000-0000-8000-000000000001"
		}, want: investigationplan.ErrInvalidDefinition},
		{name: "tenant uuid v6", mutate: func(value *investigationplan.Definition) {
			value.Profiles[0].Scope.TenantID = "10000000-0000-6000-8000-000000000001"
		}, want: investigationplan.ErrInvalidDefinition},
		{name: "workspace empty", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Scope.WorkspaceID = "" }, want: investigationplan.ErrInvalidDefinition},
		{name: "workspace uppercase", mutate: func(value *investigationplan.Definition) {
			value.Profiles[0].Scope.WorkspaceID = "B0000000-0000-4000-8000-000000000002"
		}, want: investigationplan.ErrInvalidDefinition},
		{name: "environment empty", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Scope.EnvironmentID = "" }, want: investigationplan.ErrInvalidDefinition},
		{name: "environment malformed", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Scope.EnvironmentID = "staging" }, want: investigationplan.ErrInvalidDefinition},
		{name: "service empty", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Scope.ServiceID = "" }, want: investigationplan.ErrInvalidDefinition},
		{name: "service uppercase", mutate: func(value *investigationplan.Definition) {
			value.Profiles[0].Scope.ServiceID = "D0000000-0000-4000-8000-000000000004"
		}, want: investigationplan.ErrInvalidDefinition},
		{name: "integration empty", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Match.IntegrationID = "" }, want: investigationplan.ErrInvalidDefinition},
		{name: "integration uppercase", mutate: func(value *investigationplan.Definition) {
			value.Profiles[0].Match.IntegrationID = "E0000000-0000-4000-8000-000000000005"
		}, want: investigationplan.ErrInvalidDefinition},
		{name: "integration uuid v0", mutate: func(value *investigationplan.Definition) {
			value.Profiles[0].Match.IntegrationID = "50000000-0000-0000-8000-000000000005"
		}, want: investigationplan.ErrInvalidDefinition},
		{name: "provider empty", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Match.Provider = "" }, want: investigationplan.ErrInvalidDefinition},
		{name: "provider uppercase", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Match.Provider = "Alertmanager" }, want: investigationplan.ErrInvalidDefinition},
		{name: "provider leading punctuation", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Match.Provider = "-alertmanager" }, want: investigationplan.ErrInvalidDefinition},
		{name: "provider control", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Match.Provider = "alert\nmanager" }, want: investigationplan.ErrInvalidDefinition},
		{name: "labels empty", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Match.Labels = nil }, want: investigationplan.ErrInvalidDefinition},
		{name: "labels over limit", mutate: func(value *investigationplan.Definition) {
			value.Profiles[0].Match.Labels = repeatLabel(value.Profiles[0].Match.Labels[0], 17)
		}, want: investigationplan.ErrInvalidDefinition},
		{name: "label key empty", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Match.Labels[0].Key = "" }, want: investigationplan.ErrInvalidDefinition},
		{name: "label key malformed", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Match.Labels[0].Key = "_service" }, want: investigationplan.ErrInvalidDefinition},
		{name: "label value empty", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Match.Labels[0].Value = "" }, want: investigationplan.ErrInvalidDefinition},
		{name: "label value over limit", mutate: func(value *investigationplan.Definition) {
			value.Profiles[0].Match.Labels[0].Value = strings.Repeat("x", 513)
		}, want: investigationplan.ErrInvalidDefinition},
		{name: "label sensitive name", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Match.Labels[0].Key = "access_token" }, want: investigationplan.ErrInvalidDefinition},
		{name: "label duplicate", mutate: func(value *investigationplan.Definition) {
			value.Profiles[0].Match.Labels = append(value.Profiles[0].Match.Labels, value.Profiles[0].Match.Labels[0])
		}, want: investigationplan.ErrInvalidDefinition},
		{name: "tasks empty", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Tasks = nil }, want: investigationplan.ErrInvalidDefinition},
		{name: "tasks over limit", mutate: func(value *investigationplan.Definition) {
			value.Profiles[0].Tasks = repeatTask(value.Profiles[0].Tasks[0], 13)
		}, want: investigationplan.ErrInvalidDefinition},
		{name: "task key uppercase", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Tasks[0].Key = "Metrics" }, want: investigationplan.ErrInvalidDefinition},
		{name: "task key duplicate", mutate: func(value *investigationplan.Definition) {
			value.Profiles[0].Tasks = append(value.Profiles[0].Tasks, value.Profiles[0].Tasks[0])
		}, want: investigationplan.ErrInvalidDefinition},
		{name: "connector empty", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Tasks[0].ConnectorID = "" }, want: investigationplan.ErrInvalidDefinition},
		{name: "connector unauthorized", mutate: func(value *investigationplan.Definition) {
			value.Profiles[0].Tasks[0].ConnectorID = value.Profiles[0].Tasks[0].ConnectorID[:len(value.Profiles[0].Tasks[0].ConnectorID)-1] + "0"
		}, want: investigationplan.ErrInvalidDefinition},
		{name: "operation uppercase", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Tasks[0].Operation = "RANGE_QUERY" }, want: investigationplan.ErrInvalidDefinition},
		{name: "operation unauthorized", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Tasks[0].Operation = "search" }, want: investigationplan.ErrInvalidDefinition},
		{name: "input empty", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Tasks[0].Input = nil }, want: investigationplan.ErrInvalidDefinition},
		{name: "input array", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Tasks[0].Input = json.RawMessage(`[]`) }, want: investigationplan.ErrInvalidDefinition},
		{name: "input target material", mutate: func(value *investigationplan.Definition) {
			value.Profiles[0].Tasks[0].Input = json.RawMessage(`{"endpoint":"https://example.invalid"}`)
		}, want: investigationplan.ErrInvalidDefinition},
		{name: "input unknown contract field", mutate: func(value *investigationplan.Definition) {
			value.Profiles[0].Tasks[0].Input = json.RawMessage(`{"lookback_minutes":15,"extra":true}`)
		}, want: investigationplan.ErrInvalidDefinition},
		{name: "input per task over limit", mutate: func(value *investigationplan.Definition) {
			value.Profiles[0].Tasks[0].Input = json.RawMessage(`{"padding":"` + strings.Repeat("x", 70<<10) + `"}`)
		}, want: investigationplan.ErrInvalidDefinition},
		{name: "scope not authorized by registry", mutate: func(value *investigationplan.Definition) { value.Profiles[0].Scope.EnvironmentID = otherEnvironment }, want: investigationplan.ErrInvalidDefinition},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			definition := cloneDefinition(t, valid)
			test.mutate(&definition)
			if _, err := investigationplan.New(context.Background(), authority, registry, definition); !errors.Is(err, test.want) {
				t.Fatalf("New() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestPlannerAcceptsOnlyItsProcessAuthority(t *testing.T) {
	registry, connectorID := testRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	planner, err := investigationplan.New(context.Background(), authority, registry, testDefinition(registry.Digest(), connectorID))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	copyOfAuthority := *authority
	if !planner.AcceptsAuthority(authority) || !planner.AcceptsAuthority(&copyOfAuthority) {
		t.Fatalf("Planner rejected its own process authority")
	}
	if planner.AcceptsAuthority(nil) || planner.AcceptsAuthority(&investigationplan.ScopeAuthority{}) ||
		planner.AcceptsAuthority(investigationplan.NewScopeAuthority()) {
		t.Fatalf("Planner accepted nil, zero, or foreign authority")
	}
}

func TestNewRejectsOversizedInMemoryDefinitionBeforeCanonicalization(t *testing.T) {
	registry, connectorID := testRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	definition := testDefinition(registry.Digest(), connectorID)
	definition.Profiles = repeatProfile(definition.Profiles[0], 2)
	definition.Profiles[1].Match.Labels[1].Value = "staging-b"
	for profileIndex := range definition.Profiles {
		definition.Profiles[profileIndex].Tasks = repeatTask(definition.Profiles[profileIndex].Tasks[0], 12)
		for taskIndex := range definition.Profiles[profileIndex].Tasks {
			definition.Profiles[profileIndex].Tasks[taskIndex].Key = fmt.Sprintf("task-%02d", taskIndex)
			definition.Profiles[profileIndex].Tasks[taskIndex].Input = json.RawMessage(
				`{"padding":"` + strings.Repeat("x", 48<<10) + `"}`,
			)
		}
	}
	_, err := investigationplan.New(context.Background(), authority, registry, definition)
	if !errors.Is(err, investigationplan.ErrDefinitionTooLarge) ||
		!errors.Is(err, investigationplan.ErrInvalidDefinition) {
		t.Fatalf("New() error = %v, want definition size rejection", err)
	}
}

func TestNewRejectsDefinitionWhoseEscapedManifestExceedsFileLimit(t *testing.T) {
	registry, connectorID := testRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	definition := testDefinition(registry.Digest(), connectorID)
	definition.Profiles = repeatProfile(definition.Profiles[0], 1000)
	for index := range definition.Profiles {
		definition.Profiles[index].Match.Labels = []investigationplan.LabelMatch{{
			Key:   "cluster",
			Value: fmt.Sprintf("%04d", index) + strings.Repeat(`\`, 508),
		}}
	}
	encoded := manifestBytes(t, definition)
	if len(encoded) <= investigationplan.MaximumDefinitionBytes {
		t.Fatalf("escaped manifest size = %d, want > %d", len(encoded), investigationplan.MaximumDefinitionBytes)
	}
	if _, err := investigationplan.New(context.Background(), authority, registry, definition); !errors.Is(err, investigationplan.ErrDefinitionTooLarge) {
		t.Fatalf("New() error = %v, want ErrDefinitionTooLarge for %d-byte manifest", err, len(encoded))
	}
}

func TestNewRejectsRawDefinitionMaterialAboveLimitEvenWhenJSONCompacts(t *testing.T) {
	registry, connectorID := testRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	definition := testDefinition(registry.Digest(), connectorID)
	definition.Profiles = repeatProfile(definition.Profiles[0], 2)
	definition.Profiles[1].Match.Labels[1].Value = "staging-b"
	core := `{"lookback_minutes":15}`
	padding := (64 << 10) - len(core)
	input := json.RawMessage(strings.Repeat(" ", padding/2) + core + strings.Repeat(" ", padding-padding/2))
	rawBytes := 0
	for profileIndex := range definition.Profiles {
		definition.Profiles[profileIndex].Tasks = repeatTask(definition.Profiles[profileIndex].Tasks[0], 12)
		for taskIndex := range definition.Profiles[profileIndex].Tasks {
			definition.Profiles[profileIndex].Tasks[taskIndex].Key = fmt.Sprintf("task-%02d", taskIndex)
			definition.Profiles[profileIndex].Tasks[taskIndex].Input = input
			rawBytes += len(input)
		}
	}
	if rawBytes <= investigationplan.MaximumDefinitionBytes {
		t.Fatalf("raw task bytes = %d, want > %d", rawBytes, investigationplan.MaximumDefinitionBytes)
	}
	if encoded := manifestBytes(t, definition); len(encoded) >= investigationplan.MaximumDefinitionBytes {
		t.Fatalf("compact manifest bytes = %d, want < %d", len(encoded), investigationplan.MaximumDefinitionBytes)
	}
	if _, err := investigationplan.New(context.Background(), authority, registry, definition); !errors.Is(err, investigationplan.ErrDefinitionTooLarge) {
		t.Fatalf("New() error = %v, want ErrDefinitionTooLarge for %d raw task bytes", err, rawBytes)
	}
}

func TestResolveFailsClosedOnUntrustedOrUnmatchedFacts(t *testing.T) {
	registry, connectorID := testRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	planner, err := investigationplan.New(context.Background(), authority, registry, testDefinition(registry.Digest(), connectorID))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	trusted := trustedScope(t, authority, testTenantID, testWorkspaceID)
	tests := []struct {
		name   string
		mutate func(*investigationplan.ResolveRequest)
		want   error
	}{
		{name: "digest empty", mutate: func(value *investigationplan.ResolveRequest) { value.ExpectedPlanDigest = "" }, want: investigationplan.ErrPlanDigestMismatch},
		{name: "digest mismatch", mutate: func(value *investigationplan.ResolveRequest) { value.ExpectedPlanDigest = strings.Repeat("b", 64) }, want: investigationplan.ErrPlanDigestMismatch},
		{name: "trusted scope absent", mutate: func(value *investigationplan.ResolveRequest) {
			value.TrustedScope = investigationplan.TrustedSignalScope{}
		}, want: investigationplan.ErrInvalidRequest},
		{name: "signal id not persistent", mutate: func(value *investigationplan.ResolveRequest) { value.Signal.ID = "signal-1" }, want: investigationplan.ErrInvalidRequest},
		{name: "signal workspace differs", mutate: func(value *investigationplan.ResolveRequest) {
			value.Signal.WorkspaceID = "20000000-0000-4000-8000-000000000012"
		}, want: investigationplan.ErrInvalidRequest},
		{name: "signal integration malformed", mutate: func(value *investigationplan.ResolveRequest) { value.Signal.IntegrationID = "integration" }, want: investigationplan.ErrInvalidRequest},
		{name: "provider unmatched", mutate: func(value *investigationplan.ResolveRequest) { value.Signal.Provider = "prometheus" }, want: investigationplan.ErrMappingUnresolved},
		{name: "integration unmatched", mutate: func(value *investigationplan.ResolveRequest) {
			value.Signal.IntegrationID = "50000000-0000-4000-8000-000000000015"
		}, want: investigationplan.ErrMappingUnresolved},
		{name: "label absent", mutate: func(value *investigationplan.ResolveRequest) { delete(value.Signal.Labels, "cluster") }, want: investigationplan.ErrMappingUnresolved},
		{name: "label differs", mutate: func(value *investigationplan.ResolveRequest) { value.Signal.Labels["cluster"] = "production" }, want: investigationplan.ErrMappingUnresolved},
		{name: "invalid status", mutate: func(value *investigationplan.ResolveRequest) { value.Signal.Status = "unknown" }, want: investigationplan.ErrInvalidRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := investigationplan.ResolveRequest{
				ExpectedPlanDigest: planner.ManifestDigest(), TrustedScope: trusted, Signal: validSignal(),
			}
			test.mutate(&request)
			if _, err := planner.Resolve(context.Background(), request); !errors.Is(err, test.want) {
				t.Fatalf("Resolve() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestScopeAuthorityBindsTrustedScopeToItsAuthority(t *testing.T) {
	registry, connectorID := testRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	planner, err := investigationplan.New(
		context.Background(), authority, registry, testDefinition(registry.Digest(), connectorID),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	registration := investigationplan.TrustedSignalRegistration{
		TenantID: testTenantID, WorkspaceID: testWorkspaceID,
	}
	sameScope, err := authority.Attest(registration)
	if err != nil {
		t.Fatalf("ScopeAuthority.Attest() error = %v", err)
	}
	request := investigationplan.ResolveRequest{
		ExpectedPlanDigest: planner.ManifestDigest(), TrustedScope: sameScope, Signal: validSignal(),
	}
	if _, err := planner.Resolve(context.Background(), request); err != nil {
		t.Fatalf("Resolve(same authority) error = %v", err)
	}
	changed := testDefinition(registry.Digest(), connectorID)
	changed.Profiles[0].Tasks[0].Input = json.RawMessage(`{"lookback_minutes":20}`)
	secondPlanner, err := investigationplan.New(context.Background(), authority, registry, changed)
	if err != nil {
		t.Fatalf("New(second Planner) error = %v", err)
	}
	request.ExpectedPlanDigest = secondPlanner.ManifestDigest()
	if _, err := secondPlanner.Resolve(context.Background(), request); err != nil {
		t.Fatalf("Resolve(same authority, second Planner) error = %v", err)
	}
	request.ExpectedPlanDigest = planner.ManifestDigest()
	if _, err := secondPlanner.Resolve(context.Background(), request); !errors.Is(err, investigationplan.ErrPlanDigestMismatch) {
		t.Fatalf("Resolve(wrong Planner digest) error = %v, want ErrPlanDigestMismatch", err)
	}
	request.ExpectedPlanDigest = planner.ManifestDigest()

	foreign := investigationplan.NewScopeAuthority()
	request.TrustedScope, err = foreign.Attest(registration)
	if err != nil {
		t.Fatalf("foreign ScopeAuthority.Attest() error = %v", err)
	}
	if _, err := planner.Resolve(context.Background(), request); !errors.Is(err, investigationplan.ErrInvalidRequest) {
		t.Fatalf("Resolve(foreign authority) error = %v, want ErrInvalidRequest", err)
	}

	copiedAuthority := *authority
	request.TrustedScope, err = (&copiedAuthority).Attest(registration)
	if err != nil {
		t.Fatalf("copied ScopeAuthority.Attest() error = %v", err)
	}
	copiedScope := request.TrustedScope
	request.TrustedScope = copiedScope
	if _, err := planner.Resolve(context.Background(), request); err != nil {
		t.Fatalf("Resolve(copied authority/scope) error = %v", err)
	}
}

func TestScopeAuthorityRejectsNilZeroAndDirectRegistrationPromotion(t *testing.T) {
	registration := investigationplan.TrustedSignalRegistration{
		TenantID: testTenantID, WorkspaceID: testWorkspaceID,
	}
	var nilAuthority *investigationplan.ScopeAuthority
	if _, err := nilAuthority.Attest(registration); !errors.Is(err, investigationplan.ErrInvalidRequest) {
		t.Fatalf("nil ScopeAuthority.Attest() error = %v", err)
	}
	zeroAuthority := &investigationplan.ScopeAuthority{}
	if _, err := zeroAuthority.Attest(registration); !errors.Is(err, investigationplan.ErrInvalidRequest) {
		t.Fatalf("zero ScopeAuthority.Attest() error = %v", err)
	}
	registry, connectorID := testRegistry(t)
	definition := testDefinition(registry.Digest(), connectorID)
	for name, authority := range map[string]*investigationplan.ScopeAuthority{
		"nil": nil, "zero": zeroAuthority,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := investigationplan.New(context.Background(), authority, registry, definition); !errors.Is(err, investigationplan.ErrInvalidRequest) {
				t.Fatalf("New() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
	if _, found := reflect.TypeOf(registration).MethodByName("Scope"); found {
		t.Fatal("TrustedSignalRegistration exposes a direct Scope promotion method")
	}
}

func TestPlannerDetachesRetainedStringsFromLargeBackings(t *testing.T) {
	registry, connectorID := testRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	digestSource := strings.Repeat("x", 1<<20) + registry.Digest()
	labelSource := strings.Repeat("x", 1<<20) + "payments"
	tenantSource := strings.Repeat("x", 1<<20) + testTenantID
	digestView := digestSource[len(digestSource)-len(registry.Digest()):]
	labelView := labelSource[len(labelSource)-len("payments"):]
	tenantView := tenantSource[len(tenantSource)-len(testTenantID):]
	tenantSourcePointer := unsafe.StringData(tenantView)

	definition := testDefinition(digestView, connectorID)
	definition.Profiles[0].Scope.TenantID = tenantView
	definition.Profiles[0].Match.Labels[0].Value = labelView
	planner, err := investigationplan.New(context.Background(), authority, registry, definition)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	trusted, err := authority.Attest(investigationplan.TrustedSignalRegistration{
		TenantID: tenantView, WorkspaceID: testWorkspaceID,
	})
	if err != nil {
		t.Fatalf("ScopeAuthority.Attest() error = %v", err)
	}
	if unsafe.StringData(planner.RegistryDigest()) == unsafe.StringData(digestView) {
		t.Fatal("Planner retained the large registry-digest backing string")
	}
	digestSource, labelSource, tenantSource = "", "", ""
	digestView, labelView, tenantView = "", "", ""
	definition = investigationplan.Definition{}
	runtime.GC()

	if planner.RegistryDigest() != registry.Digest() {
		t.Fatalf("Planner retained registry digest backing: %q", planner.RegistryDigest())
	}
	plan, err := planner.Resolve(context.Background(), investigationplan.ResolveRequest{
		ExpectedPlanDigest: planner.ManifestDigest(), TrustedScope: trusted, Signal: validSignal(),
	})
	if err != nil {
		t.Fatalf("Resolve() after source backing release error = %v", err)
	}
	if plan.Scope().TenantID != testTenantID {
		t.Fatalf("Plan.Scope().TenantID = %q", plan.Scope().TenantID)
	}
	if unsafe.StringData(plan.Scope().TenantID) == tenantSourcePointer {
		t.Fatal("Plan retained the large tenant backing string")
	}
}

func TestPlannerDigestAndCorrelationSemanticsAreStable(t *testing.T) {
	registry, connectorID := testRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	definition := testDefinition(registry.Digest(), connectorID)
	definition.Profiles[0].Tasks = append(definition.Profiles[0].Tasks, investigationplan.TaskDefinition{
		Key: "metrics-short", ConnectorID: connectorID, Operation: definition.Profiles[0].Tasks[0].Operation,
		Input: json.RawMessage(`{"lookback_minutes":10}`),
	})
	planner, err := investigationplan.New(context.Background(), authority, registry, definition)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	reordered := cloneDefinition(t, definition)
	reordered.Profiles[0].Match.Labels[0], reordered.Profiles[0].Match.Labels[1] =
		reordered.Profiles[0].Match.Labels[1], reordered.Profiles[0].Match.Labels[0]
	reordered.Profiles[0].Tasks[0], reordered.Profiles[0].Tasks[1] =
		reordered.Profiles[0].Tasks[1], reordered.Profiles[0].Tasks[0]
	reorderedPlanner, err := investigationplan.New(context.Background(), authority, registry, reordered)
	if err != nil {
		t.Fatalf("New(reordered) error = %v", err)
	}
	if reorderedPlanner.ManifestDigest() != planner.ManifestDigest() {
		t.Fatalf("manifest digest changed under semantic reorder: %q != %q", reorderedPlanner.ManifestDigest(), planner.ManifestDigest())
	}
	trusted := trustedScope(t, authority, testTenantID, testWorkspaceID)
	plan := resolvePlan(t, planner, trusted, validSignal())
	reorderedPlan := resolvePlan(t, reorderedPlanner, trusted, validSignal())
	if reorderedPlan.ProfileDigest() != plan.ProfileDigest() || reorderedPlan.TasksHash() != plan.TasksHash() {
		t.Fatal("profile or tasks digest changed under semantic reorder")
	}
	multiple := cloneDefinition(t, definition)
	multiple.Profiles = repeatProfile(multiple.Profiles[0], 2)
	multiple.Profiles[1].Match.Labels[1].Value = "staging-b"
	multiplePlanner, err := investigationplan.New(context.Background(), authority, registry, multiple)
	if err != nil {
		t.Fatalf("New(multiple) error = %v", err)
	}
	multiple.Profiles[0], multiple.Profiles[1] = multiple.Profiles[1], multiple.Profiles[0]
	reorderedProfilesPlanner, err := investigationplan.New(context.Background(), authority, registry, multiple)
	if err != nil {
		t.Fatalf("New(reordered profiles) error = %v", err)
	}
	if multiplePlanner.ManifestDigest() != reorderedProfilesPlanner.ManifestDigest() {
		t.Fatal("manifest digest changed under profile reorder")
	}

	changed := cloneDefinition(t, definition)
	changed.Profiles[0].Tasks[0].Input = json.RawMessage(`{"lookback_minutes":20}`)
	changedPlanner, err := investigationplan.New(context.Background(), authority, registry, changed)
	if err != nil {
		t.Fatalf("New(changed) error = %v", err)
	}
	changedPlan := resolvePlan(t, changedPlanner, trusted, validSignal())
	if changedPlanner.ManifestDigest() == planner.ManifestDigest() || changedPlan.ProfileDigest() == plan.ProfileDigest() ||
		changedPlan.TasksHash() == plan.TasksHash() {
		t.Fatal("task semantic change did not change all plan digests")
	}
	if changedPlan.CorrelateSignalRequest().CorrelationKey != plan.CorrelateSignalRequest().CorrelationKey {
		t.Fatal("correlation key incorrectly depends on tasks or plan digest")
	}

	semanticallySameSignal := validSignal()
	semanticallySameSignal.Status = "resolved"
	semanticallySameSignal.ProviderEventID = "event-2"
	semanticallySameSignal.PayloadHash = strings.Repeat("b", 64)
	semanticallySameSignal.ObservedAt = semanticallySameSignal.ObservedAt.Add(time.Hour)
	semanticallySameSignal.Labels["ignored"] = "extra"
	sameCorrelation := resolvePlan(t, planner, trusted, semanticallySameSignal).CorrelateSignalRequest().CorrelationKey
	if sameCorrelation != plan.CorrelateSignalRequest().CorrelationKey {
		t.Fatal("correlation key depends on status/time/event/payload/raw extra labels")
	}
	differentFingerprint := validSignal()
	differentFingerprint.Fingerprint = "payments-staging-errors"
	if resolvePlan(t, planner, trusted, differentFingerprint).CorrelateSignalRequest().CorrelationKey == plan.CorrelateSignalRequest().CorrelationKey {
		t.Fatal("correlation key does not bind fingerprint")
	}
}

func TestPlannerRejectsOverlappingProfilesAndAcceptsProvenDisjointProfiles(t *testing.T) {
	registry, connectorID := testRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	definition := testDefinition(registry.Digest(), connectorID)
	definition.Profiles = repeatProfile(definition.Profiles[0], 2)
	definition.Profiles[1].Match.Labels = []investigationplan.LabelMatch{{Key: "region", Value: "us-east"}}
	if _, err := investigationplan.New(context.Background(), authority, registry, definition); !errors.Is(err, investigationplan.ErrProfileOverlap) {
		t.Fatalf("New(overlap) error = %v, want ErrProfileOverlap", err)
	}
	definition.Profiles[1].Match.Labels = []investigationplan.LabelMatch{
		{Key: "service", Value: "payments"}, {Key: "cluster", Value: "staging-b"},
	}
	planner, err := investigationplan.New(context.Background(), authority, registry, definition)
	if err != nil {
		t.Fatalf("New(disjoint) error = %v", err)
	}
	signal := validSignal()
	signal.Labels["cluster"] = "staging-b"
	if _, err := planner.Resolve(context.Background(), investigationplan.ResolveRequest{
		ExpectedPlanDigest: planner.ManifestDigest(),
		TrustedScope:       trustedScope(t, authority, testTenantID, testWorkspaceID),
		Signal:             signal,
	}); err != nil {
		t.Fatalf("Resolve(disjoint) error = %v", err)
	}
}

func TestPlannerPlanAndTrustedScopeAreRedactedAndNonUnmarshalable(t *testing.T) {
	registry, connectorID := testRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	planner, err := investigationplan.New(context.Background(), authority, registry, testDefinition(registry.Digest(), connectorID))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	trusted := trustedScope(t, authority, testTenantID, testWorkspaceID)
	registration := investigationplan.TrustedSignalRegistration{TenantID: testTenantID, WorkspaceID: testWorkspaceID}
	plan := resolvePlan(t, planner, trusted, validSignal())
	for name, value := range map[string]any{
		"authority": authority, "planner": planner, "plan": plan,
		"registration": registration, "trusted": trusted,
	} {
		t.Run(name, func(t *testing.T) {
			formatted := fmt.Sprintf("%v|%#v|%+v", value, value, value)
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			combined := formatted + string(encoded)
			for _, forbidden := range []string{testTenantID, testWorkspaceID, testEnvironmentID, testServiceID, connectorID} {
				if strings.Contains(combined, forbidden) {
					t.Fatalf("redacted value leaked %q through %q", forbidden, combined)
				}
			}
		})
	}
	if err := json.Unmarshal([]byte(`{"redacted":true}`), &trusted); !errors.Is(err, investigationplan.ErrInvalidRequest) {
		t.Fatalf("TrustedSignalScope.UnmarshalJSON() error = %v", err)
	}
	if err := json.Unmarshal([]byte(`{"redacted":true}`), &registration); !errors.Is(err, investigationplan.ErrInvalidRequest) {
		t.Fatalf("TrustedSignalRegistration.UnmarshalJSON() error = %v", err)
	}
	var decodedAuthority investigationplan.ScopeAuthority
	if err := json.Unmarshal([]byte(`{"redacted":true}`), &decodedAuthority); !errors.Is(err, investigationplan.ErrInvalidRequest) {
		t.Fatalf("ScopeAuthority.UnmarshalJSON() error = %v", err)
	}
	if err := json.Unmarshal([]byte(`{"redacted":true}`), &plan); !errors.Is(err, investigationplan.ErrInvalidRequest) {
		t.Fatalf("Plan.UnmarshalJSON() error = %v", err)
	}
	if err := json.Unmarshal([]byte(`{"redacted":true}`), planner); !errors.Is(err, investigationplan.ErrManifestDefinition) {
		t.Fatalf("Planner.UnmarshalJSON() error = %v", err)
	}
}

func TestPlannerReadyNilAndContextCancellation(t *testing.T) {
	registry, connectorID := testRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	var nilPlanner *investigationplan.Planner
	if nilPlanner.Ready() || nilPlanner.ManifestDigest() != "" || nilPlanner.RegistryDigest() != "" {
		t.Fatal("nil Planner reports ready state")
	}
	if _, err := nilPlanner.Resolve(context.Background(), investigationplan.ResolveRequest{}); !errors.Is(err, investigationplan.ErrPlanDigestMismatch) {
		t.Fatalf("nil Planner Resolve() error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := investigationplan.New(cancelled, authority, registry, testDefinition(registry.Digest(), connectorID)); !errors.Is(err, context.Canceled) {
		t.Fatalf("New(cancelled) error = %v", err)
	}
	planner, err := investigationplan.New(context.Background(), authority, registry, testDefinition(registry.Digest(), connectorID))
	if err != nil || !planner.Ready() {
		t.Fatalf("New() = %#v, %v", planner, err)
	}
	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, err := planner.Resolve(deadline, investigationplan.ResolveRequest{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Resolve(deadline) error = %v", err)
	}
}

func TestInvestigationPlanV1GoldenDigests(t *testing.T) {
	registry, connectorID := testRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	planner, err := investigationplan.New(context.Background(), authority, registry, testDefinition(registry.Digest(), connectorID))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	plan := resolvePlan(t, planner, trustedScope(t, authority, testTenantID, testWorkspaceID), validSignal())
	got := map[string]string{
		"registry":    registry.Digest(),
		"manifest":    planner.ManifestDigest(),
		"profile":     plan.ProfileDigest(),
		"tasks":       plan.TasksHash(),
		"correlation": plan.CorrelateSignalRequest().CorrelationKey,
	}
	want := map[string]string{
		"registry":    "7ab132dddd812c1a4ee531b4fe8ce10bd6326d768b69796c53d8c87ff27ba680",
		"manifest":    "24598b4bfab3c2bd1c0dbd7a32efb4213575803c97f05663fffdb2f70acec5cf",
		"profile":     "11afccf69dcd45bfb1f796d6b541b64f1af943d2a92feb6ca63a37322c0ad020",
		"tasks":       "9649a920bf23d6bcfff48a1aa4e71628c750b5e75528291065f287424367e3d6",
		"correlation": "corr.v1.ec495239aa517f9142cb7a7d0e3f870befd397f7bcc3c88c422809465b497a52",
	}
	for name, expected := range want {
		if got[name] != expected {
			t.Errorf("%s golden = %q, want %q", name, got[name], expected)
		}
	}
}

func TestPlannerConcurrentResolveReturnsDetachedPlans(t *testing.T) {
	registry, connectorID := testRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	planner, err := investigationplan.New(context.Background(), authority, registry, testDefinition(registry.Digest(), connectorID))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	trusted := trustedScope(t, authority, testTenantID, testWorkspaceID)
	const workers = 32
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			plan, err := planner.Resolve(context.Background(), investigationplan.ResolveRequest{
				ExpectedPlanDigest: planner.ManifestDigest(), TrustedScope: trusted, Signal: validSignal(),
			})
			if err != nil {
				errorsChannel <- err
				return
			}
			tasks := plan.TaskSpecs()
			tasks[0].Input[0] = 'x'
			if string(plan.TaskSpecs()[0].Input) != `{"lookback_minutes":15}` {
				errorsChannel <- errors.New("task input aliases concurrent caller")
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Errorf("concurrent Resolve() error = %v", err)
	}
}

func cloneDefinition(t *testing.T, source investigationplan.Definition) investigationplan.Definition {
	t.Helper()
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var cloned investigationplan.Definition
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	return cloned
}

func repeatProfile(source investigationplan.ProfileDefinition, count int) []investigationplan.ProfileDefinition {
	profiles := make([]investigationplan.ProfileDefinition, count)
	for index := range profiles {
		profiles[index] = source
		profiles[index].Match.Labels = append([]investigationplan.LabelMatch(nil), source.Match.Labels...)
		profiles[index].Tasks = append([]investigationplan.TaskDefinition(nil), source.Tasks...)
	}
	return profiles
}

func repeatLabel(source investigationplan.LabelMatch, count int) []investigationplan.LabelMatch {
	labels := make([]investigationplan.LabelMatch, count)
	for index := range labels {
		labels[index] = source
		labels[index].Key = fmt.Sprintf("label-%02d", index)
	}
	return labels
}

func repeatTask(source investigationplan.TaskDefinition, count int) []investigationplan.TaskDefinition {
	tasks := make([]investigationplan.TaskDefinition, count)
	for index := range tasks {
		tasks[index] = source
		tasks[index].Input = append(json.RawMessage(nil), source.Input...)
	}
	return tasks
}

func trustedScope(
	t *testing.T,
	authority *investigationplan.ScopeAuthority,
	tenantID string,
	workspaceID string,
) investigationplan.TrustedSignalScope {
	t.Helper()
	scope, err := authority.Attest(investigationplan.TrustedSignalRegistration{
		TenantID: tenantID, WorkspaceID: workspaceID,
	})
	if err != nil {
		t.Fatalf("ScopeAuthority.Attest() error = %v", err)
	}
	return scope
}

func resolvePlan(t *testing.T, planner *investigationplan.Planner, trusted investigationplan.TrustedSignalScope, signal domain.Signal) investigationplan.Plan {
	t.Helper()
	plan, err := planner.Resolve(context.Background(), investigationplan.ResolveRequest{
		ExpectedPlanDigest: planner.ManifestDigest(), TrustedScope: trusted, Signal: signal,
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	return plan
}
