package investigationplan_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigationplan"
)

func TestNewRejectsUnsafeDefinitions(t *testing.T) {
	registry, connectorID := testRegistry(t)
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
			if _, err := investigationplan.New(context.Background(), registry, definition); !errors.Is(err, test.want) {
				t.Fatalf("New() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNewRejectsOversizedInMemoryDefinitionBeforeCanonicalization(t *testing.T) {
	registry, connectorID := testRegistry(t)
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
	_, err := investigationplan.New(context.Background(), registry, definition)
	if !errors.Is(err, investigationplan.ErrDefinitionTooLarge) ||
		!errors.Is(err, investigationplan.ErrInvalidDefinition) {
		t.Fatalf("New() error = %v, want definition size rejection", err)
	}
}

func TestResolveFailsClosedOnUntrustedOrUnmatchedFacts(t *testing.T) {
	registry, connectorID := testRegistry(t)
	planner, err := investigationplan.New(context.Background(), registry, testDefinition(registry.Digest(), connectorID))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	trusted := trustedScope(t, testTenantID, testWorkspaceID)
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

func TestPlannerDigestAndCorrelationSemanticsAreStable(t *testing.T) {
	registry, connectorID := testRegistry(t)
	definition := testDefinition(registry.Digest(), connectorID)
	definition.Profiles[0].Tasks = append(definition.Profiles[0].Tasks, investigationplan.TaskDefinition{
		Key: "metrics-short", ConnectorID: connectorID, Operation: definition.Profiles[0].Tasks[0].Operation,
		Input: json.RawMessage(`{"lookback_minutes":10}`),
	})
	planner, err := investigationplan.New(context.Background(), registry, definition)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	reordered := cloneDefinition(t, definition)
	reordered.Profiles[0].Match.Labels[0], reordered.Profiles[0].Match.Labels[1] =
		reordered.Profiles[0].Match.Labels[1], reordered.Profiles[0].Match.Labels[0]
	reordered.Profiles[0].Tasks[0], reordered.Profiles[0].Tasks[1] =
		reordered.Profiles[0].Tasks[1], reordered.Profiles[0].Tasks[0]
	reorderedPlanner, err := investigationplan.New(context.Background(), registry, reordered)
	if err != nil {
		t.Fatalf("New(reordered) error = %v", err)
	}
	if reorderedPlanner.ManifestDigest() != planner.ManifestDigest() {
		t.Fatalf("manifest digest changed under semantic reorder: %q != %q", reorderedPlanner.ManifestDigest(), planner.ManifestDigest())
	}
	trusted := trustedScope(t, testTenantID, testWorkspaceID)
	plan := resolvePlan(t, planner, trusted, validSignal())
	reorderedPlan := resolvePlan(t, reorderedPlanner, trusted, validSignal())
	if reorderedPlan.ProfileDigest() != plan.ProfileDigest() || reorderedPlan.TasksHash() != plan.TasksHash() {
		t.Fatal("profile or tasks digest changed under semantic reorder")
	}
	multiple := cloneDefinition(t, definition)
	multiple.Profiles = repeatProfile(multiple.Profiles[0], 2)
	multiple.Profiles[1].Match.Labels[1].Value = "staging-b"
	multiplePlanner, err := investigationplan.New(context.Background(), registry, multiple)
	if err != nil {
		t.Fatalf("New(multiple) error = %v", err)
	}
	multiple.Profiles[0], multiple.Profiles[1] = multiple.Profiles[1], multiple.Profiles[0]
	reorderedProfilesPlanner, err := investigationplan.New(context.Background(), registry, multiple)
	if err != nil {
		t.Fatalf("New(reordered profiles) error = %v", err)
	}
	if multiplePlanner.ManifestDigest() != reorderedProfilesPlanner.ManifestDigest() {
		t.Fatal("manifest digest changed under profile reorder")
	}

	changed := cloneDefinition(t, definition)
	changed.Profiles[0].Tasks[0].Input = json.RawMessage(`{"lookback_minutes":20}`)
	changedPlanner, err := investigationplan.New(context.Background(), registry, changed)
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
	definition := testDefinition(registry.Digest(), connectorID)
	definition.Profiles = repeatProfile(definition.Profiles[0], 2)
	definition.Profiles[1].Match.Labels = []investigationplan.LabelMatch{{Key: "region", Value: "us-east"}}
	if _, err := investigationplan.New(context.Background(), registry, definition); !errors.Is(err, investigationplan.ErrProfileOverlap) {
		t.Fatalf("New(overlap) error = %v, want ErrProfileOverlap", err)
	}
	definition.Profiles[1].Match.Labels = []investigationplan.LabelMatch{
		{Key: "service", Value: "payments"}, {Key: "cluster", Value: "staging-b"},
	}
	planner, err := investigationplan.New(context.Background(), registry, definition)
	if err != nil {
		t.Fatalf("New(disjoint) error = %v", err)
	}
	signal := validSignal()
	signal.Labels["cluster"] = "staging-b"
	if _, err := planner.Resolve(context.Background(), investigationplan.ResolveRequest{
		ExpectedPlanDigest: planner.ManifestDigest(),
		TrustedScope:       trustedScope(t, testTenantID, testWorkspaceID),
		Signal:             signal,
	}); err != nil {
		t.Fatalf("Resolve(disjoint) error = %v", err)
	}
}

func TestPlannerPlanAndTrustedScopeAreRedactedAndNonUnmarshalable(t *testing.T) {
	registry, connectorID := testRegistry(t)
	planner, err := investigationplan.New(context.Background(), registry, testDefinition(registry.Digest(), connectorID))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	trusted := trustedScope(t, testTenantID, testWorkspaceID)
	registration := investigationplan.TrustedSignalRegistration{TenantID: testTenantID, WorkspaceID: testWorkspaceID}
	plan := resolvePlan(t, planner, trusted, validSignal())
	for name, value := range map[string]any{"planner": planner, "plan": plan, "registration": registration, "trusted": trusted} {
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
	if err := json.Unmarshal([]byte(`{"redacted":true}`), &plan); !errors.Is(err, investigationplan.ErrInvalidRequest) {
		t.Fatalf("Plan.UnmarshalJSON() error = %v", err)
	}
	if err := json.Unmarshal([]byte(`{"redacted":true}`), planner); !errors.Is(err, investigationplan.ErrManifestDefinition) {
		t.Fatalf("Planner.UnmarshalJSON() error = %v", err)
	}
}

func TestPlannerReadyNilAndContextCancellation(t *testing.T) {
	registry, connectorID := testRegistry(t)
	var nilPlanner *investigationplan.Planner
	if nilPlanner.Ready() || nilPlanner.ManifestDigest() != "" || nilPlanner.RegistryDigest() != "" {
		t.Fatal("nil Planner reports ready state")
	}
	if _, err := nilPlanner.Resolve(context.Background(), investigationplan.ResolveRequest{}); !errors.Is(err, investigationplan.ErrPlanDigestMismatch) {
		t.Fatalf("nil Planner Resolve() error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := investigationplan.New(cancelled, registry, testDefinition(registry.Digest(), connectorID)); !errors.Is(err, context.Canceled) {
		t.Fatalf("New(cancelled) error = %v", err)
	}
	planner, err := investigationplan.New(context.Background(), registry, testDefinition(registry.Digest(), connectorID))
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
	planner, err := investigationplan.New(context.Background(), registry, testDefinition(registry.Digest(), connectorID))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	plan := resolvePlan(t, planner, trustedScope(t, testTenantID, testWorkspaceID), validSignal())
	got := map[string]string{
		"registry":    registry.Digest(),
		"manifest":    planner.ManifestDigest(),
		"profile":     plan.ProfileDigest(),
		"tasks":       plan.TasksHash(),
		"correlation": plan.CorrelateSignalRequest().CorrelationKey,
	}
	want := map[string]string{
		"registry":    "e936b99babbd772561ab9e059530c918d635ff5430614691f828d19005ee3c32",
		"manifest":    "141e51b8790fb2bdf89329e36fc588fd1ca6bfea575f100b1a1a984e226193a0",
		"profile":     "8306af2765d24a5b85d7e14f2ed2e1003a075c614fe2a6533037eedef402041c",
		"tasks":       "77e3e084cd46c0c0d3fc5f2424961152e01a784fa773ed69d29bc30c5b3113d2",
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
	planner, err := investigationplan.New(context.Background(), registry, testDefinition(registry.Digest(), connectorID))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	trusted := trustedScope(t, testTenantID, testWorkspaceID)
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

func trustedScope(t *testing.T, tenantID, workspaceID string) investigationplan.TrustedSignalScope {
	t.Helper()
	scope, err := (investigationplan.TrustedSignalRegistration{TenantID: tenantID, WorkspaceID: workspaceID}).Scope()
	if err != nil {
		t.Fatalf("TrustedSignalRegistration.Scope() error = %v", err)
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
