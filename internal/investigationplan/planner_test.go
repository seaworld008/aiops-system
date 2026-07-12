package investigationplan_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigationplan"
	"github.com/seaworld008/aiops-system/internal/readconnector"
)

const (
	testTenantID      = "10000000-0000-4000-8000-000000000001"
	testWorkspaceID   = "20000000-0000-4000-8000-000000000002"
	testEnvironmentID = "30000000-0000-4000-8000-000000000003"
	testServiceID     = "40000000-0000-4000-8000-000000000004"
	testIntegrationID = "50000000-0000-4000-8000-000000000005"
	testSignalID      = "60000000-0000-4000-8000-000000000006"
)

func TestPlannerResolvesTrustedExactSignalToDetachedPlan(t *testing.T) {
	registry, connectorID := testRegistry(t)
	planner, err := investigationplan.New(context.Background(), registry, investigationplan.Definition{
		RegistryDigest: registry.Digest(),
		Profiles: []investigationplan.ProfileDefinition{{
			Scope: investigationplan.Scope{
				TenantID: testTenantID, WorkspaceID: testWorkspaceID,
				EnvironmentID: testEnvironmentID, ServiceID: testServiceID,
			},
			Match: investigationplan.MatchDefinition{
				IntegrationID: testIntegrationID,
				Provider:      "alertmanager",
				Labels: []investigationplan.LabelMatch{
					{Key: "service", Value: "payments"},
					{Key: "cluster", Value: "staging-a"},
				},
			},
			Tasks: []investigationplan.TaskDefinition{{
				Key: "metrics", ConnectorID: connectorID, Operation: readconnector.OperationPrometheusRangeQuery,
				Input: json.RawMessage(`{"lookback_minutes":15}`),
			}},
		}},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	trusted, err := (investigationplan.TrustedSignalRegistration{
		TenantID: testTenantID, WorkspaceID: testWorkspaceID,
	}).Scope()
	if err != nil {
		t.Fatalf("TrustedSignalRegistration.Scope() error = %v", err)
	}
	signal := validSignal()
	signal.Labels["severity"] = "critical"
	plan, err := planner.Resolve(context.Background(), investigationplan.ResolveRequest{
		ExpectedPlanDigest: planner.ManifestDigest(), TrustedScope: trusted, Signal: signal,
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if plan.ManifestDigest() != planner.ManifestDigest() || plan.RegistryDigest() != registry.Digest() ||
		!domain.ValidSHA256Hex(plan.ProfileDigest()) || !domain.ValidSHA256Hex(plan.TasksHash()) {
		t.Fatalf("resolved plan digests are invalid")
	}
	scope := plan.Scope()
	if scope.TenantID != testTenantID || scope.WorkspaceID != testWorkspaceID ||
		scope.EnvironmentID != testEnvironmentID || scope.ServiceID != testServiceID ||
		scope.MappingStatus != domain.MappingExact {
		t.Fatalf("Plan.Scope() = %#v", scope)
	}
	correlation := plan.CorrelateSignalRequest()
	if correlation.WorkspaceID != testWorkspaceID || correlation.SignalID != testSignalID ||
		correlation.ServiceID != testServiceID || correlation.EnvironmentID != testEnvironmentID ||
		correlation.MappingStatus != domain.MappingExact || !domain.ValidCorrelationKey(correlation.CorrelationKey) {
		t.Fatalf("Plan.CorrelateSignalRequest() = %#v", correlation)
	}
	tasks := plan.TaskSpecs()
	if len(tasks) != 1 || tasks[0].Key != "metrics" || tasks[0].ConnectorID != connectorID ||
		string(tasks[0].Input) != `{"lookback_minutes":15}` {
		t.Fatalf("Plan.TaskSpecs() = %#v", tasks)
	}
	tasks[0].Input[0] = 'x'
	if got := plan.TaskSpecs(); string(got[0].Input) != `{"lookback_minutes":15}` {
		t.Fatalf("Plan.TaskSpecs() aliases caller mutation: %#v", got)
	}
}

func validSignal() domain.Signal {
	return domain.Signal{
		ID: testSignalID, WorkspaceID: testWorkspaceID, IntegrationID: testIntegrationID,
		Provider: "alertmanager", ProviderEventID: "event-1",
		PayloadHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Fingerprint: "payments-staging-latency", Status: "firing",
		Labels:     map[string]string{"service": "payments", "cluster": "staging-a"},
		ObservedAt: time.Date(2026, 7, 12, 2, 0, 0, 0, time.UTC),
	}
}

func testRegistry(t *testing.T) (*readconnector.Registry, string) {
	t.Helper()
	definition := readconnector.Definition{
		Scope: readconnector.Scope{
			TenantID: testTenantID, WorkspaceID: testWorkspaceID,
			EnvironmentID: testEnvironmentID, ServiceID: testServiceID,
		},
		TargetRef: "prometheus-staging-v1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		PrometheusRangeQuery: &readconnector.PrometheusRangeQueryV1{
			Expression: "up", StepSeconds: 30, MaxLookbackMinutes: 60, MaxItems: 100, MaxSamples: 121,
		},
	}
	connectorID, err := readconnector.BuildConnectorID("prometheus-staging", definition)
	if err != nil {
		t.Fatalf("BuildConnectorID() error = %v", err)
	}
	definition.ConnectorID = connectorID
	registry, err := readconnector.New([]readconnector.Definition{definition})
	if err != nil {
		t.Fatalf("readconnector.New() error = %v", err)
	}
	return registry, connectorID
}
