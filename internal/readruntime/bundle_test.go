package readruntime_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/readexecutor"
	"github.com/seaworld008/aiops-system/internal/readruntime"
	"github.com/seaworld008/aiops-system/internal/readtarget"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

func TestBundleAtomicallyAuthorizesBindsAndPreparesExactRuntime(t *testing.T) {
	fixture := newBinderFixture(t, readconnector.KindPrometheus)
	bundle, err := readruntime.NewBundle(fixture.connectors, fixture.targets, fixture.egress, fixture.profile)
	if err != nil || bundle == nil || !bundle.Ready() {
		t.Fatalf("NewBundle() = %#v, %v", bundle, err)
	}
	descriptor := validBundleDescriptor(t, bundle, fixture)
	if err := bundle.AuthorizeStart(context.Background(), descriptor); err != nil {
		t.Fatalf("AuthorizeStart() error = %v", err)
	}
	if err := bundle.AuthorizeHeartbeat(context.Background(), descriptor); err != nil {
		t.Fatalf("AuthorizeHeartbeat() error = %v", err)
	}
	collectedAt := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	evidence := readtask.EvidenceCompletion{CollectedAt: collectedAt, Items: []json.RawMessage{
		json.RawMessage(fmt.Sprintf(`{"metric":{"job":"api"},"values":[[%d,"1"]]}`, collectedAt.Add(-time.Minute).Unix())),
	}}
	if err := bundle.AuthorizeCompletion(context.Background(), descriptor, evidence); err != nil {
		t.Fatalf("AuthorizeCompletion() error = %v", err)
	}
	prepared, err := bundle.Prepare(context.Background(), descriptor, 7, 11)
	if err != nil || prepared == nil {
		t.Fatalf("Prepare() = %#v, %v", prepared, err)
	}
	equivalent, err := readruntime.NewBundle(fixture.connectors, fixture.targets, fixture.egress, fixture.profile)
	if err != nil {
		t.Fatal(err)
	}
	if result, executeErr := equivalent.Execute(context.Background(), prepared, nil, nil); result.Valid() ||
		!errors.Is(executeErr, readexecutor.ErrExecutionRejected) {
		t.Fatalf("Execute(cross-Bundle prepared) = %#v, %v", result, executeErr)
	}
	preparedCopy := *prepared
	if result, executeErr := bundle.Execute(context.Background(), &preparedCopy, nil, nil); result.Valid() ||
		!errors.Is(executeErr, readexecutor.ErrExecutionRejected) {
		t.Fatalf("Execute(copied prepared) = %#v, %v", result, executeErr)
	}
	encodedPrepared, err := json.Marshal(prepared)
	if err != nil || string(encodedPrepared) != `{"redacted":true}` {
		t.Fatalf("json.Marshal(Prepared) = %s, %v", encodedPrepared, err)
	}

	components, err := investigation.ResolveTaskRuntimeComponents(
		context.Background(), bundle.Bind, fixture.scope, fixture.plan, []investigation.TaskSpec{fixture.spec},
	)
	if err != nil || len(components) != 1 || components[0].ConnectorDigest != descriptor.RuntimeBinding.ConnectorDigest ||
		components[0].TargetDigest != descriptor.RuntimeBinding.TargetDigest ||
		components[0].ExecutorDigest != descriptor.RuntimeBinding.ExecutorDigest {
		t.Fatalf("Bundle.Bind components = %#v, %v", components, err)
	}

	summary := bundle.Summary()
	if summary.Validate() != nil || summary.BundleDigest != bundle.Digest() ||
		summary.ConnectorRegistryDigest != fixture.connectors.Digest() || summary.TargetRegistryDigest != fixture.targets.Digest() ||
		summary.EgressRegistryDigest != fixture.egress.Digest() || summary.ExecutorProfileDigest != fixture.profile.Digest() {
		t.Fatalf("Bundle.Summary() = %#v", summary)
	}
	second, err := readruntime.NewBundle(fixture.connectors, fixture.targets, fixture.egress, fixture.profile)
	if err != nil || second.Digest() != bundle.Digest() {
		t.Fatalf("same graph bundle digest = %q / %q / %v", bundle.Digest(), second.Digest(), err)
	}
	differentFixture := newBinderFixture(t, readconnector.KindPrometheus)
	different, err := readruntime.NewBundle(
		differentFixture.connectors, differentFixture.targets, differentFixture.egress, differentFixture.profile,
	)
	if err != nil || different.Digest() == bundle.Digest() {
		t.Fatalf("different manifest graph did not change Bundle digest: %q / %q / %v", bundle.Digest(), different.Digest(), err)
	}

	copied := *bundle
	if copied.Ready() || copied.Digest() != "" || copied.Summary() != (readruntime.Summary{}) {
		t.Fatal("copied Bundle retained authority")
	}
	encoded, err := json.Marshal(bundle)
	if err != nil || string(encoded) != `{"redacted":true}` {
		t.Fatalf("json.Marshal(Bundle) = %s, %v", encoded, err)
	}
	var decoded readruntime.Bundle
	if err := json.Unmarshal(encoded, &decoded); !errors.Is(err, readruntime.ErrBundleRejected) {
		t.Fatalf("json.Unmarshal(Bundle) error = %v", err)
	}
	var decodedSummary readruntime.Summary
	summaryWire, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(summaryWire, &decodedSummary); !errors.Is(err, readruntime.ErrBundleRejected) {
		t.Fatalf("json.Unmarshal(Summary) error = %v", err)
	}
	rendered := fmt.Sprintf("%s %+v %#v", bundle, bundle, bundle)
	for _, forbidden := range []string{
		fixture.targetDefinition.Endpoint.Origin, fixture.targetDefinition.CredentialRoleRef,
		fixture.targetDefinition.NetworkPolicyRef, fixture.targetDefinition.Endpoint.CABundleFile,
	} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("Bundle rendering leaked %q: %s", forbidden, rendered)
		}
	}
}

func TestBundleAuthorizersRejectEveryPersistedRuntimeDriftBeforeTypedAdmission(t *testing.T) {
	fixture := newBinderFixture(t, readconnector.KindPrometheus)
	bundle, err := readruntime.NewBundle(fixture.connectors, fixture.targets, fixture.egress, fixture.profile)
	if err != nil {
		t.Fatal(err)
	}
	baseline := validBundleDescriptor(t, bundle, fixture)
	tests := map[string]func(*readtask.Descriptor){
		"plan registry": func(value *readtask.Descriptor) {
			value.PlanBinding.RegistryDigest = strings.Repeat("9", 64)
			rebindBundleDescriptor(t, value)
		},
		"connector component and id": func(value *readtask.Descriptor) {
			value.RuntimeBinding.ConnectorDigest = strings.Repeat("8", 64)
			value.ConnectorID = "drifted-connector-v1-" + value.RuntimeBinding.ConnectorDigest
			rebindBundleDescriptor(t, value)
		},
		"target component": func(value *readtask.Descriptor) {
			value.RuntimeBinding.TargetDigest = strings.Repeat("7", 64)
			rebindBundleDescriptor(t, value)
		},
		"executor component": func(value *readtask.Descriptor) {
			value.RuntimeBinding.ExecutorDigest = strings.Repeat("6", 64)
			rebindBundleDescriptor(t, value)
		},
		"aggregate digest": func(value *readtask.Descriptor) {
			value.RuntimeBinding.RuntimeDigest = strings.Repeat("5", 64)
		},
		"scope": func(value *readtask.Descriptor) {
			value.EnvironmentID = "30000000-0000-4000-8000-000000000099"
			rebindBundleDescriptor(t, value)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			descriptor := cloneBundleDescriptor(baseline)
			mutate(&descriptor)
			if err := bundle.AuthorizeStart(context.Background(), descriptor); err == nil {
				t.Fatal("AuthorizeStart() accepted drift")
			}
			if err := bundle.AuthorizeHeartbeat(context.Background(), descriptor); err == nil {
				t.Fatal("AuthorizeHeartbeat() accepted drift")
			}
			if err := bundle.AuthorizeCompletion(context.Background(), descriptor, readtask.EvidenceCompletion{}); err == nil {
				t.Fatal("AuthorizeCompletion() accepted drift")
			}
			if prepared, err := bundle.Prepare(context.Background(), descriptor, 1, 1); prepared != nil || err == nil {
				t.Fatalf("Prepare() accepted drift: %#v, %v", prepared, err)
			}
		})
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := bundle.AuthorizeStart(cancelled, baseline); !errors.Is(err, context.Canceled) {
		t.Fatalf("AuthorizeStart(cancelled) error = %v", err)
	}
	if err := bundle.AuthorizeHeartbeat(cancelled, baseline); !errors.Is(err, context.Canceled) {
		t.Fatalf("AuthorizeHeartbeat(cancelled) error = %v", err)
	}
	if prepared, err := bundle.Prepare(nil, baseline, 1, 1); prepared != nil || !errors.Is(err, readruntime.ErrBundleRejected) {
		t.Fatalf("Prepare(nil context) = %#v, %v", prepared, err)
	}
	if err := bundle.AuthorizeStart(panicContext{}, baseline); !errors.Is(err, readruntime.ErrBundleRejected) {
		t.Fatalf("AuthorizeStart(panicking context) error = %v", err)
	}
	if err := bundle.AuthorizeHeartbeat(panicContext{}, baseline); !errors.Is(err, readruntime.ErrBundleRejected) {
		t.Fatalf("AuthorizeHeartbeat(panicking context) error = %v", err)
	}
}

func TestBundleConstructionFailsClosedOnPartialOrCrossManifestGraph(t *testing.T) {
	fixture := newBinderFixture(t, readconnector.KindPrometheus)
	other := newBinderFixture(t, readconnector.KindPrometheus)
	victoria := newBinderFixture(t, readconnector.KindVictoriaLogs)

	for name, build := range map[string]func() (*readruntime.Bundle, error){
		"nil connector": func() (*readruntime.Bundle, error) {
			return readruntime.NewBundle(nil, fixture.targets, fixture.egress, fixture.profile)
		},
		"nil target": func() (*readruntime.Bundle, error) {
			return readruntime.NewBundle(fixture.connectors, nil, fixture.egress, fixture.profile)
		},
		"nil egress": func() (*readruntime.Bundle, error) {
			return readruntime.NewBundle(fixture.connectors, fixture.targets, nil, fixture.profile)
		},
		"nil profile": func() (*readruntime.Bundle, error) {
			return readruntime.NewBundle(fixture.connectors, fixture.targets, fixture.egress, nil)
		},
		"target manifest drift": func() (*readruntime.Bundle, error) {
			return readruntime.NewBundle(fixture.connectors, other.targets, other.egress, fixture.profile)
		},
		"connector manifest drift": func() (*readruntime.Bundle, error) {
			return readruntime.NewBundle(other.connectors, fixture.targets, fixture.egress, fixture.profile)
		},
		"kind drift": func() (*readruntime.Bundle, error) {
			return readruntime.NewBundle(fixture.connectors, victoria.targets, victoria.egress, fixture.profile)
		},
		"policy scope drift": func() (*readruntime.Bundle, error) {
			return readruntime.NewBundle(fixture.connectors, fixture.targets,
				driftedEgressRegistry(t, fixture, func(value *readexecutor.EgressPolicyDefinition) {
					value.Scope.EnvironmentID = "30000000-0000-4000-8000-000000000099"
				}), fixture.profile)
		},
		"policy hostname drift": func() (*readruntime.Bundle, error) {
			return readruntime.NewBundle(fixture.connectors, fixture.targets,
				driftedEgressRegistry(t, fixture, func(value *readexecutor.EgressPolicyDefinition) {
					value.Hostname = "logs.staging.example.internal"
				}), fixture.profile)
		},
		"policy port drift": func() (*readruntime.Bundle, error) {
			return readruntime.NewBundle(fixture.connectors, fixture.targets,
				driftedEgressRegistry(t, fixture, func(value *readexecutor.EgressPolicyDefinition) {
					value.Port = 9555
				}), fixture.profile)
		},
		"policy content drift": func() (*readruntime.Bundle, error) {
			return readruntime.NewBundle(fixture.connectors, fixture.targets,
				driftedEgressRegistry(t, fixture, func(value *readexecutor.EgressPolicyDefinition) {
					value.AllowedPrefixes = []string{"10.55.9.0/24"}
				}), fixture.profile)
		},
		"copied egress": func() (*readruntime.Bundle, error) {
			copy := *fixture.egress
			return readruntime.NewBundle(fixture.connectors, fixture.targets, &copy, fixture.profile)
		},
		"copied profile": func() (*readruntime.Bundle, error) {
			copy := *fixture.profile
			return readruntime.NewBundle(fixture.connectors, fixture.targets, fixture.egress, &copy)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bundle, err := build()
			if bundle != nil || !errors.Is(err, readruntime.ErrBundleRejected) {
				t.Fatalf("NewBundle(%s) = %#v, %v", name, bundle, err)
			}
		})
	}
}

func validBundleDescriptor(t *testing.T, bundle *readruntime.Bundle, fixture binderFixture) readtask.Descriptor {
	t.Helper()
	components, err := bundle.Bind(context.Background(), fixture.scope, fixture.plan, fixture.spec)
	if err != nil {
		t.Fatal(err)
	}
	boundAt := time.Date(2026, 7, 12, 9, 0, 0, 123456000, time.UTC)
	runtimeBinding, err := investigation.BuildReadTaskRuntimeBinding(
		fixture.scope, fixture.plan, fixture.spec, 1, components, boundAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	inputHash := sha256.Sum256(fixture.spec.Input)
	descriptor := readtask.Descriptor{
		TenantID: fixture.scope.TenantID, WorkspaceID: fixture.scope.WorkspaceID,
		EnvironmentID: fixture.scope.EnvironmentID, ServiceID: fixture.scope.ServiceID,
		IncidentID:      "50000000-0000-4000-8000-000000000005",
		InvestigationID: "60000000-0000-4000-8000-000000000006",
		TaskID:          "70000000-0000-4000-8000-000000000007", TaskKey: fixture.spec.Key, Position: 1,
		ConnectorID: fixture.spec.ConnectorID, Operation: fixture.spec.Operation,
		Input: append(json.RawMessage(nil), fixture.spec.Input...), InputHash: hex.EncodeToString(inputHash[:]),
		PlanBinding: fixture.plan, RuntimeBinding: runtimeBinding,
	}
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("valid Descriptor.Validate() error = %v", err)
	}
	return descriptor
}

func cloneBundleDescriptor(source readtask.Descriptor) readtask.Descriptor {
	source.Input = append(json.RawMessage(nil), source.Input...)
	return source
}

func rebindBundleDescriptor(t *testing.T, descriptor *readtask.Descriptor) {
	t.Helper()
	digest := sha256.Sum256(descriptor.Input)
	descriptor.InputHash = hex.EncodeToString(digest[:])
	runtimeDigest, err := investigation.ReadTaskRuntimeDigest(
		investigation.TaskSpecScope{
			TenantID: descriptor.TenantID, WorkspaceID: descriptor.WorkspaceID,
			EnvironmentID: descriptor.EnvironmentID, ServiceID: descriptor.ServiceID,
			MappingStatus: domain.MappingExact,
		},
		descriptor.PlanBinding,
		investigation.TaskSpec{
			Key: descriptor.TaskKey, ConnectorID: descriptor.ConnectorID,
			Operation: descriptor.Operation, Input: append(json.RawMessage(nil), descriptor.Input...),
		},
		descriptor.Position,
		investigation.TaskRuntimeComponents{
			ConnectorDigest: descriptor.RuntimeBinding.ConnectorDigest,
			TargetDigest:    descriptor.RuntimeBinding.TargetDigest,
			ExecutorDigest:  descriptor.RuntimeBinding.ExecutorDigest,
		},
	)
	if err != nil {
		t.Fatalf("rebind descriptor: %v", err)
	}
	descriptor.RuntimeBinding.RuntimeDigest = runtimeDigest
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("drifted Descriptor should remain structurally valid: %v", err)
	}
}

func driftedEgressRegistry(
	t *testing.T,
	fixture binderFixture,
	mutate func(*readexecutor.EgressPolicyDefinition),
) *readexecutor.EgressRegistry {
	t.Helper()
	parsed, err := url.Parse(fixture.targetDefinition.Endpoint.Origin)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(9443)
	definition := readexecutor.EgressPolicyDefinition{
		Scope:    readtarget.Scope{TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: environmentID},
		Hostname: parsed.Hostname(), Port: port, AllowedPrefixes: []string{"10.42.9.0/24"},
	}
	mutate(&definition)
	ref, err := readexecutor.BuildEgressPolicyRef("drifted-egress", definition)
	if err != nil {
		t.Fatal(err)
	}
	definition.PolicyRef = ref
	registry, err := readexecutor.NewEgressRegistry([]readexecutor.EgressPolicyDefinition{definition})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}
