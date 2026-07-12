package readconnector_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/readgateway"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

const (
	tenantID            = "10000000-0000-4000-8000-000000000001"
	workspaceID         = "20000000-0000-4000-8000-000000000002"
	environmentID       = "30000000-0000-4000-8000-000000000003"
	serviceID           = "40000000-0000-4000-8000-000000000004"
	secretCanary        = "registry-canary-do-not-render"
	prometheusTargetRef = "prometheus-staging-target-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	victoriaTargetRef   = "victorialogs-staging-target-v1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var (
	prometheusID = mustBuiltConnectorID("prometheus-staging-health", unboundDefinitions()[0])
	victoriaID   = mustBuiltConnectorID("victorialogs-staging-errors", unboundDefinitions()[1])
)

func TestRegistryAuthorizersShareOneExactImmutableContract(t *testing.T) {
	definitions := validDefinitions()
	registry, err := readconnector.New(definitions)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if !registry.Ready() || !domain.ValidSHA256Hex(registry.Digest()) {
		t.Fatalf("registry readiness/digest = %t/%q", registry.Ready(), registry.Digest())
	}
	var taskAuthorizer investigation.TaskSpecAuthorizer = registry.AuthorizeTaskSpec
	var startAuthorizer readgateway.StartAuthorizer = registry.AuthorizeStart
	var completionAuthorizer readgateway.CompletionAuthorizer = registry.AuthorizeCompletion
	if taskAuthorizer == nil || startAuthorizer == nil || completionAuthorizer == nil {
		t.Fatal("registry authorizer adapters are unavailable")
	}
	digest := registry.Digest()

	scope := validTaskScope()
	spec := investigation.TaskSpec{
		Key: "metrics", ConnectorID: prometheusID, Operation: readconnector.OperationPrometheusRangeQuery,
		Input: json.RawMessage(`{"lookback_minutes":15}`),
	}
	if err := registry.AuthorizeTaskSpec(context.Background(), scope, spec); err != nil {
		t.Fatalf("AuthorizeTaskSpec() error = %v", err)
	}
	descriptor := validDescriptor(t, prometheusID, readconnector.OperationPrometheusRangeQuery, spec.Input)
	if err := registry.AuthorizeStart(context.Background(), descriptor); err != nil {
		t.Fatalf("AuthorizeStart() error = %v", err)
	}
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	evidence := readtask.EvidenceCompletion{
		CollectedAt: now,
		Items: []json.RawMessage{json.RawMessage(fmt.Sprintf(
			`{"metric":{"job":"api"},"values":[[%d,"1.5"],[%d,"NaN"]]}`,
			now.Add(-10*time.Minute).Unix(), now.Add(-time.Minute).Unix(),
		))},
	}
	if err := registry.AuthorizeCompletion(context.Background(), descriptor, evidence); err != nil {
		t.Fatalf("AuthorizeCompletion() error = %v", err)
	}

	execution, err := registry.ResolveExecution(descriptor)
	if err != nil {
		t.Fatalf("ResolveExecution() error = %v", err)
	}
	query, ok := execution.PrometheusRangeQuery()
	if !ok || execution.Kind() != readconnector.KindPrometheus || execution.Operation() != readconnector.OperationPrometheusRangeQuery ||
		execution.TargetRef() != prometheusTargetRef || !domain.ValidSHA256Hex(execution.ContractDigest()) ||
		execution.Lookback() != 15*time.Minute ||
		query.Expression() != `sum(rate(http_requests_total[5m]))` || query.Step() != 30*time.Second {
		t.Fatalf("resolved execution did not preserve the immutable typed contract")
	}
	queryWire, queryMarshalErr := json.Marshal(query)
	queryRendered := fmt.Sprintf("%+v %#v", query, query)
	if queryMarshalErr != nil || string(queryWire) != `{"redacted":true}` || strings.Contains(queryRendered, "http_requests_total") {
		t.Fatalf("execution rendering leaked its fixed query: %s / %s / %v", queryWire, queryRendered, queryMarshalErr)
	}

	// The constructor must detach every caller-owned object.
	definitions[0].TargetRef = secretCanary
	definitions[0].PrometheusRangeQuery.Expression = secretCanary
	definitions[1].VictoriaLogsSearch.Fields[0].Name = secretCanary
	if registry.Digest() != digest || registry.AuthorizeTaskSpec(context.Background(), scope, spec) != nil {
		t.Fatal("caller mutation changed the immutable registry")
	}
	encoded, marshalErr := json.Marshal(registry)
	valueEncoded, valueMarshalErr := json.Marshal(*registry)
	rendered := fmt.Sprintf("%v %+v %#v / %v %+v %#v", registry, registry, registry, *registry, *registry, *registry)
	if marshalErr != nil || valueMarshalErr != nil || string(encoded) != `{"redacted":true}` ||
		string(valueEncoded) != `{"redacted":true}` || strings.Contains(rendered, secretCanary) ||
		strings.Contains(rendered, "http_requests_total") || strings.Contains(rendered, "prometheus-staging-target") {
		t.Fatalf("registry rendering leaked configuration: %s / %s / %v", encoded, rendered, marshalErr)
	}
}

func TestRegistryDigestIsIndependentOfManifestAndFieldOrder(t *testing.T) {
	first := validDefinitions()
	second := validDefinitions()
	second[0], second[1] = second[1], second[0]
	fields := second[0].VictoriaLogsSearch.Fields
	fields[0], fields[len(fields)-1] = fields[len(fields)-1], fields[0]
	left, err := readconnector.New(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := readconnector.New(second)
	if err != nil {
		t.Fatal(err)
	}
	if left.Digest() != right.Digest() {
		t.Fatalf("semantic manifest order changed digest: %q != %q", left.Digest(), right.Digest())
	}
}

func TestConnectorIDContentAddressBindsEveryAdmissionContractField(t *testing.T) {
	base := unboundDefinitions()[0]
	id, err := readconnector.BuildConnectorID("prometheus-staging-health", base)
	if err != nil || id != prometheusID || len(id) > 128 || len(id) < 64 || !domain.ValidSHA256Hex(id[len(id)-64:]) {
		t.Fatalf("BuildConnectorID() = %q, %v", id, err)
	}
	const goldenPrometheusID = "prometheus-staging-health-v1-83004ffac7bfe4e53c40492220072dd08343bbbfddd0d3851de2de1378a6cf11"
	const goldenVictoriaLogsID = "victorialogs-staging-errors-v1-e011d6bc0557c71650569feeee89d1853f9b0027610578e6fd15982b75be0bd2"
	if prometheusID != goldenPrometheusID || victoriaID != goldenVictoriaLogsID {
		t.Fatalf("validator v1 content IDs changed without a version bump: %q / %q", prometheusID, victoriaID)
	}
	mutations := map[string]func(*readconnector.Definition){
		"tenant":    func(item *readconnector.Definition) { item.Scope.TenantID = "10000000-0000-4000-8000-000000000099" },
		"workspace": func(item *readconnector.Definition) { item.Scope.WorkspaceID = "20000000-0000-4000-8000-000000000099" },
		"environment": func(item *readconnector.Definition) {
			item.Scope.EnvironmentID = "30000000-0000-4000-8000-000000000099"
		},
		"service": func(item *readconnector.Definition) { item.Scope.ServiceID = "40000000-0000-4000-8000-000000000099" },
		"target": func(item *readconnector.Definition) {
			item.TargetRef = "prometheus-staging-target-v1-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		},
		"query":    func(item *readconnector.Definition) { item.PrometheusRangeQuery.Expression = "up" },
		"step":     func(item *readconnector.Definition) { item.PrometheusRangeQuery.StepSeconds++ },
		"lookback": func(item *readconnector.Definition) { item.PrometheusRangeQuery.MaxLookbackMinutes++ },
		"items":    func(item *readconnector.Definition) { item.PrometheusRangeQuery.MaxItems-- },
		"samples":  func(item *readconnector.Definition) { item.PrometheusRangeQuery.MaxSamples-- },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := mutateDefinitions(base, mutate)[0]
			changed.ConnectorID = ""
			changedID, buildErr := readconnector.BuildConnectorID("prometheus-staging-health", changed)
			if buildErr != nil || changedID == id {
				t.Fatalf("contract mutation ID = %q, %v; want a different content address", changedID, buildErr)
			}
			changed.ConnectorID = id
			if registry, newErr := readconnector.New([]readconnector.Definition{changed}); registry != nil || !errors.Is(newErr, readconnector.ErrInvalidDefinition) {
				t.Fatalf("New(drift under old ID) = %#v, %v", registry, newErr)
			}
		})
	}

	victoriaBase := unboundDefinitions()[1]
	victoriaMutations := map[string]func(*readconnector.Definition){
		"query":      func(item *readconnector.Definition) { item.VictoriaLogsSearch.Query = "error" },
		"limit":      func(item *readconnector.Definition) { item.VictoriaLogsSearch.Limit-- },
		"lookback":   func(item *readconnector.Definition) { item.VictoriaLogsSearch.MaxLookbackMinutes++ },
		"field name": func(item *readconnector.Definition) { item.VictoriaLogsSearch.Fields[1].Name = "message" },
		"field type": func(item *readconnector.Definition) {
			item.VictoriaLogsSearch.Fields[2].Type = readconnector.FieldString
			item.VictoriaLogsSearch.Fields[2].MaxBytes = 64
		},
		"field required":  func(item *readconnector.Definition) { item.VictoriaLogsSearch.Fields[1].Required = false },
		"field max bytes": func(item *readconnector.Definition) { item.VictoriaLogsSearch.Fields[1].MaxBytes-- },
		"kind operation": func(item *readconnector.Definition) {
			item.VictoriaLogsSearch = nil
			prometheus := *unboundDefinitions()[0].PrometheusRangeQuery
			item.PrometheusRangeQuery = &prometheus
		},
	}
	for name, mutate := range victoriaMutations {
		t.Run("victorialogs "+name, func(t *testing.T) {
			changed := mutateDefinitions(victoriaBase, mutate)[0]
			changed.ConnectorID = ""
			changedID, buildErr := readconnector.BuildConnectorID("victorialogs-staging-errors", changed)
			if buildErr != nil || changedID == victoriaID {
				t.Fatalf("contract mutation ID = %q, %v; want a different content address", changedID, buildErr)
			}
			changed.ConnectorID = victoriaID
			if registry, newErr := readconnector.New([]readconnector.Definition{changed}); registry != nil || !errors.Is(newErr, readconnector.ErrInvalidDefinition) {
				t.Fatalf("New(drift under old ID) = %#v, %v", registry, newErr)
			}
		})
	}

	reordered := unboundDefinitions()[1]
	originalFirst := reordered.VictoriaLogsSearch.Fields[0]
	last := len(reordered.VictoriaLogsSearch.Fields) - 1
	reordered.VictoriaLogsSearch.Fields[0], reordered.VictoriaLogsSearch.Fields[last] =
		reordered.VictoriaLogsSearch.Fields[last], reordered.VictoriaLogsSearch.Fields[0]
	reorderedID, err := readconnector.BuildConnectorID("victorialogs-staging-errors", reordered)
	if err != nil || reorderedID != victoriaID || reordered.VictoriaLogsSearch.Fields[last] != originalFirst {
		t.Fatalf("field order changed content address or caller slice: %q, %v", reorderedID, err)
	}

	for name, identifier := range map[string]string{
		"changed nibble": prometheusID[:len(prometheusID)-1] + "0",
		"uppercase hash": prometheusID[:len(prometheusID)-1] + "A",
		"truncated hash": prometheusID[:len(prometheusID)-1],
	} {
		t.Run(name, func(t *testing.T) {
			definition := unboundDefinitions()[0]
			definition.ConnectorID = identifier
			if registry, newErr := readconnector.New([]readconnector.Definition{definition}); registry != nil || !errors.Is(newErr, readconnector.ErrInvalidDefinition) {
				t.Fatalf("New(%s) = %#v, %v", name, registry, newErr)
			}
		})
	}
	for name, base := range map[string]string{
		"max base":      strings.Repeat("a", 60),
		"too long base": strings.Repeat("a", 61),
	} {
		t.Run(name, func(t *testing.T) {
			identifier, buildErr := readconnector.BuildConnectorID(base, unboundDefinitions()[0])
			if name == "max base" {
				if buildErr != nil || len(identifier) != 128 {
					t.Fatalf("BuildConnectorID(max base) = %q (%d), %v", identifier, len(identifier), buildErr)
				}
				return
			}
			if identifier != "" || !errors.Is(buildErr, readconnector.ErrInvalidDefinition) {
				t.Fatalf("BuildConnectorID(too long base) = %q, %v", identifier, buildErr)
			}
		})
	}
	if identifier, buildErr := readconnector.BuildConnectorID("vault-secret", unboundDefinitions()[0]); identifier != "" || !errors.Is(buildErr, readconnector.ErrInvalidDefinition) {
		t.Fatalf("BuildConnectorID(sensitive base) = %q, %v", identifier, buildErr)
	}
	if identifier, buildErr := readconnector.BuildConnectorID("api-key-metrics", unboundDefinitions()[0]); identifier != "" || !errors.Is(buildErr, readconnector.ErrInvalidDefinition) {
		t.Fatalf("BuildConnectorID(obfuscated sensitive base) = %q, %v", identifier, buildErr)
	}
	sensitiveID := unboundDefinitions()[0]
	sensitiveID.ConnectorID = "vault-secret-v1-" + prometheusID[len(prometheusID)-64:]
	if registry, newErr := readconnector.New([]readconnector.Definition{sensitiveID}); registry != nil || !errors.Is(newErr, readconnector.ErrInvalidDefinition) {
		t.Fatalf("New(sensitive content-address base) = %#v, %v", registry, newErr)
	}
}

func TestRegistryRejectsInvalidOrAmbiguousDefinitions(t *testing.T) {
	valid := validDefinitions()[0]
	otherEnvironment := "30000000-0000-4000-8000-000000000099"

	tests := map[string][]readconnector.Definition{
		"empty": nil,
		"both operations": mutateDefinitions(valid, func(item *readconnector.Definition) {
			item.VictoriaLogsSearch = validDefinitions()[1].VictoriaLogsSearch
		}),
		"no operation": mutateDefinitions(valid, func(item *readconnector.Definition) {
			item.PrometheusRangeQuery = nil
		}),
		"invalid tenant":        mutateDefinitions(valid, func(item *readconnector.Definition) { item.Scope.TenantID = "" }),
		"slug tenant":           mutateDefinitions(valid, func(item *readconnector.Definition) { item.Scope.TenantID = "tenant-slug" }),
		"invalid environment":   mutateDefinitions(valid, func(item *readconnector.Definition) { item.Scope.EnvironmentID = "bad value" }),
		"unversioned connector": mutateDefinitions(valid, func(item *readconnector.Definition) { item.ConnectorID = "prometheus-staging" }),
		"connector over domain limit": mutateDefinitions(valid, func(item *readconnector.Definition) {
			item.ConnectorID = "p" + strings.Repeat("a", 117) + "-v123456789"
		}),
		"target URL": mutateDefinitions(valid, func(item *readconnector.Definition) { item.TargetRef = "https://secret.invalid" }),
		"sensitive target": mutateDefinitions(valid, func(item *readconnector.Definition) {
			item.TargetRef = "vault-secret-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}),
		"empty query":        mutateDefinitions(valid, func(item *readconnector.Definition) { item.PrometheusRangeQuery.Expression = "" }),
		"multiline query":    mutateDefinitions(valid, func(item *readconnector.Definition) { item.PrometheusRangeQuery.Expression = "up\nsecret" }),
		"zero step":          mutateDefinitions(valid, func(item *readconnector.Definition) { item.PrometheusRangeQuery.StepSeconds = 0 }),
		"lookback too large": mutateDefinitions(valid, func(item *readconnector.Definition) { item.PrometheusRangeQuery.MaxLookbackMinutes = 1441 }),
		"items too large": mutateDefinitions(valid, func(item *readconnector.Definition) {
			item.PrometheusRangeQuery.MaxItems = readtask.MaxEvidenceItems + 1
		}),
		"samples inconsistent": mutateDefinitions(valid, func(item *readconnector.Definition) { item.PrometheusRangeQuery.MaxSamples = 1 }),
		"duplicate exact key":  {valid, valid},
		"connector reused across environments": {
			valid,
			func() readconnector.Definition {
				copy := valid
				copy.Scope.EnvironmentID = otherEnvironment
				return copy
			}(),
		},
	}
	alias := unboundDefinitions()[0]
	alias.ConnectorID = mustBuiltConnectorID("prometheus-staging-health-alias", alias)
	tests["duplicate contract alias"] = []readconnector.Definition{valid, alias}

	victoria := validDefinitions()[1]
	tests["missing required time"] = mutateDefinitions(victoria, func(item *readconnector.Definition) {
		item.VictoriaLogsSearch.Fields = item.VictoriaLogsSearch.Fields[1:]
	})
	tests["duplicate fields"] = mutateDefinitions(victoria, func(item *readconnector.Definition) {
		item.VictoriaLogsSearch.Fields = append(item.VictoriaLogsSearch.Fields, item.VictoriaLogsSearch.Fields[0])
	})
	tests["reserved field"] = mutateDefinitions(victoria, func(item *readconnector.Definition) {
		item.VictoriaLogsSearch.Fields[1].Name = "source_url"
	})
	tests["tokenized reserved field"] = mutateDefinitions(victoria, func(item *readconnector.Definition) {
		item.VictoriaLogsSearch.Fields[1].Name = "target_status"
	})
	tests["sensitive output field"] = mutateDefinitions(victoria, func(item *readconnector.Definition) {
		item.VictoriaLogsSearch.Fields[1].Name = "api_token"
	})
	tests["nested field type"] = mutateDefinitions(victoria, func(item *readconnector.Definition) {
		item.VictoriaLogsSearch.Fields[1].Type = "object"
	})
	tests["non-string max bytes"] = mutateDefinitions(victoria, func(item *readconnector.Definition) {
		item.VictoriaLogsSearch.Fields[2].MaxBytes = 10
	})

	for name, definitions := range tests {
		t.Run(name, func(t *testing.T) {
			registry, err := readconnector.New(definitions)
			if !errors.Is(err, readconnector.ErrInvalidDefinition) || registry != nil {
				t.Fatalf("New() = %#v, %v, want ErrInvalidDefinition", registry, err)
			}
			if strings.Contains(fmt.Sprint(err), secretCanary) || strings.Contains(fmt.Sprint(err), "https://") {
				t.Fatalf("definition error leaked configuration: %v", err)
			}
		})
	}
}

func TestRegistryTaskAndStartAuthorizationFailClosedOnEveryScopeAndSchemaDrift(t *testing.T) {
	registry := mustRegistry(t)
	validScope := validTaskScope()
	validSpec := investigation.TaskSpec{
		Key: "metrics", ConnectorID: prometheusID, Operation: readconnector.OperationPrometheusRangeQuery,
		Input: json.RawMessage(`{"lookback_minutes":15}`),
	}

	tests := map[string]struct {
		scope investigation.TaskSpecScope
		spec  investigation.TaskSpec
	}{
		"tenant":        {mutateScope(validScope, func(scope *investigation.TaskSpecScope) { scope.TenantID = "10000000-0000-4000-8000-000000000099" }), validSpec},
		"workspace":     {mutateScope(validScope, func(scope *investigation.TaskSpecScope) { scope.WorkspaceID = "20000000-0000-4000-8000-000000000099" }), validSpec},
		"environment":   {mutateScope(validScope, func(scope *investigation.TaskSpecScope) { scope.EnvironmentID = "30000000-0000-4000-8000-000000000099" }), validSpec},
		"service":       {mutateScope(validScope, func(scope *investigation.TaskSpecScope) { scope.ServiceID = "40000000-0000-4000-8000-000000000099" }), validSpec},
		"mapping":       {mutateScope(validScope, func(scope *investigation.TaskSpecScope) { scope.MappingStatus = domain.MappingAmbiguous }), validSpec},
		"connector":     {validScope, mutateSpec(validSpec, func(spec *investigation.TaskSpec) { spec.ConnectorID = victoriaID })},
		"operation":     {validScope, mutateSpec(validSpec, func(spec *investigation.TaskSpec) { spec.Operation = "query_range" })},
		"prefix":        {validScope, mutateSpec(validSpec, func(spec *investigation.TaskSpec) { spec.ConnectorID = "prometheus" })},
		"missing input": {validScope, mutateSpec(validSpec, func(spec *investigation.TaskSpec) { spec.Input = json.RawMessage(`{}`) })},
		"extra input": {validScope, mutateSpec(validSpec, func(spec *investigation.TaskSpec) {
			spec.Input = json.RawMessage(`{"lookback_minutes":15,"query":"up"}`)
		})},
		"duplicate": {validScope, mutateSpec(validSpec, func(spec *investigation.TaskSpec) {
			spec.Input = json.RawMessage(`{"lookback_minutes":15,"lookback_minutes":10}`)
		})},
		"string":      {validScope, mutateSpec(validSpec, func(spec *investigation.TaskSpec) { spec.Input = json.RawMessage(`{"lookback_minutes":"15"}`) })},
		"float":       {validScope, mutateSpec(validSpec, func(spec *investigation.TaskSpec) { spec.Input = json.RawMessage(`{"lookback_minutes":15.0}`) })},
		"zero":        {validScope, mutateSpec(validSpec, func(spec *investigation.TaskSpec) { spec.Input = json.RawMessage(`{"lookback_minutes":0}`) })},
		"above limit": {validScope, mutateSpec(validSpec, func(spec *investigation.TaskSpec) { spec.Input = json.RawMessage(`{"lookback_minutes":61}`) })},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			if err := registry.AuthorizeTaskSpec(context.Background(), testCase.scope, testCase.spec); !errors.Is(err, readconnector.ErrContractRejected) {
				t.Fatalf("AuthorizeTaskSpec() error = %v, want ErrContractRejected", err)
			}
		})
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := registry.AuthorizeTaskSpec(cancelled, validScope, validSpec); !errors.Is(err, context.Canceled) {
		t.Fatalf("AuthorizeTaskSpec(cancelled) error = %v", err)
	}

	validDescriptor := validDescriptor(t, prometheusID, readconnector.OperationPrometheusRangeQuery, validSpec.Input)
	unknown := validDescriptor
	unknown.ConnectorID = "prometheus-staging-unknown-v1"
	if err := registry.AuthorizeStart(context.Background(), unknown); !errors.Is(err, readtask.ErrIntegrity) {
		t.Fatalf("AuthorizeStart(non-content-addressed) error = %v", err)
	}
	wrongService := validDescriptor
	wrongService.ServiceID = "40000000-0000-4000-8000-000000000099"
	if err := registry.AuthorizeStart(context.Background(), wrongService); !errors.Is(err, readtask.ErrIntegrity) {
		t.Fatalf("AuthorizeStart(wrong service) error = %v", err)
	}
	corrupt := validDescriptor
	corrupt.Input = json.RawMessage(`{"lookback_minutes":61}`)
	digest := sha256.Sum256(corrupt.Input)
	corrupt.InputHash = hex.EncodeToString(digest[:])
	if err := registry.AuthorizeStart(context.Background(), corrupt); !errors.Is(err, readtask.ErrIntegrity) {
		t.Fatalf("AuthorizeStart(corrupt persisted input) error = %v", err)
	}
}

func TestRegistrySupportsConcurrentReadOnlyAuthorization(t *testing.T) {
	registry := mustRegistry(t)
	scope := validTaskScope()
	spec := investigation.TaskSpec{Key: "metrics", ConnectorID: prometheusID, Operation: readconnector.OperationPrometheusRangeQuery, Input: json.RawMessage(`{"lookback_minutes":15}`)}
	descriptor := validDescriptor(t, prometheusID, readconnector.OperationPrometheusRangeQuery, spec.Input)
	var group sync.WaitGroup
	errorsChannel := make(chan error, 192)
	for index := 0; index < 64; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for _, operation := range []func() error{
				func() error { return registry.AuthorizeTaskSpec(context.Background(), scope, spec) },
				func() error { return registry.AuthorizeStart(context.Background(), descriptor) },
				func() error { _, err := registry.ResolveExecution(descriptor); return err },
			} {
				if err := operation(); err != nil {
					errorsChannel <- err
				}
			}
		}()
	}
	group.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Errorf("concurrent authorization error = %v", err)
	}
}

func TestRegistryResolvesCanonicalTaskSpecForTrustedRuntimeBinder(t *testing.T) {
	registry := mustRegistry(t)
	scope := validTaskScope()
	spec := investigation.TaskSpec{
		Key: "metrics", ConnectorID: prometheusID,
		Operation: readconnector.OperationPrometheusRangeQuery,
		Input:     json.RawMessage(`{"lookback_minutes":15}`),
	}

	resolved, err := registry.ResolveTaskSpec(context.Background(), scope, spec)
	if err != nil || resolved.Kind() != readconnector.KindPrometheus ||
		resolved.Operation() != readconnector.OperationPrometheusRangeQuery ||
		resolved.TargetRef() != prometheusTargetRef ||
		resolved.ContractDigest() != prometheusID[len(prometheusID)-64:] ||
		resolved.Lookback() != 15*time.Minute {
		t.Fatalf("ResolveTaskSpec() = %#v, %v", resolved, err)
	}

	wrongScope := scope
	wrongScope.EnvironmentID = "30000000-0000-4000-8000-000000000099"
	if result, err := registry.ResolveTaskSpec(context.Background(), wrongScope, spec); result.Kind() != "" ||
		!errors.Is(err, readconnector.ErrContractRejected) {
		t.Fatalf("ResolveTaskSpec(wrong scope) = %#v, %v", result, err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := registry.ResolveTaskSpec(cancelled, scope, spec); result.Kind() != "" ||
		!errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveTaskSpec(cancelled) = %#v, %v", result, err)
	}

	var typedNil *nilSafeContext
	if result, err := registry.ResolveTaskSpec(typedNil, scope, spec); result.Kind() != "" ||
		!errors.Is(err, readconnector.ErrContractRejected) {
		t.Fatalf("ResolveTaskSpec(typed nil context) = %#v, %v", result, err)
	}
	if err := registry.AuthorizeTaskSpec(typedNil, scope, spec); !errors.Is(err, readconnector.ErrContractRejected) {
		t.Fatalf("AuthorizeTaskSpec(typed nil context) error = %v", err)
	}

	for name, invalid := range map[string]investigation.TaskSpec{
		"non canonical input": mutateSpec(spec, func(value *investigation.TaskSpec) {
			value.Input = json.RawMessage(`{ "lookback_minutes": 15 }`)
		}),
		"invalid key": mutateSpec(spec, func(value *investigation.TaskSpec) {
			value.Key = "Metrics"
		}),
	} {
		t.Run(name, func(t *testing.T) {
			if result, err := registry.ResolveTaskSpec(context.Background(), scope, invalid); result.Kind() != "" ||
				!errors.Is(err, readconnector.ErrContractRejected) {
				t.Fatalf("ResolveTaskSpec(%s) = %#v, %v", name, result, err)
			}
		})
	}
}

func unboundDefinitions() []readconnector.Definition {
	return []readconnector.Definition{
		{
			Scope:     readconnector.Scope{TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: environmentID, ServiceID: serviceID},
			TargetRef: prometheusTargetRef,
			PrometheusRangeQuery: &readconnector.PrometheusRangeQueryV1{
				Expression: `sum(rate(http_requests_total[5m]))`, StepSeconds: 30,
				MaxLookbackMinutes: 60, MaxItems: 100, MaxSamples: 20_000,
			},
		},
		{
			Scope:     readconnector.Scope{TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: environmentID, ServiceID: serviceID},
			TargetRef: victoriaTargetRef,
			VictoriaLogsSearch: &readconnector.VictoriaLogsSearchV1{
				Query: `_stream:{app="payments"} level:error`, Limit: 100, MaxLookbackMinutes: 60,
				Fields: []readconnector.FieldSpec{
					{Name: "_time", Type: readconnector.FieldString, Required: true, MaxBytes: 64},
					{Name: "_msg", Type: readconnector.FieldString, Required: true, MaxBytes: 2048},
					{Name: "status", Type: readconnector.FieldNumber},
					{Name: "retryable", Type: readconnector.FieldBoolean},
					{Name: "trace", Type: readconnector.FieldNull},
				},
			},
		},
	}
}

func validDefinitions() []readconnector.Definition {
	definitions := unboundDefinitions()
	definitions[0].ConnectorID = prometheusID
	definitions[1].ConnectorID = victoriaID
	return definitions
}

func mustBuiltConnectorID(base string, definition readconnector.Definition) string {
	identifier, err := readconnector.BuildConnectorID(base, definition)
	if err != nil {
		panic(err)
	}
	return identifier
}

func mustRegistry(t *testing.T) *readconnector.Registry {
	t.Helper()
	registry, err := readconnector.New(validDefinitions())
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func validTaskScope() investigation.TaskSpecScope {
	return investigation.TaskSpecScope{
		TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: environmentID,
		ServiceID: serviceID, MappingStatus: domain.MappingExact,
	}
}

func validDescriptor(t *testing.T, connectorID, operation string, input json.RawMessage) readtask.Descriptor {
	t.Helper()
	if len(connectorID) < 64 {
		t.Fatalf("test ConnectorID %q has no SHA-256 content-address suffix", connectorID)
	}
	connectorDigest := connectorID[len(connectorID)-64:]
	if !domain.ValidSHA256Hex(connectorDigest) {
		t.Fatalf("test ConnectorID %q has an invalid SHA-256 content-address suffix", connectorID)
	}
	digest := sha256.Sum256(input)
	descriptor := readtask.Descriptor{
		TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: environmentID,
		ServiceID:  serviceID,
		IncidentID: "50000000-0000-4000-8000-000000000005", InvestigationID: "60000000-0000-4000-8000-000000000006",
		TaskID: "70000000-0000-4000-8000-000000000007", TaskKey: "metrics", Position: 1,
		ConnectorID: connectorID, Operation: operation, Input: append(json.RawMessage(nil), input...),
		InputHash: hex.EncodeToString(digest[:]),
		PlanBinding: domain.InvestigationPlanBinding{
			SchemaVersion:  domain.InvestigationPlanBindingSchemaVersion,
			ManifestDigest: strings.Repeat("1", 64), RegistryDigest: strings.Repeat("2", 64),
			ProfileDigest: strings.Repeat("3", 64), TasksHash: strings.Repeat("4", 64),
		},
		RuntimeBinding: domain.ReadTaskRuntimeBinding{
			SchemaVersion:   domain.ReadTaskRuntimeBindingSchemaVersion,
			ConnectorDigest: connectorDigest, TargetDigest: strings.Repeat("5", 64),
			ExecutorDigest: strings.Repeat("6", 64), RuntimeDigest: strings.Repeat("7", 64),
			BoundAt: time.Date(2026, 7, 12, 8, 9, 10, 123456000, time.UTC),
		},
	}
	runtimeDigest, err := investigation.ReadTaskRuntimeDigest(
		validTaskScope(),
		descriptor.PlanBinding,
		investigation.TaskSpec{
			Key: descriptor.TaskKey, ConnectorID: descriptor.ConnectorID,
			Operation: descriptor.Operation, Input: append(json.RawMessage(nil), descriptor.Input...),
		}, descriptor.Position,
		investigation.TaskRuntimeComponents{
			ConnectorDigest: descriptor.RuntimeBinding.ConnectorDigest,
			TargetDigest:    descriptor.RuntimeBinding.TargetDigest,
			ExecutorDigest:  descriptor.RuntimeBinding.ExecutorDigest,
		},
	)
	if err != nil {
		t.Fatalf("build Descriptor runtime digest: %v", err)
	}
	descriptor.RuntimeBinding.RuntimeDigest = runtimeDigest
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("valid test Descriptor.Validate() error = %v", err)
	}
	return descriptor
}

func mutateDefinitions(source readconnector.Definition, mutate func(*readconnector.Definition)) []readconnector.Definition {
	copy := source
	if source.PrometheusRangeQuery != nil {
		value := *source.PrometheusRangeQuery
		copy.PrometheusRangeQuery = &value
	}
	if source.VictoriaLogsSearch != nil {
		value := *source.VictoriaLogsSearch
		value.Fields = append([]readconnector.FieldSpec(nil), source.VictoriaLogsSearch.Fields...)
		copy.VictoriaLogsSearch = &value
	}
	mutate(&copy)
	return []readconnector.Definition{copy}
}

func mutateScope(source investigation.TaskSpecScope, mutate func(*investigation.TaskSpecScope)) investigation.TaskSpecScope {
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
