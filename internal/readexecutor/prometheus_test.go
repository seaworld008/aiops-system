package readexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/readconnector"
)

const (
	prometheusTestTenant      = "10000000-0000-4000-8000-000000000001"
	prometheusTestWorkspace   = "20000000-0000-4000-8000-000000000002"
	prometheusTestEnvironment = "30000000-0000-4000-8000-000000000003"
	prometheusTestService     = "40000000-0000-4000-8000-000000000004"
)

func TestParsePrometheusResponseProjectsCanonicalMatrixFloatEvidence(t *testing.T) {
	t.Parallel()
	execution := prometheusExecutionForTest(t, 2, 6)
	collectedAt := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	body := []byte(`{
		"status":"success",
		"data":{"resultType":"matrix","result":[
			{"values":[[1783850340,"NaN"],[1783850370,"+Inf"],[1783850400,"-Inf"]],"metric":{"job":"a"}},
			{"metric":{"zone":"east","job":"b"},"values":[[1783850340,"1.5"],[1783850370,"2"],[1783850400,"3e1"]]}
		]},
		"warnings":[],"infos":[]
	}`)

	evidence, failure := parsePrometheusResponse(body, execution, collectedAt)
	if failure != responseAccepted || !evidence.CollectedAt.Equal(collectedAt) || len(evidence.Items) != 2 {
		t.Fatalf("parsePrometheusResponse() = %#v, %v", evidence, failure)
	}
	want := []string{
		`{"metric":{"job":"a"},"values":[[1783850340,"NaN"],[1783850370,"+Inf"],[1783850400,"-Inf"]]}`,
		`{"metric":{"job":"b","zone":"east"},"values":[[1783850340,"1.5"],[1783850370,"2"],[1783850400,"3e1"]]}`,
	}
	for index := range want {
		if string(evidence.Items[index]) != want[index] {
			t.Fatalf("evidence.Items[%d] = %s, want %s", index, evidence.Items[index], want[index])
		}
	}
	if err := execution.ValidateEvidence(evidence); err != nil {
		t.Fatalf("projected Evidence failed immutable connector validation: %v", err)
	}
	clear(body)
	for index := range want {
		if string(evidence.Items[index]) != want[index] {
			t.Fatalf("Evidence retained upstream response backing at item %d", index)
		}
	}
}

func TestParsePrometheusResponseRejectsNonDeterministicMatrixOrdering(t *testing.T) {
	t.Parallel()
	execution := prometheusExecutionForTest(t, 2, 6)
	collectedAt := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	tests := map[string]string{
		"series out of order": `
			{"metric":{"job":"b"},"values":[[1783850340,"1"]]},
			{"metric":{"job":"a"},"values":[[1783850340,"1"]]}`,
		"duplicate series": `
			{"metric":{"job":"a"},"values":[[1783850340,"1"]]},
			{"metric":{"job":"a"},"values":[[1783850370,"2"]]}`,
		"first sample off grid": `
			{"metric":{"job":"a"},"values":[[1783850341,"1"]]}`,
		"samples out of order": `
			{"metric":{"job":"a"},"values":[[1783850370,"1"],[1783850340,"2"]]}`,
		"duplicate timestamp": `
			{"metric":{"job":"a"},"values":[[1783850340,"1"],[1783850340,"2"]]}`,
	}
	for name, result := range tests {
		t.Run(name, func(t *testing.T) {
			body := []byte(fmt.Sprintf(`{"status":"success","data":{"resultType":"matrix","result":[%s]}}`, result))
			evidence, failure := parsePrometheusResponse(body, execution, collectedAt)
			if failure != responseRejected || evidence.Items != nil || !evidence.CollectedAt.IsZero() {
				t.Fatalf("parsePrometheusResponse(%s) = %#v, %v; want redacted rejection", name, evidence, failure)
			}
		})
	}
}

func TestParsePrometheusResponseUsesPrometheusLabelSetOrdering(t *testing.T) {
	t.Parallel()
	execution := prometheusExecutionForTest(t, 2, 6)
	collectedAt := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	body := []byte(`{"status":"success","data":{"resultType":"matrix","result":[
		{"metric":{"job":"a"},"values":[[1783850340,"1"]]},
		{"metric":{"job":"a","zone":"east"},"values":[[1783850340,"1"]]}]}}`)
	evidence, failure := parsePrometheusResponse(body, execution, collectedAt)
	if failure != responseAccepted || len(evidence.Items) != 2 {
		t.Fatalf("shorter label-set prefix should sort first: %#v, %v", evidence, failure)
	}
}

func TestParsePrometheusResponseClassifiesEnvelopeAndPolicyFailuresWithoutLeakingBody(t *testing.T) {
	t.Parallel()
	execution := prometheusExecutionForTest(t, 2, 6)
	collectedAt := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	const canary = "prometheus-response-secret-canary"
	tests := map[string]struct {
		body []byte
		want responseFailure
	}{
		"malformed":                      {[]byte(`{` + canary), responseInvalid},
		"unknown envelope field":         {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[]},"unknown":"` + canary + `"}`), responseInvalid},
		"duplicate envelope field":       {[]byte(`{"status":"success","status":"success","data":{"resultType":"matrix","result":[]}}`), responseInvalid},
		"case-folded status":             {[]byte(`{"STATUS":"success","data":{"resultType":"matrix","result":[]}}`), responseInvalid},
		"case-folded status alias":       {[]byte(`{"status":"error","STATUS":"success","data":{"resultType":"matrix","result":[]}}`), responseInvalid},
		"case-folded warning alias":      {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[]},"warnings":["partial"],"WARNINGS":[]}`), responseInvalid},
		"case-folded result type":        {[]byte(`{"status":"success","data":{"RESULTTYPE":"matrix","result":[]}}`), responseInvalid},
		"trailing value":                 {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}} {}`), responseInvalid},
		"error envelope":                 {[]byte(`{"status":"error","data":{"resultType":"matrix","result":[]}}`), responseInvalid},
		"wrong result type":              {[]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`), responseInvalid},
		"missing result":                 {[]byte(`{"status":"success","data":{"resultType":"matrix"}}`), responseInvalid},
		"unknown series field":           {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"a"},"values":[[1783850340,"1"]],"unknown":"` + canary + `"}]}}`), responseInvalid},
		"missing metric":                 {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"values":[[1783850340,"1"]]}]}}`), responseInvalid},
		"null metric":                    {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":null,"values":[[1783850340,"1"]]}]}}`), responseInvalid},
		"missing values":                 {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"a"}}]}}`), responseInvalid},
		"null values":                    {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"a"},"values":null}]}}`), responseInvalid},
		"duplicate metric label":         {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"a","job":"b"},"values":[[1783850340,"1"]]}]}}`), responseInvalid},
		"short sample tuple":             {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"a"},"values":[[1783850340]]}]}}`), responseInvalid},
		"string timestamp":               {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"a"},"values":[["1783850340","1"]]}]}}`), responseInvalid},
		"non-array warnings":             {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[]},"warnings":"` + canary + `"}`), responseInvalid},
		"null infos":                     {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[]},"infos":null}`), responseInvalid},
		"partial warning":                {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[]},"warnings":["` + canary + `"]}`), responseRejected},
		"partial info":                   {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[]},"infos":["` + canary + `"]}`), responseRejected},
		"empty native histograms field":  {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"a"},"values":[[1783850340,"1"]],"histograms":[]}]}}`), responseRejected},
		"null native histograms field":   {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"a"},"values":[[1783850340,"1"]],"histograms":null}]}}`), responseRejected},
		"native histogram in values":     {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"a"},"values":[[1783850340,{"count":"1"}]]}]}}`), responseRejected},
		"numeric sample value":           {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"a"},"values":[[1783850340,1]]}]}}`), responseRejected},
		"empty values":                   {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"a"},"values":[]}]}}`), responseRejected},
		"invalid finite value":           {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"a"},"values":[[1783850340,"not-a-number"]]}]}}`), responseRejected},
		"noncanonical positive infinity": {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"a"},"values":[[1783850340,"Inf"]]}]}}`), responseRejected},
		"too many series": {[]byte(`{"status":"success","data":{"resultType":"matrix","result":[
			{"metric":{"job":"a"},"values":[[1783850340,"1"]]},
			{"metric":{"job":"b"},"values":[[1783850340,"1"]]},
			{"metric":{"job":"c"},"values":[[1783850340,"1"]]}]}}`), responseRejected},
		"upstream body over budget": {bytes.Repeat([]byte("x"), MaximumUpstreamResponseBytes+1), responseRejected},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			evidence, failure := parsePrometheusResponse(test.body, execution, collectedAt)
			if failure != test.want || evidence.Items != nil || !evidence.CollectedAt.IsZero() {
				t.Fatalf("parsePrometheusResponse(%s) = %#v, %v; want %v", name, evidence, failure, test.want)
			}
			rendered := fmt.Sprintf("%v %+v %#v", failure, failure, failure)
			if strings.Contains(rendered, canary) {
				t.Fatalf("response failure leaked upstream body: %s", rendered)
			}
		})
	}
}

func TestParsePrometheusResponseEnforcesSampleAndEvidenceBudgets(t *testing.T) {
	t.Parallel()
	collectedAt := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)

	t.Run("global sample budget", func(t *testing.T) {
		execution := prometheusExecutionForTest(t, 2, 3)
		body := []byte(`{"status":"success","data":{"resultType":"matrix","result":[
			{"metric":{"job":"a"},"values":[[1783850340,"1"],[1783850370,"2"]]},
			{"metric":{"job":"b"},"values":[[1783850340,"1"],[1783850370,"2"]]}]}}`)
		if evidence, failure := parsePrometheusResponse(body, execution, collectedAt); failure != responseRejected || evidence.Items != nil {
			t.Fatalf("global sample overflow = %#v, %v", evidence, failure)
		}
	})

	t.Run("canonical Evidence byte budget", func(t *testing.T) {
		execution := prometheusExecutionForTest(t, 2, 6)
		metric := make(map[string]string, 64)
		for index := range 64 {
			metric[fmt.Sprintf("label_%02d", index)] = strings.Repeat("x", 1024)
		}
		body, err := json.Marshal(map[string]any{
			"status": "success",
			"data": map[string]any{"resultType": "matrix", "result": []any{
				map[string]any{"metric": metric, "values": []any{[]any{1783850340, "1"}}},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if evidence, failure := parsePrometheusResponse(body, execution, collectedAt); failure != responseRejected || evidence.Items != nil {
			t.Fatalf("Evidence byte overflow = %#v, %v", evidence, failure)
		}
	})
}

func TestParsePrometheusResponseReturnsDetachedNonNilEmptyEvidence(t *testing.T) {
	t.Parallel()
	execution := prometheusExecutionForTest(t, 2, 6)
	collectedAt := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	body := []byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`)
	evidence, failure := parsePrometheusResponse(body, execution, collectedAt)
	if failure != responseAccepted || evidence.Items == nil || len(evidence.Items) != 0 || !evidence.CollectedAt.Equal(collectedAt) {
		t.Fatalf("empty matrix Evidence = %#v, %v", evidence, failure)
	}
	body[0] = '['
	if evidence.Items == nil || len(evidence.Items) != 0 {
		t.Fatal("accepted empty Evidence retained upstream body backing")
	}
}

func prometheusExecutionForTest(t *testing.T, maxItems, maxSamples int) readconnector.ExecutionSpec {
	t.Helper()
	definition := readconnector.Definition{
		Scope: readconnector.Scope{
			TenantID: prometheusTestTenant, WorkspaceID: prometheusTestWorkspace,
			EnvironmentID: prometheusTestEnvironment, ServiceID: prometheusTestService,
		},
		TargetRef: "metrics-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PrometheusRangeQuery: &readconnector.PrometheusRangeQueryV1{
			Expression: "up", StepSeconds: 30, MaxLookbackMinutes: 1,
			MaxItems: maxItems, MaxSamples: maxSamples,
		},
	}
	connectorID, err := readconnector.BuildConnectorID("metrics", definition)
	if err != nil {
		t.Fatalf("BuildConnectorID() error = %v", err)
	}
	definition.ConnectorID = connectorID
	registry, err := readconnector.New([]readconnector.Definition{definition})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	execution, err := registry.ResolveTaskSpec(context.Background(), investigation.TaskSpecScope{
		TenantID: prometheusTestTenant, WorkspaceID: prometheusTestWorkspace,
		EnvironmentID: prometheusTestEnvironment, ServiceID: prometheusTestService,
		MappingStatus: domain.MappingExact,
	}, investigation.TaskSpec{
		Key: "metrics", ConnectorID: connectorID, Operation: readconnector.OperationPrometheusRangeQuery,
		Input: json.RawMessage(`{"lookback_minutes":1}`),
	})
	if err != nil {
		t.Fatalf("ResolveTaskSpec() error = %v", err)
	}
	return execution
}
