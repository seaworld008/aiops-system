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

func TestParseVictoriaLogsResponseProjectsCanonicalChronologicalEvidence(t *testing.T) {
	t.Parallel()
	execution := victoriaExecutionForTest(t, 3)
	collectedAt := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	body := []byte("  {\"_msg\":\"later\",\"_time\":\"2026-07-12T09:59:30Z\",\"level\":2}\r\n" +
		"{\"level\":1,\"_time\":\"2026-07-12T09:59:00Z\",\"_msg\":\"earlier\"}\n")

	evidence, failure := parseVictoriaLogsResponse(body, execution, collectedAt)
	if failure != responseAccepted || len(evidence.Items) != 2 || !evidence.CollectedAt.Equal(collectedAt) {
		t.Fatalf("parseVictoriaLogsResponse() = %#v, %v", evidence, failure)
	}
	want := []string{
		`{"_msg":"earlier","_time":"2026-07-12T09:59:00Z","level":1}`,
		`{"_msg":"later","_time":"2026-07-12T09:59:30Z","level":2}`,
	}
	for index := range want {
		if string(evidence.Items[index]) != want[index] {
			t.Fatalf("Evidence.Items[%d] = %s, want %s", index, evidence.Items[index], want[index])
		}
	}
	if err := execution.ValidateEvidence(evidence); err != nil {
		t.Fatalf("Evidence failed connector validation: %v", err)
	}
	clear(body)
	if string(evidence.Items[0]) != want[0] {
		t.Fatal("Evidence retained upstream response backing")
	}
}

func TestParseVictoriaLogsResponseReturnsDetachedNonNilEmptyEvidence(t *testing.T) {
	t.Parallel()
	execution := victoriaExecutionForTest(t, 3)
	collectedAt := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	evidence, failure := parseVictoriaLogsResponse(nil, execution, collectedAt)
	if failure != responseAccepted || evidence.Items == nil || len(evidence.Items) != 0 || !evidence.CollectedAt.Equal(collectedAt) {
		t.Fatalf("empty VictoriaLogs Evidence = %#v, %v", evidence, failure)
	}
}

func TestParseVictoriaLogsResponseRejectsMalformedPartialOrOutOfContractLines(t *testing.T) {
	t.Parallel()
	execution := victoriaExecutionForTest(t, 2)
	collectedAt := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	valid := `{"_time":"2026-07-12T09:59:30Z","_msg":"ok","level":1}`
	const canary = "victoria-response-secret-canary"
	tests := map[string]struct {
		body []byte
		want responseFailure
	}{
		"blank line":               {[]byte(valid + "\n\n" + valid), responseInvalid},
		"array line":               {[]byte(`[]`), responseInvalid},
		"malformed":                {[]byte(`{"_time":"` + canary), responseInvalid},
		"duplicate field":          {[]byte(`{"_time":"2026-07-12T09:59:30Z","_time":"2026-07-12T09:59:31Z","_msg":"ok","level":1}`), responseInvalid},
		"trailing value":           {[]byte(valid + ` {}`), responseInvalid},
		"missing time":             {[]byte(`{"_msg":"ok","level":1}`), responseRejected},
		"null time":                {[]byte(`{"_time":null,"_msg":"ok","level":1}`), responseRejected},
		"non UTC time":             {[]byte(`{"_time":"2026-07-12T17:59:30+08:00","_msg":"ok","level":1}`), responseRejected},
		"non canonical time":       {[]byte(`{"_time":"2026-07-12T09:59:30.000Z","_msg":"ok","level":1}`), responseRejected},
		"time outside window":      {[]byte(`{"_time":"2026-07-12T09:00:00Z","_msg":"ok","level":1}`), responseRejected},
		"missing required message": {[]byte(`{"_time":"2026-07-12T09:59:30Z","level":1}`), responseRejected},
		"unknown field":            {[]byte(`{"_time":"2026-07-12T09:59:30Z","_msg":"ok","level":1,"unknown":"` + canary + `"}`), responseRejected},
		"wrong number type":        {[]byte(`{"_time":"2026-07-12T09:59:30Z","_msg":"ok","level":"1"}`), responseRejected},
		"unsafe value":             {[]byte(`{"_time":"2026-07-12T09:59:30Z","_msg":"Bearer ` + canary + `","level":1}`), responseRejected},
		"too many rows":            {[]byte(valid + "\n" + valid + "\n" + valid), responseRejected},
		"newline amplification":    {bytes.Repeat([]byte{'\n'}, MaximumUpstreamResponseBytes), responseInvalid},
		"upstream over budget":     {bytes.Repeat([]byte("x"), MaximumUpstreamResponseBytes+1), responseRejected},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			evidence, failure := parseVictoriaLogsResponse(test.body, execution, collectedAt)
			if failure != test.want || evidence.Items != nil || !evidence.CollectedAt.IsZero() {
				t.Fatalf("parseVictoriaLogsResponse(%s) = %#v, %v; want %v", name, evidence, failure, test.want)
			}
			if strings.Contains(fmt.Sprintf("%v %+v %#v", failure, failure, failure), canary) {
				t.Fatal("failure leaked upstream body")
			}
		})
	}
}

func TestParseVictoriaLogsResponseEnforcesProjectedEvidenceBudget(t *testing.T) {
	t.Parallel()
	execution := victoriaExecutionForTestWithMessageBudget(t, 2, 16<<10)
	collectedAt := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	message := strings.Repeat("x", 16<<10)
	line := fmt.Sprintf(`{"_time":"2026-07-12T09:59:30Z","_msg":%q,"level":1}`, message)
	body := []byte(line + "\n" + line)
	if evidence, failure := parseVictoriaLogsResponse(body, execution, collectedAt); failure != responseAccepted || len(evidence.Items) != 2 {
		t.Fatalf("bounded evidence = %#v, %v", evidence, failure)
	}

	message = strings.Repeat("x", 33<<10)
	body = []byte(fmt.Sprintf(`{"_time":"2026-07-12T09:59:30Z","_msg":%q,"level":1}`, message))
	if evidence, failure := parseVictoriaLogsResponse(body, execution, collectedAt); failure != responseRejected || evidence.Items != nil {
		t.Fatalf("oversized field = %#v, %v", evidence, failure)
	}
}

func victoriaExecutionForTest(t *testing.T, limit int) readconnector.ExecutionSpec {
	return victoriaExecutionForTestWithMessageBudget(t, limit, 2048)
}

func victoriaExecutionForTestWithMessageBudget(t *testing.T, limit, messageBytes int) readconnector.ExecutionSpec {
	t.Helper()
	definition := readconnector.Definition{
		Scope: readconnector.Scope{
			TenantID: prometheusTestTenant, WorkspaceID: prometheusTestWorkspace,
			EnvironmentID: prometheusTestEnvironment, ServiceID: prometheusTestService,
		},
		TargetRef: "logs-v1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		VictoriaLogsSearch: &readconnector.VictoriaLogsSearchV1{
			Query: "error | fields _time, _msg, level", Limit: limit, MaxLookbackMinutes: 1,
			Fields: []readconnector.FieldSpec{
				{Name: "_time", Type: readconnector.FieldString, Required: true, MaxBytes: 64},
				{Name: "_msg", Type: readconnector.FieldString, Required: true, MaxBytes: messageBytes},
				{Name: "level", Type: readconnector.FieldNumber, Required: true},
			},
		},
	}
	connectorID, err := readconnector.BuildConnectorID("logs", definition)
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
		Key: "logs", ConnectorID: connectorID, Operation: readconnector.OperationVictoriaLogsSearch,
		Input: json.RawMessage(`{"lookback_minutes":1}`),
	})
	if err != nil {
		t.Fatalf("ResolveTaskSpec() error = %v", err)
	}
	return execution
}
