package readconnector_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

func TestPrometheusRangeCompletionContractRejectsEveryShapeOrBudgetDrift(t *testing.T) {
	registry := mustRegistry(t)
	descriptor := validDescriptor(t, prometheusID, readconnector.OperationPrometheusRangeQuery, json.RawMessage(`{"lookback_minutes":15}`))
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	valid := readtask.EvidenceCompletion{CollectedAt: now, Items: []json.RawMessage{
		json.RawMessage(fmt.Sprintf(`{"metric":{"job":"api"},"values":[[%d,"1"]]}`, now.Add(-time.Minute).Unix())),
	}}
	if err := registry.AuthorizeCompletion(context.Background(), descriptor, valid); err != nil {
		t.Fatalf("AuthorizeCompletion(valid) error = %v", err)
	}

	tests := map[string]json.RawMessage{
		"missing metric":           json.RawMessage(fmt.Sprintf(`{"values":[[%d,"1"]]}`, now.Unix())),
		"missing values":           json.RawMessage(`{"metric":{"job":"api"}}`),
		"extra field":              json.RawMessage(fmt.Sprintf(`{"metric":{},"values":[[%d,"1"]],"histograms":[]}`, now.Unix())),
		"native histogram":         json.RawMessage(fmt.Sprintf(`{"metric":{},"values":[[%d,{"count":"1"}]]}`, now.Unix())),
		"bad label":                json.RawMessage(fmt.Sprintf(`{"metric":{"bad-label":"x"},"values":[[%d,"1"]]}`, now.Unix())),
		"reserved label":           json.RawMessage(fmt.Sprintf(`{"metric":{"source":"x"},"values":[[%d,"1"]]}`, now.Unix())),
		"tokenized reserved label": json.RawMessage(fmt.Sprintf(`{"metric":{"source_name":"x"},"values":[[%d,"1"]]}`, now.Unix())),
		"reserved name carrier":    json.RawMessage(fmt.Sprintf(`{"metric":{"name":"source_url"},"values":[[%d,"1"]]}`, now.Unix())),
		"null label":               json.RawMessage(fmt.Sprintf(`{"metric":{"job":null},"values":[[%d,"1"]]}`, now.Unix())),
		"short sample":             json.RawMessage(fmt.Sprintf(`{"metric":{},"values":[[%d]]}`, now.Unix())),
		"long sample":              json.RawMessage(fmt.Sprintf(`{"metric":{},"values":[[%d,"1","x"]]}`, now.Unix())),
		"numeric value":            json.RawMessage(fmt.Sprintf(`{"metric":{},"values":[[%d,1]]}`, now.Unix())),
		"bad value":                json.RawMessage(fmt.Sprintf(`{"metric":{},"values":[[%d,"not-a-number"]]}`, now.Unix())),
		"timestamp before range":   json.RawMessage(fmt.Sprintf(`{"metric":{},"values":[[%d,"1"]]}`, now.Add(-20*time.Minute).Unix())),
		"timestamp in future":      json.RawMessage(fmt.Sprintf(`{"metric":{},"values":[[%d,"1"]]}`, now.Add(time.Minute).Unix())),
		"timestamps decrease":      json.RawMessage(fmt.Sprintf(`{"metric":{},"values":[[%d,"1"],[%d,"2"]]}`, now.Add(-time.Minute).Unix(), now.Add(-2*time.Minute).Unix())),
		"duplicate timestamp":      json.RawMessage(fmt.Sprintf(`{"metric":{},"values":[[%d,"1"],[%d,"2"]]}`, now.Add(-time.Minute).Unix(), now.Add(-time.Minute).Unix())),
		"denser than fixed step":   json.RawMessage(fmt.Sprintf(`{"metric":{},"values":[[%d,"1"],[%d,"2"]]}`, now.Add(-time.Minute).Unix(), now.Add(-time.Minute+time.Second).Unix())),
		"off fixed step grid":      json.RawMessage(fmt.Sprintf(`{"metric":{},"values":[[%d,"1"],[%d,"2"]]}`, now.Add(-time.Minute).Unix(), now.Add(-29*time.Second).Unix())),
		"empty values":             json.RawMessage(`{"metric":{},"values":[]}`),
		"noncanonical timestamp":   json.RawMessage(fmt.Sprintf(`{"metric":{},"values":[[%d.0,"1"]]}`, now.Unix())),
	}
	for name, item := range tests {
		t.Run(name, func(t *testing.T) {
			evidence := valid
			evidence.Items = []json.RawMessage{item}
			if err := registry.AuthorizeCompletion(context.Background(), descriptor, evidence); !errors.Is(err, readconnector.ErrContractRejected) {
				t.Fatalf("AuthorizeCompletion() error = %v, want ErrContractRejected", err)
			}
		})
	}

	tooMany := valid
	tooMany.Items = make([]json.RawMessage, 101)
	for index := range tooMany.Items {
		tooMany.Items[index] = valid.Items[0]
	}
	if err := registry.AuthorizeCompletion(context.Background(), descriptor, tooMany); !errors.Is(err, readconnector.ErrContractRejected) {
		t.Fatalf("AuthorizeCompletion(too many items) error = %v", err)
	}
}

func TestVictoriaLogsCompletionContractEnforcesProjectionTypesAndWindow(t *testing.T) {
	registry := mustRegistry(t)
	descriptor := validDescriptor(t, victoriaID, readconnector.OperationVictoriaLogsSearch, json.RawMessage(`{"lookback_minutes":15}`))
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	valid := readtask.EvidenceCompletion{CollectedAt: now, Items: []json.RawMessage{
		json.RawMessage(`{"_time":"2026-07-11T09:59:00Z","_msg":"boom","status":503,"retryable":true,"trace":null}`),
	}}
	if err := registry.AuthorizeCompletion(context.Background(), descriptor, valid); err != nil {
		t.Fatalf("AuthorizeCompletion(valid) error = %v", err)
	}

	tests := map[string]json.RawMessage{
		"empty":               json.RawMessage(`{}`),
		"unknown field":       json.RawMessage(`{"_time":"2026-07-11T09:59:00Z","_msg":"boom","pod":"x"}`),
		"missing required":    json.RawMessage(`{"_time":"2026-07-11T09:59:00Z"}`),
		"nested":              json.RawMessage(`{"_time":"2026-07-11T09:59:00Z","_msg":{"nested":"boom"}}`),
		"wrong string":        json.RawMessage(`{"_time":"2026-07-11T09:59:00Z","_msg":42}`),
		"null string":         json.RawMessage(`{"_time":"2026-07-11T09:59:00Z","_msg":null}`),
		"wrong number":        json.RawMessage(`{"_time":"2026-07-11T09:59:00Z","_msg":"boom","status":"503"}`),
		"wrong boolean":       json.RawMessage(`{"_time":"2026-07-11T09:59:00Z","_msg":"boom","retryable":"true"}`),
		"wrong null":          json.RawMessage(`{"_time":"2026-07-11T09:59:00Z","_msg":"boom","trace":"value"}`),
		"noncanonical time":   json.RawMessage(`{"_time":"2026-07-11T09:59:00+00:00","_msg":"boom"}`),
		"before range":        json.RawMessage(`{"_time":"2026-07-11T09:40:00Z","_msg":"boom"}`),
		"future":              json.RawMessage(`{"_time":"2026-07-11T10:01:00Z","_msg":"boom"}`),
		"unsafe integer":      json.RawMessage(`{"_time":"2026-07-11T09:59:00Z","_msg":"boom","status":9007199254740992}`),
		"rounded integer":     json.RawMessage(`{"_time":"2026-07-11T09:59:00Z","_msg":"boom","status":9007199254740993}`),
		"noncanonical number": json.RawMessage(`{"_time":"2026-07-11T09:59:00Z","_msg":"boom","status":1.0}`),
		"negative zero":       json.RawMessage(`{"_time":"2026-07-11T09:59:00Z","_msg":"boom","status":-0}`),
		"underflow":           json.RawMessage(`{"_time":"2026-07-11T09:59:00Z","_msg":"boom","status":1e-400}`),
		"overflow":            json.RawMessage(`{"_time":"2026-07-11T09:59:00Z","_msg":"boom","status":1e999}`),
	}
	for name, item := range tests {
		t.Run(name, func(t *testing.T) {
			evidence := valid
			evidence.Items = []json.RawMessage{item}
			if err := registry.AuthorizeCompletion(context.Background(), descriptor, evidence); !errors.Is(err, readconnector.ErrContractRejected) {
				t.Fatalf("AuthorizeCompletion() error = %v, want ErrContractRejected", err)
			}
		})
	}
	safeInteger := valid
	safeInteger.Items = []json.RawMessage{json.RawMessage(
		`{"_time":"2026-07-11T09:59:00Z","_msg":"boom","status":9007199254740991}`,
	)}
	if err := registry.AuthorizeCompletion(context.Background(), descriptor, safeInteger); err != nil {
		t.Fatalf("AuthorizeCompletion(max safe integer) error = %v", err)
	}

	tooLong := valid
	tooLong.Items = []json.RawMessage{json.RawMessage(fmt.Sprintf(
		`{"_time":"2026-07-11T09:59:00Z","_msg":%q}`, strings.Repeat("x", 2049),
	))}
	if err := registry.AuthorizeCompletion(context.Background(), descriptor, tooLong); !errors.Is(err, readconnector.ErrContractRejected) {
		t.Fatalf("AuthorizeCompletion(oversized field) error = %v", err)
	}
}
