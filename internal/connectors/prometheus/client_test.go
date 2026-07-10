package prometheus_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/connectors"
	"github.com/aiops-system/control-plane/internal/connectors/prometheus"
)

func TestQuerySendsBoundedPrometheusRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/query" {
			t.Fatalf("path = %q, want /api/v1/query", request.URL.Path)
		}
		if request.URL.Query().Get("query") != "up" {
			t.Fatalf("query = %q, want up", request.URL.Query().Get("query"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"job":"api"},"value":[1783650000,"1"]}]}}`))
	}))
	defer server.Close()

	client, err := prometheus.New(server.URL, nil, connectors.Budget{
		Timeout:  2 * time.Second,
		MaxBytes: 16 << 10,
		MaxItems: 10,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result, err := client.Query(context.Background(), "up", time.Unix(1783650000, 0))
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if result.Source != "prometheus" || result.ItemCount != 1 || result.ContentHash == "" {
		t.Fatalf("result = %#v", result)
	}
}

func TestQueryRejectsEmptyExpression(t *testing.T) {
	client, err := prometheus.New("http://prometheus.invalid", nil, connectors.DefaultBudget())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := client.Query(context.Background(), "", time.Now()); err == nil {
		t.Fatal("Query() error = nil, want validation error")
	}
}

func TestQueryRangeSendsBoundsAndStep(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/query_range" {
			t.Fatalf("path = %q, want /api/v1/query_range", request.URL.Path)
		}
		if request.URL.Query().Get("start") == "" || request.URL.Query().Get("end") == "" || request.URL.Query().Get("step") != "30" {
			t.Fatalf("missing bounds/step: %s", request.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	}))
	defer server.Close()

	client, err := prometheus.New(server.URL, nil, connectors.DefaultBudget())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	start := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	if _, err := client.QueryRange(context.Background(), prometheus.RangeRequest{
		Expression: "rate(http_requests_total[5m])",
		Start: start,
		End: start.Add(10 * time.Minute),
		Step: 30 * time.Second,
	}); err != nil {
		t.Fatalf("QueryRange() error = %v", err)
	}
}

func TestQueryRangeRejectsWindowOrSampleBudgetOverflow(t *testing.T) {
	budget := connectors.DefaultBudget()
	budget.MaxTimeRange = 15 * time.Minute
	budget.MaxSamples = 10
	client, err := prometheus.New("http://prometheus.invalid", nil, budget)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	start := time.Now()
	for _, request := range []prometheus.RangeRequest{
		{Expression: "up", Start: start, End: start.Add(16 * time.Minute), Step: time.Minute},
		{Expression: "up", Start: start, End: start.Add(10 * time.Minute), Step: time.Second},
	} {
		if _, err := client.QueryRange(context.Background(), request); err == nil {
			t.Fatalf("QueryRange(%#v) error = nil, want budget rejection", request)
		}
	}
}
