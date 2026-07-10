package prometheus_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	projected, err := json.Marshal(result.Items)
	if err != nil {
		t.Fatalf("marshal result items: %v", err)
	}
	wantHash := sha256.Sum256(projected)
	if result.ContentHash != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("ContentHash = %q, want final Items hash", result.ContentHash)
	}
}

func TestNewRejectsUnsafeURLAndQueryRejectsRedirect(t *testing.T) {
	t.Parallel()

	for _, rawURL := range []string{"file:///tmp/prometheus", "https://user@example.com", "https://example.com?token=x", "https://example.com#fragment"} {
		if _, err := prometheus.New(rawURL, nil, connectors.DefaultBudget()); err == nil {
			t.Fatalf("New(%q) error = nil, want URL rejection", rawURL)
		}
	}

	targetCalled := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalled = true }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer redirect.Close()
	client, err := prometheus.New(redirect.URL, nil, connectors.DefaultBudget())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := client.Query(context.Background(), "up", time.Now()); err == nil {
		t.Fatal("Query() followed redirect")
	}
	if targetCalled {
		t.Fatal("redirect target was called")
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
		Start:      start,
		End:        start.Add(10 * time.Minute),
		Step:       30 * time.Second,
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

func TestQueryRejectsActualInstantSampleOverflow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"value":[1,"1"]},{"histogram":[1,{"count":"1"}]}]}}`))
	}))
	defer server.Close()

	budget := connectors.DefaultBudget()
	budget.MaxSamples = 1
	client, err := prometheus.New(server.URL, nil, budget)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := client.Query(context.Background(), "up", time.Now()); err == nil {
		t.Fatal("Query() error = nil, want actual sample budget rejection")
	}
}

func TestQueryRangeCountsNativeHistogramSamples(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"histograms":[[1,{"count":"1"}],[2,{"count":"1"}]]},{"values":[[1,"1"],[2,"1"]]}]}}`))
	}))
	defer server.Close()

	budget := connectors.DefaultBudget()
	budget.MaxSamples = 2
	client, err := prometheus.New(server.URL, nil, budget)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	start := time.Now().UTC()
	if _, err := client.QueryRange(context.Background(), prometheus.RangeRequest{
		Expression: "up",
		Start:      start,
		End:        start.Add(time.Minute),
		Step:       time.Minute,
	}); err == nil {
		t.Fatal("QueryRange() error = nil, want native histogram sample budget rejection")
	}
}
