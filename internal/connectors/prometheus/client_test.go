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
