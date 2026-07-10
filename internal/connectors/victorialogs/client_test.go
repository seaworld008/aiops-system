package victorialogs_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/connectors"
	"github.com/seaworld008/aiops-system/internal/connectors/victorialogs"
)

func TestSearchEnforcesTimeFieldsLimitAndTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/select/logsql/query" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		body, _ := io.ReadAll(request.Body)
		values, _ := url.ParseQuery(string(body))
		if values.Get("start") == "" || values.Get("end") == "" {
			t.Fatalf("missing time bounds: %s", body)
		}
		if values.Get("limit") != "3" || values.Get("timeout") != "2s" {
			t.Fatalf("limit/timeout not enforced: %s", body)
		}
		if query := values.Get("query"); !strings.Contains(query, "fields _time,level,_msg") {
			t.Fatalf("query missing field projection: %q", query)
		}
		_, _ = w.Write([]byte("{\"_time\":\"2026-07-10T10:00:00Z\",\"level\":\"error\",\"_msg\":\"boom\",\"secret\":\"must-not-leak\"}\n"))
	}))
	defer server.Close()

	client, err := victorialogs.New(server.URL, nil, connectors.Budget{
		Timeout:  2 * time.Second,
		MaxBytes: 16 << 10,
		MaxItems: 2,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result, err := client.Search(context.Background(), victorialogs.SearchRequest{
		Query:  `service_name:api AND error`,
		Start:  time.Date(2026, 7, 10, 9, 55, 0, 0, time.UTC),
		End:    time.Date(2026, 7, 10, 10, 5, 0, 0, time.UTC),
		Fields: []string{"_time", "level", "_msg"},
		Limit:  2,
	})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if result.ItemCount != 1 || result.Source != "victorialogs" || result.ContentHash == "" {
		t.Fatalf("result = %#v", result)
	}
	if strings.Contains(string(result.Items[0]), "secret") {
		t.Fatalf("unrequested field leaked into evidence: %s", result.Items[0])
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

func TestNewRejectsUnsafeURLAndSearchRejectsRedirect(t *testing.T) {
	t.Parallel()

	for _, rawURL := range []string{"file:///tmp/logs", "https://user@example.com", "https://example.com?token=x", "https://example.com#fragment"} {
		if _, err := victorialogs.New(rawURL, nil, connectors.DefaultBudget()); err == nil {
			t.Fatalf("New(%q) error = nil, want URL rejection", rawURL)
		}
	}

	targetCalled := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalled = true }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	client, err := victorialogs.New(redirect.URL, nil, connectors.DefaultBudget())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	start := time.Now().UTC()
	_, err = client.Search(context.Background(), victorialogs.SearchRequest{Query: "error", Start: start, End: start.Add(time.Minute), Fields: []string{"_msg"}, Limit: 1})
	if err == nil {
		t.Fatal("Search() followed redirect")
	}
	if targetCalled {
		t.Fatal("redirect target was called")
	}
}

func TestSearchRejectsUnboundedOrInvalidRequests(t *testing.T) {
	budget := connectors.DefaultBudget()
	budget.MaxTimeRange = 15 * time.Minute
	client, err := victorialogs.New("http://victorialogs.invalid", nil, budget)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	requests := []victorialogs.SearchRequest{
		{Query: "error", Start: time.Now(), End: time.Time{}, Fields: []string{"_msg"}, Limit: 1},
		{Query: "error", Start: time.Now(), End: time.Now().Add(time.Minute), Fields: nil, Limit: 1},
		{Query: "error", Start: time.Now(), End: time.Now().Add(time.Minute), Fields: []string{"_msg"}, Limit: connectors.DefaultBudget().MaxItems + 1},
		{Query: "error", Start: time.Now(), End: time.Now().Add(16 * time.Minute), Fields: []string{"_msg"}, Limit: 1},
	}
	for _, request := range requests {
		if _, err := client.Search(context.Background(), request); err == nil {
			t.Fatalf("Search(%#v) error = nil, want validation error", request)
		}
	}
}
