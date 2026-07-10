package argocd_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/connectors"
	"github.com/aiops-system/control-plane/internal/connectors/argocd"
)

func TestListApplicationsReturnsBoundedReadOnlyStatusEvidence(t *testing.T) {
	const token = "argocd-secret-token"
	body := []byte(`{"items":[{"metadata":{"name":"checkout"},"status":{"health":{"status":"Healthy"},"sync":{"status":"Synced","revision":"abc123"},"history":[{"id":1,"revision":"old123"}]}},{"metadata":{"name":"orders"},"status":{"health":{"status":"Degraded"},"sync":{"status":"OutOfSync","revision":"def456"},"history":[]}},{"metadata":{"name":"payments"},"status":{"health":{"status":"Healthy"},"sync":{"status":"Synced","revision":"ghi789"},"history":[]}}]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Fatalf("method = %q, want GET", request.Method)
		}
		if request.URL.Path != "/api/v1/applications" {
			t.Fatalf("path = %q, want /api/v1/applications", request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer "+token {
			t.Fatalf("Authorization = %q", got)
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()

	client, err := argocd.New(server.URL, token, nil, connectors.Budget{
		Timeout:  2 * time.Second,
		MaxBytes: 16 << 10,
		MaxItems: 2,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result, err := client.ListApplications(context.Background())
	if err != nil {
		t.Fatalf("ListApplications() error = %v", err)
	}
	projectedBody, _ := json.Marshal(result.Items)
	wantHash := sha256.Sum256(projectedBody)
	if result.Source != "argocd" || result.ItemCount != 2 || len(result.Items) != 2 {
		t.Fatalf("result = %#v", result)
	}
	if !result.Truncated || result.ContentHash != hex.EncodeToString(wantHash[:]) || result.CollectedAt.IsZero() {
		t.Fatalf("missing truncation/hash/time: %#v", result)
	}
	if strings.Contains(result.Query, token) {
		t.Fatalf("Query leaks bearer token: %q", result.Query)
	}

	var application struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			Health struct {
				Status string `json:"status"`
			} `json:"health"`
			Sync struct {
				Status   string `json:"status"`
				Revision string `json:"revision"`
			} `json:"sync"`
			History []json.RawMessage `json:"history"`
		} `json:"status"`
	}
	if err := json.Unmarshal(result.Items[0], &application); err != nil {
		t.Fatalf("decode application evidence: %v", err)
	}
	if application.Metadata.Name != "checkout" || application.Status.Health.Status != "Healthy" || application.Status.Sync.Status != "Synced" || application.Status.Sync.Revision != "abc123" || len(application.Status.History) != 1 {
		t.Fatalf("application = %#v", application)
	}
}

func TestArgoCDEnforcesResponseByteAndTimeoutBudgets(t *testing.T) {
	t.Run("response bytes", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", 65)))
		}))
		defer server.Close()

		client, err := argocd.New(server.URL, "token", nil, connectors.Budget{
			Timeout:  time.Second,
			MaxBytes: 64,
			MaxItems: 10,
		})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if _, err := client.ListApplications(context.Background()); err == nil {
			t.Fatal("ListApplications() error = nil, want response byte budget error")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
			<-request.Context().Done()
		}))
		defer server.Close()

		client, err := argocd.New(server.URL, "token", nil, connectors.Budget{
			Timeout:  20 * time.Millisecond,
			MaxBytes: 16 << 10,
			MaxItems: 10,
		})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if _, err := client.ListApplications(context.Background()); err == nil {
			t.Fatal("ListApplications() error = nil, want timeout error")
		}
	})
}

func TestArgoCDRejectsMalformedApplicationEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":{}}`))
	}))
	defer server.Close()

	client, err := argocd.New(server.URL, "token", nil, connectors.DefaultBudget())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := client.ListApplications(context.Background()); err == nil {
		t.Fatal("ListApplications() error = nil, want decode error")
	}
}

func TestArgoCDProjectsOnlyStatusTimelineFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"checkout","namespace":"argocd","annotations":{"secret":"hidden"}},"spec":{"source":{"helm":{"parameters":[{"name":"password","value":"secret"}]}}},"status":{"health":{"status":"Healthy","message":"ok"},"sync":{"status":"Synced","revision":"abc"},"history":[{"id":1,"revision":"old","deployedAt":"2026-07-10T10:00:00Z","source":{"helm":{"parameters":[{"value":"secret"}]}}}]}}]}`))
	}))
	defer server.Close()
	client, err := argocd.New(server.URL, "token", nil, connectors.DefaultBudget())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	result, err := client.ListApplications(context.Background())
	if err != nil {
		t.Fatalf("ListApplications() error = %v", err)
	}
	encoded := string(result.Items[0])
	if strings.Contains(encoded, "password") || strings.Contains(encoded, "annotations") || strings.Contains(encoded, `"value":"secret"`) {
		t.Fatalf("projected application evidence leaks arbitrary config: %s", encoded)
	}
	if !strings.Contains(encoded, "Healthy") || !strings.Contains(encoded, "abc") || !strings.Contains(encoded, "old") {
		t.Fatalf("projected application evidence misses status timeline: %s", encoded)
	}
}

func TestArgoCDRejectsRedirectsWithoutMutatingCallerHTTPClient(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetRequests.Add(1)
		_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"checkout"}}]}`))
	}))
	defer target.Close()

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, target.URL, http.StatusFound)
	}))
	defer redirect.Close()

	var callerRedirectHookCalls atomic.Int32
	provided := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			callerRedirectHookCalls.Add(1)
			return nil
		},
	}
	client, err := argocd.New(redirect.URL, "token", provided, connectors.DefaultBudget())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := client.ListApplications(context.Background()); err == nil {
		t.Fatal("ListApplications() error = nil, want redirect rejection")
	}
	if got := targetRequests.Load(); got != 0 {
		t.Fatalf("redirect target requests = %d, want 0", got)
	}
	if got := callerRedirectHookCalls.Load(); got != 0 {
		t.Fatalf("caller CheckRedirect calls = %d, want connector-owned redirect policy", got)
	}

	if provided.CheckRedirect == nil {
		t.Fatal("provided CheckRedirect was mutated")
	}
	if err := provided.CheckRedirect(&http.Request{}, nil); err != nil {
		t.Fatalf("provided CheckRedirect() error = %v", err)
	}
	if got := callerRedirectHookCalls.Load(); got != 1 {
		t.Fatalf("provided CheckRedirect calls after direct use = %d, want 1", got)
	}
}

func TestArgoCDNewRejectsUnsafeURLAndToken(t *testing.T) {
	tests := []struct {
		name   string
		rawURL string
		token  string
	}{
		{name: "non HTTP scheme", rawURL: "ftp://argocd.example", token: "token"},
		{name: "non-loopback cleartext", rawURL: "http://argocd.example", token: "token"},
		{name: "forced empty query", rawURL: "https://argocd.example?", token: "token"},
		{name: "URL user info", rawURL: "https://user@argocd.example", token: "token"},
		{name: "URL query", rawURL: "https://argocd.example?debug=true", token: "token"},
		{name: "URL fragment", rawURL: "https://argocd.example#fragment", token: "token"},
		{name: "empty token", rawURL: "https://argocd.example", token: ""},
		{name: "leading whitespace", rawURL: "https://argocd.example", token: " token"},
		{name: "trailing whitespace", rawURL: "https://argocd.example", token: "token "},
		{name: "embedded whitespace", rawURL: "https://argocd.example", token: "tok en"},
		{name: "control character", rawURL: "https://argocd.example", token: "tok\x7fen"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := argocd.New(test.rawURL, test.token, nil, connectors.DefaultBudget()); err == nil {
				t.Fatal("New() error = nil, want input validation error")
			}
		})
	}
}

func TestArgoCDRejectsMissingItemsAndInvalidApplicationNames(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "null envelope", body: `null`},
		{name: "missing items", body: `{}`},
		{name: "null items", body: `{"items":null}`},
		{name: "missing application name", body: `{"items":[{"metadata":{}}]}`},
		{name: "blank application name", body: `{"items":[{"metadata":{"name":"   "}}]}`},
		{name: "invalid application name", body: `{"items":[{"metadata":{"name":"../production"}}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			client, err := argocd.New(server.URL, "token", nil, connectors.DefaultBudget())
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if _, err := client.ListApplications(context.Background()); err == nil {
				t.Fatal("ListApplications() error = nil, want response validation error")
			}
		})
	}
}
