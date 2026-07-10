package awx_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/connectors"
	"github.com/seaworld008/aiops-system/internal/connectors/awx"
)

func TestListInventoryHostsUsesBoundedReadOnlyRequest(t *testing.T) {
	const token = "awx-secret-token"
	body := []byte(`{"count":3,"next":"/api/v2/inventories/42/hosts/?page=2","results":[{"id":1,"name":"linux-1"},{"id":2,"name":"windows-1"},{"id":3,"name":"linux-2"}]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Fatalf("method = %q, want GET", request.Method)
		}
		if request.URL.Path != "/api/v2/inventories/42/hosts/" {
			t.Fatalf("path = %q, want inventory hosts endpoint", request.URL.Path)
		}
		if request.URL.Query().Get("page") != "1" || request.URL.Query().Get("page_size") != "2" {
			t.Fatalf("pagination = %q, want page=1&page_size=2", request.URL.RawQuery)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer "+token {
			t.Fatalf("Authorization = %q", got)
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()

	client, err := awx.New(server.URL, token, nil, connectors.Budget{
		Timeout:  2 * time.Second,
		MaxBytes: 16 << 10,
		MaxItems: 2,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result, err := client.ListInventoryHosts(context.Background(), 42)
	if err != nil {
		t.Fatalf("ListInventoryHosts() error = %v", err)
	}
	projectedBody, _ := json.Marshal(result.Items)
	wantHash := sha256.Sum256(projectedBody)
	if result.Source != "awx" || result.ItemCount != 2 || len(result.Items) != 2 {
		t.Fatalf("result = %#v", result)
	}
	if !result.Truncated {
		t.Fatal("Truncated = false, want true")
	}
	if result.ContentHash != hex.EncodeToString(wantHash[:]) || result.CollectedAt.IsZero() {
		t.Fatalf("hash/time missing from result: %#v", result)
	}
	if strings.Contains(result.Query, token) {
		t.Fatalf("Query leaks bearer token: %q", result.Query)
	}
}

func TestListInventoryHostsCapsAWXPageSizeAtFixedMaximum(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if got := request.URL.Query().Get("page_size"); got != "100" {
			t.Fatalf("page_size = %q, want fixed maximum 100", got)
		}
		_, _ = w.Write([]byte(`{"count":0,"next":null,"results":[]}`))
	}))
	defer server.Close()

	client, err := awx.New(server.URL, "token", nil, connectors.Budget{
		Timeout:  time.Second,
		MaxBytes: 16 << 10,
		MaxItems: 500,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := client.ListInventoryHosts(context.Background(), 1); err != nil {
		t.Fatalf("ListInventoryHosts() error = %v", err)
	}
}

func TestGetJobTemplateAndJobStatusUseReadOnlyEndpoints(t *testing.T) {
	const token = "awx-read-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Fatalf("method = %q, want GET", request.Method)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer "+token {
			t.Fatalf("Authorization = %q", got)
		}
		switch request.URL.Path {
		case "/api/v2/job_templates/7/":
			_, _ = w.Write([]byte(`{"id":7,"name":"restart-service","job_type":"run"}`))
		case "/api/v2/jobs/9/":
			_, _ = w.Write([]byte(`{"id":9,"status":"successful","finished":"2026-07-10T10:00:00Z"}`))
		default:
			t.Fatalf("unexpected path %q", request.URL.Path)
		}
	}))
	defer server.Close()

	client, err := awx.New(server.URL, token, nil, connectors.Budget{
		Timeout:  time.Second,
		MaxBytes: 16 << 10,
		MaxItems: 10,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	results := make([]connectors.Result, 0, 2)
	template, err := client.GetJobTemplate(context.Background(), 7)
	if err != nil {
		t.Fatalf("GetJobTemplate() error = %v", err)
	}
	results = append(results, template)
	job, err := client.GetJobStatus(context.Background(), 9)
	if err != nil {
		t.Fatalf("GetJobStatus() error = %v", err)
	}
	results = append(results, job)

	for index, result := range results {
		if result.Source != "awx" || result.ItemCount != 1 || len(result.Items) != 1 || result.ContentHash == "" || result.CollectedAt.IsZero() {
			t.Fatalf("result[%d] = %#v", index, result)
		}
		if result.Truncated || strings.Contains(result.Query, token) {
			t.Fatalf("unsafe result[%d] = %#v", index, result)
		}
	}
}

func TestAWXEnforcesResponseByteAndTimeoutBudgets(t *testing.T) {
	t.Run("response bytes", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", 65)))
		}))
		defer server.Close()

		client, err := awx.New(server.URL, "token", nil, connectors.Budget{
			Timeout:  time.Second,
			MaxBytes: 64,
			MaxItems: 10,
		})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if _, err := client.GetJobStatus(context.Background(), 1); err == nil {
			t.Fatal("GetJobStatus() error = nil, want response byte budget error")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
			<-request.Context().Done()
		}))
		defer server.Close()

		client, err := awx.New(server.URL, "token", nil, connectors.Budget{
			Timeout:  20 * time.Millisecond,
			MaxBytes: 16 << 10,
			MaxItems: 10,
		})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if _, err := client.GetJobStatus(context.Background(), 1); err == nil {
			t.Fatal("GetJobStatus() error = nil, want timeout error")
		}
	})
}

func TestAWXRejectsInvalidResourceIDs(t *testing.T) {
	client, err := awx.New("https://awx.invalid", "token", nil, connectors.DefaultBudget())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for name, call := range map[string]func() error{
		"inventory": func() error {
			_, err := client.ListInventoryHosts(context.Background(), 0)
			return err
		},
		"template": func() error {
			_, err := client.GetJobTemplate(context.Background(), -1)
			return err
		},
		"job": func() error {
			_, err := client.GetJobStatus(context.Background(), 0)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("error = nil, want positive ID validation error")
			}
		})
	}
}

func TestAWXResultQueryContainsOnlySanitizedResourceIdentity(t *testing.T) {
	const token = "do-not-copy-into-query"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":23,"status":"running"}`))
	}))
	defer server.Close()

	client, err := awx.New(server.URL, token, nil, connectors.DefaultBudget())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	result, err := client.GetJobStatus(context.Background(), 23)
	if err != nil {
		t.Fatalf("GetJobStatus() error = %v", err)
	}
	if result.Query != "job_status id="+strconv.Itoa(23) {
		t.Fatalf("Query = %q", result.Query)
	}
}

func TestAWXProjectsOutVariablesAndCredentialMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"count":1,"next":null,"results":[{"id":1,"name":"linux-1","enabled":true,"variables":"password=secret","summary_fields":{"credentials":[{"name":"prod-root"}]}}]}`))
	}))
	defer server.Close()
	client, err := awx.New(server.URL, "token", nil, connectors.DefaultBudget())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	result, err := client.ListInventoryHosts(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListInventoryHosts() error = %v", err)
	}
	encoded := string(result.Items[0])
	if strings.Contains(encoded, "password") || strings.Contains(encoded, "prod-root") || !strings.Contains(encoded, "linux-1") {
		t.Fatalf("projected host evidence = %s", encoded)
	}
}

func TestAWXRejectsRedirectsWithoutMutatingCallerHTTPClient(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetRequests.Add(1)
		_, _ = w.Write([]byte(`{"id":1,"status":"successful"}`))
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
	client, err := awx.New(redirect.URL, "token", provided, connectors.DefaultBudget())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := client.GetJobStatus(context.Background(), 1); err == nil {
		t.Fatal("GetJobStatus() error = nil, want redirect rejection")
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

func TestAWXNewRejectsUnsafeURLAndToken(t *testing.T) {
	tests := []struct {
		name   string
		rawURL string
		token  string
	}{
		{name: "non HTTP scheme", rawURL: "ftp://awx.example", token: "token"},
		{name: "non-loopback cleartext", rawURL: "http://awx.example", token: "token"},
		{name: "forced empty query", rawURL: "https://awx.example?", token: "token"},
		{name: "URL user info", rawURL: "https://user@awx.example", token: "token"},
		{name: "URL query", rawURL: "https://awx.example?debug=true", token: "token"},
		{name: "URL fragment", rawURL: "https://awx.example#fragment", token: "token"},
		{name: "empty token", rawURL: "https://awx.example", token: ""},
		{name: "leading whitespace", rawURL: "https://awx.example", token: " token"},
		{name: "trailing whitespace", rawURL: "https://awx.example", token: "token "},
		{name: "embedded whitespace", rawURL: "https://awx.example", token: "tok en"},
		{name: "control character", rawURL: "https://awx.example", token: "tok\x7fen"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := awx.New(test.rawURL, test.token, nil, connectors.DefaultBudget()); err == nil {
				t.Fatal("New() error = nil, want input validation error")
			}
		})
	}
}

func TestAWXRejectsMalformedInventoryEnvelopeAndHostIdentity(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "null envelope", body: `null`},
		{name: "missing count", body: `{"next":null,"results":[]}`},
		{name: "negative count", body: `{"count":-1,"next":null,"results":[]}`},
		{name: "missing next", body: `{"count":0,"results":[]}`},
		{name: "missing results", body: `{"count":0,"next":null}`},
		{name: "null results", body: `{"count":0,"next":null,"results":null}`},
		{name: "count smaller than results", body: `{"count":0,"next":null,"results":[{"id":1,"name":"host"}]}`},
		{name: "missing host id", body: `{"count":1,"next":null,"results":[{"name":"host"}]}`},
		{name: "missing host name", body: `{"count":1,"next":null,"results":[{"id":1}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			client, err := awx.New(server.URL, "token", nil, connectors.DefaultBudget())
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if _, err := client.ListInventoryHosts(context.Background(), 1); err == nil {
				t.Fatal("ListInventoryHosts() error = nil, want response validation error")
			}
		})
	}
}

func TestAWXRejectsObjectWithWrongIdentityOrMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		body string
		call func(*awx.Client) error
	}{
		{
			name: "job template ID mismatch",
			body: `{"id":8,"name":"restart","job_type":"run"}`,
			call: func(client *awx.Client) error {
				_, err := client.GetJobTemplate(context.Background(), 7)
				return err
			},
		},
		{
			name: "job template missing name",
			body: `{"id":7,"job_type":"run"}`,
			call: func(client *awx.Client) error {
				_, err := client.GetJobTemplate(context.Background(), 7)
				return err
			},
		},
		{
			name: "job template missing job type",
			body: `{"id":7,"name":"restart"}`,
			call: func(client *awx.Client) error {
				_, err := client.GetJobTemplate(context.Background(), 7)
				return err
			},
		},
		{
			name: "job status ID mismatch",
			body: `{"id":10,"status":"successful"}`,
			call: func(client *awx.Client) error {
				_, err := client.GetJobStatus(context.Background(), 9)
				return err
			},
		},
		{
			name: "job status missing status",
			body: `{"id":9}`,
			call: func(client *awx.Client) error {
				_, err := client.GetJobStatus(context.Background(), 9)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			client, err := awx.New(server.URL, "token", nil, connectors.DefaultBudget())
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if err := test.call(client); err == nil {
				t.Fatal("object lookup error = nil, want response identity/shape validation error")
			}
		})
	}
}

func TestAWXObjectContentHashUsesReturnedItems(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":9,"status":"successful"}`))
	}))
	defer server.Close()

	client, err := awx.New(server.URL, "token", nil, connectors.DefaultBudget())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	result, err := client.GetJobStatus(context.Background(), 9)
	if err != nil {
		t.Fatalf("GetJobStatus() error = %v", err)
	}
	projectedItems, err := json.Marshal(result.Items)
	if err != nil {
		t.Fatalf("marshal result items: %v", err)
	}
	wantHash := sha256.Sum256(projectedItems)
	if got, want := result.ContentHash, hex.EncodeToString(wantHash[:]); got != want {
		t.Fatalf("ContentHash = %q, want hash(Result.Items) %q", got, want)
	}
}
