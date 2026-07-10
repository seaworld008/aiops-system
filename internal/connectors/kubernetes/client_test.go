package kubernetes_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/connectors"
	"github.com/seaworld008/aiops-system/internal/connectors/kubernetes"
)

const testToken = "service-account-token"

func TestGetDeploymentUsesAuthorizedReadOnlyRequest(t *testing.T) {
	body := []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"api","namespace":"production"}}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", request.Method)
		}
		if request.URL.Path != "/apis/apps/v1/namespaces/production/deployments/api" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		if request.URL.RawQuery != "" {
			t.Fatalf("query = %q, want empty", request.URL.RawQuery)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Fatalf("Authorization = %q", got)
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()

	client := newClient(t, server.URL, server.Client(), connectors.Budget{
		Timeout: time.Second, MaxBytes: 4096, MaxItems: 10,
	})
	result, err := client.GetDeployment(context.Background(), "production", "api")
	if err != nil {
		t.Fatalf("GetDeployment() error = %v", err)
	}
	if result.Source != "kubernetes" || result.ItemCount != 1 || result.Truncated {
		t.Fatalf("result = %#v", result)
	}
	assertFinalItemsHash(t, result)
	if len(result.Items) != 1 || !strings.Contains(string(result.Items[0]), `"kind":"Deployment"`) {
		t.Fatalf("Items = %s", result.Items)
	}
	if strings.Contains(result.Query, testToken) {
		t.Fatalf("query summary leaked bearer token: %q", result.Query)
	}
}

func TestListPodsEnforcesSelectorLimitAndTruncation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", request.Method)
		}
		if request.URL.Path != "/api/v1/namespaces/production/pods" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		if got := request.URL.Query().Get("labelSelector"); got != "app in (api,worker)" {
			t.Fatalf("labelSelector = %q", got)
		}
		if got := request.URL.Query().Get("limit"); got != "1" {
			t.Fatalf("limit = %q, want 1", got)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Fatalf("Authorization = %q", got)
		}
		_, _ = io.WriteString(w, `{"apiVersion":"v1","kind":"PodList","metadata":{"continue":"next-page"},"items":[{"apiVersion":"v1","kind":"Pod","metadata":{"name":"api-0","namespace":"production"}},{"apiVersion":"v1","kind":"Pod","metadata":{"name":"api-1","namespace":"production"}}]}`)
	}))
	defer server.Close()

	client := newClient(t, server.URL, server.Client(), connectors.Budget{
		Timeout: time.Second, MaxBytes: 4096, MaxItems: 1,
	})
	result, err := client.ListPods(context.Background(), "production", "app in (api,worker)")
	if err != nil {
		t.Fatalf("ListPods() error = %v", err)
	}
	if result.ItemCount != 1 || len(result.Items) != 1 || !result.Truncated {
		t.Fatalf("result = %#v, want one truncated item", result)
	}
	if !strings.Contains(result.Query, "labelSelector") || strings.Contains(result.Query, testToken) {
		t.Fatalf("query summary = %q", result.Query)
	}
}

func TestListEventsUsesFieldSelectorAndBudgetLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", request.Method)
		}
		if request.URL.Path != "/api/v1/namespaces/production/events" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		if got := request.URL.Query().Get("fieldSelector"); got != "involvedObject.name=api-0,type!=Normal" {
			t.Fatalf("fieldSelector = %q", got)
		}
		if got := request.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit = %q, want 2", got)
		}
		_, _ = io.WriteString(w, `{"apiVersion":"v1","kind":"EventList","metadata":{},"items":[{"apiVersion":"v1","kind":"Event","metadata":{"name":"api-backoff","namespace":"production"},"reason":"BackOff"}]}`)
	}))
	defer server.Close()

	client := newClient(t, server.URL, server.Client(), connectors.Budget{
		Timeout: time.Second, MaxBytes: 4096, MaxItems: 2,
	})
	result, err := client.ListEvents(context.Background(), "production", "involvedObject.name=api-0,type!=Normal")
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	if result.ItemCount != 1 || result.Truncated || result.ContentHash == "" {
		t.Fatalf("result = %#v", result)
	}
}

func TestClientProjectsSensitiveKubernetesFieldsAndHashesFinalItems(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/apis/apps/v1/namespaces/production/deployments/api":
			_, _ = io.WriteString(w, `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"api","namespace":"production","uid":"deployment-uid","labels":{"app":"api"},"annotations":{"credential":"annotation-secret"},"managedFields":[{"manager":"secret-manager"}]},"spec":{"replicas":2,"template":{"metadata":{"labels":{"app":"api"},"annotations":{"token":"template-secret"}},"spec":{"containers":[{"name":"api","image":"registry/api:v1","command":["/bin/api"],"args":["--token=command-secret"],"env":[{"name":"PASSWORD","value":"inline-password"},{"name":"TOKEN","valueFrom":{"secretKeyRef":{"name":"prod-secret","key":"token"}}}]}],"volumes":[{"name":"credentials","secret":{"secretName":"prod-secret"}}],"imagePullSecrets":[{"name":"pull-secret"}]}},"strategy":{"rollingUpdate":{"maxUnavailable":"25%"}}},"status":{"replicas":2,"readyReplicas":1,"availableReplicas":1,"conditions":[{"type":"Available","status":"True","reason":"MinimumReplicasAvailable","message":"deployment-condition-secret"}]}}`)
		case "/api/v1/namespaces/production/pods":
			_, _ = io.WriteString(w, `{"apiVersion":"v1","kind":"PodList","metadata":{},"items":[{"apiVersion":"v1","kind":"Pod","metadata":{"name":"api-0","namespace":"production","uid":"pod-uid","labels":{"app":"api"},"annotations":{"credential":"pod-annotation-secret"}},"spec":{"nodeName":"worker-1","containers":[{"name":"api","image":"registry/api:v1","command":["sh"],"args":["--password=pod-arg-secret"],"env":[{"name":"PASSWORD","value":"pod-inline-password"}]}],"volumes":[{"secret":{"secretName":"pod-secret"}}]},"status":{"phase":"Running","containerStatuses":[{"name":"api","ready":false,"restartCount":2,"image":"registry/api:v1","state":{"waiting":{"reason":"CrashLoopBackOff","message":"pod-state-secret"}}}]}},{"apiVersion":"v1","kind":"Pod","metadata":{"name":"discarded","namespace":"production","annotations":{"credential":"discarded-secret"}}}]}`)
		case "/api/v1/namespaces/production/events":
			_, _ = io.WriteString(w, `{"apiVersion":"v1","kind":"EventList","metadata":{},"items":[{"apiVersion":"v1","kind":"Event","metadata":{"name":"api-backoff","namespace":"production","uid":"event-uid","annotations":{"credential":"event-annotation-secret"}},"involvedObject":{"apiVersion":"v1","kind":"Pod","namespace":"production","name":"api-0","uid":"pod-uid"},"reason":"BackOff","type":"Warning","action":"Restarting","message":"credential=event-message-secret","count":3,"lastTimestamp":"2026-07-10T10:00:00Z"}]}`)
		default:
			t.Fatalf("unexpected path %q", request.URL.Path)
		}
	}))
	defer server.Close()

	client := newClient(t, server.URL, server.Client(), connectors.Budget{
		Timeout: time.Second, MaxBytes: 32 << 10, MaxItems: 1,
	})

	deployment, err := client.GetDeployment(context.Background(), "production", "api")
	if err != nil {
		t.Fatalf("GetDeployment() error = %v", err)
	}
	assertProjectedEvidence(t, deployment, []string{`"name":"api"`, `"image":"registry/api:v1"`, `"availableReplicas":1`})

	pods, err := client.ListPods(context.Background(), "production", "app=api")
	if err != nil {
		t.Fatalf("ListPods() error = %v", err)
	}
	if !pods.Truncated || pods.ItemCount != 1 {
		t.Fatalf("pods result = %#v, want one truncated item", pods)
	}
	assertProjectedEvidence(t, pods, []string{`"name":"api-0"`, `"restartCount":2`, `"reason":"CrashLoopBackOff"`})

	events, err := client.ListEvents(context.Background(), "production", "involvedObject.name=api-0")
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	assertProjectedEvidence(t, events, []string{`"name":"api-backoff"`, `"reason":"BackOff"`, `"type":"Warning"`})
}

func TestClientRejectsMismatchedOrIncompleteKubernetesResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
		call func(*kubernetes.Client) error
	}{
		{
			name: "deployment identity mismatch",
			body: `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"other","namespace":"production"}}`,
			call: func(client *kubernetes.Client) error {
				_, err := client.GetDeployment(context.Background(), "production", "api")
				return err
			},
		},
		{
			name: "pod list missing items",
			body: `{"apiVersion":"v1","kind":"PodList","metadata":{}}`,
			call: func(client *kubernetes.Client) error {
				_, err := client.ListPods(context.Background(), "production", "app=api")
				return err
			},
		},
		{
			name: "pod namespace mismatch",
			body: `{"apiVersion":"v1","kind":"PodList","metadata":{},"items":[{"apiVersion":"v1","kind":"Pod","metadata":{"name":"api-0","namespace":"other"}}]}`,
			call: func(client *kubernetes.Client) error {
				_, err := client.ListPods(context.Background(), "production", "app=api")
				return err
			},
		},
		{
			name: "event list null",
			body: `null`,
			call: func(client *kubernetes.Client) error {
				_, err := client.ListEvents(context.Background(), "production", "type=Warning")
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			client := newClient(t, server.URL, server.Client(), connectors.DefaultBudget())
			if err := test.call(client); err == nil {
				t.Fatal("error = nil, want response contract rejection")
			}
		})
	}
}

func TestClientRejectsInvalidResourceInputsBeforeNetwork(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid input reached the network")
		return nil, errors.New("unexpected request")
	})}
	client := newClient(t, "https://kubernetes.example", httpClient, connectors.Budget{
		Timeout: time.Second, MaxBytes: 4096, MaxItems: 10,
	})

	tests := []struct {
		name string
		call func() error
	}{
		{name: "empty namespace", call: func() error {
			_, err := client.GetDeployment(context.Background(), "", "api")
			return err
		}},
		{name: "path traversal name", call: func() error {
			_, err := client.GetDeployment(context.Background(), "production", "../secret")
			return err
		}},
		{name: "invalid DNS segment in name", call: func() error {
			_, err := client.GetDeployment(context.Background(), "production", "api-.example")
			return err
		}},
		{name: "empty label selector", call: func() error {
			_, err := client.ListPods(context.Background(), "production", "")
			return err
		}},
		{name: "query injection label selector", call: func() error {
			_, err := client.ListPods(context.Background(), "production", "app=api&limit=999")
			return err
		}},
		{name: "unbalanced label selector", call: func() error {
			_, err := client.ListPods(context.Background(), "production", "app in (api")
			return err
		}},
		{name: "invalid DNS prefix in label selector", call: func() error {
			_, err := client.ListPods(context.Background(), "production", "api-.example/component=worker")
			return err
		}},
		{name: "control character field selector", call: func() error {
			_, err := client.ListEvents(context.Background(), "production", "reason=BackOff\n")
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); err == nil {
				t.Fatal("error = nil, want validation failure")
			}
		})
	}
}

func TestClientEnforcesResponseSizeAndTimeout(t *testing.T) {
	t.Run("response size", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, strings.Repeat("x", 128))
		}))
		defer server.Close()
		client := newClient(t, server.URL, server.Client(), connectors.Budget{
			Timeout: time.Second, MaxBytes: 32, MaxItems: 1,
		})
		if _, err := client.GetDeployment(context.Background(), "production", "api"); err == nil {
			t.Fatal("GetDeployment() error = nil, want size rejection")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			<-request.Context().Done()
			return nil, request.Context().Err()
		})}
		client := newClient(t, "https://kubernetes.example", httpClient, connectors.Budget{
			Timeout: 20 * time.Millisecond, MaxBytes: 4096, MaxItems: 1,
		})
		_, err := client.GetDeployment(context.Background(), "production", "api")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("GetDeployment() error = %v, want deadline exceeded", err)
		}
	})
}

func TestClientDoesNotFollowRedirectsWithBearerToken(t *testing.T) {
	targetCalled := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		targetCalled = true
		if request.Header.Get("Authorization") != "" {
			t.Errorf("redirect target received Authorization header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	client := newClient(t, source.URL, source.Client(), connectors.Budget{
		Timeout: time.Second, MaxBytes: 4096, MaxItems: 1,
	})
	if _, err := client.GetDeployment(context.Background(), "production", "api"); err == nil {
		t.Fatal("GetDeployment() error = nil, want redirect rejection")
	}
	if targetCalled {
		t.Fatal("client followed redirect")
	}
}

func TestNewRejectsInvalidURLTokenOrBudget(t *testing.T) {
	validBudget := connectors.Budget{Timeout: time.Second, MaxBytes: 4096, MaxItems: 1}
	for _, test := range []struct {
		name   string
		url    string
		token  string
		budget connectors.Budget
	}{
		{name: "relative URL", url: "/cluster", token: testToken, budget: validBudget},
		{name: "non-loopback cleartext", url: "http://kubernetes.example", token: testToken, budget: validBudget},
		{name: "empty token", url: "https://kubernetes.example", token: "", budget: validBudget},
		{name: "header injection token", url: "https://kubernetes.example", token: "token\nvalue", budget: validBudget},
		{name: "invalid budget", url: "https://kubernetes.example", token: testToken, budget: connectors.Budget{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := kubernetes.New(test.url, test.token, nil, test.budget); err == nil {
				t.Fatal("New() error = nil, want validation failure")
			}
		})
	}
}

func assertProjectedEvidence(t *testing.T, result connectors.Result, required []string) {
	t.Helper()
	if len(result.Items) == 0 {
		t.Fatal("Items is empty")
	}
	encoded := string(result.Items[0])
	for _, forbidden := range []string{
		`"annotations"`, `"managedFields"`, `"env"`, `"command"`, `"args"`,
		`"volumes"`, `"imagePullSecrets"`, `"secret"`, `"message"`,
		"inline-password", "credential=",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("projected evidence contains forbidden %q: %s", forbidden, encoded)
		}
	}
	for _, expected := range required {
		if !strings.Contains(encoded, expected) {
			t.Fatalf("projected evidence missing %q: %s", expected, encoded)
		}
	}
	assertFinalItemsHash(t, result)
}

func assertFinalItemsHash(t *testing.T, result connectors.Result) {
	t.Helper()
	projected, err := json.Marshal(result.Items)
	if err != nil {
		t.Fatalf("marshal final Items: %v", err)
	}
	wantHash := sha256.Sum256(projected)
	if result.ContentHash != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("ContentHash = %q, want final Items hash %q", result.ContentHash, hex.EncodeToString(wantHash[:]))
	}
}

func newClient(t *testing.T, rawURL string, httpClient *http.Client, budget connectors.Budget) *kubernetes.Client {
	t.Helper()
	client, err := kubernetes.New(rawURL, testToken, httpClient, budget)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
