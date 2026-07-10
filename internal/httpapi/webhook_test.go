package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aiops-system/control-plane/internal/httpapi"
	"github.com/aiops-system/control-plane/internal/signal"
)

func TestWebhookAcceptsAlertmanagerWithoutIdempotencyHeader(t *testing.T) {
	ingestor := &fakeSignalIngestor{result: signal.IngestResult{Accepted: 1}}
	router := httpapi.NewRouter(httpapi.Dependencies{SignalIngestor: ingestor, WebhookVerifier: allowWebhookVerifier{}})
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/integrations/integration-1/webhooks/alertmanager",
		strings.NewReader(`{"alerts":[{"fingerprint":"abc","startsAt":"2026-07-10T09:59:00Z"}]}`),
	)
	req.Header.Set("X-Workspace-ID", "workspace-1")
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()

	router.ServeHTTP(res, req)

	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", res.Code, res.Body.String())
	}
	if ingestor.provider != "alertmanager" || ingestor.integrationID != "integration-1" {
		t.Fatalf("ingestor got provider=%q integration=%q", ingestor.provider, ingestor.integrationID)
	}
}

func TestWebhookReturnsProblemJSONForInvalidPayload(t *testing.T) {
	ingestor := &fakeSignalIngestor{err: signal.ErrInvalidPayload}
	router := httpapi.NewRouter(httpapi.Dependencies{SignalIngestor: ingestor, WebhookVerifier: allowWebhookVerifier{}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/i/webhooks/nightingale", strings.NewReader(`{`))
	req.Header.Set("X-Workspace-ID", "workspace-1")
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()

	router.ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.Code)
	}
	if got := res.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/problem+json") {
		t.Fatalf("Content-Type = %q, want application/problem+json", got)
	}
	var problem map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &problem); err != nil {
		t.Fatalf("problem response is invalid JSON: %v", err)
	}
	if problem["code"] != "invalid_signal_payload" {
		t.Fatalf("problem code = %v, want invalid_signal_payload", problem["code"])
	}
}

func TestWebhookRejectsInvalidSignature(t *testing.T) {
	router := httpapi.NewRouter(httpapi.Dependencies{
		SignalIngestor:  &fakeSignalIngestor{},
		WebhookVerifier: rejectWebhookVerifier{},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/i/webhooks/alertmanager", strings.NewReader(`{"alerts":[]}`))
	req.Header.Set("X-Workspace-ID", "workspace-1")
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()

	router.ServeHTTP(res, req)

	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.Code)
	}
}

func TestRouterUsesProblemJSONForNotFoundAndMethodNotAllowed(t *testing.T) {
	router := httpapi.NewRouter(httpapi.Dependencies{})
	for _, tc := range []struct {
		method string
		path   string
		want   int
	}{
		{method: http.MethodGet, path: "/missing", want: http.StatusNotFound},
		{method: http.MethodPost, path: "/healthz", want: http.StatusMethodNotAllowed},
	} {
		res := httptest.NewRecorder()
		router.ServeHTTP(res, httptest.NewRequest(tc.method, tc.path, nil))
		if res.Code != tc.want {
			t.Fatalf("%s %s status = %d, want %d", tc.method, tc.path, res.Code, tc.want)
		}
		if got := res.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/problem+json") {
			t.Fatalf("%s %s Content-Type = %q", tc.method, tc.path, got)
		}
	}
}

type fakeSignalIngestor struct {
	result        signal.IngestResult
	err           error
	provider      string
	integrationID string
}

func (fake *fakeSignalIngestor) Ingest(_ context.Context, _, integrationID, provider string, _ []byte) (signal.IngestResult, error) {
	fake.provider = provider
	fake.integrationID = integrationID
	return fake.result, fake.err
}

type allowWebhookVerifier struct{}

func (allowWebhookVerifier) Verify(string, string, http.Header, []byte) error { return nil }

type rejectWebhookVerifier struct{}

func (rejectWebhookVerifier) Verify(string, string, http.Header, []byte) error {
	return httpapi.ErrInvalidWebhookSignature
}
