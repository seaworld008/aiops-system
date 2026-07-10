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
	router := httpapi.NewRouter(httpapi.Dependencies{SignalIngestor: ingestor})
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
	router := httpapi.NewRouter(httpapi.Dependencies{SignalIngestor: ingestor})
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
