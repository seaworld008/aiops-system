package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aiops-system/control-plane/internal/httpapi"
)

func TestHealthEndpoints(t *testing.T) {
	router := httpapi.NewRouter(httpapi.Dependencies{
		Version: "test-version",
		Ready:   func() error { return nil },
	})

	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)

		if res.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", path, res.Code)
		}

		var body map[string]string
		if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
			t.Fatalf("GET %s returned invalid JSON: %v", path, err)
		}
		if body["status"] != "ok" {
			t.Fatalf("GET %s status body = %q, want ok", path, body["status"])
		}
	}
}

func TestReadinessReturnsServiceUnavailable(t *testing.T) {
	router := httpapi.NewRouter(httpapi.Dependencies{
		Ready: func() error { return errNotReady{} },
	})
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	res := httptest.NewRecorder()

	router.ServeHTTP(res, req)

	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", res.Code)
	}
}

type errNotReady struct{}

func (errNotReady) Error() string { return "not ready" }
