package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/httpapi"
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
		if requestID := res.Header().Get("X-Request-ID"); requestID == "" {
			t.Fatalf("GET %s missing X-Request-ID", path)
		}
		if traceID := res.Header().Get("X-Trace-ID"); traceID == "" {
			t.Fatalf("GET %s missing X-Trace-ID", path)
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

func TestRequestMetadataExtractsW3CTraceID(t *testing.T) {
	router := httpapi.NewRouter(httpapi.Dependencies{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if got := res.Header().Get("X-Trace-ID"); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("X-Trace-ID = %q", got)
	}
}

func TestRequestMetadataRejectsInvalidW3CTraceParents(t *testing.T) {
	t.Parallel()

	for _, traceparent := range []string{
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
	} {
		router := httpapi.NewRouter(httpapi.Dependencies{})
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.Header.Set("traceparent", traceparent)
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		if got := res.Header().Get("X-Trace-ID"); len(got) != 32 || strings.Contains(traceparent, got) {
			t.Fatalf("traceparent %q produced trace id %q", traceparent, got)
		}
	}
}

func TestSessionEndpointRequiresVerifiedOIDCPrincipal(t *testing.T) {
	t.Parallel()

	principal := authn.Principal{
		Subject: "subject-1", Username: "alice", Roles: []authn.Role{authn.RoleSRE},
		WorkspaceIDs: []string{"workspace-1"}, EnvironmentIDs: []string{"PROD"}, ServiceIDs: []string{"service-1"},
		AuthenticatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
	}
	router := httpapi.NewRouter(httpapi.Dependencies{Authenticator: fakeAuthenticator{principal: principal}})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "subject-1") {
		t.Fatalf("session response = %d %s", response.Code, response.Body.String())
	}

	router = httpapi.NewRouter(httpapi.Dependencies{Authenticator: fakeAuthenticator{err: authn.ErrUnauthenticated}})
	request = httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	request.Header.Set("X-User-ID", "forged")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "authentication_required") {
		t.Fatalf("unauthorized session response = %d %s", response.Code, response.Body.String())
	}
}

type fakeAuthenticator struct {
	principal authn.Principal
	err       error
}

func (authenticator fakeAuthenticator) Authenticate(*http.Request) (authn.Principal, error) {
	return authenticator.principal, authenticator.err
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
