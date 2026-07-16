package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/httpapi"
)

func TestRouterKeepsUnknownAPIOutOfSPAFallbackAndIncludesWebReadiness(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeWebFixture(t, root)
	webUI, err := httpapi.NewWebUI(root, "https://identity.example.com")
	if err != nil {
		t.Fatalf("NewWebUI() error = %v", err)
	}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Version: "test-version",
		Ready:   webUI.Ready,
		WebUI:   webUI,
	})
	api := httptest.NewRecorder()
	router.ServeHTTP(api, httptest.NewRequest(http.MethodGet, "/api/unknown", nil))
	if api.Code != http.StatusNotFound || strings.Contains(api.Body.String(), "shell") ||
		!strings.Contains(api.Body.String(), "route_not_found") {
		t.Fatalf("unknown API response = %d %q", api.Code, api.Body.String())
	}

	if err := os.Remove(filepath.Join(root, "index.html")); err != nil {
		t.Fatalf("remove index: %v", err)
	}
	ready := httptest.NewRecorder()
	router.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready after Web asset loss = %d %q", ready.Code, ready.Body.String())
	}
}

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

	var typedNil *fakeAuthenticator
	router = httpapi.NewRouter(httpapi.Dependencies{Authenticator: typedNil})
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/session", nil))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "authentication_unavailable") {
		t.Fatalf("typed-nil authenticator response = %d %s", response.Code, response.Body.String())
	}
}

func TestControlPlaneOpenAPIOperationsAreRegisteredWithExactMethods(t *testing.T) {
	t.Parallel()
	const (
		workspaceID   = "11111111-1111-4111-8111-111111111111"
		environmentID = "22222222-2222-4222-8222-222222222222"
		resourceID    = "33333333-3333-4333-8333-333333333333"
	)
	base := "/api/v1/workspaces/" + workspaceID
	environmentBase := base + "/environments/" + environmentID
	operations := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/browser-config"},
		{http.MethodGet, environmentBase + "/assets"},
		{http.MethodPost, environmentBase + "/assets"},
		{http.MethodGet, environmentBase + "/assets/" + resourceID},
		{http.MethodPatch, environmentBase + "/assets/" + resourceID},
		{http.MethodPost, environmentBase + "/assets/" + resourceID + ":quarantine"},
		{http.MethodPost, environmentBase + "/assets/" + resourceID + ":retire"},
		{http.MethodGet, environmentBase + "/asset-relations"},
		{http.MethodGet, environmentBase + "/service-asset-bindings"},
		{http.MethodPost, environmentBase + "/service-asset-bindings"},
		{http.MethodDelete, environmentBase + "/service-asset-bindings/" + resourceID},
		{http.MethodGet, base + "/asset-sources"},
		{http.MethodGet, base + "/asset-sources/" + resourceID},
		{http.MethodGet, base + "/asset-source-runs/" + resourceID},
		{http.MethodGet, base + "/asset-conflicts?environment_id=" + environmentID},
		{http.MethodPost, base + "/asset-conflicts/" + resourceID + ":resolve"},
	}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: fakeAuthenticator{principal: authn.Principal{
			Subject: "test", TenantID: workspaceID, Roles: []authn.Role{authn.RoleAdmin},
			WorkspaceIDs: []string{workspaceID}, EnvironmentIDs: []string{environmentID},
			AuthenticatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
		}},
	})
	for _, operation := range operations {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(operation.method, operation.path, nil))
		if response.Code == http.StatusNotFound || response.Code == http.StatusMethodNotAllowed {
			t.Errorf("%s %s was not registered exactly: %d %s", operation.method, operation.path, response.Code, response.Body.String())
		}
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
