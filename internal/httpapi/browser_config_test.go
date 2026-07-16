package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/httpapi"
)

func TestBrowserConfigIsAnonymousClosedAndNoStore(t *testing.T) {
	t.Parallel()
	browserConfig, err := httpapi.NewBrowserConfig(httpapi.BrowserConfigInput{
		OIDCURL: "https://identity.example.com", OIDCRealm: "aiops",
		OIDCClientID: "control-plane-web", Version: "1.0.0", Commit: "abcdef1",
		ContractDigest: "sha256:" + strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatalf("NewBrowserConfig() error = %v", err)
	}
	router := httpapi.NewRouter(httpapi.Dependencies{BrowserConfig: browserConfig})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/browser-config", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET browser-config = %d %s", response.Code, response.Body.String())
	}
	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := response.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode browser-config: %v", err)
	}
	if len(body) != 3 || body["api_base_path"] != "/api/v1" {
		t.Fatalf("browser-config = %#v", body)
	}
	encoded := strings.ToLower(response.Body.String())
	for _, forbidden := range []string{
		"secret", "token", "credential", "vault", "header", "dsn", "private_key",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Errorf("browser-config contains %q: %s", forbidden, encoded)
		}
	}
}

func TestBrowserConfigRejectsMalformedOrIncompletePublicMetadata(t *testing.T) {
	t.Parallel()
	valid := httpapi.BrowserConfigInput{
		OIDCURL: "https://identity.example.com", OIDCRealm: "aiops",
		OIDCClientID: "control-plane-web", Version: "1.0.0", Commit: "abcdef1",
		ContractDigest: "sha256:" + strings.Repeat("a", 64),
	}
	tests := map[string]func(*httpapi.BrowserConfigInput){
		"unsafe url":      func(value *httpapi.BrowserConfigInput) { value.OIDCURL = "http://identity.example.com" },
		"unclean url":     func(value *httpapi.BrowserConfigInput) { value.OIDCURL = "https://identity.example.com/a/../b" },
		"loopback url":    func(value *httpapi.BrowserConfigInput) { value.OIDCURL = "https://127.0.0.1" },
		"private url":     func(value *httpapi.BrowserConfigInput) { value.OIDCURL = "https://10.0.0.1" },
		"internal host":   func(value *httpapi.BrowserConfigInput) { value.OIDCURL = "https://identity.internal" },
		"missing realm":   func(value *httpapi.BrowserConfigInput) { value.OIDCRealm = "" },
		"wrong client":    func(value *httpapi.BrowserConfigInput) { value.OIDCClientID = "another-client" },
		"missing version": func(value *httpapi.BrowserConfigInput) { value.Version = "" },
		"bad commit":      func(value *httpapi.BrowserConfigInput) { value.Commit = "unsafe\ncommit" },
		"bad digest":      func(value *httpapi.BrowserConfigInput) { value.ContractDigest = "sha256:bad" },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := httpapi.NewBrowserConfig(candidate); err == nil {
				t.Fatal("NewBrowserConfig() error = nil")
			}
		})
	}
}

func TestBrowserConfigFailsClosedWhenDependencyIsMissing(t *testing.T) {
	t.Parallel()
	response := httptest.NewRecorder()
	httpapi.NewRouter(httpapi.Dependencies{}).ServeHTTP(
		response, httptest.NewRequest(http.MethodGet, "/api/v1/browser-config", nil),
	)
	if response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), `"code":"browser_config_unavailable"`) {
		t.Fatalf("GET browser-config = %d %s", response.Code, response.Body.String())
	}
}
