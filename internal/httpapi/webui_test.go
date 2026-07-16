package httpapi_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/seaworld008/aiops-system/internal/httpapi"
)

const expectedWebCSP = "default-src 'self'; script-src 'self'; style-src 'self'; " +
	"connect-src 'self' https://identity.example.com; frame-ancestors 'none'; " +
	"base-uri 'none'; object-src 'none'; form-action https://identity.example.com"

func TestNewWebUIRequiresIndexManifestAndEveryHashedAsset(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if _, err := httpapi.NewWebUI(root, "https://identity.example.com"); err == nil {
		t.Fatal("NewWebUI() error = nil without index and manifest")
	}
	writeWebFixture(t, root)
	if err := os.Remove(filepath.Join(root, "index.html")); err != nil {
		t.Fatalf("remove index: %v", err)
	}
	if _, err := httpapi.NewWebUI(root, "https://identity.example.com"); err == nil {
		t.Fatal("NewWebUI() error = nil without index")
	}
	writeFile(t, filepath.Join(root, "index.html"), "<!doctype html><p>shell</p>")
	if err := os.Remove(filepath.Join(root, ".vite", "manifest.json")); err != nil {
		t.Fatalf("remove manifest: %v", err)
	}
	if _, err := httpapi.NewWebUI(root, "https://identity.example.com"); err == nil {
		t.Fatal("NewWebUI() error = nil without manifest")
	}
	writeWebFixture(t, root)
	if err := os.Remove(filepath.Join(root, "assets", "index-abc12345.js")); err != nil {
		t.Fatalf("remove manifest asset: %v", err)
	}
	if _, err := httpapi.NewWebUI(root, "https://identity.example.com"); err == nil {
		t.Fatal("NewWebUI() error = nil without referenced asset")
	}
}

func TestNewWebUIRejectsUnhashedManifestReferencesAndSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics are platform-specific")
	}

	t.Run("unhashed manifest", func(t *testing.T) {
		root := t.TempDir()
		writeWebFixture(t, root)
		writeFile(t, filepath.Join(root, "assets", "index.js"), "unsafe")
		writeFile(t, filepath.Join(root, ".vite", "manifest.json"),
			`{"src/main.tsx":{"file":"assets/index.js","isEntry":true}}`)
		if _, err := httpapi.NewWebUI(root, "https://identity.example.com"); err == nil {
			t.Fatal("NewWebUI() error = nil for unhashed asset")
		}
	})

	t.Run("root symlink", func(t *testing.T) {
		target := t.TempDir()
		writeWebFixture(t, target)
		link := filepath.Join(t.TempDir(), "web-link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink root: %v", err)
		}
		if _, err := httpapi.NewWebUI(link, "https://identity.example.com"); err == nil {
			t.Fatal("NewWebUI() error = nil for symlink root")
		}
	})

	t.Run("file symlink", func(t *testing.T) {
		root := t.TempDir()
		writeWebFixture(t, root)
		outside := filepath.Join(t.TempDir(), "outside.html")
		writeFile(t, outside, "<p>outside</p>")
		if err := os.Remove(filepath.Join(root, "index.html")); err != nil {
			t.Fatalf("remove index: %v", err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "index.html")); err != nil {
			t.Fatalf("symlink index: %v", err)
		}
		if _, err := httpapi.NewWebUI(root, "https://identity.example.com"); err == nil {
			t.Fatal("NewWebUI() error = nil for symlink index")
		}
	})

	t.Run("manifest asset symlink", func(t *testing.T) {
		root := t.TempDir()
		writeWebFixture(t, root)
		outside := filepath.Join(t.TempDir(), "outside.js")
		writeFile(t, outside, "outside")
		asset := filepath.Join(root, "assets", "index-abc12345.js")
		if err := os.Remove(asset); err != nil {
			t.Fatalf("remove asset: %v", err)
		}
		if err := os.Symlink(outside, asset); err != nil {
			t.Fatalf("symlink asset: %v", err)
		}
		if _, err := httpapi.NewWebUI(root, "https://identity.example.com"); err == nil {
			t.Fatal("NewWebUI() error = nil for symlink manifest asset")
		}
	})

	t.Run("nested asset directory symlink", func(t *testing.T) {
		root := t.TempDir()
		writeWebFixture(t, root)
		outside := t.TempDir()
		writeFile(t, filepath.Join(outside, "index-abc12345.js"), "outside")
		writeFile(t, filepath.Join(outside, "index-def67890.css"), "body{}")
		if err := os.RemoveAll(filepath.Join(root, "assets")); err != nil {
			t.Fatalf("remove assets: %v", err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "assets")); err != nil {
			t.Fatalf("symlink assets directory: %v", err)
		}
		if _, err := httpapi.NewWebUI(root, "https://identity.example.com"); err == nil {
			t.Fatal("NewWebUI() error = nil for symlink asset directory")
		}
	})
}

func TestWebUIRootHandleDoesNotFollowAConcurrentRootSymlinkReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics are platform-specific")
	}

	parent := t.TempDir()
	root := filepath.Join(parent, "web")
	writeWebFixture(t, root)
	webUI, err := httpapi.NewWebUI(root, "https://identity.example.com")
	if err != nil {
		t.Fatalf("NewWebUI() error = %v", err)
	}
	closer, hasCloser := any(webUI).(io.Closer)
	if hasCloser {
		defer closer.Close()
	}

	trustedRoot := filepath.Join(parent, "trusted-web")
	if err := os.Rename(root, trustedRoot); err != nil {
		t.Fatalf("rename trusted root: %v", err)
	}
	replacement := t.TempDir()
	writeWebFixture(t, replacement)
	writeFile(t, filepath.Join(replacement, "assets", "index-abc12345.js"), "outside-root")
	if err := os.Symlink(replacement, root); err != nil {
		t.Fatalf("replace root with symlink: %v", err)
	}

	handler := webUI.Wrap(http.NotFoundHandler())
	failures := make(chan string, 16)
	var requests sync.WaitGroup
	for range 16 {
		requests.Add(1)
		go func() {
			defer requests.Done()
			response := httptest.NewRecorder()
			handler.ServeHTTP(
				response,
				httptest.NewRequest(http.MethodGet, "/assets/index-abc12345.js", nil),
			)
			if response.Code != http.StatusOK || response.Body.String() != "console-safe" {
				failures <- response.Body.String()
			}
		}()
	}
	requests.Wait()
	close(failures)
	for failure := range failures {
		t.Errorf("concurrent request escaped rooted handle: %q", failure)
	}
	if err := webUI.Ready(); err == nil {
		t.Fatal("Ready() error = nil after public root identity changed")
	}
	if !hasCloser {
		t.Fatal("WebUI does not implement io.Closer for rooted handle lifecycle")
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := webUI.Ready(); err == nil {
		t.Fatal("Ready() error = nil after rooted handle was closed")
	}
}

func TestWebUIServesOnlyNormalizedHTMLRoutesAndImmutableAssets(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeWebFixture(t, root)
	webUI, err := httpapi.NewWebUI(root, "https://identity.example.com/realms/aiops")
	if err != nil {
		t.Fatalf("NewWebUI() error = %v", err)
	}
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusTeapot)
		_, _ = writer.Write([]byte("next:" + request.URL.Path))
	})
	handler := webUI.Wrap(next)

	for _, path := range []string{"/", "/index.html", "/assets", "/assets/asset-1"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Accept", "text/html,application/xhtml+xml")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "shell") {
			t.Errorf("GET %s = %d %q", path, response.Code, response.Body.String())
		}
		if got := response.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("GET %s Cache-Control = %q", path, got)
		}
		if got := response.Header().Get("Content-Security-Policy"); got != expectedWebCSP {
			t.Errorf("GET %s CSP = %q", path, got)
		}
		if response.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("GET %s unexpectedly enabled CORS", path)
		}
	}

	assetRequest := httptest.NewRequest(http.MethodGet, "/assets/index-abc12345.js", nil)
	assetResponse := httptest.NewRecorder()
	handler.ServeHTTP(assetResponse, assetRequest)
	if assetResponse.Code != http.StatusOK || assetResponse.Body.String() != "console-safe" {
		t.Fatalf("asset response = %d %q", assetResponse.Code, assetResponse.Body.String())
	}
	if got := assetResponse.Header().Get("Cache-Control"); got != "public,max-age=31536000,immutable" {
		t.Fatalf("asset Cache-Control = %q", got)
	}
	for header, want := range map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": expectedWebCSP,
	} {
		if got := assetResponse.Header().Get(header); got != want {
			t.Errorf("asset %s = %q, want %q", header, got, want)
		}
	}

	headRequest := httptest.NewRequest(http.MethodHead, "/assets", nil)
	headRequest.Header.Set("Accept", "text/html")
	headResponse := httptest.NewRecorder()
	handler.ServeHTTP(headResponse, headRequest)
	if headResponse.Code != http.StatusOK || headResponse.Body.Len() != 0 {
		t.Fatalf("HEAD SPA response = %d %q", headResponse.Code, headResponse.Body.String())
	}
	indexHeadRequest := httptest.NewRequest(http.MethodHead, "/index.html", nil)
	indexHeadResponse := httptest.NewRecorder()
	handler.ServeHTTP(indexHeadResponse, indexHeadRequest)
	if indexHeadResponse.Code != http.StatusOK || indexHeadResponse.Body.Len() != 0 ||
		indexHeadResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf(
			"HEAD index response = %d %q cache=%q",
			indexHeadResponse.Code,
			indexHeadResponse.Body.String(),
			indexHeadResponse.Header().Get("Cache-Control"),
		)
	}

	for _, accept := range []string{"", "application/json", "text/html;q=0", "*/*"} {
		request := httptest.NewRequest(http.MethodGet, "/overview", nil)
		request.Header.Set("Accept", accept)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code == http.StatusOK || strings.Contains(response.Body.String(), "shell") {
			t.Errorf("Accept %q unexpectedly received SPA fallback", accept)
		}
	}

	manifestRequest := httptest.NewRequest(http.MethodGet, "/.vite/manifest.json", nil)
	manifestResponse := httptest.NewRecorder()
	handler.ServeHTTP(manifestResponse, manifestRequest)
	if manifestResponse.Code == http.StatusOK ||
		strings.Contains(manifestResponse.Body.String(), "src/main.tsx") {
		t.Fatalf("manifest was publicly served: %d %q", manifestResponse.Code, manifestResponse.Body.String())
	}
}

func TestWebUIDelegatesReservedAndNonReadRequestsWithoutFallback(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeWebFixture(t, root)
	webUI, err := httpapi.NewWebUI(root, "https://identity.example.com")
	if err != nil {
		t.Fatalf("NewWebUI() error = %v", err)
	}
	handler := webUI.Wrap(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusTeapot)
		_, _ = writer.Write([]byte("delegated:" + request.URL.Path))
	}))
	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api"},
		{http.MethodGet, "/api/v1/missing"},
		{http.MethodGet, "/healthz"},
		{http.MethodGet, "/healthz/detail"},
		{http.MethodGet, "/readyz"},
		{http.MethodGet, "/readyz/detail"},
		{http.MethodPost, "/assets"},
		{http.MethodPut, "/overview"},
	}
	for _, test := range tests {
		request := httptest.NewRequest(test.method, test.path, nil)
		request.Header.Set("Accept", "text/html")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusTeapot ||
			!strings.Contains(response.Body.String(), "delegated:") ||
			strings.Contains(response.Body.String(), "shell") {
			t.Errorf("%s %s = %d %q", test.method, test.path, response.Code, response.Body.String())
		}
	}
}

func TestWebUIRejectsTraversalEncodedSeparatorsAndDirectoryListings(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeWebFixture(t, root)
	webUI, err := httpapi.NewWebUI(root, "https://identity.example.com")
	if err != nil {
		t.Fatalf("NewWebUI() error = %v", err)
	}
	handler := webUI.Wrap(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusTeapot)
	}))
	rawTargets := []string{
		"/assets%2findex-abc12345.js",
		"/assets%5cindex-abc12345.js",
		"/assets%252findex-abc12345.js",
		"/%252e%252e/private",
		"/foo%00bar",
		"//evil.invalid/path",
		"/a/../overview",
		"/.",
		"/assets/",
		"/unknown.js",
	}
	for _, target := range rawTargets {
		request := httptest.NewRequest(http.MethodGet, "http://control-plane.example"+target, nil)
		request.Header.Set("Accept", "text/html")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code == http.StatusOK || strings.Contains(response.Body.String(), "shell") {
			t.Errorf("GET %q unexpectedly fell back: %d %q", target, response.Code, response.Body.String())
		}
	}
	for _, path := range []string{"/foo\\bar", "/foo\x00bar"} {
		request := &http.Request{
			Method:     http.MethodGet,
			URL:        &url.URL{Path: path},
			Header:     http.Header{"Accept": []string{"text/html"}},
			RequestURI: path,
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code == http.StatusOK || strings.Contains(response.Body.String(), "shell") {
			t.Errorf("GET path %q unexpectedly fell back", path)
		}
	}
}

func TestWebUIReadinessFailsWhenAnyStartupArtifactDisappears(t *testing.T) {
	t.Parallel()

	for _, relative := range []string{
		"index.html",
		filepath.Join(".vite", "manifest.json"),
		filepath.Join("assets", "index-abc12345.js"),
		filepath.Join("assets", "index-def67890.css"),
	} {
		t.Run(relative, func(t *testing.T) {
			root := t.TempDir()
			writeWebFixture(t, root)
			webUI, err := httpapi.NewWebUI(root, "https://identity.example.com")
			if err != nil {
				t.Fatalf("NewWebUI() error = %v", err)
			}
			if err := webUI.Ready(); err != nil {
				t.Fatalf("Ready() before removal = %v", err)
			}
			if err := os.Remove(filepath.Join(root, relative)); err != nil {
				t.Fatalf("remove %s: %v", relative, err)
			}
			if err := webUI.Ready(); err == nil {
				t.Fatalf("Ready() error = nil after removing %s", relative)
			}
		})
	}
}

func TestRouterComposesWebUIWithoutChangingHealthOrAPIRoutes(t *testing.T) {
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
	health := httptest.NewRecorder()
	router.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"status":"ok"`) {
		t.Fatalf("health response = %d %q", health.Code, health.Body.String())
	}
	spaRequest := httptest.NewRequest(http.MethodGet, "/assets", nil)
	spaRequest.Header.Set("Accept", "text/html")
	spa := httptest.NewRecorder()
	router.ServeHTTP(spa, spaRequest)
	if spa.Code != http.StatusOK || !strings.Contains(spa.Body.String(), "shell") {
		t.Fatalf("SPA response = %d %q", spa.Code, spa.Body.String())
	}
	api := httptest.NewRecorder()
	router.ServeHTTP(api, httptest.NewRequest(http.MethodGet, "/api/missing", nil))
	if api.Code != http.StatusNotFound || !strings.Contains(api.Body.String(), "route_not_found") {
		body, _ := io.ReadAll(api.Result().Body)
		t.Fatalf("API response = %d %q", api.Code, body)
	}
}

func writeWebFixture(t *testing.T, root string) {
	t.Helper()
	writeFile(t, filepath.Join(root, "index.html"), "<!doctype html><p>shell</p>")
	writeFile(t, filepath.Join(root, ".vite", "manifest.json"),
		`{"src/main.tsx":{"file":"assets/index-abc12345.js","css":["assets/index-def67890.css"],"isEntry":true}}`)
	writeFile(t, filepath.Join(root, "assets", "index-abc12345.js"), "console-safe")
	writeFile(t, filepath.Join(root, "assets", "index-def67890.css"), "body{}")
}

func writeFile(t *testing.T, name, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(name), err)
	}
	if err := os.WriteFile(name, []byte(value), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
