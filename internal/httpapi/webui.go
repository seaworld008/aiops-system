package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	webIndexPath    = "index.html"
	webManifestPath = ".vite/manifest.json"
	maxManifestSize = 1 << 20
)

var hashedWebAssetPattern = regexp.MustCompile(
	`^assets/[A-Za-z0-9][A-Za-z0-9._-]*-[A-Za-z0-9_-]{8,}\.[A-Za-z0-9]+$`,
)

type WebUI struct {
	rootPath       string
	root           *os.Root
	oidcOrigin     string
	contentPolicy  string
	manifestDigest [sha256.Size]byte
	manifestAssets []string
	assetSet       map[string]struct{}
	closeOnce      sync.Once
	closeErr       error
}

type viteManifestEntry struct {
	File    string   `json:"file"`
	CSS     []string `json:"css"`
	Assets  []string `json:"assets"`
	IsEntry bool     `json:"isEntry"`
}

func NewWebUI(root, oidcURL string) (*WebUI, error) {
	if !validWebRoot(root) {
		return nil, errors.New("web root must be a clean absolute directory")
	}
	before, err := os.Lstat(root)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, errors.New("web root is unavailable")
	}
	rooted, err := os.OpenRoot(root)
	if err != nil {
		return nil, errors.New("web root is unavailable")
	}
	keepRoot := false
	defer func() {
		if !keepRoot {
			_ = rooted.Close()
		}
	}()
	opened, openedErr := rooted.Stat(".")
	after, afterErr := os.Lstat(root)
	if openedErr != nil || afterErr != nil ||
		after.Mode()&os.ModeSymlink != 0 || !after.IsDir() ||
		!os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return nil, errors.New("web root identity changed")
	}
	origin, err := publicHTTPSOrigin(oidcURL)
	if err != nil {
		return nil, errors.New("web OIDC origin is invalid")
	}
	digest, assets, err := loadViteManifest(rooted)
	if err != nil {
		return nil, err
	}
	if err := validateRegularWebFile(rooted, webIndexPath); err != nil {
		return nil, errors.New("web index is unavailable")
	}
	assetSet := make(map[string]struct{}, len(assets))
	for _, asset := range assets {
		if err := validateRegularWebFile(rooted, asset); err != nil {
			return nil, errors.New("web manifest asset is unavailable")
		}
		assetSet["/"+asset] = struct{}{}
	}
	webUI := &WebUI{
		rootPath:       root,
		root:           rooted,
		oidcOrigin:     origin,
		contentPolicy:  webContentSecurityPolicy(origin),
		manifestDigest: digest,
		manifestAssets: assets,
		assetSet:       assetSet,
	}
	keepRoot = true
	return webUI, nil
}

func (webUI *WebUI) Ready() error {
	if webUI == nil || !webUI.rootIdentityAvailable() {
		return errors.New("web UI is unavailable")
	}
	if err := validateRegularWebFile(webUI.root, webIndexPath); err != nil {
		return errors.New("web UI is unavailable")
	}
	digest, assets, err := loadViteManifest(webUI.root)
	if err != nil || !bytes.Equal(digest[:], webUI.manifestDigest[:]) ||
		len(assets) != len(webUI.manifestAssets) {
		return errors.New("web UI is unavailable")
	}
	for index, asset := range assets {
		if asset != webUI.manifestAssets[index] {
			return errors.New("web UI is unavailable")
		}
		if err := validateRegularWebFile(webUI.root, asset); err != nil {
			return errors.New("web UI is unavailable")
		}
	}
	return nil
}

func (webUI *WebUI) Close() error {
	if webUI == nil || webUI.root == nil {
		return nil
	}
	webUI.closeOnce.Do(func() {
		webUI.closeErr = webUI.root.Close()
	})
	return webUI.closeErr
}

func (webUI *WebUI) rootIdentityAvailable() bool {
	if webUI == nil || webUI.root == nil {
		return false
	}
	opened, openedErr := webUI.root.Stat(".")
	current, currentErr := os.Lstat(webUI.rootPath)
	return openedErr == nil && currentErr == nil &&
		current.Mode()&os.ModeSymlink == 0 && current.IsDir() &&
		os.SameFile(opened, current)
}

func (webUI *WebUI) Wrap(next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if webUI == nil || reservedWebPath(request.URL.Path) ||
			(request.Method != http.MethodGet && request.Method != http.MethodHead) {
			next.ServeHTTP(writer, request)
			return
		}
		if !validWebRequestPath(request) {
			http.NotFound(writer, request)
			return
		}
		requestPath := request.URL.Path
		if requestPath == "/.vite" || strings.HasPrefix(requestPath, "/.vite/") {
			http.NotFound(writer, request)
			return
		}
		if requestPath == "/index.html" {
			webUI.serveFile(writer, request, webIndexPath, false)
			return
		}
		if _, ok := webUI.assetSet[requestPath]; ok {
			webUI.serveFile(writer, request, strings.TrimPrefix(requestPath, "/"), true)
			return
		}
		if path.Ext(requestPath) != "" || !acceptsHTML(request.Header.Get("Accept")) {
			next.ServeHTTP(writer, request)
			return
		}
		webUI.serveFile(writer, request, webIndexPath, false)
	})
}

func (webUI *WebUI) serveFile(
	writer http.ResponseWriter,
	request *http.Request,
	relative string,
	immutable bool,
) {
	file, err := secureOpenRegularWebFile(webUI.root, relative)
	if err != nil {
		http.Error(writer, "Web asset unavailable", http.StatusServiceUnavailable)
		return
	}
	defer file.Close()
	webUI.setHeaders(writer.Header())
	if immutable {
		writer.Header().Set("Cache-Control", "public,max-age=31536000,immutable")
	} else {
		writer.Header().Set("Cache-Control", "no-store")
	}
	if contentType := mime.TypeByExtension(filepath.Ext(relative)); contentType != "" {
		writer.Header().Set("Content-Type", contentType)
	}
	http.ServeContent(writer, request, filepath.Base(relative), time.Time{}, file)
}

func (webUI *WebUI) setHeaders(headers http.Header) {
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("Referrer-Policy", "no-referrer")
	headers.Set("Content-Security-Policy", webUI.contentPolicy)
}

func loadViteManifest(root *os.Root) ([sha256.Size]byte, []string, error) {
	var empty [sha256.Size]byte
	file, err := secureOpenRegularWebFile(root, webManifestPath)
	if err != nil {
		return empty, nil, errors.New("web manifest is unavailable")
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxManifestSize+1))
	if err != nil || len(content) == 0 || len(content) > maxManifestSize ||
		rejectDuplicateJSONKeys(content) != nil {
		return empty, nil, errors.New("web manifest is invalid")
	}
	var manifest map[string]viteManifestEntry
	if err := json.Unmarshal(content, &manifest); err != nil || len(manifest) == 0 {
		return empty, nil, errors.New("web manifest is invalid")
	}
	assets := make(map[string]struct{})
	hasEntry := false
	for _, entry := range manifest {
		hasEntry = hasEntry || entry.IsEntry
		references := make([]string, 0, 1+len(entry.CSS)+len(entry.Assets))
		references = append(references, entry.File)
		references = append(references, entry.CSS...)
		references = append(references, entry.Assets...)
		for _, reference := range references {
			if !hashedWebAssetPattern.MatchString(reference) ||
				path.Clean(reference) != reference {
				return empty, nil, errors.New("web manifest contains an invalid asset")
			}
			assets[reference] = struct{}{}
		}
	}
	if !hasEntry || len(assets) == 0 {
		return empty, nil, errors.New("web manifest has no entry assets")
	}
	ordered := make([]string, 0, len(assets))
	for asset := range assets {
		ordered = append(ordered, asset)
	}
	sort.Strings(ordered)
	return sha256.Sum256(content), ordered, nil
}

func validateRegularWebFile(root *os.Root, relative string) error {
	file, err := secureOpenRegularWebFile(root, relative)
	if err != nil {
		return err
	}
	return file.Close()
}

func secureOpenRegularWebFile(root *os.Root, relative string) (*os.File, error) {
	if root == nil {
		return nil, errors.New("web root is unavailable")
	}
	if relative == "" || filepath.IsAbs(relative) || strings.Contains(relative, `\`) ||
		path.Clean(relative) != relative || strings.HasPrefix(relative, "../") {
		return nil, errors.New("invalid web asset path")
	}
	parts := strings.Split(relative, "/")
	before := make([]os.FileInfo, len(parts))
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, errors.New("invalid web asset path")
		}
		current := filepath.FromSlash(strings.Join(parts[:index+1], "/"))
		info, err := root.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("web asset is unavailable")
		}
		if index < len(parts)-1 && !info.IsDir() {
			return nil, errors.New("web asset parent is invalid")
		}
		if index == len(parts)-1 && !info.Mode().IsRegular() {
			return nil, errors.New("web asset is not a regular file")
		}
		before[index] = info
	}
	file, err := root.Open(filepath.FromSlash(relative))
	if err != nil {
		return nil, errors.New("web asset is unavailable")
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() ||
		!os.SameFile(before[len(before)-1], opened) {
		_ = file.Close()
		return nil, errors.New("web asset identity changed")
	}
	for index := range parts {
		current := filepath.FromSlash(strings.Join(parts[:index+1], "/"))
		after, afterErr := root.Lstat(current)
		if afterErr != nil || after.Mode()&os.ModeSymlink != 0 ||
			!os.SameFile(before[index], after) ||
			index < len(parts)-1 && !after.IsDir() ||
			index == len(parts)-1 && !after.Mode().IsRegular() {
			_ = file.Close()
			return nil, errors.New("web asset identity changed")
		}
	}
	return file, nil
}

func validWebRoot(root string) bool {
	return root != "" && root == strings.TrimSpace(root) && len(root) <= 4096 && filepath.IsAbs(root) &&
		filepath.Clean(root) == root && root != filepath.VolumeName(root)+string(filepath.Separator) &&
		!strings.ContainsAny(root, "\x00\r\n")
}

func publicHTTPSOrigin(value string) (string, error) {
	if !validBrowserOIDCURL(value) {
		return "", errors.New("invalid OIDC URL")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", errors.New("invalid OIDC URL")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func webContentSecurityPolicy(oidcOrigin string) string {
	return fmt.Sprintf(
		"default-src 'self'; script-src 'self'; style-src 'self'; "+
			"connect-src 'self' %s; frame-ancestors 'none'; base-uri 'none'; "+
			"object-src 'none'; form-action %s",
		oidcOrigin, oidcOrigin,
	)
}

func reservedWebPath(requestPath string) bool {
	for _, prefix := range []string{"/api", "/healthz", "/readyz"} {
		if requestPath == prefix || strings.HasPrefix(requestPath, prefix+"/") {
			return true
		}
	}
	return false
}

func validWebRequestPath(request *http.Request) bool {
	requestPath := request.URL.Path
	if requestPath == "" || !strings.HasPrefix(requestPath, "/") ||
		strings.Contains(requestPath, `\`) || strings.ContainsRune(requestPath, '\x00') ||
		strings.Contains(requestPath, "//") ||
		(requestPath != "/" && (path.Clean(requestPath) != requestPath ||
			strings.HasSuffix(requestPath, "/"))) {
		return false
	}
	escaped := strings.ToLower(request.URL.EscapedPath())
	for _, encoded := range []string{"%00", "%25", "%2e", "%2f", "%5c"} {
		if strings.Contains(escaped, encoded) {
			return false
		}
	}
	return true
}

func acceptsHTML(value string) bool {
	for _, rawRange := range strings.Split(value, ",") {
		parts := strings.Split(rawRange, ";")
		mediaType := strings.ToLower(strings.TrimSpace(parts[0]))
		if mediaType != "text/html" && mediaType != "application/xhtml+xml" {
			continue
		}
		quality := 1.0
		for _, parameter := range parts[1:] {
			name, rawValue, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if !ok || strings.ToLower(name) != "q" {
				continue
			}
			parsed, err := strconv.ParseFloat(rawValue, 64)
			if err != nil || parsed < 0 || parsed > 1 {
				quality = 0
			} else {
				quality = parsed
			}
		}
		if quality > 0 {
			return true
		}
	}
	return false
}
