package httpapi

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode"
)

var browserOIDCIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type BrowserConfigInput struct {
	OIDCURL, OIDCRealm, OIDCClientID string
	Version, Commit, ContractDigest  string
}

type BrowserConfig struct {
	OIDC        browserOIDCConfig `json:"oidc"`
	APIBasePath string            `json:"api_base_path"`
	Build       browserBuildInfo  `json:"build"`
}

type browserOIDCConfig struct {
	URL      string `json:"url"`
	Realm    string `json:"realm"`
	ClientID string `json:"client_id"`
}

type browserBuildInfo struct {
	Version        string `json:"version"`
	Commit         string `json:"commit"`
	ContractDigest string `json:"contract_digest"`
}

func NewBrowserConfig(input BrowserConfigInput) (*BrowserConfig, error) {
	if !validBrowserOIDCURL(input.OIDCURL) ||
		!browserOIDCIdentifierPattern.MatchString(input.OIDCRealm) ||
		input.OIDCClientID != "control-plane-web" ||
		!validPublicBuildValue(input.Version, 128) ||
		!validPublicBuildValue(input.Commit, 128) ||
		!strings.HasPrefix(input.ContractDigest, "sha256:") ||
		!validSHA256Hex(strings.TrimPrefix(input.ContractDigest, "sha256:")) {
		return nil, errors.New("valid public browser configuration is required")
	}
	return &BrowserConfig{
		OIDC: browserOIDCConfig{
			URL: input.OIDCURL, Realm: input.OIDCRealm, ClientID: input.OIDCClientID,
		},
		APIBasePath: "/api/v1",
		Build: browserBuildInfo{
			Version: input.Version, Commit: input.Commit, ContractDigest: input.ContractDigest,
		},
	}, nil
}

func browserConfigHandler(configuration *BrowserConfig) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if configuration == nil {
			writeRequestProblem(
				writer, request, http.StatusServiceUnavailable,
				"browser_config_unavailable", "Browser configuration is unavailable",
			)
			return
		}
		writeJSON(writer, http.StatusOK, configuration)
	}
}

func validBrowserOIDCURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && value == strings.TrimSpace(value) && len(value) <= 2048 &&
		parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.Opaque == "" && parsed.RawQuery == "" && !parsed.ForceQuery &&
		parsed.Fragment == "" && parsed.RawPath == "" &&
		(parsed.Path == "" || path.Clean(parsed.Path) == parsed.Path) &&
		validPublicBrowserOIDCHost(parsed.Hostname()) &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

func validPublicBrowserOIDCHost(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) ||
		strings.HasSuffix(value, ".") {
		return false
	}
	if address := net.ParseIP(value); address != nil {
		return address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() &&
			!address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast()
	}
	for _, suffix := range []string{
		"localhost", ".localhost", ".local", ".internal", ".invalid", ".test", ".home.arpa",
	} {
		if value == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(value, suffix) {
			return false
		}
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
				character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validPublicBuildValue(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}
