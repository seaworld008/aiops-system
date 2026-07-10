package vault

import (
	"bytes"
	"encoding/pem"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestNewProfileCopiesSecurityConfiguration(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	config := ProfileConfig{
		IssuerID: "vault-database-nonprod", Revision: "rev-1", Address: server.URL,
		ServerName: serverURL.Hostname(), CAPEM: caPEM, Namespace: "aiops/",
		ManagerPolicy: "aiops-issuer-manager", TokenRole: "aiops-db-job", ChildPolicy: "aiops-db-job",
		DynamicPath: "database/creds/aiops-db-job", MountType: "database",
		Metadata:     map[string]string{"profile": "vault-database-nonprod", "revision": "rev-1"},
		SecretFields: []SecretField{{Name: "username", MaxBytes: 256}, {Name: "password", MaxBytes: 4096}},
	}

	profile, err := NewProfile(config)
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}
	config.CAPEM[0] ^= 0xff
	config.Metadata["profile"] = "mutated"
	config.SecretFields[0].Name = "mutated"

	if profile.IssuerID() != "vault-database-nonprod" || profile.Revision() != "rev-1" {
		t.Fatalf("profile identity = %q/%q", profile.IssuerID(), profile.Revision())
	}
	metadata := profile.Metadata()
	fields := profile.SecretFields()
	if metadata["profile"] != "vault-database-nonprod" || len(fields) != 2 || fields[0].Name != "username" {
		t.Fatalf("profile retained caller mutation: metadata=%v fields=%v", metadata, fields)
	}
	metadata["profile"] = "second-mutation"
	fields[0].Name = "second-mutation"
	if profile.Metadata()["profile"] != "vault-database-nonprod" || profile.SecretFields()[0].Name != "username" {
		t.Fatal("profile accessors exposed mutable internal state")
	}
}

func TestNewProfileRejectsAmbiguousCAInput(t *testing.T) {
	t.Parallel()

	config := testProfileConfig(t)
	config.CAPEM = append(bytes.Clone(config.CAPEM), []byte("not-a-certificate")...)

	if _, err := NewProfile(config); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("NewProfile(ambiguous CA) error = %v, want ErrInvalidProfile", err)
	}
}

func TestNewProfileRejectsMutableOrInsecureTrustConfiguration(t *testing.T) {
	t.Parallel()

	base := testProfileConfig(t)
	tests := map[string]func(*ProfileConfig){
		"plaintext HTTP": func(config *ProfileConfig) {
			config.Address = strings.Replace(config.Address, "https://", "http://", 1)
		},
		"userinfo": func(config *ProfileConfig) {
			config.Address = strings.Replace(config.Address, "https://", "https://user@", 1)
		},
		"forced empty query":     func(config *ProfileConfig) { config.Address += "?" },
		"query":                  func(config *ProfileConfig) { config.Address += "?target=other" },
		"fragment":               func(config *ProfileConfig) { config.Address += "#other" },
		"base path":              func(config *ProfileConfig) { config.Address += "/mutable" },
		"wildcard host":          func(config *ProfileConfig) { config.Address = "https://*.example.com" },
		"wildcard server name":   func(config *ProfileConfig) { config.ServerName = "*.example.com" },
		"missing CA":             func(config *ProfileConfig) { config.CAPEM = nil },
		"prefixed CA garbage":    func(config *ProfileConfig) { config.CAPEM = append([]byte("garbage"), config.CAPEM...) },
		"path traversal":         func(config *ProfileConfig) { config.DynamicPath = "database/../creds/job" },
		"encoded path":           func(config *ProfileConfig) { config.DynamicPath = "database/%2e%2e/job" },
		"mutable metadata":       func(config *ProfileConfig) { config.Metadata["profile"] = "other" },
		"duplicate secret field": func(config *ProfileConfig) { config.SecretFields[1].Name = config.SecretFields[0].Name },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			config := base
			config.CAPEM = bytes.Clone(base.CAPEM)
			config.Metadata = maps.Clone(base.Metadata)
			config.SecretFields = slices.Clone(base.SecretFields)
			mutate(&config)
			if _, err := NewProfile(config); !errors.Is(err, ErrInvalidProfile) {
				t.Fatalf("NewProfile(%s) error = %v, want ErrInvalidProfile", name, err)
			}
		})
	}
}

func testProfileConfig(t *testing.T) ProfileConfig {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	return ProfileConfig{
		IssuerID: "vault-database-nonprod", Revision: "rev-1", Address: server.URL,
		ServerName: serverURL.Hostname(),
		CAPEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
		Namespace:  "aiops/", ManagerPolicy: "aiops-issuer-manager", TokenRole: "aiops-db-job",
		ChildPolicy: "aiops-db-job", DynamicPath: "database/creds/aiops-db-job", MountType: "database",
		Metadata: map[string]string{"profile": "vault-database-nonprod", "revision": "rev-1"},
		SecretFields: []SecretField{
			{Name: "username", MaxBytes: 256}, {Name: "password", MaxBytes: 4096},
		},
	}
}
