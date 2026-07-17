package externalcmdb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

func TestCapabilitiesUsesOnlyFixedGETRequestSurface(t *testing.T) {
	t.Parallel()

	received := make(chan *http.Request, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received <- request.Clone(request.Context())
		writer.Header().Set("Content-Type", catalogContentType)
		fmt.Fprint(writer, `{
			"protocol_version":"cmdb-catalog/v1",
			"authority_id":"cmdb-production-01",
			"snapshot_epoch":"snapshot-0001",
			"max_page_size":500,
			"supports_delta":true,
			"supports_tombstone":true,
			"server_time":"2026-07-17T09:30:00Z",
			"permissions":["assets.read","relations.read"]
		}`)
	}))
	t.Cleanup(server.Close)

	client, err := newCatalogClient(catalogClientConfig{
		BaseURL:        server.URL,
		TLSConfig:      verifiedTLSConfigForServer(t, server),
		RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("newCatalogClient() error = %v", err)
	}

	got, err := client.capabilities(context.Background())
	if err != nil {
		t.Fatalf("capabilities() error = %v", err)
	}
	if got.AuthorityID != "cmdb-production-01" {
		t.Fatalf("authority_id = %q", got.AuthorityID)
	}
	request := <-received
	if request.Method != http.MethodGet || request.URL.Path != capabilitiesPath {
		t.Fatalf("request = %s %s", request.Method, request.URL.Path)
	}
	if request.URL.RawQuery != "" || request.Body != http.NoBody {
		t.Fatalf("request exposes query/body: query=%q body=%T", request.URL.RawQuery, request.Body)
	}
	if request.Header.Get("Accept") != catalogContentType {
		t.Fatalf("Accept = %q", request.Header.Get("Accept"))
	}
}

func TestCatalogClientRequiresTLS13AndRejectsRedirects(t *testing.T) {
	t.Parallel()

	client, err := newCatalogClient(catalogClientConfig{
		BaseURL:        "https://cmdb.invalid",
		TLSConfig:      &tls.Config{MinVersion: tls.VersionTLS12},
		RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("newCatalogClient() error = %v", err)
	}

	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T", client.httpClient.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("transport must not use environment proxy")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("TLS MinVersion = %#x", transport.TLSClientConfig.MinVersion)
	}
	if err := client.httpClient.CheckRedirect(nil, nil); err == nil {
		t.Fatal("redirect was accepted")
	}
}

func TestCatalogClientRejectsInsecureSkipVerify(t *testing.T) {
	t.Parallel()

	client, err := newCatalogClient(catalogClientConfig{
		BaseURL: "https://cmdb.invalid",
		TLSConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		},
		RequestTimeout: time.Second,
	})
	if err == nil || client != nil {
		t.Fatalf("newCatalogClient() = (%#v, %v), want insecure TLS rejection", client, err)
	}
	if strings.Contains(err.Error(), "cmdb.invalid") {
		t.Fatalf("TLS rejection leaked endpoint: %v", err)
	}
}

func TestAssetProbeUsesFixedMaxLimitWithoutCallerSelectedQuery(t *testing.T) {
	t.Parallel()

	received := make(chan *http.Request, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received <- request.Clone(request.Context())
		writer.Header().Set("Content-Type", catalogContentType)
		fmt.Fprint(writer, `{
			"items":[],
			"next_cursor":"",
			"snapshot_epoch":"snapshot-0001",
			"final_page":true,
			"complete_snapshot":true
		}`)
	}))
	t.Cleanup(server.Close)

	client := catalogClientForTLSServer(t, server)
	if _, err := client.assets(context.Background(), catalogCursor{}, maxPageBodyBytes); err != nil {
		t.Fatalf("assets() error = %v", err)
	}
	request := <-received
	if request.Method != http.MethodGet || request.URL.Path != assetsPath ||
		request.URL.RawQuery != "limit=500" || request.Body != http.NoBody {
		t.Fatalf("asset probe request = %s %s?%s body=%T",
			request.Method, request.URL.Path, request.URL.RawQuery, request.Body)
	}
	if closedCatalogRequest(assetsPath, "limit=499") ||
		closedCatalogRequest(assetsPath, "cursor=caller-selected") ||
		closedCatalogRequest(assetsPath, "") ||
		closedCatalogRequest(relationsPath, "") ||
		closedCatalogRequest("/v1/arbitrary", "") {
		t.Fatal("closed request validator accepted caller-selected wire surface")
	}
}

func TestRelationsUsesFixedLimitAndCanonicalTypedCursor(t *testing.T) {
	t.Parallel()

	received := make(chan *http.Request, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received <- request.Clone(request.Context())
		writer.Header().Set("Content-Type", catalogContentType)
		fmt.Fprint(writer, `{
			"items":[],
			"next_cursor":"",
			"snapshot_epoch":"snapshot-0001",
			"final_page":true,
			"complete_snapshot":true
		}`)
	}))
	t.Cleanup(server.Close)

	cursor, err := newCatalogCursor("next+/=")
	if err != nil {
		t.Fatalf("newCatalogCursor() error = %v", err)
	}
	client := catalogClientForTLSServer(t, server)
	if _, err := client.relations(context.Background(), cursor, maxPageBodyBytes); err != nil {
		t.Fatalf("relations() error = %v", err)
	}
	request := <-received
	if request.Method != http.MethodGet || request.URL.Path != relationsPath ||
		request.URL.RawQuery != "cursor=next%2B%2F%3D&limit=2000" ||
		request.URL.Query().Get("cursor") != "next+/=" ||
		request.Body != http.NoBody {
		t.Fatalf("relation request = %s %s?%s body=%T",
			request.Method, request.URL.Path, request.URL.RawQuery, request.Body)
	}
	for _, invalid := range []string{
		"caller&limit=1",
		"line\nbreak",
		strings.Repeat("a", 2_049),
	} {
		if cursor, err := newCatalogCursor(invalid); err == nil {
			t.Fatalf("newCatalogCursor(%q) = %#v, want rejection", invalid, cursor)
		}
	}
}

func TestCatalogClientRejectsUnsafeResponseEnvelopes(t *testing.T) {
	t.Parallel()

	valid := `{
		"protocol_version":"cmdb-catalog/v1",
		"authority_id":"cmdb-production-01",
		"snapshot_epoch":"snapshot-0001",
		"max_page_size":500,
		"supports_delta":true,
		"supports_tombstone":true,
		"server_time":"2026-07-17T09:30:00Z",
		"permissions":["assets.read","relations.read"]
	}`
	tests := []struct {
		name            string
		contentType     string
		contentEncoding string
		body            string
	}{
		{
			name:        "non-exact content type",
			contentType: "application/json; charset=utf-8",
			body:        valid,
		},
		{
			name:            "content encoding",
			contentType:     catalogContentType,
			contentEncoding: "gzip",
			body:            valid,
		},
		{
			name:        "duplicate key",
			contentType: catalogContentType,
			body: strings.Replace(
				valid,
				`"authority_id":"cmdb-production-01",`,
				`"authority_id":"cmdb-production-01","authority_id":"duplicate",`,
				1,
			),
		},
		{
			name:        "unknown field",
			contentType: catalogContentType,
			body: strings.Replace(
				valid,
				`"permissions":["assets.read","relations.read"]`,
				`"permissions":["assets.read","relations.read"],"unexpected":"LEAK-MARKER"`,
				1,
			),
		},
		{
			name:        "trailing JSON",
			contentType: catalogContentType,
			body:        valid + `{}`,
		},
		{
			name:        "body limit",
			contentType: catalogContentType,
			body:        strings.Repeat(" ", int(maxCapabilitiesBodyBytes)+1),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", test.contentType)
				if test.contentEncoding != "" {
					writer.Header().Set("Content-Encoding", test.contentEncoding)
				}
				fmt.Fprint(writer, test.body)
			}))
			t.Cleanup(server.Close)

			client := catalogClientForTLSServer(t, server)
			if _, err := client.capabilities(context.Background()); err == nil {
				t.Fatal("capabilities() accepted unsafe response")
			} else if strings.Contains(err.Error(), "LEAK-MARKER") ||
				strings.Contains(err.Error(), server.URL) {
				t.Fatalf("error leaked response/endpoint: %v", err)
			}
		})
	}
}

func TestProviderValidateUsesBoundRuntimeAndReturnsContractProof(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 17, 9, 30, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-bearer-token" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", catalogContentType)
		switch request.URL.Path {
		case capabilitiesPath:
			fmt.Fprintf(writer, `{
				"protocol_version":"cmdb-catalog/v1",
				"authority_id":"cmdb-production-01",
				"snapshot_epoch":"snapshot-0001",
				"max_page_size":500,
				"supports_delta":true,
				"supports_tombstone":true,
				"server_time":%q,
				"permissions":["assets.read","relations.read"]
			}`, now.Format(time.RFC3339Nano))
		case assetsPath:
			fmt.Fprint(writer, `{
				"items":[],
				"next_cursor":"",
				"snapshot_epoch":"snapshot-0001",
				"final_page":true,
				"complete_snapshot":true
			}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	request := validExternalCMDBValidationRequest()
	binding := discoverysource.RuntimeBinding{
		Locator:              request.Locator,
		SourceRevision:       request.SourceRevision,
		SourceRevisionDigest: request.SourceRevisionDigest,
		RevisionStatus:       assetcatalog.SourceRevisionValidating,
		ProviderKind:         providerKind,
		ProfileCode:          profileCode,
	}
	material := RuntimeMaterial{
		BaseURL:             server.URL,
		TLSConfig:           verifiedTLSConfigForServer(t, server),
		BearerToken:         []byte("test-bearer-token"),
		ExpectedAuthorityID: "cmdb-production-01",
		EnvironmentID:       "44444444-4444-4444-8444-444444444444",
	}
	runtime, err := discoverysource.BindRuntime(
		binding,
		&material,
		func(*RuntimeMaterial) error { return nil },
		func(value *RuntimeMaterial) { value.Clear() },
	)
	if err != nil {
		t.Fatalf("BindRuntime() error = %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })

	factory, err := NewClientFactory(binding)
	if err != nil {
		t.Fatalf("NewClientFactory() error = %v", err)
	}
	factory.now = func() time.Time { return now }
	contractProvider, err := New(factory)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	proof, err := contractProvider.Validate(context.Background(), runtime, request)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if proof.Outcome != assetcatalog.ValidationOutcomeSucceeded || proof.Code != "VALIDATION_SUCCEEDED" {
		t.Fatalf("proof = %#v", proof)
	}
	if err := discoverysource.ValidateValidationResult(request, proof, nil); err != nil {
		t.Fatalf("proof violates discoverysource contract: %v", err)
	}
}

func TestProviderValidateRejectsWrongCAAndSNIAsTrustFailure(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 17, 9, 30, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", catalogContentType)
		switch request.URL.Path {
		case capabilitiesPath:
			fmt.Fprintf(writer, `{
				"protocol_version":"cmdb-catalog/v1",
				"authority_id":"cmdb-production-01",
				"snapshot_epoch":"snapshot-0001",
				"max_page_size":500,
				"supports_delta":true,
				"supports_tombstone":true,
				"server_time":%q,
				"permissions":["assets.read","relations.read"]
			}`, now.Format(time.RFC3339Nano))
		case assetsPath:
			fmt.Fprint(writer, `{
				"items":[],
				"next_cursor":"",
				"snapshot_epoch":"snapshot-0001",
				"final_page":true,
				"complete_snapshot":true
			}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	tests := []struct {
		name      string
		tlsConfig func(*testing.T) *tls.Config
	}{
		{
			name: "wrong CA",
			tlsConfig: func(t *testing.T) *tls.Config {
				config := verifiedTLSConfigForServer(t, server)
				config.RootCAs = x509.NewCertPool()
				return config
			},
		},
		{
			name: "wrong SNI",
			tlsConfig: func(t *testing.T) *tls.Config {
				config := verifiedTLSConfigForServer(t, server)
				config.ServerName = "wrong-sni.example.invalid"
				return config
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			request := validExternalCMDBValidationRequest()
			binding := validatingBindingForRequest(request)
			material := RuntimeMaterial{
				BaseURL:             server.URL,
				TLSConfig:           test.tlsConfig(t),
				BearerToken:         []byte("test-bearer-token"),
				ExpectedAuthorityID: "cmdb-production-01",
				EnvironmentID:       "44444444-4444-4444-8444-444444444444",
			}
			runtime, err := discoverysource.BindRuntime(
				binding,
				&material,
				func(*RuntimeMaterial) error { return nil },
				func(value *RuntimeMaterial) { value.Clear() },
			)
			if err != nil {
				t.Fatalf("BindRuntime() error = %v", err)
			}
			t.Cleanup(func() { _ = runtime.Close() })
			factory, err := NewClientFactory(binding)
			if err != nil {
				t.Fatalf("NewClientFactory() error = %v", err)
			}
			factory.now = func() time.Time { return now }
			contractProvider, err := New(factory)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			proof, err := contractProvider.Validate(context.Background(), runtime, request)
			if err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if proof.Outcome != assetcatalog.ValidationOutcomeFailed ||
				len(proof.Checks) != 1 ||
				proof.Checks[0].Kind != discoverysource.ValidationCheckTrustOrSignature ||
				proof.Checks[0].Passed {
				t.Fatalf("trust failure proof = %#v", proof)
			}
			if err := discoverysource.ValidateValidationResult(request, proof, nil); err != nil {
				t.Fatalf("trust failure violates discoverysource contract: %v", err)
			}
		})
	}
}

func TestProviderValidateRejectsMissingCredentialBeforeNetwork(t *testing.T) {
	t.Parallel()

	var networkCalls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		networkCalls.Add(1)
	}))
	t.Cleanup(server.Close)

	request := validExternalCMDBValidationRequest()
	binding := validatingBindingForRequest(request)
	material := RuntimeMaterial{
		BaseURL:             server.URL,
		TLSConfig:           verifiedTLSConfigForServer(t, server),
		ExpectedAuthorityID: "cmdb-production-01",
		EnvironmentID:       "44444444-4444-4444-8444-444444444444",
	}
	runtime, err := discoverysource.BindRuntime(
		binding,
		&material,
		func(*RuntimeMaterial) error { return nil },
		func(value *RuntimeMaterial) { value.Clear() },
	)
	if err != nil {
		t.Fatalf("BindRuntime() error = %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	factory, err := NewClientFactory(binding)
	if err != nil {
		t.Fatalf("NewClientFactory() error = %v", err)
	}
	contractProvider, err := New(factory)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	proof, err := contractProvider.Validate(context.Background(), runtime, request)
	if err == nil {
		t.Fatalf("Validate() = %#v, want missing-credential rejection", proof)
	}
	if networkCalls.Load() != 0 {
		t.Fatalf("missing credential made %d network calls", networkCalls.Load())
	}
	for _, sensitive := range []string{server.URL, request.SourceRevisionDigest} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("missing-credential rejection leaked sensitive value: %v", err)
		}
	}
}

func TestProviderValidateConsumesRequestPageByteBudget(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 17, 9, 30, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", catalogContentType)
		switch request.URL.Path {
		case capabilitiesPath:
			fmt.Fprintf(writer, `{
				"protocol_version":"cmdb-catalog/v1",
				"authority_id":"cmdb-production-01",
				"snapshot_epoch":"snapshot-0001",
				"max_page_size":500,
				"supports_delta":true,
				"supports_tombstone":true,
				"server_time":%q,
				"permissions":["assets.read","relations.read"]
			}`, now.Format(time.RFC3339Nano))
		case assetsPath:
			fmt.Fprint(writer, `{
				"items":[],
				"next_cursor":"",
				"snapshot_epoch":"snapshot-0001",
				"final_page":true,
				"complete_snapshot":true
			}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	request := validExternalCMDBValidationRequest()
	request.Limits.MaxPageBytes = 64
	binding := validatingBindingForRequest(request)
	material := RuntimeMaterial{
		BaseURL:             server.URL,
		TLSConfig:           verifiedTLSConfigForServer(t, server),
		BearerToken:         []byte("test-bearer-token"),
		ExpectedAuthorityID: "cmdb-production-01",
		EnvironmentID:       "44444444-4444-4444-8444-444444444444",
	}
	runtime, err := discoverysource.BindRuntime(
		binding,
		&material,
		func(*RuntimeMaterial) error { return nil },
		func(value *RuntimeMaterial) { value.Clear() },
	)
	if err != nil {
		t.Fatalf("BindRuntime() error = %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	factory, err := NewClientFactory(binding)
	if err != nil {
		t.Fatalf("NewClientFactory() error = %v", err)
	}
	factory.now = func() time.Time { return now }
	contractProvider, err := New(factory)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	proof, err := contractProvider.Validate(context.Background(), runtime, request)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if proof.Outcome != assetcatalog.ValidationOutcomeFailed ||
		len(proof.Checks) != 1 ||
		proof.Checks[0].Kind != discoverysource.ValidationCheckBudget ||
		proof.Checks[0].Passed {
		t.Fatalf("small page budget proof = %#v", proof)
	}
	if err := discoverysource.ValidateValidationResult(request, proof, nil); err != nil {
		t.Fatalf("budget failure violates discoverysource contract: %v", err)
	}
}

func TestProviderValidateRejectsBindingDriftBeforeNetwork(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status assetcatalog.SourceRevisionStatus
		mutate func(*discoverysource.ValidationRequest)
	}{
		{
			name:   "wrong locator",
			status: assetcatalog.SourceRevisionValidating,
			mutate: func(request *discoverysource.ValidationRequest) {
				request.Locator.SourceID = "55555555-5555-4555-8555-555555555555"
			},
		},
		{
			name:   "wrong revision",
			status: assetcatalog.SourceRevisionValidating,
			mutate: func(request *discoverysource.ValidationRequest) {
				request.SourceRevision++
			},
		},
		{
			name:   "wrong digest",
			status: assetcatalog.SourceRevisionValidating,
			mutate: func(request *discoverysource.ValidationRequest) {
				request.SourceRevisionDigest = strings.Repeat("b", 64)
			},
		},
		{
			name:   "published binding",
			status: assetcatalog.SourceRevisionPublished,
			mutate: func(*discoverysource.ValidationRequest) {},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var networkCalls atomic.Int64
			server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				networkCalls.Add(1)
			}))
			t.Cleanup(server.Close)

			boundRequest := validExternalCMDBValidationRequest()
			binding := discoverysource.RuntimeBinding{
				Locator:              boundRequest.Locator,
				SourceRevision:       boundRequest.SourceRevision,
				SourceRevisionDigest: boundRequest.SourceRevisionDigest,
				RevisionStatus:       test.status,
				ProviderKind:         providerKind,
				ProfileCode:          profileCode,
			}
			material := RuntimeMaterial{
				BaseURL:             server.URL,
				TLSConfig:           verifiedTLSConfigForServer(t, server),
				BearerToken:         []byte("test-bearer-token"),
				ExpectedAuthorityID: "cmdb-production-01",
				EnvironmentID:       "44444444-4444-4444-8444-444444444444",
			}
			runtime, err := discoverysource.BindRuntime(
				binding,
				&material,
				func(*RuntimeMaterial) error { return nil },
				func(value *RuntimeMaterial) { value.Clear() },
			)
			if err != nil {
				t.Fatalf("BindRuntime() error = %v", err)
			}
			t.Cleanup(func() { _ = runtime.Close() })

			factory, err := NewClientFactory(binding)
			if err != nil {
				t.Fatalf("NewClientFactory() error = %v", err)
			}
			contractProvider, err := New(factory)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			request := boundRequest
			test.mutate(&request)

			proof, err := contractProvider.Validate(context.Background(), runtime, request)
			if err == nil {
				t.Fatalf("Validate() = %#v, want binding rejection", proof)
			}
			if proof.Outcome != "" || proof.Code != "" || len(proof.Checks) != 0 {
				t.Fatalf("binding rejection returned proof = %#v", proof)
			}
			if networkCalls.Load() != 0 {
				t.Fatalf("binding rejection made %d network calls", networkCalls.Load())
			}
			for _, sensitive := range []string{
				server.URL,
				boundRequest.SourceRevisionDigest,
				request.SourceRevisionDigest,
			} {
				if strings.Contains(err.Error(), sensitive) {
					t.Fatalf("binding rejection leaked sensitive value: %v", err)
				}
			}
		})
	}
}

func TestRuntimeMaterialCannotSerializeOrRevealSensitiveValues(t *testing.T) {
	t.Parallel()

	material := RuntimeMaterial{
		BaseURL:             "https://cmdb.example.invalid",
		BearerToken:         []byte("secret-token"),
		ExpectedAuthorityID: "cmdb-production-01",
	}
	if _, err := json.Marshal(material); !errors.Is(err, discoverysource.ErrSensitiveSerialization) {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	rendered := fmt.Sprintf("%v %#v", material, material)
	for _, sensitive := range []string{material.BaseURL, string(material.BearerToken)} {
		if strings.Contains(rendered, sensitive) {
			t.Fatalf("formatted runtime material leaked %q", sensitive)
		}
	}
}

func validExternalCMDBValidationRequest() discoverysource.ValidationRequest {
	return discoverysource.ValidationRequest{
		Locator: assetcatalog.SourceLocator{
			Scope: assetcatalog.SourceScope{
				TenantID:    "11111111-1111-4111-8111-111111111111",
				WorkspaceID: "22222222-2222-4222-8222-222222222222",
			},
			SourceID: "33333333-3333-4333-8333-333333333333",
		},
		SourceRevision:       17,
		SourceRevisionDigest: strings.Repeat("a", 64),
		Limits: discoverysource.Limits{
			MaxPageItems:     500,
			MaxPageRelations: 2_000,
			MaxPageBytes:     4 << 20,
			MaxDocumentBytes: 64 << 10,
		},
	}
}

func validatingBindingForRequest(request discoverysource.ValidationRequest) discoverysource.RuntimeBinding {
	return discoverysource.RuntimeBinding{
		Locator:              request.Locator,
		SourceRevision:       request.SourceRevision,
		SourceRevisionDigest: request.SourceRevisionDigest,
		RevisionStatus:       assetcatalog.SourceRevisionValidating,
		ProviderKind:         providerKind,
		ProfileCode:          profileCode,
	}
}

func catalogClientForTLSServer(t *testing.T, server *httptest.Server) *catalogClient {
	t.Helper()

	client, err := newCatalogClient(catalogClientConfig{
		BaseURL:        server.URL,
		TLSConfig:      verifiedTLSConfigForServer(t, server),
		RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("newCatalogClient() error = %v", err)
	}
	t.Cleanup(client.close)
	return client
}

func verifiedTLSConfigForServer(t *testing.T, server *httptest.Server) *tls.Config {
	t.Helper()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse TLS server URL: %v", err)
	}
	roots := x509.NewCertPool()
	if certificate := server.Certificate(); certificate == nil {
		t.Fatal("TLS server has no certificate")
	} else {
		roots.AddCert(certificate)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: parsed.Hostname(),
	}
}
