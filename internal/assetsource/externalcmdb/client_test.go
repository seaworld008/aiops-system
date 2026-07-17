package externalcmdb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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

func TestCatalogClientPreservesCallerCancellationAndDeadline(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	client := catalogClientForTLSServer(t, server)

	tests := []struct {
		name    string
		context func() (context.Context, context.CancelFunc)
		want    error
	}{
		{
			name: "canceled",
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
			want: context.Canceled,
		},
		{
			name: "deadline exceeded",
			context: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			},
			want: context.DeadlineExceeded,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := test.context()
			defer cancel()
			if _, err := client.capabilities(ctx); !errors.Is(err, test.want) {
				t.Fatalf("capabilities() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCatalogClientDoesNotTreatTransportCancellationAsCallerCancellation(t *testing.T) {
	t.Parallel()

	baseURL, err := url.Parse("https://cmdb.invalid")
	if err != nil {
		t.Fatal(err)
	}
	for _, transportErr := range []error{context.Canceled, context.DeadlineExceeded} {
		client := &catalogClient{
			baseURL: baseURL,
			httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, transportErr
			})},
		}
		var capabilities catalogCapabilities
		err = client.getJSON(context.Background(), capabilitiesPath, maxCapabilitiesBodyBytes, &capabilities)
		if errors.Is(err, transportErr) || !clientErrorHasCode(err, "TRANSPORT_FAILED") {
			t.Fatalf("getJSON() error = %v, want TRANSPORT_FAILED", err)
		}
	}
}

func TestCatalogClientPreservesCallerContextDuringBodyRead(t *testing.T) {
	t.Parallel()

	for _, want := range []error{context.Canceled, context.DeadlineExceeded} {
		want := want
		t.Run(want.Error(), func(t *testing.T) {
			t.Parallel()

			baseURL, err := url.Parse("https://cmdb.invalid")
			if err != nil {
				t.Fatal(err)
			}
			bodyRead := make(chan struct{}, 1)
			var bodyObserved atomic.Bool

			var ctx context.Context
			var cancel context.CancelFunc
			if errors.Is(want, context.Canceled) {
				ctx, cancel = context.WithCancel(context.Background())
			} else {
				ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
			}
			defer cancel()
			client := &catalogClient{
				baseURL: baseURL,
				httpClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     http.Header{"Content-Type": []string{catalogContentType}},
						Body: &blockingContextBody{
							ctx: request.Context(), read: bodyRead, observed: &bodyObserved,
						},
						Request: request,
					}, nil
				})},
			}
			if errors.Is(want, context.Canceled) {
				go func() {
					<-bodyRead
					cancel()
				}()
			}

			if _, err := client.capabilities(ctx); !errors.Is(err, want) {
				t.Fatalf("capabilities() body-read error = %v, want %v", err, want)
			}
			if !bodyObserved.Load() {
				t.Fatal("capabilities() did not begin body read after response headers")
			}
		})
	}
}

func TestCatalogClientDoesNotTreatBodyReadErrorAsCallerCancellation(t *testing.T) {
	t.Parallel()

	baseURL, err := url.Parse("https://cmdb.invalid")
	if err != nil {
		t.Fatal(err)
	}
	for _, bodyErr := range []error{context.Canceled, context.DeadlineExceeded} {
		client := &catalogClient{
			baseURL: baseURL,
			httpClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{catalogContentType}},
					Body:       io.NopCloser(errorReader{err: bodyErr}),
					Request:    request,
				}, nil
			})},
		}
		var capabilities catalogCapabilities
		err = client.getJSON(context.Background(), capabilitiesPath, maxCapabilitiesBodyBytes, &capabilities)
		if errors.Is(err, bodyErr) || !protocolErrorHasCode(err, "BODY_READ_FAILED") {
			t.Fatalf("getJSON() body-read error = %v, want BODY_READ_FAILED", err)
		}
	}
}

func TestProviderValidatePreservesCallerContextByPhase(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 17, 9, 30, 0, 0, time.UTC)
	tests := []struct {
		name       string
		targetPath string
		want       error
	}{
		{name: "capabilities canceled", targetPath: capabilitiesPath, want: context.Canceled},
		{name: "capabilities deadline", targetPath: capabilitiesPath, want: context.DeadlineExceeded},
		{name: "asset probe canceled", targetPath: assetsPath, want: context.Canceled},
		{name: "asset probe deadline", targetPath: assetsPath, want: context.DeadlineExceeded},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			targetReached := make(chan struct{}, 1)
			var targetObserved atomic.Bool
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == test.targetPath {
					targetObserved.Store(true)
					targetReached <- struct{}{}
					<-request.Context().Done()
					return
				}
				writer.Header().Set("Content-Type", catalogContentType)
				switch request.URL.Path {
				case capabilitiesPath:
					writeValidCapabilities(writer, now)
				case assetsPath:
					writeEmptyAssetPage(writer)
				default:
					http.NotFound(writer, request)
				}
			}))
			t.Cleanup(server.Close)

			factory, runtime, request := externalCMDBValidationFixture(t, server, now)
			contractProvider, err := New(factory)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			var ctx context.Context
			var cancel context.CancelFunc
			if errors.Is(test.want, context.Canceled) {
				ctx, cancel = context.WithCancel(context.Background())
				done := make(chan struct{})
				t.Cleanup(func() { close(done) })
				go func() {
					select {
					case <-targetReached:
						cancel()
					case <-done:
					}
				}()
			} else {
				ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
			}
			defer cancel()

			proof, err := contractProvider.Validate(ctx, runtime, request)
			if !errors.Is(err, test.want) {
				t.Fatalf("Validate() = (%#v, %v), want zero proof and %v", proof, err, test.want)
			}
			if proof.Outcome != "" || proof.Code != "" || len(proof.Checks) != 0 {
				t.Fatalf("caller context returned validation proof = %#v", proof)
			}
			if !targetObserved.Load() {
				t.Fatalf("Validate() did not reach %s before caller context ended", test.targetPath)
			}
		})
	}
}

func TestCatalogClientReturnsTypedProviderBackoff(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 17, 9, 30, 0, 0, time.UTC)
	tests := []struct {
		name       string
		statusCode int
		retryAfter string
		operation  string
		want       time.Duration
	}{
		{
			name:       "assets 429 delta seconds",
			statusCode: http.StatusTooManyRequests,
			retryAfter: "17",
			operation:  "assets",
			want:       17 * time.Second,
		},
		{
			name:       "relations 503 HTTP date",
			statusCode: http.StatusServiceUnavailable,
			retryAfter: now.Add(42 * time.Second).Format(http.TimeFormat),
			operation:  "relations",
			want:       42 * time.Second,
		},
		{
			name:       "capabilities accepts zero",
			statusCode: http.StatusTooManyRequests,
			retryAfter: "0",
			operation:  "capabilities",
			want:       0,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Retry-After", test.retryAfter)
				writer.WriteHeader(test.statusCode)
			}))
			t.Cleanup(server.Close)
			factory, runtime, _ := externalCMDBValidationFixture(t, server, now)
			session, err := factory.open(runtime)
			if err != nil {
				t.Fatalf("open() error = %v", err)
			}
			t.Cleanup(session.close)

			switch test.operation {
			case "assets":
				_, err = session.client.assets(context.Background(), catalogCursor{}, maxPageBodyBytes)
			case "relations":
				_, err = session.client.relations(context.Background(), catalogCursor{}, maxPageBodyBytes)
			case "capabilities":
				_, err = session.client.capabilities(context.Background())
			default:
				t.Fatalf("unknown operation %q", test.operation)
			}
			if got, ok := providerRetryAfter(err); !ok || got != test.want {
				t.Fatalf("%s error = %v, retry after = (%v, %t), want %v",
					test.operation, err, got, ok, test.want)
			}
			if _, marshalErr := json.Marshal(err); !errors.Is(marshalErr, discoverysource.ErrSensitiveSerialization) {
				t.Fatalf("json.Marshal(backoff) error = %v", marshalErr)
			}
			rendered := fmt.Sprintf("%v %#v", err, err)
			for _, sensitive := range []string{
				server.URL,
				strconv.Itoa(test.statusCode),
				"Retry-After",
				test.retryAfter,
			} {
				if sensitive != "" && strings.Contains(rendered, sensitive) {
					t.Fatalf("backoff error leaked %q: %s", sensitive, rendered)
				}
			}
		})
	}
}

func TestCatalogClientRejectsInvalidOrInapplicableRetryAfter(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 17, 9, 30, 0, 0, time.UTC)
	tests := []struct {
		name       string
		statusCode int
		values     []string
	}{
		{name: "429 missing", statusCode: http.StatusTooManyRequests},
		{name: "503 repeated", statusCode: http.StatusServiceUnavailable, values: []string{"1", "2"}},
		{name: "429 malformed", statusCode: http.StatusTooManyRequests, values: []string{"later"}},
		{name: "429 negative", statusCode: http.StatusTooManyRequests, values: []string{"-1"}},
		{name: "503 over maximum", statusCode: http.StatusServiceUnavailable, values: []string{"61"}},
		{
			name:       "429 past HTTP date",
			statusCode: http.StatusTooManyRequests,
			values:     []string{now.Add(-time.Second).Format(http.TimeFormat)},
		},
		{
			name:       "503 HTTP date over maximum",
			statusCode: http.StatusServiceUnavailable,
			values:     []string{now.Add(61 * time.Second).Format(http.TimeFormat)},
		},
		{name: "other status stays rejected", statusCode: http.StatusBadGateway, values: []string{"5"}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				for _, value := range test.values {
					writer.Header().Add("Retry-After", value)
				}
				writer.WriteHeader(test.statusCode)
			}))
			t.Cleanup(server.Close)
			factory, runtime, _ := externalCMDBValidationFixture(t, server, now)
			session, err := factory.open(runtime)
			if err != nil {
				t.Fatalf("open() error = %v", err)
			}
			t.Cleanup(session.close)

			_, err = session.client.capabilities(context.Background())
			if _, ok := providerRetryAfter(err); ok || !clientErrorHasCode(err, "STATUS_REJECTED") {
				t.Fatalf("capabilities() error = %v, want STATUS_REJECTED without backoff", err)
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

func externalCMDBValidationFixture(
	t *testing.T,
	server *httptest.Server,
	now time.Time,
) (ClientFactory, discoverysource.BoundRuntime, discoverysource.ValidationRequest) {
	t.Helper()

	request := validExternalCMDBValidationRequest()
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
	return factory, runtime, request
}

func writeValidCapabilities(writer http.ResponseWriter, now time.Time) {
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
}

func writeEmptyAssetPage(writer http.ResponseWriter) {
	fmt.Fprint(writer, `{
		"items":[],
		"next_cursor":"",
		"snapshot_epoch":"snapshot-0001",
		"final_page":true,
		"complete_snapshot":true
	}`)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type errorReader struct {
	err error
}

func (reader errorReader) Read([]byte) (int, error) {
	return 0, reader.err
}

type blockingContextBody struct {
	ctx      context.Context
	read     chan struct{}
	observed *atomic.Bool
}

func (body *blockingContextBody) Read([]byte) (int, error) {
	body.observed.Store(true)
	select {
	case body.read <- struct{}{}:
	default:
	}
	<-body.ctx.Done()
	return 0, body.ctx.Err()
}

func (*blockingContextBody) Close() error {
	return nil
}
