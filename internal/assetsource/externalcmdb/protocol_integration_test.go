package externalcmdb

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

func TestProtocolIntegrationFixedMTLSWire(t *testing.T) {
	t.Parallel()

	fixtures := externalCMDBFixtures{
		capabilities: loadExternalCMDBFixture(t, "capabilities.json"),
		assetPage1:   loadExternalCMDBFixture(t, "assets-page-1.json"),
		assetPage2:   loadExternalCMDBFixture(t, "assets-page-2.json"),
		relations:    loadExternalCMDBFixture(t, "relations.json"),
	}
	var mu sync.Mutex
	var requests []string
	var violations []string
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests = append(requests, request.URL.RequestURI())
		if request.TLS == nil || request.TLS.Version != tls.VersionTLS13 ||
			len(request.TLS.PeerCertificates) < 1 ||
			request.ProtoMajor != 1 && request.ProtoMajor != 2 {
			violations = append(violations, "TLS/mTLS/protocol")
		}
		if request.Method != http.MethodGet || request.ContentLength != 0 ||
			request.Header.Get("Accept") != catalogContentType ||
			request.Header.Get("Authorization") != "Bearer test-bearer-token" {
			violations = append(violations, "method/body/fixed headers")
		}
		for header := range request.Header {
			if !slices.Contains([]string{"Accept", "Authorization", "User-Agent"}, header) {
				violations = append(violations, "unexpected header "+header)
			}
		}

		writer.Header().Set("Content-Type", catalogContentType)
		switch request.URL.RequestURI() {
		case capabilitiesPath:
			_, _ = writer.Write(fixtures.capabilities)
		case assetsPath + "?limit=500":
			_, _ = writer.Write(fixtures.assetPage1)
		case assetsPath + "?cursor=asset-cursor-0002&limit=500":
			_, _ = writer.Write(fixtures.assetPage2)
		case relationsPath + "?limit=2000":
			_, _ = writer.Write(fixtures.relations)
		default:
			http.NotFound(writer, request)
		}
	})
	server, clientTLS := newCatalogMTLSServer(t, handler)

	contractProvider, boundRuntime, request := newMTLSDiscoveryProviderFixture(t, server, clientTLS)
	first := requireDiscoverPage(t, contractProvider, boundRuntime, request)
	request.Checkpoint = first.NextCheckpoint.Clone()
	second := requireDiscoverPage(t, contractProvider, boundRuntime, request)
	request.Checkpoint = second.NextCheckpoint.Clone()
	third := requireDiscoverPage(t, contractProvider, boundRuntime, request)
	if !third.FinalPage || !third.CompleteSnapshot {
		t.Fatalf("terminal page = %#v", third)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{
		capabilitiesPath,
		assetsPath + "?limit=500",
		assetsPath + "?cursor=asset-cursor-0002&limit=500",
		relationsPath + "?limit=2000",
	}
	if fmt.Sprint(requests) != fmt.Sprint(want) || len(violations) != 0 {
		t.Fatalf("wire requests=%v violations=%v, want %v", requests, violations, want)
	}
}

func newCatalogMTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, *tls.Config) {
	t.Helper()

	now := time.Now().UTC()
	caCertificate, caKey := issueTestCertificateAuthority(t, now)
	serverCertificate := issueTestLeafCertificate(
		t, now, caCertificate, caKey, 2, "external-cmdb-server",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	)
	clientCertificate := issueTestLeafCertificate(
		t, now, caCertificate, caKey, 3, "discovery-worker-client",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)

	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse mTLS server URL: %v", err)
	}
	return server, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		ServerName:   parsed.Hostname(),
		Certificates: []tls.Certificate{clientCertificate},
	}
}

func issueTestCertificateAuthority(
	t *testing.T,
	now time.Time,
) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "external-cmdb-test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return certificate, privateKey
}

func issueTestLeafCertificate(
	t *testing.T,
	now time.Time,
	ca *x509.Certificate,
	caKey ed25519.PrivateKey,
	serial int64,
	commonName string,
	usage []x509.ExtKeyUsage,
) tls.Certificate {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usage,
	}
	if slices.Contains(usage, x509.ExtKeyUsageServerAuth) {
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, ca.Raw},
		PrivateKey:  privateKey,
	}
}

func newMTLSDiscoveryProviderFixture(
	t *testing.T,
	server *httptest.Server,
	clientTLS *tls.Config,
) (discoverysource.Provider, discoverysource.BoundRuntime, discoverysource.DiscoverRequest) {
	t.Helper()

	checkpoint, err := discoverysource.NewCheckpoint(profileCode, nil)
	if err != nil {
		t.Fatalf("NewCheckpoint() error = %v", err)
	}
	request := discoverysource.DiscoverRequest{
		Locator: assetcatalog.SourceLocator{
			Scope: assetcatalog.SourceScope{
				TenantID:    "11111111-1111-4111-8111-111111111111",
				WorkspaceID: "22222222-2222-4222-8222-222222222222",
			},
			SourceID: "33333333-3333-4333-8333-333333333333",
		},
		SourceRevision:       18,
		SourceRevisionDigest: strings.Repeat("a", 64),
		Checkpoint:           checkpoint,
		Limits: discoverysource.Limits{
			MaxPageItems:     assetPageLimit,
			MaxPageRelations: relationPageLimit,
			MaxPageBytes:     maxPageBodyBytes,
			MaxDocumentBytes: 64 << 10,
		},
	}
	binding := discoverysource.RuntimeBinding{
		Locator:              request.Locator,
		SourceRevision:       request.SourceRevision,
		SourceRevisionDigest: request.SourceRevisionDigest,
		RevisionStatus:       assetcatalog.SourceRevisionPublished,
		ProviderKind:         providerKind,
		ProfileCode:          profileCode,
	}
	material := RuntimeMaterial{
		BaseURL:             server.URL,
		TLSConfig:           clientTLS,
		BearerToken:         []byte("test-bearer-token"),
		ExpectedAuthorityID: "cmdb-production-01",
		EnvironmentID:       discoverTestEnvironmentID,
	}
	boundRuntime, err := discoverysource.BindRuntime(
		binding,
		&material,
		func(*RuntimeMaterial) error { return nil },
		func(value *RuntimeMaterial) { value.Clear() },
	)
	if err != nil {
		t.Fatalf("BindRuntime() error = %v", err)
	}
	t.Cleanup(func() { _ = boundRuntime.Close() })

	factory, err := NewClientFactory(binding)
	if err != nil {
		t.Fatalf("NewClientFactory() error = %v", err)
	}
	factory.now = func() time.Time {
		return time.Date(2026, time.July, 17, 9, 30, 0, 0, time.UTC)
	}
	contractProvider, err := New(factory)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return contractProvider, boundRuntime, request
}
