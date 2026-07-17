package vsphere

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/vim25/types"
)

func TestClientTransportDisablesProxyAndRedirectsWithExplicitTLSFloor(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:8080")

	endpoint, err := NewEndpointHandle("https://vcenter.example.invalid/sdk")
	if err != nil {
		t.Fatalf("NewEndpointHandle() error = %v", err)
	}
	tests := []struct {
		name       string
		mode       TLSCompatibility
		wantMinTLS uint16
	}{
		{name: "TLS 1.3 preferred", mode: TLSCompatibilityStrict, wantMinTLS: tls.VersionTLS13},
		{name: "reviewed vCenter TLS 1.2 floor", mode: TLSCompatibilityVCenter12, wantMinTLS: tls.VersionTLS12},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			trust, err := NewTrustHandle(&tls.Config{
				RootCAs:    nonEmptyRootPool(t),
				ServerName: "vcenter.example.invalid",
			}, test.mode)
			if err != nil {
				t.Fatalf("NewTrustHandle() error = %v", err)
			}
			client, _, err := newSOAPClient(endpoint.snapshot(), trust.snapshot(), nil)
			if err != nil {
				t.Fatalf("newSOAPClient() error = %v", err)
			}
			t.Cleanup(client.CloseIdleConnections)

			transport := client.DefaultTransport()
			if transport.Proxy != nil {
				t.Fatal("SOAP transport must not use environment proxy")
			}
			if transport.DialTLS != nil || transport.DialTLSContext != nil {
				t.Fatal("SOAP transport retained govmomi TLS dial or thumbprint fallback")
			}
			if transport.MaxConnsPerHost != maxSOAPConnections ||
				transport.MaxIdleConnsPerHost != maxSOAPConnections {
				t.Fatalf("SOAP connection budget = %d/%d", transport.MaxConnsPerHost, transport.MaxIdleConnsPerHost)
			}
			bounded, ok := client.Transport.(*boundedResponseTransport)
			if !ok || bounded.maxBytes != maxSOAPResponseBytes {
				t.Fatalf("SOAP response transport = %#v", client.Transport)
			}
			if transport.TLSClientConfig == nil ||
				transport.TLSClientConfig.InsecureSkipVerify ||
				transport.TLSClientConfig.MinVersion != test.wantMinTLS {
				t.Fatalf("TLS config = %#v", transport.TLSClientConfig)
			}
			if client.Timeout != soapCallTimeout {
				t.Fatalf("SOAP timeout = %s, want %s", client.Timeout, soapCallTimeout)
			}
			if client.CheckRedirect == nil || client.CheckRedirect(nil, nil) == nil {
				t.Fatal("SOAP redirect was accepted")
			}
		})
	}
}

func TestClientTransportRejectsKnownAndStreamedOversizeResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		contentLength int64
	}{
		{name: "known length", contentLength: 5},
		{name: "streamed length", contentLength: -1},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			closed := false
			transport := &boundedResponseTransport{
				next: roundTripFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode:    http.StatusOK,
						ContentLength: test.contentLength,
						Body: &closeTrackingBody{
							Reader: bytes.NewBufferString("12345"),
							closed: &closed,
						},
					}, nil
				}),
				maxBytes: 4,
			}
			response, err := transport.RoundTrip(&http.Request{})
			if test.contentLength > transport.maxBytes {
				if response != nil ||
					!errors.Is(err, errClientContract) ||
					!closed {
					t.Fatalf("RoundTrip() = (%#v, %v), closed=%v", response, err, closed)
				}
				return
			}
			if err != nil {
				t.Fatalf("RoundTrip() error = %v", err)
			}
			defer response.Body.Close()
			payload, err := io.ReadAll(response.Body)
			if string(payload) != "1234" ||
				!errors.Is(err, errClientContract) {
				t.Fatalf("ReadAll() = (%q, %v)", payload, err)
			}
		})
	}
}

func TestClientTransportTLSPathHonorsRequestCancellation(t *testing.T) {
	t.Parallel()

	endpoint, err := NewEndpointHandle("https://vcenter.example.invalid/sdk")
	if err != nil {
		t.Fatalf("NewEndpointHandle() error = %v", err)
	}
	trust, err := NewTrustHandle(&tls.Config{
		RootCAs:    nonEmptyRootPool(t),
		ServerName: "vcenter.example.invalid",
	}, TLSCompatibilityStrict)
	if err != nil {
		t.Fatalf("NewTrustHandle() error = %v", err)
	}
	client, _, err := newSOAPClient(endpoint.snapshot(), trust.snapshot(), nil)
	if err != nil {
		t.Fatalf("newSOAPClient() error = %v", err)
	}
	defer client.CloseIdleConnections()

	started := make(chan struct{}, 1)
	client.DefaultTransport().DialContext = func(
		ctx context.Context,
		_, _ string,
	) (net.Conn, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	requestContext, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(
		requestContext,
		http.MethodPost,
		"https://vcenter.example.invalid/sdk",
		nil,
	)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	result := make(chan error, 1)
	go func() {
		response, requestErr := client.Client.Do(request)
		if response != nil {
			_ = response.Body.Close()
		}
		result <- requestErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("fixed DialContext was not used")
	}
	cancel()
	select {
	case requestErr := <-result:
		if !errors.Is(requestErr, context.Canceled) {
			t.Fatalf("client.Do() error = %v, want context cancellation", requestErr)
		}
	case <-time.After(time.Second):
		t.Fatal("TLS dial ignored request cancellation")
	}
}

func TestTLSPeerDigestRejectsCertificateDrift(t *testing.T) {
	t.Parallel()

	first := httptest.NewTLSServer(nil)
	defer first.Close()

	var peer peerCertificateDigest
	if err := peer.set(first.Certificate()); err != nil {
		t.Fatalf("first peer set error = %v", err)
	}
	firstDigest := peer.get()
	if err := peer.set(first.Certificate()); err != nil {
		t.Fatalf("same peer set error = %v", err)
	}
	drifted := *first.Certificate()
	drifted.Raw = append(append([]byte(nil), drifted.Raw...), 0)
	if err := peer.set(&drifted); !errors.Is(err, errClientContract) {
		t.Fatalf("drifted peer set error = %v", err)
	}
	if got := peer.get(); got != firstDigest {
		t.Fatalf("peer digest changed from %q to %q", firstDigest, got)
	}
}

func TestTrustAndRuntimeRejectInsecureTLSMissingCredentialAndMalformedEndpoint(t *testing.T) {
	t.Parallel()

	if trust, err := NewTrustHandle(&tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            x509.NewCertPool(),
		ServerName:         "vcenter.example.invalid",
	}, TLSCompatibilityStrict); err == nil {
		t.Fatalf("NewTrustHandle() = %#v, want InsecureSkipVerify rejection", trust)
	}
	if endpoint, err := NewEndpointHandle("https://user:password@vcenter.example.invalid/sdk"); err == nil {
		t.Fatalf("NewEndpointHandle() = %#v, want URL userinfo rejection", endpoint)
	}
	if endpoint, err := NewEndpointHandle("https://vcenter.example.invalid/sdk?header=x"); err == nil {
		t.Fatalf("NewEndpointHandle() = %#v, want query rejection", endpoint)
	}
	if credential, err := NewCredentialHandle("svc-vsphere-read", nil); err == nil {
		t.Fatalf("NewCredentialHandle() = %#v, want missing credential rejection", credential)
	}

	endpoint, _ := NewEndpointHandle("https://vcenter.example.invalid/sdk")
	trust, _ := NewTrustHandle(&tls.Config{
		RootCAs:    nonEmptyRootPool(t),
		ServerName: "vcenter.example.invalid",
	}, TLSCompatibilityStrict)
	authority, _ := NewAuthorityHandle(
		testInstanceUUID,
		testEnvironmentID,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	if material, err := NewRuntimeMaterial(endpoint, CredentialHandle{}, trust, authority); err == nil {
		t.Fatalf("NewRuntimeMaterial() = %#v, want missing credential rejection", material)
	}
}

func TestTLS12CompatibilityDoesNotWeakenAnExplicitTLS13Minimum(t *testing.T) {
	t.Parallel()

	trust, err := NewTrustHandle(&tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    nonEmptyRootPool(t),
		ServerName: "vcenter.example.invalid",
	}, TLSCompatibilityVCenter12)
	if err != nil {
		t.Fatalf("NewTrustHandle() error = %v", err)
	}
	if got := trust.snapshot().config.MinVersion; got != tls.VersionTLS13 {
		t.Fatalf("minimum TLS version = %#x, want TLS 1.3", got)
	}
}

func TestTrustHandleRejectsTLSHooksAndOwnsPinnedRoots(t *testing.T) {
	t.Parallel()

	roots := nonEmptyRootPool(t)
	base := func() *tls.Config {
		return &tls.Config{
			RootCAs:    roots,
			ServerName: "vcenter.example.invalid",
		}
	}
	tests := []struct {
		name   string
		mutate func(*tls.Config)
	}{
		{
			name: "key log writer",
			mutate: func(config *tls.Config) {
				config.KeyLogWriter = io.Discard
			},
		},
		{
			name: "custom clock",
			mutate: func(config *tls.Config) {
				config.Time = time.Now
			},
		},
		{
			name: "custom randomness",
			mutate: func(config *tls.Config) {
				config.Rand = bytes.NewReader(make([]byte, 256))
			},
		},
		{
			name: "caller selected cipher",
			mutate: func(config *tls.Config) {
				config.CipherSuites = []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}
			},
		},
		{
			name: "client session cache",
			mutate: func(config *tls.Config) {
				config.ClientSessionCache = tls.NewLRUClientSessionCache(1)
			},
		},
		{
			name: "custom ALPN",
			mutate: func(config *tls.Config) {
				config.NextProtos = []string{"h2"}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			config := base()
			test.mutate(config)
			if trust, err := NewTrustHandle(config, TLSCompatibilityStrict); err == nil {
				t.Fatalf("NewTrustHandle() = %#v, want TLS hook rejection", trust)
			}
		})
	}

	trust, err := NewTrustHandle(base(), TLSCompatibilityStrict)
	if err != nil {
		t.Fatalf("NewTrustHandle() error = %v", err)
	}
	snapshot := trust.snapshot()
	defer snapshot.Clear()
	if snapshot.config.RootCAs == roots {
		t.Fatal("TrustHandle retained the caller-owned CertPool")
	}
}

func TestValidateRejectsWrongCAAndSNIAsTrustFailure(t *testing.T) {
	model := simulator.VPX()
	if err := model.Create(); err != nil {
		t.Fatalf("create simulator model: %v", err)
	}
	t.Cleanup(model.Remove)
	model.Service.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server := model.Service.NewServer()
	t.Cleanup(server.Close)

	endpointURL := *server.URL
	user := endpointURL.User
	endpointURL.User = nil
	if user == nil {
		t.Fatal("simulator URL has no credential")
	}
	password, ok := user.Password()
	if !ok {
		t.Fatal("simulator URL has no password")
	}
	endpoint, err := NewEndpointHandle(endpointURL.String())
	if err != nil {
		t.Fatalf("NewEndpointHandle() error = %v", err)
	}
	credential, err := NewCredentialHandle(user.Username(), []byte(password))
	if err != nil {
		t.Fatalf("NewCredentialHandle() error = %v", err)
	}
	authority, err := NewAuthorityHandle(
		model.ServiceContent.About.InstanceUuid,
		testEnvironmentID,
		[]types.ManagedObjectReference{model.RootFolder.Reference()},
	)
	if err != nil {
		t.Fatalf("NewAuthorityHandle() error = %v", err)
	}

	validRoots := x509.NewCertPool()
	validRoots.AddCert(server.Certificate())
	tests := []struct {
		name      string
		tlsConfig *tls.Config
	}{
		{
			name: "wrong CA",
			tlsConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    nonEmptyRootPool(t),
				ServerName: endpointURL.Hostname(),
			},
		},
		{
			name: "wrong SNI",
			tlsConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    validRoots,
				ServerName: "wrong-sni.example.invalid",
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			trust, err := NewTrustHandle(test.tlsConfig, TLSCompatibilityStrict)
			if err != nil {
				t.Fatalf("NewTrustHandle() error = %v", err)
			}
			material, err := NewRuntimeMaterial(endpoint, credential, trust, authority)
			if err != nil {
				t.Fatalf("NewRuntimeMaterial() error = %v", err)
			}
			request := validValidationRequest()
			binding := validatingBinding(request)
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
			provider, err := New(factory)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			proof, err := provider.Validate(context.Background(), runtime, request)
			if err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if proof.Outcome != assetcatalog.ValidationOutcomeFailed ||
				proof.Code != "VALIDATION_REJECTED" ||
				len(proof.Checks) != 1 ||
				proof.Checks[0].Kind != discoverysource.ValidationCheckTrustOrSignature ||
				proof.Checks[0].Code != "TRUST_OR_SIGNATURE_REJECTED" {
				t.Fatalf("trust failure proof = %#v", proof)
			}
			if err := discoverysource.ValidateValidationResult(request, proof, nil); err != nil {
				t.Fatalf("trust failure violates discoverysource contract: %v", err)
			}
			rendered := fmt.Sprintf("%v %#v", err, proof)
			for _, sensitive := range []string{
				endpointURL.String(),
				user.Username(),
				password,
				test.tlsConfig.ServerName,
			} {
				if sensitive != "" && strings.Contains(rendered, sensitive) {
					t.Fatalf("trust failure leaked runtime material %q: %s", sensitive, rendered)
				}
			}
		})
	}
}

func TestRuntimeMaterialCannotSerializeLogOrRetainSecretsAfterClear(t *testing.T) {
	t.Parallel()

	endpoint, err := NewEndpointHandle("https://vcenter.example.invalid/sdk")
	if err != nil {
		t.Fatalf("NewEndpointHandle() error = %v", err)
	}
	credential, err := NewCredentialHandle("svc-vsphere-read", []byte("super-secret-password"))
	if err != nil {
		t.Fatalf("NewCredentialHandle() error = %v", err)
	}
	trust, err := NewTrustHandle(&tls.Config{
		RootCAs:    nonEmptyRootPool(t),
		ServerName: "vcenter.example.invalid",
	}, TLSCompatibilityStrict)
	if err != nil {
		t.Fatalf("NewTrustHandle() error = %v", err)
	}
	authority, err := NewAuthorityHandle(
		testInstanceUUID,
		testEnvironmentID,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	if err != nil {
		t.Fatalf("NewAuthorityHandle() error = %v", err)
	}
	material, err := NewRuntimeMaterial(endpoint, credential, trust, authority)
	if err != nil {
		t.Fatalf("NewRuntimeMaterial() error = %v", err)
	}

	for name, value := range map[string]any{
		"endpoint handle":   endpoint,
		"credential handle": credential,
		"trust handle":      trust,
		"authority handle":  authority,
		"runtime material":  material,
	} {
		if _, err := json.Marshal(value); !errors.Is(err, discoverysource.ErrSensitiveSerialization) {
			t.Fatalf("json.Marshal(%s) error = %v", name, err)
		}
	}
	rendered := fmt.Sprintf(
		"%v %#v %v %#v %v %#v %v %#v %v %#v",
		endpoint, endpoint,
		credential, credential,
		trust, trust,
		authority, authority,
		material, material,
	)
	for _, sensitive := range []string{
		"vcenter.example.invalid",
		"svc-vsphere-read",
		"super-secret-password",
		testInstanceUUID,
	} {
		if strings.Contains(rendered, sensitive) {
			t.Fatalf("formatted runtime material leaked %q: %s", sensitive, rendered)
		}
	}

	material.Clear()
	if snapshot, ok := material.snapshot(); ok {
		defer snapshot.Clear()
		t.Fatalf("cleared material remained accessible: %#v", snapshot)
	}
}

func TestVCenterAdapterContainsNoForbiddenSDKMethodsOrGenericTransport(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	packageDir := filepath.Dir(currentFile)
	productionFiles := []string{"profile.go", "client.go", "validate.go", "normalize.go"}
	forbiddenSelectors := []string{
		"PowerOnVM_Task",
		"PowerOffVM_Task",
		"ReconfigVM_Task",
		"CloneVM_Task",
		"MigrateVM_Task",
		"AcquireTicket",
		"AcquireCloneTicket",
		"InitiateFileTransferToGuest",
		"InitiateFileTransferFromGuest",
		"DeleteDatastoreFile_Task",
		"MoveDatastoreFile_Task",
		"CopyDatastoreFile_Task",
		"ProxyFromEnvironment",
		"Getenv",
	}
	forbiddenImports := []string{
		"github.com/vmware/govmomi/guest",
		"github.com/vmware/govmomi/nfc",
		"github.com/vmware/govmomi/vmdk",
		"github.com/vmware/govmomi/vslm",
	}

	for _, name := range productionFiles {
		path := filepath.Join(packageDir, name)
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.AllErrors)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, spec := range file.Imports {
			importPath := strings.Trim(spec.Path.Value, `"`)
			if slices.Contains(forbiddenImports, importPath) {
				t.Errorf("%s imports forbidden SDK package %q", name, importPath)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if ok && slices.Contains(forbiddenSelectors, selector.Sel.Name) {
				t.Errorf("%s uses forbidden selector %s", name, selector.Sel.Name)
			}
			if pair, ok := node.(*ast.KeyValueExpr); ok {
				identifier, identifierOK := pair.Key.(*ast.Ident)
				literal, literalOK := pair.Value.(*ast.Ident)
				if identifierOK && literalOK &&
					identifier.Name == "InsecureSkipVerify" &&
					literal.Name == "true" {
					t.Errorf("%s enables InsecureSkipVerify", name)
				}
			}
			return true
		})
	}
}

func TestPublicRequestAndRuntimeSurfaceCannotCarryWireOverrides(t *testing.T) {
	t.Parallel()

	requestTypes := []any{
		discoverysource.ValidationRequest{},
		discoverysource.DiscoverRequest{},
	}
	for _, request := range requestTypes {
		requestType := reflect.TypeOf(request)
		for _, forbidden := range []string{
			"URL",
			"Endpoint",
			"Path",
			"Method",
			"Header",
			"Body",
			"Query",
			"Command",
			"Script",
			"SQL",
		} {
			if _, found := requestType.FieldByName(forbidden); found {
				t.Fatalf("%s exposes forbidden wire override %s", requestType.Name(), forbidden)
			}
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type closeTrackingBody struct {
	io.Reader
	closed *bool
}

func (body *closeTrackingBody) Close() error {
	*body.closed = true
	return nil
}
