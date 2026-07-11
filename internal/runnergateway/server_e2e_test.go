package runnergateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/runneridentity"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
)

func TestGatewayServerMTLSEndToEndReauthorizesEveryKeepAliveRequest(t *testing.T) {
	tests := []struct {
		name       string
		transition e2eAuthorizationState
	}{
		{name: "registration disabled", transition: e2eRegistrationDisabled},
		{name: "certificate revoked", transition: e2eCertificateRevoked},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGatewayE2EFixture(t)
			client, transport, dialCount := fixture.client(t, &fixture.writeClient.TLS, nil)
			t.Cleanup(transport.CloseIdleConnections)

			response := doGatewayE2ERequest(t, client, fixture.identityURL(), nil)
			if response.StatusCode != http.StatusOK || response.TLS == nil ||
				response.TLS.Version != tls.VersionTLS13 || response.TLS.NegotiatedProtocol != "http/1.1" {
				body := readGatewayE2EBody(t, response)
				t.Fatalf("first identity response status=%d tls=%#v body=%q", response.StatusCode, response.TLS, body)
			}
			body := readGatewayE2EBody(t, response)
			var identityResponse RunnerIdentityResponse
			if err := json.Unmarshal([]byte(body), &identityResponse); err != nil {
				t.Fatalf("decode first identity response: %v", err)
			}
			if identityResponse.RunnerID != "write-runner-01" || identityResponse.Pool != "WRITE" {
				t.Fatalf("first identity response = %#v", identityResponse)
			}

			fixture.backend.setAuthorizationState(test.transition)
			var reused atomic.Bool
			trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused.Store(info.Reused) }}
			response = doGatewayE2ERequest(t, client, fixture.identityURL(), trace)
			body = readGatewayE2EBody(t, response)
			if response.StatusCode != http.StatusForbidden || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("second identity response status=%d cache=%q body=%q",
					response.StatusCode, response.Header.Get("Cache-Control"), body)
			}
			if !reused.Load() || dialCount.Load() != 1 {
				t.Fatalf("second request reused=%t TCP dials=%d, want same keepalive connection", reused.Load(), dialCount.Load())
			}
			authCalls, identityCalls := fixture.backend.calls()
			if authCalls != 2 || identityCalls != 1 {
				t.Fatalf("backend calls after revocation: authenticate=%d identity=%d", authCalls, identityCalls)
			}
		})
	}
}

func TestGatewayServerMTLSEndToEndRejectsMissingAndUntrustedClientCertificates(t *testing.T) {
	fixture := newGatewayE2EFixture(t)
	tests := []struct {
		name                 string
		certificate          *tls.Certificate
		getClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	}{
		{name: "no client certificate"},
		{
			name: "untrusted client CA",
			getClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return &fixture.untrustedClient.TLS, nil
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, transport, _ := fixture.client(t, test.certificate, test.getClientCertificate)
			t.Cleanup(transport.CloseIdleConnections)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, fixture.identityURL(), nil)
			if err != nil {
				t.Fatal(err)
			}
			response, requestErr := client.Do(request)
			if requestErr == nil {
				body := readGatewayE2EBody(t, response)
				t.Fatalf("mTLS request unexpectedly reached HTTP: status=%d body=%q", response.StatusCode, body)
			}
		})
	}
	authCalls, identityCalls := fixture.backend.calls()
	if authCalls != 0 || identityCalls != 0 {
		t.Fatalf("failed TLS handshakes reached backend: authenticate=%d identity=%d", authCalls, identityCalls)
	}
}

type gatewayE2EFixture struct {
	address         string
	now             time.Time
	serverCA        *testpki.Authority
	writeClient     testpki.Certificate
	untrustedClient testpki.Certificate
	backend         *gatewayE2EBackend
}

func newGatewayE2EFixture(t *testing.T) *gatewayE2EFixture {
	t.Helper()
	now := time.Date(2040, 1, 2, 3, 4, 5, 0, time.UTC)
	readCA := mustGatewayE2EAuthority(t, "runner-read-root", now)
	writeCA := mustGatewayE2EAuthority(t, "runner-write-root", now)
	serverCA := mustGatewayE2EAuthority(t, "runner-server-root", now)
	untrustedCA := mustGatewayE2EAuthority(t, "runner-untrusted-root", now)
	serverCertificate, err := serverCA.IssueServer("runner-gateway.test", now)
	if err != nil {
		t.Fatal(err)
	}
	writeURI, err := url.Parse("spiffe://aiops.example/runner/write/write-runner-01")
	if err != nil {
		t.Fatal(err)
	}
	writeClient, err := writeCA.IssueClient(testpki.ClientOptions{URIs: []*url.URL{writeURI}}, now)
	if err != nil {
		t.Fatal(err)
	}
	untrustedClient, err := untrustedCA.IssueClient(testpki.ClientOptions{URIs: []*url.URL{writeURI}}, now)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example",
		ReadRoots:   []*x509.Certificate{readCA.Certificate},
		WriteRoots:  []*x509.Certificate{writeCA.Certificate},
		Clock:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := verifier.ServerTLSConfig(serverCertificate.TLS)
	if err != nil {
		t.Fatal(err)
	}
	backend := &gatewayE2EBackend{authorizationState: e2eAuthorized}
	handler, err := NewRouter(verifier, backend)
	if err != nil {
		t.Fatal(err)
	}
	listenContext, cancelListen := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelListen()
	listener, err := new(net.ListenConfig).Listen(listenContext, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewGatewayServer(listener.Addr().String(), handler, configuration)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(listener) }()
	t.Cleanup(func() {
		shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelShutdown()
		if err := server.Shutdown(shutdownContext); err != nil {
			t.Errorf("GatewayServer.Shutdown() error = %v", err)
		}
		select {
		case err := <-serveResult:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("GatewayServer.Serve() error = %v", err)
			}
		case <-shutdownContext.Done():
			t.Errorf("GatewayServer.Serve() did not stop: %v", shutdownContext.Err())
		}
	})
	return &gatewayE2EFixture{
		address: listener.Addr().String(), now: now, serverCA: serverCA,
		writeClient: writeClient, untrustedClient: untrustedClient, backend: backend,
	}
}

func (fixture *gatewayE2EFixture) identityURL() string {
	return "https://" + fixture.address + "/runner/v1/identity"
}

func (fixture *gatewayE2EFixture) client(
	t *testing.T,
	certificate *tls.Certificate,
	getClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error),
) (*http.Client, *http.Transport, *atomic.Int64) {
	t.Helper()
	var dialCount atomic.Int64
	dialer := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
	configuration := &tls.Config{
		RootCAs: fixture.serverCA.CertPool(), ServerName: "runner-gateway.test",
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"},
		Time: func() time.Time { return fixture.now }, GetClientCertificate: getClientCertificate,
	}
	if certificate != nil {
		configuration.Certificates = []tls.Certificate{*certificate}
	}
	transport := &http.Transport{
		Proxy: nil, TLSClientConfig: configuration, ForceAttemptHTTP2: false,
		DisableCompression: true, IdleConnTimeout: 2 * time.Second, TLSHandshakeTimeout: 2 * time.Second,
		ResponseHeaderTimeout: 2 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialCount.Add(1)
			return dialer.DialContext(ctx, network, address)
		},
	}
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}, transport, &dialCount
}

func doGatewayE2ERequest(t *testing.T, client *http.Client, target string, trace *httptrace.ClientTrace) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	if trace != nil {
		ctx = httptrace.WithClientTrace(ctx, trace)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	return response
}

func readGatewayE2EBody(t *testing.T, response *http.Response) string {
	t.Helper()
	if response == nil || response.Body == nil {
		t.Fatal("missing HTTP response body")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 128<<10))
	closeErr := response.Body.Close()
	if err != nil {
		t.Fatalf("read HTTP response: %v", err)
	}
	if closeErr != nil {
		t.Fatalf("close HTTP response: %v", closeErr)
	}
	return string(body)
}

func mustGatewayE2EAuthority(t *testing.T, name string, now time.Time) *testpki.Authority {
	t.Helper()
	authority, err := testpki.NewAuthority(name, now)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

type e2eAuthorizationState uint8

const (
	e2eAuthorized e2eAuthorizationState = iota
	e2eRegistrationDisabled
	e2eCertificateRevoked
)

type gatewayE2EBackend struct {
	mu                 sync.Mutex
	authorizationState e2eAuthorizationState
	authenticateCalls  int
	identityCalls      int
}

func (backend *gatewayE2EBackend) setAuthorizationState(state e2eAuthorizationState) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.authorizationState = state
}

func (backend *gatewayE2EBackend) calls() (authenticate, identity int) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return backend.authenticateCalls, backend.identityCalls
}

func (backend *gatewayE2EBackend) AuthenticateRequest(
	_ context.Context,
	identity runneridentity.Identity,
) (RequestPrincipal, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.authenticateCalls++
	if backend.authorizationState != e2eAuthorized {
		return nil, ErrForbidden
	}
	return &gatewayE2EPrincipal{identity: identity}, nil
}

func (backend *gatewayE2EBackend) Identity(
	_ context.Context,
	identity runneridentity.Identity,
) (RunnerIdentityResponse, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.identityCalls++
	return RunnerIdentityResponse{
		SchemaVersion: "runner-identity-response.v1", RunnerID: identity.Instance(), Pool: string(identity.Pool()),
		ScopeRevision: 1, MaxConcurrency: 1, Capabilities: []string{},
		CertificateSHA256: identity.Evidence().LeafSHA256(), CertificateNotAfter: identity.Evidence().NotAfter(),
	}, nil
}

func (*gatewayE2EBackend) LeaseJob(context.Context, runneridentity.Identity, JobLeaseRequest) (*JobLeaseResponse, error) {
	return nil, ErrUnavailable
}

func (*gatewayE2EBackend) AnchorCredential(context.Context, runneridentity.Identity, string, string, CredentialAnchorRequest) (CredentialAnchorResponse, error) {
	return CredentialAnchorResponse{}, ErrUnavailable
}

func (*gatewayE2EBackend) StartJob(context.Context, runneridentity.Identity, string, string, JobStartRequest) (JobStartResponse, error) {
	return JobStartResponse{}, ErrUnavailable
}

func (*gatewayE2EBackend) HeartbeatJob(context.Context, runneridentity.Identity, string, string, JobHeartbeatRequest) (JobHeartbeatResponse, error) {
	return JobHeartbeatResponse{}, ErrUnavailable
}

func (*gatewayE2EBackend) ReleaseJob(context.Context, runneridentity.Identity, string, string, JobReleaseRequest) (JobStateResponse, error) {
	return JobStateResponse{}, ErrUnavailable
}

func (*gatewayE2EBackend) CompleteJob(context.Context, runneridentity.Identity, string, string, JobCompleteRequest) (JobCompletionResponse, error) {
	return JobCompletionResponse{}, ErrUnavailable
}

func (*gatewayE2EBackend) LeaseRevocation(context.Context, runneridentity.Identity, RevocationLeaseRequest) (*RevocationLeaseResponse, error) {
	return nil, ErrUnavailable
}

func (*gatewayE2EBackend) HeartbeatRevocation(context.Context, runneridentity.Identity, string, string, RevocationHeartbeatRequest) (RevocationHeartbeatResponse, error) {
	return RevocationHeartbeatResponse{}, ErrUnavailable
}

func (*gatewayE2EBackend) CompleteRevocation(context.Context, runneridentity.Identity, string, string, RevocationCompleteRequest) (RevocationCompletionResponse, error) {
	return RevocationCompletionResponse{}, ErrUnavailable
}

type gatewayE2EPrincipal struct {
	identity runneridentity.Identity
}

func (principal *gatewayE2EPrincipal) Valid() bool {
	return principal != nil && principal.identity.Valid()
}

func (principal *gatewayE2EPrincipal) RunnerID() string { return principal.identity.Instance() }
func (*gatewayE2EPrincipal) TenantID() string           { return "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }
func (principal *gatewayE2EPrincipal) Pool() runneridentity.Pool {
	return principal.identity.Pool()
}
func (*gatewayE2EPrincipal) ScopeRevision() int64              { return 1 }
func (*gatewayE2EPrincipal) MaxConcurrency() int               { return 1 }
func (*gatewayE2EPrincipal) CredentialRevocationCapable() bool { return false }
func (principal *gatewayE2EPrincipal) CertificateSHA256() string {
	return principal.identity.Evidence().LeafSHA256()
}
func (principal *gatewayE2EPrincipal) CertificateNotAfter() time.Time {
	return principal.identity.Evidence().NotAfter()
}
func (*gatewayE2EPrincipal) Allows(string, string) bool { return true }
