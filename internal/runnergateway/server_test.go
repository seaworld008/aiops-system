package runnergateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
)

func TestNewGatewayServerPinsMTLS13HTTP1AndResourceBounds(t *testing.T) {
	configuration := gatewayServerTLSFixture()
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	server, err := NewGatewayServer("127.0.0.1:8443", handler, configuration)
	if err != nil {
		t.Fatalf("NewGatewayServer() error = %v", err)
	}
	if server == nil || server.httpServer == nil || server.tlsConfig == nil {
		t.Fatalf("NewGatewayServer() = %#v", server)
	}
	if server.httpServer.Addr != "127.0.0.1:8443" || server.httpServer.Handler == nil ||
		server.httpServer.ReadHeaderTimeout != 5*time.Second || server.httpServer.ReadTimeout != 15*time.Second ||
		server.httpServer.WriteTimeout != 30*time.Second || server.httpServer.IdleTimeout != 60*time.Second ||
		server.httpServer.MaxHeaderBytes != 16<<10 || server.httpServer.ErrorLog == nil ||
		server.httpServer.Protocols == nil || !server.httpServer.Protocols.HTTP1() ||
		server.httpServer.Protocols.HTTP2() || server.httpServer.Protocols.UnencryptedHTTP2() {
		t.Fatalf("Gateway HTTP bounds = %#v", server.httpServer)
	}
	if server.tlsConfig == configuration || server.httpServer.TLSConfig == configuration ||
		server.tlsConfig.MinVersion != tls.VersionTLS13 || server.tlsConfig.MaxVersion != tls.VersionTLS13 ||
		server.tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert || !server.tlsConfig.SessionTicketsDisabled ||
		len(server.tlsConfig.NextProtos) != 1 || server.tlsConfig.NextProtos[0] != "http/1.1" {
		t.Fatalf("Gateway TLS config = %#v", server.tlsConfig)
	}

	configuration.NextProtos[0] = "mutated"
	if server.tlsConfig.NextProtos[0] != "http/1.1" {
		t.Fatal("Gateway server retained caller-owned mutable TLS config")
	}
}

func TestNewGatewayServerRejectsEveryWeakenedTLSBoundary(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*tls.Config)
	}{
		{name: "minimum TLS", mutate: func(value *tls.Config) { value.MinVersion = tls.VersionTLS12 }},
		{name: "maximum TLS", mutate: func(value *tls.Config) { value.MaxVersion = 0 }},
		{name: "client auth", mutate: func(value *tls.Config) { value.ClientAuth = tls.VerifyClientCertIfGiven }},
		{name: "client roots", mutate: func(value *tls.Config) { value.ClientCAs = nil }},
		{name: "server certificate", mutate: func(value *tls.Config) { value.Certificates = nil }},
		{name: "session tickets", mutate: func(value *tls.Config) { value.SessionTicketsDisabled = false }},
		{name: "insecure verify", mutate: func(value *tls.Config) { value.InsecureSkipVerify = true }},
		{name: "proxy ALPN", mutate: func(value *tls.Config) { value.NextProtos = []string{"h2", "http/1.1"} }},
		{name: "dynamic config", mutate: func(value *tls.Config) {
			value.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return value, nil }
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := gatewayServerTLSFixture()
			test.mutate(configuration)
			if _, err := NewGatewayServer("127.0.0.1:8443", http.NotFoundHandler(), configuration); err == nil {
				t.Fatal("NewGatewayServer() error = nil, want fail-closed rejection")
			}
		})
	}
	for _, test := range []struct {
		name    string
		addr    string
		handler http.Handler
		tls     *tls.Config
	}{
		{name: "empty address", handler: http.NotFoundHandler(), tls: gatewayServerTLSFixture()},
		{name: "nil handler", addr: "127.0.0.1:8443", tls: gatewayServerTLSFixture()},
		{name: "nil TLS", addr: "127.0.0.1:8443", handler: http.NotFoundHandler()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewGatewayServer(test.addr, test.handler, test.tls); err == nil {
				t.Fatal("NewGatewayServer() error = nil, want fail-closed rejection")
			}
		})
	}
}

func TestGatewayServerServeWrapsTheListenerInTLSAndShutdownIsSafe(t *testing.T) {
	configuration := gatewayServerTLSFixture()
	server, err := NewGatewayServer("127.0.0.1:8443", http.NotFoundHandler(), configuration)
	if err != nil {
		t.Fatal(err)
	}
	listener := &recordingListener{accepted: make(chan struct{}), closed: make(chan struct{})}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()

	select {
	case <-listener.accepted:
	case <-time.After(time.Second):
		t.Fatal("Gateway server did not accept from the supplied listener")
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	select {
	case serveErr := <-result:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			t.Fatalf("Serve() error = %v", serveErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Gateway Serve did not stop after Shutdown")
	}
	if listener.acceptedConn == nil {
		t.Fatal("recording listener did not retain accepted connection")
	}
	if _, ok := listener.acceptedConn.(*tls.Conn); ok {
		t.Fatal("underlying listener unexpectedly observed a TLS wrapper")
	}
}

func TestGatewayServerNeverServesPlaintextHTTP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	configuration := realGatewayServerTLSFixture(t)
	var handlerCalls atomic.Int64
	server, err := NewGatewayServer(listener.Addr().String(), http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		handlerCalls.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}), configuration)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(listener) }()

	connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if _, err := connection.Write([]byte("GET /runner/v1/identity HTTP/1.1\r\nHost: gateway\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 256)
	read, readErr := connection.Read(buffer)
	_ = connection.Close()
	if readErr != nil || !strings.Contains(string(buffer[:read]), "400 Bad Request") ||
		!strings.Contains(string(buffer[:read]), "HTTPS server") || handlerCalls.Load() != 0 {
		t.Fatalf("plaintext connection read=%d error=%v body=%q handler_calls=%d",
			read, readErr, buffer[:read], handlerCalls.Load())
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if err := <-serveResult; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Serve() error = %v", err)
	}
}

func gatewayServerTLSFixture() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(&x509.Certificate{Raw: []byte("root")})
	return &tls.Config{
		Certificates:           []tls.Certificate{{Certificate: [][]byte{[]byte("server")}}},
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              pool,
		NextProtos:             []string{"http/1.1"},
		SessionTicketsDisabled: true,
		VerifyConnection:       func(tls.ConnectionState) error { return nil },
	}
}

func realGatewayServerTLSFixture(t *testing.T) *tls.Config {
	t.Helper()
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	authority, err := testpki.NewAuthority("gateway-server-test", now)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := authority.IssueServer("gateway.internal", now)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates:           []tls.Certificate{certificate.TLS},
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              authority.CertPool(),
		NextProtos:             []string{"http/1.1"},
		SessionTicketsDisabled: true,
		VerifyConnection:       func(tls.ConnectionState) error { return nil },
	}
}

type recordingListener struct {
	mu           sync.Mutex
	accepted     chan struct{}
	closed       chan struct{}
	acceptedConn net.Conn
	served       bool
}

func (listener *recordingListener) Accept() (net.Conn, error) {
	listener.mu.Lock()
	if listener.served {
		listener.mu.Unlock()
		<-listener.closed
		return nil, net.ErrClosed
	}
	listener.served = true
	client, server := net.Pipe()
	listener.acceptedConn = server
	listener.mu.Unlock()
	close(listener.accepted)
	go func() {
		<-listener.closed
		_ = client.Close()
	}()
	return server, nil
}

func (listener *recordingListener) Close() error {
	select {
	case <-listener.closed:
	default:
		close(listener.closed)
	}
	if listener.acceptedConn != nil {
		return listener.acceptedConn.Close()
	}
	return nil
}

func (*recordingListener) Addr() net.Addr { return staticAddr("recording") }

type staticAddr string

func (address staticAddr) Network() string { return "tcp" }
func (address staticAddr) String() string  { return string(address) }
