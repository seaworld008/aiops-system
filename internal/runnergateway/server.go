package runnergateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	gatewayReadHeaderTimeout = 5 * time.Second
	gatewayReadTimeout       = 15 * time.Second
	gatewayWriteTimeout      = 30 * time.Second
	gatewayIdleTimeout       = 60 * time.Second
	gatewayMaxHeaderBytes    = 16 << 10
)

// GatewayServer owns the Runner listener's transport boundary. Its HTTP
// server is deliberately private so callers cannot accidentally serve the
// Runner API over plaintext TCP or enable a second protocol stack.
type GatewayServer struct {
	httpServer *http.Server
	tlsConfig  *tls.Config
}

// NewGatewayServer accepts only the fail-closed TLS shape produced by the
// Runner identity verifier. The configuration is cloned before it is retained
// so later caller mutation cannot weaken a running listener.
func NewGatewayServer(address string, handler http.Handler, configuration *tls.Config) (*GatewayServer, error) {
	if !validGatewayAddress(address) || nilInterface(handler) || !validGatewayTLSConfig(configuration) {
		return nil, fmt.Errorf("invalid Runner Gateway server configuration")
	}
	tlsConfiguration := cloneGatewayTLSConfig(configuration)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	httpServer := &http.Server{
		Addr:                         address,
		Handler:                      handler,
		DisableGeneralOptionsHandler: true,
		TLSConfig:                    tlsConfiguration.Clone(),
		ReadHeaderTimeout:            gatewayReadHeaderTimeout,
		ReadTimeout:                  gatewayReadTimeout,
		WriteTimeout:                 gatewayWriteTimeout,
		IdleTimeout:                  gatewayIdleTimeout,
		MaxHeaderBytes:               gatewayMaxHeaderBytes,
		Protocols:                    protocols,
		// The standard server logger can include peer addresses and raw TLS
		// parser text. Authentication failures are intentionally represented
		// only by bounded protocol responses and metrics at higher layers.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	return &GatewayServer{httpServer: httpServer, tlsConfig: tlsConfiguration}, nil
}

// Serve always wraps listener in TLS inside this trust-boundary type. Load
// balancers in front of it must therefore use TCP passthrough.
func (server *GatewayServer) Serve(listener net.Listener) error {
	if server == nil || server.httpServer == nil || server.tlsConfig == nil || nilInterface(listener) {
		return fmt.Errorf("invalid Runner Gateway listener")
	}
	return server.httpServer.Serve(tls.NewListener(listener, server.tlsConfig.Clone()))
}

func (server *GatewayServer) Shutdown(ctx context.Context) error {
	if server == nil || server.httpServer == nil || ctx == nil {
		return fmt.Errorf("invalid Runner Gateway shutdown")
	}
	return server.httpServer.Shutdown(ctx)
}

func validGatewayAddress(value string) bool {
	if value == "" || len(value) > 512 || strings.TrimSpace(value) != value {
		return false
	}
	_, portText, err := net.SplitHostPort(value)
	if err != nil || portText == "" {
		return false
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port >= 1 && port <= 65535 && strconv.Itoa(port) == portText
}

func validGatewayTLSConfig(configuration *tls.Config) bool {
	return configuration != nil && configuration.MinVersion == tls.VersionTLS13 &&
		configuration.MaxVersion == tls.VersionTLS13 &&
		configuration.ClientAuth == tls.RequireAndVerifyClientCert &&
		configuration.ClientCAs != nil && len(configuration.ClientCAs.Subjects()) > 0 &&
		len(configuration.Certificates) == 1 && configuration.GetCertificate == nil &&
		configuration.GetConfigForClient == nil && configuration.VerifyConnection != nil &&
		!configuration.InsecureSkipVerify && configuration.KeyLogWriter == nil &&
		configuration.NameToCertificate == nil && len(configuration.CipherSuites) == 0 && len(configuration.CurvePreferences) == 0 &&
		configuration.SessionTicketsDisabled && configuration.Renegotiation == tls.RenegotiateNever &&
		len(configuration.NextProtos) == 1 && configuration.NextProtos[0] == "http/1.1"
}

func cloneGatewayTLSConfig(configuration *tls.Config) *tls.Config {
	cloned := configuration.Clone()
	cloned.NextProtos = append([]string(nil), configuration.NextProtos...)
	cloned.ClientCAs = configuration.ClientCAs.Clone()
	cloned.Certificates = make([]tls.Certificate, len(configuration.Certificates))
	for index, certificate := range configuration.Certificates {
		clonedCertificate := certificate
		clonedCertificate.Certificate = make([][]byte, len(certificate.Certificate))
		for chainIndex, encoded := range certificate.Certificate {
			clonedCertificate.Certificate[chainIndex] = bytes.Clone(encoded)
		}
		clonedCertificate.OCSPStaple = bytes.Clone(certificate.OCSPStaple)
		clonedCertificate.SignedCertificateTimestamps = make([][]byte, len(certificate.SignedCertificateTimestamps))
		for timestampIndex, timestamp := range certificate.SignedCertificateTimestamps {
			clonedCertificate.SignedCertificateTimestamps[timestampIndex] = bytes.Clone(timestamp)
		}
		cloned.Certificates[index] = clonedCertificate
	}
	return cloned
}
