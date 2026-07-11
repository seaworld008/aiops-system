package runnerclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/seaworld008/aiops-system/internal/runnergateway"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
)

const (
	defaultResponseLimit = int64(64 << 10)
	requestTimeout       = 30 * time.Second
)

var (
	runnerInstancePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`)
	problemTypePattern        = regexp.MustCompile(`^urn:aiops:problem:runner:[a-z0-9]+(?:-[a-z0-9]+)*$`)
	problemCodePattern        = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)
	subjectAlternativeNameOID = asn1.ObjectIdentifier{2, 5, 29, 17}
)

type problemWire struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Code     string `json:"code"`
	Detail   string `json:"detail"`
	Instance string `json:"instance"`
}

type Client struct {
	baseURL             url.URL
	httpClient          *http.Client
	expectedPool        runneridentity.Pool
	runnerInstance      string
	certificateSHA256   string
	certificateNotAfter time.Time
}

func (*Client) String() string { return "RunnerGatewayClient{Security:[REDACTED]}" }

func (client *Client) GoString() string { return client.String() }

func (client *Client) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, client.String())
}

func (*Client) MarshalJSON() ([]byte, error) { return marshalRedacted() }

func (*Client) UnmarshalJSON([]byte) error { return ErrInvalidConfiguration }

func New(options Options) (*Client, error) {
	baseURL, err := parseBaseURL(options.BaseURL)
	if err != nil || !options.ExpectedPool.Valid() || !validServerName(options.ServerName) || !validTrustDomain(options.TrustDomain) {
		return nil, ErrInvalidConfiguration
	}
	rootPEM, certificatePEM, privateKeyPEM, err := loadTrustFiles(options)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	defer clear(rootPEM)
	defer clear(certificatePEM)
	defer clear(privateKeyPEM)

	rootPool, err := parseRootPool(rootPEM)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	if validateClientCertificatePEM(certificatePEM) != nil || validateClientPrivateKeyPEM(privateKeyPEM) != nil {
		return nil, ErrInvalidConfiguration
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, ErrInvalidConfiguration
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	instance, err := validateClientLeaf(leaf, options.TrustDomain, options.ExpectedPool, time.Now().UTC())
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	certificate.Leaf = leaf
	digest := sha256.Sum256(leaf.Raw)

	tlsConfiguration := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		RootCAs:                rootPool,
		ServerName:             options.ServerName,
		Certificates:           []tls.Certificate{certificate},
		NextProtos:             []string{"http/1.1"},
		InsecureSkipVerify:     false,
		SessionTicketsDisabled: true,
		Renegotiation:          tls.RenegotiateNever,
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		TLSClientConfig:       tlsConfiguration,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   8,
		MaxConnsPerHost:       16,
		DisableCompression:    true,
		TLSNextProto:          make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrRedirectRejected
		},
	}
	return &Client{
		baseURL: *baseURL, httpClient: client, expectedPool: options.ExpectedPool,
		runnerInstance: instance, certificateSHA256: hex.EncodeToString(digest[:]),
		certificateNotAfter: leaf.NotAfter.UTC(),
	}, nil
}

func (client *Client) CloseIdleConnections() {
	if client != nil && client.httpClient != nil {
		client.httpClient.CloseIdleConnections()
	}
}

func (client *Client) Identity(ctx context.Context) (Identity, error) {
	if client == nil || client.httpClient == nil || ctx == nil {
		return Identity{}, ErrInvalidConfiguration
	}
	request, err := client.newRequest(ctx, http.MethodGet, "/runner/v1/identity", nil)
	if err != nil {
		return Identity{}, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return Identity{}, boundedTransportError(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Identity{}, decodeProblem(response)
	}
	var wire runnergateway.RunnerIdentityResponse
	if err := decodeJSONResponse(response, defaultResponseLimit, &wire); err != nil {
		return Identity{}, err
	}
	identity := Identity{
		RunnerID: wire.RunnerID, Pool: runneridentity.Pool(wire.Pool), ScopeRevision: wire.ScopeRevision.Int64(),
		MaxConcurrency: wire.MaxConcurrency, Capabilities: slices.Clone(wire.Capabilities),
		CertificateSHA256: wire.CertificateSHA256, CertificateNotAfter: wire.CertificateNotAfter.UTC(),
	}
	if !client.validIdentity(identity) {
		return Identity{}, ErrInvalidResponse
	}
	return identity, nil
}

func (client *Client) validIdentity(identity Identity) bool {
	if !identifierPattern.MatchString(identity.RunnerID) || identity.Pool != client.expectedPool || identity.ScopeRevision <= 0 ||
		identity.MaxConcurrency < 1 || identity.MaxConcurrency > 1024 ||
		identity.CertificateSHA256 != client.certificateSHA256 ||
		!identity.CertificateNotAfter.Equal(client.certificateNotAfter) || identity.Capabilities == nil {
		return false
	}
	if identity.Pool == runneridentity.PoolRead {
		return len(identity.Capabilities) == 0
	}
	return len(identity.Capabilities) == 0 || len(identity.Capabilities) == 1 && identity.Capabilities[0] == "CREDENTIAL_REVOCATION"
}

func (client *Client) newRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	if client == nil || client.httpClient == nil || ctx == nil || !strings.HasPrefix(path, "/runner/v1/") ||
		strings.ContainsAny(path, "?#%") {
		return nil, ErrInvalidConfiguration
	}
	endpoint := client.baseURL
	endpoint.Path = path
	var reader io.Reader
	var requestBody *zeroingBody
	if body != nil {
		requestBody = &zeroingBody{data: bytes.Clone(body)}
		reader = requestBody
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	request.Header.Set("Accept", "application/json, application/problem+json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
		request.ContentLength = int64(len(body))
	}
	return request, nil
}

func decodeJSONResponse(response *http.Response, limit int64, target any) error {
	if err := validateResponseBoundary(response, "application/json"); err != nil {
		return err
	}
	body, err := readBoundedBody(response.Body, limit)
	if err != nil {
		return err
	}
	defer clear(body)
	if !validStrictJSONDocument(body) {
		return ErrInvalidResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalidResponse
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return ErrInvalidResponse
	}
	return nil
}

func validateResponseBoundary(response *http.Response, contentType string) error {
	if response == nil || response.Body == nil || response.ProtoMajor != 1 || response.TLS == nil ||
		response.TLS.Version != tls.VersionTLS13 || len(response.Header.Values("Cache-Control")) != 1 ||
		response.Header.Get("Cache-Control") != "no-store" || len(response.Header.Values("Content-Type")) != 1 ||
		response.Header.Get("Content-Type") != contentType || response.Header.Get("Content-Encoding") != "" ||
		len(response.Header.Values("X-Content-Type-Options")) != 1 || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		return ErrInvalidResponse
	}
	return nil
}

func readBoundedBody(body io.Reader, limit int64) ([]byte, error) {
	if body == nil || limit <= 0 {
		return nil, ErrInvalidResponse
	}
	contents, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil || len(contents) == 0 || int64(len(contents)) > limit {
		clear(contents)
		return nil, ErrInvalidResponse
	}
	return contents, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrInvalidResponse
	}
	return nil
}

func decodeProblem(response *http.Response) error {
	if response == nil {
		return ErrInvalidResponse
	}
	if err := validateResponseBoundary(response, "application/problem+json"); err != nil {
		return err
	}
	body, err := readBoundedBody(response.Body, defaultResponseLimit)
	if err != nil {
		return ErrInvalidResponse
	}
	defer clear(body)
	if !validStrictJSONDocument(body) {
		return ErrInvalidResponse
	}
	var wire problemWire
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || ensureJSONEOF(decoder) != nil || !validProblemWire(wire, response.StatusCode) {
		return ErrInvalidResponse
	}
	return &ProblemError{Type: wire.Type, Title: wire.Title, Status: wire.Status, Code: wire.Code, Instance: wire.Instance}
}

func validProblemWire(wire problemWire, status int) bool {
	instanceID := strings.TrimPrefix(wire.Instance, "urn:aiops:request:")
	return wire.Status == status && wire.Status >= 400 && wire.Status <= 599 &&
		problemTypePattern.MatchString(wire.Type) && problemCodePattern.MatchString(wire.Code) &&
		validProblemText(wire.Title, 256) && validProblemText(wire.Detail, 1024) &&
		wire.Instance == "urn:aiops:request:"+instanceID && uuidPattern.MatchString(instanceID)
}

func validProblemText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func boundedTransportError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return fmt.Errorf("Runner Gateway transport failed")
}

func parseBaseURL(raw string) (*url.URL, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.Contains(raw, "*") {
		return nil, ErrInvalidConfiguration
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || parsed.ForceQuery ||
		(parsed.Path != "" && parsed.Path != "/") || strings.ContainsAny(parsed.Host, "\\%") {
		return nil, ErrInvalidConfiguration
	}
	port := parsed.Port()
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 || strconv.Itoa(portNumber) != port ||
		parsed.Host != net.JoinHostPort(parsed.Hostname(), port) {
		return nil, ErrInvalidConfiguration
	}
	parsed.Path = ""
	return parsed, nil
}

func validServerName(value string) bool {
	if value == "" || len(value) > 253 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "*/\\%") {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func parseRootPool(contents []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	count := 0
	seen := make(map[[sha256.Size]byte]struct{})
	for len(contents) > 0 {
		if !bytes.HasPrefix(contents, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrInvalidConfiguration
		}
		block, rest := pem.Decode(contents)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) >= len(contents) {
			return nil, ErrInvalidConfiguration
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		digest := sha256.Sum256(certificate.Raw)
		_, duplicate := seen[digest]
		if err != nil || duplicate || !certificate.IsCA || !certificate.BasicConstraintsValid ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 || certificate.CheckSignatureFrom(certificate) != nil {
			return nil, ErrInvalidConfiguration
		}
		seen[digest] = struct{}{}
		pool.AddCert(certificate)
		count++
		contents = rest
	}
	if count == 0 {
		return nil, ErrInvalidConfiguration
	}
	return pool, nil
}

func validateClientCertificatePEM(contents []byte) error {
	seen := make(map[[sha256.Size]byte]struct{})
	count := 0
	for len(contents) > 0 {
		if !bytes.HasPrefix(contents, []byte("-----BEGIN CERTIFICATE-----")) {
			return ErrInvalidConfiguration
		}
		block, rest := pem.Decode(contents)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) >= len(contents) {
			return ErrInvalidConfiguration
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		digest := sha256.Sum256(block.Bytes)
		_, duplicate := seen[digest]
		if err != nil || duplicate {
			return ErrInvalidConfiguration
		}
		if count == 0 {
			if certificate.IsCA {
				return ErrInvalidConfiguration
			}
		} else if !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return ErrInvalidConfiguration
		}
		seen[digest] = struct{}{}
		count++
		if count > 16 {
			return ErrInvalidConfiguration
		}
		contents = rest
	}
	if count == 0 {
		return ErrInvalidConfiguration
	}
	return nil
}

func validateClientPrivateKeyPEM(contents []byte) error {
	if !bytes.HasPrefix(contents, []byte("-----BEGIN PRIVATE KEY-----")) {
		return ErrInvalidConfiguration
	}
	block, rest := pem.Decode(contents)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return ErrInvalidConfiguration
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return ErrInvalidConfiguration
	}
	signer, ok := key.(crypto.Signer)
	if !ok || signer.Public() == nil {
		return ErrInvalidConfiguration
	}
	return nil
}

func validateClientLeaf(certificate *x509.Certificate, trustDomain string, pool runneridentity.Pool, now time.Time) (string, error) {
	if certificate == nil || certificate.IsCA || !certificate.BasicConstraintsValid ||
		certificate.KeyUsage != x509.KeyUsageDigitalSignature || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) ||
		len(certificate.URIs) != 1 || len(certificate.DNSNames) != 0 || len(certificate.IPAddresses) != 0 || len(certificate.EmailAddresses) != 0 ||
		len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		len(certificate.UnknownExtKeyUsage) != 0 || !validTrustDomain(trustDomain) {
		return "", ErrInvalidConfiguration
	}
	identity := certificate.URIs[0]
	rawIdentity, ok := singleClientURISAN(certificate)
	if identity == nil || identity.Scheme != "spiffe" || identity.Host != trustDomain || identity.User != nil || identity.Port() != "" ||
		identity.RawQuery != "" || identity.Fragment != "" || identity.RawPath != "" || identity.ForceQuery ||
		!ok || identity.String() != rawIdentity {
		return "", ErrInvalidConfiguration
	}
	segment := "read"
	if pool == runneridentity.PoolWrite {
		segment = "write"
	}
	prefix := "/runner/" + segment + "/"
	if !strings.HasPrefix(identity.Path, prefix) || strings.Count(identity.Path, "/") != 3 {
		return "", ErrInvalidConfiguration
	}
	instance := strings.TrimPrefix(identity.Path, prefix)
	if !runnerInstancePattern.MatchString(instance) || identity.String() != "spiffe://"+trustDomain+prefix+instance {
		return "", ErrInvalidConfiguration
	}
	return instance, nil
}

func singleClientURISAN(certificate *x509.Certificate) (string, bool) {
	if certificate == nil {
		return "", false
	}
	var encoded []byte
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(subjectAlternativeNameOID) {
			continue
		}
		if encoded != nil {
			return "", false
		}
		encoded = extension.Value
	}
	if len(encoded) == 0 {
		return "", false
	}
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(encoded, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return "", false
	}
	var name asn1.RawValue
	rest, err = asn1.Unmarshal(sequence.Bytes, &name)
	if err != nil || len(rest) != 0 || name.Class != asn1.ClassContextSpecific || name.Tag != 6 || name.IsCompound || len(name.Bytes) == 0 {
		return "", false
	}
	for _, character := range name.Bytes {
		if character < 0x21 || character > 0x7e {
			return "", false
		}
	}
	return string(name.Bytes), true
}

func validTrustDomain(value string) bool {
	if len(value) < 1 || len(value) > 255 || value != strings.ToLower(value) || strings.ContainsAny(value, ":/@%") || net.ParseIP(value) != nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

type zeroingBody struct {
	mu     sync.Mutex
	data   []byte
	offset int
}

func (body *zeroingBody) Read(destination []byte) (int, error) {
	if body == nil {
		return 0, io.EOF
	}
	body.mu.Lock()
	defer body.mu.Unlock()
	if body.offset >= len(body.data) {
		return 0, io.EOF
	}
	read := copy(destination, body.data[body.offset:])
	body.offset += read
	return read, nil
}

func (body *zeroingBody) Close() error {
	if body == nil {
		return nil
	}
	body.mu.Lock()
	clear(body.data)
	body.data = nil
	body.offset = 0
	body.mu.Unlock()
	return nil
}
