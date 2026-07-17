package discoverycleanup

import (
	"bytes"
	"context"
	"crypto"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/securemanifest"
)

const (
	sessionTransportProtocolVersion  = "discovery-cleanup-session.v1"
	sessionTransportOpenPath         = "/discovery-cleanup/v1/session:open-or-recover"
	sessionTransportRevokePath       = "/discovery-cleanup/v1/session:revoke"
	sessionTransportRedaction        = "[REDACTED_CLEANUP_SESSION_TRANSPORT]"
	sessionLeaseRedaction            = "[REDACTED_CLEANUP_SESSION_LEASE]"
	sessionTransportOptionsRedaction = "[REDACTED_CLEANUP_SESSION_TRANSPORT_OPTIONS]"

	sessionTransportRequestLimit  = 8 << 10
	sessionTransportResponseLimit = 8 << 10
	sessionTransportSeal          = uint64(0x7a2f4c09d18e63b5)
)

var (
	ErrSessionTransportInvalid     = errors.New("cleanup session transport configuration invalid")
	ErrSessionTransportUnavailable = errors.New(
		"cleanup session transport unavailable",
	)
	ErrSessionTransportAuthentication = errors.New(
		"cleanup session transport peer authentication failed",
	)
	ErrSessionTransportDrift = errors.New(
		"cleanup session transport exact attempt drift",
	)
	ErrSessionTransportProtocol = errors.New(
		"cleanup session transport protocol rejected",
	)

	errSessionTransportRetryable = errors.New("cleanup session transport retryable failure")
	errSessionPeerIdentity       = errors.New("cleanup session transport peer identity mismatch")
)

// SessionTransportOptions contains the preconfigured, fixed authority
// connection. It is process-only even though its fields are exported for
// composition: JSON, text, binary, and formatted representations are always
// redacted.
type SessionTransportOptions struct {
	BaseURL              string
	ServerName           string
	ExpectedPeerIdentity string
	RootCAs              *x509.CertPool
	ClientCertificate    tls.Certificate
}

// SessionOpenRequest is the complete safe wire tuple. RuntimeBindingDigest is
// a digest of immutable runtime and descriptor facts, never the runtime itself.
type SessionOpenRequest struct {
	Coordinates          discoveryqueue.RunCoordinates
	Attempt              discoveryqueue.CleanupAttempt
	RuntimeBindingDigest string
}

func (request SessionOpenRequest) Validate() error {
	if !request.Coordinates.Valid() || !request.Attempt.Valid() ||
		request.Attempt.RunID != request.Coordinates.RunID ||
		!validSessionDigest(request.RuntimeBindingDigest) {
		return ErrSessionTransportInvalid
	}
	return nil
}

// SessionTransport is a fixed TLS 1.3 mutual-authentication client. It has no
// general request surface and cannot carry Provider or credential material.
type SessionTransport struct {
	self  *SessionTransport
	seal  uint64
	state *sessionTransportState
}

type sessionTransportState struct {
	mu          sync.Mutex
	baseURL     url.URL
	client      *http.Client
	transport   *http.Transport
	attempts    map[string]sessionTransportAttempt
	lifetime    context.Context
	cancel      context.CancelFunc
	operations  sync.WaitGroup
	destroyDone chan struct{}
	destroyed   bool
}

type sessionTransportAttempt struct {
	tuple   sessionTransportTuple
	receipt []byte
}

type sessionTransportTuple struct {
	tenantID             string
	workspaceID          string
	runID                string
	attemptID            string
	attemptEpoch         int64
	runtimeBindingDigest string
}

// SessionLease is an opaque, transport-issued receipt capability. Only the
// exact wrapper returned by OpenOrRecover can be used with its owning client.
type SessionLease struct {
	state *sessionLeaseState
}

type sessionLeaseState struct {
	mu         sync.Mutex
	owner      *sessionTransportState
	issued     *SessionLease
	tuple      sessionTransportTuple
	receipt    []byte
	initial    bool
	revokeDone chan struct{}
	revokeErr  error
	revoking   bool
	revoked    bool
	destroyed  bool
}

type sessionRunWire struct {
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	RunID       string `json:"run_id"`
}

type sessionOpenRequestWire struct {
	Version              string         `json:"version"`
	Run                  sessionRunWire `json:"run"`
	AttemptID            string         `json:"attempt_id"`
	AttemptEpoch         int64          `json:"attempt_epoch"`
	RuntimeBindingDigest string         `json:"runtime_binding_digest"`
}

type sessionRevokeRequestWire struct {
	Version              string         `json:"version"`
	Run                  sessionRunWire `json:"run"`
	AttemptID            string         `json:"attempt_id"`
	AttemptEpoch         int64          `json:"attempt_epoch"`
	RuntimeBindingDigest string         `json:"runtime_binding_digest"`
	Receipt              string         `json:"receipt"`
}

type sessionOpenResponseWire struct {
	Version              string         `json:"version"`
	Run                  sessionRunWire `json:"run"`
	AttemptID            string         `json:"attempt_id"`
	AttemptEpoch         int64          `json:"attempt_epoch"`
	RuntimeBindingDigest string         `json:"runtime_binding_digest"`
	Receipt              string         `json:"receipt"`
	Disposition          string         `json:"disposition"`
}

type sessionRevokeResponseWire struct {
	Version              string         `json:"version"`
	Run                  sessionRunWire `json:"run"`
	AttemptID            string         `json:"attempt_id"`
	AttemptEpoch         int64          `json:"attempt_epoch"`
	RuntimeBindingDigest string         `json:"runtime_binding_digest"`
	Receipt              string         `json:"receipt"`
	Status               string         `json:"status"`
}

type sessionProblemWire struct {
	Code string `json:"code"`
}

func NewSessionTransport(options SessionTransportOptions) (*SessionTransport, error) {
	baseURL, peerIdentity, certificate, roots, err := validateSessionTransportOptions(options)
	if err != nil {
		return nil, ErrSessionTransportInvalid
	}
	tlsConfiguration := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		RootCAs:                roots,
		ServerName:             options.ServerName,
		Certificates:           []tls.Certificate{certificate},
		NextProtos:             []string{"http/1.1"},
		SessionTicketsDisabled: true,
	}
	tlsConfiguration.VerifyConnection = func(state tls.ConnectionState) error {
		if state.Version != tls.VersionTLS13 ||
			len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return errSessionPeerIdentity
		}
		leaf := state.PeerCertificates[0]
		if leaf == nil || len(leaf.URIs) != 1 ||
			!constantTimeStringEqual(leaf.URIs[0].String(), peerIdentity) {
			return errSessionPeerIdentity
		}
		return nil
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		TLSClientConfig:        tlsConfiguration,
		TLSHandshakeTimeout:    5 * time.Second,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxConnsPerHost:        1,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
		ForceAttemptHTTP2:      false,
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	lifetime, cancel := context.WithCancel(context.Background())
	private := &sessionTransportState{
		baseURL:     baseURL,
		client:      client,
		transport:   transport,
		attempts:    make(map[string]sessionTransportAttempt),
		lifetime:    lifetime,
		cancel:      cancel,
		destroyDone: make(chan struct{}),
	}
	result := &SessionTransport{seal: sessionTransportSeal, state: private}
	result.self = result
	return result, nil
}

func (transport *SessionTransport) OpenOrRecover(
	ctx context.Context,
	request SessionOpenRequest,
) (*SessionLease, error) {
	if ctx == nil || request.Validate() != nil || !transport.authentic() {
		return nil, ErrSessionTransportInvalid
	}
	private, operationContext, release, err := transport.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	tuple := newSessionTransportTuple(request)
	if err := private.pinAttempt(tuple); err != nil {
		return nil, err
	}
	wire := tuple.openWire()
	var response sessionOpenResponseWire
	if err := private.exchange(operationContext, sessionTransportOpenPath, wire, &response); err != nil {
		return nil, transportOperationError(private, ctx, err)
	}
	if !response.matches(tuple) || !validOpaqueSessionReceipt(response.Receipt) ||
		(response.Disposition != "OPENED" && response.Disposition != "RECOVERED") {
		return nil, ErrSessionTransportDrift
	}
	if err := private.acceptReceipt(tuple, response.Receipt); err != nil {
		return nil, err
	}
	leaseState := &sessionLeaseState{
		owner: private, tuple: tuple, receipt: []byte(response.Receipt),
		initial: response.Disposition == "OPENED",
	}
	lease := &SessionLease{state: leaseState}
	leaseState.issued = lease
	return lease, nil
}

func (transport *SessionTransport) Revoke(ctx context.Context, lease *SessionLease) error {
	if ctx == nil || !transport.authentic() {
		return ErrSessionTransportInvalid
	}
	for {
		private, operationContext, release, err := transport.begin(ctx)
		if err != nil {
			return err
		}
		leaseState, done, snapshot, receipt, stateErr := authenticateSessionLease(private, lease)
		if stateErr != nil {
			release()
			return stateErr
		}
		if done != nil {
			release()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-done:
			}
			continue
		}
		if leaseState.revoked || leaseState.revokeErr != nil {
			result := leaseState.revokeErr
			leaseState.mu.Unlock()
			release()
			return result
		}
		leaseState.revoking = true
		leaseState.revokeDone = make(chan struct{})
		leaseState.mu.Unlock()

		wire := snapshot.revokeWire(string(receipt))
		var response sessionRevokeResponseWire
		exchangeErr := private.exchange(operationContext, sessionTransportRevokePath, wire, &response)
		if exchangeErr == nil && (!response.matches(snapshot, string(receipt)) ||
			response.Status != "REVOKED") {
			exchangeErr = ErrSessionTransportDrift
		}
		exchangeErr = transportOperationError(private, ctx, exchangeErr)
		clear(receipt)

		leaseState.mu.Lock()
		leaseState.revoking = false
		if exchangeErr == nil {
			leaseState.revoked = true
		} else {
			leaseState.revokeErr = exchangeErr
		}
		close(leaseState.revokeDone)
		leaseState.mu.Unlock()
		release()
		return exchangeErr
	}
}

func (lease *SessionLease) Initial() (bool, error) {
	if lease == nil || lease.state == nil {
		return false, ErrSessionTransportInvalid
	}
	private := lease.state
	private.mu.Lock()
	defer private.mu.Unlock()
	if private.destroyed || private.issued != lease || private.owner == nil ||
		len(private.receipt) == 0 {
		return false, ErrSessionTransportInvalid
	}
	return private.initial, nil
}

func (lease *SessionLease) Destroy() {
	if lease == nil || lease.state == nil {
		return
	}
	private := lease.state
	for {
		private.mu.Lock()
		if private.destroyed || private.issued != lease {
			private.mu.Unlock()
			return
		}
		if private.revoking {
			done := private.revokeDone
			private.mu.Unlock()
			<-done
			continue
		}
		private.destroyed = true
		clear(private.receipt)
		private.receipt = nil
		private.owner = nil
		private.tuple = sessionTransportTuple{}
		private.issued = nil
		private.mu.Unlock()
		return
	}
}

func (transport *SessionTransport) Destroy() {
	if !transport.authentic() {
		return
	}
	private := transport.state
	private.mu.Lock()
	if private.destroyed {
		done := private.destroyDone
		private.mu.Unlock()
		<-done
		return
	}
	private.destroyed = true
	private.cancel()
	httpTransport := private.transport
	private.mu.Unlock()
	if httpTransport != nil {
		httpTransport.CloseIdleConnections()
	}
	private.operations.Wait()

	private.mu.Lock()
	for attemptID, attempt := range private.attempts {
		clear(attempt.receipt)
		delete(private.attempts, attemptID)
	}
	private.attempts = nil
	private.baseURL = url.URL{}
	private.client = nil
	private.transport = nil
	private.mu.Unlock()
	if httpTransport != nil && httpTransport.TLSClientConfig != nil {
		for index := range httpTransport.TLSClientConfig.Certificates {
			clearTLSCertificate(&httpTransport.TLSClientConfig.Certificates[index])
		}
		httpTransport.TLSClientConfig.Certificates = nil
		httpTransport.TLSClientConfig.RootCAs = nil
		httpTransport.TLSClientConfig.VerifyConnection = nil
		httpTransport.TLSClientConfig.NextProtos = nil
	}
	close(private.destroyDone)
}

func (transport *SessionTransport) authentic() bool {
	return transport != nil && transport.self == transport &&
		transport.seal == sessionTransportSeal && transport.state != nil
}

func (transport *SessionTransport) begin(
	ctx context.Context,
) (*sessionTransportState, context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	private := transport.state
	private.mu.Lock()
	if private.destroyed || private.client == nil {
		private.mu.Unlock()
		return nil, nil, nil, ErrSessionTransportUnavailable
	}
	private.operations.Add(1)
	private.mu.Unlock()
	operationContext, unlink := linkedContext(ctx, private.lifetime)
	release := func() {
		unlink()
		private.operations.Done()
	}
	return private, operationContext, release, nil
}

func (private *sessionTransportState) pinAttempt(tuple sessionTransportTuple) error {
	private.mu.Lock()
	defer private.mu.Unlock()
	if private.destroyed {
		return ErrSessionTransportUnavailable
	}
	existing, ok := private.attempts[tuple.attemptID]
	if ok && !existing.tuple.equal(tuple) {
		return ErrSessionTransportDrift
	}
	if !ok {
		private.attempts[tuple.attemptID] = sessionTransportAttempt{tuple: tuple}
	}
	return nil
}

func (private *sessionTransportState) acceptReceipt(
	tuple sessionTransportTuple,
	receipt string,
) error {
	private.mu.Lock()
	defer private.mu.Unlock()
	if private.destroyed {
		return ErrSessionTransportUnavailable
	}
	existing, ok := private.attempts[tuple.attemptID]
	if !ok || !existing.tuple.equal(tuple) {
		return ErrSessionTransportDrift
	}
	if len(existing.receipt) != 0 &&
		subtle.ConstantTimeCompare(existing.receipt, []byte(receipt)) != 1 {
		return ErrSessionTransportDrift
	}
	clear(existing.receipt)
	existing.receipt = []byte(receipt)
	private.attempts[tuple.attemptID] = existing
	return nil
}

func (private *sessionTransportState) exchange(
	ctx context.Context,
	path string,
	value any,
	target any,
) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > sessionTransportRequestLimit {
		clear(encoded)
		return ErrSessionTransportProtocol
	}
	defer clear(encoded)
	for attempt := 0; attempt < 2; attempt++ {
		err = private.exchangeOnce(ctx, path, encoded, target)
		if !errors.Is(err, errSessionTransportRetryable) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return ErrSessionTransportUnavailable
}

func (private *sessionTransportState) exchangeOnce(
	ctx context.Context,
	path string,
	encoded []byte,
	target any,
) error {
	endpoint := private.baseURL
	endpoint.Path = path
	endpoint.RawPath, endpoint.RawQuery, endpoint.Fragment = "", "", ""
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint.String(), bytes.NewReader(encoded),
	)
	if err != nil {
		return ErrSessionTransportProtocol
	}
	request.Close = true
	request.ContentLength = int64(len(encoded))
	request.GetBody = nil
	request.Header.Set("Accept", "application/json, application/problem+json")
	request.Header.Set("Content-Type", "application/json")
	response, err := private.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if sessionAuthenticationError(err) {
			return ErrSessionTransportAuthentication
		}
		return errSessionTransportRetryable
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		if err := decodeSessionResponse(response, "application/json", target); err != nil {
			return err
		}
		return nil
	}
	var problem sessionProblemWire
	if err := decodeSessionResponse(response, "application/problem+json", &problem); err != nil ||
		problem.Code != "session_rejected" {
		return ErrSessionTransportProtocol
	}
	switch response.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrSessionTransportAuthentication
	case http.StatusConflict:
		return ErrSessionTransportDrift
	default:
		if response.StatusCode >= 500 {
			return errSessionTransportRetryable
		}
		return ErrSessionTransportProtocol
	}
}

func decodeSessionResponse(response *http.Response, contentType string, target any) error {
	if response == nil || response.Body == nil || response.ProtoMajor != 1 ||
		response.TLS == nil || response.TLS.Version != tls.VersionTLS13 ||
		len(response.Header.Values("Cache-Control")) != 1 ||
		response.Header.Get("Cache-Control") != "no-store" ||
		len(response.Header.Values("Content-Type")) != 1 ||
		response.Header.Get("Content-Type") != contentType ||
		response.Header.Get("Content-Encoding") != "" || response.Uncompressed ||
		len(response.Header.Values("X-Content-Type-Options")) != 1 ||
		response.Header.Get("X-Content-Type-Options") != "nosniff" {
		return ErrSessionTransportProtocol
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, sessionTransportResponseLimit+1))
	if err != nil ||
		(response.ContentLength >= 0 && int64(len(body)) != response.ContentLength) {
		clear(body)
		return errSessionTransportRetryable
	}
	if len(body) == 0 || len(body) > sessionTransportResponseLimit {
		clear(body)
		return ErrSessionTransportProtocol
	}
	defer clear(body)
	if securemanifest.DecodeStrict(body, target) != nil {
		return ErrSessionTransportProtocol
	}
	return nil
}

func authenticateSessionLease(
	owner *sessionTransportState,
	lease *SessionLease,
) (
	*sessionLeaseState,
	<-chan struct{},
	sessionTransportTuple,
	[]byte,
	error,
) {
	if owner == nil || lease == nil || lease.state == nil {
		return nil, nil, sessionTransportTuple{}, nil, ErrSessionTransportInvalid
	}
	private := lease.state
	private.mu.Lock()
	if private.destroyed || private.issued != lease || private.owner != owner ||
		len(private.receipt) == 0 {
		private.mu.Unlock()
		return nil, nil, sessionTransportTuple{}, nil, ErrSessionTransportInvalid
	}
	if private.revoking {
		done := private.revokeDone
		private.mu.Unlock()
		return private, done, sessionTransportTuple{}, nil, nil
	}
	return private, nil, private.tuple, bytes.Clone(private.receipt), nil
}

func newSessionTransportTuple(request SessionOpenRequest) sessionTransportTuple {
	return sessionTransportTuple{
		tenantID:             request.Coordinates.Scope.TenantID,
		workspaceID:          request.Coordinates.Scope.WorkspaceID,
		runID:                request.Coordinates.RunID,
		attemptID:            request.Attempt.AttemptID,
		attemptEpoch:         request.Attempt.AttemptEpoch,
		runtimeBindingDigest: request.RuntimeBindingDigest,
	}
}

func (tuple sessionTransportTuple) openWire() sessionOpenRequestWire {
	return sessionOpenRequestWire{
		Version: sessionTransportProtocolVersion,
		Run: sessionRunWire{
			TenantID: tuple.tenantID, WorkspaceID: tuple.workspaceID, RunID: tuple.runID,
		},
		AttemptID: tuple.attemptID, AttemptEpoch: tuple.attemptEpoch,
		RuntimeBindingDigest: tuple.runtimeBindingDigest,
	}
}

func (tuple sessionTransportTuple) revokeWire(receipt string) sessionRevokeRequestWire {
	return sessionRevokeRequestWire{
		Version: sessionTransportProtocolVersion,
		Run: sessionRunWire{
			TenantID: tuple.tenantID, WorkspaceID: tuple.workspaceID, RunID: tuple.runID,
		},
		AttemptID: tuple.attemptID, AttemptEpoch: tuple.attemptEpoch,
		RuntimeBindingDigest: tuple.runtimeBindingDigest, Receipt: receipt,
	}
}

func (tuple sessionTransportTuple) equal(other sessionTransportTuple) bool {
	return tuple.tenantID == other.tenantID &&
		tuple.workspaceID == other.workspaceID &&
		tuple.runID == other.runID &&
		tuple.attemptID == other.attemptID &&
		tuple.attemptEpoch == other.attemptEpoch &&
		constantTimeStringEqual(tuple.runtimeBindingDigest, other.runtimeBindingDigest)
}

func (response sessionOpenResponseWire) matches(tuple sessionTransportTuple) bool {
	return response.Version == sessionTransportProtocolVersion &&
		response.Run.TenantID == tuple.tenantID &&
		response.Run.WorkspaceID == tuple.workspaceID &&
		response.Run.RunID == tuple.runID &&
		response.AttemptID == tuple.attemptID &&
		response.AttemptEpoch == tuple.attemptEpoch &&
		constantTimeStringEqual(response.RuntimeBindingDigest, tuple.runtimeBindingDigest)
}

func (response sessionRevokeResponseWire) matches(
	tuple sessionTransportTuple,
	receipt string,
) bool {
	return response.Version == sessionTransportProtocolVersion &&
		response.Run.TenantID == tuple.tenantID &&
		response.Run.WorkspaceID == tuple.workspaceID &&
		response.Run.RunID == tuple.runID &&
		response.AttemptID == tuple.attemptID &&
		response.AttemptEpoch == tuple.attemptEpoch &&
		constantTimeStringEqual(response.RuntimeBindingDigest, tuple.runtimeBindingDigest) &&
		constantTimeStringEqual(response.Receipt, receipt)
}

func validateSessionTransportOptions(
	options SessionTransportOptions,
) (url.URL, string, tls.Certificate, *x509.CertPool, error) {
	parsed, err := url.Parse(options.BaseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Port() == "" ||
		parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		options.BaseURL != strings.TrimSuffix(parsed.String(), "/") {
		return url.URL{}, "", tls.Certificate{}, nil, ErrSessionTransportInvalid
	}
	if options.ServerName == "" || strings.TrimSpace(options.ServerName) != options.ServerName ||
		len(options.ServerName) > 253 || strings.ContainsAny(options.ServerName, "*:/?#") {
		return url.URL{}, "", tls.Certificate{}, nil, ErrSessionTransportInvalid
	}
	peer, err := url.Parse(options.ExpectedPeerIdentity)
	if err != nil || !validSPIFFEIdentity(peer) || peer.String() != options.ExpectedPeerIdentity {
		return url.URL{}, "", tls.Certificate{}, nil, ErrSessionTransportInvalid
	}
	if options.RootCAs == nil || len(options.RootCAs.Subjects()) == 0 {
		return url.URL{}, "", tls.Certificate{}, nil, ErrSessionTransportInvalid
	}
	roots := options.RootCAs.Clone()
	certificate, err := cloneAndValidateClientCertificate(options.ClientCertificate, roots)
	if err != nil {
		return url.URL{}, "", tls.Certificate{}, nil, ErrSessionTransportInvalid
	}
	parsed.Path = ""
	return *parsed, peer.String(), certificate, roots, nil
}

func cloneAndValidateClientCertificate(
	source tls.Certificate,
	roots *x509.CertPool,
) (tls.Certificate, error) {
	if len(source.Certificate) == 0 || source.PrivateKey == nil || roots == nil {
		return tls.Certificate{}, ErrSessionTransportInvalid
	}
	leaf, err := x509.ParseCertificate(source.Certificate[0])
	if err != nil || len(leaf.URIs) != 1 || !validSPIFFEIdentity(leaf.URIs[0]) {
		return tls.Certificate{}, ErrSessionTransportInvalid
	}
	signer, ok := source.PrivateKey.(crypto.Signer)
	if !ok || signer.Public() == nil {
		return tls.Certificate{}, ErrSessionTransportInvalid
	}
	leafPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return tls.Certificate{}, ErrSessionTransportInvalid
	}
	signerPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || subtle.ConstantTimeCompare(leafPublic, signerPublic) != 1 {
		return tls.Certificate{}, ErrSessionTransportInvalid
	}
	intermediates := x509.NewCertPool()
	for _, encoded := range source.Certificate[1:] {
		certificate, parseErr := x509.ParseCertificate(encoded)
		if parseErr != nil {
			return tls.Certificate{}, ErrSessionTransportInvalid
		}
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return tls.Certificate{}, ErrSessionTransportInvalid
	}
	result := tls.Certificate{
		Certificate:                 make([][]byte, len(source.Certificate)),
		PrivateKey:                  source.PrivateKey,
		OCSPStaple:                  bytes.Clone(source.OCSPStaple),
		SignedCertificateTimestamps: make([][]byte, len(source.SignedCertificateTimestamps)),
		Leaf:                        leaf,
	}
	for index := range source.Certificate {
		result.Certificate[index] = bytes.Clone(source.Certificate[index])
	}
	for index := range source.SignedCertificateTimestamps {
		result.SignedCertificateTimestamps[index] =
			bytes.Clone(source.SignedCertificateTimestamps[index])
	}
	return result, nil
}

func clearTLSCertificate(certificate *tls.Certificate) {
	if certificate == nil {
		return
	}
	for index := range certificate.Certificate {
		clear(certificate.Certificate[index])
		certificate.Certificate[index] = nil
	}
	clear(certificate.OCSPStaple)
	for index := range certificate.SignedCertificateTimestamps {
		clear(certificate.SignedCertificateTimestamps[index])
		certificate.SignedCertificateTimestamps[index] = nil
	}
	certificate.Certificate = nil
	certificate.PrivateKey = nil
	certificate.OCSPStaple = nil
	certificate.SignedCertificateTimestamps = nil
	certificate.Leaf = nil
}

func validSPIFFEIdentity(identity *url.URL) bool {
	return identity != nil && identity.Scheme == "spiffe" && identity.Host != "" &&
		identity.User == nil && identity.Path != "" && identity.Path != "/" &&
		strings.HasPrefix(identity.Path, "/") && identity.RawPath == "" &&
		identity.RawQuery == "" && identity.Fragment == "" &&
		!strings.Contains(identity.Path, "//") && strings.TrimSpace(identity.String()) == identity.String()
}

func validSessionDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	clear(decoded)
	return err == nil
}

func validOpaqueSessionReceipt(value string) bool {
	if len(value) < 32 || len(value) > 256 {
		return false
	}
	for _, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("._~-", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func constantTimeStringEqual(left, right string) bool {
	return len(left) == len(right) &&
		subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func sessionAuthenticationError(err error) bool {
	if errors.Is(err, errSessionPeerIdentity) {
		return true
	}
	var certificateError *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	return errors.As(err, &certificateError) ||
		errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostnameError)
}

func transportOperationError(
	private *sessionTransportState,
	caller context.Context,
	err error,
) error {
	if err == nil {
		return nil
	}
	private.mu.Lock()
	destroyed := private.destroyed
	private.mu.Unlock()
	if destroyed {
		return ErrSessionTransportUnavailable
	}
	if caller != nil && caller.Err() != nil {
		return caller.Err()
	}
	switch {
	case errors.Is(err, ErrSessionTransportAuthentication):
		return ErrSessionTransportAuthentication
	case errors.Is(err, ErrSessionTransportDrift):
		return ErrSessionTransportDrift
	case errors.Is(err, ErrSessionTransportProtocol):
		return ErrSessionTransportProtocol
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return ErrSessionTransportUnavailable
	}
}

func (SessionTransportOptions) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*SessionTransportOptions) UnmarshalJSON([]byte) error {
	return ErrSensitiveSerialization
}
func (SessionTransportOptions) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*SessionTransportOptions) UnmarshalText([]byte) error {
	return ErrSensitiveSerialization
}
func (SessionTransportOptions) MarshalBinary() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*SessionTransportOptions) UnmarshalBinary([]byte) error {
	return ErrSensitiveSerialization
}
func (SessionTransportOptions) String() string   { return sessionTransportOptionsRedaction }
func (SessionTransportOptions) GoString() string { return sessionTransportOptionsRedaction }
func (SessionTransportOptions) LogValue() slog.Value {
	return slog.StringValue(sessionTransportOptionsRedaction)
}
func (SessionTransportOptions) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, sessionTransportOptionsRedaction)
}

func (SessionTransport) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*SessionTransport) UnmarshalJSON([]byte) error { return ErrSensitiveSerialization }
func (SessionTransport) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*SessionTransport) UnmarshalText([]byte) error { return ErrSensitiveSerialization }
func (SessionTransport) MarshalBinary() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*SessionTransport) UnmarshalBinary([]byte) error { return ErrSensitiveSerialization }
func (SessionTransport) String() string                { return sessionTransportRedaction }
func (SessionTransport) GoString() string              { return sessionTransportRedaction }
func (SessionTransport) LogValue() slog.Value {
	return slog.StringValue(sessionTransportRedaction)
}
func (SessionTransport) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, sessionTransportRedaction)
}

func (SessionLease) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*SessionLease) UnmarshalJSON([]byte) error { return ErrSensitiveSerialization }
func (SessionLease) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*SessionLease) UnmarshalText([]byte) error { return ErrSensitiveSerialization }
func (SessionLease) MarshalBinary() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*SessionLease) UnmarshalBinary([]byte) error { return ErrSensitiveSerialization }
func (SessionLease) String() string                { return sessionLeaseRedaction }
func (SessionLease) GoString() string              { return sessionLeaseRedaction }
func (SessionLease) LogValue() slog.Value          { return slog.StringValue(sessionLeaseRedaction) }
func (SessionLease) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, sessionLeaseRedaction)
}
