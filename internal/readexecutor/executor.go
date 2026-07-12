package readexecutor

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/readtarget"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

var (
	errTransportRejected = errors.New("READ upstream transport rejected")
	bearerPattern        = regexp.MustCompile(`^[A-Za-z0-9._~+/\-]+=*$`)
)

type executorSeal struct{ value byte }

var trustedExecutorSeal = &executorSeal{value: 1}

type lookupNetIP func(context.Context, string, string) ([]netip.Addr, error)
type dialLiteral func(context.Context, string, string) (net.Conn, error)

// valueFreeContext preserves cancellation and deadlines while preventing
// caller-installed trace hooks or request-scoped values from crossing the
// credential and network boundary.
type valueFreeContext struct{ context.Context }

func (valueFreeContext) Value(any) any { return nil }

// Executor owns only a pinned profile and fixed resolver/dial primitives. A
// fresh one-shot transport is created for every Prepared capability.
type Executor struct {
	profile *Profile
	lookup  lookupNetIP
	dial    dialLiteral
	seal    *executorSeal
	self    *Executor
}

func NewExecutor(profile *Profile) (*Executor, error) {
	resolver := &net.Resolver{PreferGo: true, StrictErrors: true}
	dialer := &net.Dialer{Timeout: DialTimeout, KeepAlive: -1, FallbackDelay: -1}
	return newExecutor(profile, resolver.LookupNetIP, dialer.DialContext)
}

func newExecutor(profile *Profile, lookup lookupNetIP, dial dialLiteral) (*Executor, error) {
	if profile == nil || !profile.Ready() || lookup == nil || dial == nil {
		return nil, ErrExecutionRejected
	}
	created := &Executor{profile: profile, lookup: lookup, dial: dial, seal: trustedExecutorSeal}
	created.self = created
	return created, nil
}

func (executor *Executor) Ready() bool {
	return executor != nil && executor.self == executor && executor.seal == trustedExecutorSeal &&
		executor.profile != nil && executor.profile.Ready() && executor.lookup != nil && executor.dial != nil
}

type preparedValues struct {
	leaseEpoch    int64
	scopeRevision int64
	execution     readconnector.ExecutionSpec
	policy        *EgressPolicy
	origin        url.URL
	tlsConfig     *tls.Config
	endpointPath  string
	credentialRef string
}

// Prepare performs no DNS, dialing or credential operation. It binds the
// persisted descriptor and current claim fence to immutable process-owned
// connector, target, egress and executor facts.
func (executor *Executor) Prepare(
	ctx context.Context,
	descriptor readtask.Descriptor,
	leaseEpoch int64,
	scopeRevision int64,
	execution readconnector.ExecutionSpec,
	target readtarget.Target,
	policy *EgressPolicy,
) (prepared *Prepared, returnedErr error) {
	defer func() {
		if recover() != nil {
			prepared = nil
			returnedErr = ErrExecutionRejected
		}
	}()
	if err := executionContextError(ctx); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, ErrExecutionRejected
	}
	if !executor.Ready() || descriptor.Validate() != nil || leaseEpoch <= 0 || scopeRevision <= 0 ||
		policy == nil || !policy.Ready() || execution.Operation() != descriptor.Operation ||
		!execution.MatchesDescriptor(descriptor) ||
		!executor.profile.Supports(execution.Kind(), execution.Operation()) || target.Kind() != execution.Kind() ||
		execution.TargetRef() == "" || execution.TargetRef() != target.TargetRef() ||
		!equalDigest(execution.ContractDigest(), descriptor.RuntimeBinding.ConnectorDigest) ||
		!equalDigest(target.Digest(), descriptor.RuntimeBinding.TargetDigest) ||
		!equalDigest(executor.profile.Digest(), descriptor.RuntimeBinding.ExecutorDigest) ||
		!referenceDigestMatches(execution.TargetRef(), target.Digest()) ||
		policy.Ref() != target.NetworkPolicyRef() ||
		!policy.matchesScope(descriptor.TenantID, descriptor.WorkspaceID, descriptor.EnvironmentID) {
		return nil, ErrExecutionRejected
	}
	endpointPath, supported := executor.profile.EndpointPath(execution.Kind(), execution.Operation())
	origin := target.OriginURL()
	tlsConfiguration := target.TLSConfig()
	if !supported || origin == nil || origin.Scheme != "https" || origin.Host == "" ||
		policy.hostname() != origin.Hostname() || strconv.Itoa(int(policy.port())) != origin.Port() ||
		!validExecutorTLSConfig(tlsConfiguration, origin.Hostname()) ||
		!validExecutionSpecShape(execution) {
		return nil, ErrExecutionRejected
	}
	created := &Prepared{
		taskID: descriptor.TaskID, seal: trustedPreparedSeal, state: &preparedState{},
		values: preparedValues{
			leaseEpoch: leaseEpoch, scopeRevision: scopeRevision, execution: execution, policy: policy,
			origin: *origin, tlsConfig: tlsConfiguration, endpointPath: endpointPath,
			credentialRef: target.CredentialRoleRef(),
		},
	}
	created.self = created
	if err := executionContextError(ctx); err != nil {
		return nil, err
	}
	return created, nil
}

// Execute consumes Prepared exactly once. Expected upstream failures are
// returned only as a bounded Result; error is reserved for invalid local use.
func (executor *Executor) Execute(
	ctx context.Context,
	prepared *Prepared,
	start *ExecutionStart,
	credentials BearerSource,
) (result Result, returnedErr error) {
	bindOutcome := false
	defer func() {
		if recover() != nil {
			if bindOutcome {
				result = bindResult(newFailureResult(readtask.FailureUnknown), start)
				returnedErr = nil
			} else {
				result = Result{}
				returnedErr = ErrExecutionRejected
			}
		}
	}()
	if !executor.Ready() || prepared == nil || !prepared.ready() || start == nil || !start.ready() ||
		credentials == nil || start.taskID != prepared.taskID {
		return Result{}, ErrExecutionRejected
	}
	contextErr := executionContextError(ctx)
	if contextErr != nil && !errors.Is(contextErr, context.Canceled) &&
		!errors.Is(contextErr, context.DeadlineExceeded) {
		return Result{}, ErrExecutionRejected
	}
	if !prepared.consume() {
		return Result{}, ErrExecutionRejected
	}
	values := prepared.values
	prepared.values = preparedValues{}
	if start.leaseEpoch != values.leaseEpoch || start.scopeRevision != values.scopeRevision {
		return Result{}, ErrExecutionRejected
	}
	bindOutcome = true
	if contextErr != nil {
		return bindResult(contextResult(contextErr), start), nil
	}
	requestContext, cancel := context.WithTimeout(valueFreeContext{Context: ctx}, RequestTimeout)
	defer cancel()
	addresses, failure := executor.resolveAddresses(requestContext, values)
	if failure != "" {
		return bindResult(newFailureResult(failure), start), nil
	}
	request, err := buildRequest(requestContext, values, start.startedAt)
	if err != nil {
		return Result{}, ErrExecutionRejected
	}
	transport := executor.newTransport(values, addresses)
	defer transport.CloseIdleConnections()
	result, failure = roundTripWithBearer(
		requestContext, transport, request, values.credentialRef,
		values.execution, start.startedAt, credentials,
	)
	if failure != "" {
		return bindResult(newFailureResult(failure), start), nil
	}
	if !result.Valid() {
		return bindResult(newFailureResult(readtask.FailureUnknown), start), nil
	}
	return bindResult(result, start), nil
}

func (executor *Executor) resolveAddresses(ctx context.Context, values preparedValues) ([]netip.Addr, readtask.FailureCode) {
	resolveContext, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()
	addresses, err := executor.lookup(resolveContext, "ip", values.origin.Hostname()+".")
	if err != nil {
		return nil, transportFailure(resolveContext, err, readtask.FailureConnectorUnavailable)
	}
	if len(addresses) == 0 || len(addresses) > MaximumDNSAnswers {
		return nil, readtask.FailureResultRejected
	}
	unique := make(map[netip.Addr]struct{}, len(addresses))
	resolved := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() || address.Zone() != "" || !values.policy.allows(address) {
			return nil, readtask.FailureResultRejected
		}
		if _, duplicate := unique[address]; duplicate {
			continue
		}
		unique[address] = struct{}{}
		resolved = append(resolved, address)
	}
	if len(resolved) == 0 || len(resolved) > MaximumDNSAnswers {
		return nil, readtask.FailureResultRejected
	}
	sort.Slice(resolved, func(left, right int) bool { return resolved[left].Compare(resolved[right]) < 0 })
	return resolved, ""
}

func (executor *Executor) newTransport(values preparedValues, addresses []netip.Addr) *http.Transport {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	var dialStarted atomic.Bool
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != values.origin.Host || !dialStarted.CompareAndSwap(false, true) {
				return nil, errTransportRejected
			}
			dialContext, cancel := context.WithTimeout(ctx, DialTimeout)
			defer cancel()
			var lastErr error
			for _, candidate := range addresses {
				literal := netip.AddrPortFrom(candidate, values.policy.port()).String()
				connection, err := executor.dial(dialContext, "tcp", literal)
				if err != nil {
					lastErr = err
					continue
				}
				if !remoteAddressMatches(connection.RemoteAddr(), candidate, values.policy.port()) {
					_ = connection.Close()
					continue
				}
				return connection, nil
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, errTransportRejected
		},
		TLSClientConfig:        values.tlsConfig.Clone(),
		TLSHandshakeTimeout:    TLSHandshakeTimeout,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxConnsPerHost:        1,
		ResponseHeaderTimeout:  ResponseHeaderTimeout,
		MaxResponseHeaderBytes: int64(MaximumResponseHeaderBytes),
		ForceAttemptHTTP2:      false,
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{},
		Protocols:              protocols,
	}
}

func buildRequest(ctx context.Context, values preparedValues, collectedAt time.Time) (*http.Request, error) {
	windowStart := collectedAt.Add(-values.execution.Lookback())
	if !validExecutionTime(collectedAt) || collectedAt.Location() != time.UTC ||
		!validExecutionTime(windowStart) || windowStart.Location() != time.UTC || !windowStart.Before(collectedAt) {
		return nil, ErrExecutionRejected
	}
	form := url.Values{}
	form.Set("start", windowStart.Format(time.RFC3339Nano))
	form.Set("end", collectedAt.Format(time.RFC3339Nano))
	form.Set("timeout", UpstreamQueryTimeout.String())
	accept := "application/json"
	switch values.execution.Kind() {
	case readconnector.KindPrometheus:
		query, ok := values.execution.PrometheusRangeQuery()
		if !ok {
			return nil, ErrExecutionRejected
		}
		form.Set("query", query.Expression())
		form.Set("step", strconv.FormatInt(int64(query.Step()/time.Second), 10))
		form.Set("limit", strconv.Itoa(query.MaxItems()+1))
	case readconnector.KindVictoriaLogs:
		query, ok := values.execution.VictoriaLogsSearch()
		if !ok {
			return nil, ErrExecutionRejected
		}
		form.Set("query", query.Query())
		form.Set("limit", strconv.Itoa(query.Limit()+1))
		accept = "application/stream+json, application/json"
	default:
		return nil, ErrExecutionRejected
	}
	encoded := form.Encode()
	if len(encoded) == 0 || len(encoded) > MaximumRequestFormBytes {
		return nil, ErrExecutionRejected
	}
	destination := values.origin
	destination.Path = values.endpointPath
	destination.RawPath = ""
	destination.RawQuery = ""
	destination.ForceQuery = false
	destination.Fragment = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, destination.String(), strings.NewReader(encoded))
	if err != nil {
		return nil, ErrExecutionRejected
	}
	request.GetBody = nil
	request.Close = true
	request.Header = http.Header{
		"Accept":        []string{accept},
		"Cache-Control": []string{"no-store"},
		"Content-Type":  []string{"application/x-www-form-urlencoded"},
		"User-Agent":    []string{"aiops-read-executor/1"},
	}
	return request, nil
}

func roundTripWithBearer(
	ctx context.Context,
	transport *http.Transport,
	request *http.Request,
	credentialRef string,
	execution readconnector.ExecutionSpec,
	collectedAt time.Time,
	source BearerSource,
) (result Result, failure readtask.FailureCode) {
	if transport == nil || request == nil || source == nil || credentialRef == "" {
		return Result{}, readtask.FailureUnknown
	}
	defer request.Header.Del("Authorization")
	var callbackMu sync.Mutex
	callbackActive := true
	var response *http.Response
	var roundTripErr error
	calls := 0
	providerFailure, providerReturned := invokeBearerSource(ctx, credentialRef, source, func(token []byte) {
		callbackMu.Lock()
		defer callbackMu.Unlock()
		if !callbackActive {
			return
		}
		defer request.Header.Del("Authorization")
		calls++
		if calls != 1 || len(token) < MinimumBearerBytes || len(token) > MaximumBearerBytes || !bearerPattern.Match(token) {
			roundTripErr = ErrExecutionRejected
			return
		}
		authorization := make([]byte, len("Bearer ")+len(token))
		copy(authorization, "Bearer ")
		copy(authorization[len("Bearer "):], token)
		request.Header.Set("Authorization", string(authorization))
		clear(authorization)
		response, roundTripErr = transport.RoundTrip(request)
		request.Header.Del("Authorization")
		if roundTripErr == nil && response != nil {
			result = consumeResponse(response, request, execution, collectedAt, token)
			response = nil
		}
	})
	callbackMu.Lock()
	callbackActive = false
	callbackMu.Unlock()
	if !providerReturned {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return Result{}, readtask.FailureUnknown
	}
	if calls != 1 {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if validCredentialFailure(providerFailure) {
			return Result{}, providerFailure
		}
		return Result{}, readtask.FailureUnknown
	}
	if providerFailure != "" {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if validCredentialFailure(providerFailure) {
			return Result{}, providerFailure
		}
		return Result{}, readtask.FailureUnknown
	}
	if roundTripErr != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if errors.Is(roundTripErr, ErrExecutionRejected) {
			return Result{}, readtask.FailureAuthentication
		}
		return Result{}, transportFailure(ctx, roundTripErr, readtask.FailureConnectorUnavailable)
	}
	if !result.Valid() {
		return Result{}, readtask.FailureUnknown
	}
	return result, ""
}

func invokeBearerSource(
	ctx context.Context,
	credentialRef string,
	source BearerSource,
	use func([]byte),
) (failure readtask.FailureCode, returned bool) {
	defer func() {
		if recover() != nil {
			failure = ""
			returned = false
		}
	}()
	return source(ctx, credentialRef, use), true
}

func consumeResponse(
	response *http.Response,
	request *http.Request,
	execution readconnector.ExecutionSpec,
	collectedAt time.Time,
	bearer []byte,
) Result {
	if response == nil || response.Body == nil || request == nil ||
		len(bearer) < MinimumBearerBytes || len(bearer) > MaximumBearerBytes {
		return newFailureResult(readtask.FailureInvalidResponse)
	}
	bodyClosed := false
	defer func() {
		if !bodyClosed {
			_ = response.Body.Close()
		}
	}()
	if response.ProtoMajor != 1 || response.ProtoMinor != 1 || response.TLS == nil ||
		response.TLS.Version != tls.VersionTLS13 || !response.TLS.HandshakeComplete ||
		len(response.TLS.VerifiedChains) == 0 || response.TLS.ServerName != request.URL.Hostname() ||
		(response.TLS.NegotiatedProtocol != "" && response.TLS.NegotiatedProtocol != "http/1.1") ||
		response.Uncompressed || len(response.Header.Values("Content-Encoding")) != 0 ||
		len(response.Header.Values("Set-Cookie")) != 0 || len(response.Trailer) != 0 ||
		!validTransferEncoding(response.TransferEncoding) {
		return newFailureResult(readtask.FailureInvalidResponse)
	}
	if response.ContentLength > MaximumUpstreamResponseBytes {
		return newFailureResult(readtask.FailureResultRejected)
	}
	if failure := statusFailure(response.StatusCode); failure != "" {
		closeErr := response.Body.Close()
		bodyClosed = true
		if closeErr != nil {
			return newFailureResult(transportFailure(request.Context(), closeErr, readtask.FailureConnectorUnavailable))
		}
		return newFailureResult(failure)
	}
	if !validResponseContentType(response.Header, execution.Kind()) {
		return newFailureResult(readtask.FailureInvalidResponse)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaximumUpstreamResponseBytes+1))
	if err != nil {
		return newFailureResult(transportFailure(request.Context(), err, readtask.FailureConnectorUnavailable))
	}
	closeErr := response.Body.Close()
	bodyClosed = true
	if closeErr != nil {
		return newFailureResult(transportFailure(request.Context(), closeErr, readtask.FailureConnectorUnavailable))
	}
	defer clear(body)
	if len(body) > MaximumUpstreamResponseBytes || len(response.Trailer) != 0 {
		return newFailureResult(readtask.FailureResultRejected)
	}
	if failure := contextFailure(request.Context(), ""); failure != "" {
		return newFailureResult(failure)
	}
	var evidence readtask.EvidenceCompletion
	var failure responseFailure
	switch execution.Kind() {
	case readconnector.KindPrometheus:
		evidence, failure = parsePrometheusResponse(body, execution, collectedAt)
	case readconnector.KindVictoriaLogs:
		evidence, failure = parseVictoriaLogsResponse(body, execution, collectedAt)
	default:
		return newFailureResult(readtask.FailureInvalidResponse)
	}
	if contextual := contextFailure(request.Context(), ""); contextual != "" {
		return newFailureResult(contextual)
	}
	switch failure {
	case responseAccepted:
		if execution.ValidateEvidence(evidence) != nil || evidenceContainsBearer(evidence, bearer) {
			return newFailureResult(readtask.FailureResultRejected)
		}
		return newEvidenceResult(evidence)
	case responseRejected:
		return newFailureResult(readtask.FailureResultRejected)
	default:
		return newFailureResult(readtask.FailureInvalidResponse)
	}
}

func evidenceContainsBearer(evidence readtask.EvidenceCompletion, bearer []byte) bool {
	if len(bearer) < MinimumBearerBytes || len(bearer) > MaximumBearerBytes {
		return true
	}
	for _, item := range evidence.Items {
		if bytes.Contains(item, bearer) {
			return true
		}
	}
	return false
}

func validExecutorTLSConfig(configuration *tls.Config, hostname string) bool {
	return configuration != nil && configuration.MinVersion == tls.VersionTLS13 &&
		configuration.MaxVersion == tls.VersionTLS13 && configuration.RootCAs != nil &&
		len(configuration.RootCAs.Subjects()) > 0 &&
		configuration.ServerName == hostname && !configuration.InsecureSkipVerify &&
		len(configuration.NextProtos) == 1 && configuration.NextProtos[0] == "http/1.1" &&
		configuration.SessionTicketsDisabled && configuration.Renegotiation == tls.RenegotiateNever &&
		len(configuration.Certificates) == 0 && len(configuration.NameToCertificate) == 0 &&
		configuration.GetClientCertificate == nil && configuration.ClientAuth == tls.NoClientCert &&
		configuration.GetCertificate == nil && configuration.GetConfigForClient == nil &&
		configuration.VerifyPeerCertificate == nil && configuration.VerifyConnection == nil &&
		configuration.ClientCAs == nil && configuration.ClientSessionCache == nil && configuration.Time == nil &&
		configuration.Rand == nil && configuration.KeyLogWriter == nil && configuration.UnwrapSession == nil &&
		configuration.WrapSession == nil && len(configuration.CipherSuites) == 0 &&
		!configuration.PreferServerCipherSuites && configuration.SessionTicketKey == [32]byte{} &&
		len(configuration.CurvePreferences) == 0 && !configuration.DynamicRecordSizingDisabled &&
		len(configuration.EncryptedClientHelloConfigList) == 0 &&
		configuration.EncryptedClientHelloRejectionVerify == nil &&
		configuration.GetEncryptedClientHelloKeys == nil && len(configuration.EncryptedClientHelloKeys) == 0
}

func validExecutionSpecShape(execution readconnector.ExecutionSpec) bool {
	if execution.Lookback() <= 0 || !domain.ValidSHA256Hex(execution.ContractDigest()) {
		return false
	}
	switch execution.Kind() {
	case readconnector.KindPrometheus:
		query, ok := execution.PrometheusRangeQuery()
		return ok && query.Expression() != "" && query.Step() > 0 && query.Step()%time.Second == 0 &&
			query.MaxItems() > 0 && query.MaxItems() <= readtask.MaxEvidenceItems && query.MaxSamples() > 0
	case readconnector.KindVictoriaLogs:
		query, ok := execution.VictoriaLogsSearch()
		return ok && query.Query() != "" && query.Limit() > 0 && query.Limit() <= readtask.MaxEvidenceItems &&
			len(query.Fields()) > 0
	default:
		return false
	}
}

func statusFailure(status int) readtask.FailureCode {
	switch status {
	case http.StatusOK:
		return ""
	case http.StatusUnauthorized:
		return readtask.FailureAuthentication
	case http.StatusForbidden:
		return readtask.FailurePermissionDenied
	case http.StatusRequestTimeout, http.StatusGatewayTimeout, http.StatusServiceUnavailable:
		return readtask.FailureTimeout
	case http.StatusTooManyRequests:
		return readtask.FailureRateLimited
	case http.StatusUnprocessableEntity:
		return readtask.FailureResultRejected
	default:
		if status >= 500 && status <= 599 {
			return readtask.FailureConnectorUnavailable
		}
		return readtask.FailureInvalidResponse
	}
}

func validResponseContentType(header http.Header, kind readconnector.Kind) bool {
	values := header.Values("Content-Type")
	if kind == readconnector.KindVictoriaLogs && len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	if kind == readconnector.KindVictoriaLogs && values[0] == "" {
		return true
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	if err != nil || len(parameters) > 1 {
		return false
	}
	if len(parameters) == 1 && !strings.EqualFold(parameters["charset"], "utf-8") {
		return false
	}
	switch kind {
	case readconnector.KindPrometheus:
		return mediaType == "application/json"
	case readconnector.KindVictoriaLogs:
		return mediaType == "application/json" || mediaType == "application/stream+json"
	default:
		return false
	}
}

func validTransferEncoding(values []string) bool {
	return len(values) == 0 || len(values) == 1 && values[0] == "chunked"
}

func remoteAddressMatches(remote net.Addr, expected netip.Addr, port uint16) bool {
	if remote == nil || !expected.IsValid() || port == 0 {
		return false
	}
	address, err := netip.ParseAddrPort(remote.String())
	return err == nil && address.Addr().Unmap() == expected.Unmap() && address.Port() == port
}

func contextFailure(ctx context.Context, fallback readtask.FailureCode) readtask.FailureCode {
	err := executionContextError(ctx)
	switch {
	case errors.Is(err, context.Canceled):
		return readtask.FailureCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return readtask.FailureTimeout
	default:
		return fallback
	}
}

func transportFailure(ctx context.Context, err error, fallback readtask.FailureCode) readtask.FailureCode {
	if contextual := contextFailure(ctx, fallback); contextual != fallback {
		return contextual
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return readtask.FailureTimeout
	}
	return fallback
}

func contextResult(err error) Result {
	if errors.Is(err, context.Canceled) {
		return newFailureResult(readtask.FailureCancelled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return newFailureResult(readtask.FailureTimeout)
	}
	return newFailureResult(readtask.FailureUnknown)
}

func validCredentialFailure(code readtask.FailureCode) bool {
	switch code {
	case readtask.FailureConnectorUnavailable, readtask.FailureRateLimited, readtask.FailureTimeout,
		readtask.FailureAuthentication, readtask.FailurePermissionDenied, readtask.FailureCancelled,
		readtask.FailureUnknown:
		return true
	default:
		return false
	}
}

func equalDigest(left, right string) bool {
	return domain.ValidSHA256Hex(left) && domain.ValidSHA256Hex(right) &&
		subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func referenceDigestMatches(reference, digest string) bool {
	return len(reference) >= len(digest) && equalDigest(reference[len(reference)-len(digest):], digest)
}

func (Executor) String() string   { return "<aiops-fixed-read-executor>" }
func (Executor) GoString() string { return "<aiops-fixed-read-executor>" }
func (Executor) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-fixed-read-executor>")
}
func (Executor) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Executor) UnmarshalJSON([]byte) error  { return ErrExecutionRejected }
