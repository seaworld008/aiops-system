package externalcmdb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

const (
	connectTimeout         = 5 * time.Second
	maxRequestTimeout      = 15 * time.Second
	maxResponseHeaderBytes = 64 << 10
	maxProviderRetryAfter  = 60 * time.Second

	providerKind = "CMDB_CATALOG_V1"
	profileCode  = assetcatalog.ProfileCode("CMDB_CATALOG_V1")

	runtimeMaterialRedaction = "[REDACTED_EXTERNAL_CMDB_RUNTIME]"
	providerBackoffRedaction = "[REDACTED_EXTERNAL_CMDB_BACKOFF]"
	assetPageLimit           = 500
	relationPageLimit        = 2_000
)

var (
	errClientContract   = errors.New("external cmdb client contract violation")
	errProviderContract = errors.New("external cmdb provider contract violation")
)

type catalogClientConfig struct {
	BaseURL        string
	TLSConfig      *tls.Config
	BearerToken    []byte
	RequestTimeout time.Duration
	Now            func() time.Time
}

type catalogClient struct {
	baseURL     *url.URL
	bearerToken []byte
	httpClient  *http.Client
	now         func() time.Time
}

type catalogCursor struct {
	value string
}

func newCatalogCursor(value string) (catalogCursor, error) {
	if value == "" {
		return catalogCursor{}, nil
	}
	if len(value) > 2_048 {
		return catalogCursor{}, clientError("CURSOR_REJECTED")
	}
	for _, character := range []byte(value) {
		switch {
		case character >= 'A' && character <= 'Z',
			character >= 'a' && character <= 'z',
			character >= '0' && character <= '9',
			character == '.', character == '_', character == '~',
			character == '+', character == '/', character == '=',
			character == '-':
		default:
			return catalogCursor{}, clientError("CURSOR_REJECTED")
		}
	}
	return catalogCursor{value: value}, nil
}

type clientContractError struct {
	code string
}

func (err *clientContractError) Error() string {
	return errClientContract.Error() + ": " + err.code
}

func (*clientContractError) Unwrap() error {
	return errClientContract
}

type providerBackoffError struct {
	delay time.Duration
}

func (*providerBackoffError) Error() string {
	return providerBackoffRedaction
}

func (*providerBackoffError) Unwrap() error {
	return errClientContract
}

func (*providerBackoffError) MarshalJSON() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*providerBackoffError) UnmarshalJSON([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (*providerBackoffError) MarshalText() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*providerBackoffError) UnmarshalText([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (*providerBackoffError) MarshalBinary() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*providerBackoffError) UnmarshalBinary([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (*providerBackoffError) String() string       { return providerBackoffRedaction }
func (*providerBackoffError) GoString() string     { return providerBackoffRedaction }
func (*providerBackoffError) LogValue() slog.Value { return slog.StringValue(providerBackoffRedaction) }
func (*providerBackoffError) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, providerBackoffRedaction)
}

func providerRetryAfter(err error) (time.Duration, bool) {
	var backoff *providerBackoffError
	if !errors.As(err, &backoff) || backoff == nil ||
		backoff.delay < 0 || backoff.delay > maxProviderRetryAfter {
		return 0, false
	}
	return backoff.delay, true
}

// RuntimeMaterial contains one already-resolved, process-local connection
// binding. It is intentionally non-serializable and must only be placed inside
// discoverysource.BoundRuntime.
type RuntimeMaterial struct {
	BaseURL             string
	TLSConfig           *tls.Config
	BearerToken         []byte
	ExpectedAuthorityID string
	EnvironmentID       string
}

func (material *RuntimeMaterial) Clear() {
	if material == nil {
		return
	}
	clear(material.BearerToken)
	material.BearerToken = nil
	material.BaseURL = ""
	material.TLSConfig = nil
	material.ExpectedAuthorityID = ""
	material.EnvironmentID = ""
}

func (RuntimeMaterial) MarshalJSON() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*RuntimeMaterial) UnmarshalJSON([]byte) error { return discoverysource.ErrSensitiveSerialization }
func (RuntimeMaterial) MarshalText() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*RuntimeMaterial) UnmarshalText([]byte) error { return discoverysource.ErrSensitiveSerialization }
func (RuntimeMaterial) MarshalBinary() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*RuntimeMaterial) UnmarshalBinary([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (RuntimeMaterial) String() string       { return runtimeMaterialRedaction }
func (RuntimeMaterial) GoString() string     { return runtimeMaterialRedaction }
func (RuntimeMaterial) LogValue() slog.Value { return slog.StringValue(runtimeMaterialRedaction) }
func (RuntimeMaterial) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, runtimeMaterialRedaction)
}

type ClientFactory struct {
	binding discoverysource.RuntimeBinding
	now     func() time.Time
}

func NewClientFactory(binding discoverysource.RuntimeBinding) (ClientFactory, error) {
	if binding.ProviderKind != providerKind || binding.ProfileCode != profileCode {
		return ClientFactory{}, providerError("FACTORY_BINDING_REJECTED")
	}
	return ClientFactory{binding: binding, now: time.Now}, nil
}

type runtimeSession struct {
	client              *catalogClient
	expectedAuthorityID string
	environmentID       string
}

func (factory ClientFactory) open(runtime discoverysource.BoundRuntime) (runtimeSession, error) {
	if factory.now == nil || factory.binding.ProviderKind != providerKind || factory.binding.ProfileCode != profileCode {
		return runtimeSession{}, providerError("FACTORY_REJECTED")
	}
	var session runtimeSession
	err := discoverysource.WithRuntime(runtime, factory.binding, func(material *RuntimeMaterial) error {
		if material == nil || material.TLSConfig == nil ||
			!safeIdentifier(material.ExpectedAuthorityID) || !canonicalUUIDPattern.MatchString(material.EnvironmentID) {
			return providerError("RUNTIME_MATERIAL_REJECTED")
		}
		if !validBearerToken(material.BearerToken) && !hasClientCertificate(material.TLSConfig) {
			return providerError("RUNTIME_CREDENTIAL_REJECTED")
		}
		client, err := newCatalogClient(catalogClientConfig{
			BaseURL:        material.BaseURL,
			TLSConfig:      material.TLSConfig,
			BearerToken:    material.BearerToken,
			RequestTimeout: maxRequestTimeout,
			Now:            factory.now,
		})
		if err != nil {
			return err
		}
		session = runtimeSession{
			client:              client,
			expectedAuthorityID: material.ExpectedAuthorityID,
			environmentID:       material.EnvironmentID,
		}
		return nil
	})
	if err != nil {
		session.close()
		return runtimeSession{}, providerError("RUNTIME_ACCESS_REJECTED")
	}
	return session, nil
}

func (session *runtimeSession) close() {
	if session == nil {
		return
	}
	if session.client != nil {
		session.client.close()
	}
	session.client = nil
	session.expectedAuthorityID = ""
	session.environmentID = ""
}

type provider struct {
	factory ClientFactory
}

func New(factory ClientFactory) (discoverysource.Provider, error) {
	if factory.now == nil || factory.binding.ProviderKind != providerKind || factory.binding.ProfileCode != profileCode {
		return nil, providerError("FACTORY_REJECTED")
	}
	return &provider{factory: factory}, nil
}

func (*provider) Kind() assetcatalog.SourceKind { return assetcatalog.SourceKindExternalCMDB }
func (*provider) ProviderKind() string          { return providerKind }

func (value *provider) Validate(
	ctx context.Context,
	runtime discoverysource.BoundRuntime,
	request discoverysource.ValidationRequest,
) (discoverysource.ValidationProof, error) {
	if value == nil {
		return discoverysource.ValidationProof{}, providerError("INACTIVE_PROVIDER")
	}
	if err := request.Validate(); err != nil {
		return discoverysource.ValidationProof{}, err
	}
	if !validationRequestMatchesBinding(request, value.factory.binding) {
		return discoverysource.ValidationProof{}, providerError("VALIDATION_BINDING_REJECTED")
	}
	session, err := value.factory.open(runtime)
	if err != nil {
		return discoverysource.ValidationProof{}, err
	}
	defer session.close()

	capabilities, err := session.client.capabilities(ctx)
	if err != nil {
		if contextErr := callerContextError(ctx); contextErr != nil {
			return discoverysource.ValidationProof{}, contextErr
		}
		if clientErrorHasCode(err, "TLS_TRUST_REJECTED") {
			return validationFailure(
				discoverysource.ValidationCheckTrustOrSignature,
				"TRUST_OR_SIGNATURE_REJECTED",
				"VALIDATION_REJECTED",
			), nil
		}
		return validationFailure(
			discoverysource.ValidationCheckNetwork,
			"NETWORK_REJECTED",
			"VALIDATION_REJECTED",
		), nil
	}
	validation := validateCapabilities(capabilities, session.expectedAuthorityID, value.factory.now().UTC())
	if !validation.Passed {
		return proofForCapabilityFailure(validation.Code), nil
	}

	pageBodyLimit := min(maxPageBodyBytes, request.Limits.MaxPageBytes)
	page, err := session.client.assets(ctx, catalogCursor{}, pageBodyLimit)
	if err != nil {
		if contextErr := callerContextError(ctx); contextErr != nil {
			return discoverysource.ValidationProof{}, contextErr
		}
		if protocolErrorHasCode(err, "BODY_LIMIT_EXCEEDED") {
			return validationFailure(
				discoverysource.ValidationCheckBudget,
				"BUDGET_REJECTED",
				"VALIDATION_REJECTED",
			), nil
		}
		return validationFailure(
			discoverysource.ValidationCheckSchema,
			"SCHEMA_REJECTED",
			"VALIDATION_REJECTED",
		), nil
	}
	probe := validateAssetProbe(page, capabilities, session.environmentID, request.Limits)
	if !probe.Passed {
		return validationFailure(probe.Kind, probe.CheckCode, probe.ProofCode), nil
	}
	return successfulValidationProof(capabilities, len(page.Items)), nil
}

func validationRequestMatchesBinding(
	request discoverysource.ValidationRequest,
	binding discoverysource.RuntimeBinding,
) bool {
	return binding.RevisionStatus == assetcatalog.SourceRevisionValidating &&
		request.Locator == binding.Locator &&
		request.SourceRevision == binding.SourceRevision &&
		request.SourceRevisionDigest == binding.SourceRevisionDigest
}

func newCatalogClient(config catalogClientConfig) (*catalogClient, error) {
	baseURL, err := url.Parse(config.BaseURL)
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" || baseURL.User != nil ||
		baseURL.RawQuery != "" || baseURL.Fragment != "" || baseURL.RawPath != "" ||
		baseURL.Path != "" && baseURL.Path != "/" {
		return nil, clientError("INVALID_BASE_URL")
	}
	if config.TLSConfig == nil || config.TLSConfig.InsecureSkipVerify {
		return nil, clientError("TLS_VERIFICATION_REQUIRED")
	}
	if config.RequestTimeout <= 0 || config.RequestTimeout > maxRequestTimeout {
		return nil, clientError("INVALID_REQUEST_TIMEOUT")
	}

	tlsConfig := config.TLSConfig.Clone()
	if tlsConfig.MaxVersion != 0 && tlsConfig.MaxVersion < tls.VersionTLS13 {
		return nil, clientError("TLS13_UNAVAILABLE")
	}
	tlsConfig.MinVersion = tls.VersionTLS13

	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}).DialContext,
		DisableCompression:     true,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           8,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        30 * time.Second,
		TLSHandshakeTimeout:    connectTimeout,
		ResponseHeaderTimeout:  config.RequestTimeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		TLSClientConfig:        tlsConfig,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   config.RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return clientError("REDIRECT_REJECTED")
		},
	}

	now := config.Now
	if now == nil {
		now = time.Now
	}
	baseURL.Path = ""
	return &catalogClient{
		baseURL:     baseURL,
		bearerToken: append([]byte(nil), config.BearerToken...),
		httpClient:  httpClient,
		now:         now,
	}, nil
}

func (client *catalogClient) capabilities(ctx context.Context) (catalogCapabilities, error) {
	var capabilities catalogCapabilities
	if client == nil {
		return capabilities, clientError("INACTIVE_CLIENT")
	}
	if err := client.getJSON(ctx, capabilitiesPath, maxCapabilitiesBodyBytes, &capabilities); err != nil {
		return catalogCapabilities{}, err
	}
	return capabilities, nil
}

func (client *catalogClient) assets(
	ctx context.Context,
	cursor catalogCursor,
	maxBodyBytes int64,
) (catalogPage[catalogAsset], error) {
	var page catalogPage[catalogAsset]
	if client == nil || maxBodyBytes <= 0 || maxBodyBytes > maxPageBodyBytes {
		return page, clientError("INACTIVE_CLIENT")
	}
	query, err := fixedPageQuery(assetPageLimit, cursor)
	if err != nil {
		return catalogPage[catalogAsset]{}, err
	}
	if err := client.getJSONWithFixedQuery(ctx, assetsPath, query, maxBodyBytes, &page); err != nil {
		return catalogPage[catalogAsset]{}, err
	}
	if len(page.Items) > assetPageLimit {
		return catalogPage[catalogAsset]{}, protocolError("PAGE_ITEM_LIMIT_EXCEEDED")
	}
	if _, err := newCatalogCursor(page.NextCursor); err != nil {
		return catalogPage[catalogAsset]{}, protocolError("CURSOR_SCHEMA_REJECTED")
	}
	return page, nil
}

func (client *catalogClient) relations(
	ctx context.Context,
	cursor catalogCursor,
	maxBodyBytes int64,
) (catalogPage[catalogRelation], error) {
	var page catalogPage[catalogRelation]
	if client == nil || maxBodyBytes <= 0 || maxBodyBytes > maxPageBodyBytes {
		return page, clientError("INACTIVE_CLIENT")
	}
	query, err := fixedPageQuery(relationPageLimit, cursor)
	if err != nil {
		return catalogPage[catalogRelation]{}, err
	}
	if err := client.getJSONWithFixedQuery(ctx, relationsPath, query, maxBodyBytes, &page); err != nil {
		return catalogPage[catalogRelation]{}, err
	}
	if len(page.Items) > relationPageLimit {
		return catalogPage[catalogRelation]{}, protocolError("PAGE_ITEM_LIMIT_EXCEEDED")
	}
	if _, err := newCatalogCursor(page.NextCursor); err != nil {
		return catalogPage[catalogRelation]{}, protocolError("CURSOR_SCHEMA_REJECTED")
	}
	return page, nil
}

func fixedPageQuery(limit int, cursor catalogCursor) (string, error) {
	if limit != assetPageLimit && limit != relationPageLimit {
		return "", clientError("PAGE_LIMIT_REJECTED")
	}
	if cursor.value != "" {
		validated, err := newCatalogCursor(cursor.value)
		if err != nil || validated != cursor {
			return "", clientError("CURSOR_REJECTED")
		}
	}
	values := url.Values{"limit": []string{strconv.Itoa(limit)}}
	if cursor.value != "" {
		values.Set("cursor", cursor.value)
	}
	return values.Encode(), nil
}

func (client *catalogClient) getJSON(ctx context.Context, path string, maxBodyBytes int64, destination any) error {
	return client.getJSONWithFixedQuery(ctx, path, "", maxBodyBytes, destination)
}

func (client *catalogClient) getJSONWithFixedQuery(
	ctx context.Context,
	path string,
	rawQuery string,
	maxBodyBytes int64,
	destination any,
) error {
	if ctx == nil || destination == nil || !closedCatalogRequest(path, rawQuery) {
		return clientError("REQUEST_REJECTED")
	}
	requestURL := *client.baseURL
	requestURL.Path = path
	requestURL.RawQuery = rawQuery
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return clientError("REQUEST_REJECTED")
	}
	request.Header.Set("Accept", catalogContentType)
	if len(client.bearerToken) > 0 {
		request.Header.Set("Authorization", "Bearer "+string(client.bearerToken))
	}

	response, err := client.httpClient.Do(request)
	if err != nil {
		if contextErr := callerContextError(ctx); contextErr != nil {
			return contextErr
		}
		if isTLSVerificationError(err) {
			return clientError("TLS_TRUST_REJECTED")
		}
		return clientError("TRANSPORT_FAILED")
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusTooManyRequests ||
			response.StatusCode == http.StatusServiceUnavailable {
			if delay, ok := parseProviderRetryAfter(response.Header.Values("Retry-After"), client.now); ok {
				return &providerBackoffError{delay: delay}
			}
		}
		return clientError("STATUS_REJECTED")
	}
	if response.Header.Get("Content-Encoding") != "" {
		return clientError("CONTENT_ENCODING_REJECTED")
	}
	if values := response.Header.Values("Content-Type"); len(values) != 1 || values[0] != catalogContentType {
		return clientError("CONTENT_TYPE_REJECTED")
	}
	if err := decodeStrictJSON(response.Body, maxBodyBytes, destination); err != nil {
		if contextErr := callerContextError(ctx); contextErr != nil {
			return contextErr
		}
		return err
	}
	return nil
}

func (client *catalogClient) close() {
	if client == nil {
		return
	}
	clear(client.bearerToken)
	client.bearerToken = nil
	if transport, ok := client.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	client.baseURL = nil
	client.httpClient = nil
	client.now = nil
}

func callerContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	switch err := ctx.Err(); {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func parseProviderRetryAfter(values []string, now func() time.Time) (time.Duration, bool) {
	if len(values) != 1 || values[0] == "" || now == nil {
		return 0, false
	}
	value := values[0]
	deltaSeconds := true
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			deltaSeconds = false
			break
		}
	}
	if deltaSeconds {
		seconds, err := strconv.ParseUint(value, 10, 64)
		if err != nil || seconds > uint64(maxProviderRetryAfter/time.Second) {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	retryAt, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	delay := retryAt.Sub(now())
	if delay < 0 || delay > maxProviderRetryAfter {
		return 0, false
	}
	return delay, true
}

func closedCatalogRequest(path string, rawQuery string) bool {
	switch path {
	case capabilitiesPath:
		return rawQuery == ""
	case assetsPath:
		return validFixedPageQuery(rawQuery, assetPageLimit)
	case relationsPath:
		return validFixedPageQuery(rawQuery, relationPageLimit)
	default:
		return false
	}
}

func validFixedPageQuery(rawQuery string, expectedLimit int) bool {
	if rawQuery == "" {
		return false
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil || values.Encode() != rawQuery || len(values) < 1 || len(values) > 2 ||
		len(values["limit"]) != 1 || values.Get("limit") != strconv.Itoa(expectedLimit) {
		return false
	}
	if cursorValues, present := values["cursor"]; present {
		if len(cursorValues) != 1 || cursorValues[0] == "" {
			return false
		}
		if _, err := newCatalogCursor(cursorValues[0]); err != nil {
			return false
		}
	}
	for key := range values {
		if key != "limit" && key != "cursor" {
			return false
		}
	}
	return true
}

func clientError(code string) error {
	return &clientContractError{code: strings.ToUpper(code)}
}

func providerError(code string) error {
	return fmt.Errorf("%w: %s", errProviderContract, strings.ToUpper(code))
}

func clientErrorHasCode(err error, code string) bool {
	var contractError *clientContractError
	return errors.As(err, &contractError) && contractError.code == code
}

func isTLSVerificationError(err error) bool {
	var tlsVerification *tls.CertificateVerificationError
	if errors.As(err, &tlsVerification) {
		return true
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return true
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return true
	}
	var invalidCertificate x509.CertificateInvalidError
	return errors.As(err, &invalidCertificate)
}

func validBearerToken(token []byte) bool {
	if len(token) == 0 || len(token) > 8<<10 || token[0] == '=' {
		return false
	}
	padding := false
	for _, character := range token {
		switch {
		case character >= 'A' && character <= 'Z',
			character >= 'a' && character <= 'z',
			character >= '0' && character <= '9',
			character == '-', character == '.', character == '_',
			character == '~', character == '+', character == '/':
			if padding {
				return false
			}
		case character == '=':
			padding = true
		default:
			return false
		}
	}
	return true
}

func hasClientCertificate(config *tls.Config) bool {
	if config == nil {
		return false
	}
	for _, certificate := range config.Certificates {
		if len(certificate.Certificate) > 0 && certificate.PrivateKey != nil {
			return true
		}
	}
	return false
}

var _ discoverysource.Provider = (*provider)(nil)
