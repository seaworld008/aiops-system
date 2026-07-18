package proxmox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	sdk "github.com/luthermonson/go-proxmox"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

const (
	connectTimeout         = 5 * time.Second
	providerCallTimeout    = 30 * time.Second
	maxResponseHeaderBytes = 64 << 10
	maxResponseBodyBytes   = 8 << 20
	maxHTTPConnections     = 2
	maxInventoryResources  = 5_000
)

var (
	errClientContract   = errors.New("proxmox client contract violation")
	errProviderContract = errors.New("proxmox provider contract violation")
	lowercaseDigest     = regexp.MustCompile(`^[0-9a-f]{64}$`)

	fixedWirePaths = []string{
		"/api2/json/version",
		"/api2/json/cluster/status",
		"/api2/json/nodes",
		"/api2/json/cluster/resources?type=vm",
	}
)

type clientFailureStage uint8

const (
	clientFailureRuntime clientFailureStage = iota + 1
	clientFailureIdentity
	clientFailureTrust
	clientFailureNetwork
	clientFailureCredential
	clientFailureProtocol
	clientFailureIncomplete
	clientFailureDLP
	clientFailureBudget
)

type clientContractError struct {
	stage clientFailureStage
	code  string
}

func (value *clientContractError) Error() string {
	return errClientContract.Error() + ": " + value.code
}

func (*clientContractError) Unwrap() error {
	return errClientContract
}

type retryAfterError struct {
	duration time.Duration
}

func (value *retryAfterError) Error() string {
	return errClientContract.Error() + ": PROVIDER_RETRY_AFTER"
}

func (*retryAfterError) Unwrap() error {
	return errClientContract
}

type VersionInfo struct {
	Version string
	Release string
	RepoID  string
}

type ClusterMember struct {
	Name   string
	Online bool
}

type ClusterStatus struct {
	Identity   string
	Name       string
	Generation int64
	Quorate    bool
	Members    []ClusterMember
}

type Node struct {
	Name        string
	Status      string
	CPUCount    int64
	MemoryBytes uint64
}

type ClusterResource struct {
	ID          string
	Type        string
	VMID        uint64
	Name        string
	Node        string
	Status      string
	Template    bool
	CPUCount    uint64
	MemoryBytes uint64
}

type InventoryClient interface {
	Version(context.Context) (VersionInfo, error)
	ClusterStatus(context.Context) (ClusterStatus, error)
	ListNodes(context.Context) ([]Node, error)
	ListClusterResources(context.Context) ([]ClusterResource, error)
}

type clientSession struct {
	client                     InventoryClient
	authority                  authoritySnapshot
	acceptedCheckpointSequence int64
	peerDigest                 string
	peer                       *peerDigestTracker
	roleDigest                 string
	close                      func()
}

func (session clientSession) TLSPeerDigest() string {
	if session.peer != nil {
		return session.peer.value()
	}
	return session.peerDigest
}

func (session *clientSession) Close() {
	if session == nil {
		return
	}
	if session.close != nil {
		session.close()
	}
	session.client = nil
	session.authority.Clear()
	session.acceptedCheckpointSequence = 0
	session.peerDigest = ""
	session.peer = nil
	session.roleDigest = ""
	session.close = nil
}

type ClientFactory struct {
	binding    discoverysource.RuntimeBinding
	openClient func(context.Context, resolvedRuntime) (clientSession, error)
	now        func() time.Time
}

func NewClientFactory(binding discoverysource.RuntimeBinding) (ClientFactory, error) {
	if binding.ProviderKind != providerKind ||
		binding.ProfileCode != profileCode ||
		binding.RevisionStatus != assetcatalog.SourceRevisionValidating &&
			binding.RevisionStatus != assetcatalog.SourceRevisionPublished {
		return ClientFactory{}, providerError("FACTORY_BINDING_REJECTED")
	}
	return ClientFactory{
		binding: binding,
		now:     time.Now,
	}, nil
}

func (factory ClientFactory) open(
	ctx context.Context,
	runtime discoverysource.BoundRuntime,
) (clientSession, error) {
	if ctx == nil ||
		factory.binding.ProviderKind != providerKind ||
		factory.binding.ProfileCode != profileCode {
		return clientSession{}, clientError(clientFailureRuntime, "FACTORY_REJECTED")
	}
	var resolved resolvedRuntime
	err := discoverysource.WithRuntime(runtime, factory.binding, func(material *RuntimeMaterial) error {
		var ok bool
		resolved, ok = material.snapshot()
		if !ok {
			return clientError(clientFailureRuntime, "RUNTIME_MATERIAL_REJECTED")
		}
		return nil
	})
	if err != nil {
		resolved.Clear()
		return clientSession{}, clientError(clientFailureRuntime, "RUNTIME_ACCESS_REJECTED")
	}
	defer resolved.Clear()
	if !resolved.valid() {
		return clientSession{}, clientError(clientFailureRuntime, "RUNTIME_MATERIAL_REJECTED")
	}

	opener := factory.openClient
	if opener == nil {
		now := factory.now
		if now == nil {
			now = time.Now
		}
		opener = func(ctx context.Context, value resolvedRuntime) (clientSession, error) {
			return openSDKInventoryClient(ctx, value, now)
		}
	}
	session, err := opener(ctx, resolved)
	if err != nil {
		return clientSession{}, err
	}
	if session.client == nil {
		session.Close()
		return clientSession{}, clientError(clientFailureProtocol, "CLIENT_REJECTED")
	}
	session.authority = resolved.authority
	session.acceptedCheckpointSequence = resolved.acceptedCheckpointSequence
	if session.close == nil {
		session.close = func() {}
	}
	return session, nil
}

type sdkInventoryClient struct {
	client  *sdk.Client
	cluster *sdk.Cluster
	mu      sync.Mutex
}

func (client *sdkInventoryClient) Version(ctx context.Context) (VersionInfo, error) {
	if client == nil || client.client == nil || ctx == nil {
		return VersionInfo{}, clientError(clientFailureRuntime, "CLIENT_REJECTED")
	}
	value, err := client.client.Version(ctx)
	if err != nil {
		return VersionInfo{}, sanitizeSDKError(ctx, err)
	}
	if value == nil {
		return VersionInfo{}, clientError(clientFailureProtocol, "VERSION_REJECTED")
	}
	return VersionInfo{
		Version: value.Version,
		Release: value.Release,
		RepoID:  value.RepoID,
	}, nil
}

func (client *sdkInventoryClient) ClusterStatus(ctx context.Context) (ClusterStatus, error) {
	if client == nil || client.client == nil || ctx == nil {
		return ClusterStatus{}, clientError(clientFailureRuntime, "CLIENT_REJECTED")
	}
	cluster, err := client.client.Cluster(ctx)
	if err != nil {
		return ClusterStatus{}, sanitizeSDKError(ctx, err)
	}
	if cluster == nil {
		return ClusterStatus{}, clientError(clientFailureProtocol, "CLUSTER_STATUS_REJECTED")
	}
	members := make([]ClusterMember, 0, len(cluster.Nodes))
	for _, member := range cluster.Nodes {
		if member == nil {
			return ClusterStatus{}, clientError(clientFailureProtocol, "CLUSTER_MEMBER_REJECTED")
		}
		members = append(members, ClusterMember{
			Name:   member.Name,
			Online: member.Online == 1,
		})
	}
	client.mu.Lock()
	client.cluster = cluster
	client.mu.Unlock()
	return ClusterStatus{
		Identity:   cluster.ID,
		Name:       cluster.Name,
		Generation: int64(cluster.Version),
		Quorate:    cluster.Quorate == 1,
		Members:    members,
	}, nil
}

func (client *sdkInventoryClient) ListNodes(ctx context.Context) ([]Node, error) {
	if client == nil || client.client == nil || ctx == nil {
		return nil, clientError(clientFailureRuntime, "CLIENT_REJECTED")
	}
	values, err := client.client.Nodes(ctx)
	if err != nil {
		return nil, sanitizeSDKError(ctx, err)
	}
	nodes := make([]Node, 0, len(values))
	for _, value := range values {
		if value == nil {
			return nil, clientError(clientFailureProtocol, "NODE_REJECTED")
		}
		nodes = append(nodes, Node{
			Name:        value.Node,
			Status:      value.Status,
			CPUCount:    int64(value.MaxCPU),
			MemoryBytes: value.MaxMem,
		})
	}
	return nodes, nil
}

func (client *sdkInventoryClient) ListClusterResources(
	ctx context.Context,
) ([]ClusterResource, error) {
	if client == nil || client.client == nil || ctx == nil {
		return nil, clientError(clientFailureRuntime, "CLIENT_REJECTED")
	}
	client.mu.Lock()
	cluster := client.cluster
	client.mu.Unlock()
	if cluster == nil {
		return nil, clientError(clientFailureProtocol, "CLUSTER_SEQUENCE_REJECTED")
	}
	values, err := cluster.Resources(ctx, "vm")
	if err != nil {
		return nil, sanitizeSDKError(ctx, err)
	}
	resources := make([]ClusterResource, 0, len(values))
	for _, value := range values {
		if value == nil {
			return nil, clientError(clientFailureProtocol, "RESOURCE_REJECTED")
		}
		resources = append(resources, ClusterResource{
			ID:          value.ID,
			Type:        value.Type,
			VMID:        value.VMID,
			Name:        value.Name,
			Node:        value.Node,
			Status:      value.Status,
			Template:    value.Template == 1,
			CPUCount:    value.MaxCPU,
			MemoryBytes: value.MaxMem,
		})
	}
	return resources, nil
}

type peerDigestTracker struct {
	mu     sync.Mutex
	digest string
}

func (tracker *peerDigestTracker) observe(state tls.ConnectionState) error {
	if tracker == nil ||
		len(state.PeerCertificates) == 0 ||
		len(state.VerifiedChains) == 0 ||
		len(state.PeerCertificates[0].Raw) == 0 {
		return clientError(clientFailureTrust, "TLS_PEER_REJECTED")
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	digest := hex.EncodeToString(sum[:])
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if tracker.digest != "" && tracker.digest != digest {
		return clientError(clientFailureTrust, "TLS_PEER_DRIFT_REJECTED")
	}
	tracker.digest = digest
	return nil
}

func (tracker *peerDigestTracker) value() string {
	if tracker == nil {
		return ""
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.digest
}

func (tracker *peerDigestTracker) Clear() {
	if tracker == nil {
		return
	}
	tracker.mu.Lock()
	tracker.digest = ""
	tracker.mu.Unlock()
}

func openSDKInventoryClient(
	ctx context.Context,
	runtime resolvedRuntime,
	now func() time.Time,
) (clientSession, error) {
	if ctx == nil || !runtime.valid() || now == nil {
		return clientSession{}, clientError(clientFailureRuntime, "CLIENT_CONFIG_REJECTED")
	}
	tlsConfig := runtime.trust.tlsConfig()
	if tlsConfig == nil {
		return clientSession{}, clientError(clientFailureTrust, "TLS_CONFIG_REJECTED")
	}
	peer := &peerDigestTracker{}
	tlsConfig.VerifyConnection = peer.observe

	baseTransport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:      false,
		DisableCompression:     true,
		MaxIdleConns:           maxHTTPConnections,
		MaxIdleConnsPerHost:    maxHTTPConnections,
		MaxConnsPerHost:        maxHTTPConnections,
		IdleConnTimeout:        30 * time.Second,
		TLSHandshakeTimeout:    connectTimeout,
		ResponseHeaderTimeout:  providerCallTimeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		TLSClientConfig:        tlsConfig,
	}
	guard := &fixedInventoryTransport{
		next:     baseTransport,
		baseURL:  runtime.endpoint.endpoint.String(),
		tokenID:  runtime.token.tokenID,
		secret:   append([]byte(nil), runtime.token.secret...),
		now:      now,
		maxBytes: maxResponseBodyBytes,
	}
	httpClient := &http.Client{
		Transport: guard,
		Timeout:   providerCallTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return clientError(clientFailureNetwork, "REDIRECT_REJECTED")
		},
	}
	client := sdk.NewClient(
		runtime.endpoint.endpoint.String(),
		sdk.WithHTTPClient(httpClient),
		sdk.WithAPIToken(runtime.token.tokenID, string(runtime.token.secret)),
		sdk.WithUserAgent("aiops-proxmox-inventory/1"),
		sdk.WithLogger(noopSDKLogger{}),
	)
	roleDigest := digestStringTuple("proxmox-token-role.v1", runtime.token.tokenID)
	value := &sdkInventoryClient{client: client}
	return clientSession{
		client:     value,
		peer:       peer,
		roleDigest: roleDigest,
		close: func() {
			guard.CloseIdleConnections()
			guard.Clear()
			peer.Clear()
			value.mu.Lock()
			value.cluster = nil
			value.client = nil
			value.mu.Unlock()
		},
	}, nil
}

type fixedInventoryTransport struct {
	next     *http.Transport
	baseURL  string
	tokenID  string
	secret   []byte
	now      func() time.Time
	maxBytes int64
	mu       sync.Mutex
	nextPath int
}

type callerSignalContext struct {
	context.Context
}

func (callerSignalContext) Value(any) any {
	return nil
}

func (transport *fixedInventoryTransport) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	if transport == nil ||
		transport.next == nil ||
		request == nil ||
		request.URL == nil ||
		transport.maxBytes <= 0 {
		return nil, clientError(clientFailureRuntime, "TRANSPORT_REJECTED")
	}
	if err := transport.validateRequest(request); err != nil {
		return nil, err
	}
	wireRequest := request.WithContext(callerSignalContext{Context: request.Context()})
	response, err := transport.next.RoundTrip(wireRequest)
	if err != nil {
		return nil, sanitizeTransportError(request.Context(), err)
	}
	if response == nil || response.Body == nil {
		return nil, clientError(clientFailureNetwork, "RESPONSE_REJECTED")
	}
	body, err := transport.readAndValidateResponse(request, response)
	if err != nil {
		_ = response.Body.Close()
		return nil, err
	}
	_ = response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	return response, nil
}

func (transport *fixedInventoryTransport) validateRequest(request *http.Request) error {
	base, err := url.Parse(transport.baseURL)
	if err != nil ||
		request.Method != http.MethodGet ||
		request.Body != nil && request.Body != http.NoBody ||
		request.URL.Scheme != "https" ||
		request.URL.Host != base.Host {
		return clientError(clientFailureProtocol, "REQUEST_SURFACE_REJECTED")
	}
	path := request.URL.EscapedPath()
	if request.URL.RawQuery != "" {
		path += "?" + request.URL.RawQuery
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.nextPath >= len(fixedWirePaths) ||
		path != fixedWirePaths[transport.nextPath] {
		return clientError(clientFailureProtocol, "REQUEST_SEQUENCE_REJECTED")
	}
	transport.nextPath++
	if values := request.Header.Values("Authorization"); len(values) != 1 ||
		values[0] != "PVEAPIToken="+transport.tokenID+"="+string(transport.secret) {
		return clientError(clientFailureCredential, "AUTHORIZATION_REJECTED")
	}
	if values := request.Header.Values("Accept"); !slices.Equal(values, []string{"application/json"}) {
		return clientError(clientFailureProtocol, "ACCEPT_HEADER_REJECTED")
	}
	if values := request.Header.Values("User-Agent"); !slices.Equal(values, []string{"aiops-proxmox-inventory/1"}) {
		return clientError(clientFailureProtocol, "USER_AGENT_REJECTED")
	}
	for key := range request.Header {
		switch http.CanonicalHeaderKey(key) {
		case "Authorization", "Accept", "User-Agent":
		default:
			return clientError(clientFailureProtocol, "REQUEST_HEADER_REJECTED")
		}
	}
	return nil
}

func (transport *fixedInventoryTransport) readAndValidateResponse(
	request *http.Request,
	response *http.Response,
) ([]byte, error) {
	switch response.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, clientError(clientFailureCredential, "TOKEN_SCOPE_REJECTED")
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable:
		duration, err := parseRetryAfter(response.Header.Values("Retry-After"), transport.now())
		if err != nil {
			return nil, err
		}
		return nil, &retryAfterError{duration: duration}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if response.StatusCode >= 500 {
			return nil, clientError(clientFailureIncomplete, "UPSTREAM_INCOMPLETE")
		}
		return nil, clientError(clientFailureProtocol, "UPSTREAM_STATUS_REJECTED")
	}
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return nil, clientError(clientFailureProtocol, "CONTENT_TYPE_REJECTED")
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		return nil, clientError(clientFailureProtocol, "CONTENT_TYPE_REJECTED")
	}
	if response.ContentLength > transport.maxBytes {
		return nil, clientError(clientFailureBudget, "RESPONSE_LIMIT_REJECTED")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, transport.maxBytes+1))
	if err != nil {
		if contextErr := request.Context().Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, clientError(clientFailureNetwork, "RESPONSE_READ_REJECTED")
	}
	if int64(len(body)) > transport.maxBytes {
		clear(body)
		return nil, clientError(clientFailureBudget, "RESPONSE_LIMIT_REJECTED")
	}
	path := request.URL.EscapedPath()
	if request.URL.RawQuery != "" {
		path += "?" + request.URL.RawQuery
	}
	if err := validateWireEnvelope(path, body); err != nil {
		clear(body)
		return nil, err
	}
	return body, nil
}

func (transport *fixedInventoryTransport) CloseIdleConnections() {
	if transport == nil || transport.next == nil {
		return
	}
	transport.next.CloseIdleConnections()
}

func (transport *fixedInventoryTransport) Clear() {
	if transport == nil {
		return
	}
	clear(transport.secret)
	transport.secret = nil
	transport.tokenID = ""
	transport.baseURL = ""
}

func parseRetryAfter(values []string, now time.Time) (time.Duration, error) {
	if len(values) != 1 ||
		values[0] == "" ||
		strings.Contains(values[0], ",") ||
		now.IsZero() {
		return 0, clientError(clientFailureProtocol, "PROVIDER_RETRY_AFTER_REJECTED")
	}
	if seconds, err := strconv.ParseInt(values[0], 10, 64); err == nil {
		duration := time.Duration(seconds) * time.Second
		if duration <= 0 || duration > 60*time.Second {
			return 0, clientError(clientFailureProtocol, "PROVIDER_RETRY_AFTER_REJECTED")
		}
		return duration, nil
	}
	when, err := http.ParseTime(values[0])
	if err != nil {
		return 0, clientError(clientFailureProtocol, "PROVIDER_RETRY_AFTER_REJECTED")
	}
	duration := when.Sub(now.UTC())
	if duration <= 0 || duration > 60*time.Second || duration%time.Second != 0 {
		return 0, clientError(clientFailureProtocol, "PROVIDER_RETRY_AFTER_REJECTED")
	}
	return duration, nil
}

func validateWireEnvelope(path string, body []byte) error {
	if len(body) == 0 || !utf8.Valid(body) {
		return clientError(clientFailureProtocol, "RESPONSE_JSON_REJECTED")
	}
	if err := rejectDuplicateJSONFields(body); err != nil {
		return err
	}
	if err := rejectSensitiveJSON(body); err != nil {
		return err
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil ||
		len(envelope) != 1 ||
		envelope["data"] == nil {
		return clientError(clientFailureProtocol, "RESPONSE_ENVELOPE_REJECTED")
	}
	data := envelope["data"]
	switch path {
	case "/api2/json/version":
		return validateVersionData(data)
	case "/api2/json/cluster/status":
		return validateClusterStatusData(data)
	case "/api2/json/nodes":
		return validateNodeData(data)
	case "/api2/json/cluster/resources?type=vm":
		return validateResourceData(data)
	default:
		return clientError(clientFailureProtocol, "RESPONSE_PATH_REJECTED")
	}
}

func validateVersionData(data []byte) error {
	object, err := strictObject(data, []string{"release", "repoid", "version"}, []string{"release", "repoid", "version"})
	if err != nil {
		return err
	}
	for _, key := range []string{"release", "repoid", "version"} {
		if _, err := strictString(object[key]); err != nil {
			return err
		}
	}
	return nil
}

func validateClusterStatusData(data []byte) error {
	var rows []json.RawMessage
	if err := json.Unmarshal(data, &rows); err != nil || len(rows) < 2 || len(rows) > maxInventoryResources {
		return clientError(clientFailureProtocol, "CLUSTER_STATUS_REJECTED")
	}
	clusterCount := 0
	nodeCount := 0
	var declaredNodes uint64
	for _, row := range rows {
		base, err := strictObject(
			row,
			[]string{"id", "ip", "level", "local", "name", "nodeid", "nodes", "online", "quorate", "type", "version"},
			[]string{"type"},
		)
		if err != nil {
			return err
		}
		kind, err := strictString(base["type"])
		if err != nil {
			return err
		}
		switch kind {
		case "cluster":
			clusterCount++
			if _, err := strictObject(
				row,
				[]string{"id", "name", "nodes", "quorate", "type", "version"},
				[]string{"id", "name", "nodes", "quorate", "type", "version"},
			); err != nil {
				return err
			}
			if _, err := strictString(base["id"]); err != nil {
				return err
			}
			if _, err := strictString(base["name"]); err != nil {
				return err
			}
			for _, key := range []string{"quorate", "version"} {
				if _, err := strictNonNegativeInteger(base[key]); err != nil {
					return err
				}
			}
			declaredNodes, err = strictNonNegativeInteger(base["nodes"])
			if err != nil {
				return err
			}
		case "node":
			nodeCount++
			if _, err := strictObject(
				row,
				[]string{"id", "ip", "level", "local", "name", "nodeid", "online", "type"},
				[]string{"id", "name", "online", "type"},
			); err != nil {
				return err
			}
			for _, key := range []string{"id", "name"} {
				if _, err := strictString(base[key]); err != nil {
					return err
				}
			}
			if base["level"] != nil {
				if _, err := strictString(base["level"]); err != nil {
					return err
				}
			}
			if _, err := strictNonNegativeInteger(base["online"]); err != nil {
				return err
			}
			if err := validateOptionalIntegers(base, "local", "nodeid"); err != nil {
				return err
			}
			if err := validateOptionalStrings(base, "ip"); err != nil {
				return err
			}
		default:
			return clientError(clientFailureProtocol, "CLUSTER_MEMBER_TYPE_REJECTED")
		}
	}
	if clusterCount != 1 || nodeCount == 0 || declaredNodes != uint64(nodeCount) {
		return clientError(clientFailureProtocol, "CLUSTER_STATUS_REJECTED")
	}
	return nil
}

func validateNodeData(data []byte) error {
	var rows []json.RawMessage
	if err := json.Unmarshal(data, &rows); err != nil || len(rows) == 0 || len(rows) > maxInventoryResources {
		return clientError(clientFailureProtocol, "NODE_LIST_REJECTED")
	}
	for _, row := range rows {
		object, err := strictObject(
			row,
			[]string{
				"cpu", "disk", "id", "level", "maxcpu", "maxdisk", "maxmem",
				"mem", "node", "ssl_fingerprint", "status", "type", "uptime",
			},
			[]string{"maxcpu", "maxmem", "node", "status", "type"},
		)
		if err != nil {
			return err
		}
		for _, key := range []string{"node", "status", "type"} {
			if _, err := strictString(object[key]); err != nil {
				return err
			}
		}
		for _, key := range []string{"maxcpu", "maxmem"} {
			if _, err := strictNonNegativeInteger(object[key]); err != nil {
				return err
			}
		}
		if err := validateOptionalStrings(object, "id", "level", "ssl_fingerprint"); err != nil {
			return err
		}
		if err := validateOptionalIntegers(object, "disk", "maxdisk", "mem", "uptime"); err != nil {
			return err
		}
		if err := validateOptionalNumbers(object, "cpu"); err != nil {
			return err
		}
	}
	return nil
}

func validateResourceData(data []byte) error {
	var rows []json.RawMessage
	if err := json.Unmarshal(data, &rows); err != nil || len(rows) > maxInventoryResources {
		if len(rows) > maxInventoryResources {
			return clientError(clientFailureBudget, "RESOURCE_LIMIT_REJECTED")
		}
		return clientError(clientFailureProtocol, "RESOURCE_LIST_REJECTED")
	}
	for _, row := range rows {
		object, err := strictObject(
			row,
			[]string{
				"cgroup-mode", "content", "cpu", "disk", "diskread", "diskwrite",
				"hastate", "id", "level", "maxcpu", "maxdisk", "maxmem", "mem",
				"name", "netin", "netout", "node", "plugintype", "pool", "shared",
				"status", "storage", "tags", "template", "type", "uptime", "vmid",
			},
			[]string{"id", "maxcpu", "maxmem", "name", "node", "status", "template", "type", "vmid"},
		)
		if err != nil {
			return err
		}
		for _, key := range []string{"id", "name", "node", "status", "type"} {
			if _, err := strictString(object[key]); err != nil {
				return err
			}
		}
		for _, key := range []string{"maxcpu", "maxmem", "template", "vmid"} {
			value, err := strictNonNegativeInteger(object[key])
			if err != nil {
				return err
			}
			if key == "template" && value > 1 {
				return clientError(clientFailureProtocol, "RESOURCE_TEMPLATE_REJECTED")
			}
		}
		if err := validateOptionalStrings(
			object,
			"content", "hastate", "level", "plugintype", "pool", "storage", "tags",
		); err != nil {
			return err
		}
		if err := validateOptionalIntegers(
			object,
			"cgroup-mode", "disk", "diskread", "diskwrite", "maxdisk", "mem",
			"netin", "netout", "shared", "uptime",
		); err != nil {
			return err
		}
		if err := validateOptionalNumbers(object, "cpu"); err != nil {
			return err
		}
	}
	return nil
}

func strictObject(
	raw []byte,
	allowed []string,
	required []string,
) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, clientError(clientFailureProtocol, "RESPONSE_OBJECT_REJECTED")
	}
	for key := range object {
		if !slices.Contains(allowed, key) {
			return nil, clientError(clientFailureProtocol, "RESPONSE_FIELD_REJECTED")
		}
	}
	for _, key := range required {
		if object[key] == nil {
			return nil, clientError(clientFailureProtocol, "RESPONSE_FIELD_REJECTED")
		}
	}
	return object, nil
}

func strictString(raw []byte) (string, error) {
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil || !safeRuntimeText(value, 0, 512) {
		return "", clientError(clientFailureProtocol, "RESPONSE_STRING_REJECTED")
	}
	return value, nil
}

func strictNonNegativeInteger(raw []byte) (uint64, error) {
	if len(raw) == 0 {
		return 0, clientError(clientFailureProtocol, "RESPONSE_NUMBER_REJECTED")
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&number) != nil {
		return 0, clientError(clientFailureProtocol, "RESPONSE_NUMBER_REJECTED")
	}
	text := number.String()
	if text == "" {
		return 0, clientError(clientFailureProtocol, "RESPONSE_NUMBER_REJECTED")
	}
	for _, character := range text {
		if character < '0' || character > '9' {
			return 0, clientError(clientFailureProtocol, "RESPONSE_NUMBER_REJECTED")
		}
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, clientError(clientFailureProtocol, "RESPONSE_NUMBER_REJECTED")
	}
	return value, nil
}

func strictNonNegativeNumber(raw []byte) (float64, error) {
	if len(raw) == 0 {
		return 0, clientError(clientFailureProtocol, "RESPONSE_NUMBER_REJECTED")
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&number) != nil {
		return 0, clientError(clientFailureProtocol, "RESPONSE_NUMBER_REJECTED")
	}
	value, err := strconv.ParseFloat(number.String(), 64)
	if err != nil || value < 0 {
		return 0, clientError(clientFailureProtocol, "RESPONSE_NUMBER_REJECTED")
	}
	return value, nil
}

func validateOptionalStrings(object map[string]json.RawMessage, keys ...string) error {
	for _, key := range keys {
		if object[key] == nil {
			continue
		}
		if _, err := strictString(object[key]); err != nil {
			return err
		}
	}
	return nil
}

func validateOptionalIntegers(object map[string]json.RawMessage, keys ...string) error {
	for _, key := range keys {
		if object[key] == nil {
			continue
		}
		if _, err := strictNonNegativeInteger(object[key]); err != nil {
			return err
		}
	}
	return nil
}

func validateOptionalNumbers(object map[string]json.RawMessage, keys ...string) error {
	for _, key := range keys {
		if object[key] == nil {
			continue
		}
		if _, err := strictNonNegativeNumber(object[key]); err != nil {
			return err
		}
	}
	return nil
}

func rejectDuplicateJSONFields(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := walkJSONValue(decoder); err != nil {
		return clientError(clientFailureProtocol, "RESPONSE_JSON_REJECTED")
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return clientError(clientFailureProtocol, "RESPONSE_TRAILING_REJECTED")
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder) error {
	tokenValue, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := tokenValue.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyValue, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyValue.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid object end")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid array end")
		}
	default:
		return errors.New("invalid delimiter")
	}
	return nil
}

func rejectSensitiveJSON(body []byte) error {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil || containsSensitiveJSON(value) {
		return clientError(clientFailureDLP, "RESPONSE_DLP_REJECTED")
	}
	return nil
}

func containsSensitiveJSON(value any) bool {
	switch typed := value.(type) {
	case string:
		return unsafeWireText(typed)
	case []any:
		for _, item := range typed {
			if containsSensitiveJSON(item) {
				return true
			}
		}
	case map[string]any:
		for key, item := range typed {
			if unsafeWireText(key) || containsSensitiveJSON(item) {
				return true
			}
		}
	}
	return false
}

func unsafeWireText(value string) bool {
	if !utf8.ValidString(value) || credentialPattern.MatchString(value) {
		return true
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"://",
		"-----begin",
		"authorization",
		"bearer ",
		"cloud-init",
		"cloud_init",
		"console",
		"credential",
		"dsn=",
		"endpoint",
		"password",
		"private_key",
		"private-key",
		"pveapitoken",
		"secret",
		"ssh-rsa",
		"token",
		"vnc",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func sanitizeSDKError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	var retry *retryAfterError
	if errors.As(err, &retry) {
		return retry
	}
	var contract *clientContractError
	if errors.As(err, &contract) {
		return contract
	}
	return clientError(clientFailureProtocol, "SDK_RESPONSE_REJECTED")
}

func sanitizeTransportError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	var certificateError *tls.CertificateVerificationError
	var hostError x509.HostnameError
	if errors.As(err, &certificateError) || errors.As(err, &hostError) {
		return clientError(clientFailureTrust, "TLS_VERIFY_REJECTED")
	}
	var operationError *net.OpError
	if errors.As(err, &operationError) {
		return clientError(clientFailureNetwork, "NETWORK_REJECTED")
	}
	return clientError(clientFailureNetwork, "NETWORK_REJECTED")
}

type noopSDKLogger struct{}

func (noopSDKLogger) Debugf(string, ...interface{}) {}
func (noopSDKLogger) Errorf(string, ...interface{}) {}
func (noopSDKLogger) Infof(string, ...interface{})  {}
func (noopSDKLogger) Warnf(string, ...interface{})  {}

func clientError(stage clientFailureStage, code string) error {
	return &clientContractError{stage: stage, code: code}
}

func clientErrorStage(err error) clientFailureStage {
	var value *clientContractError
	if !errors.As(err, &value) {
		return 0
	}
	return value.stage
}

func providerRetryAfter(err error) (time.Duration, bool) {
	var value *retryAfterError
	if !errors.As(err, &value) {
		return 0, false
	}
	return value.duration, true
}

func providerError(code string) error {
	return fmt.Errorf("%w: %s", errProviderContract, code)
}

func digestStringTuple(fields ...string) string {
	hasher := sha256.New()
	for _, field := range fields {
		writeDigestFrame(hasher, []byte(field))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func writeDigestFrame(writer io.Writer, value []byte) {
	_, _ = writer.Write([]byte{1})
	length := uint32(len(value))
	_, _ = writer.Write([]byte{
		byte(length >> 24),
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	})
	_, _ = writer.Write(value)
}
