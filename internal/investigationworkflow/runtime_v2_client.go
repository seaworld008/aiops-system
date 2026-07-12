package investigationworkflow

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	workflowservicepb "go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"google.golang.org/grpc"
)

const (
	runtimeV2StarterIdentity  = "aiops-investigation-read-v2-starter"
	runtimeV2ControlIdentity  = "aiops-investigation-read-v2-control"
	runtimeV2AttestationLimit = 5 * time.Second
	runtimeV2OptionsRedaction = "<aiops-read-client-options>"
	runtimeV2StarterRedaction = "<aiops-read-starter-client>"
	runtimeV2ControlRedaction = "<aiops-read-control-client>"
)

var (
	errRuntimeV2ClientRejected = errors.New("investigation READ runtime client rejected")
	runtimeV2StarterClientSeal = &runtimeV2RoleMarker{role: 1}
	runtimeV2ControlClientSeal = &runtimeV2RoleMarker{role: 2}
	runtimeV2ConnectionSeal    = &runtimeV2ConnectionMarker{value: 1}
)

type runtimeV2RoleMarker struct{ role byte }
type runtimeV2ConnectionMarker struct{ value byte }

// RuntimeV2ClientOptions is intentionally narrower than client.Options. Every
// trust input is explicit; default endpoints, implicit system-root fallback,
// API keys, headers, interceptors, and caller-selected converters have no
// representation here.
type RuntimeV2ClientOptions struct {
	HostPort   string
	Namespace  string
	ServerName string
	RootCAs    *x509.CertPool
	// Certificate must carry a current clientAuth leaf and a matching ECDSA
	// P-256 private key. The builder detaches all mutable certificate storage.
	Certificate tls.Certificate
}

func (RuntimeV2ClientOptions) String() string   { return runtimeV2OptionsRedaction }
func (RuntimeV2ClientOptions) GoString() string { return runtimeV2OptionsRedaction }

func (RuntimeV2ClientOptions) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, runtimeV2OptionsRedaction)
}

func (RuntimeV2ClientOptions) MarshalJSON() ([]byte, error) {
	return nil, errRuntimeV2ClientRejected
}

func (*RuntimeV2ClientOptions) UnmarshalJSON([]byte) error {
	return errRuntimeV2ClientRejected
}

type runtimeV2ClientLifecycle struct {
	assembly  sync.RWMutex
	closeOnce sync.Once
	closed    atomic.Bool
	closeErr  error
}

// runtimeV2ConnectionBinding is an opaque production-only proof that role
// clients were dialed against the same explicit Temporal deployment and trust
// roots. Role-specific client certificates are deliberately not part of it.
type runtimeV2ConnectionBinding struct {
	hostPort        string
	namespace       string
	serverName      string
	rootCAs         *x509.CertPool
	deploymentProof [sha256.Size]byte
	attested        bool
	seal            *runtimeV2ConnectionMarker
}

type runtimeV2StarterTransport interface {
	ExecuteWorkflow(context.Context, client.StartWorkflowOptions, interface{}, ...interface{}) (client.WorkflowRun, error)
	DescribeWorkflowExecution(context.Context, string, string) (*workflowservicepb.DescribeWorkflowExecutionResponse, error)
	FirstWorkflowHistoryEvent(context.Context, string, string) (*historypb.HistoryEvent, error)
}

type runtimeV2SDKStarterTransport struct{ client.Client }

func (transport *runtimeV2SDKStarterTransport) FirstWorkflowHistoryEvent(
	ctx context.Context,
	workflowID string,
	runID string,
) (event *historypb.HistoryEvent, returnedErr error) {
	defer func() {
		if recover() != nil {
			if contextErr := canonicalRuntimeV2ContextError(ctx); contextErr == context.Canceled || contextErr == context.DeadlineExceeded {
				event, returnedErr = nil, contextErr
				return
			}
			event, returnedErr = nil, errRuntimeV2ClientRejected
		}
	}()
	if transport == nil || nilInterface(transport.Client) {
		return nil, errRuntimeV2ClientRejected
	}
	if contextErr := canonicalRuntimeV2ContextError(ctx); contextErr != nil {
		return nil, contextErr
	}
	iterator := transport.GetWorkflowHistory(
		ctx, workflowID, runID, false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT,
	)
	if iterator == nil || !iterator.HasNext() {
		if contextErr := canonicalRuntimeV2ContextError(ctx); contextErr == context.Canceled || contextErr == context.DeadlineExceeded {
			return nil, contextErr
		}
		return nil, errRuntimeV2ClientRejected
	}
	event, err := iterator.Next()
	if err != nil || event == nil {
		if contextErr := canonicalRuntimeV2ContextError(ctx); contextErr == context.Canceled || contextErr == context.DeadlineExceeded {
			return nil, contextErr
		}
		return nil, errRuntimeV2ClientRejected
	}
	return event, nil
}

// RuntimeV2StarterClient is a sealed capability for starting and verifying
// v2 READ workflows. It cannot be used to construct a Worker.
type RuntimeV2StarterClient struct {
	transport  runtimeV2StarterTransport
	converter  *runtimeV2DataConverter
	connection *runtimeV2ConnectionBinding
	namespace  string
	seal       *runtimeV2RoleMarker
	self       *RuntimeV2StarterClient
	lifecycle  *runtimeV2ClientLifecycle
}

// RuntimeV2ControlClient is a separate sealed capability for the trusted
// control-plane Worker. It cannot be passed to the v2 Starter.
type RuntimeV2ControlClient struct {
	sdk        client.Client
	converter  *runtimeV2DataConverter
	connection *runtimeV2ConnectionBinding
	namespace  string
	seal       *runtimeV2RoleMarker
	self       *RuntimeV2ControlClient
	lifecycle  *runtimeV2ClientLifecycle
}

// DialRuntimeV2StarterClient creates the Starter-only Temporal capability with
// the package-owned v2 converter and an explicit TLS 1.3 mTLS profile. Until
// supervised process assembly lands, production callsites are repository-gated
// to zero.
func DialRuntimeV2StarterClient(
	ctx context.Context,
	options RuntimeV2ClientOptions,
) (createdClient *RuntimeV2StarterClient, returnedErr error) {
	var sdk client.Client
	defer func() {
		if recover() != nil {
			closeRuntimeV2SDK(sdk)
			createdClient, returnedErr = nil, errRuntimeV2ClientRejected
		}
	}()
	if contextErr := canonicalRuntimeV2ContextError(ctx); contextErr != nil {
		return nil, contextErr
	}
	sdkOptions, err := runtimeV2SDKOptions(options, runtimeV2StarterIdentity)
	if err != nil {
		return nil, errRuntimeV2ClientRejected
	}
	connection, err := newRuntimeV2ConnectionBinding(sdkOptions)
	if err != nil {
		return nil, errRuntimeV2ClientRejected
	}
	sdk, err = client.DialContext(ctx, sdkOptions)
	if err != nil || nilInterface(sdk) {
		closeRuntimeV2SDK(sdk)
		sdk = nil
		if contextErr := canonicalRuntimeV2ContextError(ctx); contextErr == context.Canceled || contextErr == context.DeadlineExceeded {
			return nil, contextErr
		}
		return nil, errRuntimeV2ClientRejected
	}
	connection, err = attestRuntimeV2Connection(ctx, sdk, connection)
	if err != nil {
		closeRuntimeV2SDK(sdk)
		sdk = nil
		if contextErr := canonicalRuntimeV2ContextError(ctx); contextErr == context.Canceled || contextErr == context.DeadlineExceeded {
			return nil, contextErr
		}
		return nil, errRuntimeV2ClientRejected
	}
	createdClient, err = newRuntimeV2StarterClient(&runtimeV2SDKStarterTransport{Client: sdk}, sdkOptions.Namespace)
	if err != nil {
		closeRuntimeV2SDK(sdk)
		return nil, errRuntimeV2ClientRejected
	}
	createdClient.connection = connection
	return createdClient, nil
}

// DialRuntimeV2ControlClient creates the control-Worker-only Temporal
// capability with the package-owned v2 converter and explicit TLS 1.3 mTLS.
// Until supervised process assembly lands, production callsites are
// repository-gated to zero.
func DialRuntimeV2ControlClient(
	ctx context.Context,
	options RuntimeV2ClientOptions,
) (createdClient *RuntimeV2ControlClient, returnedErr error) {
	var sdk client.Client
	defer func() {
		if recover() != nil {
			closeRuntimeV2SDK(sdk)
			createdClient, returnedErr = nil, errRuntimeV2ClientRejected
		}
	}()
	if contextErr := canonicalRuntimeV2ContextError(ctx); contextErr != nil {
		return nil, contextErr
	}
	sdkOptions, err := runtimeV2SDKOptions(options, runtimeV2ControlIdentity)
	if err != nil {
		return nil, errRuntimeV2ClientRejected
	}
	connection, err := newRuntimeV2ConnectionBinding(sdkOptions)
	if err != nil {
		return nil, errRuntimeV2ClientRejected
	}
	sdk, err = client.DialContext(ctx, sdkOptions)
	if err != nil || nilInterface(sdk) {
		closeRuntimeV2SDK(sdk)
		sdk = nil
		if contextErr := canonicalRuntimeV2ContextError(ctx); contextErr == context.Canceled || contextErr == context.DeadlineExceeded {
			return nil, contextErr
		}
		return nil, errRuntimeV2ClientRejected
	}
	connection, err = attestRuntimeV2Connection(ctx, sdk, connection)
	if err != nil {
		closeRuntimeV2SDK(sdk)
		sdk = nil
		if contextErr := canonicalRuntimeV2ContextError(ctx); contextErr == context.Canceled || contextErr == context.DeadlineExceeded {
			return nil, contextErr
		}
		return nil, errRuntimeV2ClientRejected
	}
	createdClient, err = newRuntimeV2ControlClient(sdk, sdkOptions.Namespace)
	if err != nil {
		closeRuntimeV2SDK(sdk)
		return nil, errRuntimeV2ClientRejected
	}
	createdClient.connection = connection
	return createdClient, nil
}

func canonicalRuntimeV2ContextError(ctx context.Context) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = errRuntimeV2ClientRejected
		}
	}()
	if nilInterface(ctx) {
		return errRuntimeV2ClientRejected
	}
	switch contextErr := ctx.Err(); contextErr {
	case nil:
		return nil
	case context.Canceled:
		return context.Canceled
	case context.DeadlineExceeded:
		return context.DeadlineExceeded
	default:
		return errRuntimeV2ClientRejected
	}
}

func closeRuntimeV2SDK(sdk client.Client) {
	if nilInterface(sdk) {
		return
	}
	defer func() { _ = recover() }()
	sdk.Close()
}

func newRuntimeV2ConnectionBinding(options client.Options) (*runtimeV2ConnectionBinding, error) {
	tlsConfiguration := options.ConnectionOptions.TLS
	if !validRuntimeV2HostPort(options.HostPort) || options.Namespace == "" ||
		!temporalNamespacePattern.MatchString(options.Namespace) || tlsConfiguration == nil ||
		!validRuntimeV2ServerName(tlsConfiguration.ServerName) || tlsConfiguration.RootCAs == nil ||
		len(tlsConfiguration.RootCAs.Subjects()) == 0 ||
		(options.Identity != runtimeV2StarterIdentity && options.Identity != runtimeV2ControlIdentity) {
		return nil, errRuntimeV2ClientRejected
	}
	return &runtimeV2ConnectionBinding{
		hostPort: strings.Clone(options.HostPort), namespace: strings.Clone(options.Namespace),
		serverName: strings.Clone(tlsConfiguration.ServerName), rootCAs: tlsConfiguration.RootCAs.Clone(),
		seal: runtimeV2ConnectionSeal,
	}, nil
}

// attestRuntimeV2Connection binds configuration identity to stable facts read
// from the authenticated Temporal server. Endpoint, SNI, roots, and namespace
// alone are insufficient when one load balancer can route independent role
// dials to different deployments.
func attestRuntimeV2Connection(
	ctx context.Context,
	sdk client.Client,
	binding *runtimeV2ConnectionBinding,
) (*runtimeV2ConnectionBinding, error) {
	if canonicalRuntimeV2ContextError(ctx) != nil || nilInterface(sdk) || binding == nil ||
		binding.seal != runtimeV2ConnectionSeal {
		return nil, errRuntimeV2ClientRejected
	}
	service := sdk.WorkflowService()
	if nilInterface(service) {
		return nil, errRuntimeV2ClientRejected
	}
	probeContext, cancel := context.WithTimeout(ctx, runtimeV2AttestationLimit)
	defer cancel()
	cluster, err := service.GetClusterInfo(probeContext, &workflowservicepb.GetClusterInfoRequest{})
	if err != nil || cluster == nil {
		return nil, errRuntimeV2ClientRejected
	}
	described, err := service.DescribeNamespace(probeContext, &workflowservicepb.DescribeNamespaceRequest{
		Namespace: binding.namespace, WeakConsistency: false,
	})
	if err != nil || described == nil || described.NamespaceInfo == nil ||
		described.NamespaceInfo.State != enumspb.NAMESPACE_STATE_REGISTERED ||
		described.NamespaceInfo.Name != binding.namespace {
		return nil, errRuntimeV2ClientRejected
	}
	proof, err := runtimeV2DeploymentProof(
		cluster.ClusterId,
		cluster.ClusterName,
		described.NamespaceInfo.Name,
		described.NamespaceInfo.Id,
	)
	if err != nil {
		return nil, errRuntimeV2ClientRejected
	}
	attested := *binding
	attested.deploymentProof = proof
	attested.attested = true
	return &attested, nil
}

func runtimeV2DeploymentProof(
	clusterID string,
	clusterName string,
	namespace string,
	namespaceID string,
) ([sha256.Size]byte, error) {
	clusterUUID, err := uuid.Parse(clusterID)
	if err != nil || clusterUUID == uuid.Nil || clusterUUID.String() != clusterID {
		return [sha256.Size]byte{}, errRuntimeV2ClientRejected
	}
	namespaceUUID, err := uuid.Parse(namespaceID)
	if err != nil || namespaceUUID == uuid.Nil || namespaceUUID.String() != namespaceID {
		return [sha256.Size]byte{}, errRuntimeV2ClientRejected
	}
	values := []struct {
		value string
		limit int
	}{
		{clusterName, 255},
		{namespace, 255},
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("aiops-temporal-deployment-binding.v1\x00"))
	_, _ = hasher.Write(clusterUUID[:])
	_, _ = hasher.Write(namespaceUUID[:])
	var length [4]byte
	for _, field := range values {
		if field.value == "" || len(field.value) > field.limit || !utf8.ValidString(field.value) ||
			strings.TrimSpace(field.value) != field.value || runtimeV2IdentityContainsControl(field.value) {
			return [sha256.Size]byte{}, errRuntimeV2ClientRejected
		}
		binary.BigEndian.PutUint32(length[:], uint32(len(field.value)))
		_, _ = hasher.Write(length[:])
		_, _ = hasher.Write([]byte(field.value))
	}
	var proof [sha256.Size]byte
	copy(proof[:], hasher.Sum(nil))
	return proof, nil
}

func runtimeV2IdentityContainsControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return true
		}
	}
	return false
}

func (binding *runtimeV2ConnectionBinding) valid() bool {
	return binding != nil && binding.seal == runtimeV2ConnectionSeal &&
		binding.attested && binding.deploymentProof != [sha256.Size]byte{} &&
		validRuntimeV2HostPort(binding.hostPort) && binding.namespace != "" &&
		temporalNamespacePattern.MatchString(binding.namespace) &&
		validRuntimeV2ServerName(binding.serverName) && binding.rootCAs != nil &&
		len(binding.rootCAs.Subjects()) > 0
}

func (binding *runtimeV2ConnectionBinding) same(other *runtimeV2ConnectionBinding) bool {
	return binding.valid() && other.valid() && binding.hostPort == other.hostPort &&
		binding.namespace == other.namespace && binding.serverName == other.serverName &&
		binding.rootCAs.Equal(other.rootCAs) &&
		bytes.Equal(binding.deploymentProof[:], other.deploymentProof[:])
}

func runtimeV2SDKOptions(options RuntimeV2ClientOptions, identity string) (client.Options, error) {
	if identity != runtimeV2StarterIdentity && identity != runtimeV2ControlIdentity {
		return client.Options{}, errRuntimeV2ClientRejected
	}
	if !validRuntimeV2HostPort(options.HostPort) ||
		!temporalNamespacePattern.MatchString(options.Namespace) || options.Namespace == "" ||
		!validRuntimeV2ServerName(options.ServerName) || options.RootCAs == nil ||
		len(options.RootCAs.Subjects()) == 0 {
		return client.Options{}, errRuntimeV2ClientRejected
	}
	certificate, err := validateAndCloneRuntimeV2Certificate(options.Certificate, time.Now())
	if err != nil {
		return client.Options{}, errRuntimeV2ClientRejected
	}
	dataConverter, err := newRuntimeV2DataConverter()
	if err != nil {
		return client.Options{}, errRuntimeV2ClientRejected
	}
	failureConverter, err := newRuntimeV2FailureConverter(dataConverter)
	if err != nil {
		return client.Options{}, errRuntimeV2ClientRejected
	}
	return client.Options{
		HostPort: strings.Clone(options.HostPort), Namespace: strings.Clone(options.Namespace), Identity: identity,
		DataConverter:    dataConverter,
		FailureConverter: failureConverter,
		ConnectionOptions: client.ConnectionOptions{TLS: &tls.Config{
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			RootCAs: options.RootCAs.Clone(), ServerName: strings.Clone(options.ServerName),
			Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2"},
		}, DialOptions: []grpc.DialOption{grpc.WithNoProxy()}},
		PayloadLimits: client.PayloadLimitOptions{
			PayloadSizeWarning: maximumHistoryDTOBytes, MemoSizeWarning: maximumHistoryDTOBytes,
		},
	}, nil
}

func validRuntimeV2HostPort(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "/?#@\x00\r\n\t") {
		return false
	}
	host, encodedPort, err := net.SplitHostPort(value)
	if err != nil || !validRuntimeV2EndpointHost(host) {
		return false
	}
	port, err := strconv.Atoi(encodedPort)
	return err == nil && port >= 1 && port <= 65535 && strconv.Itoa(port) == encodedPort
}

func validRuntimeV2EndpointHost(value string) bool {
	if value == "" || strings.Contains(value, "%") {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	return validRuntimeV2DNSName(value)
}

func validRuntimeV2ServerName(value string) bool {
	if value == "" || strings.HasPrefix(value, "*.") || strings.Contains(value, "%") {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	return validRuntimeV2DNSName(value)
}

func validRuntimeV2DNSName(value string) bool {
	if len(value) == 0 || len(value) > 253 || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
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

func validateAndCloneRuntimeV2Certificate(
	certificate tls.Certificate,
	now time.Time,
) (cloned tls.Certificate, returnedErr error) {
	defer func() {
		if recover() != nil {
			cloned, returnedErr = tls.Certificate{}, errRuntimeV2ClientRejected
		}
	}()
	if len(certificate.Certificate) < 1 || len(certificate.Certificate) > 8 || certificate.PrivateKey == nil {
		return tls.Certificate{}, errRuntimeV2ClientRejected
	}
	parsed := make([]*x509.Certificate, len(certificate.Certificate))
	for index, raw := range certificate.Certificate {
		if len(raw) == 0 || len(raw) > 64*1024 {
			return tls.Certificate{}, errRuntimeV2ClientRejected
		}
		decoded, err := x509.ParseCertificate(raw)
		if err != nil {
			return tls.Certificate{}, errRuntimeV2ClientRejected
		}
		parsed[index] = decoded
	}
	leaf := parsed[0]
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.IsCA ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(leaf.ExtKeyUsage) != 1 ||
		leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 {
		return tls.Certificate{}, errRuntimeV2ClientRejected
	}
	if certificate.Leaf != nil && !bytes.Equal(certificate.Leaf.Raw, leaf.Raw) {
		return tls.Certificate{}, errRuntimeV2ClientRejected
	}
	privateKey, ok := certificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || privateKey == nil || privateKey.Curve != elliptic.P256() || privateKey.D == nil ||
		privateKey.PublicKey.X == nil || privateKey.PublicKey.Y == nil || privateKey.D.Sign() <= 0 ||
		privateKey.D.Cmp(elliptic.P256().Params().N) >= 0 ||
		!elliptic.P256().IsOnCurve(privateKey.PublicKey.X, privateKey.PublicKey.Y) {
		return tls.Certificate{}, errRuntimeV2ClientRejected
	}
	derivedX, derivedY := elliptic.P256().ScalarBaseMult(privateKey.D.Bytes())
	if derivedX == nil || derivedY == nil || derivedX.Cmp(privateKey.PublicKey.X) != 0 ||
		derivedY.Cmp(privateKey.PublicKey.Y) != 0 {
		return tls.Certificate{}, errRuntimeV2ClientRejected
	}
	detachedPrivateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(), X: new(big.Int).Set(privateKey.PublicKey.X),
			Y: new(big.Int).Set(privateKey.PublicKey.Y),
		},
		D: new(big.Int).Set(privateKey.D),
	}
	leafPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return tls.Certificate{}, errRuntimeV2ClientRejected
	}
	privatePublic, err := x509.MarshalPKIXPublicKey(&detachedPrivateKey.PublicKey)
	if err != nil || !bytes.Equal(leafPublic, privatePublic) {
		return tls.Certificate{}, errRuntimeV2ClientRejected
	}
	cloned = tls.Certificate{
		Certificate: make([][]byte, len(certificate.Certificate)), PrivateKey: detachedPrivateKey,
	}
	for index, raw := range certificate.Certificate {
		cloned.Certificate[index] = bytes.Clone(raw)
	}
	cloned.Leaf, err = x509.ParseCertificate(cloned.Certificate[0])
	if err != nil {
		return tls.Certificate{}, errRuntimeV2ClientRejected
	}
	cloned.OCSPStaple = bytes.Clone(certificate.OCSPStaple)
	cloned.SignedCertificateTimestamps = make([][]byte, len(certificate.SignedCertificateTimestamps))
	for index, timestamp := range certificate.SignedCertificateTimestamps {
		cloned.SignedCertificateTimestamps[index] = bytes.Clone(timestamp)
	}
	cloned.SupportedSignatureAlgorithms = append(
		[]tls.SignatureScheme(nil), certificate.SupportedSignatureAlgorithms...,
	)
	return cloned, nil
}

func newRuntimeV2StarterClient(
	transport runtimeV2StarterTransport,
	namespace string,
) (*RuntimeV2StarterClient, error) {
	if nilInterface(transport) || !temporalNamespacePattern.MatchString(namespace) {
		return nil, errRuntimeV2ClientRejected
	}
	dataConverter, err := newRuntimeV2DataConverter()
	if err != nil {
		return nil, errRuntimeV2ClientRejected
	}
	created := &RuntimeV2StarterClient{
		transport: transport, converter: dataConverter, namespace: strings.Clone(namespace),
		seal: runtimeV2StarterClientSeal, lifecycle: &runtimeV2ClientLifecycle{},
	}
	created.self = created
	return created, nil
}

func newRuntimeV2ControlClient(
	sdk client.Client,
	namespace string,
) (*RuntimeV2ControlClient, error) {
	if nilInterface(sdk) || !temporalNamespacePattern.MatchString(namespace) {
		return nil, errRuntimeV2ClientRejected
	}
	dataConverter, err := newRuntimeV2DataConverter()
	if err != nil {
		return nil, errRuntimeV2ClientRejected
	}
	created := &RuntimeV2ControlClient{
		sdk: sdk, converter: dataConverter, namespace: strings.Clone(namespace),
		seal: runtimeV2ControlClientSeal, lifecycle: &runtimeV2ClientLifecycle{},
	}
	created.self = created
	return created, nil
}

func (runtimeClient *RuntimeV2StarterClient) structurallyValid() bool {
	return runtimeClient != nil && runtimeClient.seal == runtimeV2StarterClientSeal && runtimeClient.self == runtimeClient &&
		runtimeClient.lifecycle != nil && runtimeClient.converter.valid() &&
		!nilInterface(runtimeClient.transport) && temporalNamespacePattern.MatchString(runtimeClient.namespace)
}

func (runtimeClient *RuntimeV2StarterClient) valid() bool {
	return runtimeClient.structurallyValid() && !runtimeClient.lifecycle.closed.Load()
}

func (runtimeClient *RuntimeV2StarterClient) validForStarter() bool {
	return runtimeClient.valid()
}

func (runtimeClient *RuntimeV2StarterClient) starterTransportValue() runtimeV2StarterTransport {
	if !runtimeClient.valid() {
		return nil
	}
	return runtimeClient.transport
}

func (runtimeClient *RuntimeV2StarterClient) namespaceValue() string {
	if !runtimeClient.valid() {
		return ""
	}
	return runtimeClient.namespace
}

// Namespace returns only the non-sensitive namespace and is empty for an
// invalid, copied, or closed Starter capability.
func (runtimeClient *RuntimeV2StarterClient) Namespace() string {
	return runtimeClient.namespaceValue()
}

// sameTemporalConnection returns true only when both live role capabilities
// were produced by public production dials against one exact endpoint,
// namespace, TLS server identity, root pool, server cluster ID, and namespace
// ID. It never exposes those values.
func (runtimeClient *RuntimeV2StarterClient) sameTemporalConnection(
	controlClient *RuntimeV2ControlClient,
) bool {
	return runtimeClient.valid() && controlClient.valid() &&
		runtimeClient.connection != nil && controlClient.connection != nil &&
		runtimeClient.namespace == runtimeClient.connection.namespace &&
		controlClient.namespace == controlClient.connection.namespace &&
		runtimeClient.connection.same(controlClient.connection)
}

func (runtimeClient *RuntimeV2ControlClient) structurallyValid() bool {
	return runtimeClient != nil && runtimeClient.seal == runtimeV2ControlClientSeal && runtimeClient.self == runtimeClient &&
		runtimeClient.lifecycle != nil && runtimeClient.converter.valid() && !nilInterface(runtimeClient.sdk) &&
		temporalNamespacePattern.MatchString(runtimeClient.namespace)
}

func (runtimeClient *RuntimeV2ControlClient) valid() bool {
	return runtimeClient.structurallyValid() && !runtimeClient.lifecycle.closed.Load()
}

func (runtimeClient *RuntimeV2ControlClient) sdkValue() client.Client {
	if !runtimeClient.valid() {
		return nil
	}
	return runtimeClient.sdk
}

func (runtimeClient *RuntimeV2ControlClient) namespaceValue() string {
	if !runtimeClient.valid() {
		return ""
	}
	return runtimeClient.namespace
}

// Namespace returns only the non-sensitive namespace and is empty for an
// invalid, copied, or closed control-plane Worker capability.
func (runtimeClient *RuntimeV2ControlClient) Namespace() string {
	return runtimeClient.namespaceValue()
}

// Close permanently invalidates the Starter capability and closes its
// underlying SDK transport at most once when that transport owns a closer.
func (runtimeClient *RuntimeV2StarterClient) Close() error {
	if !runtimeClient.structurallyValid() {
		return errRuntimeV2ClientRejected
	}
	lifecycle := runtimeClient.lifecycle
	lifecycle.closeOnce.Do(func() {
		lifecycle.assembly.Lock()
		defer lifecycle.assembly.Unlock()
		lifecycle.closed.Store(true)
		defer func() {
			if recover() != nil {
				lifecycle.closeErr = errRuntimeV2ClientRejected
			}
		}()
		if closer, ok := runtimeClient.transport.(interface{ Close() }); ok {
			closer.Close()
		}
	})
	return lifecycle.closeErr
}

// Close permanently invalidates the control-plane Worker capability and
// closes its underlying SDK client at most once.
func (runtimeClient *RuntimeV2ControlClient) Close() error {
	if !runtimeClient.structurallyValid() {
		return errRuntimeV2ClientRejected
	}
	lifecycle := runtimeClient.lifecycle
	lifecycle.closeOnce.Do(func() {
		lifecycle.assembly.Lock()
		defer lifecycle.assembly.Unlock()
		lifecycle.closed.Store(true)
		defer func() {
			if recover() != nil {
				lifecycle.closeErr = errRuntimeV2ClientRejected
			}
		}()
		runtimeClient.sdk.Close()
	})
	return lifecycle.closeErr
}

func (RuntimeV2StarterClient) String() string   { return runtimeV2StarterRedaction }
func (RuntimeV2StarterClient) GoString() string { return runtimeV2StarterRedaction }

func (RuntimeV2StarterClient) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, runtimeV2StarterRedaction)
}

func (RuntimeV2StarterClient) MarshalJSON() ([]byte, error) {
	return nil, errRuntimeV2ClientRejected
}

func (*RuntimeV2StarterClient) UnmarshalJSON([]byte) error {
	return errRuntimeV2ClientRejected
}

func (RuntimeV2ControlClient) String() string   { return runtimeV2ControlRedaction }
func (RuntimeV2ControlClient) GoString() string { return runtimeV2ControlRedaction }

func (RuntimeV2ControlClient) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, runtimeV2ControlRedaction)
}

func (RuntimeV2ControlClient) MarshalJSON() ([]byte, error) {
	return nil, errRuntimeV2ClientRejected
}

func (*RuntimeV2ControlClient) UnmarshalJSON([]byte) error {
	return errRuntimeV2ClientRejected
}
