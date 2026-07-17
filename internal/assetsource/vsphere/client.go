package vsphere

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/session"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/methods"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"
)

const (
	connectTimeout         = 5 * time.Second
	soapCallTimeout        = 30 * time.Second
	sessionCleanupTimeout  = 5 * time.Second
	maxResponseHeaderBytes = 64 << 10
	maxSOAPResponseBytes   = 8 << 20
	maxSOAPConnections     = 2
)

var (
	errClientContract   = errors.New("vsphere client contract violation")
	errProviderContract = errors.New("vsphere provider contract violation")
)

type clientFailureStage uint8

const (
	clientFailureRuntime clientFailureStage = iota + 1
	clientFailureIdentity
	clientFailureTrust
	clientFailureNetwork
	clientFailureCredential
	clientFailureProtocol
	clientFailureCleanup
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

type vcenterIdentity struct {
	InstanceUUID string
	APIVersion   string
	APIType      string
}

type sessionIdentity struct {
	UserName string
}

type entityPrivilegeSnapshot struct {
	Entity     types.ManagedObjectReference
	Privileges []string
}

type rootProbeObject struct {
	Reference types.ManagedObjectReference
	Name      string
}

type rootProbeResult struct {
	Objects []rootProbeObject
}

type validationClient interface {
	Identity() vcenterIdentity
	TLSPeerDigest() string
	CurrentSession(context.Context) (sessionIdentity, error)
	EffectivePrivileges(
		context.Context,
		[]types.ManagedObjectReference,
		string,
	) ([]entityPrivilegeSnapshot, error)
	ProbeRoots(context.Context, []types.ManagedObjectReference) (rootProbeResult, error)
	Close(context.Context) error
}

type ClientFactory struct {
	binding       discoverysource.RuntimeBinding
	openClient    func(context.Context, resolvedRuntime) (validationClient, error)
	observeMethod func(string)
}

func NewClientFactory(binding discoverysource.RuntimeBinding) (ClientFactory, error) {
	if binding.ProviderKind != providerKind ||
		binding.ProfileCode != profileCode ||
		binding.RevisionStatus != assetcatalog.SourceRevisionValidating &&
			binding.RevisionStatus != assetcatalog.SourceRevisionPublished {
		return ClientFactory{}, providerError("FACTORY_BINDING_REJECTED")
	}
	return ClientFactory{binding: binding}, nil
}

type openedValidationClient struct {
	client    validationClient
	authority authoritySnapshot
}

func (factory ClientFactory) open(
	ctx context.Context,
	runtime discoverysource.BoundRuntime,
) (openedValidationClient, error) {
	if ctx == nil ||
		factory.binding.ProviderKind != providerKind ||
		factory.binding.ProfileCode != profileCode {
		return openedValidationClient{}, clientError(clientFailureRuntime, "FACTORY_REJECTED")
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
		return openedValidationClient{}, clientError(clientFailureRuntime, "RUNTIME_ACCESS_REJECTED")
	}
	defer resolved.Clear()
	if !resolved.valid() {
		return openedValidationClient{}, clientError(clientFailureRuntime, "RUNTIME_MATERIAL_REJECTED")
	}

	authority := authoritySnapshot{
		instanceUUID:  resolved.authority.instanceUUID,
		environmentID: resolved.authority.environmentID,
		roots:         slices.Clone(resolved.authority.roots),
		rootDigest:    resolved.authority.rootDigest,
	}
	opener := factory.openClient
	if opener == nil {
		opener = func(ctx context.Context, runtime resolvedRuntime) (validationClient, error) {
			return openGovmomiValidationClient(ctx, runtime, factory.observeMethod)
		}
	}
	client, err := opener(ctx, resolved)
	if err != nil {
		authority.Clear()
		return openedValidationClient{}, err
	}
	if client == nil {
		authority.Clear()
		return openedValidationClient{}, clientError(clientFailureProtocol, "CLIENT_REJECTED")
	}
	return openedValidationClient{client: client, authority: authority}, nil
}

type peerCertificateDigest struct {
	mu     sync.Mutex
	digest string
}

func (value *peerCertificateDigest) set(certificate *x509.Certificate) error {
	if value == nil || certificate == nil || len(certificate.Raw) == 0 {
		return clientError(clientFailureTrust, "TLS_PEER_REJECTED")
	}
	digest := sha256.Sum256(certificate.Raw)
	encoded := hex.EncodeToString(digest[:])
	value.mu.Lock()
	defer value.mu.Unlock()
	if value.digest != "" && value.digest != encoded {
		return clientError(clientFailureTrust, "TLS_PEER_DRIFT_REJECTED")
	}
	value.digest = encoded
	return nil
}

func (value *peerCertificateDigest) get() string {
	if value == nil {
		return ""
	}
	value.mu.Lock()
	defer value.mu.Unlock()
	return value.digest
}

func (value *peerCertificateDigest) clear() {
	if value == nil {
		return
	}
	value.mu.Lock()
	value.digest = ""
	value.mu.Unlock()
}

func newSOAPClient(
	endpoint endpointSnapshot,
	trust trustSnapshot,
	observe func(string),
) (*soap.Client, *peerCertificateDigest, error) {
	if !endpoint.valid() || !trust.valid() {
		return nil, nil, clientError(clientFailureRuntime, "CLIENT_CONFIG_REJECTED")
	}
	tlsConfig := clonePinnedTLSConfig(trust.config)
	peerDigest := &peerCertificateDigest{}
	existingVerifyConnection := tlsConfig.VerifyConnection
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if existingVerifyConnection != nil {
			if err := existingVerifyConnection(state); err != nil {
				return err
			}
		}
		if len(state.PeerCertificates) == 0 {
			return clientError(clientFailureTrust, "TLS_PEER_REJECTED")
		}
		return peerDigest.set(state.PeerCertificates[0])
	}

	client := soap.NewClient(cloneURL(endpoint.endpoint), false)
	transport := client.DefaultTransport()
	transport.Proxy = nil
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	transport.DialContext = (&net.Dialer{
		Timeout:   connectTimeout,
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.DisableCompression = true
	transport.ForceAttemptHTTP2 = false
	transport.MaxIdleConns = maxSOAPConnections
	transport.MaxIdleConnsPerHost = maxSOAPConnections
	transport.MaxConnsPerHost = maxSOAPConnections
	transport.IdleConnTimeout = 30 * time.Second
	transport.TLSHandshakeTimeout = connectTimeout
	transport.ResponseHeaderTimeout = soapCallTimeout
	transport.ExpectContinueTimeout = time.Second
	transport.MaxResponseHeaderBytes = maxResponseHeaderBytes
	transport.TLSClientConfig = tlsConfig

	client.Transport = &boundedResponseTransport{
		next:     transport,
		maxBytes: maxSOAPResponseBytes,
	}
	client.Timeout = soapCallTimeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return clientError(clientFailureNetwork, "REDIRECT_REJECTED")
	}
	if observe != nil {
		observe("SOAP_CLIENT_CONSTRUCTED")
	}
	return client, peerDigest, nil
}

type boundedResponseTransport struct {
	next     http.RoundTripper
	maxBytes int64
}

func (transport *boundedResponseTransport) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	if transport == nil ||
		transport.next == nil ||
		transport.maxBytes <= 0 {
		return nil, clientError(clientFailureRuntime, "TRANSPORT_REJECTED")
	}
	response, err := transport.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response == nil || response.Body == nil {
		return nil, clientError(clientFailureNetwork, "RESPONSE_REJECTED")
	}
	if response.ContentLength > transport.maxBytes {
		_ = response.Body.Close()
		return nil, clientError(clientFailureNetwork, "RESPONSE_LIMIT_REJECTED")
	}
	response.Body = &boundedResponseBody{
		body:      response.Body,
		remaining: transport.maxBytes,
	}
	return response, nil
}

func (transport *boundedResponseTransport) CloseIdleConnections() {
	if transport == nil {
		return
	}
	if closer, ok := transport.next.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

type boundedResponseBody struct {
	body      io.ReadCloser
	remaining int64
}

func (body *boundedResponseBody) Read(destination []byte) (int, error) {
	if body == nil || body.body == nil {
		return 0, io.ErrClosedPipe
	}
	if body.remaining <= 0 {
		var probe [1]byte
		count, err := body.body.Read(probe[:])
		if count > 0 {
			return 0, clientError(clientFailureNetwork, "RESPONSE_LIMIT_REJECTED")
		}
		return 0, err
	}
	if int64(len(destination)) > body.remaining {
		destination = destination[:body.remaining]
	}
	count, err := body.body.Read(destination)
	body.remaining -= int64(count)
	return count, err
}

func (body *boundedResponseBody) Close() error {
	if body == nil || body.body == nil {
		return nil
	}
	err := body.body.Close()
	body.body = nil
	body.remaining = 0
	return err
}

type observedRoundTripper struct {
	next    soap.RoundTripper
	observe func(string)
}

func (value observedRoundTripper) RoundTrip(
	ctx context.Context,
	request soap.HasFault,
	response soap.HasFault,
) error {
	if value.observe != nil {
		value.observe(soapMethodName(request))
	}
	return value.next.RoundTrip(ctx, request, response)
}

func soapMethodName(request soap.HasFault) string {
	value := reflect.TypeOf(request)
	if value == nil {
		return "UNKNOWN"
	}
	for value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	return strings.TrimSuffix(value.Name(), "Body")
}

type govmomiValidationClient struct {
	mu        sync.Mutex
	client    *vim25.Client
	soap      *soap.Client
	session   *session.Manager
	peer      *peerCertificateDigest
	closed    bool
	closeErr  error
	closeDone chan struct{}
}

func openGovmomiValidationClient(
	ctx context.Context,
	runtime resolvedRuntime,
	observe func(string),
) (validationClient, error) {
	return openGovmomiValidationClientWithCallTimeout(
		ctx,
		runtime,
		observe,
		soapCallTimeout,
	)
}

func openGovmomiValidationClientWithCallTimeout(
	ctx context.Context,
	runtime resolvedRuntime,
	observe func(string),
	callTimeout time.Duration,
) (_ validationClient, returnedErr error) {
	if ctx == nil ||
		!runtime.valid() ||
		callTimeout <= 0 ||
		callTimeout > soapCallTimeout {
		return nil, clientError(clientFailureRuntime, "RUNTIME_MATERIAL_REJECTED")
	}
	soapClient, peerDigest, err := newSOAPClient(runtime.endpoint, runtime.trust, nil)
	if err != nil {
		return nil, err
	}
	client := &govmomiValidationClient{
		soap:      soapClient,
		peer:      peerDigest,
		closeDone: make(chan struct{}),
	}
	defer func() {
		panicValue := recover()
		if returnedErr != nil || panicValue != nil {
			cleanupContext, cancel := context.WithTimeout(
				context.WithoutCancel(ctx),
				sessionCleanupTimeout,
			)
			_ = client.Close(cleanupContext)
			cancel()
		}
		if panicValue != nil {
			panic(panicValue)
		}
	}()

	if observe != nil {
		observe("RetrieveServiceContent")
	}
	vimClient, err := func() (*vim25.Client, error) {
		serviceContentContext, cancelServiceContent := context.WithTimeout(
			ctx,
			callTimeout,
		)
		defer cancelServiceContent()
		return vim25.NewClient(serviceContentContext, soapClient)
	}()
	if err != nil {
		if isTLSVerificationError(err) {
			return nil, clientError(clientFailureTrust, "TLS_TRUST_REJECTED")
		}
		return nil, clientError(clientFailureNetwork, "SERVICE_CONTENT_FAILED")
	}
	if !validValidationServiceContent(vimClient.ServiceContent) {
		return nil, clientError(clientFailureProtocol, "SERVICE_CONTENT_REJECTED")
	}
	about := vimClient.ServiceContent.About
	if !validVCenterIdentity(vcenterIdentity{
		InstanceUUID: about.InstanceUuid,
		APIVersion:   about.ApiVersion,
		APIType:      about.ApiType,
	}, runtime.authority) {
		return nil, clientError(clientFailureIdentity, "VCENTER_IDENTITY_REJECTED")
	}
	if peerDigest.get() == "" {
		return nil, clientError(clientFailureTrust, "TLS_PEER_REJECTED")
	}
	if observe != nil {
		vimClient.RoundTripper = observedRoundTripper{next: soapClient, observe: observe}
	}
	client.client = vimClient
	client.session = session.NewManager(vimClient)

	password := string(runtime.credential.password)
	user := url.UserPassword(runtime.credential.userName, password)
	password = ""
	loginErr := func() error {
		loginContext, cancelLogin := context.WithTimeout(ctx, callTimeout)
		defer cancelLogin()
		return client.session.Login(loginContext, user)
	}()
	if loginErr != nil {
		if isTLSVerificationError(loginErr) {
			return nil, clientError(clientFailureTrust, "TLS_TRUST_REJECTED")
		}
		return nil, clientError(clientFailureCredential, "CREDENTIAL_OPEN_REJECTED")
	}
	return client, nil
}

func validValidationServiceContent(content types.ServiceContent) bool {
	return content.SessionManager != nil &&
		validServiceReference(*content.SessionManager, "SessionManager") &&
		content.AuthorizationManager != nil &&
		validServiceReference(*content.AuthorizationManager, "AuthorizationManager") &&
		validServiceReference(content.PropertyCollector, "PropertyCollector")
}

func validServiceReference(
	reference types.ManagedObjectReference,
	expectedType string,
) bool {
	return reference.Type == expectedType &&
		managedObjectValue.MatchString(reference.Value) &&
		safeRuntimeText(reference.Value, 1, 256)
}

func (client *govmomiValidationClient) Identity() vcenterIdentity {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed || client.client == nil {
		return vcenterIdentity{}
	}
	about := client.client.ServiceContent.About
	return vcenterIdentity{
		InstanceUUID: about.InstanceUuid,
		APIVersion:   about.ApiVersion,
		APIType:      about.ApiType,
	}
}

func (client *govmomiValidationClient) TLSPeerDigest() string {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return ""
	}
	return client.peer.get()
}

func (client *govmomiValidationClient) CurrentSession(
	ctx context.Context,
) (sessionIdentity, error) {
	client.mu.Lock()
	if client.closed ||
		client.client == nil ||
		client.client.ServiceContent.SessionManager == nil {
		client.mu.Unlock()
		return sessionIdentity{}, clientError(clientFailureCredential, "SESSION_REJECTED")
	}
	vimClient := client.client
	sessionReference := *vimClient.ServiceContent.SessionManager
	client.mu.Unlock()

	request := types.RetrievePropertiesEx{
		This: vimClient.ServiceContent.PropertyCollector,
		SpecSet: []types.PropertyFilterSpec{{
			PropSet: []types.PropertySpec{{
				Type:    "SessionManager",
				PathSet: []string{"currentSession"},
			}},
			ObjectSet: []types.ObjectSpec{{Obj: sessionReference}},
		}},
		Options: types.RetrieveOptions{MaxObjects: 1},
	}
	callContext, cancel := context.WithTimeout(ctx, soapCallTimeout)
	defer cancel()
	response, err := methods.RetrievePropertiesEx(callContext, vimClient, &request)
	if err != nil ||
		response == nil ||
		response.Returnval == nil ||
		response.Returnval.Token != "" ||
		len(response.Returnval.Objects) != 1 {
		return sessionIdentity{}, clientError(clientFailureCredential, "SESSION_REJECTED")
	}
	object := response.Returnval.Objects[0]
	if compareManagedObjectReference(object.Obj, sessionReference) != 0 ||
		len(object.MissingSet) != 0 ||
		len(object.PropSet) != 1 ||
		object.PropSet[0].Name != "currentSession" {
		return sessionIdentity{}, clientError(clientFailureCredential, "SESSION_REJECTED")
	}
	var current *types.UserSession
	switch value := object.PropSet[0].Val.(type) {
	case types.UserSession:
		current = &value
	case *types.UserSession:
		current = value
	}
	if current == nil || !safeRuntimeText(current.UserName, 1, 256) {
		return sessionIdentity{}, clientError(clientFailureCredential, "SESSION_REJECTED")
	}
	return sessionIdentity{UserName: current.UserName}, nil
}

func (client *govmomiValidationClient) EffectivePrivileges(
	ctx context.Context,
	roots []types.ManagedObjectReference,
	userName string,
) ([]entityPrivilegeSnapshot, error) {
	client.mu.Lock()
	if client.closed || client.client == nil {
		client.mu.Unlock()
		return nil, clientError(clientFailureProtocol, "PRIVILEGE_CHECK_REJECTED")
	}
	vimClient := client.client
	client.mu.Unlock()
	if !safeRuntimeText(userName, 1, 256) ||
		len(roots) == 0 ||
		len(roots) > maxAuthorityRoots {
		return nil, clientError(clientFailureProtocol, "PRIVILEGE_CHECK_REJECTED")
	}

	callContext, cancel := context.WithTimeout(ctx, soapCallTimeout)
	defer cancel()
	results, err := object.NewAuthorizationManager(vimClient).
		FetchUserPrivilegeOnEntities(callContext, slices.Clone(roots), userName)
	if err != nil {
		return nil, clientError(clientFailureProtocol, "PRIVILEGE_CHECK_FAILED")
	}
	snapshots := make([]entityPrivilegeSnapshot, 0, len(results))
	for _, result := range results {
		privileges := slices.Clone(result.Privileges)
		slices.Sort(privileges)
		snapshots = append(snapshots, entityPrivilegeSnapshot{
			Entity:     result.Entity,
			Privileges: privileges,
		})
	}
	slices.SortFunc(snapshots, func(left, right entityPrivilegeSnapshot) int {
		return compareManagedObjectReference(left.Entity, right.Entity)
	})
	return snapshots, nil
}

func (client *govmomiValidationClient) ProbeRoots(
	ctx context.Context,
	roots []types.ManagedObjectReference,
) (rootProbeResult, error) {
	client.mu.Lock()
	if client.closed || client.client == nil {
		client.mu.Unlock()
		return rootProbeResult{}, clientError(clientFailureProtocol, "PROPERTY_PROBE_REJECTED")
	}
	vimClient := client.client
	client.mu.Unlock()
	if len(roots) == 0 || len(roots) > maxAuthorityRoots {
		return rootProbeResult{}, clientError(clientFailureProtocol, "PROPERTY_PROBE_REJECTED")
	}

	objectSet := make([]types.ObjectSpec, 0, len(roots))
	typesPresent := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		if !validAuthorityRoot(root) {
			return rootProbeResult{}, clientError(clientFailureProtocol, "PROPERTY_PROBE_REJECTED")
		}
		objectSet = append(objectSet, types.ObjectSpec{Obj: root})
		typesPresent[root.Type] = struct{}{}
	}
	typeCodes := make([]string, 0, len(typesPresent))
	for typeCode := range typesPresent {
		typeCodes = append(typeCodes, typeCode)
	}
	slices.Sort(typeCodes)
	propertySet := make([]types.PropertySpec, 0, len(typeCodes))
	for _, typeCode := range typeCodes {
		propertySet = append(propertySet, types.PropertySpec{
			Type:    typeCode,
			PathSet: []string{"name"},
		})
	}

	request := types.RetrievePropertiesEx{
		This: vimClient.ServiceContent.PropertyCollector,
		SpecSet: []types.PropertyFilterSpec{{
			PropSet:   propertySet,
			ObjectSet: objectSet,
		}},
		Options: types.RetrieveOptions{MaxObjects: int32(len(roots))},
	}
	callContext, cancel := context.WithTimeout(ctx, soapCallTimeout)
	defer cancel()
	response, err := methods.RetrievePropertiesEx(callContext, vimClient, &request)
	if err != nil ||
		response == nil ||
		response.Returnval == nil ||
		response.Returnval.Token != "" ||
		len(response.Returnval.Objects) != len(roots) {
		return rootProbeResult{}, clientError(clientFailureProtocol, "PROPERTY_PROBE_FAILED")
	}

	objects := make([]rootProbeObject, 0, len(roots))
	for _, objectContent := range response.Returnval.Objects {
		if len(objectContent.MissingSet) != 0 ||
			len(objectContent.PropSet) != 1 ||
			objectContent.PropSet[0].Name != "name" {
			return rootProbeResult{}, clientError(clientFailureProtocol, "PROPERTY_PROBE_REJECTED")
		}
		name, ok := objectContent.PropSet[0].Val.(string)
		if !ok || !safeRuntimeText(name, 1, 256) || sensitiveRuntimeText(name) {
			return rootProbeResult{}, clientError(clientFailureProtocol, "PROPERTY_PROBE_REJECTED")
		}
		objects = append(objects, rootProbeObject{
			Reference: objectContent.Obj,
			Name:      name,
		})
	}
	slices.SortFunc(objects, func(left, right rootProbeObject) int {
		return compareManagedObjectReference(left.Reference, right.Reference)
	})
	return rootProbeResult{Objects: objects}, nil
}

func (client *govmomiValidationClient) Close(ctx context.Context) error {
	if client == nil {
		return clientError(clientFailureCleanup, "INACTIVE_CLIENT")
	}
	client.mu.Lock()
	if client.closed {
		done := client.closeDone
		client.mu.Unlock()
		<-done
		client.mu.Lock()
		err := client.closeErr
		client.mu.Unlock()
		return err
	}
	client.closed = true
	manager := client.session
	soapClient := client.soap
	peer := client.peer
	client.client = nil
	client.session = nil
	client.soap = nil
	client.peer = nil
	client.mu.Unlock()

	var closeErr error
	if manager != nil {
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionCleanupTimeout)
		if err := manager.Logout(cleanupContext); err != nil {
			closeErr = clientError(clientFailureCleanup, "SESSION_LOGOUT_FAILED")
		}
		cancel()
	}
	if soapClient != nil {
		soapClient.CloseIdleConnections()
		if transport := soapClient.DefaultTransport(); transport != nil {
			if config := transport.TLSClientConfig; config != nil {
				config.RootCAs = nil
				config.ServerName = ""
				config.VerifyConnection = nil
			}
			transport.TLSClientConfig = nil
		}
		soapClient.Jar = nil
	}
	if peer != nil {
		peer.clear()
	}

	client.mu.Lock()
	client.closeErr = closeErr
	close(client.closeDone)
	client.mu.Unlock()
	return closeErr
}

func clientError(stage clientFailureStage, code string) error {
	return &clientContractError{stage: stage, code: strings.ToUpper(code)}
}

func clientErrorStage(err error) clientFailureStage {
	var contractError *clientContractError
	if errors.As(err, &contractError) {
		return contractError.stage
	}
	return 0
}

func providerError(code string) error {
	return fmt.Errorf("%w: %s", errProviderContract, strings.ToUpper(code))
}

func isTLSVerificationError(err error) bool {
	if clientErrorStage(err) == clientFailureTrust {
		return true
	}
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
