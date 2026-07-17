package vsphere

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/vim25/types"
)

const (
	testTenantID       = "11111111-1111-4111-8111-111111111111"
	testWorkspaceID    = "22222222-2222-4222-8222-222222222222"
	testSourceID       = "33333333-3333-4333-8333-333333333333"
	testEnvironmentID  = "44444444-4444-4444-8444-444444444444"
	testInstanceUUID   = "55555555-5555-4555-8555-555555555555"
	otherInstanceUUID  = "66666666-6666-4666-8666-666666666666"
	testTLSPeerDigest  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testRevisionDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var testAuthorityRoot = types.ManagedObjectReference{Type: "Folder", Value: "group-d1"}

func TestValidateRejectsDifferentVCenterInstanceUUID(t *testing.T) {
	t.Parallel()

	request := validValidationRequest()
	binding := validatingBinding(request)
	client := successfulFakeValidationClient()
	client.identity.InstanceUUID = otherInstanceUUID
	provider := providerWithFakeClient(t, binding, client)
	runtime := validBoundRuntime(t, binding)

	proof, err := provider.Validate(context.Background(), runtime, request)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if proof.Outcome != assetcatalog.ValidationOutcomeFailed ||
		proof.Code != "AUTHORITY_REJECTED" ||
		len(proof.Checks) != 1 ||
		proof.Checks[0].Kind != discoverysource.ValidationCheckIdentity ||
		proof.Checks[0].Code != "IDENTITY_REJECTED" ||
		proof.Checks[0].Passed {
		t.Fatalf("identity mismatch proof = %#v", proof)
	}
	if err := discoverysource.ValidateValidationResult(request, proof, nil); err != nil {
		t.Fatalf("identity mismatch violates discoverysource contract: %v", err)
	}
}

func TestValidateEnforcesMissingAndExtraPrivilegeSemantics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		privileges       []string
		wantOutcome      assetcatalog.ValidationOutcome
		wantCode         string
		wantWarningCount int64
	}{
		{
			name:             "exact read only set",
			privileges:       slices.Clone(requiredReadPrivileges),
			wantOutcome:      assetcatalog.ValidationOutcomeSucceeded,
			wantCode:         "VALIDATION_SUCCEEDED",
			wantWarningCount: 0,
		},
		{
			name:        "missing System Read",
			privileges:  []string{"System.Anonymous", "System.View"},
			wantOutcome: assetcatalog.ValidationOutcomeFailed,
			wantCode:    "VALIDATION_REJECTED",
		},
		{
			name: "extra mutation privilege is a stable warning",
			privileges: []string{
				"System.Anonymous",
				"System.Read",
				"System.View",
				"VirtualMachine.Interact.PowerOn",
			},
			wantOutcome:      assetcatalog.ValidationOutcomeSucceeded,
			wantCode:         "VALIDATION_SUCCEEDED",
			wantWarningCount: 1,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			request := validValidationRequest()
			binding := validatingBinding(request)
			client := successfulFakeValidationClient()
			client.privilegeSets[0].Privileges = slices.Clone(test.privileges)
			provider := providerWithFakeClient(t, binding, client)
			runtime := validBoundRuntime(t, binding)

			proof, err := provider.Validate(context.Background(), runtime, request)
			if err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if proof.Outcome != test.wantOutcome || proof.Code != test.wantCode {
				t.Fatalf("proof = %#v, want outcome=%q code=%q", proof, test.wantOutcome, test.wantCode)
			}
			if err := discoverysource.ValidateValidationResult(request, proof, nil); err != nil {
				t.Fatalf("proof violates discoverysource contract: %v", err)
			}

			if test.wantOutcome == assetcatalog.ValidationOutcomeSucceeded {
				fixedProbe := validationCheck(t, proof, discoverysource.ValidationCheckFixedProbe)
				if fixedProbe.Count != test.wantWarningCount {
					t.Fatalf("fixed probe warning count = %d, want %d", fixedProbe.Count, test.wantWarningCount)
				}
			} else {
				if len(proof.Checks) != 1 ||
					proof.Checks[0].Kind != discoverysource.ValidationCheckFixedProbe ||
					proof.Checks[0].Code != "FIXED_PROBE_REJECTED" {
					t.Fatalf("missing privilege proof = %#v", proof)
				}
			}
		})
	}
}

func TestValidatePropagatesCallerCancellationFromOpen(t *testing.T) {
	tests := []struct {
		name    string
		newCall func() (context.Context, context.CancelFunc, func())
		wantErr error
	}{
		{
			name: "cancel",
			newCall: func() (context.Context, context.CancelFunc, func()) {
				ctx, cancel := context.WithCancel(context.Background())
				return ctx, cancel, cancel
			},
			wantErr: context.Canceled,
		},
		{
			name: "deadline",
			newCall: func() (context.Context, context.CancelFunc, func()) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				return ctx, cancel, func() {}
			},
			wantErr: context.DeadlineExceeded,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			request := validValidationRequest()
			binding := validatingBinding(request)
			ctx, cancel, trigger := test.newCall()
			defer cancel()
			provider := providerWithOpenClient(
				t,
				binding,
				func(callContext context.Context, _ resolvedRuntime) (validationClient, error) {
					trigger()
					<-callContext.Done()
					return nil, clientError(clientFailureNetwork, "CALLER_CONTEXT_REJECTED")
				},
			)
			runtime := validBoundRuntime(t, binding)

			proof, err := provider.Validate(ctx, runtime, request)
			requireZeroValidationProof(t, proof)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Validate() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestValidatePropagatesCallerCancellationFromValidationStages(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*fakeValidationClient, context.CancelFunc)
	}{
		{
			name: "current session",
			configure: func(client *fakeValidationClient, cancel context.CancelFunc) {
				client.currentSession = func(context.Context) (sessionIdentity, error) {
					cancel()
					return sessionIdentity{}, clientError(clientFailureCredential, "SESSION_REJECTED")
				}
			},
		},
		{
			name: "effective privileges",
			configure: func(client *fakeValidationClient, cancel context.CancelFunc) {
				client.effectivePrivileges = func(
					context.Context,
					[]types.ManagedObjectReference,
					string,
				) ([]entityPrivilegeSnapshot, error) {
					cancel()
					return nil, clientError(clientFailureProtocol, "PRIVILEGE_CHECK_REJECTED")
				}
			},
		},
		{
			name: "root probe",
			configure: func(client *fakeValidationClient, cancel context.CancelFunc) {
				client.probeRoots = func(
					context.Context,
					[]types.ManagedObjectReference,
				) (rootProbeResult, error) {
					cancel()
					return rootProbeResult{}, clientError(clientFailureProtocol, "PROPERTY_PROBE_REJECTED")
				}
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			request := validValidationRequest()
			binding := validatingBinding(request)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := successfulFakeValidationClient()
			test.configure(client, cancel)
			provider := providerWithFakeClient(t, binding, client)
			runtime := validBoundRuntime(t, binding)

			proof, err := provider.Validate(ctx, runtime, request)
			requireZeroValidationProof(t, proof)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Validate() error = %v, want context.Canceled", err)
			}
			if client.closeCalls.Load() != 1 {
				t.Fatalf("close calls = %d, want 1", client.closeCalls.Load())
			}
		})
	}
}

func TestValidateUsesRealSOAPSimulatorAndOnlyFixedReadSurface(t *testing.T) {
	model := simulator.VPX()
	if err := model.Create(); err != nil {
		t.Fatalf("create simulator model: %v", err)
	}
	t.Cleanup(model.Remove)
	model.Service.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server := model.Service.NewServer()
	t.Cleanup(server.Close)

	endpointURL := *server.URL
	user := endpointURL.User
	endpointURL.User = nil
	if user == nil {
		t.Fatal("simulator URL has no credential")
	}
	password, ok := user.Password()
	if !ok || password == "" {
		t.Fatal("simulator URL has no password")
	}

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	endpoint, err := NewEndpointHandle(endpointURL.String())
	if err != nil {
		t.Fatalf("NewEndpointHandle() error = %v", err)
	}
	credential, err := NewCredentialHandle(user.Username(), []byte(password))
	if err != nil {
		t.Fatalf("NewCredentialHandle() error = %v", err)
	}
	trust, err := NewTrustHandle(&tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: endpointURL.Hostname(),
	}, TLSCompatibilityStrict)
	if err != nil {
		t.Fatalf("NewTrustHandle() error = %v", err)
	}
	authority, err := NewAuthorityHandle(
		model.ServiceContent.About.InstanceUuid,
		testEnvironmentID,
		[]types.ManagedObjectReference{model.RootFolder.Reference()},
	)
	if err != nil {
		t.Fatalf("NewAuthorityHandle() error = %v", err)
	}
	material, err := NewRuntimeMaterial(endpoint, credential, trust, authority)
	if err != nil {
		t.Fatalf("NewRuntimeMaterial() error = %v", err)
	}

	request := validValidationRequest()
	binding := validatingBinding(request)
	runtime, err := discoverysource.BindRuntime(
		binding,
		&material,
		func(*RuntimeMaterial) error { return nil },
		func(value *RuntimeMaterial) { value.Clear() },
	)
	if err != nil {
		t.Fatalf("BindRuntime() error = %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })

	factory, err := NewClientFactory(binding)
	if err != nil {
		t.Fatalf("NewClientFactory() error = %v", err)
	}
	var methodMu sync.Mutex
	var methods []string
	factory.observeMethod = func(method string) {
		methodMu.Lock()
		methods = append(methods, method)
		methodMu.Unlock()
	}
	provider, err := New(factory)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	proof, err := provider.Validate(context.Background(), runtime, request)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if proof.Outcome != assetcatalog.ValidationOutcomeSucceeded ||
		proof.Code != "VALIDATION_SUCCEEDED" {
		t.Fatalf("proof = %#v", proof)
	}
	if err := discoverysource.ValidateValidationResult(request, proof, nil); err != nil {
		t.Fatalf("proof violates discoverysource contract: %v", err)
	}
	for _, kind := range []discoverysource.ValidationCheckKind{
		discoverysource.ValidationCheckIdentity,
		discoverysource.ValidationCheckTrustOrSignature,
		discoverysource.ValidationCheckCredentialOpen,
		discoverysource.ValidationCheckFixedProbe,
	} {
		if validationCheck(t, proof, kind).DigestSHA256 == "" {
			t.Fatalf("%s check does not bind a digest: %#v", kind, proof)
		}
	}

	methodMu.Lock()
	gotMethods := slices.Clone(methods)
	methodMu.Unlock()
	wantMethods := []string{
		"RetrieveServiceContent",
		"Login",
		"RetrievePropertiesEx",
		"FetchUserPrivilegeOnEntities",
		"RetrievePropertiesEx",
		"Logout",
	}
	if !slices.Equal(gotMethods, wantMethods) {
		t.Fatalf("SOAP methods = %v, want exactly %v", gotMethods, wantMethods)
	}

	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("json.Marshal(proof) error = %v", err)
	}
	for _, sensitive := range []string{
		endpointURL.String(),
		user.Username(),
		password,
		model.ServiceContent.About.InstanceUuid,
	} {
		if strings.Contains(string(encoded), sensitive) {
			t.Fatalf("proof leaked runtime/session material %q: %s", sensitive, encoded)
		}
	}
}

func TestOpenGovmomiValidationClientUsesIndependentPerCallBudgets(t *testing.T) {
	const (
		callTimeout    = 250 * time.Millisecond
		callDelay      = 150 * time.Millisecond
		callDelayMilli = int(callDelay / time.Millisecond)
	)

	model := simulator.VPX()
	if err := model.Create(); err != nil {
		t.Fatalf("create simulator model: %v", err)
	}
	t.Cleanup(model.Remove)
	model.DelayConfig.MethodDelay = map[string]int{
		"RetrieveServiceContent": callDelayMilli,
		"Login":                  callDelayMilli,
	}
	model.Service.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server := model.Service.NewServer()
	t.Cleanup(server.Close)

	endpointURL := *server.URL
	user := endpointURL.User
	endpointURL.User = nil
	if user == nil {
		t.Fatal("simulator URL has no credential")
	}
	password, ok := user.Password()
	if !ok || password == "" {
		t.Fatal("simulator URL has no password")
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	endpoint, err := NewEndpointHandle(endpointURL.String())
	if err != nil {
		t.Fatalf("NewEndpointHandle() error = %v", err)
	}
	credential, err := NewCredentialHandle(user.Username(), []byte(password))
	if err != nil {
		t.Fatalf("NewCredentialHandle() error = %v", err)
	}
	trust, err := NewTrustHandle(&tls.Config{
		RootCAs:    roots,
		ServerName: endpointURL.Hostname(),
	}, TLSCompatibilityStrict)
	if err != nil {
		t.Fatalf("NewTrustHandle() error = %v", err)
	}
	authority, err := NewAuthorityHandle(
		model.ServiceContent.About.InstanceUuid,
		testEnvironmentID,
		[]types.ManagedObjectReference{model.RootFolder.Reference()},
	)
	if err != nil {
		t.Fatalf("NewAuthorityHandle() error = %v", err)
	}
	material, err := NewRuntimeMaterial(endpoint, credential, trust, authority)
	if err != nil {
		t.Fatalf("NewRuntimeMaterial() error = %v", err)
	}
	resolved, ok := material.snapshot()
	if !ok {
		t.Fatal("RuntimeMaterial.snapshot() rejected valid fixture")
	}
	defer resolved.Clear()

	var observed []string
	startedAt := time.Now()
	client, err := openGovmomiValidationClientWithCallTimeout(
		context.Background(),
		resolved,
		func(method string) { observed = append(observed, method) },
		callTimeout,
	)
	elapsed := time.Since(startedAt)
	if err != nil {
		t.Fatalf("openGovmomiValidationClientWithCallTimeout() error = %v", err)
	}
	if client == nil {
		t.Fatal("openGovmomiValidationClientWithCallTimeout() returned nil client")
	}
	if err := client.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if elapsed < 2*callDelay {
		t.Fatalf("two delayed SOAP calls completed in %s, want at least %s", elapsed, 2*callDelay)
	}
	if !slices.Equal(observed, []string{
		"RetrieveServiceContent",
		"Login",
		"Logout",
	}) {
		t.Fatalf("SOAP methods = %v", observed)
	}
}

func TestDifferentVCenterInstanceIsRejectedBeforeCredentialLogin(t *testing.T) {
	model := simulator.VPX()
	if err := model.Create(); err != nil {
		t.Fatalf("create simulator model: %v", err)
	}
	t.Cleanup(model.Remove)
	model.Service.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server := model.Service.NewServer()
	t.Cleanup(server.Close)

	endpointURL := *server.URL
	user := endpointURL.User
	endpointURL.User = nil
	if user == nil {
		t.Fatal("simulator URL has no credential")
	}
	password, ok := user.Password()
	if !ok || password == "" {
		t.Fatal("simulator URL has no password")
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	endpoint, err := NewEndpointHandle(endpointURL.String())
	if err != nil {
		t.Fatalf("NewEndpointHandle() error = %v", err)
	}
	credential, err := NewCredentialHandle(user.Username(), []byte(password))
	if err != nil {
		t.Fatalf("NewCredentialHandle() error = %v", err)
	}
	trust, err := NewTrustHandle(&tls.Config{
		RootCAs:    roots,
		ServerName: endpointURL.Hostname(),
	}, TLSCompatibilityStrict)
	if err != nil {
		t.Fatalf("NewTrustHandle() error = %v", err)
	}
	authority, err := NewAuthorityHandle(
		otherInstanceUUID,
		testEnvironmentID,
		[]types.ManagedObjectReference{model.RootFolder.Reference()},
	)
	if err != nil {
		t.Fatalf("NewAuthorityHandle() error = %v", err)
	}
	material, err := NewRuntimeMaterial(endpoint, credential, trust, authority)
	if err != nil {
		t.Fatalf("NewRuntimeMaterial() error = %v", err)
	}
	resolved, ok := material.snapshot()
	if !ok {
		t.Fatal("RuntimeMaterial.snapshot() rejected valid fixture")
	}
	defer resolved.Clear()

	var observed []string
	client, err := openGovmomiValidationClient(
		context.Background(),
		resolved,
		func(method string) { observed = append(observed, method) },
	)
	if client != nil {
		defer client.Close(context.Background())
	}
	var contractError *clientContractError
	if client != nil ||
		!errors.As(err, &contractError) ||
		contractError.code != "VCENTER_IDENTITY_REJECTED" {
		t.Fatalf("openGovmomiValidationClient() = (%#v, %v)", client, err)
	}
	if !slices.Equal(observed, []string{"RetrieveServiceContent"}) {
		t.Fatalf("wrong-instance SOAP methods = %v, want no credential Login", observed)
	}
	proof, mapped := validationFailureForClientError(err)
	if !mapped ||
		proof.Outcome != assetcatalog.ValidationOutcomeFailed ||
		proof.Code != "AUTHORITY_REJECTED" ||
		len(proof.Checks) != 1 ||
		proof.Checks[0].Kind != discoverysource.ValidationCheckIdentity {
		t.Fatalf("wrong-instance failure mapping = (%#v, %v)", proof, mapped)
	}
}

func TestValidateClosesSessionWhenProbeFails(t *testing.T) {
	t.Parallel()

	request := validValidationRequest()
	binding := validatingBinding(request)
	client := successfulFakeValidationClient()
	client.probeErr = context.DeadlineExceeded
	provider := providerWithFakeClient(t, binding, client)
	runtime := validBoundRuntime(t, binding)

	proof, err := provider.Validate(context.Background(), runtime, request)
	if err == nil {
		t.Fatalf("Validate() = %#v, want probe error", proof)
	}
	if client.closeCalls.Load() != 1 {
		t.Fatalf("close calls = %d, want 1", client.closeCalls.Load())
	}
}

func TestValidateClosesSessionAtPanicBoundary(t *testing.T) {
	t.Parallel()

	request := validValidationRequest()
	binding := validatingBinding(request)
	client := successfulFakeValidationClient()
	client.identityPanic = true
	provider := providerWithFakeClient(t, binding, client)
	runtime := validBoundRuntime(t, binding)

	var recovered any
	func() {
		defer func() {
			recovered = recover()
		}()
		_, _ = provider.Validate(context.Background(), runtime, request)
	}()
	if recovered == nil {
		t.Fatal("Validate() swallowed the fixture panic")
	}
	if client.closeCalls.Load() != 1 {
		t.Fatalf("close calls = %d, want 1", client.closeCalls.Load())
	}
}

type fakeValidationClient struct {
	identity            vcenterIdentity
	identityPanic       bool
	peerDigest          string
	session             sessionIdentity
	currentSession      func(context.Context) (sessionIdentity, error)
	privilegeSets       []entityPrivilegeSnapshot
	effectivePrivileges func(context.Context, []types.ManagedObjectReference, string) ([]entityPrivilegeSnapshot, error)
	probe               rootProbeResult
	probeRoots          func(context.Context, []types.ManagedObjectReference) (rootProbeResult, error)
	probeErr            error
	closeErr            error
	closeCalls          atomic.Int64
}

func (client *fakeValidationClient) Identity() vcenterIdentity {
	if client.identityPanic {
		panic("fixture identity panic")
	}
	return client.identity
}

func (client *fakeValidationClient) TLSPeerDigest() string {
	return client.peerDigest
}

func (client *fakeValidationClient) CurrentSession(ctx context.Context) (sessionIdentity, error) {
	if client.currentSession != nil {
		return client.currentSession(ctx)
	}
	return client.session, nil
}

func (client *fakeValidationClient) EffectivePrivileges(
	ctx context.Context,
	roots []types.ManagedObjectReference,
	userName string,
) ([]entityPrivilegeSnapshot, error) {
	if client.effectivePrivileges != nil {
		return client.effectivePrivileges(ctx, roots, userName)
	}
	return slices.Clone(client.privilegeSets), nil
}

func (client *fakeValidationClient) ProbeRoots(
	ctx context.Context,
	roots []types.ManagedObjectReference,
) (rootProbeResult, error) {
	if client.probeRoots != nil {
		return client.probeRoots(ctx, roots)
	}
	if client.probeErr != nil {
		return rootProbeResult{}, client.probeErr
	}
	return client.probe, nil
}

func (client *fakeValidationClient) Close(context.Context) error {
	client.closeCalls.Add(1)
	return client.closeErr
}

func successfulFakeValidationClient() *fakeValidationClient {
	return &fakeValidationClient{
		identity: vcenterIdentity{
			InstanceUUID: testInstanceUUID,
			APIVersion:   "8.0.3.0",
			APIType:      "VirtualCenter",
		},
		peerDigest: testTLSPeerDigest,
		session:    sessionIdentity{UserName: "svc-vsphere-read"},
		privilegeSets: []entityPrivilegeSnapshot{{
			Entity:     testAuthorityRoot,
			Privileges: slices.Clone(requiredReadPrivileges),
		}},
		probe: rootProbeResult{Objects: []rootProbeObject{{
			Reference: testAuthorityRoot,
			Name:      "root",
		}}},
	}
}

func providerWithFakeClient(
	t *testing.T,
	binding discoverysource.RuntimeBinding,
	client validationClient,
) discoverysource.Provider {
	t.Helper()

	return providerWithOpenClient(
		t,
		binding,
		func(context.Context, resolvedRuntime) (validationClient, error) {
			return client, nil
		},
	)
}

func providerWithOpenClient(
	t *testing.T,
	binding discoverysource.RuntimeBinding,
	openClient func(context.Context, resolvedRuntime) (validationClient, error),
) discoverysource.Provider {
	t.Helper()

	factory, err := NewClientFactory(binding)
	if err != nil {
		t.Fatalf("NewClientFactory() error = %v", err)
	}
	factory.openClient = openClient
	provider, err := New(factory)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return provider
}

func requireZeroValidationProof(
	t *testing.T,
	proof discoverysource.ValidationProof,
) {
	t.Helper()
	if proof.Outcome != "" || proof.Code != "" || len(proof.Checks) != 0 {
		t.Fatalf("validation proof = %#v, want zero proof", proof)
	}
}

func validBoundRuntime(
	t *testing.T,
	binding discoverysource.RuntimeBinding,
) discoverysource.BoundRuntime {
	t.Helper()

	endpoint, err := NewEndpointHandle("https://vcenter.example.invalid/sdk")
	if err != nil {
		t.Fatalf("NewEndpointHandle() error = %v", err)
	}
	credential, err := NewCredentialHandle("svc-vsphere-read", []byte("test-password"))
	if err != nil {
		t.Fatalf("NewCredentialHandle() error = %v", err)
	}
	trust, err := NewTrustHandle(&tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    nonEmptyRootPool(t),
		ServerName: "vcenter.example.invalid",
	}, TLSCompatibilityStrict)
	if err != nil {
		t.Fatalf("NewTrustHandle() error = %v", err)
	}
	authority, err := NewAuthorityHandle(
		testInstanceUUID,
		testEnvironmentID,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	if err != nil {
		t.Fatalf("NewAuthorityHandle() error = %v", err)
	}
	material, err := NewRuntimeMaterial(endpoint, credential, trust, authority)
	if err != nil {
		t.Fatalf("NewRuntimeMaterial() error = %v", err)
	}
	runtime, err := discoverysource.BindRuntime(
		binding,
		&material,
		func(*RuntimeMaterial) error { return nil },
		func(value *RuntimeMaterial) { value.Clear() },
	)
	if err != nil {
		t.Fatalf("BindRuntime() error = %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	return runtime
}

func validValidationRequest() discoverysource.ValidationRequest {
	return discoverysource.ValidationRequest{
		Locator: assetcatalog.SourceLocator{
			Scope: assetcatalog.SourceScope{
				TenantID:    testTenantID,
				WorkspaceID: testWorkspaceID,
			},
			SourceID: testSourceID,
		},
		SourceRevision:       20,
		SourceRevisionDigest: testRevisionDigest,
		Limits: discoverysource.Limits{
			MaxPageItems:     500,
			MaxPageRelations: 2_000,
			MaxPageBytes:     8 << 20,
			MaxDocumentBytes: 64 << 10,
		},
	}
}

func validatingBinding(request discoverysource.ValidationRequest) discoverysource.RuntimeBinding {
	return discoverysource.RuntimeBinding{
		Locator:              request.Locator,
		SourceRevision:       request.SourceRevision,
		SourceRevisionDigest: request.SourceRevisionDigest,
		RevisionStatus:       assetcatalog.SourceRevisionValidating,
		ProviderKind:         providerKind,
		ProfileCode:          profileCode,
	}
}

func validationCheck(
	t *testing.T,
	proof discoverysource.ValidationProof,
	kind discoverysource.ValidationCheckKind,
) discoverysource.ValidationCheck {
	t.Helper()
	for _, check := range proof.Checks {
		if check.Kind == kind {
			return check
		}
	}
	t.Fatalf("proof has no %s check: %#v", kind, proof)
	return discoverysource.ValidationCheck{}
}

func nonEmptyRootPool(t *testing.T) *x509.CertPool {
	t.Helper()
	server := httptest.NewTLSServer(nil)
	certificate := server.Certificate()
	server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return roots
}
