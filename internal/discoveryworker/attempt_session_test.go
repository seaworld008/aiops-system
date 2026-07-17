package discoveryworker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/assetsource/externalcmdb"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
	"github.com/seaworld008/aiops-system/internal/sourceprofile"
)

const (
	attemptSessionTenantID      = "51000000-0000-4000-8000-000000000001"
	attemptSessionWorkspaceID   = "52000000-0000-4000-8000-000000000002"
	attemptSessionSourceID      = "53000000-0000-4000-8000-000000000003"
	attemptSessionRunID         = "54000000-0000-4000-8000-000000000004"
	attemptSessionAttemptID     = "55000000-0000-4000-8000-000000000005"
	attemptSessionEnvironmentID = "56000000-0000-4000-8000-000000000006"
	attemptSessionRevisionSHA   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	attemptSessionOpenPath   = "/discovery-cleanup/v1/session:open-or-recover"
	attemptSessionRevokePath = "/discovery-cleanup/v1/session:revoke"
)

func TestAttemptSessionRecoveryRequiresExactOpenAndNeverRecreatesRuntime(t *testing.T) {
	server := newAttemptSessionAuthorityServer(t)
	request := attemptSessionOpenRequest()
	binding := attemptSessionBinding(request)
	proofAuthority := &attemptSessionProofAuthority{key: []byte("task28b-proof-authority-key-0001")}

	factoryA := newAttemptSessionRuntimeFactory(t, binding)
	transportA := server.newTransport(t, "worker-a")
	authorityA := mustAttemptSessionAuthority(t, transportA, factoryA)
	brokerA, err := discoverycleanup.NewCleanupBroker(authorityA, proofAuthority)
	if err != nil {
		t.Fatalf("NewCleanupBroker(A) error = %v", err)
	}
	session, err := brokerA.OpenAttempt(t.Context(), request)
	if err != nil {
		t.Fatalf("OpenAttempt(A) error = %v", err)
	}
	bound, err := brokerA.BindAttemptRuntime(t.Context(), session, binding)
	if err != nil || bound.Binding() != binding {
		t.Fatalf("BindAttemptRuntime(A) = %#v,%v", bound, err)
	}
	resolveRequest, err := newResolveOpenedAttemptRequest(
		session, request.Coordinates, request.Attempt, binding, bound,
		assetcatalog.RunKindValidation, 0, "", nil,
	)
	if err != nil {
		t.Fatalf("newResolveOpenedAttemptRequest() error = %v", err)
	}
	claimRuntime, err := authorityA.ResolveOpenedAttempt(t.Context(), resolveRequest)
	if err != nil || claimRuntime.validate(resolveRequest) != nil {
		t.Fatalf("ResolveOpenedAttempt(A) = %#v,%v", claimRuntime, err)
	}
	claimRuntime.destroy()
	session.Destroy()
	brokerA.Destroy()
	authorityA.Destroy()
	transportA.Destroy()

	factoryB := newAttemptSessionRuntimeFactory(t, binding)
	transportB := server.newTransport(t, "worker-b")
	t.Cleanup(transportB.Destroy)
	authorityB := mustAttemptSessionAuthority(t, transportB, factoryB)
	t.Cleanup(authorityB.Destroy)
	brokerB, err := discoverycleanup.NewCleanupBroker(authorityB, proofAuthority)
	if err != nil {
		t.Fatalf("NewCleanupBroker(B) error = %v", err)
	}
	t.Cleanup(brokerB.Destroy)
	if proof, revokeErr := brokerB.RevokeAttempt(t.Context(), request.Attempt.AttemptID); proof.Validate() == nil ||
		!errors.Is(revokeErr, discoverycleanup.ErrAttemptNotFound) {
		proof.Destroy()
		t.Fatalf("direct replacement RevokeAttempt = %#v,%v", proof, revokeErr)
	}
	recoveryHandle, err := authorityB.OpenSession(t.Context(), request)
	if err != nil || recoveryHandle == nil {
		t.Fatalf("OpenSession(recovery capability) = %#v,%v", recoveryHandle, err)
	}
	if _, runtimeCapable := recoveryHandle.(discoverycleanup.RuntimeSessionHandle); runtimeCapable {
		t.Fatal("recovery handle unexpectedly implements RuntimeSessionHandle")
	}
	recoveryHandle.Destroy()

	queue := &attemptSessionCleanupQueue{}
	worker := &Worker{queue: queue, cleanupBroker: brokerB}
	claim := attemptSessionCleanupClaim(request)
	if err := worker.processCleanupClaim(t.Context(), &claim, request.Coordinates, false); err != nil {
		t.Fatalf("processCleanupClaim(recovery) error = %v", err)
	}
	if queue.recordCleanupCalls != 1 || queue.delayCalls != 1 {
		t.Fatalf("cleanup queue calls = record:%d delay:%d", queue.recordCleanupCalls, queue.delayCalls)
	}
	if queue.proof.Status() != assetcatalog.CredentialCleanupRevoked ||
		queue.proof.Attempt() != request.Attempt ||
		brokerB.VerifyCleanupProof(t.Context(), queue.proof) != nil {
		t.Fatalf("cleanup proof = %#v", queue.proof)
	}
	queue.proof.Destroy()

	if factoryA.openRuntimeCalls != 1 || factoryA.resolveClaimCalls != 1 {
		t.Fatalf("worker A factory calls = open:%d resolve:%d", factoryA.openRuntimeCalls, factoryA.resolveClaimCalls)
	}
	if len(factoryA.serializationErrors) != 2 {
		t.Fatalf("initial runtime serialization checks = %d, want 2", len(factoryA.serializationErrors))
	}
	for _, serializationErr := range factoryA.serializationErrors {
		if !errors.Is(serializationErr, ErrSensitiveSerialization) {
			t.Fatalf("initial runtime serialization error = %v", serializationErr)
		}
	}
	if factoryB.openRuntimeCalls != 0 || factoryB.resolveClaimCalls != 0 ||
		factoryB.provider.validateCalls != 0 || factoryB.provider.discoverCalls != 0 {
		t.Fatalf(
			"recovery factory/provider calls = open:%d resolve:%d validate:%d discover:%d",
			factoryB.openRuntimeCalls, factoryB.resolveClaimCalls,
			factoryB.provider.validateCalls, factoryB.provider.discoverCalls,
		)
	}
	openCalls, revokeCalls := server.logicalCalls()
	if openCalls != 1 || revokeCalls != 1 {
		t.Fatalf("authority logical calls = open:%d revoke:%d, want 1/1", openCalls, revokeCalls)
	}
}

func TestAttemptSessionRuntimeBindingDriftStopsBeforeResolverAndProvider(t *testing.T) {
	server := newAttemptSessionAuthorityServer(t)
	request := attemptSessionOpenRequest()
	binding := attemptSessionBinding(request)
	proofAuthority := &attemptSessionProofAuthority{key: []byte("task28b-proof-authority-key-0002")}

	factoryA := newAttemptSessionRuntimeFactory(t, binding)
	transportA := server.newTransport(t, "worker-a")
	authorityA := mustAttemptSessionAuthority(t, transportA, factoryA)
	brokerA, _ := discoverycleanup.NewCleanupBroker(authorityA, proofAuthority)
	if _, err := brokerA.OpenAttempt(t.Context(), request); err != nil {
		t.Fatalf("OpenAttempt(initial) error = %v", err)
	}
	brokerA.Destroy()
	authorityA.Destroy()
	transportA.Destroy()

	driftedBinding := binding
	driftedBinding.SourceRevisionDigest = strings.Repeat("b", 64)
	factoryB := newAttemptSessionRuntimeFactory(t, driftedBinding)
	transportB := server.newTransport(t, "worker-b")
	t.Cleanup(transportB.Destroy)
	authorityB := mustAttemptSessionAuthority(t, transportB, factoryB)
	t.Cleanup(authorityB.Destroy)
	brokerB, _ := discoverycleanup.NewCleanupBroker(authorityB, proofAuthority)
	t.Cleanup(brokerB.Destroy)
	if session, err := brokerB.OpenAttempt(t.Context(), request); session != nil ||
		(!errors.Is(err, discoverycleanup.ErrSessionAuthentication) &&
			!errors.Is(err, discoverycleanup.ErrAttemptUncertain)) {
		t.Fatalf("OpenAttempt(binding drift) = %#v,%v", session, err)
	}
	if factoryB.openRuntimeCalls != 0 || factoryB.resolveClaimCalls != 0 ||
		factoryB.provider.validateCalls != 0 || factoryB.provider.discoverCalls != 0 {
		t.Fatalf("binding drift reached runtime/resolver/provider: %#v", factoryB)
	}
}

func TestSameAttemptSessionRejectsForeignOrReconstructedRuntimeCell(t *testing.T) {
	server := newAttemptSessionAuthorityServer(t)
	request := attemptSessionOpenRequest()
	binding := attemptSessionBinding(request)
	proofAuthority := &attemptSessionProofAuthority{key: []byte("task28b-proof-authority-key-0003")}

	tests := map[string]func(*attemptSessionRuntimeFactory){
		"foreign bound capability": func(factory *attemptSessionRuntimeFactory) {
			factory.returnForeignBoundRuntime = true
		},
		"raw unbound runtime": func(factory *attemptSessionRuntimeFactory) {
			factory.returnReconstructedBoundRuntime = true
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			factory := newAttemptSessionRuntimeFactory(t, binding)
			mutate(factory)
			transport := server.newTransport(t, strings.ReplaceAll(name, " ", "-"))
			t.Cleanup(transport.Destroy)
			authority := mustAttemptSessionAuthority(t, transport, factory)
			t.Cleanup(authority.Destroy)
			broker, _ := discoverycleanup.NewCleanupBroker(authority, proofAuthority)
			t.Cleanup(broker.Destroy)
			driftRequest := request
			driftRequest.Attempt.AttemptID = attemptSessionAttemptForName(name)
			session, err := broker.OpenAttempt(t.Context(), driftRequest)
			if session != nil || !errors.Is(err, discoverycleanup.ErrAttemptUncertain) {
				t.Fatalf("OpenAttempt(%s) = %#v,%v", name, session, err)
			}
			proof, revokeErr := broker.RevokeAttempt(t.Context(), driftRequest.Attempt.AttemptID)
			if revokeErr != nil || proof.Status() != assetcatalog.CredentialCleanupUncertain {
				t.Fatalf("cleanup after rejected runtime = %#v,%v", proof, revokeErr)
			}
			proof.Destroy()
			if factory.resolveClaimCalls != 0 || factory.provider.validateCalls != 0 ||
				factory.provider.discoverCalls != 0 {
				t.Fatalf("foreign runtime reached resolver/provider: %#v", factory)
			}
		})
	}
}

func TestAttemptSessionSecretSerializationAndMissingDependenciesFailClosed(t *testing.T) {
	server := newAttemptSessionAuthorityServer(t)
	transport := server.newTransport(t, "worker-a")
	t.Cleanup(transport.Destroy)
	binding := attemptSessionBinding(attemptSessionOpenRequest())
	factory := newAttemptSessionRuntimeFactory(t, binding)
	descriptor := sourceprofile.ExternalCMDBV1()

	var typedDescriptor *attemptSessionNilDescriptor
	var typedFactory *attemptSessionRuntimeFactory
	tests := map[string]struct {
		transport  *discoverycleanup.SessionTransport
		descriptor AttemptProfileDescriptor
		factory    AttemptRuntimeFactory
	}{
		"transport":        {descriptor: descriptor, factory: factory},
		"descriptor":       {transport: transport, factory: factory},
		"typed descriptor": {transport: transport, descriptor: typedDescriptor, factory: factory},
		"factory":          {transport: transport, descriptor: descriptor},
		"typed factory":    {transport: transport, descriptor: descriptor, factory: typedFactory},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			authority, err := NewAttemptSessionAuthority(test.transport, test.descriptor, test.factory)
			if authority != nil || !errors.Is(err, ErrAttemptSessionAuthority) {
				t.Fatalf("NewAttemptSessionAuthority(%s) = %#v,%v", name, authority, err)
			}
		})
	}

	authority := mustAttemptSessionAuthority(t, transport, factory)
	t.Cleanup(authority.Destroy)
	if _, err := json.Marshal(authority); !errors.Is(err, ErrSensitiveSerialization) {
		t.Fatalf("json.Marshal(authority) error = %v", err)
	}
	rendered := fmt.Sprintf("%v %#v", authority, authority)
	for _, forbidden := range []string{
		attemptSessionRunID, attemptSessionAttemptID, server.server.URL,
		server.serverIdentity,
	} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("authority formatting leaked %q: %q", forbidden, rendered)
		}
	}
}

func mustAttemptSessionAuthority(
	t *testing.T,
	transport *discoverycleanup.SessionTransport,
	factory *attemptSessionRuntimeFactory,
) *AttemptSessionAuthority {
	t.Helper()
	authority, err := NewAttemptSessionAuthority(
		transport, sourceprofile.ExternalCMDBV1(), factory,
	)
	if err != nil {
		t.Fatalf("NewAttemptSessionAuthority() error = %v", err)
	}
	return authority
}

func attemptSessionOpenRequest() discoverycleanup.OpenAttemptRequest {
	scope := assetcatalog.SourceScope{
		TenantID: attemptSessionTenantID, WorkspaceID: attemptSessionWorkspaceID,
	}
	return discoverycleanup.OpenAttemptRequest{
		Coordinates: discoveryqueue.RunCoordinates{Scope: scope, RunID: attemptSessionRunID},
		Attempt: discoveryqueue.CleanupAttempt{
			RunID: attemptSessionRunID, AttemptID: attemptSessionAttemptID, AttemptEpoch: 1,
		},
	}
}

func attemptSessionBinding(
	request discoverycleanup.OpenAttemptRequest,
) discoverysource.RuntimeBinding {
	return discoverysource.RuntimeBinding{
		Locator: assetcatalog.SourceLocator{
			Scope: request.Coordinates.Scope, SourceID: attemptSessionSourceID,
		},
		SourceRevision:       1,
		SourceRevisionDigest: attemptSessionRevisionSHA,
		RevisionStatus:       assetcatalog.SourceRevisionValidating,
		ProviderKind:         "CMDB_CATALOG_V1",
		ProfileCode:          "CMDB_CATALOG_V1",
	}
}

func attemptSessionCleanupClaim(
	request discoverycleanup.OpenAttemptRequest,
) discoveryqueue.ClaimResult {
	notBefore := time.Now().UTC().Add(time.Second).Truncate(time.Microsecond)
	return discoveryqueue.ClaimResult{
		Run: assetcatalog.SourceRun{
			ID: request.Coordinates.RunID, Scope: request.Coordinates.Scope,
			SourceID: attemptSessionSourceID, SourceRevision: 1,
			SourceRevisionDigest:    attemptSessionRevisionSHA,
			Kind:                    assetcatalog.RunKindDiscovery,
			Status:                  assetcatalog.RunStatusRunning,
			Stage:                   assetcatalog.RunStageCleaningUp,
			FenceEpoch:              request.Attempt.AttemptEpoch,
			CredentialCleanupStatus: assetcatalog.CredentialCleanupPending,
		},
		ProviderKind: "CMDB_CATALOG_V1", ProfileCode: "CMDB_CATALOG_V1",
		Mode: discoveryqueue.ClaimModeCleanupOnly,
		CleanupAttempt: &discoveryqueue.CleanupAttempt{
			RunID: request.Attempt.RunID, AttemptID: request.Attempt.AttemptID,
			AttemptEpoch: request.Attempt.AttemptEpoch,
		},
		PersistedDelay: &discoveryqueue.PersistedDelay{
			Reason: discoveryqueue.DelayReasonTransportBackoff, NotBefore: notBefore,
			DigestSHA256: strings.Repeat("d", 64),
		},
	}
}

type attemptSessionCleanupQueue struct {
	discoveryqueue.Queue
	recordCleanupCalls int
	delayCalls         int
	proof              discoveryqueue.CleanupProof
}

func (queue *attemptSessionCleanupQueue) RecordCleanup(
	_ context.Context,
	_ assetcatalog.LeaseFence,
	proof discoveryqueue.CleanupProof,
) (discoveryqueue.CleanupResult, error) {
	queue.recordCleanupCalls++
	queue.proof.Destroy()
	queue.proof = proof.Clone()
	return discoveryqueue.CleanupResult{
		Attempt: proof.Attempt(), Status: proof.Status(),
		DigestSHA256: proof.DigestSHA256(),
	}, nil
}

func (queue *attemptSessionCleanupQueue) Delay(
	_ context.Context,
	_ assetcatalog.LeaseFence,
	command discoveryqueue.DelayCommand,
) (assetcatalog.SourceRun, error) {
	queue.delayCalls++
	return assetcatalog.SourceRun{
		ID: command.Coordinates.RunID, Scope: command.Coordinates.Scope,
		Status: assetcatalog.RunStatusDelayed, Stage: assetcatalog.RunStageDelayed,
	}, nil
}

type attemptSessionRuntimeFactory struct {
	t        *testing.T
	binding  discoverysource.RuntimeBinding
	profile  externalcmdb.ReconciliationDescriptor
	provider *attemptSessionProvider

	openRuntimeCalls                int
	resolveClaimCalls               int
	returnForeignBoundRuntime       bool
	returnReconstructedBoundRuntime bool
	serializationErrors             []error
}

func newAttemptSessionRuntimeFactory(
	t *testing.T,
	binding discoverysource.RuntimeBinding,
) *attemptSessionRuntimeFactory {
	t.Helper()
	profile, err := externalcmdb.NewReconciliationDescriptor(sourceprofile.ExternalCMDBV1())
	if err != nil {
		t.Fatalf("NewReconciliationDescriptor() error = %v", err)
	}
	return &attemptSessionRuntimeFactory{
		t: t, binding: binding, profile: profile, provider: &attemptSessionProvider{},
	}
}

func (factory *attemptSessionRuntimeFactory) ResolveRuntimeBinding(
	context.Context,
	discoverycleanup.OpenAttemptRequest,
) (discoverysource.RuntimeBinding, error) {
	return factory.binding, nil
}

func (factory *attemptSessionRuntimeFactory) OpenInitialRuntime(
	_ context.Context,
	request *InitialRuntimeRequest,
) (*SessionBoundRuntime, error) {
	factory.openRuntimeCalls++
	if _, err := json.Marshal(request); err != nil {
		factory.serializationErrors = append(factory.serializationErrors, err)
	}
	material := &attemptSessionRuntimeMaterial{}
	bound, err := discoverysource.BindRuntime(
		request.RuntimeBinding(), material,
		func(*attemptSessionRuntimeMaterial) error { return nil },
		func(value *attemptSessionRuntimeMaterial) { value.cleared = true },
	)
	if err != nil {
		return nil, err
	}
	if factory.returnForeignBoundRuntime {
		foreign := &InitialRuntimeRequest{}
		result, bindErr := foreign.BindRuntime(bound)
		if bindErr != nil {
			bound.Clear()
		}
		return result, bindErr
	}
	result, err := request.BindRuntime(bound)
	if err != nil {
		bound.Clear()
		return nil, err
	}
	if _, marshalErr := json.Marshal(result); marshalErr != nil {
		factory.serializationErrors = append(factory.serializationErrors, marshalErr)
	}
	if factory.returnReconstructedBoundRuntime {
		return &SessionBoundRuntime{}, nil
	}
	return result, nil
}

func (factory *attemptSessionRuntimeFactory) ResolveClaimRuntime(
	context.Context,
	ResolveOpenedAttemptRequest,
) (
	discoverysource.Provider,
	*discoverysource.Checkpoint,
	discoverysource.Limits,
	assetdiscovery.FactPolicy,
	error,
) {
	factory.resolveClaimCalls++
	checkpoint, err := factory.profile.NewCheckpoint()
	if err != nil {
		return nil, nil, discoverysource.Limits{}, assetdiscovery.FactPolicy{}, err
	}
	policy, err := factory.profile.FactPolicy([]string{attemptSessionEnvironmentID})
	if err != nil {
		checkpoint.Clear()
		return nil, nil, discoverysource.Limits{}, assetdiscovery.FactPolicy{}, err
	}
	return factory.provider, &checkpoint, factory.profile.Limits(), policy, nil
}

type attemptSessionRuntimeMaterial struct {
	cleared bool
}

type attemptSessionProvider struct {
	validateCalls int
	discoverCalls int
}

func (*attemptSessionProvider) Kind() assetcatalog.SourceKind {
	return assetcatalog.SourceKindExternalCMDB
}

func (*attemptSessionProvider) ProviderKind() string { return "CMDB_CATALOG_V1" }

func (provider *attemptSessionProvider) Validate(
	context.Context,
	discoverysource.BoundRuntime,
	discoverysource.ValidationRequest,
) (discoverysource.ValidationProof, error) {
	provider.validateCalls++
	return discoverysource.ValidationProof{}, errors.New("provider call forbidden in Task28B test")
}

func (provider *attemptSessionProvider) Discover(
	context.Context,
	discoverysource.BoundRuntime,
	discoverysource.DiscoverRequest,
) (discoverysource.DiscoverOutcome, error) {
	provider.discoverCalls++
	return nil, errors.New("provider call forbidden in Task28B test")
}

type attemptSessionProofAuthority struct {
	key []byte
}

func (authority *attemptSessionProofAuthority) SignCleanupProof(
	_ context.Context,
	digest []byte,
) ([]byte, error) {
	mac := hmac.New(sha256.New, authority.key)
	_, _ = mac.Write(digest)
	return mac.Sum(nil), nil
}

func (authority *attemptSessionProofAuthority) VerifyCleanupProof(
	_ context.Context,
	digest []byte,
	signature []byte,
) error {
	expected, _ := authority.SignCleanupProof(context.Background(), digest)
	defer clear(expected)
	if !hmac.Equal(expected, signature) {
		return errors.New("invalid cleanup proof")
	}
	return nil
}

type attemptSessionNilDescriptor struct{}

func (*attemptSessionNilDescriptor) Valid() bool                           { return false }
func (*attemptSessionNilDescriptor) SourceKind() assetcatalog.SourceKind   { return "" }
func (*attemptSessionNilDescriptor) ProviderKind() string                  { return "" }
func (*attemptSessionNilDescriptor) ProfileCode() assetcatalog.ProfileCode { return "" }
func (*attemptSessionNilDescriptor) DigestSHA256() string                  { return "" }

type attemptSessionRunWire struct {
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	RunID       string `json:"run_id"`
}

type attemptSessionWire struct {
	Version              string                `json:"version"`
	Run                  attemptSessionRunWire `json:"run"`
	AttemptID            string                `json:"attempt_id"`
	AttemptEpoch         int64                 `json:"attempt_epoch"`
	RuntimeBindingDigest string                `json:"runtime_binding_digest"`
	Receipt              string                `json:"receipt,omitempty"`
}

type attemptSessionAuthorityRecord struct {
	wire    attemptSessionWire
	receipt string
	creator string
	revoked bool
}

type attemptSessionAuthorityServer struct {
	t              *testing.T
	server         *httptest.Server
	ca             *testpki.Authority
	serverIdentity string

	mu          sync.Mutex
	records     map[string]*attemptSessionAuthorityRecord
	openCalls   int
	revokeCalls int
}

func newAttemptSessionAuthorityServer(t *testing.T) *attemptSessionAuthorityServer {
	t.Helper()
	now := time.Now().UTC()
	ca, err := testpki.NewAuthority("attempt-session-ca", now)
	if err != nil {
		t.Fatalf("NewAuthority() error = %v", err)
	}
	serverIdentity := "spiffe://aiops.test/discovery-session-authority/attempt"
	serverURI, _ := url.Parse(serverIdentity)
	serverCertificate, err := ca.IssueClient(testpki.ClientOptions{
		CommonName: "attempt-session-authority.test",
		URIs:       []*url.URL{serverURI}, DNSNames: []string{"attempt-session-authority.test"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, now)
	if err != nil {
		t.Fatalf("Issue server certificate: %v", err)
	}
	fixture := &attemptSessionAuthorityServer{
		t: t, ca: ca, serverIdentity: serverIdentity,
		records: make(map[string]*attemptSessionAuthorityRecord),
	}
	fixture.server = httptest.NewUnstartedServer(http.HandlerFunc(fixture.serveHTTP))
	fixture.server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate.TLS},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: ca.CertPool(),
		NextProtos: []string{"http/1.1"},
	}
	fixture.server.StartTLS()
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (server *attemptSessionAuthorityServer) newTransport(
	t *testing.T,
	worker string,
) *discoverycleanup.SessionTransport {
	t.Helper()
	worker = strings.ReplaceAll(worker, " ", "-")
	identity, _ := url.Parse("spiffe://aiops.test/discovery-worker/" + worker)
	certificate, err := server.ca.IssueClient(testpki.ClientOptions{
		CommonName: worker, URIs: []*url.URL{identity},
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("IssueClient(%s) error = %v", worker, err)
	}
	transport, err := discoverycleanup.NewSessionTransport(discoverycleanup.SessionTransportOptions{
		BaseURL: server.server.URL, ServerName: "attempt-session-authority.test",
		ExpectedPeerIdentity: server.serverIdentity, RootCAs: server.ca.CertPool(),
		ClientCertificate: certificate.TLS,
	})
	if err != nil {
		t.Fatalf("NewSessionTransport(%s) error = %v", worker, err)
	}
	return transport
}

func (server *attemptSessionAuthorityServer) serveHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	body, _ := io.ReadAll(io.LimitReader(request.Body, 8192))
	var wire attemptSessionWire
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || request.TLS == nil ||
		len(request.TLS.PeerCertificates) == 0 ||
		len(request.TLS.PeerCertificates[0].URIs) != 1 {
		server.writeProblem(writer, http.StatusBadRequest)
		return
	}
	peer := request.TLS.PeerCertificates[0].URIs[0].String()
	server.mu.Lock()
	record := server.records[wire.AttemptID]
	comparison := wire
	comparison.Receipt = ""
	if record != nil {
		expected := record.wire
		expected.Receipt = ""
		if !reflect.DeepEqual(expected, comparison) {
			server.mu.Unlock()
			server.writeProblem(writer, http.StatusConflict)
			return
		}
	}
	switch request.URL.Path {
	case attemptSessionOpenPath:
		if record == nil {
			digest := sha256.Sum256(body)
			record = &attemptSessionAuthorityRecord{
				wire: comparison, receipt: hex.EncodeToString(digest[:]), creator: peer,
			}
			server.records[wire.AttemptID] = record
			server.openCalls++
		}
		disposition := "RECOVERED"
		if record.creator == peer {
			disposition = "OPENED"
		}
		response := server.response(record, disposition, "")
		server.mu.Unlock()
		server.writeJSON(writer, response)
	case attemptSessionRevokePath:
		if record == nil || wire.Receipt != record.receipt {
			server.mu.Unlock()
			server.writeProblem(writer, http.StatusConflict)
			return
		}
		if !record.revoked {
			record.revoked = true
			server.revokeCalls++
		}
		response := server.response(record, "", "REVOKED")
		server.mu.Unlock()
		server.writeJSON(writer, response)
	default:
		server.mu.Unlock()
		server.writeProblem(writer, http.StatusNotFound)
	}
}

func (server *attemptSessionAuthorityServer) response(
	record *attemptSessionAuthorityRecord,
	disposition string,
	status string,
) map[string]any {
	response := map[string]any{
		"version": record.wire.Version,
		"run": map[string]any{
			"tenant_id":    record.wire.Run.TenantID,
			"workspace_id": record.wire.Run.WorkspaceID,
			"run_id":       record.wire.Run.RunID,
		},
		"attempt_id":             record.wire.AttemptID,
		"attempt_epoch":          record.wire.AttemptEpoch,
		"runtime_binding_digest": record.wire.RuntimeBindingDigest,
		"receipt":                record.receipt,
	}
	if disposition != "" {
		response["disposition"] = disposition
	}
	if status != "" {
		response["status"] = status
	}
	return response
}

func (server *attemptSessionAuthorityServer) writeJSON(
	writer http.ResponseWriter,
	value any,
) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(writer).Encode(value)
}

func (server *attemptSessionAuthorityServer) writeProblem(
	writer http.ResponseWriter,
	status int,
) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/problem+json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, `{"code":"session_rejected"}`)
}

func (server *attemptSessionAuthorityServer) logicalCalls() (int, int) {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.openCalls, server.revokeCalls
}

func attemptSessionAttemptForName(name string) string {
	digest := sha256.Sum256([]byte(name))
	encoded := hex.EncodeToString(digest[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-4" + encoded[13:16] +
		"-8" + encoded[17:20] + "-" + encoded[20:32]
}
