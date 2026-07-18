package discoveryworker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverycheckpoint"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoverylimit"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
	"github.com/seaworld008/aiops-system/internal/sourceprofile"
)

const (
	productionTestTenantID      = "11111111-1111-4111-8111-111111111111"
	productionTestWorkspaceID   = "22222222-2222-4222-8222-222222222222"
	productionTestSourceID      = "33333333-3333-4333-8333-333333333333"
	productionTestRunID         = "44444444-4444-4444-8444-444444444444"
	productionTestEnvironmentID = "55555555-5555-4555-8555-555555555555"
)

func TestProductionConstructorFailsClosedForEveryMissingDependency(t *testing.T) {
	fixture := newProductionFixture(t, "worker-a")
	defer fixture.close()

	tests := map[string]func(*ProductionDependencies){
		"queue":             func(value *ProductionDependencies) { value.Queue = nil },
		"page committer":    func(value *ProductionDependencies) { value.PageCommitter = nil },
		"limiter":           func(value *ProductionDependencies) { value.Limiter = nil },
		"attempt authority": func(value *ProductionDependencies) { value.AttemptAuthority = nil },
		"session transport": func(value *ProductionDependencies) { value.SessionTransport = nil },
		"checkpoints":       func(value *ProductionDependencies) { value.Checkpoints = nil },
		"registry":          func(value *ProductionDependencies) { value.Registry = nil },
		"workload identity": func(value *ProductionDependencies) { value.WorkloadIdentity = nil },
		"observer":          func(value *ProductionDependencies) { value.Observer = nil },
		"proof authority":   func(value *ProductionDependencies) { value.CleanupProofAuthority = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			dependencies := fixture.dependencies.Clone()
			mutate(&dependencies)
			production, err := NewProduction(dependencies)
			if !errors.Is(err, ErrProductionDependencies) || production != nil {
				t.Fatalf("NewProduction() = %#v,%v, want nil, ErrProductionDependencies", production, err)
			}
		})
	}
}

func TestProductionConstructorDerivesStableWorkerAndFreshProcessDigests(t *testing.T) {
	firstFixture := newProductionFixture(t, "worker-a")
	defer firstFixture.close()
	first, err := NewProduction(firstFixture.dependencies.Clone())
	if err != nil {
		t.Fatalf("NewProduction(first) error = %v", err)
	}
	defer first.Close()

	secondFixture := newProductionFixture(t, "worker-a")
	defer secondFixture.close()
	second, err := NewProduction(secondFixture.dependencies.Clone())
	if err != nil {
		t.Fatalf("NewProduction(second) error = %v", err)
	}
	defer second.Close()

	otherFixture := newProductionFixture(t, "worker-b")
	defer otherFixture.close()
	other, err := NewProduction(otherFixture.dependencies.Clone())
	if err != nil {
		t.Fatalf("NewProduction(other) error = %v", err)
	}
	defer other.Close()

	firstIdentity := first.IdentityDigests()
	secondIdentity := second.IdentityDigests()
	otherIdentity := other.IdentityDigests()
	for name, value := range map[string]string{
		"first worker":   firstIdentity.WorkerIdentityDigest,
		"first process":  firstIdentity.ProcessInstanceDigest,
		"second worker":  secondIdentity.WorkerIdentityDigest,
		"second process": secondIdentity.ProcessInstanceDigest,
		"other worker":   otherIdentity.WorkerIdentityDigest,
		"other process":  otherIdentity.ProcessInstanceDigest,
	} {
		if len(value) != 64 || strings.ToLower(value) != value {
			t.Fatalf("%s digest = %q", name, value)
		}
	}
	if firstIdentity.WorkerIdentityDigest != secondIdentity.WorkerIdentityDigest {
		t.Fatal("same authenticated workload identity changed worker digest across restart")
	}
	if firstIdentity.ProcessInstanceDigest == secondIdentity.ProcessInstanceDigest {
		t.Fatal("fresh process-instance digest was reused")
	}
	if firstIdentity.WorkerIdentityDigest == otherIdentity.WorkerIdentityDigest {
		t.Fatal("different authenticated workload identities shared worker digest")
	}

	dependencyType := reflect.TypeOf(ProductionDependencies{})
	for _, forbidden := range []string{
		"WorkerIdentityDigest", "ProcessInstanceDigest", "WorkerID", "ProcessID",
		"IdentityDigest",
	} {
		if _, exists := dependencyType.FieldByName(forbidden); exists {
			t.Fatalf("ProductionDependencies exposes caller-supplied %s", forbidden)
		}
	}
}

func TestProductionManifestIsSafeContentAddressedAndProcessIndependent(t *testing.T) {
	firstFixture := newProductionFixture(t, "worker-a")
	defer firstFixture.close()
	first, err := NewProduction(firstFixture.dependencies.Clone())
	if err != nil {
		t.Fatalf("NewProduction(first) error = %v", err)
	}
	defer first.Close()

	secondFixture := newProductionFixture(t, "worker-a")
	defer secondFixture.close()
	second, err := NewProduction(secondFixture.dependencies.Clone())
	if err != nil {
		t.Fatalf("NewProduction(second) error = %v", err)
	}
	defer second.Close()

	firstManifest := first.RuntimeAdmissionManifest()
	secondManifest := second.RuntimeAdmissionManifest()
	if firstManifest.DigestSHA256() == "" ||
		firstManifest.DigestSHA256() != secondManifest.DigestSHA256() ||
		string(firstManifest.CanonicalJSON()) != string(secondManifest.CanonicalJSON()) {
		t.Fatalf("manifest drift = %q/%q", firstManifest.DigestSHA256(), secondManifest.DigestSHA256())
	}
	var document struct {
		SchemaVersion string `json:"schema_version"`
		Providers     []struct {
			ProviderKind                    string `json:"provider_kind"`
			ProfileCode                     string `json:"profile_code"`
			CanonicalDescriptorDigest       string `json:"canonical_descriptor_digest"`
			RuntimeRecoveryCapabilityDigest string `json:"runtime_recovery_capability_digest"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(firstManifest.CanonicalJSON(), &document); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if document.SchemaVersion != RuntimeAdmissionManifestSchemaVersion ||
		len(document.Providers) != 1 ||
		document.Providers[0].ProviderKind != "CMDB_CATALOG_V1" ||
		document.Providers[0].ProfileCode != "CMDB_CATALOG_V1" ||
		document.Providers[0].CanonicalDescriptorDigest !=
			sourceprofile.ExternalCMDBV1().DigestSHA256() ||
		document.Providers[0].RuntimeRecoveryCapabilityDigest !=
			RuntimeRecoveryCapabilityDigest() {
		t.Fatalf("runtime admission manifest = %#v", document)
	}
	encoded := strings.ToLower(string(firstManifest.CanonicalJSON()))
	for _, forbidden := range []string{
		"endpoint", "credential", "socket", "private_key", "token", "secret",
		"source_id", "run_id", "worker_identity", "process_instance",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("runtime manifest contains forbidden field/token %q: %s", forbidden, encoded)
		}
	}
}

func TestProductionObserverDecoratesExactDependenciesWithClosedSafeEnums(t *testing.T) {
	fixture := newProductionFixture(t, "worker-a")
	defer fixture.close()
	recorder := &productionObserverRecorder{}
	fixture.dependencies.Observer = recorder
	production, err := NewProduction(fixture.dependencies.Clone())
	if err != nil {
		t.Fatalf("NewProduction() error = %v", err)
	}
	defer production.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := production.Run(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run() error = %v", err)
	}
	observations := recorder.clone()
	if len(observations) == 0 {
		t.Fatal("observer received no real dependency-boundary observation")
	}
	for _, observation := range observations {
		if !observation.Provider().Valid() ||
			!observation.Boundary().Valid() ||
			!observation.Result().Valid() {
			t.Fatalf("unsafe observation = %#v", observation)
		}
	}
	observationType := reflect.TypeOf(WorkerObservation{})
	gotFields := make([]string, 0, observationType.NumField())
	for index := 0; index < observationType.NumField(); index++ {
		gotFields = append(gotFields, observationType.Field(index).Name)
	}
	if !reflect.DeepEqual(gotFields, []string{"provider", "boundary", "result"}) {
		t.Fatalf("WorkerObservation fields = %#v", gotFields)
	}
}

func TestProductionPageCommitObserverDerivesProviderOnlyFromExactRegistry(t *testing.T) {
	registry, err := NewRegistry(ExternalCMDBDeclaration())
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	recorder := &productionObserverRecorder{}
	observed := newObservedDependencies(
		registry,
		recorder,
		&productionQueue{},
		productionPageCommitter{},
		productionLimiter{},
	)
	_, err = observed.pageCommitter.ApplyPage(
		context.Background(),
		assetcatalog.LeaseFence{},
		discoverysource.PageCommitCoordinates{
			Locator: assetcatalog.SourceLocator{
				SourceID: "VSPHERE_VCENTER_V1",
			},
			RunID: "KUBERNETES_OPERATOR",
		},
		discoverysource.Page{
			Items: []assetdiscovery.NormalizedItem{{
				ProviderKind: "AWX_INVENTORY",
				Document: json.RawMessage(
					`{"labels":{"provider":"UNREGISTERED"}}`,
				),
			}},
		},
	)
	if !errors.Is(err, discoverysource.ErrPageCommitUnavailable) {
		t.Fatalf("ApplyPage() error = %v", err)
	}
	observations := recorder.clone()
	if len(observations) != 1 {
		t.Fatalf("observations = %#v", observations)
	}
	if observations[0].Provider() != ObserverProviderExternalCMDB ||
		observations[0].Boundary() != ObserverBoundaryPageCommit ||
		observations[0].Result() != ObserverResultUnavailable {
		t.Fatalf("PageCommit observation = %#v", observations[0])
	}
}

func TestProductionRejectsNonSingleObserverRegistryBeforeWorkerCreation(t *testing.T) {
	tests := map[string]func(*ProviderRegistry) *ProviderRegistry{
		"empty": func(*ProviderRegistry) *ProviderRegistry {
			return &ProviderRegistry{}
		},
		"ambiguous": func(input *ProviderRegistry) *ProviderRegistry {
			ambiguous := *input
			ambiguous.kinds = append(
				ambiguous.kinds,
				string(ObserverProviderExternalCMDB),
			)
			ambiguous.self = &ambiguous
			return &ambiguous
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newProductionFixture(t, "worker-"+name)
			defer fixture.close()
			dependencies := fixture.dependencies.Clone()
			dependencies.Registry = mutate(dependencies.Registry)
			production, err := NewProduction(dependencies)
			if !errors.Is(err, ErrProductionDependencies) || production != nil {
				t.Fatalf(
					"NewProduction() = %#v,%v, want nil, ErrProductionDependencies",
					production,
					err,
				)
			}
			fixture.queueFactory.mu.Lock()
			builds := fixture.queueFactory.builds
			fixture.queueFactory.mu.Unlock()
			if builds != 0 {
				t.Fatalf("production queue builds = %d, want 0", builds)
			}
		})
	}
}

func TestProductionUsesOneAuthorityForBrokerQueueAndClaimRuntime(t *testing.T) {
	fixture := newProductionFixture(t, "worker-a")
	defer fixture.close()
	production, err := NewProduction(fixture.dependencies.Clone())
	if err != nil {
		t.Fatalf("NewProduction() error = %v", err)
	}
	defer production.Close()

	fixture.queueFactory.mu.Lock()
	builds := fixture.queueFactory.builds
	verifier := fixture.queueFactory.verifier
	fixture.queueFactory.mu.Unlock()
	if builds != 1 || verifier != production.state.broker {
		t.Fatalf("queue factory builds/verifier = %d/%T", builds, verifier)
	}
	if production.state.worker.cleanupBroker != production.state.broker {
		t.Fatal("Worker received a Broker other than the constructor-owned Broker")
	}
	if production.state.worker.claimRuntimeResolver != fixture.authority ||
		production.state.authority != fixture.authority ||
		production.state.transport != fixture.transport {
		t.Fatal("Broker opener and claim runtime resolver did not share the exact Task 28B authority")
	}
	dependencyType := reflect.TypeOf(ProductionDependencies{})
	for _, forbidden := range []string{
		"SessionOpener", "ClaimRuntimeResolver", "CredentialResolver",
		"RuntimeResolver", "CleanupBroker",
	} {
		if _, exists := dependencyType.FieldByName(forbidden); exists {
			t.Fatalf("ProductionDependencies exposes independent %s injection", forbidden)
		}
	}
}

func TestProductionRejectsSessionTransportThatIsNotOwnedByAttemptAuthority(t *testing.T) {
	fixture := newProductionFixture(t, "worker-a")
	defer fixture.close()
	foreign := newProductionFixture(t, "worker-b")
	defer foreign.close()
	dependencies := fixture.dependencies.Clone()
	dependencies.SessionTransport = foreign.transport
	production, err := NewProduction(dependencies)
	if !errors.Is(err, ErrProductionDependencies) || production != nil {
		t.Fatalf("NewProduction(foreign transport) = %#v,%v", production, err)
	}
}

func TestProductionRejectsAuthorityRegistryDescriptorDriftBeforeQueue(t *testing.T) {
	neutral := sourceprofile.ExternalCMDBV1()
	valid := productionAttemptProfileDescriptor{
		sourceKind: neutral.SourceKind(), providerKind: neutral.ProviderKind(),
		profileCode: neutral.ProfileCode(), digest: neutral.DigestSHA256(),
	}
	tests := map[string]func(*productionAttemptProfileDescriptor){
		"source kind": func(value *productionAttemptProfileDescriptor) {
			value.sourceKind = assetcatalog.SourceKindVSphere
		},
		"provider kind": func(value *productionAttemptProfileDescriptor) {
			value.providerKind = "DRIFTED_CMDB_V1"
		},
		"profile code": func(value *productionAttemptProfileDescriptor) {
			value.profileCode = "DRIFTED_CMDB_V1"
		},
		"descriptor digest": func(value *productionAttemptProfileDescriptor) {
			value.digest = strings.Repeat("b", sha256.Size*2)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newProductionFixture(t, "worker-"+strings.ReplaceAll(name, " ", "-"))
			defer fixture.close()
			descriptor := valid
			mutate(&descriptor)
			if !descriptor.Valid() {
				t.Fatalf("test descriptor %q is not structurally valid", name)
			}
			authority, err := NewAttemptSessionAuthority(
				fixture.transport,
				descriptor,
				fixture.runtimeFactory,
			)
			if err != nil {
				t.Fatalf("NewAttemptSessionAuthority(%s) error = %v", name, err)
			}
			defer authority.Destroy()

			dependencies := fixture.dependencies.Clone()
			dependencies.AttemptAuthority = authority
			production, productionErr := NewProduction(dependencies)
			if production != nil {
				_ = production.Close()
			}
			fixture.queueFactory.mu.Lock()
			builds := fixture.queueFactory.builds
			fixture.queueFactory.mu.Unlock()
			if production != nil ||
				!errors.Is(productionErr, ErrProductionDependencies) ||
				builds != 0 {
				t.Fatalf(
					"NewProduction(%s drift) = %#v,%v, queue builds=%d",
					name,
					production,
					productionErr,
					builds,
				)
			}
		})
	}
}

func TestProductionTypesCloseSensitiveSerializationAndLoopRemainsTask28AOwned(t *testing.T) {
	fixture := newProductionFixture(t, "worker-a")
	defer fixture.close()
	production, err := NewProduction(fixture.dependencies.Clone())
	if err != nil {
		t.Fatalf("NewProduction() error = %v", err)
	}
	defer production.Close()
	if _, err := json.Marshal(production); !errors.Is(err, ErrSensitiveSerialization) {
		t.Fatalf("json.Marshal(Production) error = %v", err)
	}
	if got := fmt.Sprintf("%v", production); got != productionRedaction {
		t.Fatalf("Production format = %q", got)
	}
	source, err := os.ReadFile("production.go")
	if err != nil {
		t.Fatalf("read production.go: %v", err)
	}
	if bytes.Count(source, []byte("New(Dependencies{")) != 1 {
		t.Fatal("production constructor does not inject the one Task 28A Worker loop exactly once")
	}
	for _, forbidden := range [][]byte{
		[]byte("func (production *Production) processClaim"),
		[]byte("func (production *Production) processRun"),
		[]byte("func (production *Production) heartbeat"),
	} {
		if bytes.Contains(source, forbidden) {
			t.Fatalf("production.go copied a Worker loop method %q", forbidden)
		}
	}
}

type productionFixture struct {
	dependencies   ProductionDependencies
	keyring        *discoverycheckpoint.InMemoryKeyring
	transport      *discoverycleanup.SessionTransport
	authority      *AttemptSessionAuthority
	runtimeFactory *productionRuntimeFactory
	proof          *productionProofAuthority
	queueFactory   *productionQueueFactory
}

func newProductionFixture(t *testing.T, worker string) *productionFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	ca, err := testpki.NewAuthority("production-test-ca", now)
	if err != nil {
		t.Fatalf("NewAuthority() error = %v", err)
	}
	workerURI, err := url.Parse("spiffe://aiops.test/discovery-worker/" + worker)
	if err != nil {
		t.Fatalf("parse worker URI: %v", err)
	}
	client, err := ca.IssueClient(testpki.ClientOptions{URIs: []*url.URL{workerURI}}, now)
	if err != nil {
		t.Fatalf("IssueClient() error = %v", err)
	}
	transport, err := discoverycleanup.NewSessionTransport(
		discoverycleanup.SessionTransportOptions{
			BaseURL: "https://127.0.0.1:9443", ServerName: "session-authority.test",
			ExpectedPeerIdentity: "spiffe://aiops.test/discovery-session-authority/shared",
			RootCAs:              ca.CertPool(), ClientCertificate: client.TLS,
		},
	)
	if err != nil {
		t.Fatalf("NewSessionTransport() error = %v", err)
	}
	factory := &productionRuntimeFactory{
		binding: discoverysource.RuntimeBinding{
			Locator: assetcatalog.SourceLocator{
				Scope: assetcatalog.SourceScope{
					TenantID: productionTestTenantID, WorkspaceID: productionTestWorkspaceID,
				},
				SourceID: productionTestSourceID,
			},
			SourceRevision: 1, SourceRevisionDigest: strings.Repeat("a", 64),
			RevisionStatus: assetcatalog.SourceRevisionPublished,
			ProviderKind:   "CMDB_CATALOG_V1", ProfileCode: "CMDB_CATALOG_V1",
		},
	}
	authority, err := NewAttemptSessionAuthority(
		transport, sourceprofile.ExternalCMDBV1(), factory,
	)
	if err != nil {
		transport.Destroy()
		t.Fatalf("NewAttemptSessionAuthority() error = %v", err)
	}
	keyring, err := discoverycheckpoint.NewInMemoryKeyring(
		"production-test-key", map[string][32]byte{"production-test-key": {1}},
	)
	if err != nil {
		authority.Destroy()
		transport.Destroy()
		t.Fatalf("NewInMemoryKeyring() error = %v", err)
	}
	codec, err := discoverycheckpoint.NewCheckpointCodec(keyring)
	if err != nil {
		keyring.Destroy()
		authority.Destroy()
		transport.Destroy()
		t.Fatalf("NewCheckpointCodec() error = %v", err)
	}
	registry, err := NewRegistry(ExternalCMDBDeclaration())
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	identity, err := NewWorkloadIdentity(client.TLS, ca.CertPool(), now)
	if err != nil {
		t.Fatalf("NewWorkloadIdentity() error = %v", err)
	}
	proof := &productionProofAuthority{key: []byte("0123456789abcdef0123456789abcdef")}
	queueFactory := &productionQueueFactory{}
	return &productionFixture{
		keyring: keyring, transport: transport, authority: authority,
		runtimeFactory: factory, proof: proof,
		queueFactory: queueFactory,
		dependencies: ProductionDependencies{
			Queue: queueFactory, PageCommitter: productionPageCommitter{},
			Limiter: productionLimiter{}, AttemptAuthority: authority,
			SessionTransport: transport, Checkpoints: codec, Registry: registry,
			WorkloadIdentity: identity, Observer: NewClosedWorkerObserver(),
			CleanupProofAuthority: proof,
		},
	}
}

type productionQueueFactory struct {
	mu       sync.Mutex
	builds   int
	verifier discoveryqueue.CleanupProofVerifier
}

func (factory *productionQueueFactory) BuildProductionQueue(
	verifier discoveryqueue.CleanupProofVerifier,
) (discoveryqueue.Queue, error) {
	factory.mu.Lock()
	factory.builds++
	factory.verifier = verifier
	factory.mu.Unlock()
	return &productionQueue{}, nil
}

func (fixture *productionFixture) close() {
	if fixture == nil {
		return
	}
	if fixture.authority != nil {
		fixture.authority.Destroy()
	}
	if fixture.transport != nil {
		fixture.transport.Destroy()
	}
	if fixture.proof != nil {
		fixture.proof.Destroy()
	}
	if fixture.keyring != nil {
		fixture.keyring.Destroy()
	}
}

type productionQueue struct {
	discoveryqueue.Queue
}

func (*productionQueue) Claim(context.Context, discoveryqueue.ClaimCommand) (discoveryqueue.ClaimResult, error) {
	return discoveryqueue.ClaimResult{}, discoveryqueue.ErrNoWork
}
func (*productionQueue) Reclaim(context.Context, discoveryqueue.ReclaimCommand) (discoveryqueue.ClaimResult, error) {
	return discoveryqueue.ClaimResult{}, discoveryqueue.ErrNoWork
}
func (*productionQueue) ReclaimFinalizing(context.Context, discoveryqueue.ReclaimCommand) (discoveryqueue.ClaimResult, error) {
	return discoveryqueue.ClaimResult{}, discoveryqueue.ErrNoWork
}

type productionPageCommitter struct{}

func (productionPageCommitter) ApplyPage(
	context.Context,
	assetcatalog.LeaseFence,
	discoverysource.PageCommitCoordinates,
	discoverysource.Page,
) (discoverysource.PageCommitResult, error) {
	return discoverysource.PageCommitResult{}, discoverysource.ErrPageCommitUnavailable
}

type productionLimiter struct{}

func (productionLimiter) Acquire(context.Context, discoverylimit.AcquireCommand) (discoverylimit.Permit, error) {
	return discoverylimit.Permit{}, discoverylimit.ErrUnavailable
}
func (productionLimiter) Release(context.Context, discoverylimit.ReleaseCommand) (discoverylimit.Receipt, error) {
	return discoverylimit.Receipt{}, discoverylimit.ErrUnavailable
}
func (productionLimiter) Delay(context.Context, discoverylimit.DelayCommand) (discoverylimit.Receipt, error) {
	return discoverylimit.Receipt{}, discoverylimit.ErrUnavailable
}

type productionRuntimeFactory struct {
	binding discoverysource.RuntimeBinding
}

type productionAttemptProfileDescriptor struct {
	sourceKind   assetcatalog.SourceKind
	providerKind string
	profileCode  assetcatalog.ProfileCode
	digest       string
}

func (descriptor productionAttemptProfileDescriptor) Valid() bool {
	return attemptProfileSnapshot{
		sourceKind: descriptor.sourceKind, providerKind: descriptor.providerKind,
		profileCode: descriptor.profileCode, digest: descriptor.digest,
	}.valid()
}

func (descriptor productionAttemptProfileDescriptor) SourceKind() assetcatalog.SourceKind {
	return descriptor.sourceKind
}

func (descriptor productionAttemptProfileDescriptor) ProviderKind() string {
	return descriptor.providerKind
}

func (descriptor productionAttemptProfileDescriptor) ProfileCode() assetcatalog.ProfileCode {
	return descriptor.profileCode
}

func (descriptor productionAttemptProfileDescriptor) DigestSHA256() string {
	return descriptor.digest
}

func (factory *productionRuntimeFactory) ResolveRuntimeBinding(
	context.Context,
	discoverycleanup.OpenAttemptRequest,
) (discoverysource.RuntimeBinding, error) {
	return factory.binding, nil
}

func (factory *productionRuntimeFactory) OpenInitialRuntime(
	ctx context.Context,
	request *InitialRuntimeRequest,
) (*SessionBoundRuntime, error) {
	return request.ResolveRuntime(
		ctx,
		func(
			_ context.Context,
			tuple *InitialRuntimeTuple,
		) (
			discoverysource.BoundRuntime,
			InitialRuntimeLifecycle,
			error,
		) {
			material := &struct{}{}
			runtime, err := discoverysource.BindRuntime(
				tuple.RuntimeBinding(),
				material,
				func(*struct{}) error { return nil },
				func(*struct{}) {},
			)
			if err != nil {
				return discoverysource.BoundRuntime{}, nil, err
			}
			return runtime, productionRuntimeLifecycle{}, nil
		},
	)
}

type productionRuntimeLifecycle struct{}

func (productionRuntimeLifecycle) Revoke(context.Context) error { return nil }
func (productionRuntimeLifecycle) Destroy()                     {}

func (factory *productionRuntimeFactory) ResolveClaimRuntime(
	context.Context,
	ResolveOpenedAttemptRequest,
) (
	discoverysource.Provider,
	*discoverysource.Checkpoint,
	discoverysource.Limits,
	assetdiscovery.FactPolicy,
	error,
) {
	return productionProvider{}, nil, discoverysource.Limits{}, assetdiscovery.FactPolicy{},
		errors.New("provider runtime is closed in constructor tests")
}

type productionProvider struct{}

func (productionProvider) Kind() assetcatalog.SourceKind { return assetcatalog.SourceKindExternalCMDB }
func (productionProvider) ProviderKind() string          { return "CMDB_CATALOG_V1" }
func (productionProvider) Validate(
	context.Context,
	discoverysource.BoundRuntime,
	discoverysource.ValidationRequest,
) (discoverysource.ValidationProof, error) {
	return discoverysource.ValidationProof{}, errors.New("provider call is forbidden")
}
func (productionProvider) Discover(
	context.Context,
	discoverysource.BoundRuntime,
	discoverysource.DiscoverRequest,
) (discoverysource.DiscoverOutcome, error) {
	return nil, errors.New("provider call is forbidden")
}

type productionProofAuthority struct {
	mu        sync.Mutex
	key       []byte
	destroyed bool
}

func (authority *productionProofAuthority) SignCleanupProof(
	ctx context.Context,
	digest []byte,
) ([]byte, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.destroyed || ctx == nil || ctx.Err() != nil {
		return nil, errors.New("proof authority unavailable")
	}
	mac := hmac.New(sha256.New, authority.key)
	_, _ = mac.Write(digest)
	return mac.Sum(nil), nil
}

func (authority *productionProofAuthority) VerifyCleanupProof(
	ctx context.Context,
	digest []byte,
	signature []byte,
) error {
	expected, err := authority.SignCleanupProof(ctx, digest)
	if err != nil || !hmac.Equal(expected, signature) {
		return errors.New("proof authority unavailable")
	}
	return nil
}

func (authority *productionProofAuthority) Destroy() {
	authority.mu.Lock()
	clear(authority.key)
	authority.key = nil
	authority.destroyed = true
	authority.mu.Unlock()
}

type productionObserverRecorder struct {
	mu           sync.Mutex
	observations []WorkerObservation
}

func (recorder *productionObserverRecorder) ObserveWorker(observation WorkerObservation) {
	recorder.mu.Lock()
	recorder.observations = append(recorder.observations, observation)
	recorder.mu.Unlock()
}

func (recorder *productionObserverRecorder) clone() []WorkerObservation {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]WorkerObservation(nil), recorder.observations...)
}

var (
	_ discoveryqueue.Queue            = (*productionQueue)(nil)
	_ discoverysource.PageCommitter   = productionPageCommitter{}
	_ discoverylimit.Limiter          = productionLimiter{}
	_ AttemptRuntimeFactory           = (*productionRuntimeFactory)(nil)
	_ discoverysource.Provider        = productionProvider{}
	_ ProductionCleanupProofAuthority = (*productionProofAuthority)(nil)
	_ WorkerObserver                  = (*productionObserverRecorder)(nil)
)
