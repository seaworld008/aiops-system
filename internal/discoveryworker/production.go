package discoveryworker

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverycheckpoint"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoverylimit"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

const (
	RuntimeAdmissionManifestSchemaVersion = "discovery-worker-runtime-admission.v1"
	productionRedaction                   = "[REDACTED_DISCOVERY_WORKER_PRODUCTION]"
	workloadIdentityRedaction             = "[REDACTED_DISCOVERY_WORKLOAD_IDENTITY]"
	productionSeal                        = uint64(0x47e98a61c30f2bd5)
	workloadIdentitySeal                  = uint64(0x8f0a5c12d9374eb6)
	productionLeaseDuration               = 15 * time.Second
)

var (
	ErrProductionDependencies = errors.New("discovery worker production dependencies invalid")
	ErrProductionUnavailable  = errors.New("discovery worker production unavailable")
	ErrWorkloadIdentity       = errors.New("discovery worker workload identity rejected")
)

// ProductionCleanupProofAuthority is a process-owned cleanup proof signer. Its
// Destroy method must clear signing material and permanently close the signer.
type ProductionCleanupProofAuthority interface {
	discoverycleanup.ProofAuthority
	Destroy()
}

// WorkloadIdentity is derived from a locally authenticated mTLS client
// certificate. It retains only a domain-separated digest of the canonical
// workload identity, never the URI or certificate.
type WorkloadIdentity struct {
	self   *WorkloadIdentity
	seal   uint64
	digest string
}

// NewWorkloadIdentity verifies the certificate chain for client
// authentication and derives a stable digest from its sole canonical SPIFFE
// URI. No precomputed digest is accepted.
func NewWorkloadIdentity(
	certificate tls.Certificate,
	roots *x509.CertPool,
	now time.Time,
) (*WorkloadIdentity, error) {
	if roots == nil || len(roots.Subjects()) == 0 || len(certificate.Certificate) == 0 ||
		certificate.PrivateKey == nil || now.IsZero() {
		return nil, ErrWorkloadIdentity
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || !validDiscoveryWorkloadCertificate(leaf) {
		return nil, ErrWorkloadIdentity
	}
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok || signer.Public() == nil {
		return nil, ErrWorkloadIdentity
	}
	leafPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, ErrWorkloadIdentity
	}
	signerPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || subtle.ConstantTimeCompare(leafPublic, signerPublic) != 1 {
		return nil, ErrWorkloadIdentity
	}
	intermediates := x509.NewCertPool()
	for _, encoded := range certificate.Certificate[1:] {
		intermediate, parseErr := x509.ParseCertificate(encoded)
		if parseErr != nil {
			return nil, ErrWorkloadIdentity
		}
		intermediates.AddCert(intermediate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, ErrWorkloadIdentity
	}
	digest := digestFramedTuple(
		"discovery-worker-workload-identity.v1",
		leaf.URIs[0].String(),
	)
	identity := &WorkloadIdentity{seal: workloadIdentitySeal, digest: digest}
	identity.self = identity
	return identity, nil
}

func validDiscoveryWorkloadCertificate(certificate *x509.Certificate) bool {
	if certificate == nil || certificate.IsCA || len(certificate.URIs) != 1 ||
		len(certificate.DNSNames) != 0 || len(certificate.IPAddresses) != 0 ||
		len(certificate.EmailAddresses) != 0 {
		return false
	}
	identity := certificate.URIs[0]
	if identity == nil || identity.Scheme != "spiffe" || identity.Host == "" ||
		identity.User != nil || identity.Port() != "" || identity.Opaque != "" ||
		identity.Path == "" || identity.Path == "/" || identity.RawPath != "" ||
		identity.RawQuery != "" || identity.Fragment != "" ||
		strings.Contains(identity.Path, "//") {
		return false
	}
	return identity.String() == canonicalDiscoveryWorkloadURI(identity)
}

func canonicalDiscoveryWorkloadURI(identity *url.URL) string {
	if identity == nil {
		return ""
	}
	return "spiffe://" + identity.Host + identity.EscapedPath()
}

func (identity *WorkloadIdentity) valid() bool {
	return identity != nil && identity.self == identity &&
		identity.seal == workloadIdentitySeal && validProductionDigest(identity.digest)
}

// ProductionDependencies contains only exact production boundaries. The
// AttemptAuthority is used as both SessionOpener and ClaimRuntimeResolver;
// neither role can be injected independently.
type ProductionQueueFactory interface {
	BuildProductionQueue(
		discoveryqueue.CleanupProofVerifier,
	) (discoveryqueue.Queue, error)
}

type ProductionDependencies struct {
	Queue                 ProductionQueueFactory
	PageCommitter         discoverysource.PageCommitter
	Limiter               discoverylimit.Limiter
	AttemptAuthority      *AttemptSessionAuthority
	SessionTransport      *discoverycleanup.SessionTransport
	Checkpoints           *discoverycheckpoint.CheckpointCodec
	Registry              *ProviderRegistry
	WorkloadIdentity      *WorkloadIdentity
	Observer              WorkerObserver
	CleanupProofAuthority ProductionCleanupProofAuthority
}

func (dependencies ProductionDependencies) Clone() ProductionDependencies {
	return dependencies
}

type ProductionIdentityDigests struct {
	WorkerIdentityDigest  string
	ProcessInstanceDigest string
}

type Production struct {
	self  *Production
	seal  uint64
	state *productionState
}

type productionState struct {
	mu                    sync.Mutex
	worker                *Worker
	broker                *discoverycleanup.CleanupBroker
	authority             *AttemptSessionAuthority
	transport             *discoverycleanup.SessionTransport
	proofAuthority        ProductionCleanupProofAuthority
	manifest              RuntimeAdmissionManifest
	workerIdentityDigest  string
	processInstanceDigest string
	closed                bool
}

func NewProduction(dependencies ProductionDependencies) (*Production, error) {
	if nilDependency(dependencies.Queue) ||
		nilDependency(dependencies.PageCommitter) ||
		nilDependency(dependencies.Limiter) ||
		dependencies.AttemptAuthority == nil ||
		dependencies.SessionTransport == nil ||
		dependencies.Checkpoints == nil ||
		!dependencies.Registry.valid() ||
		!productionAuthorityMatchesRegistry(
			dependencies.AttemptAuthority,
			dependencies.SessionTransport,
			dependencies.Registry,
		) ||
		!dependencies.WorkloadIdentity.valid() ||
		nilDependency(dependencies.Observer) ||
		nilDependency(dependencies.CleanupProofAuthority) {
		return nil, ErrProductionDependencies
	}
	processDigest, err := newProcessInstanceDigest()
	if err != nil {
		return nil, ErrProductionUnavailable
	}
	manifest, err := newRuntimeAdmissionManifest(dependencies.Registry)
	if err != nil {
		return nil, ErrProductionDependencies
	}
	broker, err := discoverycleanup.NewCleanupBroker(
		dependencies.AttemptAuthority,
		dependencies.CleanupProofAuthority,
	)
	if err != nil {
		return nil, ErrProductionDependencies
	}
	queue, err := dependencies.Queue.BuildProductionQueue(broker)
	if err != nil || nilDependency(queue) {
		broker.Destroy()
		return nil, ErrProductionDependencies
	}
	observed := newObservedDependencies(
		dependencies.Registry,
		dependencies.Observer,
		queue,
		dependencies.PageCommitter,
		dependencies.Limiter,
	)
	owner := "discovery-worker/" + dependencies.WorkloadIdentity.digest + "/" + processDigest
	worker, err := New(Dependencies{
		Queue: observed.queue, CleanupBroker: broker, Limiter: observed.limiter,
		PageCommitter: observed.pageCommitter, Checkpoints: dependencies.Checkpoints,
		ClaimRuntimeResolver: dependencies.AttemptAuthority,
		ClaimCommand: discoveryqueue.ClaimCommand{
			Owner: owner, LeaseDuration: productionLeaseDuration,
			ProviderKinds: dependencies.Registry.ProviderKinds(),
		},
	})
	if err != nil {
		broker.Destroy()
		return nil, ErrProductionDependencies
	}
	private := &productionState{
		worker: worker, broker: broker, authority: dependencies.AttemptAuthority,
		transport:             dependencies.SessionTransport,
		proofAuthority:        dependencies.CleanupProofAuthority,
		manifest:              manifest,
		workerIdentityDigest:  dependencies.WorkloadIdentity.digest,
		processInstanceDigest: processDigest,
	}
	production := &Production{seal: productionSeal, state: private}
	production.self = production
	return production, nil
}

func productionAuthorityMatchesRegistry(
	authority *AttemptSessionAuthority,
	transport *discoverycleanup.SessionTransport,
	registry *ProviderRegistry,
) bool {
	if !authority.authentic() || transport == nil || !registry.valid() {
		return false
	}
	private := authority.state
	private.mu.Lock()
	defer private.mu.Unlock()
	if private.destroyed || private.transport != transport ||
		nilDependency(private.factory) || !private.profile.valid() {
		return false
	}
	declaration, registered := registry.Lookup(
		private.profile.providerKind,
		private.profile.profileCode,
	)
	return registered &&
		declaration.SourceKind == private.profile.sourceKind &&
		declaration.ProviderKind == private.profile.providerKind &&
		declaration.ProfileCode == private.profile.profileCode &&
		declaration.CanonicalDescriptorDigest == private.profile.digest
}

func (production *Production) authentic() bool {
	return production != nil && production.self == production &&
		production.seal == productionSeal && production.state != nil
}

func (production *Production) Run(ctx context.Context) error {
	if ctx == nil || !production.authentic() {
		return ErrProductionUnavailable
	}
	private := production.state
	private.mu.Lock()
	if private.closed || private.worker == nil {
		private.mu.Unlock()
		return ErrProductionUnavailable
	}
	worker := private.worker
	private.mu.Unlock()
	return worker.Run(ctx)
}

func (production *Production) Stop(ctx context.Context) error {
	if ctx == nil || !production.authentic() {
		return ErrProductionUnavailable
	}
	private := production.state
	private.mu.Lock()
	if private.closed {
		private.mu.Unlock()
		return nil
	}
	worker := private.worker
	private.mu.Unlock()
	if worker == nil {
		return ErrProductionUnavailable
	}
	return worker.Stop(ctx)
}

func (production *Production) Ready() error {
	if !production.authentic() {
		return ErrProductionUnavailable
	}
	private := production.state
	private.mu.Lock()
	defer private.mu.Unlock()
	if private.closed || private.worker == nil || private.broker == nil ||
		private.authority == nil || private.transport == nil ||
		nilDependency(private.proofAuthority) ||
		!validProductionDigest(private.workerIdentityDigest) ||
		!validProductionDigest(private.processInstanceDigest) ||
		!private.manifest.valid() {
		return ErrProductionUnavailable
	}
	return nil
}

func (production *Production) IdentityDigests() ProductionIdentityDigests {
	if production.Ready() != nil {
		return ProductionIdentityDigests{}
	}
	private := production.state
	private.mu.Lock()
	defer private.mu.Unlock()
	return ProductionIdentityDigests{
		WorkerIdentityDigest:  private.workerIdentityDigest,
		ProcessInstanceDigest: private.processInstanceDigest,
	}
}

func (production *Production) RuntimeAdmissionManifest() RuntimeAdmissionManifest {
	if production.Ready() != nil {
		return RuntimeAdmissionManifest{}
	}
	private := production.state
	private.mu.Lock()
	defer private.mu.Unlock()
	return private.manifest.clone()
}

func (production *Production) Close() error {
	if !production.authentic() {
		return ErrProductionUnavailable
	}
	private := production.state
	private.mu.Lock()
	if private.closed {
		private.mu.Unlock()
		return nil
	}
	private.closed = true
	worker, broker := private.worker, private.broker
	authority, transport := private.authority, private.transport
	proofAuthority := private.proofAuthority
	private.worker = nil
	private.broker = nil
	private.authority = nil
	private.transport = nil
	private.proofAuthority = nil
	private.manifest = RuntimeAdmissionManifest{}
	private.workerIdentityDigest = ""
	private.processInstanceDigest = ""
	private.mu.Unlock()

	stopContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var stopErr error
	if worker != nil {
		stopErr = worker.Stop(stopContext)
	}
	if broker != nil {
		broker.Destroy()
	}
	if authority != nil {
		authority.Destroy()
	}
	if transport != nil {
		transport.Destroy()
	}
	if !nilDependency(proofAuthority) {
		proofAuthority.Destroy()
	}
	if stopErr != nil {
		return ErrProductionUnavailable
	}
	return nil
}

func newProcessInstanceDigest() (string, error) {
	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", err
	}
	digest := digestFramedTuple(
		"discovery-worker-process-instance.v1",
		fmt.Sprintf("%x", nonce[:]),
	)
	clear(nonce[:])
	return digest, nil
}

type RuntimeAdmissionEntry struct {
	ProviderKind                    string `json:"provider_kind"`
	ProfileCode                     string `json:"profile_code"`
	CanonicalDescriptorDigest       string `json:"canonical_descriptor_digest"`
	RuntimeRecoveryCapabilityDigest string `json:"runtime_recovery_capability_digest"`
}

type RuntimeAdmissionManifest struct {
	canonical []byte
	digest    string
	entries   []RuntimeAdmissionEntry
}

type runtimeAdmissionDocument struct {
	SchemaVersion string                  `json:"schema_version"`
	Providers     []RuntimeAdmissionEntry `json:"providers"`
}

func newRuntimeAdmissionManifest(
	registry *ProviderRegistry,
) (RuntimeAdmissionManifest, error) {
	if !registry.valid() {
		return RuntimeAdmissionManifest{}, ErrProductionDependencies
	}
	entries := make([]RuntimeAdmissionEntry, 0, len(registry.entries))
	for _, providerKind := range registry.ProviderKinds() {
		for key, registered := range registry.entries {
			if key.provider != providerKind {
				continue
			}
			entries = append(entries, RuntimeAdmissionEntry{
				ProviderKind:                    registered.declaration.ProviderKind,
				ProfileCode:                     string(registered.declaration.ProfileCode),
				CanonicalDescriptorDigest:       registered.declaration.CanonicalDescriptorDigest,
				RuntimeRecoveryCapabilityDigest: registered.declaration.RuntimeRecoveryCapabilityDigest,
			})
		}
	}
	document := runtimeAdmissionDocument{
		SchemaVersion: RuntimeAdmissionManifestSchemaVersion,
		Providers:     entries,
	}
	canonical, err := json.Marshal(document)
	if err != nil || len(entries) == 0 {
		return RuntimeAdmissionManifest{}, ErrProductionDependencies
	}
	digest := sha256.Sum256(canonical)
	return RuntimeAdmissionManifest{
		canonical: slices.Clone(canonical), digest: fmt.Sprintf("%x", digest),
		entries: slices.Clone(entries),
	}, nil
}

func (manifest RuntimeAdmissionManifest) valid() bool {
	if !validProductionDigest(manifest.digest) || len(manifest.canonical) == 0 ||
		len(manifest.entries) == 0 {
		return false
	}
	digest := sha256.Sum256(manifest.canonical)
	return subtle.ConstantTimeCompare(
		[]byte(manifest.digest),
		[]byte(fmt.Sprintf("%x", digest)),
	) == 1
}

func (manifest RuntimeAdmissionManifest) clone() RuntimeAdmissionManifest {
	if !manifest.valid() {
		return RuntimeAdmissionManifest{}
	}
	return RuntimeAdmissionManifest{
		canonical: slices.Clone(manifest.canonical), digest: manifest.digest,
		entries: slices.Clone(manifest.entries),
	}
}

func (manifest RuntimeAdmissionManifest) CanonicalJSON() []byte {
	if !manifest.valid() {
		return nil
	}
	return slices.Clone(manifest.canonical)
}

func (manifest RuntimeAdmissionManifest) DigestSHA256() string {
	if !manifest.valid() {
		return ""
	}
	return manifest.digest
}

func (manifest RuntimeAdmissionManifest) Entries() []RuntimeAdmissionEntry {
	if !manifest.valid() {
		return nil
	}
	return slices.Clone(manifest.entries)
}

type ObserverProvider string

const (
	ObserverProviderExternalCMDB ObserverProvider = "CMDB_CATALOG_V1"
	ObserverProviderUnknown      ObserverProvider = "UNREGISTERED"
)

func (provider ObserverProvider) Valid() bool {
	return provider == ObserverProviderExternalCMDB ||
		provider == ObserverProviderUnknown
}

type ObserverBoundary string

const (
	ObserverBoundaryQueueClaim      ObserverBoundary = "QUEUE_CLAIM"
	ObserverBoundaryQueueRecovery   ObserverBoundary = "QUEUE_RECOVERY"
	ObserverBoundaryQueueHeartbeat  ObserverBoundary = "QUEUE_HEARTBEAT"
	ObserverBoundaryQueueTransition ObserverBoundary = "QUEUE_TRANSITION"
	ObserverBoundaryQueueCleanup    ObserverBoundary = "QUEUE_CLEANUP"
	ObserverBoundaryQueueTerminal   ObserverBoundary = "QUEUE_TERMINAL"
	ObserverBoundaryPageCommit      ObserverBoundary = "PAGE_COMMIT"
	ObserverBoundaryLimiterAcquire  ObserverBoundary = "LIMITER_ACQUIRE"
	ObserverBoundaryLimiterTerminal ObserverBoundary = "LIMITER_TERMINAL"
)

func (boundary ObserverBoundary) Valid() bool {
	switch boundary {
	case ObserverBoundaryQueueClaim, ObserverBoundaryQueueRecovery,
		ObserverBoundaryQueueHeartbeat, ObserverBoundaryQueueTransition,
		ObserverBoundaryQueueCleanup, ObserverBoundaryQueueTerminal,
		ObserverBoundaryPageCommit, ObserverBoundaryLimiterAcquire,
		ObserverBoundaryLimiterTerminal:
		return true
	default:
		return false
	}
}

type ObserverResult string

const (
	ObserverResultSuccess     ObserverResult = "SUCCESS"
	ObserverResultNoWork      ObserverResult = "NO_WORK"
	ObserverResultRejected    ObserverResult = "REJECTED"
	ObserverResultUnavailable ObserverResult = "UNAVAILABLE"
	ObserverResultCancelled   ObserverResult = "CANCELLED"
	ObserverResultFailed      ObserverResult = "FAILED"
)

func (result ObserverResult) Valid() bool {
	switch result {
	case ObserverResultSuccess, ObserverResultNoWork, ObserverResultRejected,
		ObserverResultUnavailable, ObserverResultCancelled, ObserverResultFailed:
		return true
	default:
		return false
	}
}

// WorkerObservation is deliberately limited to three closed, low-cardinality
// enums. It cannot carry Scope, Source, Run, external IDs, addresses, digests,
// or caller-defined labels.
type WorkerObservation struct {
	provider ObserverProvider
	boundary ObserverBoundary
	result   ObserverResult
}

func (observation WorkerObservation) Provider() ObserverProvider {
	return observation.provider
}
func (observation WorkerObservation) Boundary() ObserverBoundary {
	return observation.boundary
}
func (observation WorkerObservation) Result() ObserverResult {
	return observation.result
}

type WorkerObserver interface {
	ObserveWorker(WorkerObservation)
}

type closedWorkerObserver struct{}

func (closedWorkerObserver) ObserveWorker(WorkerObservation) {}

func NewClosedWorkerObserver() WorkerObserver {
	return closedWorkerObserver{}
}

type observedDependencies struct {
	queue         discoveryqueue.Queue
	pageCommitter discoverysource.PageCommitter
	limiter       discoverylimit.Limiter
}

type observationEmitter struct {
	registry *ProviderRegistry
	observer WorkerObserver
}

func newObservedDependencies(
	registry *ProviderRegistry,
	observer WorkerObserver,
	queue discoveryqueue.Queue,
	pageCommitter discoverysource.PageCommitter,
	limiter discoverylimit.Limiter,
) observedDependencies {
	emitter := &observationEmitter{registry: registry, observer: observer}
	return observedDependencies{
		queue: &observedQueue{delegate: queue, emitter: emitter},
		pageCommitter: &observedPageCommitter{
			delegate: pageCommitter, emitter: emitter,
		},
		limiter: &observedLimiter{delegate: limiter, emitter: emitter},
	}
}

func (emitter *observationEmitter) emit(
	providerKind string,
	boundary ObserverBoundary,
	err error,
) {
	if emitter == nil || !emitter.registry.valid() ||
		nilDependency(emitter.observer) || !boundary.Valid() {
		return
	}
	provider := ObserverProviderUnknown
	if providerKind == string(ObserverProviderExternalCMDB) &&
		slices.Contains(emitter.registry.ProviderKinds(), providerKind) {
		provider = ObserverProviderExternalCMDB
	}
	observation := WorkerObservation{
		provider: provider, boundary: boundary, result: observerResult(err),
	}
	func() {
		defer func() { _ = recover() }()
		emitter.observer.ObserveWorker(observation)
	}()
}

func (emitter *observationEmitter) exactRegistryProviderKind() string {
	if emitter == nil || !emitter.registry.valid() {
		return ""
	}
	return singleProvider(emitter.registry.ProviderKinds())
}

func observerResult(err error) ObserverResult {
	switch {
	case err == nil:
		return ObserverResultSuccess
	case errors.Is(err, discoveryqueue.ErrNoWork):
		return ObserverResultNoWork
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return ObserverResultCancelled
	case errors.Is(err, discoveryqueue.ErrUnavailable),
		errors.Is(err, discoverylimit.ErrUnavailable),
		errors.Is(err, discoverysource.ErrPageCommitUnavailable):
		return ObserverResultUnavailable
	case errors.Is(err, discoveryqueue.ErrInvalidRequest),
		errors.Is(err, discoveryqueue.ErrIneligible),
		errors.Is(err, discoveryqueue.ErrStaleFence),
		errors.Is(err, discoveryqueue.ErrStateConflict),
		errors.Is(err, discoveryqueue.ErrIdempotency),
		errors.Is(err, discoverylimit.ErrInvalidRequest),
		errors.Is(err, discoverylimit.ErrIneligible),
		errors.Is(err, discoverylimit.ErrStalePermit),
		errors.Is(err, discoverylimit.ErrStateConflict),
		errors.Is(err, discoverylimit.ErrIdempotency),
		errors.Is(err, discoverysource.ErrPageCommitInvalid),
		errors.Is(err, discoverysource.ErrPageCommitConflict):
		return ObserverResultRejected
	default:
		return ObserverResultFailed
	}
}

type observedQueue struct {
	delegate discoveryqueue.Queue
	emitter  *observationEmitter
}

func (queue *observedQueue) Claim(
	ctx context.Context, command discoveryqueue.ClaimCommand,
) (result discoveryqueue.ClaimResult, err error) {
	result, err = queue.delegate.Claim(ctx, command)
	queue.emitter.emit(result.ProviderKind, ObserverBoundaryQueueClaim, err)
	return
}
func (queue *observedQueue) Reclaim(
	ctx context.Context, command discoveryqueue.ReclaimCommand,
) (result discoveryqueue.ClaimResult, err error) {
	result, err = queue.delegate.Reclaim(ctx, command)
	queue.emitter.emit(result.ProviderKind, ObserverBoundaryQueueRecovery, err)
	return
}
func (queue *observedQueue) ReclaimFinalizing(
	ctx context.Context, command discoveryqueue.ReclaimCommand,
) (result discoveryqueue.ClaimResult, err error) {
	result, err = queue.delegate.ReclaimFinalizing(ctx, command)
	queue.emitter.emit(result.ProviderKind, ObserverBoundaryQueueRecovery, err)
	return
}
func (queue *observedQueue) ReapDrifted(
	ctx context.Context, command discoveryqueue.ReapCommand,
) (result discoveryqueue.ClaimResult, err error) {
	result, err = queue.delegate.ReapDrifted(ctx, command)
	queue.emitter.emit(result.ProviderKind, ObserverBoundaryQueueRecovery, err)
	return
}
func (queue *observedQueue) CancelIneligible(
	ctx context.Context, command discoveryqueue.CancelCommand,
) (result discoveryqueue.CancelResult, err error) {
	result, err = queue.delegate.CancelIneligible(ctx, command)
	queue.emitter.emit(singleProvider(command.ProviderKinds), ObserverBoundaryQueueTransition, err)
	return
}
func (queue *observedQueue) Heartbeat(
	ctx context.Context, fence assetcatalog.LeaseFence, command discoveryqueue.HeartbeatCommand,
) (result discoveryqueue.HeartbeatResult, err error) {
	result, err = queue.delegate.Heartbeat(ctx, fence, command)
	queue.emitter.emit("", ObserverBoundaryQueueHeartbeat, err)
	return
}
func (queue *observedQueue) AdvanceStage(
	ctx context.Context, fence assetcatalog.LeaseFence, command discoveryqueue.AdvanceStageCommand,
) (result assetcatalog.SourceRun, err error) {
	result, err = queue.delegate.AdvanceStage(ctx, fence, command)
	queue.emitter.emit("", ObserverBoundaryQueueTransition, err)
	return
}
func (queue *observedQueue) ReserveCleanupAttempt(
	ctx context.Context, fence assetcatalog.LeaseFence, command discoveryqueue.RunCommand,
) (result discoveryqueue.CleanupAttempt, err error) {
	result, err = queue.delegate.ReserveCleanupAttempt(ctx, fence, command)
	queue.emitter.emit("", ObserverBoundaryQueueCleanup, err)
	return
}
func (queue *observedQueue) RecordCleanup(
	ctx context.Context, fence assetcatalog.LeaseFence, proof discoveryqueue.CleanupProof,
) (result discoveryqueue.CleanupResult, err error) {
	result, err = queue.delegate.RecordCleanup(ctx, fence, proof)
	queue.emitter.emit("", ObserverBoundaryQueueCleanup, err)
	return
}
func (queue *observedQueue) Delay(
	ctx context.Context, fence assetcatalog.LeaseFence, command discoveryqueue.DelayCommand,
) (result assetcatalog.SourceRun, err error) {
	result, err = queue.delegate.Delay(ctx, fence, command)
	queue.emitter.emit("", ObserverBoundaryQueueTransition, err)
	return
}
func (queue *observedQueue) ProposeValidationResult(
	ctx context.Context, fence assetcatalog.LeaseFence, command discoveryqueue.ValidationResultCommand,
) (result discoveryqueue.WorkResult, err error) {
	result, err = queue.delegate.ProposeValidationResult(ctx, fence, command)
	queue.emitter.emit("", ObserverBoundaryQueueTransition, err)
	return
}
func (queue *observedQueue) PrepareFailureIntent(
	ctx context.Context, fence assetcatalog.LeaseFence, command discoveryqueue.FailureIntentCommand,
) (result discoveryqueue.WorkResult, err error) {
	result, err = queue.delegate.PrepareFailureIntent(ctx, fence, command)
	queue.emitter.emit("", ObserverBoundaryQueueTransition, err)
	return
}
func (queue *observedQueue) BeginCheckpointLineageRollover(
	ctx context.Context, fence assetcatalog.LeaseFence, command discoveryqueue.RolloverCommand,
) (result discoveryqueue.RolloverResult, err error) {
	result, err = queue.delegate.BeginCheckpointLineageRollover(ctx, fence, command)
	queue.emitter.emit("", ObserverBoundaryQueueTransition, err)
	return
}
func (queue *observedQueue) Complete(
	ctx context.Context, fence assetcatalog.LeaseFence, command discoveryqueue.TerminalCommand,
) (result discoveryqueue.TerminalResult, err error) {
	result, err = queue.delegate.Complete(ctx, fence, command)
	queue.emitter.emit("", ObserverBoundaryQueueTerminal, err)
	return
}
func (queue *observedQueue) Fail(
	ctx context.Context, fence assetcatalog.LeaseFence, command discoveryqueue.TerminalCommand,
) (result discoveryqueue.TerminalResult, err error) {
	result, err = queue.delegate.Fail(ctx, fence, command)
	queue.emitter.emit("", ObserverBoundaryQueueTerminal, err)
	return
}

type observedPageCommitter struct {
	delegate discoverysource.PageCommitter
	emitter  *observationEmitter
}

func (committer *observedPageCommitter) ApplyPage(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	coordinates discoverysource.PageCommitCoordinates,
	page discoverysource.Page,
) (result discoverysource.PageCommitResult, err error) {
	result, err = committer.delegate.ApplyPage(ctx, fence, coordinates, page)
	committer.emitter.emit(
		committer.emitter.exactRegistryProviderKind(),
		ObserverBoundaryPageCommit,
		err,
	)
	return
}

type observedLimiter struct {
	delegate discoverylimit.Limiter
	emitter  *observationEmitter
}

func (limiter *observedLimiter) Acquire(
	ctx context.Context, command discoverylimit.AcquireCommand,
) (result discoverylimit.Permit, err error) {
	result, err = limiter.delegate.Acquire(ctx, command)
	limiter.emitter.emit(
		command.Coordinates.ProviderKind, ObserverBoundaryLimiterAcquire, err,
	)
	return
}
func (limiter *observedLimiter) Release(
	ctx context.Context, command discoverylimit.ReleaseCommand,
) (result discoverylimit.Receipt, err error) {
	result, err = limiter.delegate.Release(ctx, command)
	limiter.emitter.emit(
		command.Coordinates.ProviderKind, ObserverBoundaryLimiterTerminal, err,
	)
	return
}
func (limiter *observedLimiter) Delay(
	ctx context.Context, command discoverylimit.DelayCommand,
) (result discoverylimit.Receipt, err error) {
	result, err = limiter.delegate.Delay(ctx, command)
	limiter.emitter.emit(
		command.Coordinates.ProviderKind, ObserverBoundaryLimiterTerminal, err,
	)
	return
}

func singleProvider(values []string) string {
	if len(values) == 1 {
		return values[0]
	}
	return ""
}

func digestFramedTuple(fields ...string) string {
	var encoded bytes.Buffer
	for _, field := range fields {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = encoded.Write(length[:])
		_, _ = encoded.WriteString(field)
	}
	digest := sha256.Sum256(encoded.Bytes())
	return fmt.Sprintf("%x", digest)
}

func validProductionDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	for _, character := range []byte(value) {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func (Production) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*Production) UnmarshalJSON([]byte) error { return ErrSensitiveSerialization }
func (Production) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*Production) UnmarshalText([]byte) error { return ErrSensitiveSerialization }
func (Production) MarshalBinary() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*Production) UnmarshalBinary([]byte) error { return ErrSensitiveSerialization }
func (Production) String() string                { return productionRedaction }
func (Production) GoString() string              { return productionRedaction }
func (Production) LogValue() slog.Value          { return slog.StringValue(productionRedaction) }
func (Production) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, productionRedaction)
}

func (WorkloadIdentity) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*WorkloadIdentity) UnmarshalJSON([]byte) error { return ErrSensitiveSerialization }
func (WorkloadIdentity) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*WorkloadIdentity) UnmarshalText([]byte) error { return ErrSensitiveSerialization }
func (WorkloadIdentity) MarshalBinary() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (*WorkloadIdentity) UnmarshalBinary([]byte) error { return ErrSensitiveSerialization }
func (WorkloadIdentity) String() string                { return workloadIdentityRedaction }
func (WorkloadIdentity) GoString() string              { return workloadIdentityRedaction }
func (WorkloadIdentity) LogValue() slog.Value {
	return slog.StringValue(workloadIdentityRedaction)
}
func (WorkloadIdentity) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, workloadIdentityRedaction)
}

var (
	_ discoveryqueue.Queue          = (*observedQueue)(nil)
	_ discoverysource.PageCommitter = (*observedPageCommitter)(nil)
	_ discoverylimit.Limiter        = (*observedLimiter)(nil)
)
