package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	assetpostgres "github.com/seaworld008/aiops-system/internal/assetcatalog/postgres"
	"github.com/seaworld008/aiops-system/internal/discoverycheckpoint"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoverylimit"
	limitpostgres "github.com/seaworld008/aiops-system/internal/discoverylimit/postgres"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	queuepostgres "github.com/seaworld008/aiops-system/internal/discoveryqueue/postgres"
	"github.com/seaworld008/aiops-system/internal/discoveryruntime"
	"github.com/seaworld008/aiops-system/internal/discoveryworker"
	"github.com/seaworld008/aiops-system/internal/securemanifest"
	"github.com/seaworld008/aiops-system/internal/sourceprofile"
	storepostgres "github.com/seaworld008/aiops-system/internal/store/postgres"
	"golang.org/x/sys/unix"
)

const (
	sourceProfileManifestSchemaVersion = "discovery-worker-source-profile-manifest.v1"
	sourceProfilePayloadSchemaVersion  = "discovery-worker-source-profile-payload.v1"
	sourceProfileKeySchemaVersion      = "discovery-worker-source-profile-key.v1"
	checkpointKeyringSchemaVersion     = "discovery-worker-checkpoint-keyring.v1"
	cleanupProofKeySchemaVersion       = "discovery-worker-cleanup-proof-key.v1"
	sourceProfileSignatureDomain       = "discovery-worker-source-profile-signature.v1"
	maximumProductionKeys              = 8
)

var errBootstrapUnavailable = errors.New("discovery worker bootstrap unavailable")

type productionRuntimeDependencies struct {
	observer              discoveryworker.WorkerObserver
	externalCMDBMaterials discoveryruntime.ExternalCMDBMaterialResolver
}

func defaultProductionRuntimeDependencies() productionRuntimeDependencies {
	return productionRuntimeDependencies{
		observer:              discoveryworker.NewClosedWorkerObserver(),
		externalCMDBMaterials: closedExternalCMDBMaterialResolver{},
	}
}

func (dependencies productionRuntimeDependencies) valid() bool {
	return !nilProductionDependency(dependencies.observer) &&
		!nilProductionDependency(dependencies.externalCMDBMaterials)
}

type closedExternalCMDBMaterialResolver struct{}

func (closedExternalCMDBMaterialResolver) ResolveExternalCMDB(
	ctx context.Context,
	_ *discoveryruntime.ExternalCMDBMaterialRequest,
) (*discoveryruntime.ExternalCMDBRuntimeMaterial, error) {
	if ctx == nil {
		return nil, discoveryruntime.ErrExternalCMDBRuntimeAuthority
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, discoveryruntime.ErrExternalCMDBRuntimeAuthority
}

type productionRuntime struct {
	mu               sync.Mutex
	worker           *discoveryworker.Production
	runtimeAuthority *discoveryruntime.ExternalCMDBAuthority
	pool             *pgxpool.Pool
	poolConfig       *pgxpool.Config
	checkpointKeys   *discoverycheckpoint.InMemoryKeyring
	schemaAdmission  *assetpostgres.SchemaAdmission
	roleAdmission    *storepostgres.DatabaseRoleAdmission
	listener         net.Listener
	server           *http.Server
	manifestDigest   string
	running          bool
	stopping         bool
	closed           bool
}

func newProduction(config Config) (*productionRuntime, error) {
	return newProductionWithObserver(config, discoveryworker.NewClosedWorkerObserver())
}

func newProductionWithObserver(
	config Config,
	observer discoveryworker.WorkerObserver,
) (*productionRuntime, error) {
	dependencies := defaultProductionRuntimeDependencies()
	dependencies.observer = observer
	return newProductionWithRuntimeDependencies(
		config,
		dependencies,
	)
}

func newProductionWithRuntimeDependencies(
	config Config,
	dependencies productionRuntimeDependencies,
) (*productionRuntime, error) {
	if config.Validate() != nil || !dependencies.valid() {
		return nil, errProductionUnavailable
	}

	certificate, roots, err := loadWorkloadTLS(
		config.WorkloadCertificateFile,
		config.WorkloadPrivateKeyFile,
		config.WorkloadCAFile,
	)
	if err != nil {
		return nil, errProductionUnavailable
	}
	identity, err := discoveryworker.NewWorkloadIdentity(certificate, roots, time.Now())
	if err != nil {
		clearTLSCertificate(&certificate)
		return nil, errProductionUnavailable
	}

	signingKeyID, signingKey, err := loadHMACKey(
		config.SourceProfileManifestKeyFile,
		sourceProfileKeySchemaVersion,
	)
	if err != nil {
		clearTLSCertificate(&certificate)
		return nil, errProductionUnavailable
	}
	registry, profileRegistry, err := loadSourceProfileManifest(
		config.SourceProfileManifestFile,
		signingKeyID,
		signingKey,
	)
	clear(signingKey[:])
	if err != nil {
		clearTLSCertificate(&certificate)
		return nil, errProductionUnavailable
	}

	checkpointKeys, err := loadCheckpointKeyring(config.CheckpointKeyringFile)
	if err != nil {
		clearTLSCertificate(&certificate)
		return nil, errProductionUnavailable
	}
	checkpoints, err := discoverycheckpoint.NewCheckpointCodec(checkpointKeys)
	if err != nil {
		checkpointKeys.Destroy()
		clearTLSCertificate(&certificate)
		return nil, errProductionUnavailable
	}

	_, cleanupKey, err := loadHMACKey(
		config.CleanupProofKeyFile,
		cleanupProofKeySchemaVersion,
	)
	if err != nil {
		checkpointKeys.Destroy()
		clearTLSCertificate(&certificate)
		return nil, errProductionUnavailable
	}
	proofAuthority, err := newHMACProofAuthority(cleanupKey)
	clear(cleanupKey[:])
	if err != nil {
		checkpointKeys.Destroy()
		clearTLSCertificate(&certificate)
		return nil, errProductionUnavailable
	}

	poolConfig, err := loadDatabaseConfig(config.DatabaseDSNFile)
	if err != nil {
		proofAuthority.Destroy()
		checkpointKeys.Destroy()
		clearTLSCertificate(&certificate)
		return nil, errProductionUnavailable
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		clearDatabaseConfig(poolConfig)
		proofAuthority.Destroy()
		checkpointKeys.Destroy()
		clearTLSCertificate(&certificate)
		return nil, errProductionUnavailable
	}

	cleanup := func() {
		pool.Close()
		clearDatabaseConfig(poolConfig)
		proofAuthority.Destroy()
		checkpointKeys.Destroy()
		clearTLSCertificate(&certificate)
	}
	startupContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	schemaAdmission := assetpostgres.NewSchemaAdmission(pool, "public")
	roleAdmission := storepostgres.NewDatabaseRoleAdmission(pool, "public")
	var databaseTime time.Time
	if pool.Ping(startupContext) != nil ||
		schemaAdmission.Check(startupContext) != nil ||
		roleAdmission.Check(startupContext) != nil ||
		pool.QueryRow(startupContext, "SELECT clock_timestamp()").Scan(&databaseTime) != nil ||
		databaseTime.IsZero() {
		cleanup()
		return nil, errProductionUnavailable
	}

	neutral, reconciliation, err := registry.ExternalCMDBDescriptors()
	if err != nil {
		cleanup()
		return nil, errProductionUnavailable
	}
	assetRepository, err := assetpostgres.NewWithSourceProfileRegistry(
		pool,
		time.Now,
		uuid.NewString,
		profileRegistry,
	)
	if err != nil {
		cleanup()
		return nil, errProductionUnavailable
	}
	pageCommitter, err := assetpostgres.NewPageCommitter(
		assetRepository,
		checkpointKeys,
		reconciliation,
	)
	if err != nil {
		cleanup()
		return nil, errProductionUnavailable
	}
	limiter, err := limitpostgres.New(pool, assetRepository)
	if err != nil {
		cleanup()
		return nil, errProductionUnavailable
	}

	sessionTransport, err := discoverycleanup.NewSessionTransport(
		discoverycleanup.SessionTransportOptions{
			BaseURL:              config.SessionAuthorityEndpoint,
			ServerName:           config.SessionAuthorityServerName,
			ExpectedPeerIdentity: config.SessionAuthorityPeerIdentity,
			RootCAs:              roots,
			ClientCertificate:    certificate,
		},
	)
	if err != nil {
		cleanup()
		return nil, errProductionUnavailable
	}
	runtimePostgres, err := discoveryruntime.NewPostgres(pool)
	if err != nil {
		sessionTransport.Destroy()
		cleanup()
		return nil, errProductionUnavailable
	}
	runtimeAuthority, err := discoveryruntime.NewExternalCMDBAuthority(
		runtimePostgres,
		dependencies.externalCMDBMaterials,
	)
	if err != nil {
		sessionTransport.Destroy()
		cleanup()
		return nil, errProductionUnavailable
	}
	attemptAuthority, err := discoveryworker.NewAttemptSessionAuthority(
		sessionTransport,
		neutral,
		runtimeAuthority,
	)
	if err != nil {
		runtimeAuthority.Destroy()
		sessionTransport.Destroy()
		cleanup()
		return nil, errProductionUnavailable
	}
	queueFactory := &postgresQueueFactory{
		pool:     pool,
		rollover: closedRolloverVerifier{},
	}
	worker, err := discoveryworker.NewProduction(discoveryworker.ProductionDependencies{
		Queue:                 queueFactory,
		PageCommitter:         pageCommitter,
		Limiter:               limiter,
		AttemptAuthority:      attemptAuthority,
		SessionTransport:      sessionTransport,
		Checkpoints:           checkpoints,
		Registry:              registry,
		WorkloadIdentity:      identity,
		Observer:              dependencies.observer,
		CleanupProofAuthority: proofAuthority,
	})
	clearTLSCertificate(&certificate)
	if err != nil {
		attemptAuthority.Destroy()
		runtimeAuthority.Destroy()
		sessionTransport.Destroy()
		cleanup()
		return nil, errProductionUnavailable
	}

	listener, err := net.Listen("tcp", config.MetricsBindAddress)
	if err != nil {
		_ = worker.Close()
		runtimeAuthority.Destroy()
		pool.Close()
		clearDatabaseConfig(poolConfig)
		checkpointKeys.Destroy()
		return nil, errProductionUnavailable
	}
	admissionManifest := worker.RuntimeAdmissionManifest()
	runtime := &productionRuntime{
		worker: worker, runtimeAuthority: runtimeAuthority,
		pool: pool, poolConfig: poolConfig,
		checkpointKeys: checkpointKeys, schemaAdmission: schemaAdmission,
		roleAdmission: roleAdmission,
		listener:      listener, manifestDigest: admissionManifest.DigestSHA256(),
	}
	runtime.server = &http.Server{
		Handler:           runtime.privateHandler(),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	if runtime.ready(startupContext) != nil {
		_ = runtime.Close()
		return nil, errProductionUnavailable
	}
	return runtime, nil
}

func (runtime *productionRuntime) Run(ctx context.Context) error {
	if ctx == nil || runtime == nil {
		return errProductionUnavailable
	}
	runtime.mu.Lock()
	if runtime.closed || runtime.running || runtime.stopping ||
		runtime.worker == nil || runtime.server == nil || runtime.listener == nil {
		runtime.mu.Unlock()
		return errProductionUnavailable
	}
	runtime.running = true
	worker, server, listener := runtime.worker, runtime.server, runtime.listener
	runtime.mu.Unlock()

	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- worker.Run(runContext) }()
	go func() { results <- server.Serve(listener) }()

	var result error
	select {
	case <-ctx.Done():
		result = ctx.Err()
	case result = <-results:
	}
	cancel()
	stopContext, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	stopErr := runtime.Stop(stopContext)
	stopCancel()

	runtime.mu.Lock()
	runtime.running = false
	runtime.mu.Unlock()
	if ctx.Err() != nil && errors.Is(result, ctx.Err()) && stopErr == nil {
		return ctx.Err()
	}
	return errProductionUnavailable
}

func (runtime *productionRuntime) Stop(ctx context.Context) error {
	if ctx == nil || runtime == nil {
		return errProductionUnavailable
	}
	runtime.mu.Lock()
	if runtime.closed {
		runtime.mu.Unlock()
		return nil
	}
	runtime.stopping = true
	worker, server := runtime.worker, runtime.server
	runtime.mu.Unlock()

	var failed bool
	if worker == nil || worker.Stop(ctx) != nil {
		failed = true
	}
	if server == nil || server.Shutdown(ctx) != nil {
		failed = true
	}
	runtime.mu.Lock()
	runtime.stopping = false
	runtime.mu.Unlock()
	if failed {
		return errProductionUnavailable
	}
	return nil
}

func (runtime *productionRuntime) Close() error {
	if runtime == nil {
		return errProductionUnavailable
	}
	runtime.mu.Lock()
	if runtime.closed {
		runtime.mu.Unlock()
		return nil
	}
	runtime.closed = true
	worker, pool, poolConfig := runtime.worker, runtime.pool, runtime.poolConfig
	runtimeAuthority := runtime.runtimeAuthority
	keys, listener := runtime.checkpointKeys, runtime.listener
	runtime.worker = nil
	runtime.runtimeAuthority = nil
	runtime.pool = nil
	runtime.poolConfig = nil
	runtime.checkpointKeys = nil
	runtime.schemaAdmission = nil
	runtime.roleAdmission = nil
	runtime.listener = nil
	runtime.server = nil
	runtime.manifestDigest = ""
	runtime.mu.Unlock()

	var failed bool
	if listener != nil {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			failed = true
		}
	}
	if worker != nil && worker.Close() != nil {
		failed = true
	}
	if runtimeAuthority != nil {
		runtimeAuthority.Destroy()
	}
	if keys != nil {
		keys.Destroy()
	}
	if pool != nil {
		pool.Close()
	}
	clearDatabaseConfig(poolConfig)
	if failed {
		return errProductionUnavailable
	}
	return nil
}

func (runtime *productionRuntime) ready(ctx context.Context) error {
	if runtime == nil || ctx == nil {
		return errProductionUnavailable
	}
	runtime.mu.Lock()
	if runtime.closed || runtime.stopping || runtime.worker == nil ||
		runtime.runtimeAuthority == nil ||
		runtime.pool == nil || runtime.schemaAdmission == nil ||
		runtime.roleAdmission == nil ||
		runtime.listener == nil || runtime.server == nil ||
		!validLowerDigest(runtime.manifestDigest) {
		runtime.mu.Unlock()
		return errProductionUnavailable
	}
	worker, pool := runtime.worker, runtime.pool
	schema, role := runtime.schemaAdmission, runtime.roleAdmission
	expectedManifest := runtime.manifestDigest
	runtime.mu.Unlock()

	if worker.Ready() != nil ||
		worker.RuntimeAdmissionManifest().DigestSHA256() != expectedManifest ||
		pool.Ping(ctx) != nil ||
		schema.Check(ctx) != nil ||
		role.Check(ctx) != nil {
		return errProductionUnavailable
	}
	var databaseTime time.Time
	if pool.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&databaseTime) != nil ||
		databaseTime.IsZero() {
		return errProductionUnavailable
	}
	return nil
}

func (runtime *productionRuntime) privateHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writePrivateStatus(writer, http.StatusMethodNotAllowed, "unavailable")
			return
		}
		runtime.mu.Lock()
		healthy := !runtime.closed
		runtime.mu.Unlock()
		if !healthy {
			writePrivateStatus(writer, http.StatusServiceUnavailable, "unavailable")
			return
		}
		writePrivateStatus(writer, http.StatusOK, "ok")
	})
	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writePrivateStatus(writer, http.StatusMethodNotAllowed, "unavailable")
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
		defer cancel()
		if runtime.ready(ctx) != nil {
			writePrivateStatus(writer, http.StatusServiceUnavailable, "unavailable")
			return
		}
		writePrivateStatus(writer, http.StatusOK, "ready")
	})
	mux.HandleFunc("/metrics", func(writer http.ResponseWriter, request *http.Request) {
		writePrivateStatus(writer, http.StatusServiceUnavailable, "closed")
	})
	return mux
}

func writePrivateStatus(writer http.ResponseWriter, status int, value string) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, `{"status":"`+value+`"}`+"\n")
}

type postgresQueueFactory struct {
	pool     *pgxpool.Pool
	rollover discoveryqueue.CheckpointLineageRolloverVerifier
}

func (factory *postgresQueueFactory) BuildProductionQueue(
	verifier discoveryqueue.CleanupProofVerifier,
) (discoveryqueue.Queue, error) {
	if factory == nil || factory.pool == nil || factory.rollover == nil ||
		verifier == nil {
		return nil, errProductionUnavailable
	}
	queue, err := queuepostgres.New(factory.pool, verifier, factory.rollover)
	if err != nil {
		return nil, errProductionUnavailable
	}
	return queue, nil
}

type closedRolloverVerifier struct{}

func (closedRolloverVerifier) VerifyCheckpointLineageRollover(
	ctx context.Context,
	_ discoveryqueue.CheckpointLineageRolloverRequest,
) error {
	if ctx == nil {
		return discoveryqueue.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return discoveryqueue.ErrIneligible
}

type hmacProofAuthority struct {
	mu        sync.RWMutex
	key       []byte
	destroyed bool
}

func newHMACProofAuthority(key [sha256.Size]byte) (*hmacProofAuthority, error) {
	if allZero(key[:]) {
		return nil, errBootstrapUnavailable
	}
	return &hmacProofAuthority{key: bytes.Clone(key[:])}, nil
}

func (authority *hmacProofAuthority) SignCleanupProof(
	ctx context.Context,
	digest []byte,
) ([]byte, error) {
	if authority == nil || ctx == nil || len(digest) != sha256.Size {
		return nil, errBootstrapUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	authority.mu.RLock()
	defer authority.mu.RUnlock()
	if authority.destroyed || len(authority.key) != sha256.Size {
		return nil, errBootstrapUnavailable
	}
	mac := hmac.New(sha256.New, authority.key)
	_, _ = mac.Write(digest)
	return mac.Sum(nil), nil
}

func (authority *hmacProofAuthority) VerifyCleanupProof(
	ctx context.Context,
	digest, signature []byte,
) error {
	if authority == nil || ctx == nil || len(digest) != sha256.Size ||
		len(signature) != sha256.Size {
		return errBootstrapUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	authority.mu.RLock()
	defer authority.mu.RUnlock()
	if authority.destroyed || len(authority.key) != sha256.Size {
		return errBootstrapUnavailable
	}
	mac := hmac.New(sha256.New, authority.key)
	_, _ = mac.Write(digest)
	if subtle.ConstantTimeCompare(mac.Sum(nil), signature) != 1 {
		return errBootstrapUnavailable
	}
	return nil
}

func (authority *hmacProofAuthority) Destroy() {
	if authority == nil {
		return
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.destroyed {
		return
	}
	clear(authority.key)
	authority.key = nil
	authority.destroyed = true
}

type sourceProfileManifestEnvelope struct {
	SchemaVersion   string               `json:"schema_version"`
	SigningKeyID    string               `json:"signing_key_id"`
	Payload         sourceProfilePayload `json:"payload"`
	PayloadSHA256   string               `json:"payload_sha256"`
	SignatureSHA256 string               `json:"signature_sha256"`
}

type sourceProfilePayload struct {
	SchemaVersion string                  `json:"schema_version"`
	Providers     []sourceProfileProvider `json:"providers"`
}

type sourceProfileProvider struct {
	SourceKind                      string `json:"source_kind"`
	ProviderKind                    string `json:"provider_kind"`
	ProfileCode                     string `json:"profile_code"`
	CanonicalDescriptorDigest       string `json:"canonical_descriptor_digest"`
	RuntimeRecoveryCapabilityDigest string `json:"runtime_recovery_capability_digest"`
	IntegrationID                   string `json:"integration_id"`
	CredentialReferenceID           string `json:"credential_reference_id"`
	TrustReferenceID                string `json:"trust_reference_id"`
	NetworkPolicyReferenceID        string `json:"network_policy_reference_id"`
}

func loadSourceProfileManifest(
	path, signingKeyID string,
	signingKey [sha256.Size]byte,
) (*discoveryworker.ProviderRegistry, assetcatalog.SourceProfileRegistry, error) {
	var document sourceProfileManifestEnvelope
	if !validKeyID(signingKeyID) || allZero(signingKey[:]) ||
		loadSecureFile(path, false, func(contents []byte) error {
			return securemanifest.DecodeStrict(contents, &document)
		}) != nil {
		return nil, nil, errBootstrapUnavailable
	}
	if document.SchemaVersion != sourceProfileManifestSchemaVersion ||
		document.SigningKeyID != signingKeyID ||
		document.Payload.SchemaVersion != sourceProfilePayloadSchemaVersion ||
		len(document.Payload.Providers) != 1 ||
		!validLowerDigest(document.PayloadSHA256) ||
		!validLowerDigest(document.SignatureSHA256) {
		return nil, nil, errBootstrapUnavailable
	}
	canonical, err := json.Marshal(document.Payload)
	if err != nil {
		return nil, nil, errBootstrapUnavailable
	}
	payloadDigest := sha256.Sum256(canonical)
	defer clear(canonical)
	decodedDigest, err := hex.DecodeString(document.PayloadSHA256)
	if err != nil || subtle.ConstantTimeCompare(payloadDigest[:], decodedDigest) != 1 {
		clear(decodedDigest)
		return nil, nil, errBootstrapUnavailable
	}
	clear(decodedDigest)
	signature, err := hex.DecodeString(document.SignatureSHA256)
	if err != nil || len(signature) != sha256.Size {
		clear(signature)
		return nil, nil, errBootstrapUnavailable
	}
	mac := hmac.New(sha256.New, signingKey[:])
	_, _ = mac.Write([]byte(sourceProfileSignatureDomain))
	_, _ = mac.Write(payloadDigest[:])
	authenticated := subtle.ConstantTimeCompare(mac.Sum(nil), signature) == 1
	clear(signature)
	if !authenticated {
		return nil, nil, errBootstrapUnavailable
	}

	row := document.Payload.Providers[0]
	declaration := discoveryworker.ProviderDeclaration{
		SourceKind:                      assetcatalog.SourceKind(row.SourceKind),
		ProviderKind:                    row.ProviderKind,
		ProfileCode:                     assetcatalog.ProfileCode(row.ProfileCode),
		CanonicalDescriptorDigest:       row.CanonicalDescriptorDigest,
		RuntimeRecoveryCapabilityDigest: row.RuntimeRecoveryCapabilityDigest,
	}
	if declaration != discoveryworker.ExternalCMDBDeclaration() {
		return nil, nil, errBootstrapUnavailable
	}
	registry, err := discoveryworker.NewRegistry(declaration)
	if err != nil {
		return nil, nil, errBootstrapUnavailable
	}
	neutral := sourceprofile.ExternalCMDBV1()
	registration, err := neutral.Registration(sourceprofile.ExternalCMDBProfileReferences{
		IntegrationID: row.IntegrationID,
		CredentialReferenceID: assetcatalog.CredentialReferenceID(
			row.CredentialReferenceID,
		),
		TrustReferenceID: assetcatalog.TrustReferenceID(row.TrustReferenceID),
		NetworkPolicyReferenceID: assetcatalog.NetworkPolicyReferenceID(
			row.NetworkPolicyReferenceID,
		),
	})
	if err != nil {
		return nil, nil, errBootstrapUnavailable
	}
	profiles, err := assetcatalog.NewSourceProfileRegistry(registration)
	if err != nil {
		return nil, nil, errBootstrapUnavailable
	}
	return registry, profiles, nil
}

type hmacKeyDocument struct {
	SchemaVersion string `json:"schema_version"`
	KeyID         string `json:"key_id"`
	KeyHex        string `json:"key_hex"`
}

func loadHMACKey(
	path, schemaVersion string,
) (string, [sha256.Size]byte, error) {
	var document hmacKeyDocument
	var key [sha256.Size]byte
	if loadSecureFile(path, true, func(contents []byte) error {
		return securemanifest.DecodeStrict(contents, &document)
	}) != nil ||
		document.SchemaVersion != schemaVersion || !validKeyID(document.KeyID) {
		return "", key, errBootstrapUnavailable
	}
	decoded, err := hex.DecodeString(document.KeyHex)
	document.KeyHex = ""
	if err != nil || len(decoded) != sha256.Size || allZero(decoded) {
		clear(decoded)
		return "", key, errBootstrapUnavailable
	}
	copy(key[:], decoded)
	clear(decoded)
	return document.KeyID, key, nil
}

type checkpointKeyringDocument struct {
	SchemaVersion string                  `json:"schema_version"`
	ActiveKeyID   string                  `json:"active_key_id"`
	Keys          []checkpointKeyDocument `json:"keys"`
}

type checkpointKeyDocument struct {
	KeyID  string `json:"key_id"`
	KeyHex string `json:"key_hex"`
}

func loadCheckpointKeyring(path string) (*discoverycheckpoint.InMemoryKeyring, error) {
	var document checkpointKeyringDocument
	if loadSecureFile(path, true, func(contents []byte) error {
		return securemanifest.DecodeStrict(contents, &document)
	}) != nil ||
		document.SchemaVersion != checkpointKeyringSchemaVersion ||
		!validKeyID(document.ActiveKeyID) ||
		len(document.Keys) == 0 || len(document.Keys) > maximumProductionKeys {
		return nil, errBootstrapUnavailable
	}
	keys := make(map[string][sha256.Size]byte, len(document.Keys))
	for index := range document.Keys {
		entry := &document.Keys[index]
		decoded, err := hex.DecodeString(entry.KeyHex)
		entry.KeyHex = ""
		if err != nil || !validKeyID(entry.KeyID) ||
			len(decoded) != sha256.Size || allZero(decoded) {
			clear(decoded)
			clearCheckpointMap(keys)
			return nil, errBootstrapUnavailable
		}
		if _, duplicate := keys[entry.KeyID]; duplicate {
			clear(decoded)
			clearCheckpointMap(keys)
			return nil, errBootstrapUnavailable
		}
		var key [sha256.Size]byte
		copy(key[:], decoded)
		clear(decoded)
		keys[entry.KeyID] = key
	}
	if _, active := keys[document.ActiveKeyID]; !active {
		clearCheckpointMap(keys)
		return nil, errBootstrapUnavailable
	}
	keyring, err := discoverycheckpoint.NewInMemoryKeyring(
		document.ActiveKeyID,
		keys,
	)
	clearCheckpointMap(keys)
	if err != nil {
		return nil, errBootstrapUnavailable
	}
	return keyring, nil
}

func clearCheckpointMap(keys map[string][sha256.Size]byte) {
	for keyID := range keys {
		keys[keyID] = [sha256.Size]byte{}
		delete(keys, keyID)
	}
}

func loadWorkloadTLS(
	certificatePath, privateKeyPath, rootCAPath string,
) (tls.Certificate, *x509.CertPool, error) {
	var certificatePEM, privateKeyPEM, rootsPEM []byte
	if loadSecureFile(certificatePath, false, func(contents []byte) error {
		certificatePEM = bytes.Clone(contents)
		return nil
	}) != nil ||
		loadSecureFile(privateKeyPath, true, func(contents []byte) error {
			privateKeyPEM = bytes.Clone(contents)
			return nil
		}) != nil ||
		loadSecureFile(rootCAPath, false, func(contents []byte) error {
			rootsPEM = bytes.Clone(contents)
			return nil
		}) != nil {
		clear(certificatePEM)
		clear(privateKeyPEM)
		clear(rootsPEM)
		return tls.Certificate{}, nil, errBootstrapUnavailable
	}
	defer clear(certificatePEM)
	defer clear(privateKeyPEM)
	defer clear(rootsPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		clearTLSCertificate(&certificate)
		return tls.Certificate{}, nil, errBootstrapUnavailable
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		clearTLSCertificate(&certificate)
		return tls.Certificate{}, nil, errBootstrapUnavailable
	}
	certificate.Leaf = leaf
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootsPEM) || len(roots.Subjects()) == 0 {
		clearTLSCertificate(&certificate)
		return tls.Certificate{}, nil, errBootstrapUnavailable
	}
	return certificate, roots, nil
}

func clearTLSCertificate(certificate *tls.Certificate) {
	if certificate == nil {
		return
	}
	for index := range certificate.Certificate {
		clear(certificate.Certificate[index])
	}
	certificate.Certificate = nil
	certificate.PrivateKey = nil
	certificate.Leaf = nil
	certificate.OCSPStaple = nil
	certificate.SignedCertificateTimestamps = nil
}

func loadDatabaseConfig(path string) (*pgxpool.Config, error) {
	var config *pgxpool.Config
	if loadSecureFile(path, true, func(contents []byte) error {
		trimmed := bytes.TrimSpace(contents)
		if len(trimmed) == 0 || bytes.IndexByte(trimmed, 0) >= 0 {
			return errBootstrapUnavailable
		}
		parsed, err := pgxpool.ParseConfig(string(trimmed))
		if err != nil {
			return errBootstrapUnavailable
		}
		config = parsed
		return nil
	}) != nil || config == nil || config.ConnConfig == nil ||
		config.ConnConfig.TLSConfig == nil ||
		config.ConnConfig.TLSConfig.InsecureSkipVerify ||
		config.ConnConfig.Host == "" || strings.HasPrefix(config.ConnConfig.Host, "/") {
		clearDatabaseConfig(config)
		return nil, errBootstrapUnavailable
	}
	config.ConnConfig.TLSConfig.MinVersion = tls.VersionTLS13
	config.ConnConfig.TLSConfig.MaxVersion = tls.VersionTLS13
	for _, fallback := range config.ConnConfig.Fallbacks {
		if fallback == nil || fallback.TLSConfig == nil ||
			fallback.TLSConfig.InsecureSkipVerify {
			clearDatabaseConfig(config)
			return nil, errBootstrapUnavailable
		}
		fallback.TLSConfig.MinVersion = tls.VersionTLS13
		fallback.TLSConfig.MaxVersion = tls.VersionTLS13
	}
	if config.ConnConfig.ConnectTimeout <= 0 ||
		config.ConnConfig.ConnectTimeout > 5*time.Second {
		config.ConnConfig.ConnectTimeout = 5 * time.Second
	}
	config.ConnConfig.RuntimeParams["application_name"] = "aiops-discovery-worker"
	config.ConnConfig.RuntimeParams["search_path"] = "public"
	config.MaxConns = 8
	config.MinConns = 1
	config.MinIdleConns = 1
	config.MaxConnIdleTime = 5 * time.Minute
	config.HealthCheckPeriod = 15 * time.Second
	config.PingTimeout = 3 * time.Second
	return config, nil
}

func clearDatabaseConfig(config *pgxpool.Config) {
	if config == nil || config.ConnConfig == nil {
		return
	}
	config.ConnConfig.Password = ""
	if config.ConnConfig.TLSConfig != nil {
		config.ConnConfig.TLSConfig.Certificates = nil
		config.ConnConfig.TLSConfig.RootCAs = nil
		config.ConnConfig.TLSConfig.ClientCAs = nil
	}
	for _, fallback := range config.ConnConfig.Fallbacks {
		if fallback != nil && fallback.TLSConfig != nil {
			fallback.TLSConfig.Certificates = nil
			fallback.TLSConfig.RootCAs = nil
			fallback.TLSConfig.ClientCAs = nil
		}
	}
}

func loadSecureFile(
	path string,
	ownerOnly bool,
	consume func([]byte) error,
) error {
	if !validConfigPath(path) || consume == nil {
		return errBootstrapUnavailable
	}
	contents, err := readStableProductionFile(path, ownerOnly)
	if err != nil {
		clear(contents)
		return errBootstrapUnavailable
	}
	defer clear(contents)
	if len(contents) == 0 || consume(contents) != nil {
		return errBootstrapUnavailable
	}
	return nil
}

func readStableProductionFile(path string, ownerOnly bool) ([]byte, error) {
	const maximumFileSize = 1 << 20
	fd, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, errBootstrapUnavailable
	}
	file := os.NewFile(uintptr(fd), "discovery-worker-bootstrap")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errBootstrapUnavailable
	}
	before, err := file.Stat()
	if err != nil || !validProductionFileInfo(before, ownerOnly, maximumFileSize) ||
		productionFileHasAccessExpandingMetadata(file) {
		_ = file.Close()
		return nil, errBootstrapUnavailable
	}
	readPass := func() ([]byte, error) {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return nil, errBootstrapUnavailable
		}
		contents, err := io.ReadAll(io.LimitReader(file, maximumFileSize+1))
		if err != nil || len(contents) > maximumFileSize {
			clear(contents)
			return nil, errBootstrapUnavailable
		}
		return contents, nil
	}
	first, err := readPass()
	if err != nil {
		_ = file.Close()
		return nil, errBootstrapUnavailable
	}
	second, secondErr := readPass()
	after, statErr := file.Stat()
	metadataRejected := statErr != nil ||
		!validProductionFileInfo(after, ownerOnly, maximumFileSize) ||
		productionFileHasAccessExpandingMetadata(file)
	closeErr := file.Close()
	defer clear(second)
	if secondErr != nil || metadataRejected || closeErr != nil ||
		!os.SameFile(before, after) || before.Mode() != after.Mode() ||
		before.Size() != after.Size() || after.Size() != int64(len(first)) ||
		!before.ModTime().Equal(after.ModTime()) ||
		!bytes.Equal(first, second) {
		clear(first)
		return nil, errBootstrapUnavailable
	}
	return first, nil
}

func validProductionFileInfo(
	info os.FileInfo,
	ownerOnly bool,
	maximumFileSize int64,
) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() < 0 ||
		info.Size() > maximumFileSize || info.Mode().Perm()&0o022 != 0 ||
		(ownerOnly && info.Mode().Perm()&0o077 != 0) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}

func productionFileHasAccessExpandingMetadata(file *os.File) bool {
	if file == nil || runtime.GOOS == "darwin" && productionDarwinFileHasACL(file) {
		return true
	}
	size, err := unix.Flistxattr(int(file.Fd()), nil)
	if err != nil || size > 1<<20 {
		return true
	}
	if size == 0 {
		return false
	}
	names := make([]byte, size)
	read, err := unix.Flistxattr(int(file.Fd()), names)
	if err != nil || read != size {
		return true
	}
	for len(names) > 0 {
		end := bytes.IndexByte(names, 0)
		if end <= 0 || !allowedProductionExtendedAttribute(
			runtime.GOOS,
			string(names[:end]),
		) {
			return true
		}
		names = names[end+1:]
	}
	return false
}

func allowedProductionExtendedAttribute(goos, name string) bool {
	switch goos {
	case "darwin":
		return name == "com.apple.provenance"
	case "linux":
		return name == "security.selinux" || name == "security.ima" ||
			name == "security.evm"
	default:
		return false
	}
}

func productionDarwinFileHasACL(file *os.File) bool {
	const (
		fgetattrlistSyscall  = 228
		attrBitMapCount      = 5
		extendedSecurityAttr = 0x00400000
		noACLEntryCount      = uint32(0xffffffff)
	)
	type attrList struct {
		bitmapCount uint16
		reserved    uint16
		commonAttr  uint32
		volumeAttr  uint32
		directory   uint32
		fileAttr    uint32
		forkAttr    uint32
	}
	attributes := attrList{
		bitmapCount: attrBitMapCount,
		commonAttr:  extendedSecurityAttr,
	}
	buffer := make([]byte, 4096)
	_, _, errno := syscall.Syscall6(
		fgetattrlistSyscall,
		file.Fd(),
		uintptr(unsafe.Pointer(&attributes)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		0,
		0,
	)
	if errno != 0 {
		return true
	}
	total := int(binary.LittleEndian.Uint32(buffer[:4]))
	if total < 12 || total > len(buffer) {
		return true
	}
	referenceOffset := int(int32(binary.LittleEndian.Uint32(buffer[4:8])))
	referenceLength := int(binary.LittleEndian.Uint32(buffer[8:12]))
	dataStart := 4 + referenceOffset
	if referenceLength == 0 {
		return false
	}
	if dataStart < 12 || referenceLength < 44 ||
		dataStart > total-referenceLength {
		return true
	}
	entryCount := binary.LittleEndian.Uint32(
		buffer[dataStart+36 : dataStart+40],
	)
	return entryCount != noACLEntryCount
}

func validKeyID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range []byte(value) {
		switch {
		case character >= 'A' && character <= 'Z':
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		case index > 0 && strings.ContainsRune("_.:/@+-", rune(character)):
		default:
			return false
		}
	}
	return true
}

func validLowerDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	valid := err == nil && len(decoded) == sha256.Size &&
		strings.ToLower(value) == value
	clear(decoded)
	return valid
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func nilProductionDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var (
	_ discoveryworker.ProductionQueueFactory          = (*postgresQueueFactory)(nil)
	_ discoveryworker.ProductionCleanupProofAuthority = (*hmacProofAuthority)(nil)
	_ discoveryruntime.ExternalCMDBMaterialResolver   = closedExternalCMDBMaterialResolver{}
	_ discoverylimit.Limiter                          = (*limitpostgres.Limiter)(nil)
)
