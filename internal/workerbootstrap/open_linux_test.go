//go:build linux

package workerbootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/investigationplan"
	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/readexecutor"
	"github.com/seaworld008/aiops-system/internal/readruntime"
	"github.com/seaworld008/aiops-system/internal/readtarget"
	"github.com/seaworld008/aiops-system/internal/securemanifest"
	"golang.org/x/sys/unix"
)

func TestOpenPublicSourceBuildsReadOnlySealedMemfd(t *testing.T) {
	fixture := newLinuxBootstrapFixture(t)
	capability, err := fixture.open()
	if err != nil {
		t.Fatalf("openPublicSourceFromAnchor() error = %v", err)
	}
	t.Cleanup(func() { _ = capability.Close() })
	summary := capability.Summary()
	if summary.SchemaVersion != PublicSourceSchemaVersion || !validSHA256(summary.ManifestSHA256) ||
		!validSHA256(summary.EnvelopeSHA256) || summary.EnvelopeSize <= 0 || summary.EnvelopeSize > maximumEnvelopeBytes {
		t.Fatalf("Summary() = %#v", summary)
	}

	capability.state.mu.Lock()
	file := capability.state.file
	if file == nil {
		capability.state.mu.Unlock()
		t.Fatal("capability has no descriptor")
	}
	fd := int(file.Fd())
	flags, flagsErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	descriptorFlags, descriptorErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	seals, sealsErr := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	var stat unix.Stat_t
	statErr := unix.Fstat(fd, &stat)
	contents := make([]byte, summary.EnvelopeSize)
	read, readErr := unix.Pread(fd, contents, 0)
	capability.state.mu.Unlock()
	if flagsErr != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || descriptorErr != nil ||
		descriptorFlags&unix.FD_CLOEXEC == 0 || sealsErr != nil || seals != requiredMemfdSeals || statErr != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o400 || stat.Nlink != 0 ||
		stat.Uid != uint32(os.Geteuid()) || int64(read) != summary.EnvelopeSize || readErr != nil {
		t.Fatalf("memfd boundary flags=%#x descriptor=%#x seals=%#x stat=%#v read=%d errors=%v/%v/%v/%v/%v",
			flags, descriptorFlags, seals, stat, read, flagsErr, descriptorErr, sealsErr, statErr, readErr)
	}
	if !bytes.HasPrefix(contents, []byte(envelopeMagicText)) || bytes.Contains(contents, []byte("PRIVATE KEY")) ||
		bytes.Contains(contents, fixture.privateKeyCanary) {
		t.Fatal("envelope framing or private-material exclusion failed")
	}
	validateEnvelopeFrame(t, contents, summary, fixture.targetRootDigest)
	secondCapability, err := fixture.open()
	if err != nil {
		t.Fatalf("second openPublicSourceFromAnchor() error = %v", err)
	}
	secondContents := readCapabilityContents(t, secondCapability)
	if closeErr := secondCapability.Close(); closeErr != nil {
		t.Fatalf("second Close() error = %v", closeErr)
	}
	if !bytes.Equal(contents, secondContents) {
		t.Fatal("same source produced a non-deterministic envelope")
	}
	if written, writeErr := unix.Pwrite(fd, []byte("x"), 0); written > 0 || writeErr == nil {
		t.Fatalf("Pwrite(sealed read-only memfd) = %d, %v; want rejection", written, writeErr)
	}
	if truncateErr := unix.Ftruncate(fd, summary.EnvelopeSize+1); truncateErr == nil {
		t.Fatal("Ftruncate(sealed read-only memfd) unexpectedly succeeded")
	}
}

func TestOpenPublicSourceRejectsFilesystemAndGraphSubstitution(t *testing.T) {
	tests := map[string]func(*testing.T, *linuxBootstrapFixture){
		"writable ancestor": func(t *testing.T, fixture *linuxBootstrapFixture) {
			t.Helper()
			if err := os.Chmod(filepath.Join(fixture.anchorPath, fixture.components[0]), 0o770); err != nil {
				t.Fatal(err)
			}
		},
		"final directory mode": func(t *testing.T, fixture *linuxBootstrapFixture) {
			t.Helper()
			if err := os.Chmod(fixture.rootPath, 0o750); err != nil {
				t.Fatal(err)
			}
		},
		"target directory mode": func(t *testing.T, fixture *linuxBootstrapFixture) {
			t.Helper()
			if err := os.Chmod(filepath.Join(fixture.rootPath, targetRootsDirectory), 0o750); err != nil {
				t.Fatal(err)
			}
		},
		"artifact mode": func(t *testing.T, fixture *linuxBootstrapFixture) {
			t.Helper()
			if err := os.Chmod(filepath.Join(fixture.rootPath, connectorManifestFilename), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"artifact symlink": func(t *testing.T, fixture *linuxBootstrapFixture) {
			t.Helper()
			path := filepath.Join(fixture.rootPath, connectorManifestFilename)
			if err := os.Rename(path, path+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".real", path); err != nil {
				t.Fatal(err)
			}
		},
		"artifact hardlink": func(t *testing.T, fixture *linuxBootstrapFixture) {
			t.Helper()
			path := filepath.Join(fixture.rootPath, connectorManifestFilename)
			if err := os.Link(path, path+".link"); err != nil {
				t.Fatal(err)
			}
		},
		"artifact xattr": func(t *testing.T, fixture *linuxBootstrapFixture) {
			t.Helper()
			path := filepath.Join(fixture.rootPath, connectorManifestFilename)
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := unix.Setxattr(path, "user.aiops_canary", []byte("x"), 0); err != nil {
				t.Skipf("user xattr unavailable: %v", err)
			}
			if err := os.Chmod(path, 0o400); err != nil {
				t.Fatal(err)
			}
		},
		"digest mismatch": func(t *testing.T, fixture *linuxBootstrapFixture) {
			t.Helper()
			path := filepath.Join(fixture.rootPath, connectorManifestFilename)
			rewriteOwnerOnlyFile(t, path, []byte(`{"schema_version":"foreign"}`))
		},
		"target closure mismatch": func(t *testing.T, fixture *linuxBootstrapFixture) {
			t.Helper()
			path := filepath.Join(fixture.rootPath, targetManifestFilename)
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			contents = bytes.Replace(contents, []byte(fixture.targetRootDigest), []byte(strings.Repeat("f", 64)), 1)
			rewriteOwnerOnlyFile(t, path, contents)
			fixture.rewriteBootstrapDigest(t, "target")
		},
		"same temporal role certificate": func(t *testing.T, fixture *linuxBootstrapFixture) {
			t.Helper()
			starter, err := os.ReadFile(filepath.Join(fixture.rootPath, temporalStarterCertificateFilename))
			if err != nil {
				t.Fatal(err)
			}
			rewriteOwnerOnlyFile(t, filepath.Join(fixture.rootPath, temporalControlCertificateFilename), starter)
			fixture.rewriteBootstrapDigest(t, "temporal-control")
		},
		"private key in certificate artifact": func(t *testing.T, fixture *linuxBootstrapFixture) {
			t.Helper()
			path := filepath.Join(fixture.rootPath, postgresClientCertificateFilename)
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			contents = append(contents, fixture.privateKeyCanary...)
			rewriteOwnerOnlyFile(t, path, contents)
			fixture.rewriteBootstrapDigest(t, "postgres-client")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newLinuxBootstrapFixture(t)
			mutate(t, fixture)
			capability, err := fixture.open()
			if capability != nil {
				_ = capability.Close()
			}
			if capability != nil || !errors.Is(err, ErrBootstrapRejected) {
				t.Fatalf("openPublicSourceFromAnchor() = %#v, %v; want rejection", capability, err)
			}
			for _, canary := range []string{fixture.rootPath, string(fixture.privateKeyCanary)} {
				if strings.Contains(err.Error(), canary) {
					t.Fatalf("error leaked canary %q: %v", canary, err)
				}
			}
		})
	}
}

func TestOpenPublicSourceAcceptsLeafOnlyClientCertificateFile(t *testing.T) {
	fixture := newLinuxBootstrapFixture(t)
	path := filepath.Join(fixture.rootPath, temporalStarterCertificateFilename)
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("fixture starter leaf is not a certificate")
	}
	rewriteOwnerOnlyFile(t, path, pem.EncodeToMemory(block))
	fixture.rewriteBootstrapDigest(t, "temporal-starter")
	capability, err := fixture.open()
	if err != nil || capability == nil {
		t.Fatalf("openPublicSourceFromAnchor(leaf only) = %#v, %v", capability, err)
	}
	if err := capability.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestPublicSourceDoesNotAttestManifestOrSnapshotSemantics(t *testing.T) {
	fixture := newLinuxBootstrapFixture(t)
	path := filepath.Join(fixture.rootPath, connectorManifestFilename)
	rewriteOwnerOnlyFile(t, path, []byte(`{"schema_version":"not-a-connector-registry"}`))
	fixture.rewriteBootstrapDigest(t, "connector")
	capability, err := fixture.open()
	if err != nil || capability == nil {
		t.Fatalf("open trusted semantic-invalid source = %#v, %v", capability, err)
	}
	// FD handoff consumes this capability without widening its summary. The
	// next gate must still build and compare the real Snapshot from this exact
	// envelope before Dial or READY; source integrity is not that proof.
	if err := capability.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestStableDescriptorReadRejectsMutationBetweenPasses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stable")
	writeOwnerOnlyFile(t, path, []byte("first"))
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	contents, err := readStableDescriptor(fd, 64, func() {
		if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
			t.Fatal(chmodErr)
		}
		if writeErr := os.WriteFile(path, []byte("other"), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		if chmodErr := os.Chmod(path, 0o400); chmodErr != nil {
			t.Fatal(chmodErr)
		}
	})
	clear(contents)
	if !errors.Is(err, ErrBootstrapRejected) {
		t.Fatalf("readStableDescriptor(mutated) error = %v, want ErrBootstrapRejected", err)
	}
}

func TestEnvelopeSourceBudgetRejectsBeforeAggregateAllocation(t *testing.T) {
	if total, ok := reserveEnvelopeSourceBytes(maximumEnvelopeSourceBytes-1, 1); !ok || total != maximumEnvelopeSourceBytes {
		t.Fatalf("reserveEnvelopeSourceBytes(exact) = %d, %t", total, ok)
	}
	for _, test := range [][2]int{
		{maximumEnvelopeSourceBytes, 1}, {-1, 1}, {1, -1},
	} {
		if total, ok := reserveEnvelopeSourceBytes(test[0], test[1]); ok || total != 0 {
			t.Fatalf("reserveEnvelopeSourceBytes(%d,%d) = %d, %t; want rejection", test[0], test[1], total, ok)
		}
	}
}

type linuxBootstrapFixture struct {
	anchorPath       string
	rootPath         string
	components       []string
	targetRootDigest string
	privateKeyCanary []byte
	postgresKey      *ecdsa.PrivateKey
	starterKey       *ecdsa.PrivateKey
	controlKey       *ecdsa.PrivateKey
	document         publicDocument
}

func newLinuxBootstrapFixture(t *testing.T) *linuxBootstrapFixture {
	t.Helper()
	anchor := t.TempDir()
	components := []string{"run", "aiops", "control-worker", "v1"}
	current := anchor
	for index, component := range components {
		current = filepath.Join(current, component)
		mode := os.FileMode(0o755)
		if index == len(components)-1 {
			mode = 0o700
		}
		if err := os.Mkdir(current, mode); err != nil {
			t.Fatal(err)
		}
	}
	rootPath := current
	if err := os.Mkdir(filepath.Join(rootPath, targetRootsDirectory), 0o700); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	postgresRoot, postgresRootKey := newTestRoot(t, "postgres-root", now)
	temporalRoot, temporalRootKey := newTestRoot(t, "temporal-root", now)
	targetRoot, _ := newTestRoot(t, "target-root", now)
	postgresCertificate, postgresKey := newTestClientCertificate(t, "postgres-client", now, postgresRoot, postgresRootKey)
	temporalStarter, starterKey := newTestClientCertificate(t, "temporal-starter", now, temporalRoot, temporalRootKey)
	temporalControl, controlKey := newTestClientCertificate(t, "temporal-control", now, temporalRoot, temporalRootKey)
	targetRootPEM := certificatePEM(targetRoot.Raw)
	targetRootHash := sha256Hex(targetRootPEM)
	targetRootPath := filepath.Join(rootPath, targetRootsDirectory, targetRootHash+certificateFileSuffix)
	writeOwnerOnlyFile(t, targetRootPath, targetRootPEM)

	const (
		tenantID      = "00000000-0000-4000-8000-000000000001"
		workspaceID   = "00000000-0000-4000-8000-000000000002"
		environmentID = "00000000-0000-4000-8000-000000000003"
		serviceID     = "00000000-0000-4000-8000-000000000004"
		integrationID = "00000000-0000-4000-8000-000000000005"
	)
	targetScope := readtarget.Scope{
		TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: environmentID,
	}
	egressDefinition := readexecutor.EgressPolicyDefinition{
		Scope: targetScope, Hostname: "metrics.aiops.internal", Port: 8443,
		AllowedPrefixes: []string{"10.42.9.0/24"},
	}
	egressRef, err := readexecutor.BuildEgressPolicyRef("metrics-egress", egressDefinition)
	if err != nil {
		t.Fatal(err)
	}
	egressDefinition.PolicyRef = egressRef
	targetDefinition := readtarget.Definition{
		Scope: targetScope, Kind: readconnector.KindPrometheus,
		Endpoint: readtarget.Endpoint{
			Origin: "https://metrics.aiops.internal:8443", ServerName: "metrics.aiops.internal",
			CABundleFile: targetRootPath,
		},
		CredentialRoleRef: "metrics-reader-v1-" + strings.Repeat("a", 64), NetworkPolicyRef: egressRef,
	}
	targetRef, err := readtarget.BuildTargetRef("metrics", targetDefinition)
	if err != nil {
		t.Fatal(err)
	}
	targetDefinition.TargetRef = targetRef
	connectorDefinition := readconnector.Definition{
		Scope: readconnector.Scope{
			TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: environmentID, ServiceID: serviceID,
		},
		TargetRef: targetRef,
		PrometheusRangeQuery: &readconnector.PrometheusRangeQueryV1{
			Expression: "up", StepSeconds: 30, MaxLookbackMinutes: 60, MaxItems: 100, MaxSamples: 121,
		},
	}
	connectorID, err := readconnector.BuildConnectorID("metrics", connectorDefinition)
	if err != nil {
		t.Fatal(err)
	}
	connectorDefinition.ConnectorID = connectorID
	connectorRegistry, err := readconnector.New([]readconnector.Definition{connectorDefinition})
	if err != nil {
		t.Fatal(err)
	}
	planDefinition := investigationplan.Definition{
		RegistryDigest: connectorRegistry.Digest(),
		Profiles: []investigationplan.ProfileDefinition{{
			Scope: investigationplan.Scope{
				TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: environmentID, ServiceID: serviceID,
			},
			Match: investigationplan.MatchDefinition{
				IntegrationID: integrationID, Provider: "alertmanager",
				Labels: []investigationplan.LabelMatch{{Key: "service", Value: "payments"}},
			},
			Tasks: []investigationplan.TaskDefinition{{
				Key: "metrics", ConnectorID: connectorID, Operation: readconnector.OperationPrometheusRangeQuery,
				Input: json.RawMessage(`{"lookback_minutes":15}`),
			}},
		}},
	}
	mustMarshal := func(value any) []byte {
		encoded, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return encoded
	}
	connectorManifest := mustMarshal(struct {
		SchemaVersion string                     `json:"schema_version"`
		Definitions   []readconnector.Definition `json:"definitions"`
	}{SchemaVersion: "read-connector-registry.v1", Definitions: []readconnector.Definition{connectorDefinition}})
	planManifest := mustMarshal(struct {
		SchemaVersion  string                                `json:"schema_version"`
		RegistryDigest string                                `json:"registry_digest"`
		Profiles       []investigationplan.ProfileDefinition `json:"profiles"`
	}{
		SchemaVersion: investigationplan.ManifestSchemaVersion, RegistryDigest: planDefinition.RegistryDigest,
		Profiles: planDefinition.Profiles,
	})
	targetManifest := mustMarshal(struct {
		SchemaVersion string                  `json:"schema_version"`
		Targets       []readtarget.Definition `json:"targets"`
	}{SchemaVersion: readtarget.ManifestSchemaVersion, Targets: []readtarget.Definition{targetDefinition}})
	egressManifest := mustMarshal(struct {
		SchemaVersion string                                `json:"schema_version"`
		Policies      []readexecutor.EgressPolicyDefinition `json:"policies"`
	}{
		SchemaVersion: readexecutor.EgressRegistrySchemaVersion,
		Policies:      []readexecutor.EgressPolicyDefinition{egressDefinition},
	})
	artifacts := map[string][]byte{
		connectorManifestFilename:          connectorManifest,
		planManifestFilename:               planManifest,
		targetManifestFilename:             targetManifest,
		egressManifestFilename:             egressManifest,
		postgresRootCAFilename:             certificatePEM(postgresRoot.Raw),
		postgresClientCertificateFilename:  certificateChainPEM(postgresCertificate.Raw, postgresRoot.Raw),
		temporalRootCAFilename:             certificatePEM(temporalRoot.Raw),
		temporalStarterCertificateFilename: certificateChainPEM(temporalStarter.Raw, temporalRoot.Raw),
		temporalControlCertificateFilename: certificateChainPEM(temporalControl.Raw, temporalRoot.Raw),
	}
	for name, contents := range artifacts {
		writeOwnerOnlyFile(t, filepath.Join(rootPath, name), contents)
	}

	loadedConnectors, err := readconnector.LoadFile(filepath.Join(rootPath, connectorManifestFilename))
	if err != nil {
		t.Fatal(err)
	}
	authority := investigationplan.NewScopeAuthority()
	planner, err := investigationplan.LoadFile(
		context.Background(), authority, filepath.Join(rootPath, planManifestFilename), loadedConnectors,
	)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := readtarget.LoadFile(filepath.Join(rootPath, targetManifestFilename))
	if err != nil {
		t.Fatal(err)
	}
	egress, err := readexecutor.LoadEgressRegistryFile(filepath.Join(rootPath, egressManifestFilename))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := readexecutor.NewProfile()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := readruntime.NewBundle(loadedConnectors, targets, egress, profile)
	if err != nil {
		t.Fatal(err)
	}
	runtimeSummary := bundle.Summary()

	document := publicDocument{
		SchemaVersion: PublicSourceSchemaVersion,
		ExpectedSnapshot: publicSnapshotDocument{
			SchemaVersion: readAssemblySnapshotSchemaVersion, PlanManifestDigest: planner.ManifestDigest(),
			ConnectorRegistryDigest: runtimeSummary.ConnectorRegistryDigest,
			TargetRegistryDigest:    runtimeSummary.TargetRegistryDigest,
			EgressRegistryDigest:    runtimeSummary.EgressRegistryDigest,
			ExecutorProfileDigest:   runtimeSummary.ExecutorProfileDigest,
			BundleDigest:            runtimeSummary.BundleDigest,
		},
		Postgres: publicPostgresDocument{
			Host: "postgres.aiops.internal", Port: 5432, Database: "aiops", User: "aiops_worker",
			ServerName: "postgres.aiops.internal",
		},
		Temporal: publicTemporalDocument{
			HostPort: "temporal.aiops.internal:7233", Namespace: "aiops-prod", ServerName: "temporal.aiops.internal",
		},
		Artifacts: publicArtifactDocument{
			ConnectorManifestSHA256:          sha256Hex(artifacts[connectorManifestFilename]),
			PlanManifestSHA256:               sha256Hex(artifacts[planManifestFilename]),
			TargetManifestSHA256:             sha256Hex(artifacts[targetManifestFilename]),
			EgressManifestSHA256:             sha256Hex(artifacts[egressManifestFilename]),
			PostgresRootCASHA256:             sha256Hex(artifacts[postgresRootCAFilename]),
			PostgresClientCertificateSHA256:  sha256Hex(artifacts[postgresClientCertificateFilename]),
			TemporalRootCASHA256:             sha256Hex(artifacts[temporalRootCAFilename]),
			TemporalStarterCertificateSHA256: sha256Hex(artifacts[temporalStarterCertificateFilename]),
			TemporalControlCertificateSHA256: sha256Hex(artifacts[temporalControlCertificateFilename]),
			TargetRootBundleSHA256:           []string{targetRootHash},
		},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	writeOwnerOnlyFile(t, filepath.Join(rootPath, bootstrapManifestFilename), encoded)
	return &linuxBootstrapFixture{
		anchorPath: anchor, rootPath: rootPath, components: components, targetRootDigest: targetRootHash,
		privateKeyCanary: []byte("-----BEGIN PRIVATE KEY-----\nbootstrap-private-canary\n-----END PRIVATE KEY-----\n"),
		postgresKey:      postgresKey, starterKey: starterKey, controlKey: controlKey,
		document: document,
	}
}

func (fixture *linuxBootstrapFixture) open() (*PublicSourceCapability, error) {
	anchorFD, err := unix.Open(fixture.anchorPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(anchorFD)
	return openPublicSourceFromAnchor(anchorFD, fixture.rootPath, fixture.components)
}

func (fixture *linuxBootstrapFixture) rewriteBootstrapDigest(t *testing.T, role string) {
	t.Helper()
	switch role {
	case "connector":
		contents, err := os.ReadFile(filepath.Join(fixture.rootPath, connectorManifestFilename))
		if err != nil {
			t.Fatal(err)
		}
		fixture.document.Artifacts.ConnectorManifestSHA256 = sha256Hex(contents)
	case "target":
		contents, err := os.ReadFile(filepath.Join(fixture.rootPath, targetManifestFilename))
		if err != nil {
			t.Fatal(err)
		}
		fixture.document.Artifacts.TargetManifestSHA256 = sha256Hex(contents)
	case "temporal-control":
		contents, err := os.ReadFile(filepath.Join(fixture.rootPath, temporalControlCertificateFilename))
		if err != nil {
			t.Fatal(err)
		}
		fixture.document.Artifacts.TemporalControlCertificateSHA256 = sha256Hex(contents)
	case "temporal-starter":
		contents, err := os.ReadFile(filepath.Join(fixture.rootPath, temporalStarterCertificateFilename))
		if err != nil {
			t.Fatal(err)
		}
		fixture.document.Artifacts.TemporalStarterCertificateSHA256 = sha256Hex(contents)
	case "postgres-client":
		contents, err := os.ReadFile(filepath.Join(fixture.rootPath, postgresClientCertificateFilename))
		if err != nil {
			t.Fatal(err)
		}
		fixture.document.Artifacts.PostgresClientCertificateSHA256 = sha256Hex(contents)
	default:
		t.Fatalf("unknown role %q", role)
	}
	encoded, err := json.Marshal(fixture.document)
	if err != nil {
		t.Fatal(err)
	}
	rewriteOwnerOnlyFile(t, filepath.Join(fixture.rootPath, bootstrapManifestFilename), encoded)
}

func writeOwnerOnlyFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o400); err != nil {
		t.Fatal(err)
	}
}

func rewriteOwnerOnlyFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
}

func newTestRoot(t *testing.T, commonName string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: newTestSerial(t), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func newTestClientCertificate(
	t *testing.T,
	commonName string,
	now time.Time,
	root *x509.Certificate,
	rootKey *ecdsa.PrivateKey,
) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: newTestSerial(t), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func newTestSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

func certificatePEM(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
}

func certificateChainPEM(chain ...[]byte) []byte {
	var encoded []byte
	for _, raw := range chain {
		encoded = append(encoded, certificatePEM(raw)...)
	}
	return encoded
}

func sha256Hex(contents []byte) string {
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

func readCapabilityContents(t *testing.T, capability *PublicSourceCapability) []byte {
	t.Helper()
	summary := capability.Summary()
	capability.state.mu.Lock()
	defer capability.state.mu.Unlock()
	if capability.state.file == nil || summary.EnvelopeSize <= 0 {
		t.Fatal("capability is not live")
	}
	contents := make([]byte, summary.EnvelopeSize)
	read, err := unix.Pread(int(capability.state.file.Fd()), contents, 0)
	if err != nil || int64(read) != summary.EnvelopeSize {
		t.Fatalf("Pread(capability) = %d, %v", read, err)
	}
	return contents
}

func validateEnvelopeFrame(t *testing.T, framed []byte, summary PublicSourceSummary, targetRootDigest string) {
	t.Helper()
	minimum := len(envelopeMagicText) + 8 + sha256.Size
	if len(framed) < minimum || !bytes.HasPrefix(framed, []byte(envelopeMagicText)) {
		t.Fatal("invalid envelope prefix")
	}
	payloadSize := binary.BigEndian.Uint64(framed[len(envelopeMagicText) : len(envelopeMagicText)+8])
	payloadStart := len(envelopeMagicText) + 8
	if payloadSize > uint64(maximumEnvelopeBytes) || payloadStart+int(payloadSize)+sha256.Size != len(framed) {
		t.Fatalf("invalid envelope length %d for %d bytes", payloadSize, len(framed))
	}
	payloadEnd := payloadStart + int(payloadSize)
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(envelopeDomainText))
	_, _ = hasher.Write(framed[:payloadEnd])
	wantDigest := hasher.Sum(nil)
	if !bytes.Equal(wantDigest, framed[payloadEnd:]) || hex.EncodeToString(wantDigest) != summary.EnvelopeSHA256 {
		t.Fatal("envelope digest mismatch")
	}
	var envelope publicWireEnvelope
	if securemanifest.DecodeStrict(framed[payloadStart:payloadEnd], &envelope) != nil ||
		envelope.SchemaVersion != publicEnvelopeSchemaVersion {
		t.Fatal("envelope JSON contract rejected")
	}
	want := []struct{ role, name string }{
		{"bootstrap_manifest", bootstrapManifestFilename},
		{"connector_manifest", connectorManifestFilename},
		{"plan_manifest", planManifestFilename},
		{"target_manifest", targetManifestFilename},
		{"egress_manifest", egressManifestFilename},
		{"postgres_root_ca", postgresRootCAFilename},
		{"postgres_client_certificate", postgresClientCertificateFilename},
		{"temporal_root_ca", temporalRootCAFilename},
		{"temporal_starter_certificate", temporalStarterCertificateFilename},
		{"temporal_control_certificate", temporalControlCertificateFilename},
		{"target_root_bundle", targetRootDigest + certificateFileSuffix},
	}
	if len(envelope.Artifacts) != len(want) {
		t.Fatalf("envelope has %d artifacts, want %d", len(envelope.Artifacts), len(want))
	}
	for index, artifact := range envelope.Artifacts {
		if artifact.Role != want[index].role || artifact.Name != want[index].name ||
			artifact.SHA256 != sha256Hex(artifact.Contents) {
			t.Errorf("artifact[%d] = %q/%q/%q", index, artifact.Role, artifact.Name, artifact.SHA256)
		}
	}
	if envelope.Artifacts[0].SHA256 != summary.ManifestSHA256 {
		t.Fatal("summary manifest digest does not bind the envelope bootstrap artifact")
	}
}
