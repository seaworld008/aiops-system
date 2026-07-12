package workerbootstrap

import (
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/seaworld008/aiops-system/internal/securemanifest"
)

const (
	readAssemblySnapshotSchemaVersion = "read-assembly-snapshot.v1"
	readTargetManifestSchemaVersion   = "read-target-manifest.v1"
	targetRootsDirectory              = "target-roots"
	certificateFileSuffix             = ".pem"
	maximumTargetRootBundles          = 256
	maximumBootstrapManifestBytes     = 64 << 10
	maximumManifestBytes              = 1 << 20
	maximumCertificateBytes           = 256 << 10
	maximumEnvelopeBytes              = 8 << 20
	maximumEnvelopeSourceBytes        = 5 << 20
	maximumPathBytes                  = 4096
)

type publicDocument struct {
	SchemaVersion string `json:"schema_version"`
	// ExpectedSnapshot is an untrusted deployment declaration until the next
	// assembly gate builds a Snapshot from this exact envelope and compares it.
	ExpectedSnapshot publicSnapshotDocument `json:"expected_snapshot"`
	Postgres         publicPostgresDocument `json:"postgres"`
	Temporal         publicTemporalDocument `json:"temporal"`
	Artifacts        publicArtifactDocument `json:"artifacts"`
}

type publicSnapshotDocument struct {
	SchemaVersion           string `json:"schema_version"`
	PlanManifestDigest      string `json:"plan_manifest_digest"`
	ConnectorRegistryDigest string `json:"connector_registry_digest"`
	TargetRegistryDigest    string `json:"target_registry_digest"`
	EgressRegistryDigest    string `json:"egress_registry_digest"`
	ExecutorProfileDigest   string `json:"executor_profile_digest"`
	BundleDigest            string `json:"bundle_digest"`
}

type publicPostgresDocument struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Database   string `json:"database"`
	User       string `json:"user"`
	ServerName string `json:"server_name"`
}

type publicTemporalDocument struct {
	HostPort   string `json:"host_port"`
	Namespace  string `json:"namespace"`
	ServerName string `json:"server_name"`
}

type publicArtifactDocument struct {
	ConnectorManifestSHA256          string   `json:"connector_manifest_sha256"`
	PlanManifestSHA256               string   `json:"plan_manifest_sha256"`
	TargetManifestSHA256             string   `json:"target_manifest_sha256"`
	EgressManifestSHA256             string   `json:"egress_manifest_sha256"`
	PostgresRootCASHA256             string   `json:"postgres_root_ca_sha256"`
	PostgresClientCertificateSHA256  string   `json:"postgres_client_certificate_sha256"`
	TemporalRootCASHA256             string   `json:"temporal_root_ca_sha256"`
	TemporalStarterCertificateSHA256 string   `json:"temporal_starter_certificate_sha256"`
	TemporalControlCertificateSHA256 string   `json:"temporal_control_certificate_sha256"`
	TargetRootBundleSHA256           []string `json:"target_root_bundle_sha256"`
}

func decodePublicDocument(encoded []byte) (publicDocument, error) {
	var document publicDocument
	if len(encoded) == 0 || len(encoded) > maximumBootstrapManifestBytes ||
		securemanifest.DecodeStrict(encoded, &document) != nil || !document.valid() {
		return publicDocument{}, ErrBootstrapRejected
	}
	return document, nil
}

func (document publicDocument) valid() bool {
	return document.SchemaVersion == PublicSourceSchemaVersion && document.ExpectedSnapshot.valid() &&
		document.Postgres.valid() && document.Temporal.valid() && document.Artifacts.valid()
}

func (document publicSnapshotDocument) valid() bool {
	return document.SchemaVersion == readAssemblySnapshotSchemaVersion &&
		validSHA256(document.PlanManifestDigest) && validSHA256(document.ConnectorRegistryDigest) &&
		validSHA256(document.TargetRegistryDigest) && validSHA256(document.EgressRegistryDigest) &&
		validSHA256(document.ExecutorProfileDigest) && validSHA256(document.BundleDigest)
}

func (document publicPostgresDocument) valid() bool {
	return validDNSName(document.Host) && document.ServerName == document.Host &&
		document.Port > 0 && document.Port <= 65535 && validDatabaseIdentifier(document.Database) &&
		validDatabaseIdentifier(document.User)
}

func (document publicTemporalDocument) valid() bool {
	host, port, err := net.SplitHostPort(document.HostPort)
	parsedPort, parseErr := strconv.Atoi(port)
	return err == nil && parseErr == nil && validDNSName(host) && document.ServerName == host &&
		parsedPort > 0 && parsedPort <= 65535 && strconv.Itoa(parsedPort) == port && validNamespace(document.Namespace)
}

func (document publicArtifactDocument) valid() bool {
	digests := []string{
		document.ConnectorManifestSHA256, document.PlanManifestSHA256,
		document.TargetManifestSHA256, document.EgressManifestSHA256,
		document.PostgresRootCASHA256, document.PostgresClientCertificateSHA256,
		document.TemporalRootCASHA256, document.TemporalStarterCertificateSHA256,
		document.TemporalControlCertificateSHA256,
	}
	for _, digest := range digests {
		if !validSHA256(digest) {
			return false
		}
	}
	if len(document.TargetRootBundleSHA256) == 0 ||
		len(document.TargetRootBundleSHA256) > maximumTargetRootBundles ||
		!sort.StringsAreSorted(document.TargetRootBundleSHA256) {
		return false
	}
	previous := ""
	for _, digest := range document.TargetRootBundleSHA256 {
		if !validSHA256(digest) || digest == previous {
			return false
		}
		previous = digest
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) ||
		strings.TrimSpace(value) != value || strings.ContainsAny(value, "/:*[]%") ||
		net.ParseIP(value) != nil || !strings.Contains(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validDatabaseIdentifier(value string) bool {
	if value == "" || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func validNamespace(value string) bool {
	if value == "" || len(value) > 63 || value[0] < 'a' || value[0] > 'z' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

type targetManifestDocument struct {
	SchemaVersion string                     `json:"schema_version"`
	Targets       []targetManifestDefinition `json:"targets"`
}

type targetManifestDefinition struct {
	Scope             targetManifestScope    `json:"scope"`
	TargetRef         string                 `json:"target_ref"`
	Kind              string                 `json:"kind"`
	Endpoint          targetManifestEndpoint `json:"endpoint"`
	CredentialRoleRef string                 `json:"credential_role_ref"`
	NetworkPolicyRef  string                 `json:"network_policy_ref"`
}

type targetManifestScope struct {
	TenantID      string `json:"tenant_id"`
	WorkspaceID   string `json:"workspace_id"`
	EnvironmentID string `json:"environment_id"`
}

type targetManifestEndpoint struct {
	Origin       string `json:"origin"`
	ServerName   string `json:"server_name"`
	CABundleFile string `json:"ca_bundle_file"`
}

func validateTargetRootClosure(encoded []byte, rootPath string, expected []string) error {
	if len(encoded) == 0 || len(encoded) > maximumManifestBytes || rootPath == "" ||
		!filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath ||
		len(expected) == 0 || !sort.StringsAreSorted(expected) {
		return ErrBootstrapRejected
	}
	var document targetManifestDocument
	if securemanifest.DecodeStrict(encoded, &document) != nil ||
		document.SchemaVersion != readTargetManifestSchemaVersion || len(document.Targets) == 0 {
		return ErrBootstrapRejected
	}
	wantDirectory := filepath.Join(rootPath, targetRootsDirectory)
	seen := make(map[string]struct{}, len(expected))
	for _, target := range document.Targets {
		path := target.Endpoint.CABundleFile
		if path == "" || len(path) > maximumPathBytes || !filepath.IsAbs(path) ||
			filepath.Clean(path) != path || strings.TrimSpace(path) != path || filepath.Dir(path) != wantDirectory {
			return ErrBootstrapRejected
		}
		base := filepath.Base(path)
		if len(base) != 64+len(certificateFileSuffix) || !strings.HasSuffix(base, certificateFileSuffix) {
			return ErrBootstrapRejected
		}
		digest := strings.TrimSuffix(base, certificateFileSuffix)
		if !validSHA256(digest) {
			return ErrBootstrapRejected
		}
		seen[digest] = struct{}{}
	}
	if len(seen) != len(expected) {
		return ErrBootstrapRejected
	}
	for _, digest := range expected {
		if _, ok := seen[digest]; !ok {
			return ErrBootstrapRejected
		}
	}
	return nil
}
