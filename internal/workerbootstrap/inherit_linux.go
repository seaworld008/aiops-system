//go:build linux

package workerbootstrap

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/seaworld008/aiops-system/internal/readassembly"
	"github.com/seaworld008/aiops-system/internal/securemanifest"
	"golang.org/x/sys/unix"
)

const (
	inheritedPublicSourceFD   = 4
	inheritedPostgresSecretFD = 5
	inheritedStarterSecretFD  = 6
	inheritedControlSecretFD  = 7
)

type inheritedArtifactExpectation struct {
	role    string
	name    string
	sha256  string
	maximum int
}

// AcceptInheritedSource validates and takes ownership of the fixed FD4 source.
// It accepts no caller-selected descriptor and fails closed outside the exact
// source/frame contract.
func AcceptInheritedSource() (*InheritedSource, error) {
	return acceptInheritedSourceDescriptors(
		inheritedPublicSourceFD,
		[3]int{inheritedPostgresSecretFD, inheritedStarterSecretFD, inheritedControlSecretFD},
	)
}

func acceptInheritedSourceDescriptor(fd int) (*InheritedSource, error) {
	return acceptInheritedSourceDescriptorSet(fd, nil)
}

func acceptInheritedSourceDescriptors(fd int, secretFDs [3]int) (*InheritedSource, error) {
	return acceptInheritedSourceDescriptorSet(fd, &secretFDs)
}

func acceptInheritedSourceDescriptorSet(fd int, secretFDs *[3]int) (*InheritedSource, error) {
	if fd < 0 {
		return nil, ErrBootstrapRejected
	}
	owned := true
	defer func() {
		if owned {
			_ = unix.Close(fd)
			if secretFDs != nil {
				for _, secretFD := range secretFDs {
					_ = unix.Close(secretFD)
				}
			}
		}
	}()
	unix.CloseOnExec(fd)
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !validInheritedSourceDescriptor(fd, before) {
		return nil, ErrBootstrapRejected
	}
	if secretFDs != nil && !validInheritedSecretDescriptors(before, *secretFDs) {
		return nil, ErrBootstrapRejected
	}
	contents, err := preadExact(fd, int(before.Size))
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	defer clear(contents)
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || !sameInheritedSourceStat(before, after) ||
		!validInheritedSourceDescriptor(fd, after) {
		return nil, ErrBootstrapRejected
	}
	summary, err := validateInheritedSourceFrame(contents)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	material, runtime, err := captureInheritedSnapshotMaterial(contents, summary)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	file := os.NewFile(uintptr(fd), memfdName)
	if file == nil {
		material.clear()
		runtime.clear()
		return nil, ErrBootstrapRejected
	}
	if secretFDs != nil {
		for index, secretFD := range secretFDs {
			runtime.readers[index] = os.NewFile(uintptr(secretFD), "control-worker-secret")
			if runtime.readers[index] == nil {
				_ = file.Close()
				material.clear()
				runtime.clear()
				return nil, ErrBootstrapRejected
			}
		}
	}
	owned = false
	return newInheritedSourceWithRuntime(file, summary, material, runtime, inheritedSourceLive), nil
}

func validInheritedSecretDescriptors(publicStat unix.Stat_t, secretFDs [3]int) bool {
	seen := map[[2]uint64]struct{}{
		{uint64(publicStat.Dev), publicStat.Ino}: {},
	}
	for _, fd := range secretFDs {
		if fd < 0 {
			return false
		}
		unix.CloseOnExec(fd)
		var stat unix.Stat_t
		flags, flagsErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		descriptorFlags, descriptorErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFIFO ||
			flagsErr != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || descriptorErr != nil ||
			descriptorFlags&unix.FD_CLOEXEC == 0 {
			return false
		}
		identity := [2]uint64{uint64(stat.Dev), stat.Ino}
		if _, duplicate := seen[identity]; duplicate {
			return false
		}
		seen[identity] = struct{}{}
	}
	return true
}

func validInheritedSourceDescriptor(fd int, stat unix.Stat_t) bool {
	var filesystem unix.Statfs_t
	flags, flagsErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	descriptorFlags, descriptorErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	seals, sealsErr := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&0o7777 == 0o400 &&
		stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 0 && stat.Size > 0 && stat.Size <= maximumEnvelopeBytes &&
		unix.Fstatfs(fd, &filesystem) == nil && filesystem.Type == unix.TMPFS_MAGIC &&
		flagsErr == nil && flags&unix.O_ACCMODE == unix.O_RDONLY && descriptorErr == nil &&
		descriptorFlags&unix.FD_CLOEXEC != 0 && sealsErr == nil && seals == requiredMemfdSeals
}

func sameInheritedSourceStat(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode &&
		left.Nlink == right.Nlink && left.Uid == right.Uid && left.Gid == right.Gid &&
		left.Size == right.Size && left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func validateInheritedSourceFrame(framed []byte) (PublicSourceSummary, error) {
	minimum := len(envelopeMagicText) + 8 + sha256.Size
	if len(framed) < minimum || len(framed) > maximumEnvelopeBytes ||
		!bytes.HasPrefix(framed, []byte(envelopeMagicText)) {
		return PublicSourceSummary{}, ErrBootstrapRejected
	}
	payloadLength := binary.BigEndian.Uint64(framed[len(envelopeMagicText) : len(envelopeMagicText)+8])
	payloadStart := len(envelopeMagicText) + 8
	if payloadLength == 0 || payloadLength > uint64(maximumEnvelopeBytes) ||
		payloadLength > uint64(len(framed)-payloadStart-sha256.Size) {
		return PublicSourceSummary{}, ErrBootstrapRejected
	}
	payloadEnd := payloadStart + int(payloadLength)
	if payloadEnd+sha256.Size != len(framed) {
		return PublicSourceSummary{}, ErrBootstrapRejected
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(envelopeDomainText))
	_, _ = hasher.Write(framed[:payloadEnd])
	digest := hasher.Sum(nil)
	if subtle.ConstantTimeCompare(digest, framed[payloadEnd:]) != 1 {
		return PublicSourceSummary{}, ErrBootstrapRejected
	}
	var envelope publicWireEnvelope
	if securemanifest.DecodeStrict(framed[payloadStart:payloadEnd], &envelope) != nil ||
		envelope.SchemaVersion != publicEnvelopeSchemaVersion || len(envelope.Artifacts) < 11 {
		return PublicSourceSummary{}, ErrBootstrapRejected
	}
	defer clearInheritedEnvelope(&envelope)
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, framed[payloadStart:payloadEnd]) {
		clear(canonical)
		return PublicSourceSummary{}, ErrBootstrapRejected
	}
	clear(canonical)
	bootstrap := envelope.Artifacts[0]
	if !validInheritedArtifact(bootstrap, "bootstrap_manifest", bootstrapManifestFilename, maximumBootstrapManifestBytes) {
		return PublicSourceSummary{}, ErrBootstrapRejected
	}
	document, err := decodePublicDocument(bootstrap.Contents)
	if err != nil {
		return PublicSourceSummary{}, ErrBootstrapRejected
	}
	expected := []inheritedArtifactExpectation{
		{role: "connector_manifest", name: connectorManifestFilename, sha256: document.Artifacts.ConnectorManifestSHA256, maximum: maximumManifestBytes},
		{role: "plan_manifest", name: planManifestFilename, sha256: document.Artifacts.PlanManifestSHA256, maximum: maximumManifestBytes},
		{role: "target_manifest", name: targetManifestFilename, sha256: document.Artifacts.TargetManifestSHA256, maximum: maximumManifestBytes},
		{role: "egress_manifest", name: egressManifestFilename, sha256: document.Artifacts.EgressManifestSHA256, maximum: maximumManifestBytes},
		{role: "postgres_root_ca", name: postgresRootCAFilename, sha256: document.Artifacts.PostgresRootCASHA256, maximum: maximumCertificateBytes},
		{role: "postgres_client_certificate", name: postgresClientCertificateFilename, sha256: document.Artifacts.PostgresClientCertificateSHA256, maximum: maximumCertificateBytes},
		{role: "temporal_root_ca", name: temporalRootCAFilename, sha256: document.Artifacts.TemporalRootCASHA256, maximum: maximumCertificateBytes},
		{role: "temporal_starter_certificate", name: temporalStarterCertificateFilename, sha256: document.Artifacts.TemporalStarterCertificateSHA256, maximum: maximumCertificateBytes},
		{role: "temporal_control_certificate", name: temporalControlCertificateFilename, sha256: document.Artifacts.TemporalControlCertificateSHA256, maximum: maximumCertificateBytes},
	}
	sourceBytes := len(bootstrap.Contents)
	for index, expectation := range expected {
		artifact := envelope.Artifacts[index+1]
		if !validInheritedArtifact(artifact, expectation.role, expectation.name, expectation.maximum) ||
			artifact.SHA256 != expectation.sha256 {
			return PublicSourceSummary{}, ErrBootstrapRejected
		}
		reserved, ok := reserveEnvelopeSourceBytes(sourceBytes, len(artifact.Contents))
		if !ok {
			return PublicSourceSummary{}, ErrBootstrapRejected
		}
		sourceBytes = reserved
	}
	targetDigests := document.Artifacts.TargetRootBundleSHA256
	if len(envelope.Artifacts) != 10+len(targetDigests) {
		return PublicSourceSummary{}, ErrBootstrapRejected
	}
	for index, targetDigest := range targetDigests {
		artifact := envelope.Artifacts[index+10]
		if !validInheritedArtifact(
			artifact,
			"target_root_bundle",
			targetDigest+certificateFileSuffix,
			maximumCertificateBytes,
		) || artifact.SHA256 != targetDigest {
			return PublicSourceSummary{}, ErrBootstrapRejected
		}
		reserved, ok := reserveEnvelopeSourceBytes(sourceBytes, len(artifact.Contents))
		if !ok {
			return PublicSourceSummary{}, ErrBootstrapRejected
		}
		sourceBytes = reserved
	}
	if validateTargetRootClosure(envelope.Artifacts[3].Contents, productionBootstrapRoot, targetDigests) != nil ||
		validateInheritedCertificates(envelope.Artifacts, time.Now().UTC()) != nil {
		return PublicSourceSummary{}, ErrBootstrapRejected
	}
	return PublicSourceSummary{
		SchemaVersion: PublicSourceSchemaVersion, ManifestSHA256: bootstrap.SHA256,
		EnvelopeSHA256: hex.EncodeToString(digest), EnvelopeSize: int64(len(framed)),
	}, nil
}

func captureInheritedSnapshotMaterial(
	framed []byte,
	summary PublicSourceSummary,
) (*inheritedSnapshotMaterial, *inheritedRuntimeMaterial, error) {
	minimum := len(envelopeMagicText) + 8 + sha256.Size
	if len(framed) < minimum || int64(len(framed)) != summary.EnvelopeSize ||
		!bytes.HasPrefix(framed, []byte(envelopeMagicText)) {
		return nil, nil, ErrBootstrapRejected
	}
	payloadLength := binary.BigEndian.Uint64(framed[len(envelopeMagicText) : len(envelopeMagicText)+8])
	payloadStart := len(envelopeMagicText) + 8
	if payloadLength == 0 || payloadLength > uint64(len(framed)-payloadStart-sha256.Size) {
		return nil, nil, ErrBootstrapRejected
	}
	payloadEnd := payloadStart + int(payloadLength)
	if payloadEnd+sha256.Size != len(framed) {
		return nil, nil, ErrBootstrapRejected
	}
	var envelope publicWireEnvelope
	if securemanifest.DecodeStrict(framed[payloadStart:payloadEnd], &envelope) != nil ||
		envelope.SchemaVersion != publicEnvelopeSchemaVersion || len(envelope.Artifacts) < 11 {
		return nil, nil, ErrBootstrapRejected
	}
	defer clearInheritedEnvelope(&envelope)
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, framed[payloadStart:payloadEnd]) {
		clear(canonical)
		return nil, nil, ErrBootstrapRejected
	}
	clear(canonical)
	document, err := decodePublicDocument(envelope.Artifacts[0].Contents)
	if err != nil || envelope.Artifacts[0].SHA256 != summary.ManifestSHA256 ||
		len(envelope.Artifacts) != 10+len(document.Artifacts.TargetRootBundleSHA256) {
		return nil, nil, ErrBootstrapRejected
	}
	material := &inheritedSnapshotMaterial{
		connector: bytes.Clone(envelope.Artifacts[1].Contents),
		plan:      bytes.Clone(envelope.Artifacts[2].Contents),
		target:    bytes.Clone(envelope.Artifacts[3].Contents),
		egress:    bytes.Clone(envelope.Artifacts[4].Contents),
		expected: readassembly.Summary{
			SchemaVersion:           cloneSnapshotString(document.ExpectedSnapshot.SchemaVersion),
			PlanManifestDigest:      cloneSnapshotString(document.ExpectedSnapshot.PlanManifestDigest),
			ConnectorRegistryDigest: cloneSnapshotString(document.ExpectedSnapshot.ConnectorRegistryDigest),
			TargetRegistryDigest:    cloneSnapshotString(document.ExpectedSnapshot.TargetRegistryDigest),
			EgressRegistryDigest:    cloneSnapshotString(document.ExpectedSnapshot.EgressRegistryDigest),
			ExecutorProfileDigest:   cloneSnapshotString(document.ExpectedSnapshot.ExecutorProfileDigest),
			BundleDigest:            cloneSnapshotString(document.ExpectedSnapshot.BundleDigest),
		},
	}
	material.roots = make([]inheritedSnapshotRoot, len(envelope.Artifacts)-10)
	for index, artifact := range envelope.Artifacts[10:] {
		material.roots[index] = inheritedSnapshotRoot{
			path:     filepath.Join(productionBootstrapRoot, targetRootsDirectory, artifact.Name),
			contents: bytes.Clone(artifact.Contents),
		}
	}
	runtime, err := captureInheritedRuntimeMaterial(document, envelope.Artifacts, time.Now().UTC())
	if err != nil {
		material.clear()
		return nil, nil, ErrBootstrapRejected
	}
	return material, runtime, nil
}

func captureInheritedRuntimeMaterial(
	document publicDocument,
	artifacts []publicWireArtifact,
	now time.Time,
) (*inheritedRuntimeMaterial, error) {
	if len(artifacts) < 10 || now.IsZero() {
		return nil, ErrBootstrapRejected
	}
	postgresRoots, err := parseRootBundle(artifacts[5].Contents, now)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	temporalRoots, err := parseRootBundle(artifacts[7].Contents, now)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	_, postgresSPKI, err := validateClientCertificateChain(artifacts[6].Contents, postgresRoots, now)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	_, starterSPKI, err := validateClientCertificateChain(artifacts[8].Contents, temporalRoots, now)
	if err != nil {
		clear(postgresSPKI)
		return nil, ErrBootstrapRejected
	}
	_, controlSPKI, err := validateClientCertificateChain(artifacts[9].Contents, temporalRoots, now)
	if err != nil {
		clear(postgresSPKI)
		clear(starterSPKI)
		return nil, ErrBootstrapRejected
	}
	return &inheritedRuntimeMaterial{
		expectedSPKI: [3][]byte{postgresSPKI, starterSPKI, controlSPKI},
		postgres:     document.Postgres,
		temporal:     document.Temporal,
		postgresRoot: bytes.Clone(artifacts[5].Contents),
		postgresCert: bytes.Clone(artifacts[6].Contents),
		temporalRoot: bytes.Clone(artifacts[7].Contents),
		starterCert:  bytes.Clone(artifacts[8].Contents),
		controlCert:  bytes.Clone(artifacts[9].Contents),
	}, nil
}

func clearInheritedEnvelope(envelope *publicWireEnvelope) {
	if envelope == nil {
		return
	}
	for index := range envelope.Artifacts {
		clear(envelope.Artifacts[index].Contents)
		envelope.Artifacts[index].Contents = nil
	}
	envelope.Artifacts = nil
}

func validInheritedArtifact(artifact publicWireArtifact, role, name string, maximum int) bool {
	return artifact.Role == role && artifact.Name == name && len(artifact.Contents) > 0 &&
		len(artifact.Contents) <= maximum && validSHA256(artifact.SHA256) && matchesSHA256(artifact.Contents, artifact.SHA256)
}

func validateInheritedCertificates(artifacts []publicWireArtifact, now time.Time) error {
	if len(artifacts) < 11 || now.IsZero() {
		return ErrBootstrapRejected
	}
	postgresRoots, err := parseRootBundle(artifacts[5].Contents, now)
	if err != nil {
		return ErrBootstrapRejected
	}
	temporalRoots, err := parseRootBundle(artifacts[7].Contents, now)
	if err != nil {
		return ErrBootstrapRejected
	}
	postgresLeaf, postgresKey, err := validateClientCertificateChain(artifacts[6].Contents, postgresRoots, now)
	if err != nil {
		return ErrBootstrapRejected
	}
	starterLeaf, starterKey, err := validateClientCertificateChain(artifacts[8].Contents, temporalRoots, now)
	if err != nil {
		return ErrBootstrapRejected
	}
	controlLeaf, controlKey, err := validateClientCertificateChain(artifacts[9].Contents, temporalRoots, now)
	if err != nil || bytes.Equal(postgresLeaf, starterLeaf) || bytes.Equal(postgresLeaf, controlLeaf) ||
		bytes.Equal(starterLeaf, controlLeaf) || bytes.Equal(postgresKey, starterKey) ||
		bytes.Equal(postgresKey, controlKey) || bytes.Equal(starterKey, controlKey) {
		return ErrBootstrapRejected
	}
	for _, artifact := range artifacts[10:] {
		if validateRootBundle(artifact.Contents, now) != nil {
			return ErrBootstrapRejected
		}
	}
	return nil
}
