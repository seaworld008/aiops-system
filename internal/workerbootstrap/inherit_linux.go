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
	"time"

	"github.com/seaworld008/aiops-system/internal/securemanifest"
	"golang.org/x/sys/unix"
)

const inheritedPublicSourceFD = 4

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
	return acceptInheritedSourceDescriptor(inheritedPublicSourceFD)
}

func acceptInheritedSourceDescriptor(fd int) (*InheritedSource, error) {
	if fd < 0 {
		return nil, ErrBootstrapRejected
	}
	owned := true
	defer func() {
		if owned {
			_ = unix.Close(fd)
		}
	}()
	unix.CloseOnExec(fd)
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !validInheritedSourceDescriptor(fd, before) {
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
	file := os.NewFile(uintptr(fd), memfdName)
	if file == nil {
		return nil, ErrBootstrapRejected
	}
	owned = false
	return newInheritedSource(file, summary), nil
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
