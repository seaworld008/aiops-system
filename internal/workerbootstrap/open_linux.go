//go:build linux

package workerbootstrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	productionBootstrapRoot = "/run/aiops/control-worker/v1"

	bootstrapManifestFilename          = "bootstrap.json"
	connectorManifestFilename          = "connector-manifest.json"
	planManifestFilename               = "plan-manifest.json"
	targetManifestFilename             = "target-manifest.json"
	egressManifestFilename             = "egress-manifest.json"
	postgresRootCAFilename             = "postgres-root-ca.pem"
	postgresClientCertificateFilename  = "postgres-client-certificate.pem"
	temporalRootCAFilename             = "temporal-root-ca.pem"
	temporalStarterCertificateFilename = "temporal-starter-certificate.pem"
	temporalControlCertificateFilename = "temporal-control-certificate.pem"

	publicEnvelopeSchemaVersion = "control-worker-public-source-envelope.v1"
	memfdName                   = "aiops-control-bootstrap"
	maximumCertificateChain     = 8
	maximumRootCertificates     = 16
	envelopeMagicText           = "AIOPS-CW-BOOT-V1\x00"
	envelopeDomainText          = "aiops/control-worker-public-source-envelope/v1\x00"
)

const requiredMemfdSeals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL

type publicWireEnvelope struct {
	SchemaVersion string               `json:"schema_version"`
	Artifacts     []publicWireArtifact `json:"artifacts"`
}

type publicWireArtifact struct {
	Role     string `json:"role"`
	Name     string `json:"name"`
	SHA256   string `json:"sha256"`
	Contents []byte `json:"contents"`
}

type fixedArtifactSpec struct {
	role     string
	filename string
	expected string
	maximum  int
	contents []byte
}

// OpenProductionSource snapshots the one compile-time production root. It has
// no environment, path, FD, or fallback input. The result is not a semantic
// Snapshot proof; its only production consumer is the reviewed FD4 handoff.
func OpenProductionSource() (capability *PublicSourceCapability, returnedErr error) {
	defer func() {
		if recover() != nil {
			if capability != nil {
				_ = capability.Close()
			}
			capability = nil
			returnedErr = ErrBootstrapRejected
		}
	}()
	anchor, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	defer unix.Close(anchor)
	return openPublicSourceFromAnchor(
		anchor,
		productionBootstrapRoot,
		[]string{"run", "aiops", "control-worker", "v1"},
	)
}

func openPublicSourceFromAnchor(
	anchor int,
	rootPath string,
	components []string,
) (capability *PublicSourceCapability, returnedErr error) {
	defer func() {
		if recover() != nil {
			if capability != nil {
				_ = capability.Close()
			}
			capability = nil
			returnedErr = ErrBootstrapRejected
		}
	}()
	if anchor < 0 || !validRootShape(rootPath, components) || !validTrustedDirectory(anchor, false) {
		return nil, ErrBootstrapRejected
	}
	root, err := traverseTrustedDirectories(anchor, components)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	defer unix.Close(root)
	targetRoots, err := openTrustedDirectoryAt(root, targetRootsDirectory, true)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	defer unix.Close(targetRoots)

	bootstrap, err := readStableFileAt(root, bootstrapManifestFilename, maximumBootstrapManifestBytes, nil)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	defer clear(bootstrap)
	document, err := decodePublicDocument(bootstrap)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	sourceBytes := len(bootstrap)

	specifications := []fixedArtifactSpec{
		{role: "connector_manifest", filename: connectorManifestFilename, expected: document.Artifacts.ConnectorManifestSHA256, maximum: maximumManifestBytes},
		{role: "plan_manifest", filename: planManifestFilename, expected: document.Artifacts.PlanManifestSHA256, maximum: maximumManifestBytes},
		{role: "target_manifest", filename: targetManifestFilename, expected: document.Artifacts.TargetManifestSHA256, maximum: maximumManifestBytes},
		{role: "egress_manifest", filename: egressManifestFilename, expected: document.Artifacts.EgressManifestSHA256, maximum: maximumManifestBytes},
		{role: "postgres_root_ca", filename: postgresRootCAFilename, expected: document.Artifacts.PostgresRootCASHA256, maximum: maximumCertificateBytes},
		{role: "postgres_client_certificate", filename: postgresClientCertificateFilename, expected: document.Artifacts.PostgresClientCertificateSHA256, maximum: maximumCertificateBytes},
		{role: "temporal_root_ca", filename: temporalRootCAFilename, expected: document.Artifacts.TemporalRootCASHA256, maximum: maximumCertificateBytes},
		{role: "temporal_starter_certificate", filename: temporalStarterCertificateFilename, expected: document.Artifacts.TemporalStarterCertificateSHA256, maximum: maximumCertificateBytes},
		{role: "temporal_control_certificate", filename: temporalControlCertificateFilename, expected: document.Artifacts.TemporalControlCertificateSHA256, maximum: maximumCertificateBytes},
	}
	for index := range specifications {
		contents, readErr := readStableFileAt(root, specifications[index].filename, specifications[index].maximum, nil)
		if readErr != nil || !matchesSHA256(contents, specifications[index].expected) {
			clear(contents)
			clearFixedArtifacts(specifications)
			return nil, ErrBootstrapRejected
		}
		reserved, ok := reserveEnvelopeSourceBytes(sourceBytes, len(contents))
		if !ok {
			clear(contents)
			clearFixedArtifacts(specifications)
			return nil, ErrBootstrapRejected
		}
		sourceBytes = reserved
		specifications[index].contents = contents
	}
	defer clearFixedArtifacts(specifications)
	if validateTargetRootClosure(specifications[2].contents, rootPath, document.Artifacts.TargetRootBundleSHA256) != nil {
		return nil, ErrBootstrapRejected
	}

	targetRootArtifacts := make([]publicWireArtifact, 0, len(document.Artifacts.TargetRootBundleSHA256))
	defer func() { clearWireArtifacts(targetRootArtifacts) }()
	for _, digest := range document.Artifacts.TargetRootBundleSHA256 {
		name := digest + certificateFileSuffix
		contents, readErr := readStableFileAt(targetRoots, name, maximumCertificateBytes, nil)
		if readErr != nil || !matchesSHA256(contents, digest) || validateRootBundle(contents, time.Now().UTC()) != nil {
			clear(contents)
			return nil, ErrBootstrapRejected
		}
		reserved, ok := reserveEnvelopeSourceBytes(sourceBytes, len(contents))
		if !ok {
			clear(contents)
			return nil, ErrBootstrapRejected
		}
		sourceBytes = reserved
		targetRootArtifacts = append(targetRootArtifacts, publicWireArtifact{
			Role: "target_root_bundle", Name: name, SHA256: digest, Contents: contents,
		})
	}

	now := time.Now().UTC()
	postgresRoots, err := parseRootBundle(specifications[4].contents, now)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	temporalRoots, err := parseRootBundle(specifications[6].contents, now)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	postgresLeaf, postgresKey, err := validateClientCertificateChain(specifications[5].contents, postgresRoots, now)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	starterLeaf, starterKey, err := validateClientCertificateChain(specifications[7].contents, temporalRoots, now)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	controlLeaf, controlKey, err := validateClientCertificateChain(specifications[8].contents, temporalRoots, now)
	if err != nil || bytes.Equal(postgresLeaf, starterLeaf) || bytes.Equal(postgresLeaf, controlLeaf) ||
		bytes.Equal(starterLeaf, controlLeaf) || bytes.Equal(postgresKey, starterKey) ||
		bytes.Equal(postgresKey, controlKey) || bytes.Equal(starterKey, controlKey) {
		return nil, ErrBootstrapRejected
	}
	if !revalidateDirectoryChain(anchor, root, targetRoots, components) {
		return nil, ErrBootstrapRejected
	}

	artifacts := make([]publicWireArtifact, 0, 1+len(specifications)+len(targetRootArtifacts))
	artifacts = append(artifacts, publicWireArtifact{
		Role: "bootstrap_manifest", Name: bootstrapManifestFilename,
		SHA256: sha256HexValue(bootstrap), Contents: bootstrap,
	})
	for _, specification := range specifications {
		artifacts = append(artifacts, publicWireArtifact{
			Role: specification.role, Name: specification.filename,
			SHA256: specification.expected, Contents: specification.contents,
		})
	}
	artifacts = append(artifacts, targetRootArtifacts...)
	framed, envelopeDigest, err := marshalPublicEnvelope(artifacts)
	if err != nil {
		clear(framed)
		return nil, ErrBootstrapRejected
	}
	defer clear(framed)
	file, err := createReadOnlySealedMemfd(framed)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	summary := PublicSourceSummary{
		SchemaVersion: PublicSourceSchemaVersion, ManifestSHA256: sha256HexValue(bootstrap),
		EnvelopeSHA256: envelopeDigest, EnvelopeSize: int64(len(framed)),
	}
	return newPublicSourceCapability(file, summary), nil
}

func validRootShape(rootPath string, components []string) bool {
	if rootPath == "" || len(rootPath) > maximumPathBytes || !filepath.IsAbs(rootPath) ||
		filepath.Clean(rootPath) != rootPath || strings.TrimSpace(rootPath) != rootPath || len(components) == 0 {
		return false
	}
	current := rootPath
	for index := len(components) - 1; index >= 0; index-- {
		component := components[index]
		if !validBasename(component) || filepath.Base(current) != component {
			return false
		}
		current = filepath.Dir(current)
	}
	return true
}

func reserveEnvelopeSourceBytes(current, additional int) (int, bool) {
	if current < 0 || additional < 0 || current > maximumEnvelopeSourceBytes ||
		additional > maximumEnvelopeSourceBytes-current {
		return 0, false
	}
	return current + additional, true
}

func validBasename(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 255 && filepath.Base(name) == name &&
		!strings.ContainsAny(name, "/\\\x00") && strings.TrimSpace(name) == name
}

func traverseTrustedDirectories(anchor int, components []string) (int, error) {
	current := anchor
	owned := false
	for index, component := range components {
		next, err := openTrustedDirectoryAt(current, component, index == len(components)-1)
		if err != nil {
			if owned {
				_ = unix.Close(current)
			}
			return -1, ErrBootstrapRejected
		}
		if owned {
			_ = unix.Close(current)
		}
		current = next
		owned = true
	}
	if !owned {
		return -1, ErrBootstrapRejected
	}
	return current, nil
}

func openTrustedDirectoryAt(parent int, name string, final bool) (int, error) {
	if parent < 0 || !validBasename(name) {
		return -1, ErrBootstrapRejected
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil || !validTrustedDirectory(fd, final) {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		return -1, ErrBootstrapRejected
	}
	return fd, nil
}

func validTrustedDirectory(fd int, final bool) bool {
	if fd < 0 {
		return false
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Nlink < 1 ||
		(stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || hasAccessExpandingMetadata(fd) {
		return false
	}
	permissions := stat.Mode & 0o7777
	if final {
		return stat.Uid == uint32(os.Geteuid()) && permissions == 0o700
	}
	return permissions&0o7022 == 0
}

func readStableFileAt(parent int, name string, maximum int, betweenReads func()) ([]byte, error) {
	if parent < 0 || !validBasename(name) || maximum <= 0 {
		return nil, ErrBootstrapRejected
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	contents, readErr := readStableDescriptor(fd, maximum, betweenReads)
	closeErr := unix.Close(fd)
	if readErr != nil || closeErr != nil {
		clear(contents)
		return nil, ErrBootstrapRejected
	}
	return contents, nil
}

func readStableDescriptor(fd int, maximum int, betweenReads func()) ([]byte, error) {
	if fd < 0 || maximum <= 0 {
		return nil, ErrBootstrapRejected
	}
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !validArtifactStat(before, maximum) || hasAccessExpandingMetadata(fd) {
		return nil, ErrBootstrapRejected
	}
	first, err := preadExact(fd, int(before.Size))
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	if betweenReads != nil {
		betweenReads()
	}
	second, secondErr := preadExact(fd, int(before.Size))
	var after unix.Stat_t
	statErr := unix.Fstat(fd, &after)
	metadataRejected := statErr != nil || !validArtifactStat(after, maximum) || hasAccessExpandingMetadata(fd)
	defer clear(second)
	if secondErr != nil || metadataRejected || !sameStableStat(before, after) || !bytes.Equal(first, second) {
		clear(first)
		return nil, ErrBootstrapRejected
	}
	return first, nil
}

func validArtifactStat(stat unix.Stat_t, maximum int) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&0o7777 == 0o400 &&
		stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1 && stat.Size > 0 && stat.Size <= int64(maximum)
}

func sameStableStat(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode &&
		left.Nlink == right.Nlink && left.Uid == right.Uid && left.Gid == right.Gid &&
		left.Size == right.Size && left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func preadExact(fd int, size int) ([]byte, error) {
	if size <= 0 {
		return nil, ErrBootstrapRejected
	}
	contents := make([]byte, size)
	offset := 0
	for offset < len(contents) {
		read, err := unix.Pread(fd, contents[offset:], int64(offset))
		if err != nil || read <= 0 {
			clear(contents)
			return nil, ErrBootstrapRejected
		}
		offset += read
	}
	return contents, nil
}

func hasAccessExpandingMetadata(fd int) bool {
	size, err := unix.Flistxattr(fd, nil)
	if err != nil || size < 0 || size > maximumCertificateBytes {
		return true
	}
	if size == 0 {
		return false
	}
	names := make([]byte, size)
	read, err := unix.Flistxattr(fd, names)
	if err != nil || read != size {
		return true
	}
	for len(names) > 0 {
		end := bytes.IndexByte(names, 0)
		if end <= 0 || !allowedLinuxXattr(string(names[:end])) {
			return true
		}
		names = names[end+1:]
	}
	return false
}

func allowedLinuxXattr(name string) bool {
	return name == "security.selinux" || name == "security.ima" || name == "security.evm"
}

func matchesSHA256(contents []byte, expected string) bool {
	decoded, err := hex.DecodeString(expected)
	actual := sha256.Sum256(contents)
	return err == nil && len(decoded) == sha256.Size && subtle.ConstantTimeCompare(actual[:], decoded) == 1
}

func sha256HexValue(contents []byte) string {
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

func parseRootBundle(encoded []byte, now time.Time) (*x509.CertPool, error) {
	certificates, err := parseCertificatePEM(encoded, maximumRootCertificates)
	if err != nil || len(certificates) == 0 || now.IsZero() {
		return nil, ErrBootstrapRejected
	}
	pool := x509.NewCertPool()
	seen := make(map[[sha256.Size]byte]struct{}, len(certificates))
	for _, certificate := range certificates {
		digest := sha256.Sum256(certificate.Raw)
		_, duplicate := seen[digest]
		if duplicate || !certificate.IsCA || !certificate.BasicConstraintsValid ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(certificate.NotBefore) ||
			!now.Before(certificate.NotAfter) || !bytes.Equal(certificate.RawSubject, certificate.RawIssuer) ||
			certificate.CheckSignatureFrom(certificate) != nil {
			return nil, ErrBootstrapRejected
		}
		seen[digest] = struct{}{}
		pool.AddCert(certificate)
	}
	return pool, nil
}

func validateRootBundle(encoded []byte, now time.Time) error {
	_, err := parseRootBundle(encoded, now)
	return err
}

func validateClientCertificateChain(
	encoded []byte,
	roots *x509.CertPool,
	now time.Time,
) (leafRaw []byte, publicKey []byte, returnedErr error) {
	certificates, err := parseCertificatePEM(encoded, maximumCertificateChain)
	if err != nil || roots == nil || len(certificates) == 0 || now.IsZero() {
		return nil, nil, ErrBootstrapRejected
	}
	leaf := certificates[0]
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || key == nil || key.Curve != elliptic.P256() || key.X == nil || key.Y == nil ||
		!elliptic.P256().IsOnCurve(key.X, key.Y) || leaf.IsCA || !leaf.BasicConstraintsValid ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(leaf.ExtKeyUsage) != 1 ||
		leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 ||
		now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, nil, ErrBootstrapRejected
	}
	intermediates := x509.NewCertPool()
	for index, certificate := range certificates[1:] {
		if !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, nil, ErrBootstrapRejected
		}
		if certificates[index].CheckSignatureFrom(certificate) != nil {
			return nil, nil, ErrBootstrapRejected
		}
		intermediates.AddCert(certificate)
	}
	verifiedChains, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil || !certificateSequenceVerified(certificates, verifiedChains) {
		return nil, nil, ErrBootstrapRejected
	}
	marshaledKey, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, nil, ErrBootstrapRejected
	}
	return bytes.Clone(leaf.Raw), marshaledKey, nil
}

func parseCertificatePEM(encoded []byte, maximum int) ([]*x509.Certificate, error) {
	if len(encoded) == 0 || len(encoded) > maximumCertificateBytes || maximum <= 0 ||
		bytes.Contains(encoded, []byte("PRIVATE KEY")) {
		return nil, ErrBootstrapRejected
	}
	remaining := bytes.Trim(encoded, " \t\r\n")
	certificates := make([]*x509.Certificate, 0, 1)
	for len(remaining) > 0 {
		if len(certificates) == maximum || !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrBootstrapRejected
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(block.Bytes) == 0 ||
			len(rest) >= len(remaining) {
			return nil, ErrBootstrapRejected
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrBootstrapRejected
		}
		certificates = append(certificates, certificate)
		remaining = bytes.Trim(rest, " \t\r\n")
	}
	if len(certificates) == 0 {
		return nil, ErrBootstrapRejected
	}
	return certificates, nil
}

func certificateSequenceVerified(provided []*x509.Certificate, verified [][]*x509.Certificate) bool {
	for _, chain := range verified {
		if len(chain) < len(provided) {
			continue
		}
		matches := true
		for index, certificate := range provided {
			if certificate == nil || !bytes.Equal(certificate.Raw, chain[index].Raw) {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func marshalPublicEnvelope(artifacts []publicWireArtifact) ([]byte, string, error) {
	if len(artifacts) == 0 {
		return nil, "", ErrBootstrapRejected
	}
	payload, err := json.Marshal(publicWireEnvelope{SchemaVersion: publicEnvelopeSchemaVersion, Artifacts: artifacts})
	if err != nil || len(payload) == 0 || len(payload) > maximumEnvelopeBytes {
		clear(payload)
		return nil, "", ErrBootstrapRejected
	}
	framedSize := len(envelopeMagicText) + 8 + len(payload) + sha256.Size
	if framedSize > maximumEnvelopeBytes {
		clear(payload)
		return nil, "", ErrBootstrapRejected
	}
	framed := make([]byte, 0, framedSize)
	framed = append(framed, envelopeMagicText...)
	length := make([]byte, 8)
	binary.BigEndian.PutUint64(length, uint64(len(payload)))
	framed = append(framed, length...)
	framed = append(framed, payload...)
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(envelopeDomainText))
	_, _ = hasher.Write(framed)
	digest := hasher.Sum(nil)
	framed = append(framed, digest...)
	clear(payload)
	return framed, hex.EncodeToString(digest), nil
}

func createReadOnlySealedMemfd(contents []byte) (*os.File, error) {
	if len(contents) == 0 || len(contents) > maximumEnvelopeBytes {
		return nil, ErrBootstrapRejected
	}
	readWriteFD, err := unix.MemfdCreate(memfdName, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	readWriteOpen := true
	defer func() {
		if readWriteOpen {
			_ = unix.Close(readWriteFD)
		}
	}()
	if unix.Fchmod(readWriteFD, 0o400) != nil || writeDescriptorAll(readWriteFD, contents) != nil {
		return nil, ErrBootstrapRejected
	}
	if _, err := unix.FcntlInt(uintptr(readWriteFD), unix.F_ADD_SEALS, requiredMemfdSeals); err != nil {
		return nil, ErrBootstrapRejected
	}
	seals, err := unix.FcntlInt(uintptr(readWriteFD), unix.F_GET_SEALS, 0)
	if err != nil || seals != requiredMemfdSeals {
		return nil, ErrBootstrapRejected
	}
	readOnlyFD, err := unix.Open("/proc/self/fd/"+strconv.Itoa(readWriteFD), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	readOnlyOpen := true
	defer func() {
		if readOnlyOpen {
			_ = unix.Close(readOnlyFD)
		}
	}()
	if !sameMemfd(readWriteFD, readOnlyFD, int64(len(contents))) {
		return nil, ErrBootstrapRejected
	}
	if unix.Close(readWriteFD) != nil {
		return nil, ErrBootstrapRejected
	}
	readWriteOpen = false
	file := os.NewFile(uintptr(readOnlyFD), memfdName)
	if file == nil {
		return nil, ErrBootstrapRejected
	}
	readOnlyOpen = false
	return file, nil
}

func writeDescriptorAll(fd int, contents []byte) error {
	written := 0
	for written < len(contents) {
		count, err := unix.Write(fd, contents[written:])
		if err != nil || count <= 0 {
			return ErrBootstrapRejected
		}
		written += count
	}
	return nil
}

func sameMemfd(readWriteFD, readOnlyFD int, size int64) bool {
	var readWriteStat, readOnlyStat unix.Stat_t
	var filesystem unix.Statfs_t
	flags, flagsErr := unix.FcntlInt(uintptr(readOnlyFD), unix.F_GETFL, 0)
	descriptorFlags, descriptorErr := unix.FcntlInt(uintptr(readOnlyFD), unix.F_GETFD, 0)
	seals, sealsErr := unix.FcntlInt(uintptr(readOnlyFD), unix.F_GET_SEALS, 0)
	return unix.Fstat(readWriteFD, &readWriteStat) == nil && unix.Fstat(readOnlyFD, &readOnlyStat) == nil &&
		unix.Fstatfs(readOnlyFD, &filesystem) == nil && filesystem.Type == unix.TMPFS_MAGIC &&
		readWriteStat.Dev == readOnlyStat.Dev && readWriteStat.Ino == readOnlyStat.Ino &&
		readOnlyStat.Mode&unix.S_IFMT == unix.S_IFREG && readOnlyStat.Mode&0o7777 == 0o400 &&
		readOnlyStat.Uid == uint32(os.Geteuid()) && readOnlyStat.Nlink == 0 && readOnlyStat.Size == size &&
		flagsErr == nil && flags&unix.O_ACCMODE == unix.O_RDONLY && descriptorErr == nil &&
		descriptorFlags&unix.FD_CLOEXEC != 0 && sealsErr == nil && seals == requiredMemfdSeals
}

func clearFixedArtifacts(specifications []fixedArtifactSpec) {
	for index := range specifications {
		clear(specifications[index].contents)
		specifications[index].contents = nil
	}
}

func clearWireArtifacts(artifacts []publicWireArtifact) {
	for index := range artifacts {
		clear(artifacts[index].Contents)
		artifacts[index].Contents = nil
	}
}

func revalidateDirectoryChain(anchor, root, targetRoots int, components []string) bool {
	if !validTrustedDirectory(anchor, false) || !validTrustedDirectory(root, true) ||
		!validTrustedDirectory(targetRoots, true) {
		return false
	}
	reopenedRoot, err := traverseTrustedDirectories(anchor, components)
	if err != nil {
		return false
	}
	defer unix.Close(reopenedRoot)
	if !sameDirectoryIdentity(root, reopenedRoot) {
		return false
	}
	reopenedTargets, err := openTrustedDirectoryAt(reopenedRoot, targetRootsDirectory, true)
	if err != nil {
		return false
	}
	defer unix.Close(reopenedTargets)
	return sameDirectoryIdentity(targetRoots, reopenedTargets)
}

func sameDirectoryIdentity(leftFD, rightFD int) bool {
	var left, right unix.Stat_t
	return unix.Fstat(leftFD, &left) == nil && unix.Fstat(rightFD, &right) == nil &&
		left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode &&
		left.Uid == right.Uid && left.Gid == right.Gid && left.Ctim == right.Ctim
}
