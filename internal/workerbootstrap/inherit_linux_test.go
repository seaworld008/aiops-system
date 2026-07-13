//go:build linux

package workerbootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/readassembly"
	"github.com/seaworld008/aiops-system/internal/securemanifest"
	"golang.org/x/sys/unix"
)

const inheritedSourceHelperEnvironment = "AIOPS_WORKERBOOTSTRAP_INHERITED_HELPER"

func TestAcceptInheritedSourceUsesFixedFD4AndSetsCLOEXEC(t *testing.T) {
	if os.Getenv(inheritedSourceHelperEnvironment) == "1" {
		source, err := AcceptInheritedSource()
		if err != nil || source == nil || source.Summary().SchemaVersion != PublicSourceSchemaVersion {
			t.Fatalf("AcceptInheritedSource() = %#v, %v", source, err)
		}
		source.state.mu.Lock()
		flags, flagsErr := unix.FcntlInt(source.state.file.Fd(), unix.F_GETFD, 0)
		source.state.mu.Unlock()
		if flagsErr != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("inherited FD4 flags = %#x, %v", flags, flagsErr)
		}
		for descriptor := inheritedPostgresSecretFD; descriptor <= inheritedControlSecretFD; descriptor++ {
			descriptorFlags, descriptorErr := unix.FcntlInt(uintptr(descriptor), unix.F_GETFD, 0)
			if descriptorErr != nil || descriptorFlags&unix.FD_CLOEXEC == 0 {
				t.Fatalf("inherited secret FD%d flags = %#x, %v", descriptor, descriptorFlags, descriptorErr)
			}
		}
		if err := source.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		return
	}
	framed := productionInheritedFrame(t)
	sourceFile, err := createReadOnlySealedMemfd(framed)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceFile.Close()
	statusReader, statusWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer statusReader.Close()
	defer statusWriter.Close()
	secretReaders := make([]*os.File, 3)
	for index := range secretReaders {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		secretReaders[index] = reader
		defer reader.Close()
		defer writer.Close()
	}
	command := exec.Command(os.Args[0], "-test.run=^TestAcceptInheritedSourceUsesFixedFD4AndSetsCLOEXEC$")
	command.Env = append(os.Environ(), inheritedSourceHelperEnvironment+"=1")
	command.ExtraFiles = []*os.File{
		statusWriter, sourceFile, secretReaders[0], secretReaders[1], secretReaders[2],
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("fixed FD4 helper failed: %v: %s", err, output)
	}
}

func TestAcceptInheritedSourceValidatesDescriptorAndFrame(t *testing.T) {
	framed := productionInheritedFrame(t)
	validFile, err := createReadOnlySealedMemfd(framed)
	if err != nil {
		t.Fatal(err)
	}
	validFD, err := unix.Dup(int(validFile.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = validFile.Close()
	source, err := acceptInheritedSourceDescriptor(validFD)
	if err != nil || source == nil || source.Summary().EnvelopeSize != int64(len(framed)) {
		t.Fatalf("acceptInheritedSourceDescriptor(valid) = %#v, %v", source, err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	ordinaryPath := strings.TrimSpace(t.TempDir()) + "/ordinary"
	if err := os.WriteFile(ordinaryPath, framed, 0o400); err != nil {
		t.Fatal(err)
	}
	ordinary, err := unix.Open(ordinaryPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	pipeReader, pipeWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipeWriter.Close()
	pipeFD, err := unix.Dup(int(pipeReader.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = pipeReader.Close()
	writable := testMemfd(t, framed, requiredMemfdSeals, false)
	missingWriteSeal := testMemfd(t, framed, requiredMemfdSeals&^unix.F_SEAL_WRITE, true)
	missingGrowSeal := testMemfd(t, framed, requiredMemfdSeals&^unix.F_SEAL_GROW, true)
	missingShrinkSeal := testMemfd(t, framed, requiredMemfdSeals&^unix.F_SEAL_SHRINK, true)
	missingFinalSeal := testMemfd(t, framed, requiredMemfdSeals&^unix.F_SEAL_SEAL, true)
	wrongMode := testMemfd(t, framed, requiredMemfdSeals, true)
	if unix.Fchmod(wrongMode, 0o600) != nil {
		t.Fatal("change test memfd mode")
	}
	empty := testMemfd(t, nil, requiredMemfdSeals, true)
	overLimit := testMemfd(t, bytes.Repeat([]byte{'x'}, maximumEnvelopeBytes+1), requiredMemfdSeals, true)
	corrupt := bytes.Clone(framed)
	corrupt[len(corrupt)-1] ^= 0xff
	corruptFile, err := createReadOnlySealedMemfd(corrupt)
	if err != nil {
		t.Fatal(err)
	}
	corruptFD, err := unix.Dup(int(corruptFile.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = corruptFile.Close()

	for name, fd := range map[string]int{
		"negative": -1, "ordinary": ordinary, "pipe": pipeFD,
		"writable": writable, "missing write seal": missingWriteSeal, "missing grow seal": missingGrowSeal,
		"missing shrink seal": missingShrinkSeal, "missing final seal": missingFinalSeal,
		"wrong mode": wrongMode, "empty": empty, "over limit": overLimit, "corrupt frame": corruptFD,
	} {
		t.Run(name, func(t *testing.T) {
			source, err := acceptInheritedSourceDescriptor(fd)
			if source != nil {
				_ = source.Close()
			}
			if source != nil || !errors.Is(err, ErrBootstrapRejected) {
				t.Fatalf("acceptInheritedSourceDescriptor() = %#v, %v; want rejection", source, err)
			}
		})
	}
}

func TestAcceptInheritedSourceRequiresThreeDistinctReadOnlySecretPipes(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, readers *[3]int, writers [3]*os.File)
		valid  bool
	}{
		{name: "exact", valid: true},
		{name: "duplicate pipe", mutate: func(t *testing.T, readers *[3]int, _ [3]*os.File) {
			_ = unix.Close(readers[1])
			duplicate, err := unix.Dup(readers[0])
			if err != nil {
				t.Fatal(err)
			}
			readers[1] = duplicate
		}},
		{name: "writer direction", mutate: func(t *testing.T, readers *[3]int, writers [3]*os.File) {
			_ = unix.Close(readers[2])
			writer, err := unix.Dup(int(writers[2].Fd()))
			if err != nil {
				t.Fatal(err)
			}
			readers[2] = writer
		}},
		{name: "ordinary file", mutate: func(t *testing.T, readers *[3]int, _ [3]*os.File) {
			_ = unix.Close(readers[0])
			ordinary, err := unix.Open(os.DevNull, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			readers[0] = ordinary
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			publicFile, err := createReadOnlySealedMemfd(productionInheritedFrame(t))
			if err != nil {
				t.Fatal(err)
			}
			publicFD, err := unix.Dup(int(publicFile.Fd()))
			if err != nil {
				t.Fatal(err)
			}
			_ = publicFile.Close()
			var readers [3]int
			var writers [3]*os.File
			for index := range readers {
				reader, writer, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				readers[index], err = unix.Dup(int(reader.Fd()))
				_ = reader.Close()
				if err != nil {
					t.Fatal(err)
				}
				writers[index] = writer
				defer writer.Close()
			}
			if test.mutate != nil {
				test.mutate(t, &readers, writers)
			}
			source, err := acceptInheritedSourceDescriptors(publicFD, readers)
			if test.valid {
				if err != nil || source == nil {
					t.Fatalf("acceptInheritedSourceDescriptors() = %#v, %v", source, err)
				}
				if closeErr := source.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
				return
			}
			if source != nil || !errors.Is(err, ErrBootstrapRejected) {
				t.Fatalf("acceptInheritedSourceDescriptors() = %#v, %v; want rejection", source, err)
			}
		})
	}
}

func TestInheritedSourceBindsSecretFramesToCertificatesCapturedFromFD4(t *testing.T) {
	framed, fixture := productionInheritedFrameWithFixture(t)
	publicFile, err := createReadOnlySealedMemfd(framed)
	if err != nil {
		t.Fatal(err)
	}
	publicFD, err := unix.Dup(int(publicFile.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = publicFile.Close()
	var readerFDs [3]int
	var writers [3]*os.File
	for index := range readerFDs {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		readerFDs[index], err = unix.Dup(int(reader.Fd()))
		_ = reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		writers[index] = writer
	}
	source, err := acceptInheritedSourceDescriptors(publicFD, readerFDs)
	if err != nil || source == nil {
		t.Fatalf("acceptInheritedSourceDescriptors() = %#v, %v", source, err)
	}
	snapshot, err := source.BuildSnapshot(context.Background())
	if err != nil || snapshot == nil || !snapshot.Ready() {
		t.Fatalf("BuildSnapshot() = %#v, %v", snapshot, err)
	}
	keys := [3]*ecdsa.PrivateKey{fixture.postgresKey, fixture.starterKey, fixture.controlKey}
	var encoded [3][]byte
	for index := range keys {
		encoded[index], err = x509.MarshalPKCS8PrivateKey(keys[index])
		if err != nil {
			t.Fatal(err)
		}
	}
	frames := testSecretBindingFrames(t, encoded)
	for index := range writers {
		if written, err := writers[index].Write(frames[index]); err != nil || written != len(frames[index]) {
			t.Fatalf("write role frame %d = %d, %v", index, written, err)
		}
		if err := writers[index].Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := source.BindControlWorkerSecrets(context.Background()); err != nil {
		t.Fatalf("BindControlWorkerSecrets() error = %v", err)
	}
	if source.state.state != inheritedSourceSecretsBound || source.state.runtime == nil ||
		source.state.runtime.bundle == nil {
		t.Fatal("certificate-bound secret bundle was not atomically published")
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInheritedSourceBuildSnapshotConsumesCapturedCanonicalMaterial(t *testing.T) {
	framed := productionInheritedFrame(t)
	envelope := decodeWireEnvelopeForTest(t, framed)
	var expected publicDocument
	if securemanifest.DecodeStrict(envelope.Artifacts[0].Contents, &expected) != nil {
		t.Fatal("decode expected semantic snapshot")
	}
	file, err := createReadOnlySealedMemfd(framed)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	source, err := acceptInheritedSourceDescriptor(fd)
	if err != nil || source == nil || source.state.material == nil {
		t.Fatalf("acceptInheritedSourceDescriptor() = %#v, %v", source, err)
	}
	material := source.state.material
	borrowed := [][]byte{material.connector, material.plan, material.target, material.egress}
	for index := range material.roots {
		borrowed = append(borrowed, material.roots[index].contents)
	}
	snapshot, err := source.BuildSnapshot(context.Background())
	if err != nil || snapshot == nil || !snapshot.Ready() {
		t.Fatalf("BuildSnapshot() = %#v, %v", snapshot, err)
	}
	actual := snapshot.Summary()
	if actual.SchemaVersion != expected.ExpectedSnapshot.SchemaVersion ||
		actual.PlanManifestDigest != expected.ExpectedSnapshot.PlanManifestDigest ||
		actual.ConnectorRegistryDigest != expected.ExpectedSnapshot.ConnectorRegistryDigest ||
		actual.TargetRegistryDigest != expected.ExpectedSnapshot.TargetRegistryDigest ||
		actual.EgressRegistryDigest != expected.ExpectedSnapshot.EgressRegistryDigest ||
		actual.ExecutorProfileDigest != expected.ExpectedSnapshot.ExecutorProfileDigest ||
		actual.BundleDigest != expected.ExpectedSnapshot.BundleDigest {
		t.Fatalf("Snapshot Summary = %#v, want exact bootstrap expected_snapshot", actual)
	}
	if source.Summary() != (PublicSourceSummary{}) || source.state.material != nil ||
		material.connector != nil || material.plan != nil || material.target != nil || material.egress != nil ||
		material.roots != nil {
		t.Fatal("BuildSnapshot retained captured manifest material")
	}
	for index, contents := range borrowed {
		if !allZero(contents) {
			t.Fatalf("captured material %d was not cleared", index)
		}
	}
	if second, secondErr := source.BuildSnapshot(context.Background()); second != nil ||
		!errors.Is(secondErr, ErrBootstrapRejected) {
		t.Fatalf("second BuildSnapshot() = %#v, %v", second, secondErr)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func allZero(contents []byte) bool {
	for _, value := range contents {
		if value != 0 {
			return false
		}
	}
	return true
}

func TestInheritedSourceBuildSnapshotRejectsExpectedDriftAndClosesSource(t *testing.T) {
	envelope := decodeWireEnvelopeForTest(t, productionInheritedFrame(t))
	var document publicDocument
	if securemanifest.DecodeStrict(envelope.Artifacts[0].Contents, &document) != nil {
		t.Fatal("decode bootstrap document")
	}
	document.ExpectedSnapshot.BundleDigest = strings.Repeat("f", 64)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Artifacts[0].Contents = encoded
	envelope.Artifacts[0].SHA256 = sha256Hex(encoded)
	file, err := createReadOnlySealedMemfd(marshalWireEnvelopeForTest(t, envelope))
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	source, err := acceptInheritedSourceDescriptor(fd)
	if err != nil {
		t.Fatal(err)
	}
	material := source.state.material
	borrowed := capturedMaterialBuffers(material)
	if snapshot, buildErr := source.BuildSnapshot(context.Background()); snapshot != nil ||
		!errors.Is(buildErr, ErrBootstrapRejected) {
		t.Fatalf("BuildSnapshot(drift) = %#v, %v", snapshot, buildErr)
	}
	if source.state.file != nil || source.state.state != inheritedSourceClosed || source.state.material != nil {
		t.Fatal("failed BuildSnapshot did not close and consume source")
	}
	if material.expected != (readassembly.Summary{}) {
		t.Fatal("failed BuildSnapshot retained expected_snapshot")
	}
	for index, contents := range borrowed {
		if !allZero(contents) {
			t.Fatalf("failed BuildSnapshot did not clear material %d", index)
		}
	}
	if err := source.Close(); err != nil {
		t.Fatalf("Close(consumed) error = %v", err)
	}
}

func TestInheritedSourceBuildSnapshotRacePublishesAtMostOneSnapshot(t *testing.T) {
	framed := productionInheritedFrame(t)
	for iteration := range 100 {
		file, err := createReadOnlySealedMemfd(framed)
		if err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Dup(int(file.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		_ = file.Close()
		source, err := acceptInheritedSourceDescriptor(fd)
		if err != nil {
			t.Fatal(err)
		}
		results := make(chan bool, 2)
		errorsSeen := make(chan error, 2)
		var wait sync.WaitGroup
		wait.Add(2)
		for range 2 {
			go func() {
				defer wait.Done()
				snapshot, buildErr := source.BuildSnapshot(context.Background())
				results <- snapshot != nil && snapshot.Ready()
				errorsSeen <- buildErr
			}()
		}
		wait.Wait()
		close(results)
		close(errorsSeen)
		ready := 0
		for result := range results {
			if result {
				ready++
			}
		}
		rejected := 0
		for buildErr := range errorsSeen {
			if errors.Is(buildErr, ErrBootstrapRejected) {
				rejected++
			} else if buildErr != nil {
				t.Fatalf("iteration %d unexpected BuildSnapshot error = %v", iteration, buildErr)
			}
		}
		if ready != 1 || rejected != 1 {
			t.Fatalf("iteration %d ready/rejected = %d/%d, want 1/1", iteration, ready, rejected)
		}
		if err := source.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInheritedSourceBuildSnapshotHostileContextClearsAndConsumes(t *testing.T) {
	file, err := createReadOnlySealedMemfd(productionInheritedFrame(t))
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	source, err := acceptInheritedSourceDescriptor(fd)
	if err != nil {
		t.Fatal(err)
	}
	material := source.state.material
	borrowed := capturedMaterialBuffers(material)
	if snapshot, buildErr := source.BuildSnapshot(panickingInheritedContext{}); snapshot != nil ||
		!errors.Is(buildErr, ErrBootstrapRejected) {
		t.Fatalf("BuildSnapshot(hostile context) = %#v, %v", snapshot, buildErr)
	}
	for index, contents := range borrowed {
		if !allZero(contents) {
			t.Fatalf("hostile context did not clear material %d", index)
		}
	}
	if material.expected != (readassembly.Summary{}) || source.state.state != inheritedSourceClosed {
		t.Fatal("hostile context retained semantic source state")
	}
}

type panickingInheritedContext struct{}

func (panickingInheritedContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (panickingInheritedContext) Done() <-chan struct{}       { return nil }
func (panickingInheritedContext) Err() error                  { panic("hostile context") }
func (panickingInheritedContext) Value(any) any               { return nil }

func capturedMaterialBuffers(material *inheritedSnapshotMaterial) [][]byte {
	if material == nil {
		return nil
	}
	borrowed := [][]byte{material.connector, material.plan, material.target, material.egress}
	for index := range material.roots {
		borrowed = append(borrowed, material.roots[index].contents)
	}
	return borrowed
}

func TestInheritedSourceBuildSnapshotCancellationIsOneShot(t *testing.T) {
	framed := productionInheritedFrame(t)
	file, err := createReadOnlySealedMemfd(framed)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	source, err := acceptInheritedSourceDescriptor(fd)
	if err != nil {
		t.Fatal(err)
	}
	material := source.state.material
	borrowed := capturedMaterialBuffers(material)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if snapshot, buildErr := source.BuildSnapshot(ctx); snapshot != nil || !errors.Is(buildErr, context.Canceled) {
		t.Fatalf("BuildSnapshot(cancelled) = %#v, %v", snapshot, buildErr)
	}
	if retry, retryErr := source.BuildSnapshot(context.Background()); retry != nil ||
		!errors.Is(retryErr, ErrBootstrapRejected) {
		t.Fatalf("BuildSnapshot(retry) = %#v, %v", retry, retryErr)
	}
	for index, contents := range borrowed {
		if !allZero(contents) {
			t.Fatalf("cancelled BuildSnapshot did not clear material %d", index)
		}
	}
	if material.expected != (readassembly.Summary{}) || source.state.state != inheritedSourceClosed {
		t.Fatal("cancelled BuildSnapshot retained semantic source state")
	}
}

func TestInheritedSourceBuildSnapshotAndCloseRaceHasOneOwner(t *testing.T) {
	framed := productionInheritedFrame(t)
	for iteration := range 100 {
		file, err := createReadOnlySealedMemfd(framed)
		if err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Dup(int(file.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		_ = file.Close()
		source, err := acceptInheritedSourceDescriptor(fd)
		if err != nil {
			t.Fatal(err)
		}
		var wait sync.WaitGroup
		wait.Add(2)
		var snapshotReady bool
		var buildErr, closeErr error
		go func() {
			defer wait.Done()
			snapshot, err := source.BuildSnapshot(context.Background())
			buildErr = err
			snapshotReady = snapshot != nil && snapshot.Ready()
		}()
		go func() {
			defer wait.Done()
			closeErr = source.Close()
		}()
		wait.Wait()
		if snapshotReady {
			if buildErr != nil {
				t.Fatalf("iteration %d ready Snapshot error = %v", iteration, buildErr)
			}
		} else if !errors.Is(buildErr, ErrBootstrapRejected) {
			t.Fatalf("iteration %d BuildSnapshot error = %v", iteration, buildErr)
		}
		if closeErr != nil && !errors.Is(closeErr, ErrBootstrapRejected) {
			t.Fatalf("iteration %d Close error = %v", iteration, closeErr)
		}
		if err := source.Close(); err != nil {
			t.Fatalf("iteration %d final Close error = %v", iteration, err)
		}
		if source.state.file != nil || source.state.material != nil || source.state.state != inheritedSourceClosed {
			t.Fatalf("iteration %d retained source ownership", iteration)
		}
	}
}

func TestInheritedSourceFrameRejectsWireSubstitution(t *testing.T) {
	valid := productionInheritedFrame(t)
	if summary, err := validateInheritedSourceFrame(valid); err != nil || summary.EnvelopeSize != int64(len(valid)) {
		t.Fatalf("validateInheritedSourceFrame(valid) = %#v, %v", summary, err)
	}
	envelope := decodeWireEnvelopeForTest(t, valid)
	roleConflict := cloneWireEnvelope(t, envelope)
	roleConflict.Artifacts[1].Role = "plan_manifest"
	digestConflict := cloneWireEnvelope(t, envelope)
	digestConflict.Artifacts[1].Contents[0] ^= 0xff
	closureConflict := cloneWireEnvelope(t, envelope)
	closureConflict.Artifacts[3].Contents = bytes.Replace(
		closureConflict.Artifacts[3].Contents,
		[]byte(closureConflict.Artifacts[10].SHA256),
		[]byte(strings.Repeat("f", 64)),
		1,
	)
	synchronizeBootstrapArtifactDigests(t, &closureConflict)
	certificateRoleConflict := cloneWireEnvelope(t, envelope)
	certificateRoleConflict.Artifacts[9].Contents = bytes.Clone(certificateRoleConflict.Artifacts[8].Contents)
	synchronizeBootstrapArtifactDigests(t, &certificateRoleConflict)
	sourceBudgetConflict := cloneWireEnvelope(t, envelope)
	for index := 1; index <= 4; index++ {
		sourceBudgetConflict.Artifacts[index].Contents = bytes.Repeat([]byte{'m'}, maximumManifestBytes)
	}
	for index := 5; index <= 9; index++ {
		sourceBudgetConflict.Artifacts[index].Contents = bytes.Repeat([]byte{'c'}, maximumCertificateBytes)
	}
	synchronizeBootstrapArtifactDigests(t, &sourceBudgetConflict)
	unknownPayload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	unknownPayload = bytes.Replace(unknownPayload, []byte(`{"schema_version":`), []byte(`{"extra":true,"schema_version":`), 1)
	nonCanonicalPayload, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string][]byte{
		"truncated":                 valid[:len(valid)-1],
		"tail tamper":               append(bytes.Clone(valid[:len(valid)-1]), valid[len(valid)-1]^0xff),
		"role conflict":             marshalWireEnvelopeForTest(t, roleConflict),
		"digest conflict":           marshalWireEnvelopeForTest(t, digestConflict),
		"target closure conflict":   marshalWireEnvelopeForTest(t, closureConflict),
		"certificate role conflict": marshalWireEnvelopeForTest(t, certificateRoleConflict),
		"source budget conflict":    marshalWireEnvelopeForTest(t, sourceBudgetConflict),
		"unknown field":             framePayloadForTest(t, unknownPayload),
		"non-canonical payload":     framePayloadForTest(t, nonCanonicalPayload),
	}
	for name, framed := range tests {
		t.Run(name, func(t *testing.T) {
			if summary, err := validateInheritedSourceFrame(framed); summary != (PublicSourceSummary{}) ||
				!errors.Is(err, ErrBootstrapRejected) {
				t.Fatalf("validateInheritedSourceFrame() = %#v, %v; want rejection", summary, err)
			}
		})
	}
}

func synchronizeBootstrapArtifactDigests(t *testing.T, envelope *publicWireEnvelope) {
	t.Helper()
	if envelope == nil || len(envelope.Artifacts) < 10 {
		t.Fatal("short test envelope")
	}
	var document publicDocument
	if securemanifest.DecodeStrict(envelope.Artifacts[0].Contents, &document) != nil {
		t.Fatal("decode bootstrap document")
	}
	document.Artifacts.ConnectorManifestSHA256 = sha256Hex(envelope.Artifacts[1].Contents)
	document.Artifacts.PlanManifestSHA256 = sha256Hex(envelope.Artifacts[2].Contents)
	document.Artifacts.TargetManifestSHA256 = sha256Hex(envelope.Artifacts[3].Contents)
	document.Artifacts.EgressManifestSHA256 = sha256Hex(envelope.Artifacts[4].Contents)
	document.Artifacts.PostgresRootCASHA256 = sha256Hex(envelope.Artifacts[5].Contents)
	document.Artifacts.PostgresClientCertificateSHA256 = sha256Hex(envelope.Artifacts[6].Contents)
	document.Artifacts.TemporalRootCASHA256 = sha256Hex(envelope.Artifacts[7].Contents)
	document.Artifacts.TemporalStarterCertificateSHA256 = sha256Hex(envelope.Artifacts[8].Contents)
	document.Artifacts.TemporalControlCertificateSHA256 = sha256Hex(envelope.Artifacts[9].Contents)
	for index := 1; index <= 9; index++ {
		envelope.Artifacts[index].SHA256 = sha256Hex(envelope.Artifacts[index].Contents)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Artifacts[0].Contents = encoded
	envelope.Artifacts[0].SHA256 = sha256Hex(encoded)
}

func productionInheritedFrame(t *testing.T) []byte {
	t.Helper()
	framed, _ := productionInheritedFrameWithFixture(t)
	return framed
}

func productionInheritedFrameWithFixture(t *testing.T) ([]byte, *linuxBootstrapFixture) {
	t.Helper()
	fixture := newLinuxBootstrapFixture(t)
	capability, err := fixture.open()
	if err != nil {
		t.Fatal(err)
	}
	framed := readCapabilityContents(t, capability)
	if err := capability.Close(); err != nil {
		t.Fatal(err)
	}
	envelope := decodeWireEnvelopeForTest(t, framed)
	target := &envelope.Artifacts[3]
	target.Contents = bytes.ReplaceAll(target.Contents, []byte(fixture.rootPath), []byte(productionBootstrapRoot))
	target.SHA256 = sha256Hex(target.Contents)
	var document publicDocument
	if securemanifest.DecodeStrict(envelope.Artifacts[0].Contents, &document) != nil {
		t.Fatal("decode fixture bootstrap")
	}
	document.Artifacts.TargetManifestSHA256 = target.SHA256
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Artifacts[0].Contents = encoded
	envelope.Artifacts[0].SHA256 = sha256Hex(encoded)
	return marshalWireEnvelopeForTest(t, envelope), fixture
}

func decodeWireEnvelopeForTest(t *testing.T, framed []byte) publicWireEnvelope {
	t.Helper()
	payloadStart := len(envelopeMagicText) + 8
	if len(framed) < payloadStart+sha256.Size {
		t.Fatal("short test envelope")
	}
	payloadLength := int(binary.BigEndian.Uint64(framed[len(envelopeMagicText):payloadStart]))
	payloadEnd := payloadStart + payloadLength
	if payloadEnd+sha256.Size != len(framed) {
		t.Fatal("invalid test envelope length")
	}
	var envelope publicWireEnvelope
	if securemanifest.DecodeStrict(framed[payloadStart:payloadEnd], &envelope) != nil {
		t.Fatal("decode test envelope")
	}
	return envelope
}

func cloneWireEnvelope(t *testing.T, envelope publicWireEnvelope) publicWireEnvelope {
	t.Helper()
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var cloned publicWireEnvelope
	if securemanifest.DecodeStrict(encoded, &cloned) != nil {
		t.Fatal("clone test envelope")
	}
	return cloned
}

func marshalWireEnvelopeForTest(t *testing.T, envelope publicWireEnvelope) []byte {
	t.Helper()
	framed, _, err := marshalPublicEnvelope(envelope.Artifacts)
	if err != nil {
		t.Fatal(err)
	}
	return framed
}

func framePayloadForTest(t *testing.T, payload []byte) []byte {
	t.Helper()
	framed := make([]byte, 0, len(envelopeMagicText)+8+len(payload)+sha256.Size)
	framed = append(framed, envelopeMagicText...)
	length := make([]byte, 8)
	binary.BigEndian.PutUint64(length, uint64(len(payload)))
	framed = append(framed, length...)
	framed = append(framed, payload...)
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(envelopeDomainText))
	_, _ = hasher.Write(framed)
	framed = append(framed, hasher.Sum(nil)...)
	return framed
}

func testMemfd(t *testing.T, contents []byte, seals int, readOnly bool) int {
	t.Helper()
	fd, err := unix.MemfdCreate("aiops-inherited-test", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	if unix.Fchmod(fd, 0o400) != nil || writeDescriptorAll(fd, contents) != nil {
		_ = unix.Close(fd)
		t.Fatal("prepare test memfd")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	if !readOnly {
		return fd
	}
	readOnlyFD, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	_ = unix.Close(fd)
	return readOnlyFD
}
