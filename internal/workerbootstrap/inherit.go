package workerbootstrap

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/seaworld008/aiops-system/internal/readassembly"
)

type inheritedSourceMarker struct{ value byte }

var sealedInheritedSourceMarker = &inheritedSourceMarker{value: 1}

type inheritedSourceState struct {
	mu       sync.Mutex
	file     *os.File
	summary  PublicSourceSummary
	material *inheritedSnapshotMaterial
	runtime  *inheritedRuntimeMaterial
	state    inheritedSourceLifecycle
}

type inheritedSourceLifecycle uint8

const (
	inheritedSourceLive inheritedSourceLifecycle = iota
	inheritedSourceBuilding
	inheritedSourceBuilt
	inheritedSourceBindingSecrets
	inheritedSourceSecretsBound
	inheritedSourceClosed
)

type inheritedSnapshotRoot struct {
	path     string
	contents []byte
}

type inheritedSnapshotMaterial struct {
	connector []byte
	plan      []byte
	target    []byte
	egress    []byte
	roots     []inheritedSnapshotRoot
	expected  readassembly.Summary
}

type inheritedRuntimeMaterial struct {
	readers      [3]*os.File
	expectedSPKI [3][]byte
	postgres     publicPostgresDocument
	temporal     publicTemporalDocument
	postgresRoot []byte
	postgresCert []byte
	temporalRoot []byte
	starterCert  []byte
	controlCert  []byte
	bundle       *inheritedSecretBundle
}

type inheritedSecretBundle struct {
	postgres        *decodedSecretFrame
	temporalStarter *decodedSecretFrame
	temporalControl *decodedSecretFrame
}

// InheritedSource owns a child-validated FD4 public source. It exposes no
// artifact bytes; only its one-shot BuildSnapshot can publish the semantic
// proof after the complete reviewed Summary matches.
type InheritedSource struct {
	state *inheritedSourceState
	seal  *inheritedSourceMarker
	self  *InheritedSource
}

func newInheritedSource(file *os.File, summary PublicSourceSummary) *InheritedSource {
	return newInheritedSourceWithSnapshot(file, summary, nil)
}

func newInheritedSourceWithSnapshot(
	file *os.File,
	summary PublicSourceSummary,
	material *inheritedSnapshotMaterial,
) *InheritedSource {
	return newInheritedSourceWithRuntime(file, summary, material, nil, inheritedSourceLive)
}

func newInheritedSourceWithRuntime(
	file *os.File,
	summary PublicSourceSummary,
	material *inheritedSnapshotMaterial,
	runtime *inheritedRuntimeMaterial,
	lifecycle inheritedSourceLifecycle,
) *InheritedSource {
	created := &InheritedSource{
		state: &inheritedSourceState{
			file: file, summary: summary, material: material, runtime: runtime, state: lifecycle,
		},
		seal: sealedInheritedSourceMarker,
	}
	created.self = created
	return created
}

func (source *InheritedSource) structurallyValid() bool {
	return source != nil && source.self == source && source.seal == sealedInheritedSourceMarker && source.state != nil
}

func (source *InheritedSource) Summary() PublicSourceSummary {
	if !source.structurallyValid() {
		return PublicSourceSummary{}
	}
	source.state.mu.Lock()
	defer source.state.mu.Unlock()
	if source.state.state != inheritedSourceLive && source.state.state != inheritedSourceBuilt ||
		source.state.file == nil {
		return PublicSourceSummary{}
	}
	return source.state.summary
}

// BindControlWorkerSecrets consumes the fixed FD5-FD7 readers exactly once,
// validates their role-specific frames and certificate-key bindings, and only
// then atomically publishes an opaque bundle inside this capability.
func (source *InheritedSource) BindControlWorkerSecrets(ctx context.Context) (returnedErr error) {
	if !source.structurallyValid() || ctx == nil {
		return ErrBootstrapRejected
	}
	var runtime *inheritedRuntimeMaterial
	bindingComplete := false
	defer func() {
		panicked := recover() != nil
		if panicked {
			returnedErr = ErrBootstrapRejected
		}
		if runtime != nil && !bindingComplete {
			if err := source.finishSecretBinding(runtime, nil, nil); err != nil {
				returnedErr = ErrBootstrapRejected
			}
		} else if panicked {
			_ = source.Close()
		}
	}()
	var err error
	runtime, err = source.beginSecretBinding(ctx)
	if err != nil {
		return err
	}
	readers := runtime.readers
	commitDone := ctx.Done()
	stopCancellationClose := context.AfterFunc(ctx, func() {
		for _, reader := range readers {
			if reader != nil {
				_ = reader.Close()
			}
		}
	})
	defer stopCancellationClose()
	var decoded [3]*decodedSecretFrame
	succeeded := false
	defer func() {
		if !succeeded {
			for index := range decoded {
				decoded[index].clear()
			}
		}
	}()
	roles := [3]secretFrameRole{
		secretFramePostgres, secretFrameTemporalStarter, secretFrameTemporalControl,
	}
	for index := range runtime.readers {
		decoded[index], err = readInheritedSecretFrame(ctx, runtime.readers[index], roles[index])
		_ = runtime.readers[index].Close()
		runtime.readers[index] = nil
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(decoded[index].privateKeySPKI, runtime.expectedSPKI[index]) != 1 {
			return ErrBootstrapRejected
		}
	}
	bundle := &inheritedSecretBundle{
		postgres: decoded[0], temporalStarter: decoded[1], temporalControl: decoded[2],
	}
	if err := source.finishSecretBinding(runtime, bundle, commitDone); err != nil {
		bundle.clear()
		if errors.Is(err, context.Canceled) {
			bindingComplete = true
			if contextErr := ctx.Err(); contextErr != nil {
				return contextErr
			}
			return context.Canceled
		}
		return ErrBootstrapRejected
	}
	bindingComplete = true
	succeeded = true
	return nil
}

func (source *InheritedSource) beginSecretBinding(ctx context.Context) (*inheritedRuntimeMaterial, error) {
	if err := ctx.Err(); err != nil {
		source.closeBeforeSecretBinding()
		return nil, err
	}
	source.state.mu.Lock()
	defer source.state.mu.Unlock()
	runtime := source.state.runtime
	if source.state.state != inheritedSourceBuilt || source.state.file == nil || runtime == nil ||
		runtime.bundle != nil || runtime.readers[0] == nil || runtime.readers[1] == nil || runtime.readers[2] == nil {
		return nil, ErrBootstrapRejected
	}
	source.state.state = inheritedSourceBindingSecrets
	return runtime, nil
}

func (source *InheritedSource) closeBeforeSecretBinding() {
	source.state.mu.Lock()
	defer source.state.mu.Unlock()
	if source.state.state != inheritedSourceBuilt {
		return
	}
	source.state.state = inheritedSourceClosed
	if source.state.file != nil {
		_ = source.state.file.Close()
		source.state.file = nil
	}
	source.state.runtime.clear()
	source.state.runtime = nil
}

func (source *InheritedSource) finishSecretBinding(
	runtime *inheritedRuntimeMaterial,
	bundle *inheritedSecretBundle,
	commitDone <-chan struct{},
) error {
	source.state.mu.Lock()
	defer source.state.mu.Unlock()
	if source.state.state != inheritedSourceBindingSecrets || source.state.runtime != runtime ||
		runtime == nil || runtime.bundle != nil {
		return ErrBootstrapRejected
	}
	commitCanceled := false
	if bundle != nil && commitDone != nil {
		select {
		case <-commitDone:
			commitCanceled = true
		default:
		}
	}
	if bundle != nil && !commitCanceled {
		for index := range runtime.expectedSPKI {
			clear(runtime.expectedSPKI[index])
			runtime.expectedSPKI[index] = nil
		}
		runtime.bundle = bundle
		source.state.state = inheritedSourceSecretsBound
		return nil
	}
	source.state.state = inheritedSourceClosed
	file := source.state.file
	source.state.file = nil
	runtime.clear()
	source.state.runtime = nil
	if file == nil || file.Close() != nil {
		return ErrBootstrapRejected
	}
	if commitCanceled {
		return context.Canceled
	}
	return nil
}

func readInheritedSecretFrame(
	ctx context.Context,
	reader *os.File,
	role secretFrameRole,
) (*decodedSecretFrame, error) {
	if ctx == nil || reader == nil || !role.valid() {
		return nil, ErrBootstrapRejected
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	contents, err := io.ReadAll(io.LimitReader(reader, int64(maximumSecretFrameBytes)+1))
	defer clear(contents)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil || len(contents) == 0 || len(contents) > maximumSecretFrameBytes {
		return nil, ErrBootstrapRejected
	}
	return decodeSecretFrame(role, contents)
}

// BuildSnapshot consumes the semantic material captured during the exact FD4
// validation. It accepts no path, descriptor, bytes, expected digest, or
// resolver from its caller. A failed build permanently closes the source; a
// successful build retains only the public source descriptor for the next
// fixed assembly gate.
func (source *InheritedSource) BuildSnapshot(
	ctx context.Context,
) (snapshot *readassembly.Snapshot, returnedErr error) {
	if !source.structurallyValid() {
		return nil, ErrBootstrapRejected
	}
	material, err := source.beginSnapshotBuild()
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	succeeded := false
	defer func() {
		material.clear()
		if recover() != nil {
			snapshot = nil
			returnedErr = ErrBootstrapRejected
		}
		if returnedErr != nil || snapshot == nil || !snapshot.Ready() {
			snapshot = nil
			if returnedErr == nil {
				returnedErr = ErrBootstrapRejected
			}
		} else {
			succeeded = true
		}
		if source.finishSnapshotBuild(succeeded) != nil {
			snapshot = nil
			returnedErr = ErrBootstrapRejected
		}
	}()
	roots := make([]readassembly.CapturedRootBundle, len(material.roots))
	for index := range material.roots {
		roots[index] = readassembly.CapturedRootBundle{
			Path: material.roots[index].path, Contents: material.roots[index].contents,
		}
	}
	snapshot, returnedErr = readassembly.LoadCanonicalManifests(
		ctx, material.connector, material.plan, material.target, material.egress, roots, material.expected,
	)
	if returnedErr != nil {
		if returnedErr == context.Canceled || returnedErr == context.DeadlineExceeded {
			return nil, returnedErr
		}
		return nil, ErrBootstrapRejected
	}
	return snapshot, nil
}

func (source *InheritedSource) beginSnapshotBuild() (*inheritedSnapshotMaterial, error) {
	source.state.mu.Lock()
	defer source.state.mu.Unlock()
	if source.state.state != inheritedSourceLive || source.state.file == nil || source.state.material == nil {
		return nil, ErrBootstrapRejected
	}
	material := source.state.material
	source.state.material = nil
	source.state.summary = PublicSourceSummary{}
	source.state.state = inheritedSourceBuilding
	return material, nil
}

func (source *InheritedSource) finishSnapshotBuild(succeeded bool) error {
	source.state.mu.Lock()
	defer source.state.mu.Unlock()
	if source.state.state != inheritedSourceBuilding || source.state.material != nil {
		return ErrBootstrapRejected
	}
	if succeeded {
		source.state.state = inheritedSourceBuilt
		return nil
	}
	source.state.state = inheritedSourceClosed
	file := source.state.file
	source.state.file = nil
	source.state.runtime.clear()
	source.state.runtime = nil
	if file == nil || file.Close() != nil {
		return ErrBootstrapRejected
	}
	return nil
}

func (material *inheritedSnapshotMaterial) clear() {
	if material == nil {
		return
	}
	clear(material.connector)
	clear(material.plan)
	clear(material.target)
	clear(material.egress)
	for index := range material.roots {
		clear(material.roots[index].contents)
		material.roots[index].path = ""
		material.roots[index].contents = nil
	}
	material.connector = nil
	material.plan = nil
	material.target = nil
	material.egress = nil
	material.roots = nil
	material.expected = readassembly.Summary{}
}

func (material *inheritedRuntimeMaterial) clear() {
	if material == nil {
		return
	}
	for index := range material.readers {
		if material.readers[index] != nil {
			_ = material.readers[index].Close()
			material.readers[index] = nil
		}
		clear(material.expectedSPKI[index])
		material.expectedSPKI[index] = nil
	}
	clear(material.postgresRoot)
	clear(material.postgresCert)
	clear(material.temporalRoot)
	clear(material.starterCert)
	clear(material.controlCert)
	material.postgresRoot = nil
	material.postgresCert = nil
	material.temporalRoot = nil
	material.starterCert = nil
	material.controlCert = nil
	material.postgres = publicPostgresDocument{}
	material.temporal = publicTemporalDocument{}
	material.bundle.clear()
	material.bundle = nil
}

func (bundle *inheritedSecretBundle) clear() {
	if bundle == nil {
		return
	}
	bundle.postgres.clear()
	bundle.temporalStarter.clear()
	bundle.temporalControl.clear()
	bundle.postgres = nil
	bundle.temporalStarter = nil
	bundle.temporalControl = nil
}

func (source *InheritedSource) Close() error {
	if !source.structurallyValid() {
		return ErrBootstrapRejected
	}
	source.state.mu.Lock()
	defer source.state.mu.Unlock()
	if source.state.state == inheritedSourceClosed {
		return nil
	}
	if source.state.state == inheritedSourceBuilding || source.state.state == inheritedSourceBindingSecrets {
		return ErrBootstrapRejected
	}
	source.state.state = inheritedSourceClosed
	file := source.state.file
	source.state.file = nil
	source.state.summary = PublicSourceSummary{}
	material := source.state.material
	source.state.material = nil
	material.clear()
	runtime := source.state.runtime
	source.state.runtime = nil
	runtime.clear()
	if file == nil || file.Close() != nil {
		return ErrBootstrapRejected
	}
	return nil
}

func (InheritedSource) String() string   { return "ControlWorkerInheritedSource{[REDACTED]}" }
func (InheritedSource) GoString() string { return "ControlWorkerInheritedSource{[REDACTED]}" }
func (InheritedSource) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "ControlWorkerInheritedSource{[REDACTED]}")
}

func (InheritedSource) MarshalJSON() ([]byte, error) { return nil, ErrBootstrapRejected }
func (*InheritedSource) UnmarshalJSON([]byte) error  { return ErrBootstrapRejected }

var _ fmt.Stringer = InheritedSource{}
var _ fmt.GoStringer = InheritedSource{}
var _ fmt.Formatter = InheritedSource{}
var _ json.Marshaler = InheritedSource{}
var _ json.Unmarshaler = (*InheritedSource)(nil)

func cloneSnapshotString(value string) string { return strings.Clone(value) }
