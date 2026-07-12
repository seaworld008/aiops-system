package workerbootstrap

import (
	"context"
	"encoding/json"
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
	state    inheritedSourceLifecycle
}

type inheritedSourceLifecycle uint8

const (
	inheritedSourceLive inheritedSourceLifecycle = iota
	inheritedSourceBuilding
	inheritedSourceBuilt
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
	created := &InheritedSource{
		state: &inheritedSourceState{file: file, summary: summary, material: material, state: inheritedSourceLive},
		seal:  sealedInheritedSourceMarker,
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

func (source *InheritedSource) Close() error {
	if !source.structurallyValid() {
		return ErrBootstrapRejected
	}
	source.state.mu.Lock()
	defer source.state.mu.Unlock()
	if source.state.state == inheritedSourceClosed {
		return nil
	}
	if source.state.state == inheritedSourceBuilding {
		return ErrBootstrapRejected
	}
	source.state.state = inheritedSourceClosed
	file := source.state.file
	source.state.file = nil
	source.state.summary = PublicSourceSummary{}
	material := source.state.material
	source.state.material = nil
	material.clear()
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
