package workerbootstrap

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

type inheritedSourceMarker struct{ value byte }

var sealedInheritedSourceMarker = &inheritedSourceMarker{value: 1}

type inheritedSourceState struct {
	mu      sync.Mutex
	file    *os.File
	summary PublicSourceSummary
	closed  bool
}

// InheritedSource owns a child-validated FD4 public source. It exposes no
// artifact bytes and is not a semantic Snapshot proof.
type InheritedSource struct {
	state *inheritedSourceState
	seal  *inheritedSourceMarker
	self  *InheritedSource
}

func newInheritedSource(file *os.File, summary PublicSourceSummary) *InheritedSource {
	created := &InheritedSource{
		state: &inheritedSourceState{file: file, summary: summary},
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
	if source.state.closed || source.state.file == nil {
		return PublicSourceSummary{}
	}
	return source.state.summary
}

func (source *InheritedSource) Close() error {
	if !source.structurallyValid() {
		return ErrBootstrapRejected
	}
	source.state.mu.Lock()
	defer source.state.mu.Unlock()
	if source.state.closed {
		return nil
	}
	source.state.closed = true
	file := source.state.file
	source.state.file = nil
	source.state.summary = PublicSourceSummary{}
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
