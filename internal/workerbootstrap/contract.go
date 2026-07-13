// Package workerbootstrap snapshots the fixed, process-owned public control
// worker source into an immutable Linux capability, then binds bounded secrets
// from fixed one-shot pipes after the semantic Snapshot gate. It exposes no
// paths or raw secret bytes outside the sealed child capability.
package workerbootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

const PublicSourceSchemaVersion = "control-worker-public-source.v1"

var ErrBootstrapRejected = errors.New("control worker bootstrap rejected")

// PublicSourceSummary contains only source-content identities. It does not
// attest that the captured manifests form a valid readassembly Snapshot.
type PublicSourceSummary struct {
	SchemaVersion  string
	ManifestSHA256 string
	EnvelopeSHA256 string
	EnvelopeSize   int64
}

type publicCapabilityMarker struct{ value byte }

var sealedPublicCapabilityMarker = &publicCapabilityMarker{value: 1}

type publicCapabilityState struct {
	mu       sync.Mutex
	file     *os.File
	summary  PublicSourceSummary
	closed   bool
	transfer bool
}

// PublicSourceCapability privately owns one read-only, fully sealed memfd. It
// proves source and transport integrity only; a future child consumer must
// construct and compare the declared Snapshot before Dial or READY.
type PublicSourceCapability struct {
	state *publicCapabilityState
	seal  *publicCapabilityMarker
	self  *PublicSourceCapability
}

func newPublicSourceCapability(file *os.File, summary PublicSourceSummary) *PublicSourceCapability {
	created := &PublicSourceCapability{
		state: &publicCapabilityState{file: file, summary: summary},
		seal:  sealedPublicCapabilityMarker,
	}
	created.self = created
	return created
}

func (capability *PublicSourceCapability) structurallyValid() bool {
	return capability != nil && capability.self == capability &&
		capability.seal == sealedPublicCapabilityMarker && capability.state != nil
}

// Summary returns a detached, secret-free identity while the capability is
// live. Invalid copies and closed capabilities return the zero value.
func (capability *PublicSourceCapability) Summary() PublicSourceSummary {
	if !capability.structurallyValid() {
		return PublicSourceSummary{}
	}
	capability.state.mu.Lock()
	defer capability.state.mu.Unlock()
	if capability.state.closed || capability.state.transfer || capability.state.file == nil {
		return PublicSourceSummary{}
	}
	return capability.state.summary
}

// Close permanently destroys this process's ownership of the capability. It
// is idempotent for the original value and rejects copied values.
func (capability *PublicSourceCapability) Close() error {
	if !capability.structurallyValid() {
		return ErrBootstrapRejected
	}
	capability.state.mu.Lock()
	defer capability.state.mu.Unlock()
	if capability.state.transfer {
		return ErrBootstrapRejected
	}
	if capability.state.closed {
		return nil
	}
	capability.state.closed = true
	file := capability.state.file
	capability.state.file = nil
	capability.state.summary = PublicSourceSummary{}
	if file == nil || file.Close() != nil {
		return ErrBootstrapRejected
	}
	return nil
}

func (capability *PublicSourceCapability) startChild(start func(*os.File) error) error {
	if !capability.structurallyValid() || start == nil {
		return ErrBootstrapRejected
	}
	capability.state.mu.Lock()
	if capability.state.closed || capability.state.transfer || capability.state.file == nil {
		capability.state.mu.Unlock()
		return ErrBootstrapRejected
	}
	capability.state.transfer = true
	file := capability.state.file
	capability.state.mu.Unlock()

	startErr := invokeChildStart(start, file)
	closeErr := file.Close()
	capability.state.mu.Lock()
	capability.state.file = nil
	capability.state.summary = PublicSourceSummary{}
	capability.state.closed = true
	capability.state.transfer = false
	capability.state.mu.Unlock()
	if startErr != nil || closeErr != nil {
		return ErrBootstrapRejected
	}
	return nil
}

func invokeChildStart(start func(*os.File) error, file *os.File) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = ErrBootstrapRejected
		}
	}()
	if start == nil || file == nil || start(file) != nil {
		return ErrBootstrapRejected
	}
	return nil
}

func (PublicSourceCapability) String() string   { return "ControlWorkerPublicSource{[REDACTED]}" }
func (PublicSourceCapability) GoString() string { return "ControlWorkerPublicSource{[REDACTED]}" }
func (PublicSourceCapability) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "ControlWorkerPublicSource{[REDACTED]}")
}

func (PublicSourceCapability) MarshalJSON() ([]byte, error) {
	return nil, ErrBootstrapRejected
}

func (*PublicSourceCapability) UnmarshalJSON([]byte) error {
	return ErrBootstrapRejected
}

var _ fmt.Stringer = PublicSourceCapability{}
var _ fmt.GoStringer = PublicSourceCapability{}
var _ fmt.Formatter = PublicSourceCapability{}
var _ json.Marshaler = PublicSourceCapability{}
var _ json.Unmarshaler = (*PublicSourceCapability)(nil)
