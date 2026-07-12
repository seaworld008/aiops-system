package workerprocess

import (
	"errors"
	"io"
	"os"
	"sync"
)

const (
	controlWorkerChildArgument  = "--aiops-internal-control-worker-child-v1"
	controlWorkerLoaderArgument = "--aiops-internal-control-worker-source-loader-v1"
	controlWorkerStatusFD       = uintptr(3)
	controlWorkerSourceFD       = 4
	controlWorkerReadyByte      = byte('R')
	controlWorkerFatalByte      = byte('F')
	controlWorkerFatalExitCode  = 70
)

var (
	errInvalidChildInvocation = errors.New("control worker child invocation rejected")
	errInvalidStatusChannel   = errors.New("control worker status channel rejected")
	errStatusAlreadyReported  = errors.New("control worker status already reported")
)

// IsControlWorkerChild recognizes only the private, fixed child invocation.
// Callers must pass os.Args[1:], without rewriting or filtering it.
func IsControlWorkerChild(args []string) bool {
	return len(args) == 1 && args[0] == controlWorkerChildArgument
}

// IsControlWorkerSourceLoaderChild recognizes only the private, fixed source
// loader invocation. The loader is public-source-only and never receives
// credentials.
func IsControlWorkerSourceLoaderChild(args []string) bool {
	return len(args) == 1 && args[0] == controlWorkerLoaderArgument
}

// RunControlWorkerSourceLoaderChild validates the contained loader boundary,
// snapshots the fixed production root, writes its public frame to FD3, and
// exits. It fails closed on non-Linux platforms.
func RunControlWorkerSourceLoaderChild(args []string) error {
	if !IsControlWorkerSourceLoaderChild(args) {
		return errInvalidChildInvocation
	}
	return runControlWorkerSourceLoaderChild()
}

// AcceptControlWorkerChild validates and takes ownership of the anonymous
// supervisor status descriptor and inherited public source. It fails closed
// outside the Linux boundary.
func AcceptControlWorkerChild(args []string) (*ChildStatus, error) {
	if !IsControlWorkerChild(args) {
		return nil, errInvalidChildInvocation
	}
	return acceptControlWorkerChild()
}

// ChildStatus is the write-only status capability inherited from the parent.
// It never carries application data or error text.
type ChildStatus struct {
	mu     sync.Mutex
	file   *os.File
	source io.Closer
	state  childStatusState
	seal   *childStatusMarker
	self   *ChildStatus
}

type childStatusMarker struct{ value byte }

var sealedChildStatusMarker = &childStatusMarker{value: 1}

type childStatusState uint8

const (
	childStatusOpen childStatusState = iota
	childStatusReady
	childStatusClosed
)

func newChildStatus(file *os.File, source io.Closer) *ChildStatus {
	created := &ChildStatus{
		file: file, source: source,
		state: childStatusOpen,
		seal:  sealedChildStatusMarker,
	}
	created.self = created
	return created
}

func (status *ChildStatus) structurallyValid() bool {
	return status != nil && status.self == status && status.seal == sealedChildStatusMarker
}

// ReportControlWorkerReady reports exactly one successful worker start.
func ReportControlWorkerReady(status *ChildStatus) error {
	if !status.structurallyValid() {
		return errInvalidStatusChannel
	}
	status.mu.Lock()
	defer status.mu.Unlock()
	if status.state != childStatusOpen || status.file == nil || status.source == nil {
		return errStatusAlreadyReported
	}
	if err := writeStatusByte(status.file, controlWorkerReadyByte); err != nil {
		status.state = childStatusClosed
		_ = status.file.Close()
		status.file = nil
		_ = status.source.Close()
		status.source = nil
		return errInvalidStatusChannel
	}
	status.state = childStatusReady
	return nil
}

// ExitControlWorkerFatal reports an unrecoverable worker failure and
// immediately exits.
// Deliberately do not add defers here: fatal containment must not run callbacks
// that could re-enter the Temporal SDK worker shutdown path.
func ExitControlWorkerFatal(status *ChildStatus) {
	if status.structurallyValid() {
		status.mu.Lock()
		if status.state != childStatusClosed && status.file != nil {
			_ = writeStatusByte(status.file, controlWorkerFatalByte)
			_ = status.file.Close()
			status.file = nil
			status.state = childStatusClosed
		}
		status.mu.Unlock()
	}
	os.Exit(controlWorkerFatalExitCode)
}

// CloseControlWorkerChild closes the status capability without emitting
// another frame.
func CloseControlWorkerChild(status *ChildStatus) error {
	if !status.structurallyValid() {
		return errInvalidStatusChannel
	}
	status.mu.Lock()
	defer status.mu.Unlock()
	if status.state == childStatusClosed {
		if status.source != nil {
			err := status.source.Close()
			status.source = nil
			if err != nil {
				return errInvalidStatusChannel
			}
		}
		return nil
	}
	status.state = childStatusClosed
	var statusErr error
	if status.file == nil {
		statusErr = errInvalidStatusChannel
	} else {
		statusErr = status.file.Close()
		status.file = nil
	}
	var sourceErr error
	if status.source == nil {
		sourceErr = errInvalidStatusChannel
	} else {
		sourceErr = status.source.Close()
		status.source = nil
	}
	if statusErr != nil || sourceErr != nil {
		return errInvalidStatusChannel
	}
	return nil
}

func writeStatusByte(file *os.File, value byte) error {
	if file == nil {
		return errInvalidStatusChannel
	}
	written, err := file.Write([]byte{value})
	if err != nil || written != 1 {
		return errInvalidStatusChannel
	}
	return nil
}
