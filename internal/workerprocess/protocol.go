package workerprocess

import (
	"errors"
	"os"
	"sync"
)

const (
	controlWorkerChildArgument = "--aiops-internal-control-worker-child-v1"
	controlWorkerStatusFD      = uintptr(3)
	controlWorkerReadyByte     = byte('R')
	controlWorkerFatalByte     = byte('F')
	controlWorkerFatalExitCode = 70
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

// AcceptControlWorkerChild validates and takes ownership of the anonymous
// supervisor status descriptor. It fails closed outside the Linux boundary.
func AcceptControlWorkerChild(args []string) (*ChildStatus, error) {
	if !IsControlWorkerChild(args) {
		return nil, errInvalidChildInvocation
	}
	return acceptControlWorkerChild()
}

// ChildStatus is the write-only status capability inherited from the parent.
// It never carries application data or error text.
type ChildStatus struct {
	mu    sync.Mutex
	file  *os.File
	state childStatusState
	seal  *childStatusMarker
	self  *ChildStatus
}

type childStatusMarker struct{ value byte }

var sealedChildStatusMarker = &childStatusMarker{value: 1}

type childStatusState uint8

const (
	childStatusOpen childStatusState = iota
	childStatusReady
	childStatusClosed
)

func newChildStatus(file *os.File) *ChildStatus {
	created := &ChildStatus{
		file:  file,
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
	if status.state != childStatusOpen || status.file == nil {
		return errStatusAlreadyReported
	}
	if err := writeStatusByte(status.file, controlWorkerReadyByte); err != nil {
		status.state = childStatusClosed
		_ = status.file.Close()
		status.file = nil
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
		return nil
	}
	status.state = childStatusClosed
	if status.file == nil {
		return errInvalidStatusChannel
	}
	err := status.file.Close()
	status.file = nil
	if err != nil {
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
