//go:build linux

package workerbootstrap

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const productionSourceLoaderFD = 3

// WriteProductionSourceToLoaderFD snapshots the fixed production root inside
// the short-lived loader child and writes only the bounded public frame to its
// fixed FD3 pipe. It never writes secrets or returns the source descriptor.
func WriteProductionSourceToLoaderFD() error {
	writer, err := acceptLoaderPipe(productionSourceLoaderFD, unix.O_WRONLY)
	if err != nil {
		return ErrBootstrapRejected
	}
	defer writer.Close()
	capability, err := OpenProductionSource()
	if err != nil {
		return ErrBootstrapRejected
	}
	defer capability.Close()
	contents, err := capabilityContents(capability)
	if err != nil {
		return ErrBootstrapRejected
	}
	defer clear(contents)
	if writeFileAll(writer, contents) != nil {
		return ErrBootstrapRejected
	}
	return nil
}

// ReceiveProductionSource takes ownership of a parent-side anonymous pipe,
// receives one bounded public frame, independently validates it, and rebuilds
// a read-only fully sealed capability in the parent process.
func ReceiveProductionSource(reader *os.File) (*PublicSourceCapability, error) {
	if !validLoaderPipe(reader, unix.O_RDONLY) {
		if reader != nil {
			_ = reader.Close()
		}
		return nil, ErrBootstrapRejected
	}
	defer reader.Close()
	limited := io.LimitReader(reader, int64(maximumEnvelopeBytes)+1)
	contents, err := io.ReadAll(limited)
	if err != nil || len(contents) == 0 || len(contents) > maximumEnvelopeBytes {
		clear(contents)
		return nil, ErrBootstrapRejected
	}
	defer clear(contents)
	summary, err := validateInheritedSourceFrame(contents)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	file, err := createReadOnlySealedMemfd(contents)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	return newPublicSourceCapability(file, summary), nil
}

func acceptLoaderPipe(fd int, accessMode int) (*os.File, error) {
	if fd < 0 {
		return nil, ErrBootstrapRejected
	}
	unix.CloseOnExec(fd)
	file := os.NewFile(uintptr(fd), "control-worker-source-loader")
	if !validLoaderPipe(file, accessMode) {
		if file != nil {
			_ = file.Close()
		}
		return nil, ErrBootstrapRejected
	}
	return file, nil
}

func validLoaderPipe(file *os.File, accessMode int) bool {
	if file == nil || (accessMode != unix.O_RDONLY && accessMode != unix.O_WRONLY) {
		return false
	}
	fd := int(file.Fd())
	var stat unix.Stat_t
	flags, flagsErr := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	descriptorFlags, descriptorErr := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	return unix.Fstat(fd, &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFIFO &&
		flagsErr == nil && flags&unix.O_ACCMODE == accessMode && descriptorErr == nil &&
		descriptorFlags&unix.FD_CLOEXEC != 0
}

func capabilityContents(capability *PublicSourceCapability) ([]byte, error) {
	if !capability.structurallyValid() {
		return nil, ErrBootstrapRejected
	}
	capability.state.mu.Lock()
	defer capability.state.mu.Unlock()
	if capability.state.closed || capability.state.transfer || capability.state.file == nil ||
		capability.state.summary.EnvelopeSize <= 0 || capability.state.summary.EnvelopeSize > maximumEnvelopeBytes {
		return nil, ErrBootstrapRejected
	}
	return preadExact(int(capability.state.file.Fd()), int(capability.state.summary.EnvelopeSize))
}

func writeFileAll(writer *os.File, contents []byte) error {
	for written := 0; written < len(contents); {
		count, err := writer.Write(contents[written:])
		if err != nil || count <= 0 {
			return ErrBootstrapRejected
		}
		written += count
	}
	return nil
}
