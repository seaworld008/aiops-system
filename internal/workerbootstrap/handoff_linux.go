//go:build linux

package workerbootstrap

import (
	"os"
	"os/exec"
	"reflect"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	fixedControlWorkerExecutable = "/proc/self/exe"
	fixedControlWorkerArgument   = "--aiops-internal-control-worker-child-v1"
	fixedControlWorkerWaitDelay  = 500 * time.Millisecond
)

// StartChild validates the complete fixed control-worker command, installs
// the status pipe as FD3, the live sealed source as FD4, and the three empty
// read-only secret pipes as FD5-FD7. The source descriptor is never returned
// to the caller and ExtraFiles is cleared before this method returns.
func (capability *PublicSourceCapability) StartChild(
	command *exec.Cmd,
	status *os.File,
	postgresSecret *os.File,
	temporalStarterSecret *os.File,
	temporalControlSecret *os.File,
) error {
	secretReaders := []*os.File{postgresSecret, temporalStarterSecret, temporalControlSecret}
	if !validFixedControlWorkerCommand(command) || !validStatusWriter(status) ||
		!validSecretReaders(secretReaders) {
		return ErrBootstrapRejected
	}
	return capability.startChild(func(file *os.File) error {
		all := []*os.File{status, file, postgresSecret, temporalStarterSecret, temporalControlSecret}
		if !distinctDescriptorIdentities(all) {
			return ErrBootstrapRejected
		}
		command.ExtraFiles = all
		defer func() { command.ExtraFiles = nil }()
		return command.Start()
	})
}

func validFixedControlWorkerCommand(command *exec.Cmd) bool {
	if command == nil || command.Path != fixedControlWorkerExecutable ||
		len(command.Args) != 2 || command.Args[0] != fixedControlWorkerExecutable ||
		command.Args[1] != fixedControlWorkerArgument || command.Env == nil || len(command.Env) != 0 ||
		command.Dir != "/" || command.Stdin != nil || command.Stdout == nil || command.Stderr == nil ||
		!sameWriter(command.Stdout, command.Stderr) || len(command.ExtraFiles) != 0 ||
		command.WaitDelay != fixedControlWorkerWaitDelay || command.Cancel != nil || command.Process != nil ||
		command.ProcessState != nil || command.Err != nil || command.SysProcAttr == nil ||
		command.SysProcAttr.PidFD == nil || *command.SysProcAttr.PidFD != -1 {
		return false
	}
	want := &syscall.SysProcAttr{
		Setpgid: true, Pdeathsig: syscall.SIGKILL, PidFD: command.SysProcAttr.PidFD,
	}
	return reflect.DeepEqual(command.SysProcAttr, want)
}

func sameWriter(left, right any) bool {
	leftValue, rightValue := reflect.ValueOf(left), reflect.ValueOf(right)
	return leftValue.IsValid() && rightValue.IsValid() && leftValue.Type() == rightValue.Type() &&
		leftValue.Kind() == reflect.Pointer && leftValue.Pointer() == rightValue.Pointer()
}

func validStatusWriter(status *os.File) bool {
	if status == nil {
		return false
	}
	fd := status.Fd()
	var stat unix.Stat_t
	flags, flagsErr := unix.FcntlInt(fd, unix.F_GETFL, 0)
	descriptorFlags, descriptorErr := unix.FcntlInt(fd, unix.F_GETFD, 0)
	return unix.Fstat(int(fd), &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFIFO &&
		flagsErr == nil && flags&unix.O_ACCMODE == unix.O_WRONLY && descriptorErr == nil &&
		descriptorFlags&unix.FD_CLOEXEC != 0
}

func validSecretReaders(readers []*os.File) bool {
	if len(readers) != 3 || !distinctDescriptorIdentities(readers) {
		return false
	}
	for _, reader := range readers {
		if !validFIFODescriptor(reader, unix.O_RDONLY) {
			return false
		}
	}
	return true
}

func validFIFODescriptor(file *os.File, accessMode int) bool {
	if file == nil {
		return false
	}
	fd := file.Fd()
	var stat unix.Stat_t
	flags, flagsErr := unix.FcntlInt(fd, unix.F_GETFL, 0)
	descriptorFlags, descriptorErr := unix.FcntlInt(fd, unix.F_GETFD, 0)
	return unix.Fstat(int(fd), &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFIFO &&
		flagsErr == nil && flags&unix.O_ACCMODE == accessMode && descriptorErr == nil &&
		descriptorFlags&unix.FD_CLOEXEC != 0
}

func distinctDescriptorIdentities(files []*os.File) bool {
	if len(files) == 0 {
		return false
	}
	seen := make(map[[2]uint64]struct{}, len(files))
	for _, file := range files {
		if file == nil {
			return false
		}
		var stat unix.Stat_t
		if unix.Fstat(int(file.Fd()), &stat) != nil {
			return false
		}
		identity := [2]uint64{uint64(stat.Dev), stat.Ino}
		if _, duplicate := seen[identity]; duplicate {
			return false
		}
		seen[identity] = struct{}{}
	}
	return true
}
