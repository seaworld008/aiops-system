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
// the status pipe as FD3 and the live sealed source as FD4, and starts exactly
// one child. The source descriptor is never returned to the caller and is
// removed from ExtraFiles before this method returns.
func (capability *PublicSourceCapability) StartChild(command *exec.Cmd, status *os.File) error {
	if !validFixedControlWorkerCommand(command) || !validStatusWriter(status) {
		return ErrBootstrapRejected
	}
	return capability.startChild(func(file *os.File) error {
		command.ExtraFiles = []*os.File{status, file}
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
