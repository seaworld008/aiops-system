//go:build linux

package isolatedexec

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func validatePlatform(executablePath string, allowCurrentOwner bool) error {
	if executablePath == "" || len(executablePath) > 4096 || !filepath.IsAbs(executablePath) ||
		filepath.Clean(executablePath) != executablePath || strings.TrimSpace(executablePath) != executablePath {
		return ErrInvalidConfiguration
	}
	for _, character := range executablePath {
		if character < 0x20 || character == 0x7f {
			return ErrInvalidConfiguration
		}
	}
	info, err := os.Lstat(executablePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || executableHasUnsafeMetadata(executablePath) {
		return ErrInvalidConfiguration
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || (stat.Uid != 0 && (!allowCurrentOwner || stat.Uid != uint32(os.Geteuid()))) {
		return ErrInvalidConfiguration
	}
	parentInfo, err := os.Lstat(filepath.Dir(executablePath))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o022 != 0 {
		return ErrInvalidConfiguration
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || (parentStat.Uid != 0 && (!allowCurrentOwner || parentStat.Uid != uint32(os.Geteuid()))) {
		return ErrInvalidConfiguration
	}
	for _, required := range []string{"/proc/self/status", "/proc/self/fd"} {
		if _, err := os.Stat(required); err != nil {
			return ErrUnsupportedPlatform
		}
	}
	if _, err := processGroupHasMembersExceptLeader(os.Getpid()); err != nil {
		return ErrUnsupportedPlatform
	}
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return ErrUnsupportedPlatform
	}
	defer unix.Close(pidfd)
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		return ErrUnsupportedPlatform
	}
	return nil
}

func executableHasUnsafeMetadata(path string) bool {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return true
	}
	defer unix.Close(descriptor)
	size, err := unix.Flistxattr(descriptor, nil)
	if err != nil || size < 0 || size > 1<<20 {
		return true
	}
	if size == 0 {
		return false
	}
	names := make([]byte, size)
	read, err := unix.Flistxattr(descriptor, names)
	if err != nil || read != size {
		return true
	}
	for len(names) > 0 {
		end := bytes.IndexByte(names, 0)
		if end <= 0 || !allowedExecutorExtendedAttribute(string(names[:end])) {
			return true
		}
		names = names[end+1:]
	}
	return false
}

func allowedExecutorExtendedAttribute(name string) bool {
	return name == "security.selinux" || name == "security.ima" || name == "security.evm"
}

func configureProcess(command *exec.Cmd) {
	if command == nil {
		return
	}
	pidfd := -1
	command.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
		PidFD:     &pidfd,
	}
}

func stableProcessHandle(command *exec.Cmd) int {
	if command == nil || command.SysProcAttr == nil || command.SysProcAttr.PidFD == nil {
		return -1
	}
	return *command.SysProcAttr.PidFD
}

func waitStableProcessExit(handle int) error {
	if handle < 0 {
		return ErrTerminationUnconfirmed
	}
	descriptors := []unix.PollFd{{Fd: int32(handle), Events: unix.POLLIN}}
	for {
		count, err := unix.Poll(descriptors, -1)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil || count != 1 || descriptors[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0 ||
			descriptors[0].Revents&(unix.POLLNVAL|unix.POLLERR) != 0 {
			return ErrTerminationUnconfirmed
		}
		return nil
	}
}

func closeStableProcessHandle(handle int) error {
	if handle < 0 {
		return ErrTerminationUnconfirmed
	}
	return unix.Close(handle)
}

func signalProcessGroup(pid int, signal syscall.Signal) error {
	if pid <= 1 {
		return ErrInvalidRequest
	}
	err := syscall.Kill(-pid, signal)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func processGroupGone(pid int) (bool, error) {
	if pid <= 1 {
		return false, ErrInvalidRequest
	}
	err := syscall.Kill(-pid, 0)
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, syscall.ESRCH):
		return true, nil
	default:
		return false, err
	}
}

func processGroupHasMembersExceptLeader(pid int) (bool, error) {
	if pid <= 1 {
		return false, ErrInvalidRequest
	}
	entries, err := os.ReadDir("/proc")
	if err != nil || len(entries) > 1<<20 {
		return false, ErrTerminationUnconfirmed
	}
	for _, entry := range entries {
		candidate, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || candidate <= 1 || candidate == pid {
			continue
		}
		contents, readErr := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil || len(contents) == 0 || len(contents) > 4096 {
			return false, ErrTerminationUnconfirmed
		}
		closing := bytes.LastIndexByte(contents, ')')
		if closing < 1 || closing+2 >= len(contents) || contents[closing+1] != ' ' {
			return false, ErrTerminationUnconfirmed
		}
		fields := bytes.Fields(contents[closing+2:])
		if len(fields) < 3 {
			return false, ErrTerminationUnconfirmed
		}
		group, groupErr := strconv.Atoi(string(fields[2]))
		if groupErr != nil {
			return false, ErrTerminationUnconfirmed
		}
		if group == pid {
			return true, nil
		}
	}
	return false, nil
}
