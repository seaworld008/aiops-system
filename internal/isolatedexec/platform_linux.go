//go:build linux

package isolatedexec

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func validatePlatform(executablePath string) error {
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
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return ErrInvalidConfiguration
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return ErrInvalidConfiguration
	}
	for _, required := range []string{"/proc/self/status", "/proc/self/fd"} {
		if _, err := os.Stat(required); err != nil {
			return ErrUnsupportedPlatform
		}
	}
	return nil
}

func configureProcess(command *exec.Cmd) {
	if command == nil {
		return
	}
	command.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
	}
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
