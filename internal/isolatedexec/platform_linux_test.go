//go:build linux

package isolatedexec

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLinuxCapabilityGateRequiresOwnedImmutableRegularSingleLinkExecutor(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "executor")
	if err := os.WriteFile(executable, []byte("fixture"), 0o500); err != nil {
		t.Fatalf("write executor fixture: %v", err)
	}
	if supervisor, err := newSupervisor(executable, defaultSettings()); err != nil || supervisor == nil {
		t.Fatalf("newSupervisor(secure executable) = %#v, %v", supervisor, err)
	}

	writable := filepath.Join(directory, "writable")
	if err := os.WriteFile(writable, []byte("fixture"), 0o720); err != nil {
		t.Fatalf("write writable fixture: %v", err)
	}
	if supervisor, err := newSupervisor(writable, defaultSettings()); supervisor != nil || !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("newSupervisor(group-writable) = %#v, %v", supervisor, err)
	}

	symlink := filepath.Join(directory, "executor-link")
	if err := os.Symlink(executable, symlink); err != nil {
		t.Fatalf("create executor symlink: %v", err)
	}
	if supervisor, err := newSupervisor(symlink, defaultSettings()); supervisor != nil || !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("newSupervisor(symlink) = %#v, %v", supervisor, err)
	}

	hardlink := filepath.Join(directory, "executor-hardlink")
	if err := os.Link(executable, hardlink); err != nil {
		t.Fatalf("create executor hard link: %v", err)
	}
	if supervisor, err := newSupervisor(executable, defaultSettings()); supervisor != nil || !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("newSupervisor(multiple links) = %#v, %v", supervisor, err)
	}
}

func TestLinuxCommandBoundaryCreatesOwnGroupAndParentDeathSignal(t *testing.T) {
	command := exec.Command("/does/not/run")
	configureProcess(command)
	if command.SysProcAttr == nil || !command.SysProcAttr.Setpgid || command.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("SysProcAttr = %#v", command.SysProcAttr)
	}
}
