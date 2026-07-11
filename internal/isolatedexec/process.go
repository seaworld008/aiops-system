package isolatedexec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const processPipeDrainTimeout = 500 * time.Millisecond

func (supervisor *Supervisor) buildCommand(
	jobDirectory string,
	extraFiles []*os.File,
	budget *outputBudget,
) *exec.Cmd {
	if supervisor == nil {
		return nil
	}
	command := exec.Command(supervisor.executablePath)
	command.Args = []string{supervisor.executablePath}
	command.Env = []string{
		"HOME=" + jobDirectory,
		"LANG=C",
		"LC_ALL=C",
		"TMPDIR=" + jobDirectory,
	}
	command.Dir = jobDirectory
	command.Stdin = nil
	command.Stdout = budget
	command.Stderr = budget
	command.ExtraFiles = append([]*os.File(nil), extraFiles...)
	command.WaitDelay = processPipeDrainTimeout
	configureProcess(command)
	return command
}

func createJobDirectory(root string) (string, error) {
	if root == "" || len(root) > 4096 || !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		strings.TrimSpace(root) != root {
		return "", ErrInvalidConfiguration
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", ErrInvalidConfiguration
	}
	directory, err := os.MkdirTemp(root, "aiops-executor-")
	if err != nil {
		return "", ErrInvalidConfiguration
	}
	fail := func() (string, error) {
		_ = os.RemoveAll(directory)
		return "", ErrInvalidConfiguration
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fail()
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		return fail()
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fail()
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		return fail()
	}
	return directory, nil
}
