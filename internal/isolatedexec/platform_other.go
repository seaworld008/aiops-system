//go:build !linux

package isolatedexec

import (
	"os"
	"os/exec"
	"syscall"
)

func validatePlatform(string, bool) error {
	return ErrUnsupportedPlatform
}

func openRuntimeBoundary(string) (*os.File, uint64, error) {
	return nil, 0, ErrUnsupportedPlatform
}

func createRuntimeJobDirectory(string, *os.File, uint64) (string, error) {
	return "", ErrUnsupportedPlatform
}

func validateRuntimeJobDirectory(string, *os.File, uint64, string) bool { return false }

func removeRuntimeJobDirectory(*os.File, string) error { return ErrUnsupportedPlatform }

func configureProcess(*exec.Cmd) {}

func stableProcessHandle(*exec.Cmd) int { return -1 }

func waitStableProcessExit(int) error { return ErrUnsupportedPlatform }

func closeStableProcessHandle(int) error { return ErrUnsupportedPlatform }

func signalProcessGroup(int, syscall.Signal) error {
	return ErrUnsupportedPlatform
}

func processGroupGone(int) (bool, error) {
	return false, ErrUnsupportedPlatform
}

func processGroupHasMembersExceptLeader(int) (bool, error) {
	return false, ErrUnsupportedPlatform
}

func reapAdoptedProcessGroupZombies(int, int) error { return ErrUnsupportedPlatform }
