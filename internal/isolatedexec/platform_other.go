//go:build !linux

package isolatedexec

import (
	"os/exec"
	"syscall"
)

func validatePlatform(string) error {
	return ErrUnsupportedPlatform
}

func configureProcess(*exec.Cmd) {}

func signalProcessGroup(int, syscall.Signal) error {
	return ErrUnsupportedPlatform
}

func processGroupGone(int) (bool, error) {
	return false, ErrUnsupportedPlatform
}
