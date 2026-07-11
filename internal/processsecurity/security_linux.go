//go:build linux

package processsecurity

import (
	"errors"
	"syscall"
)

const (
	prGetDumpable   = 3
	prSetDumpable   = 4
	prSetNoNewPrivs = 38
	prGetNoNewPrivs = 39
)

// Harden disables core dumps, same-UID ptrace/proc-mem access, and future
// privilege gains. Every setting is read back; a partial hardening attempt is
// treated as a terminal startup failure.
func Harden() error {
	limit := syscall.Rlimit{Cur: 0, Max: 0}
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &limit); err != nil {
		return ErrHardeningFailed
	}
	var observed syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &observed); err != nil || observed.Cur != 0 || observed.Max != 0 {
		return ErrHardeningFailed
	}
	if err := prctlSet(prSetDumpable, 0); err != nil {
		return ErrHardeningFailed
	}
	dumpable, err := prctlGet(prGetDumpable)
	if err != nil || dumpable != 0 {
		return ErrHardeningFailed
	}
	if err := prctlSet(prSetNoNewPrivs, 1); err != nil {
		return ErrHardeningFailed
	}
	noNewPrivileges, err := prctlGet(prGetNoNewPrivs)
	if err != nil || noNewPrivileges != 1 {
		return ErrHardeningFailed
	}
	return nil
}

func prctlSet(option, value uintptr) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, option, value, 0, 0, 0, 0)
	if errno != 0 {
		return errors.New("prctl failed")
	}
	return nil
}

func prctlGet(option uintptr) (uintptr, error) {
	value, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, option, 0, 0, 0, 0, 0)
	if errno != 0 {
		return 0, errors.New("prctl failed")
	}
	return value, nil
}
