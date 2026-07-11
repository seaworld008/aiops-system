//go:build linux

package isolatedexec

import (
	"os"
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
