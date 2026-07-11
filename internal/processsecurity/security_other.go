//go:build !linux

package processsecurity

func Harden() error { return ErrUnsupportedPlatform }
