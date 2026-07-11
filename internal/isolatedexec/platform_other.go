//go:build !linux

package isolatedexec

func validatePlatform(string) error {
	return ErrUnsupportedPlatform
}
