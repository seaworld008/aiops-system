//go:build !linux

package isolatedexec

import (
	"errors"
	"testing"
)

func TestNewFailsClosedOutsideLinux(t *testing.T) {
	if supervisor, err := New(); supervisor != nil || !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("New() = %#v, %v; want unsupported-platform rejection", supervisor, err)
	}
}
