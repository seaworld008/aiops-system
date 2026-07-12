//go:build !linux

package workerbootstrap

import (
	"errors"
	"testing"
)

func TestOpenProductionSourceFailsClosedOutsideLinux(t *testing.T) {
	capability, err := OpenProductionSource()
	if capability != nil || !errors.Is(err, ErrBootstrapRejected) {
		t.Fatalf("OpenProductionSource() = %#v, %v; want fail closed", capability, err)
	}
}
