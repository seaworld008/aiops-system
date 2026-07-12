//go:build !linux

package workerbootstrap

import (
	"errors"
	"os"
	"testing"
)

func TestOpenProductionSourceFailsClosedOutsideLinux(t *testing.T) {
	capability, err := OpenProductionSource()
	if capability != nil || !errors.Is(err, ErrBootstrapRejected) {
		t.Fatalf("OpenProductionSource() = %#v, %v; want fail closed", capability, err)
	}
}

func TestProductionSourceLoaderFailsClosedOutsideLinux(t *testing.T) {
	if err := WriteProductionSourceToLoaderFD(); !errors.Is(err, ErrBootstrapRejected) {
		t.Fatalf("WriteProductionSourceToLoaderFD() error = %v", err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	if capability, err := ReceiveProductionSource(reader); capability != nil || !errors.Is(err, ErrBootstrapRejected) {
		t.Fatalf("ReceiveProductionSource() = %#v, %v", capability, err)
	}
}
