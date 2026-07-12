//go:build linux

package workerbootstrap

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestReceiveProductionSourceRebuildsSealedCapability(t *testing.T) {
	framed := productionInheritedFrame(t)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() {
		writeErr := writeFileAll(writer, framed)
		closeErr := writer.Close()
		if writeErr != nil {
			written <- writeErr
			return
		}
		written <- closeErr
	}()
	capability, err := ReceiveProductionSource(reader)
	if err != nil || capability == nil || capability.Summary().EnvelopeSize != int64(len(framed)) {
		t.Fatalf("ReceiveProductionSource() = %#v, %v", capability, err)
	}
	if err := <-written; err != nil {
		t.Fatalf("loader writer error = %v", err)
	}
	if err := capability.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestReceiveProductionSourceRejectsInvalidPipeAndFrame(t *testing.T) {
	ordinary, err := os.CreateTemp(t.TempDir(), "loader-ordinary")
	if err != nil {
		t.Fatal(err)
	}
	if capability, err := ReceiveProductionSource(ordinary); capability != nil || !errors.Is(err, ErrBootstrapRejected) {
		t.Fatalf("ordinary ReceiveProductionSource() = %#v, %v", capability, err)
	}

	valid := productionInheritedFrame(t)
	corrupt := bytes.Clone(valid)
	corrupt[len(corrupt)-1] ^= 0xff
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	written := make(chan struct{})
	go func() {
		_ = writeFileAll(writer, corrupt)
		_ = writer.Close()
		close(written)
	}()
	if capability, err := ReceiveProductionSource(reader); capability != nil || !errors.Is(err, ErrBootstrapRejected) {
		t.Fatalf("corrupt ReceiveProductionSource() = %#v, %v", capability, err)
	}
	<-written
}
