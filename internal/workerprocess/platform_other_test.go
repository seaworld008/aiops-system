//go:build !linux

package workerprocess

import (
	"context"
	"testing"
)

func TestNonLinuxSupervisorFailsClosed(t *testing.T) {
	t.Parallel()
	if err := NewControlWorkerSupervisor().Run(context.Background()); err != errUnsupported {
		t.Fatalf("Run() error = %v, want %v", err, errUnsupported)
	}
	if status, err := AcceptControlWorkerChild([]string{controlWorkerChildArgument}); status != nil || err != errUnsupported {
		t.Fatalf("AcceptControlWorkerChild() = (%v, %v), want (nil, %v)", status, err, errUnsupported)
	}
}
