//go:build !linux

package workerprocess

import (
	"context"
	"time"
)

func openProductionControlWorkerSource(context.Context, time.Duration) (controlWorkerSource, error) {
	return nil, errUnsupported
}

func acceptControlWorkerChild() (*ChildStatus, error) {
	return nil, errUnsupported
}

func runControlWorkerSourceLoaderChild() error { return errUnsupported }

func runControlWorkerSupervisor(context.Context, supervisorSettings) error {
	return errUnsupported
}
