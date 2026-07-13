//go:build !linux

package workerprocess

import (
	"context"
	"os"
	"time"
)

func openProductionControlWorkerSource(context.Context, time.Duration) (controlWorkerSource, error) {
	return nil, errUnsupported
}

func productionControlWorkerSecretSupplier(
	context.Context,
	time.Duration,
	*os.File,
	*os.File,
	*os.File,
) error {
	return errUnsupported
}

func acceptControlWorkerChild() (*ChildStatus, error) {
	return nil, errUnsupported
}

func runControlWorkerSourceLoaderChild() error { return errUnsupported }

func runControlWorkerSecretLoaderChild() error { return errUnsupported }

func runControlWorkerSupervisor(context.Context, supervisorSettings) error {
	return errUnsupported
}
