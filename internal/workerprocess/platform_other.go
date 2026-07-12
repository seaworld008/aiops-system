//go:build !linux

package workerprocess

import "context"

func acceptControlWorkerChild() (*ChildStatus, error) {
	return nil, errUnsupported
}

func runControlWorkerSupervisor(context.Context, supervisorSettings) error {
	return errUnsupported
}
