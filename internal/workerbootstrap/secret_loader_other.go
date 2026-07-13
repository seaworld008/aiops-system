//go:build !linux

package workerbootstrap

// WriteProductionSecretsToLoaderFDs fails closed outside the reviewed Linux
// process and filesystem boundary.
func WriteProductionSecretsToLoaderFDs() error { return ErrBootstrapRejected }
