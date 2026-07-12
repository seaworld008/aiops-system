//go:build !linux

package workerbootstrap

// OpenProductionSource fails closed because sealed memfd capabilities and the
// fixed Linux directory boundary are unavailable on this platform.
func OpenProductionSource() (*PublicSourceCapability, error) {
	return nil, ErrBootstrapRejected
}
