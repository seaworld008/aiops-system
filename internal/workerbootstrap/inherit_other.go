//go:build !linux

package workerbootstrap

// AcceptInheritedSource fails closed because fixed Linux FD and memfd proofs
// are unavailable on this platform.
func AcceptInheritedSource() (*InheritedSource, error) {
	return nil, ErrBootstrapRejected
}
