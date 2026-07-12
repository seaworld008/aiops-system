//go:build !linux

package workerbootstrap

import "os"

func WriteProductionSourceToLoaderFD() error { return ErrBootstrapRejected }

func ReceiveProductionSource(reader *os.File) (*PublicSourceCapability, error) {
	if reader != nil {
		_ = reader.Close()
	}
	return nil, ErrBootstrapRejected
}
