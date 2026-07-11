// Package processsecurity applies irreversible process-local protections
// before a WRITE Runner or executor can receive credential material.
package processsecurity

import "errors"

var (
	ErrUnsupportedPlatform = errors.New("secure process runtime requires Linux")
	ErrHardeningFailed     = errors.New("secure process runtime hardening failed")
)
