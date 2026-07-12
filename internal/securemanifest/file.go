// Package securemanifest loads small, immutable, process-owned manifest files
// without exposing their path or contents through its error contract.
package securemanifest

import (
	"errors"
	"path/filepath"
	"strings"
)

const (
	maximumFileSize = 1 << 20
	maximumPathSize = 4096
)

var (
	ErrPath = errors.New("secure manifest path rejected")
	ErrFile = errors.New("secure manifest file rejected")
	ErrJSON = errors.New("secure manifest JSON rejected")
)

// Load reads a stable snapshot and lends it to consume for the duration of the
// callback. The byte slice is cleared before Load returns, including when the
// callback returns an error or panics. Callers must detach accepted values.
func Load(path string, consume func([]byte) error) error {
	if !validPath(path) {
		return ErrPath
	}
	if consume == nil {
		return ErrFile
	}
	contents, err := readStableFile(path)
	if err != nil {
		clear(contents)
		return ErrFile
	}
	defer clear(contents)
	return consume(contents)
}

func validPath(path string) bool {
	if path == "" || len(path) > maximumPathSize || !filepath.IsAbs(path) ||
		filepath.Clean(path) != path || strings.TrimSpace(path) != path {
		return false
	}
	for _, character := range path {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
