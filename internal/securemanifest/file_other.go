//go:build !darwin && !linux

package securemanifest

import "os"

func readStableFile(string) ([]byte, error) {
	return nil, ErrFile
}

func FileHasAccessExpandingMetadata(*os.File) bool { return true }
