//go:build !darwin && !linux

package securemanifest

func readStableFile(string) ([]byte, error) {
	return nil, ErrFile
}
