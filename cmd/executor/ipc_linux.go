//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

func validAnonymousPipes(files ...*os.File) bool {
	seen := make(map[string]struct{}, len(files))
	for _, file := range files {
		if file == nil {
			return false
		}
		info, err := file.Stat()
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			return false
		}
		target, err := os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(file.Fd()), 10))
		if err != nil || !strings.HasPrefix(target, "pipe:[") || !strings.HasSuffix(target, "]") {
			return false
		}
		if _, duplicate := seen[target]; duplicate {
			return false
		}
		seen[target] = struct{}{}
	}
	return len(seen) == 3
}
