//go:build !linux

package workerbootstrap

import (
	"os"
	"os/exec"
)

func (*PublicSourceCapability) StartChild(*exec.Cmd, *os.File, *os.File, *os.File, *os.File) error {
	return ErrBootstrapRejected
}
