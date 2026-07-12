//go:build linux

package workerbootstrap

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPublicSourceCapabilityStartsOnlyFixedControlWorker(t *testing.T) {
	capability, owned := testPublicSourceCapability(t)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	pidFD := -1
	command := fixedControlWorkerCommandForTest(&pidFD)
	if err := capability.StartChild(command, writer); err != nil {
		t.Fatalf("StartChild() error = %v", err)
	}
	if len(command.ExtraFiles) != 0 {
		t.Fatal("StartChild retained source descriptor")
	}
	_ = command.Process.Kill()
	_ = command.Wait()
	if pidFD >= 0 {
		_ = unix.Close(pidFD)
	}
	if _, err := owned.Stat(); err == nil {
		t.Fatal("StartChild left parent source descriptor open")
	}
}

func TestPublicSourceCapabilityRejectsCommandBoundaryDriftWithoutConsumption(t *testing.T) {
	for name, mutate := range map[string]func(*exec.Cmd){
		"path":          func(command *exec.Cmd) { command.Path = "/tmp/not-control-worker" },
		"argument":      func(command *exec.Cmd) { command.Args[1] = "--other" },
		"environment":   func(command *exec.Cmd) { command.Env = []string{"A=B"} },
		"directory":     func(command *exec.Cmd) { command.Dir = "/tmp" },
		"stdin":         func(command *exec.Cmd) { command.Stdin = bytes.NewReader(nil) },
		"output":        func(command *exec.Cmd) { command.Stderr = &bytes.Buffer{} },
		"wait delay":    func(command *exec.Cmd) { command.WaitDelay++ },
		"process group": func(command *exec.Cmd) { command.SysProcAttr.Setpgid = false },
		"death signal":  func(command *exec.Cmd) { command.SysProcAttr.Pdeathsig = 0 },
		"missing pidfd": func(command *exec.Cmd) { command.SysProcAttr.PidFD = nil },
	} {
		t.Run(name, func(t *testing.T) {
			capability, owned := testPublicSourceCapability(t)
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			pidFD := -1
			command := fixedControlWorkerCommandForTest(&pidFD)
			mutate(command)
			if err := capability.StartChild(command, writer); !errors.Is(err, ErrBootstrapRejected) {
				t.Fatalf("StartChild() error = %v", err)
			}
			if _, err := owned.Stat(); err != nil {
				t.Fatalf("rejected command consumed source: %v", err)
			}
			if err := capability.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func fixedControlWorkerCommandForTest(pidFD *int) *exec.Cmd {
	command := exec.Command(fixedControlWorkerExecutable, fixedControlWorkerArgument)
	command.Args = []string{fixedControlWorkerExecutable, fixedControlWorkerArgument}
	command.Env = []string{}
	command.Dir = "/"
	sink := &bytes.Buffer{}
	command.Stdout = sink
	command.Stderr = sink
	command.WaitDelay = fixedControlWorkerWaitDelay
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL, PidFD: pidFD}
	return command
}

func testPublicSourceCapability(t *testing.T) (*PublicSourceCapability, *os.File) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "handoff-source")
	if err != nil {
		t.Fatal(err)
	}
	return newPublicSourceCapability(file, PublicSourceSummary{
		SchemaVersion: PublicSourceSchemaVersion, ManifestSHA256: strings.Repeat("a", 64),
		EnvelopeSHA256: strings.Repeat("b", 64), EnvelopeSize: 1,
	}), file
}
