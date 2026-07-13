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
	secretReaders := testSecretReaders(t)
	pidFD := -1
	command := fixedControlWorkerCommandForTest(&pidFD)
	if err := capability.StartChild(command, writer, secretReaders[0], secretReaders[1], secretReaders[2]); err != nil {
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
			secretReaders := testSecretReaders(t)
			pidFD := -1
			command := fixedControlWorkerCommandForTest(&pidFD)
			mutate(command)
			if err := capability.StartChild(
				command, writer, secretReaders[0], secretReaders[1], secretReaders[2],
			); !errors.Is(err, ErrBootstrapRejected) {
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

func TestPublicSourceCapabilityRejectsSecretPipeBoundaryDrift(t *testing.T) {
	for name, mutate := range map[string]func([]*os.File){
		"duplicate role pipe": func(readers []*os.File) { readers[1] = readers[0] },
		"missing role pipe":   func(readers []*os.File) { readers[2] = nil },
	} {
		t.Run(name, func(t *testing.T) {
			capability, _ := testPublicSourceCapability(t)
			statusReader, statusWriter, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer statusReader.Close()
			defer statusWriter.Close()
			secretReaders := testSecretReaders(t)
			mutate(secretReaders)
			pidFD := -1
			command := fixedControlWorkerCommandForTest(&pidFD)
			if err := capability.StartChild(
				command, statusWriter, secretReaders[0], secretReaders[1], secretReaders[2],
			); !errors.Is(err, ErrBootstrapRejected) {
				t.Fatalf("StartChild() error = %v, want rejection", err)
			}
			if command.Process != nil {
				t.Fatal("rejected secret boundary started child")
			}
		})
	}
}

func testSecretReaders(t *testing.T) []*os.File {
	t.Helper()
	readers := make([]*os.File, 3)
	for index := range readers {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		readers[index] = reader
		t.Cleanup(func() {
			_ = reader.Close()
			_ = writer.Close()
		})
	}
	return readers
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
