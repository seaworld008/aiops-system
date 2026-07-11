package isolatedexec

import (
	"os"
	"reflect"
	"testing"
	"time"
)

func TestBuildCommandPinsPathArgumentsEnvironmentDirectoryAndDescriptors(t *testing.T) {
	files := make([]*os.File, 3)
	for index := range files {
		file, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatalf("open fd fixture %d: %v", index, err)
		}
		defer file.Close()
		files[index] = file
	}
	budget := newOutputBudget(64 << 10)
	supervisor := &Supervisor{executablePath: "/fixed/aiops-executor", settings: defaultSettings()}
	command := supervisor.buildCommand("/empty/job-dir", files, budget)

	if command.Path != "/fixed/aiops-executor" || !reflect.DeepEqual(command.Args, []string{"/fixed/aiops-executor"}) {
		t.Fatalf("command path/args = %q/%#v", command.Path, command.Args)
	}
	wantEnvironment := []string{
		"HOME=/empty/job-dir",
		"LANG=C",
		"LC_ALL=C",
		"TMPDIR=/empty/job-dir",
	}
	if !reflect.DeepEqual(command.Env, wantEnvironment) {
		t.Fatalf("command environment = %#v, want %#v", command.Env, wantEnvironment)
	}
	if command.Dir != "/empty/job-dir" || command.Stdin != nil {
		t.Fatalf("command dir/stdin = %q/%#v", command.Dir, command.Stdin)
	}
	if !reflect.DeepEqual(command.ExtraFiles, files) {
		t.Fatalf("command ExtraFiles = %#v", command.ExtraFiles)
	}
	if command.Stdout != budget || command.Stderr != budget {
		t.Fatal("stdout and stderr do not share the discard budget")
	}
	if command.WaitDelay != 500*time.Millisecond {
		t.Fatalf("command WaitDelay = %s, want 500ms", command.WaitDelay)
	}
}

func TestCreateJobDirectoryIsOwnedEmptyAndPrivate(t *testing.T) {
	directory, err := createJobDirectory(t.TempDir())
	if err != nil {
		t.Fatalf("createJobDirectory() error = %v", err)
	}
	defer os.RemoveAll(directory)
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatalf("stat job directory: %v", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("job directory mode = %s", info.Mode())
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("job directory entries = %#v, %v", entries, err)
	}
}
