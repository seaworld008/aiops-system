package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
)

type recordingControlWorkerSupervisor struct {
	calls atomic.Int64
	err   error
}

func (supervisor *recordingControlWorkerSupervisor) Run(context.Context) error {
	supervisor.calls.Add(1)
	return supervisor.err
}

func TestRunRejectsArgumentsAndInvalidFactories(t *testing.T) {
	if err := runWithSupervisor(nil, nil, nil); !errors.Is(err, errInvalidInvocation) {
		t.Fatalf("runWithSupervisor(nil context) error = %v", err)
	}
	for _, args := range [][]string{{"--mode=write"}, {"sh"}, {"--help"}, {"child"}} {
		if err := runWithSupervisor(context.Background(), args, func() controlWorkerSupervisor {
			return &recordingControlWorkerSupervisor{}
		}); !errors.Is(err, errInvalidInvocation) {
			t.Fatalf("runWithSupervisor(%q) error = %v", args, err)
		}
	}
	if err := runWithSupervisor(context.Background(), nil, nil); !errors.Is(err, errInvalidInvocation) {
		t.Fatalf("runWithSupervisor(nil factory) error = %v", err)
	}
	if err := runWithSupervisor(context.Background(), nil, func() controlWorkerSupervisor { return nil }); !errors.Is(err, errInvalidInvocation) {
		t.Fatalf("runWithSupervisor(nil supervisor) error = %v", err)
	}
}

func TestRunDoesNotSpawnAfterCancellationAndDelegatesOnce(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	var factoryCalls atomic.Int64
	if err := runWithSupervisor(cancelled, nil, func() controlWorkerSupervisor {
		factoryCalls.Add(1)
		return &recordingControlWorkerSupervisor{}
	}); err != nil {
		t.Fatalf("runWithSupervisor(cancelled) error = %v", err)
	}
	if factoryCalls.Load() != 0 {
		t.Fatalf("cancelled invocation constructed %d supervisors", factoryCalls.Load())
	}

	want := errors.New("fixed supervisor failure")
	supervisor := &recordingControlWorkerSupervisor{err: want}
	if err := runWithSupervisor(context.Background(), nil, func() controlWorkerSupervisor {
		factoryCalls.Add(1)
		return supervisor
	}); !errors.Is(err, want) {
		t.Fatalf("runWithSupervisor() error = %v, want %v", err, want)
	}
	if factoryCalls.Load() != 1 || supervisor.calls.Load() != 1 {
		t.Fatalf("factory calls = %d, Run calls = %d", factoryCalls.Load(), supervisor.calls.Load())
	}
}

func TestControlWorkerChildFailsClosedBeforeLiveAssembly(t *testing.T) {
	if err := runControlWorkerChild(context.Background(), nil); !errors.Is(err, errControlWorkerAssemblyUnavailable) {
		t.Fatalf("runControlWorkerChild() error = %v", err)
	}
}

func TestWorkerDependencyGraphExcludesMutationRuntime(t *testing.T) {
	command := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", ".")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("go list worker dependencies: %v", err)
	}
	dependencies := strings.Fields(string(output))
	for _, forbidden := range []string{
		"/internal/action",
		"/internal/execution",
		"/internal/credential",
		"/internal/isolatedexec",
		"/internal/executoripc",
		"/internal/connectors/kubernetes",
		"/internal/connectors/awx",
	} {
		for _, dependency := range dependencies {
			if strings.HasSuffix(dependency, forbidden) || strings.Contains(dependency, forbidden+"/") {
				t.Fatalf("control Worker dependency graph contains forbidden package %q", dependency)
			}
		}
	}
}
