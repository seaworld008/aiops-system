package main

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestRunRejectsEveryArgument(t *testing.T) {
	if err := run(context.Background(), []string{"--mode=write"}); !errors.Is(err, errInvalidInvocation) {
		t.Fatalf("run(argument) error = %v", err)
	}
}

func TestRunHasNoWriteModeAndStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx, nil); err != nil {
		t.Fatalf("run(cancelled) error = %v", err)
	}
}

func TestReadRunnerDependencyGraphContainsNoMutationExecutor(t *testing.T) {
	command := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", ".")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("go list READ runner dependencies: %v", err)
	}
	for _, forbidden := range []string{
		"/internal/isolatedexec",
		"/internal/executoripc",
		"/internal/execution",
		"/internal/credential",
		"/internal/connectors/kubernetes",
		"/internal/connectors/awx",
	} {
		if bytes.Contains(output, []byte(forbidden+"\n")) || strings.HasSuffix(strings.TrimSpace(string(output)), forbidden) {
			t.Fatalf("READ runner dependency graph contains forbidden package suffix %q", forbidden)
		}
	}
}
