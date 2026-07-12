//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProductionWorkerBinaryFailsBeforeReadyWithoutLeakingParentEnvironment(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "aiops-worker")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cmd/worker: %v\n%s", err, output)
	}

	const canary = "AIOPS_WORKER_PARENT_ENV_CANARY=must-not-cross-child-boundary"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary)
	command.Env = append(os.Environ(), canary)
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("worker exit = %v, output = %q", err, output)
	}
	if ctx.Err() != nil {
		t.Fatalf("worker did not fail closed within deadline: %v", ctx.Err())
	}
	rendered := string(output)
	if strings.Contains(rendered, canary) || strings.Contains(rendered, "must-not-cross-child-boundary") {
		t.Fatalf("worker output leaked parent environment: %q", rendered)
	}
	if strings.Contains(rendered, "ready-for-temporal-configuration") {
		t.Fatalf("worker falsely reported readiness: %q", rendered)
	}
}
