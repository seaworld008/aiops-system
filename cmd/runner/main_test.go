package main

import (
	"strings"
	"testing"
)

func TestRunRejectsWriteRunnerForEverySupportedExecutionMode(t *testing.T) {
	for _, executionMode := range []string{"", "disabled", "non-production"} {
		t.Run(executionMode, func(t *testing.T) {
			t.Setenv("AIOPS_WRITE_EXECUTION_MODE", executionMode)

			err := run([]string{"--mode=write"})
			if err == nil {
				t.Fatal("run(--mode=write) error = nil, want fail-closed rejection")
			}
			if !strings.Contains(err.Error(), "write runner is unavailable") {
				t.Fatalf("run(--mode=write) error = %q, want explicit unavailable message", err)
			}
		})
	}
}

func TestRunKeepsReadPlaceholderAvailable(t *testing.T) {
	if err := run([]string{"--mode=read"}); err != nil {
		t.Fatalf("run(--mode=read) error = %v", err)
	}
}
