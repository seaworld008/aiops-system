package config_test

import (
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/config"
)

func TestLoadUsesSafeDefaults(t *testing.T) {
	t.Setenv("AIOPS_HTTP_ADDR", "")
	t.Setenv("AIOPS_SHUTDOWN_TIMEOUT", "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.HTTPAddr != ":8080" {
		t.Fatalf("HTTPAddr = %q, want :8080", cfg.HTTPAddr)
	}
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Fatalf("ShutdownTimeout = %s, want 10s", cfg.ShutdownTimeout)
	}
	if cfg.Environment != "development" {
		t.Fatalf("Environment = %q, want development", cfg.Environment)
	}
}

func TestLoadRejectsInvalidShutdownTimeout(t *testing.T) {
	t.Setenv("AIOPS_SHUTDOWN_TIMEOUT", "not-a-duration")

	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
}
