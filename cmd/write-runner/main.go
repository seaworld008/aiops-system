package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/seaworld008/aiops-system/internal/isolatedexec"
	"github.com/seaworld008/aiops-system/internal/processsecurity"
)

var (
	errInvalidInvocation = errors.New("invalid WRITE runner invocation")
	errInvalidMode       = errors.New("WRITE execution mode must be disabled or non-production")
)

type capabilityProbe func() error
type processHardener func() error

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Getenv("AIOPS_WRITE_EXECUTION_MODE"), processsecurity.Harden, probeIsolation); err != nil {
		slog.Error("WRITE runner stopped", "error", err)
		os.Exit(2)
	}
}

func run(ctx context.Context, args []string, mode string, harden processHardener, probe capabilityProbe) error {
	if ctx == nil || len(args) != 0 || harden == nil || probe == nil {
		return errInvalidInvocation
	}
	switch mode {
	case "", "disabled":
		// Disabled mode never probes the executor and never claims an action.
	case "non-production":
		if err := harden(); err != nil {
			return fmt.Errorf("harden WRITE runner process: %w", err)
		}
		if err := probe(); err != nil {
			return fmt.Errorf("verify isolated executor capability: %w", err)
		}
	default:
		return errInvalidMode
	}
	// M4 provides the process boundary while the control plane intentionally
	// keeps StartAuthorizer nil. M6 wires only fixed non-production adapters.
	<-ctx.Done()
	return nil
}

func probeIsolation() error {
	_, err := isolatedexec.New()
	return err
}
