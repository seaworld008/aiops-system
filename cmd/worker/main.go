package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/seaworld008/aiops-system/internal/workerprocess"
)

var (
	errInvalidInvocation                = errors.New("invalid workflow worker invocation")
	errControlWorkerAssemblyUnavailable = errors.New("control worker assembly is unavailable")
)

type controlWorkerSupervisor interface {
	Run(context.Context) error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		// Every error crossing the workerprocess boundary is deliberately fixed
		// and low-sensitive. Child stderr and Temporal errors are never joined.
		slog.Error("workflow worker stopped", "error", err)
		os.Exit(2)
	}
}

func run(ctx context.Context, args []string) error {
	return runWithSupervisor(ctx, args, func() controlWorkerSupervisor {
		return workerprocess.NewControlWorkerSupervisor()
	})
}

func runWithSupervisor(
	ctx context.Context,
	args []string,
	newSupervisor func() controlWorkerSupervisor,
) error {
	if ctx == nil {
		return errInvalidInvocation
	}
	if workerprocess.IsControlWorkerChild(args) {
		status, err := workerprocess.AcceptControlWorkerChild(args)
		if err != nil {
			return err
		}
		return runControlWorkerChild(ctx, status)
	}
	if len(args) != 0 || newSupervisor == nil {
		return errInvalidInvocation
	}
	if ctx.Err() != nil {
		return nil
	}
	supervisor := newSupervisor()
	if supervisor == nil {
		return errInvalidInvocation
	}
	return supervisor.Run(ctx)
}

func runControlWorkerChild(_ context.Context, status *workerprocess.ChildStatus) error {
	if status != nil {
		_ = workerprocess.CloseControlWorkerChild(status)
	}
	// C2-4c2a installs only the containment boundary. Until the separately
	// reviewed Snapshot/Temporal/PostgreSQL assembly lands, the child must exit
	// without READY and the parent must report startup failure. READ claims and
	// the Outbox dispatcher therefore remain closed.
	return errControlWorkerAssemblyUnavailable
}
