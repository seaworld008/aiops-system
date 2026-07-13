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
	if workerprocess.IsControlWorkerSecretLoaderChild(args) {
		return workerprocess.RunControlWorkerSecretLoaderChild(args)
	}
	if workerprocess.IsControlWorkerSourceLoaderChild(args) {
		return workerprocess.RunControlWorkerSourceLoaderChild(args)
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

func runControlWorkerChild(ctx context.Context, status *workerprocess.ChildStatus) error {
	// C2-4c2b1b2b adds the post-Snapshot secret-loader only. The fixed runtime
	// factory remains unavailable, so production still exits before READY and
	// cannot activate READ claims or the Outbox dispatcher.
	return runControlWorkerChildRuntime(ctx, status)
}
