package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

var errInvalidInvocation = errors.New("invalid READ runner invocation")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		slog.Error("READ runner stopped", "error", err)
		os.Exit(2)
	}
}

func run(ctx context.Context, args []string) error {
	if ctx == nil || len(args) != 0 {
		return errInvalidInvocation
	}
	// M4 deliberately has no write or executor dependency in this binary. M5
	// will register only environment-scoped read activities here.
	<-ctx.Done()
	return nil
}
