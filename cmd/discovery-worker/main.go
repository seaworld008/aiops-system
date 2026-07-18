package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"reflect"
	"syscall"
	"time"
)

var (
	errInvalidInvocation     = errors.New("discovery worker invocation rejected")
	errProductionUnavailable = errors.New("discovery worker production unavailable")
)

type discoveryWorkerRuntime interface {
	Run(context.Context) error
	Stop(context.Context) error
	Close() error
}

type productionFactory func(Config) (discoveryWorkerRuntime, error)

func main() {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer cancel()
	if err := runWithProduction(
		ctx,
		os.Args[1:],
		os.Environ(),
		func(config Config) (discoveryWorkerRuntime, error) {
			return newProduction(config)
		},
	); err != nil {
		_, _ = os.Stderr.WriteString("discovery worker unavailable\n")
		os.Exit(1)
	}
}

func runWithProduction(
	ctx context.Context,
	arguments, environment []string,
	factory productionFactory,
) error {
	if ctx == nil || factory == nil {
		return errInvalidInvocation
	}
	config, err := loadConfig(arguments, environment)
	if err != nil {
		return errInvalidInvocation
	}
	runtime, err := factory(config)
	if err != nil {
		if !nilRuntime(runtime) {
			_ = runtime.Close()
		}
		return errProductionUnavailable
	}
	if nilRuntime(runtime) {
		return errProductionUnavailable
	}

	runErr := runtime.Run(ctx)
	stopContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	stopErr := runtime.Stop(stopContext)
	cancel()
	closeErr := runtime.Close()
	if stopErr != nil || closeErr != nil {
		return errProductionUnavailable
	}
	if runErr == nil {
		if ctx.Err() == nil {
			return errProductionUnavailable
		}
		return nil
	}
	if ctx.Err() != nil && errors.Is(runErr, ctx.Err()) {
		return nil
	}
	return errProductionUnavailable
}

func nilRuntime(runtime discoveryWorkerRuntime) bool {
	if runtime == nil {
		return true
	}
	value := reflect.ValueOf(runtime)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
