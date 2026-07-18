package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRunRejectsInvalidInvocationBeforeProductionAssembly(t *testing.T) {
	calls := 0
	factory := func(Config) (discoveryWorkerRuntime, error) {
		calls++
		return &mainRuntime{}, nil
	}
	if err := runWithProduction(nil, nil, validConfigEnvironment(), factory); !errors.Is(err, errInvalidInvocation) {
		t.Fatalf("runWithProduction(nil) error = %v", err)
	}
	if err := runWithProduction(
		context.Background(), []string{"--worker-id=forged"}, validConfigEnvironment(), factory,
	); !errors.Is(err, errInvalidInvocation) {
		t.Fatalf("runWithProduction(forged flag) error = %v", err)
	}
	if calls != 0 {
		t.Fatalf("production factory called %d times for rejected invocation", calls)
	}
}

func TestRunStartsStopsAndClosesOneProductionRuntime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &mainRuntime{runStarted: make(chan struct{})}
	runStarted := runtime.runStarted
	factoryCalls := 0
	factory := func(config Config) (discoveryWorkerRuntime, error) {
		factoryCalls++
		if err := config.Validate(); err != nil {
			t.Fatalf("factory received invalid config: %v", err)
		}
		return runtime, nil
	}
	done := make(chan error, 1)
	go func() {
		done <- runWithProduction(ctx, nil, validConfigEnvironment(), factory)
	}()
	select {
	case <-runStarted:
	case <-time.After(time.Second):
		t.Fatal("production runtime did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runWithProduction() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runWithProduction() did not shut down")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if factoryCalls != 1 || runtime.runCalls != 1 || runtime.stopCalls != 1 ||
		runtime.closeCalls != 1 {
		t.Fatalf(
			"calls factory/run/stop/close = %d/%d/%d/%d",
			factoryCalls, runtime.runCalls, runtime.stopCalls, runtime.closeCalls,
		)
	}
}

func TestRunFailsClosedWhenProductionAssemblyOrRuntimeFails(t *testing.T) {
	assemblyFailure := errors.New("assembly failed")
	partial := &mainRuntime{}
	if err := runWithProduction(
		context.Background(), nil, validConfigEnvironment(),
		func(Config) (discoveryWorkerRuntime, error) { return partial, assemblyFailure },
	); !errors.Is(err, errProductionUnavailable) || errors.Is(err, assemblyFailure) {
		t.Fatalf("assembly failure error = %v", err)
	}
	partial.mu.Lock()
	partialCloseCalls := partial.closeCalls
	partial.mu.Unlock()
	if partialCloseCalls != 1 {
		t.Fatalf("partial assembly close calls = %d", partialCloseCalls)
	}

	runtime := &mainRuntime{runError: errors.New("sensitive runtime failure")}
	if err := runWithProduction(
		context.Background(), nil, validConfigEnvironment(),
		func(Config) (discoveryWorkerRuntime, error) { return runtime, nil },
	); !errors.Is(err, errProductionUnavailable) || errors.Is(err, runtime.runError) {
		t.Fatalf("runtime failure error = %v", err)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.stopCalls != 1 || runtime.closeCalls != 1 {
		t.Fatalf("runtime failure stop/close calls = %d/%d", runtime.stopCalls, runtime.closeCalls)
	}
}

type mainRuntime struct {
	mu         sync.Mutex
	runStarted chan struct{}
	runError   error
	runCalls   int
	stopCalls  int
	closeCalls int
}

func (runtime *mainRuntime) Run(ctx context.Context) error {
	runtime.mu.Lock()
	runtime.runCalls++
	if runtime.runStarted != nil {
		close(runtime.runStarted)
		runtime.runStarted = nil
	}
	err := runtime.runError
	runtime.mu.Unlock()
	if err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

func (runtime *mainRuntime) Stop(context.Context) error {
	runtime.mu.Lock()
	runtime.stopCalls++
	runtime.mu.Unlock()
	return nil
}

func (runtime *mainRuntime) Close() error {
	runtime.mu.Lock()
	runtime.closeCalls++
	runtime.mu.Unlock()
	return nil
}

var _ discoveryWorkerRuntime = (*mainRuntime)(nil)
