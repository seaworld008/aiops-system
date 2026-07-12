package main

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestControlChildStartsBeforeREADYAndStopsOnce(t *testing.T) {
	runtime := newFakeControlChildRuntime()
	status := newFakeControlChildStatus()
	child := newControlChild(runtime, status)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- child.Run(ctx) }()
	waitControlChildSignal(t, status.readySignal, "READY")
	if runtime.starts.Load() != 1 || runtime.stops.Load() != 0 {
		t.Fatalf("lifecycle before cancellation = %d/%d", runtime.starts.Load(), runtime.stops.Load())
	}
	cancel()
	if err := receiveControlChildResult(t, result); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if runtime.starts.Load() != 1 || runtime.stops.Load() != 1 ||
		status.ready.Load() != 1 || status.fatals.Load() != 0 {
		t.Fatalf("lifecycle/status = %d/%d, %d/%d",
			runtime.starts.Load(), runtime.stops.Load(), status.ready.Load(), status.fatals.Load())
	}
	if err := child.Run(context.Background()); !errors.Is(err, errControlWorkerChildRejected) {
		t.Fatalf("second Run() error = %v", err)
	}
}

func TestControlChildStartFailureIsLowSensitiveAndCleansOnce(t *testing.T) {
	runtime := newFakeControlChildRuntime()
	runtime.startErr = errors.New("START-SECRET-CANARY")
	status := newFakeControlChildStatus()
	err := newControlChild(runtime, status).Run(context.Background())
	if !errors.Is(err, errControlWorkerChildRejected) ||
		containsControlChildCanary(err) || runtime.starts.Load() != 1 || runtime.stops.Load() != 1 ||
		status.ready.Load() != 0 || status.fatals.Load() != 0 {
		t.Fatalf("Run(start failure) = %v; lifecycle=%d/%d status=%d/%d",
			err, runtime.starts.Load(), runtime.stops.Load(), status.ready.Load(), status.fatals.Load())
	}
}

func TestControlChildStartPanicAndREADYFailureAreLowSensitive(t *testing.T) {
	t.Run("Start panic", func(t *testing.T) {
		runtime := newFakeControlChildRuntime()
		runtime.startPanic = "START-SECRET-CANARY"
		status := newFakeControlChildStatus()
		err := newControlChild(runtime, status).Run(context.Background())
		if !errors.Is(err, errControlWorkerChildRejected) || containsControlChildCanary(err) ||
			runtime.starts.Load() != 1 || runtime.stops.Load() != 1 {
			t.Fatalf("Run(Start panic) = %v; lifecycle=%d/%d",
				err, runtime.starts.Load(), runtime.stops.Load())
		}
	})

	t.Run("READY failure", func(t *testing.T) {
		runtime := newFakeControlChildRuntime()
		status := newFakeControlChildStatus()
		status.readyErr = errors.New("READY-SECRET-CANARY")
		err := newControlChild(runtime, status).Run(context.Background())
		if !errors.Is(err, errControlWorkerChildRejected) || strings.Contains(err.Error(), "READY-SECRET-CANARY") ||
			runtime.starts.Load() != 1 || runtime.stops.Load() != 1 ||
			status.ready.Load() != 1 {
			t.Fatalf("Run(READY failure) = %v; lifecycle=%d/%d READY=%d",
				err, runtime.starts.Load(), runtime.stops.Load(), status.ready.Load())
		}
	})
}

func TestControlChildFatalBeforeAndDuringStartNeverStopsOrReadies(t *testing.T) {
	t.Run("before Start", func(t *testing.T) {
		runtime := newFakeControlChildRuntime()
		close(runtime.fatal)
		status := newFakeControlChildStatus()
		err := newControlChild(runtime, status).Run(context.Background())
		if !errors.Is(err, errControlWorkerChildFatal) || runtime.starts.Load() != 0 || runtime.stops.Load() != 0 ||
			status.ready.Load() != 0 || status.fatals.Load() != 1 {
			t.Fatalf("Run(pre-start fatal) = %v; lifecycle=%d/%d status=%d/%d",
				err, runtime.starts.Load(), runtime.stops.Load(), status.ready.Load(), status.fatals.Load())
		}
	})

	t.Run("during Start", func(t *testing.T) {
		runtime := newFakeControlChildRuntime()
		runtime.startEntered = make(chan struct{})
		runtime.startRelease = make(chan struct{})
		status := newFakeControlChildStatus()
		result := make(chan error, 1)
		go func() { result <- newControlChild(runtime, status).Run(context.Background()) }()
		waitControlChildSignal(t, runtime.startEntered, "Start entry")
		close(runtime.fatal)
		waitControlChildSignal(t, status.fatalSignal, "fatal exit")
		if err := receiveControlChildResult(t, result); !errors.Is(err, errControlWorkerChildFatal) {
			t.Fatalf("Run(fatal during Start) error = %v", err)
		}
		close(runtime.startRelease)
		if runtime.starts.Load() != 1 || runtime.stops.Load() != 0 ||
			status.ready.Load() != 0 || status.fatals.Load() != 1 {
			t.Fatalf("lifecycle/status = %d/%d, %d/%d",
				runtime.starts.Load(), runtime.stops.Load(), status.ready.Load(), status.fatals.Load())
		}
	})
}

func TestControlChildCancellationDuringBlockedStartNeverCallsStopConcurrently(t *testing.T) {
	runtime := newFakeControlChildRuntime()
	runtime.startEntered = make(chan struct{})
	runtime.startRelease = make(chan struct{})
	status := newFakeControlChildStatus()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- newControlChild(runtime, status).Run(ctx) }()
	waitControlChildSignal(t, runtime.startEntered, "Start entry")
	cancel()
	if err := receiveControlChildResult(t, result); !errors.Is(err, errControlWorkerChildRejected) {
		t.Fatalf("Run(cancel during Start) error = %v", err)
	}
	close(runtime.startRelease)
	if runtime.starts.Load() != 1 || runtime.stops.Load() != 0 ||
		status.ready.Load() != 0 || status.fatals.Load() != 0 {
		t.Fatalf("lifecycle/status = %d/%d, %d/%d",
			runtime.starts.Load(), runtime.stops.Load(), status.ready.Load(), status.fatals.Load())
	}
}

func TestControlChildNeverReportsREADYAfterCancellationWinsStartCompletion(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		runtime := newFakeControlChildRuntime()
		runtime.startEntered = make(chan struct{})
		runtime.startRelease = make(chan struct{})
		status := newFakeControlChildStatus()
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { result <- newControlChild(runtime, status).Run(ctx) }()
		waitControlChildSignal(t, runtime.startEntered, "Start entry")
		cancel()
		close(runtime.startRelease)
		err := receiveControlChildResult(t, result)
		if err != nil && !errors.Is(err, errControlWorkerChildRejected) {
			t.Fatalf("iteration %d: Run() error = %v", iteration, err)
		}
		if status.ready.Load() != 0 || runtime.stops.Load() > 1 || status.fatals.Load() != 0 {
			t.Fatalf("iteration %d: READY/Stop/Fatal = %d/%d/%d",
				iteration, status.ready.Load(), runtime.stops.Load(), status.fatals.Load())
		}
	}
}

func TestControlChildFatalDuringStopDoesNotCloseOrStopAgain(t *testing.T) {
	runtime := newFakeControlChildRuntime()
	runtime.stopEntered = make(chan struct{})
	runtime.stopRelease = make(chan struct{})
	status := newFakeControlChildStatus()
	child := newControlChild(runtime, status)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- child.Run(ctx) }()
	waitControlChildSignal(t, status.readySignal, "READY")
	cancel()
	waitControlChildSignal(t, runtime.stopEntered, "Stop entry")
	close(runtime.fatal)
	waitControlChildSignal(t, status.fatalSignal, "fatal exit")
	if err := receiveControlChildResult(t, result); !errors.Is(err, errControlWorkerChildFatal) {
		t.Fatalf("Run(fatal during Stop) error = %v", err)
	}
	close(runtime.stopRelease)
	if runtime.stops.Load() != 1 || status.fatals.Load() != 1 {
		t.Fatalf("Stop/fatal calls = %d/%d", runtime.stops.Load(), status.fatals.Load())
	}
}

func TestControlChildRequiresFatalQuiescenceAfterStop(t *testing.T) {
	runtime := newFakeControlChildRuntime()
	runtime.autoQuiesce = false
	runtime.stopReturning = make(chan struct{})
	status := newFakeControlChildStatus()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- newControlChild(runtime, status).Run(ctx) }()
	waitControlChildSignal(t, status.readySignal, "READY")
	cancel()
	waitControlChildSignal(t, runtime.stopReturning, "Stop return")
	select {
	case err := <-result:
		t.Fatalf("Run() returned before fatal quiescence: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(runtime.fatal)
	waitControlChildSignal(t, status.fatalSignal, "late fatal exit")
	if err := receiveControlChildResult(t, result); !errors.Is(err, errControlWorkerChildFatal) {
		t.Fatalf("Run(late fatal after Stop) error = %v", err)
	}
}

func TestControlChildStopPanicAndInvalidCopiesFailClosed(t *testing.T) {
	runtime := newFakeControlChildRuntime()
	runtime.stopPanic = "STOP-SECRET-CANARY"
	status := newFakeControlChildStatus()
	child := newControlChild(runtime, status)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- child.Run(ctx) }()
	waitControlChildSignal(t, status.readySignal, "READY")
	cancel()
	if err := receiveControlChildResult(t, result); !errors.Is(err, errControlWorkerChildRejected) ||
		containsControlChildCanary(err) {
		t.Fatalf("Run(Stop panic) error = %v", err)
	}
	if runtime.stops.Load() != 1 {
		t.Fatalf("Stop calls = %d", runtime.stops.Load())
	}

	freshRuntime := newFakeControlChildRuntime()
	freshStatus := newFakeControlChildStatus()
	original := newControlChild(freshRuntime, freshStatus)
	forgedCopy := &controlChild{
		runtime:       original.runtime,
		status:        original.status,
		fatalObserved: original.fatalObserved,
		seal:          original.seal,
		self:          original,
	}
	if err := forgedCopy.Run(context.Background()); !errors.Is(err, errControlWorkerChildRejected) {
		t.Fatalf("forged-copy Run() error = %v", err)
	}
	if freshRuntime.starts.Load() != 0 || freshRuntime.stops.Load() != 0 ||
		freshStatus.ready.Load() != 0 || freshStatus.fatals.Load() != 0 {
		t.Fatal("copied child retained lifecycle authority")
	}
}

func TestControlChildStopErrorAndTypedNilDependenciesFailClosed(t *testing.T) {
	runtime := newFakeControlChildRuntime()
	runtime.stopErr = errors.New("STOP-SECRET-CANARY")
	status := newFakeControlChildStatus()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- newControlChild(runtime, status).Run(ctx) }()
	waitControlChildSignal(t, status.readySignal, "READY")
	cancel()
	if err := receiveControlChildResult(t, result); !errors.Is(err, errControlWorkerChildRejected) ||
		containsControlChildCanary(err) {
		t.Fatalf("Run(Stop error) = %v", err)
	}

	var nilRuntime *fakeControlChildRuntime
	if err := newControlChild(nilRuntime, newFakeControlChildStatus()).Run(context.Background()); !errors.Is(err, errControlWorkerChildRejected) {
		t.Fatalf("Run(typed-nil runtime) error = %v", err)
	}
	var nilStatus *fakeControlChildStatus
	if err := newControlChild(newFakeControlChildRuntime(), nilStatus).Run(context.Background()); !errors.Is(err, errControlWorkerChildRejected) {
		t.Fatalf("Run(typed-nil status) error = %v", err)
	}
	quiescedBeforeStart := newFakeControlChildRuntime()
	close(quiescedBeforeStart.fatalQuiesced)
	if err := newControlChild(quiescedBeforeStart, newFakeControlChildStatus()).Run(context.Background()); !errors.Is(err, errControlWorkerChildRejected) || quiescedBeforeStart.starts.Load() != 0 {
		t.Fatalf("Run(pre-quiesced fatal source) = %v; starts=%d", err, quiescedBeforeStart.starts.Load())
	}
}

type fakeControlChildRuntime struct {
	fatal         chan struct{}
	fatalQuiesced chan struct{}
	startEntered  chan struct{}
	startRelease  chan struct{}
	stopEntered   chan struct{}
	stopRelease   chan struct{}
	stopReturning chan struct{}
	startErr      error
	stopErr       error
	startPanic    any
	stopPanic     any
	autoQuiesce   bool
	starts        atomic.Int64
	stops         atomic.Int64
}

func newFakeControlChildRuntime() *fakeControlChildRuntime {
	return &fakeControlChildRuntime{
		fatal: make(chan struct{}), fatalQuiesced: make(chan struct{}), autoQuiesce: true,
	}
}

func (runtime *fakeControlChildRuntime) Start() error {
	runtime.starts.Add(1)
	if runtime.startEntered != nil {
		close(runtime.startEntered)
	}
	if runtime.startRelease != nil {
		<-runtime.startRelease
	}
	if runtime.startPanic != nil {
		panic(runtime.startPanic)
	}
	return runtime.startErr
}

func (runtime *fakeControlChildRuntime) Stop() error {
	runtime.stops.Add(1)
	if runtime.stopEntered != nil {
		close(runtime.stopEntered)
	}
	if runtime.stopRelease != nil {
		<-runtime.stopRelease
	}
	if runtime.stopPanic != nil {
		panic(runtime.stopPanic)
	}
	if runtime.stopErr == nil {
		if runtime.stopReturning != nil {
			close(runtime.stopReturning)
		}
		if runtime.autoQuiesce {
			close(runtime.fatalQuiesced)
		}
	}
	return runtime.stopErr
}

func (runtime *fakeControlChildRuntime) Fatal() <-chan struct{} { return runtime.fatal }

func (runtime *fakeControlChildRuntime) FatalQuiesced() <-chan struct{} {
	return runtime.fatalQuiesced
}

type fakeControlChildStatus struct {
	readySignal chan struct{}
	fatalSignal chan struct{}
	readyErr    error
	ready       atomic.Int64
	fatals      atomic.Int64
}

func newFakeControlChildStatus() *fakeControlChildStatus {
	return &fakeControlChildStatus{readySignal: make(chan struct{}), fatalSignal: make(chan struct{})}
}

func (status *fakeControlChildStatus) Ready() error {
	if status.ready.Add(1) == 1 {
		close(status.readySignal)
	}
	return status.readyErr
}

func (status *fakeControlChildStatus) Fatal() {
	if status.fatals.Add(1) == 1 {
		close(status.fatalSignal)
	}
}

func waitControlChildSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func receiveControlChildResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		t.Fatal("control child did not return")
		return nil
	}
}

func containsControlChildCanary(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "START-SECRET-CANARY") ||
		strings.Contains(err.Error(), "STOP-SECRET-CANARY"))
}
