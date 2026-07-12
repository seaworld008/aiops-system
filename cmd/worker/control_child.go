package main

import (
	"context"
	"errors"
	"reflect"
	"sync"

	"github.com/seaworld008/aiops-system/internal/workerprocess"
)

var (
	errControlWorkerChildRejected = errors.New("control worker child lifecycle rejected")
	errControlWorkerChildFatal    = errors.New("control worker child fatal signal received")
)

type controlChildRuntime interface {
	Start() error
	Stop() error
	Fatal() <-chan struct{}
	FatalQuiesced() <-chan struct{}
}

type controlChildStatus interface {
	Ready() error
	Fatal()
}

type controlChildMarker struct{ value byte }

var sealedControlChildMarker = &controlChildMarker{value: 1}

type controlChild struct {
	mu            sync.Mutex
	run           bool
	runtime       controlChildRuntime
	status        controlChildStatus
	fatalOnce     sync.Once
	fatalObserved chan struct{}
	seal          *controlChildMarker
	self          *controlChild
}

func newControlChild(runtime controlChildRuntime, status controlChildStatus) *controlChild {
	created := &controlChild{
		runtime:       runtime,
		status:        status,
		fatalObserved: make(chan struct{}),
		seal:          sealedControlChildMarker,
	}
	created.self = created
	return created
}

func (child *controlChild) structurallyValid() bool {
	return child != nil && child.self == child && child.seal == sealedControlChildMarker &&
		!nilControlChildDependency(child.runtime) && !nilControlChildDependency(child.status) &&
		child.fatalObserved != nil
}

func (child *controlChild) Run(ctx context.Context) error {
	if !child.structurallyValid() || ctx == nil {
		return errControlWorkerChildRejected
	}
	child.mu.Lock()
	if child.run {
		child.mu.Unlock()
		return errControlWorkerChildRejected
	}
	child.run = true
	child.mu.Unlock()

	fatal, fatalQuiesced, ok := controlChildSignals(child.runtime)
	if !ok {
		return errControlWorkerChildRejected
	}
	if channelClosed(fatal) {
		child.reportFatal()
		return errControlWorkerChildFatal
	}
	if channelClosed(fatalQuiesced) {
		return errControlWorkerChildRejected
	}
	go func() {
		<-fatal
		child.reportFatal()
	}()

	if ctx.Err() != nil {
		return errControlWorkerChildRejected
	}
	startResult := make(chan error, 1)
	go func() { startResult <- startControlChildRuntime(child.runtime) }()
	select {
	case <-child.fatalObserved:
		return errControlWorkerChildFatal
	case <-ctx.Done():
		if channelClosed(fatal) {
			child.reportFatal()
			return errControlWorkerChildFatal
		}
		return errControlWorkerChildRejected
	case startErr := <-startResult:
		if channelClosed(fatal) {
			child.reportFatal()
			return errControlWorkerChildFatal
		}
		if startErr != nil {
			return child.stopAndFinish(fatal, fatalQuiesced, errControlWorkerChildRejected)
		}
	}

	if channelClosed(fatal) {
		child.reportFatal()
		return errControlWorkerChildFatal
	}
	if ctx.Err() != nil {
		return child.stopAndFinish(fatal, fatalQuiesced, nil)
	}
	if err := reportControlChildReady(child.status); err != nil {
		return child.stopAndFinish(fatal, fatalQuiesced, errControlWorkerChildRejected)
	}
	if channelClosed(fatal) {
		child.reportFatal()
		return errControlWorkerChildFatal
	}

	select {
	case <-child.fatalObserved:
		return errControlWorkerChildFatal
	case <-ctx.Done():
		return child.stopAndFinish(fatal, fatalQuiesced, nil)
	}
}

func (child *controlChild) stopAndFinish(
	fatal <-chan struct{},
	fatalQuiesced <-chan struct{},
	cleanResult error,
) error {
	if channelClosed(fatal) {
		child.reportFatal()
		return errControlWorkerChildFatal
	}
	stopResult := make(chan error, 1)
	go func() { stopResult <- stopControlChildRuntime(child.runtime) }()
	select {
	case <-child.fatalObserved:
		return errControlWorkerChildFatal
	case stopErr := <-stopResult:
		if channelClosed(fatal) {
			child.reportFatal()
			return errControlWorkerChildFatal
		}
		if stopErr != nil {
			return errControlWorkerChildRejected
		}
		if cleanResult != nil {
			return cleanResult
		}
		select {
		case <-child.fatalObserved:
			return errControlWorkerChildFatal
		case <-fatalQuiesced:
			// The reviewed runtime adapter must close FatalQuiesced only after
			// proving that no current or future fatal callback can run. Without
			// that proof, normal shutdown intentionally remains blocked for the
			// parent process deadline to contain.
			if channelClosed(fatal) {
				child.reportFatal()
				return errControlWorkerChildFatal
			}
			return nil
		}
	}
}

func (child *controlChild) reportFatal() {
	child.fatalOnce.Do(func() {
		child.status.Fatal()
		// The production Fatal method exits and never reaches this close. Tests
		// use a returning recorder so they can assert that no cleanup follows.
		close(child.fatalObserved)
	})
}

func controlChildSignals(
	runtime controlChildRuntime,
) (fatal <-chan struct{}, fatalQuiesced <-chan struct{}, ok bool) {
	defer func() {
		if recover() != nil {
			fatal = nil
			fatalQuiesced = nil
			ok = false
		}
	}()
	fatal = runtime.Fatal()
	fatalQuiesced = runtime.FatalQuiesced()
	return fatal, fatalQuiesced, fatal != nil && fatalQuiesced != nil
}

func startControlChildRuntime(runtime controlChildRuntime) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = errControlWorkerChildRejected
		}
	}()
	if err := runtime.Start(); err != nil {
		return errControlWorkerChildRejected
	}
	return nil
}

func stopControlChildRuntime(runtime controlChildRuntime) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = errControlWorkerChildRejected
		}
	}()
	if err := runtime.Stop(); err != nil {
		return errControlWorkerChildRejected
	}
	return nil
}

func reportControlChildReady(status controlChildStatus) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = errControlWorkerChildRejected
		}
	}()
	if err := status.Ready(); err != nil {
		return errControlWorkerChildRejected
	}
	return nil
}

func channelClosed(channel <-chan struct{}) bool {
	select {
	case <-channel:
		return true
	default:
		return false
	}
}

func nilControlChildDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

type processControlChildStatus struct {
	status *workerprocess.ChildStatus
}

func (status *processControlChildStatus) Ready() error {
	return workerprocess.ReportControlWorkerReady(status.status)
}

func (status *processControlChildStatus) Fatal() {
	workerprocess.ExitControlWorkerFatal(status.status)
}

func newControlChildRuntime() (controlChildRuntime, error) {
	// C2-4c2b0 validates only lifecycle containment. Secure bootstrap and the
	// Snapshot/PostgreSQL/Temporal assembly remain separate reviewed gates.
	return nil, errControlWorkerAssemblyUnavailable
}

func runControlWorkerChildRuntime(ctx context.Context, status *workerprocess.ChildStatus) error {
	if ctx == nil {
		return errControlWorkerChildRejected
	}
	if ctx.Err() != nil {
		if status != nil {
			_ = workerprocess.CloseControlWorkerChild(status)
		}
		return errControlWorkerChildRejected
	}
	runtime, err := newControlChildRuntime()
	if err != nil || nilControlChildDependency(runtime) {
		if status != nil {
			_ = workerprocess.CloseControlWorkerChild(status)
		}
		return errControlWorkerAssemblyUnavailable
	}
	if status == nil {
		_ = stopControlChildRuntime(runtime)
		return errControlWorkerChildRejected
	}
	return newControlChild(runtime, &processControlChildStatus{status: status}).Run(ctx)
}
