package workerprocess

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"time"
)

const (
	defaultStartupTimeout   = 30 * time.Second
	defaultStartupGrace     = 2 * time.Second
	defaultShutdownGrace    = 45 * time.Second
	defaultAnomalyGrace     = 2 * time.Second
	defaultKillConfirmation = 5 * time.Second
	defaultOutputByteLimit  = 64 << 10
	controlWorkerWaitDelay  = 500 * time.Millisecond
	exitClassificationGrace = 100 * time.Millisecond
)

var (
	errInvalidSupervisor = errors.New("control worker supervisor rejected")
	errSupervisorRun     = errors.New("control worker supervisor already ran")
	errUnsupported       = errors.New("control worker supervisor unsupported")
	errChildStart        = errors.New("control worker child start rejected")
	errChildStartup      = errors.New("control worker child startup rejected")
	errChildFatal        = errors.New("control worker child fatal signal received")
	errChildProtocol     = errors.New("control worker child status rejected")
	errChildExit         = errors.New("control worker child exited unexpectedly")
	errChildStop         = errors.New("control worker child shutdown rejected")
	errOutputLimit       = errors.New("control worker child output rejected")
)

type supervisorSettings struct {
	startupTimeout time.Duration
	startupGrace   time.Duration
	shutdownGrace  time.Duration
	anomalyGrace   time.Duration
	killConfirm    time.Duration
	outputLimit    int64
	childEnv       []string
	openSource     func(context.Context, time.Duration) (controlWorkerSource, error)
}

type controlWorkerSource interface {
	StartChild(*exec.Cmd, *os.File) error
	Close() error
}

func nilControlWorkerSource(value controlWorkerSource) bool {
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

type controlWorkerSupervisorMarker struct{ value byte }

var sealedControlWorkerSupervisorMarker = &controlWorkerSupervisorMarker{value: 1}

func defaultSupervisorSettings() supervisorSettings {
	return supervisorSettings{
		startupTimeout: defaultStartupTimeout,
		startupGrace:   defaultStartupGrace,
		shutdownGrace:  defaultShutdownGrace,
		anomalyGrace:   defaultAnomalyGrace,
		killConfirm:    defaultKillConfirmation,
		outputLimit:    defaultOutputByteLimit,
		childEnv:       []string{},
		openSource:     openProductionControlWorkerSource,
	}
}

func (settings supervisorSettings) valid() bool {
	return settings.startupTimeout > 0 && settings.startupGrace > 0 &&
		settings.shutdownGrace > 0 && settings.anomalyGrace > 0 &&
		settings.killConfirm > 0 && settings.outputLimit > 0 && settings.childEnv != nil && settings.openSource != nil
}

// ControlWorkerSupervisor owns one fixed-path control worker child process.
// A supervisor is intentionally single-use.
type ControlWorkerSupervisor struct {
	mu       sync.Mutex
	run      bool
	settings supervisorSettings
	seal     *controlWorkerSupervisorMarker
	self     *ControlWorkerSupervisor
}

// NewControlWorkerSupervisor returns the production supervisor. There are no
// path, argument, environment, timeout, or command injection options.
func NewControlWorkerSupervisor() *ControlWorkerSupervisor {
	return newControlWorkerSupervisor(defaultSupervisorSettings())
}

func newControlWorkerSupervisor(settings supervisorSettings) *ControlWorkerSupervisor {
	created := &ControlWorkerSupervisor{
		settings: settings,
		seal:     sealedControlWorkerSupervisorMarker,
	}
	created.self = created
	return created
}

// Run starts and contains exactly one control worker child until ctx stops or
// the child reports a fatal condition.
func (supervisor *ControlWorkerSupervisor) Run(ctx context.Context) error {
	if supervisor == nil || supervisor.self != supervisor ||
		supervisor.seal != sealedControlWorkerSupervisorMarker || ctx == nil {
		return errInvalidSupervisor
	}
	supervisor.mu.Lock()
	if supervisor.run {
		supervisor.mu.Unlock()
		return errSupervisorRun
	}
	supervisor.run = true
	settings := supervisor.settings
	supervisor.mu.Unlock()
	if !settings.valid() || ctx.Err() != nil {
		return errInvalidSupervisor
	}
	return runControlWorkerSupervisor(ctx, settings)
}
