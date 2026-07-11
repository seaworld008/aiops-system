package isolatedexec

import (
	"errors"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const ExecutorPath = "/usr/local/libexec/aiops-executor"

var (
	ErrUnsupportedPlatform    = errors.New("isolated executor requires Linux")
	ErrInvalidConfiguration   = errors.New("invalid isolated executor configuration")
	ErrInvalidRequest         = errors.New("invalid isolated executor request")
	ErrNotReady               = errors.New("isolated executor did not become ready")
	ErrSessionConsumed        = errors.New("isolated executor session is already consumed")
	ErrTerminationUnconfirmed = errors.New("isolated executor termination is unconfirmed")
)

type settings struct {
	readyTimeout       time.Duration
	termGrace          time.Duration
	killConfirmTimeout time.Duration
	exitTimeout        time.Duration
	outputLimit        int64
	tempRoot           string
}

func defaultSettings() settings {
	return settings{
		readyTimeout:       10 * time.Second,
		termGrace:          2 * time.Second,
		killConfirmTimeout: 5 * time.Second,
		exitTimeout:        2 * time.Second,
		outputLimit:        64 << 10,
		tempRoot:           "/tmp",
	}
}

func (value settings) valid() bool {
	return value.readyTimeout > 0 && value.readyTimeout <= 30*time.Second &&
		value.termGrace == 2*time.Second &&
		value.killConfirmTimeout > 0 && value.killConfirmTimeout <= 30*time.Second &&
		value.exitTimeout > 0 && value.exitTimeout <= 10*time.Second &&
		value.outputLimit >= 1 && value.outputLimit <= 1<<20 && validTempRoot(value.tempRoot)
}

func validTempRoot(value string) bool {
	if value == "" || len(value) > 4096 || !filepath.IsAbs(value) || filepath.Clean(value) != value ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

// Supervisor owns the fixed Executor process boundary. The production
// constructor intentionally accepts no executable path, argv, environment, or
// command factory; job payloads can never select code to run.
type Supervisor struct {
	executablePath string
	settings       settings
}

func New() (*Supervisor, error) {
	return newSupervisorWithOwner(ExecutorPath, defaultSettings(), false)
}

// newSupervisor is package-private so tests can exercise the real process
// boundary with a purpose-built helper. Runtime callers only have New.
func newSupervisor(executablePath string, configuration settings) (*Supervisor, error) {
	return newSupervisorWithOwner(executablePath, configuration, true)
}

func newSupervisorWithOwner(executablePath string, configuration settings, allowCurrentOwner bool) (*Supervisor, error) {
	if !configuration.valid() {
		return nil, ErrInvalidConfiguration
	}
	if err := validatePlatform(executablePath, allowCurrentOwner); err != nil {
		return nil, err
	}
	return &Supervisor{executablePath: executablePath, settings: configuration}, nil
}

type outputBudget struct {
	limit      int64
	observed   atomic.Int64
	exceeded   atomic.Bool
	overflow   chan struct{}
	overflowDo sync.Once
}

func newOutputBudget(limit int64) *outputBudget {
	if limit <= 0 {
		return nil
	}
	return &outputBudget{limit: limit, overflow: make(chan struct{})}
}

// Write always consumes and discards the complete input so a noisy child can
// neither block on a full pipe nor smuggle output into logs. Crossing the
// shared bound emits a one-shot termination signal.
func (budget *outputBudget) Write(value []byte) (int, error) {
	if budget == nil {
		return len(value), nil
	}
	for {
		current := budget.observed.Load()
		increment := int64(len(value))
		next := current + increment
		if increment > 0 && (next < current || current > math.MaxInt64-increment) {
			next = math.MaxInt64
		}
		if budget.observed.CompareAndSwap(current, next) {
			if next > budget.limit && budget.exceeded.CompareAndSwap(false, true) {
				budget.overflowDo.Do(func() { close(budget.overflow) })
			}
			break
		}
	}
	return len(value), nil
}

func (budget *outputBudget) Overflow() <-chan struct{} {
	if budget == nil {
		return nil
	}
	return budget.overflow
}

func (budget *outputBudget) Exceeded() bool {
	return budget != nil && budget.exceeded.Load()
}

func (budget *outputBudget) BytesObserved() int64 {
	if budget == nil {
		return 0
	}
	return budget.observed.Load()
}
