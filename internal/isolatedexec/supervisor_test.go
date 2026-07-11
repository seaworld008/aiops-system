package isolatedexec

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"
)

func TestSupervisorCopiesShareClosedRuntimeBoundary(t *testing.T) {
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open temp root: %v", err)
	}
	supervisor := &Supervisor{boundary: &runtimeBoundary{root: root}}
	copy := *supervisor
	if err := copy.Close(); err != nil {
		t.Fatalf("copy.Close() error = %v", err)
	}
	if err := supervisor.Close(); err != nil {
		t.Fatalf("Supervisor.Close() after copy error = %v", err)
	}
	if _, err := root.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("retained root remains open: %v", err)
	}
}

func TestSupervisorCloseCannotCrossActiveStartReservation(t *testing.T) {
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open temp root: %v", err)
	}
	supervisor := &Supervisor{boundary: &runtimeBoundary{root: root, mount: 1}}
	release, err := supervisor.reserveJob()
	if err != nil {
		t.Fatalf("reserveJob() error = %v", err)
	}
	if err := supervisor.Close(); !errors.Is(err, ErrTerminationUnconfirmed) {
		t.Fatalf("Close(active) error = %v", err)
	}
	if supervisor.boundary.closed {
		t.Fatal("active Close marked boundary closed")
	}
	release()
	if err := supervisor.Close(); err != nil {
		t.Fatalf("Close(after release) error = %v", err)
	}
}

func TestDefaultSettingsKeepFixedTerminationAndResourceBounds(t *testing.T) {
	settings := defaultSettings()
	if settings.readyTimeout != 10*time.Second {
		t.Fatalf("ready timeout = %s, want 10s", settings.readyTimeout)
	}
	if settings.termGrace != 2*time.Second {
		t.Fatalf("TERM grace = %s, want fixed 2s", settings.termGrace)
	}
	if settings.killConfirmTimeout != 5*time.Second {
		t.Fatalf("kill confirmation timeout = %s, want 5s", settings.killConfirmTimeout)
	}
	if settings.outputLimit != 64<<10 {
		t.Fatalf("combined output limit = %d, want 64 KiB", settings.outputLimit)
	}
	if settings.exitTimeout != 2*time.Second {
		t.Fatalf("post-result exit timeout = %s, want 2s", settings.exitTimeout)
	}
	if settings.tempRoot != "/tmp" {
		t.Fatalf("temporary root = %q, want /tmp", settings.tempRoot)
	}
}

func TestOutputBudgetDiscardsContentAndSignalsOverflowOnce(t *testing.T) {
	budget := newOutputBudget(8)
	if written, err := budget.Write([]byte("1234")); err != nil || written != 4 {
		t.Fatalf("Write(first) = %d, %v", written, err)
	}
	if written, err := budget.Write([]byte("56789")); err != nil || written != 5 {
		t.Fatalf("Write(overflow) = %d, %v", written, err)
	}
	if written, err := budget.Write(bytes.Repeat([]byte{'x'}, 64)); err != nil || written != 64 {
		t.Fatalf("Write(after overflow) = %d, %v", written, err)
	}
	select {
	case <-budget.Overflow():
	default:
		t.Fatal("overflow signal is not closed")
	}
	if !budget.Exceeded() {
		t.Fatal("Exceeded() = false")
	}
	if budget.BytesObserved() != 73 {
		t.Fatalf("BytesObserved() = %d, want 73", budget.BytesObserved())
	}
}

func TestNewOutputBudgetRejectsNonPositiveLimit(t *testing.T) {
	for _, limit := range []int64{-1, 0} {
		if budget := newOutputBudget(limit); budget != nil {
			t.Fatalf("newOutputBudget(%d) = %#v, want nil", limit, budget)
		}
	}
}

func TestCompletionAllowsReleaseOnlyBeforeGoAndAfterConfirmedTermination(t *testing.T) {
	for _, test := range []struct {
		name       string
		completion Completion
		want       bool
	}{
		{name: "pre-GO confirmed", completion: Completion{TerminationConfirmed: true}, want: true},
		{name: "pre-GO unconfirmed", completion: Completion{}, want: false},
		{name: "post-GO confirmed", completion: Completion{GOAttempted: true, TerminationConfirmed: true}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.completion.SafeToRelease(); got != test.want {
				t.Fatalf("SafeToRelease() = %t, want %t", got, test.want)
			}
		})
	}
}
