package isolatedexec

import (
	"bytes"
	"testing"
	"time"
)

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
