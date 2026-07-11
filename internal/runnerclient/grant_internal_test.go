package runnerclient

import (
	"context"
	"testing"
	"time"
)

func TestExecutionLeaseTerminateIsStickyAndCancelsGrantContext(t *testing.T) {
	binding := &jobLeaseBinding{
		runtimeLeaseExpiresAt: time.Now().UTC().Add(time.Minute),
		updates:               make(chan struct{}, 1),
	}
	state := &credentialPreparationState{
		lease: binding, credentialExpiresAt: time.Now().UTC().Add(time.Minute), phase: credentialPhaseActive,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		monitorExecutionLease(ctx, cancel, state)
		close(done)
	}()
	if !binding.updateHeartbeat("TERMINATE", time.Now().UTC().Add(time.Minute)) {
		t.Fatal("TERMINATE update was rejected")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TERMINATE did not cancel the grant context")
	}
	if binding.updateHeartbeat("CONTINUE", time.Now().UTC().Add(2*time.Minute)) {
		t.Fatal("CONTINUE cleared a sticky TERMINATE")
	}
}
