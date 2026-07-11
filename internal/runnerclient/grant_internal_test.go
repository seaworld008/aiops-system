package runnerclient

import (
	"context"
	"sync"
	"sync/atomic"
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

func TestExecutionGrantCanBeConsumedExactlyOnceUnderConcurrency(t *testing.T) {
	grant := &ExecutionGrant{state: &executionGrantState{}}
	var successes atomic.Int64
	var wait sync.WaitGroup
	for range 64 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if grant.consumeIfValid(func() bool { return true }) {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful grant consumptions = %d, want 1", successes.Load())
	}
}
