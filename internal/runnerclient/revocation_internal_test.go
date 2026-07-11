package runnerclient

import (
	"testing"
	"time"
)

func TestRevocationTerminateIsStickyAndContinueExtendsRuntimeClaim(t *testing.T) {
	now := time.Now().UTC()
	state := &revocationLeaseState{runtimeClaimExpiresAt: now.Add(time.Second)}
	if !state.updateHeartbeat("CONTINUE", now.Add(time.Minute)) ||
		!state.runtimeClaimExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("CONTINUE did not extend runtime claim: %s", state.runtimeClaimExpiresAt)
	}
	if !state.updateHeartbeat("TERMINATE", now.Add(time.Minute)) || !state.terminationRequested {
		t.Fatal("TERMINATE was not recorded")
	}
	if state.updateHeartbeat("CONTINUE", now.Add(2*time.Minute)) || !state.terminationRequested ||
		!state.runtimeClaimExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatal("CONTINUE cleared sticky revocation termination")
	}
}
