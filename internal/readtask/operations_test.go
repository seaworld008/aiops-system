package readtask_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/readtask"
)

func TestReadTaskOperationsEnforceAttemptStateAndFence(t *testing.T) {
	now := time.Date(2026, 7, 12, 11, 0, 0, 0, time.UTC)
	descriptor := validDescriptor(t)
	running, fence := runningAttempt(t, descriptor, now)
	leased := running
	leased.Status = readtask.AttemptLeased
	leased.StartedAt = time.Time{}

	if err := (readtask.Start{Fence: fence}).ValidateAgainst(descriptor, leased); err != nil {
		t.Fatalf("valid Start error = %v", err)
	}
	if err := (readtask.Heartbeat{Fence: fence, Sequence: 1}).ValidateAgainst(descriptor, running); err != nil {
		t.Fatalf("valid Heartbeat error = %v", err)
	}
	if err := (readtask.Heartbeat{Fence: fence, Sequence: 2}).ValidateAgainst(descriptor, running); err == nil {
		t.Fatal("Heartbeat accepted a sequence gap")
	}
	if err := (readtask.Release{Fence: fence, ReasonCode: readtask.ReleaseConnectorNotReady}).ValidateAgainst(descriptor, leased); err != nil {
		t.Fatalf("valid Release error = %v", err)
	}
	if err := (readtask.Completion{Fence: fence, Outcome: readtask.CompletionCancelled, FailureCode: readtask.FailureCancelled}).ValidateAgainst(descriptor, running); err != nil {
		t.Fatalf("valid cancelled Completion error = %v", err)
	}

	if err := (readtask.Heartbeat{Fence: fence, Sequence: 1}).ValidateAgainst(descriptor, leased); err == nil {
		t.Fatal("Heartbeat accepted LEASED attempt")
	}
	if err := (readtask.Release{Fence: fence, ReasonCode: readtask.ReleaseConnectorNotReady}).ValidateAgainst(descriptor, running); err == nil {
		t.Fatal("Release accepted RUNNING attempt")
	}
	if err := (readtask.Start{Fence: fence}).ValidateAgainst(descriptor, running); err != nil {
		t.Fatalf("Start retry rejected current RUNNING attempt: %v", err)
	}
}

func TestProjectedCompletionBindsEveryTrustedIdentityAndExecutionFact(t *testing.T) {
	now := time.Date(2026, 7, 12, 11, 30, 0, 0, time.UTC)
	descriptor := validDescriptor(t)
	attempt, fence := runningAttempt(t, descriptor, now)
	projected, err := readtask.ProjectCompletion(descriptor, attempt, readtask.Completion{
		Fence: fence, Outcome: readtask.CompletionFailed, FailureCode: readtask.FailureTimeout,
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	mutatedDescriptors := []readtask.Descriptor{descriptor, descriptor, descriptor, descriptor, descriptor}
	mutatedDescriptors[0].ConnectorID = "prometheus_other"
	mutatedDescriptors[1].Operation = "instant_query"
	mutatedDescriptors[2].TaskKey = "service.health.other"
	mutatedDescriptors[3].Position++
	mutatedDescriptors[4].Input = json.RawMessage(`{"query":"other","window_seconds":300}`)
	inputDigest := sha256.Sum256(mutatedDescriptors[4].Input)
	mutatedDescriptors[4].InputHash = fmt.Sprintf("%x", inputDigest)
	for _, mutated := range mutatedDescriptors {
		if err := projected.ValidateAgainst(mutated, attempt); err == nil {
			t.Fatalf("projection accepted changed connector/operation: %#v", mutated)
		}
	}

	for name, mutate := range map[string]func(*readtask.Attempt){
		"epoch":          func(value *readtask.Attempt) { value.Epoch++ },
		"runner":         func(value *readtask.Attempt) { value.RunnerID = "read-runner-2" },
		"scope revision": func(value *readtask.Attempt) { value.ScopeRevision++ },
		"certificate": func(value *readtask.Attempt) {
			value.Certificate.SHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte("other-certificate")))
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := attempt
			mutate(&mutated)
			if err := projected.ValidateAgainst(descriptor, mutated); err == nil {
				t.Fatal("projection accepted changed trusted attempt binding")
			}
		})
	}

	receipt := projected.Receipt()
	receipt.RequestHash = fmt.Sprintf("%x", sha256.Sum256([]byte("other-request")))
	if err := receipt.ValidateAgainst(descriptor, attempt); err == nil {
		t.Fatal("Receipt accepted a substituted request hash")
	}
}
