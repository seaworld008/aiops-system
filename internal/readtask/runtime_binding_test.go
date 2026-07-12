package readtask_test

import (
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/readtask"
)

func TestDescriptorAttemptAndReceiptCarryExactRuntimeBindingSnapshots(t *testing.T) {
	now := time.Date(2026, 7, 12, 13, 0, 0, 0, time.UTC)
	descriptor := validDescriptor(t)
	attempt, fence := runningAttempt(t, descriptor, now)
	if !attempt.PlanBinding.Equal(descriptor.PlanBinding) || !attempt.RuntimeBinding.Equal(descriptor.RuntimeBinding) {
		t.Fatal("running attempt lost its plan/runtime binding snapshot")
	}
	projection, err := readtask.ProjectCompletion(descriptor, attempt, readtask.Completion{
		Fence: fence, Outcome: readtask.CompletionFailed, FailureCode: readtask.FailureTimeout,
	}, now)
	if err != nil {
		t.Fatalf("ProjectCompletion() error = %v", err)
	}
	receipt := projection.Receipt()
	if receipt.SchemaVersion != readtask.RunnerEvidenceSchemaVersionV3 ||
		receipt.RequestHashVersion != readtask.CompletionRequestHashVersionV3 ||
		receipt.ReceiptHashVersion != readtask.CompletionReceiptHashVersionV3 ||
		!receipt.PlanBinding.Equal(descriptor.PlanBinding) || !receipt.RuntimeBinding.Equal(descriptor.RuntimeBinding) {
		t.Fatalf("Receipt binding/version snapshot = %#v", receipt)
	}

	changedAttempt := attempt
	changedAttempt.PlanBinding.ProfileDigest = strings.Repeat("9", 64)
	if err := changedAttempt.ValidateAgainst(descriptor); err == nil {
		t.Fatal("Attempt accepted a changed plan snapshot")
	}
	changedAttempt = attempt
	changedAttempt.RuntimeBinding.TargetDigest = strings.Repeat("a", 64)
	if err := changedAttempt.ValidateAgainst(descriptor); err == nil {
		t.Fatal("Attempt accepted a changed runtime snapshot")
	}
	changedReceipt := receipt
	changedReceipt.RuntimeBinding.ExecutorDigest = strings.Repeat("b", 64)
	if err := changedReceipt.ValidateAgainst(descriptor, attempt); err == nil {
		t.Fatal("Receipt accepted a changed runtime snapshot")
	}
}

func TestCompletionV3HashesChangeWithPersistedBindingSnapshots(t *testing.T) {
	now := time.Date(2026, 7, 12, 13, 30, 0, 0, time.UTC)
	descriptor := validDescriptor(t)
	attempt, fence := runningAttempt(t, descriptor, now)
	completion := readtask.Completion{Fence: fence, Outcome: readtask.CompletionFailed, FailureCode: readtask.FailureTimeout}
	baseline, err := readtask.ProjectCompletion(descriptor, attempt, completion, now)
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*readtask.Descriptor){
		"plan": func(value *readtask.Descriptor) { value.PlanBinding.ManifestDigest = strings.Repeat("a", 64) },
		"runtime": func(value *readtask.Descriptor) {
			value.RuntimeBinding.TargetDigest = strings.Repeat("b", 64)
			rebindDescriptorRuntime(t, value)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changedDescriptor := descriptor
			mutate(&changedDescriptor)
			changedAttempt := attempt
			changedAttempt.PlanBinding = changedDescriptor.PlanBinding
			changedAttempt.RuntimeBinding = changedDescriptor.RuntimeBinding
			changed, changedErr := readtask.ProjectCompletion(changedDescriptor, changedAttempt, completion, now)
			if changedErr != nil {
				t.Fatalf("ProjectCompletion(changed binding) error = %v", changedErr)
			}
			if changed.RequestHash() == baseline.RequestHash() || changed.ReceiptHash() == baseline.ReceiptHash() {
				t.Fatal("binding snapshot change did not change both completion v3 hashes")
			}
		})
	}
	invalidDigest := descriptor
	invalidDigest.RuntimeBinding.RuntimeDigest = strings.Repeat("c", 64)
	if invalidDigest.Validate() == nil {
		t.Fatal("Descriptor accepted a caller-selected aggregate RuntimeDigest")
	}
}
