package readtask_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

func TestRecoveryRequestAcceptsTrustedTaskIdentity(t *testing.T) {
	descriptor := validDescriptor(t)
	request := recoveryRequest(descriptor)
	if err := request.Validate(); err != nil {
		t.Fatalf("RecoveryRequest.Validate() error = %v", err)
	}
}

func TestRecoveryResultAcceptsPendingTaskWithoutCommittedFields(t *testing.T) {
	descriptor := validDescriptor(t)
	request := recoveryRequest(descriptor)
	for _, status := range []domain.ReadTaskStatus{domain.ReadTaskQueued, domain.ReadTaskRunning} {
		result := readtask.RecoveryResult{
			State: readtask.RecoveryPending, InvestigationID: descriptor.InvestigationID,
			TaskID: descriptor.TaskID, Position: descriptor.Position, TaskStatus: status,
		}
		if err := result.ValidateAgainst(request); err != nil {
			t.Fatalf("RecoveryResult.ValidateAgainst(%q) error = %v", status, err)
		}
	}
}

func TestRecoveryResultAcceptsStrictCommittedTerminalUnion(t *testing.T) {
	descriptor := validDescriptor(t)
	request := recoveryRequest(descriptor)
	common := readtask.RecoveryResult{
		State: readtask.RecoveryCommitted, InvestigationID: descriptor.InvestigationID,
		TaskID: descriptor.TaskID, Position: descriptor.Position,
		ReceiptID: "13131313-1313-4131-8131-131313131313", ReceiptHash: strings.Repeat("a", 64),
	}
	tests := []struct {
		name        string
		taskStatus  domain.ReadTaskStatus
		evidenceID  string
		contentHash string
	}{
		{"evidence", domain.ReadTaskEvidence, "12121212-1212-4121-8121-121212121212", strings.Repeat("b", 64)},
		{"failed", domain.ReadTaskFailed, "", ""},
		{"cancelled", domain.ReadTaskCancelled, "", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := common
			result.TaskStatus = test.taskStatus
			result.EvidenceID = test.evidenceID
			result.ContentHash = test.contentHash
			if err := result.ValidateAgainst(request); err != nil {
				t.Fatalf("RecoveryResult.ValidateAgainst() error = %v", err)
			}
		})
	}
}

func TestRecoveryResultAcceptsControlCancellationWithoutReceipt(t *testing.T) {
	descriptor := validDescriptor(t)
	request := recoveryRequest(descriptor)
	result := readtask.RecoveryResult{
		State: readtask.RecoveryControlCancelled, InvestigationID: descriptor.InvestigationID,
		TaskID: descriptor.TaskID, Position: descriptor.Position, TaskStatus: domain.ReadTaskCancelled,
	}
	if err := result.ValidateAgainst(request); err != nil {
		t.Fatalf("RecoveryResult.ValidateAgainst() error = %v", err)
	}
}

func TestRecoveryDomainRenderingRedactsIdentityProvenanceAndReceipts(t *testing.T) {
	now := time.Date(2026, 7, 12, 15, 30, 0, 123456000, time.UTC)
	descriptor := validDescriptor(t)
	request := recoveryRequest(descriptor)
	committed := committedEvidenceResult(t, descriptor, now)
	recovery := readtask.RecoveryResult{
		State: readtask.RecoveryCommitted, InvestigationID: descriptor.InvestigationID,
		TaskID: descriptor.TaskID, Position: descriptor.Position, TaskStatus: domain.ReadTaskEvidence,
		EvidenceID: committed.EvidenceID, ContentHash: committed.Receipt.ContentHash,
		ReceiptID: committed.ReceiptID, ReceiptHash: committed.Receipt.ReceiptHash,
	}
	for name, value := range map[string]any{
		"request": request, "committed": committed, "recovery": recovery,
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(value)
			if err != nil || !bytes.Equal(encoded, []byte(`{"redacted":true}`)) {
				t.Fatalf("json.Marshal() = %s, %v", encoded, err)
			}
			rendered := fmt.Sprintf("%+v %#v", value, value)
			for _, secret := range []string{
				descriptor.TenantID, descriptor.WorkspaceID, descriptor.IncidentID,
				descriptor.PlanBinding.ManifestDigest, committed.Attempt.RunnerID,
				committed.Attempt.Certificate.SHA256, committed.Attempt.TokenSHA256,
				committed.Receipt.ReceiptHash,
			} {
				if strings.Contains(rendered, secret) {
					t.Fatalf("rendering leaked provenance %q: %s", secret, rendered)
				}
			}
		})
	}

	for name, target := range map[string]any{
		"request":   &readtask.RecoveryRequest{},
		"committed": &readtask.CommittedResult{},
		"recovery":  &readtask.RecoveryResult{},
	} {
		t.Run("unmarshal "+name, func(t *testing.T) {
			if err := json.Unmarshal([]byte(`{}`), target); err == nil {
				t.Fatal("UnmarshalJSON() accepted wire construction")
			}
		})
	}
}

func TestRecoveryRequestRejectsInvalidComparisonIdentityAndPlan(t *testing.T) {
	descriptor := validDescriptor(t)
	baseline := recoveryRequest(descriptor)
	tests := []struct {
		name   string
		mutate func(*readtask.RecoveryRequest)
	}{
		{"tenant", func(value *readtask.RecoveryRequest) { value.TenantID = "tenant" }},
		{"workspace", func(value *readtask.RecoveryRequest) { value.WorkspaceID = "workspace" }},
		{"incident", func(value *readtask.RecoveryRequest) { value.IncidentID = "incident" }},
		{"investigation", func(value *readtask.RecoveryRequest) { value.InvestigationID = "investigation" }},
		{"task", func(value *readtask.RecoveryRequest) { value.TaskID = "task" }},
		{"position zero", func(value *readtask.RecoveryRequest) { value.Position = 0 }},
		{"position too large", func(value *readtask.RecoveryRequest) { value.Position = 13 }},
		{"plan schema", func(value *readtask.RecoveryRequest) { value.PlanBinding.SchemaVersion = "legacy-plan.v0" }},
		{"plan digest", func(value *readtask.RecoveryRequest) { value.PlanBinding.TasksHash = strings.Repeat("A", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := baseline
			test.mutate(&request)
			if err := request.Validate(); err == nil {
				t.Fatal("RecoveryRequest.Validate() accepted invalid identity")
			}
		})
	}
}

func TestCommittedResultRejectsTamperedLegacyOrCrossUnionProvenance(t *testing.T) {
	now := time.Date(2026, 7, 12, 15, 45, 0, 123456000, time.UTC)
	descriptor := validDescriptor(t)
	baseline := committedEvidenceResult(t, descriptor, now)
	tests := []struct {
		name   string
		mutate func(*readtask.CommittedResult)
	}{
		{"legacy receipt", func(value *readtask.CommittedResult) { value.Receipt.SchemaVersion = "runner-evidence.v2" }},
		{"request hash version", func(value *readtask.CommittedResult) {
			value.Receipt.RequestHashVersion = "read-task-completion-request.v2"
		}},
		{"receipt hash version", func(value *readtask.CommittedResult) {
			value.Receipt.ReceiptHashVersion = "read-task-completion-receipt.v2"
		}},
		{"attempt request hash version", func(value *readtask.CommittedResult) {
			value.Attempt.RequestHashVersion = "read-task-completion-request.v2"
		}},
		{"request hash", func(value *readtask.CommittedResult) { value.Receipt.RequestHash = strings.Repeat("9", 64) }},
		{"receipt hash", func(value *readtask.CommittedResult) { value.Receipt.ReceiptHash = strings.Repeat("9", 64) }},
		{"attempt plan", func(value *readtask.CommittedResult) {
			value.Attempt.PlanBinding.ManifestDigest = strings.Repeat("9", 64)
		}},
		{"receipt plan", func(value *readtask.CommittedResult) {
			value.Receipt.PlanBinding.ProfileDigest = strings.Repeat("9", 64)
		}},
		{"attempt runtime", func(value *readtask.CommittedResult) {
			value.Attempt.RuntimeBinding.TargetDigest = strings.Repeat("9", 64)
		}},
		{"receipt runtime", func(value *readtask.CommittedResult) {
			value.Receipt.RuntimeBinding.ExecutorDigest = strings.Repeat("9", 64)
		}},
		{"wrong task union", func(value *readtask.CommittedResult) { value.TaskStatus = domain.ReadTaskFailed }},
		{"missing Evidence ID", func(value *readtask.CommittedResult) { value.EvidenceID = "" }},
		{"invalid receipt ID", func(value *readtask.CommittedResult) { value.ReceiptID = "receipt" }},
		{"non-terminal attempt", func(value *readtask.CommittedResult) { value.Attempt.Status = readtask.AttemptRunning }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := baseline
			test.mutate(&result)
			if err := result.ValidateAgainst(descriptor); err == nil {
				t.Fatal("CommittedResult.ValidateAgainst() accepted tampered provenance")
			}
		})
	}
}

func TestRecoveryResultRejectsStatePollutionAndRequestMismatch(t *testing.T) {
	descriptor := validDescriptor(t)
	request := recoveryRequest(descriptor)
	pending := readtask.RecoveryResult{
		State: readtask.RecoveryPending, InvestigationID: descriptor.InvestigationID,
		TaskID: descriptor.TaskID, Position: descriptor.Position, TaskStatus: domain.ReadTaskRunning,
	}
	committed := readtask.RecoveryResult{
		State: readtask.RecoveryCommitted, InvestigationID: descriptor.InvestigationID,
		TaskID: descriptor.TaskID, Position: descriptor.Position, TaskStatus: domain.ReadTaskEvidence,
		EvidenceID: "12121212-1212-4121-8121-121212121212", ContentHash: strings.Repeat("b", 64),
		ReceiptID: "13131313-1313-4131-8131-131313131313", ReceiptHash: strings.Repeat("a", 64),
	}
	controlCancelled := readtask.RecoveryResult{
		State: readtask.RecoveryControlCancelled, InvestigationID: descriptor.InvestigationID,
		TaskID: descriptor.TaskID, Position: descriptor.Position, TaskStatus: domain.ReadTaskCancelled,
	}
	tests := []struct {
		name   string
		value  readtask.RecoveryResult
		mutate func(*readtask.RecoveryResult)
	}{
		{"unknown state", pending, func(value *readtask.RecoveryResult) { value.State = "UNKNOWN" }},
		{"investigation mismatch", pending, func(value *readtask.RecoveryResult) { value.InvestigationID = "ffffffff-ffff-4fff-8fff-ffffffffffff" }},
		{"task mismatch", pending, func(value *readtask.RecoveryResult) { value.TaskID = "ffffffff-ffff-4fff-8fff-ffffffffffff" }},
		{"position mismatch", pending, func(value *readtask.RecoveryResult) { value.Position++ }},
		{"pending terminal", pending, func(value *readtask.RecoveryResult) { value.TaskStatus = domain.ReadTaskEvidence }},
		{"pending Evidence", pending, func(value *readtask.RecoveryResult) { value.EvidenceID = "12121212-1212-4121-8121-121212121212" }},
		{"pending receipt", pending, func(value *readtask.RecoveryResult) { value.ReceiptHash = strings.Repeat("a", 64) }},
		{"committed active", committed, func(value *readtask.RecoveryResult) { value.TaskStatus = domain.ReadTaskRunning }},
		{"committed missing receipt", committed, func(value *readtask.RecoveryResult) { value.ReceiptID = "" }},
		{"committed bad receipt hash", committed, func(value *readtask.RecoveryResult) { value.ReceiptHash = strings.Repeat("A", 64) }},
		{"committed Evidence missing hash", committed, func(value *readtask.RecoveryResult) { value.ContentHash = "" }},
		{"committed failure with Evidence", committed, func(value *readtask.RecoveryResult) { value.TaskStatus = domain.ReadTaskFailed }},
		{"control cancel wrong status", controlCancelled, func(value *readtask.RecoveryResult) { value.TaskStatus = domain.ReadTaskFailed }},
		{"control cancel receipt", controlCancelled, func(value *readtask.RecoveryResult) { value.ReceiptID = "13131313-1313-4131-8131-131313131313" }},
		{"control cancel Evidence", controlCancelled, func(value *readtask.RecoveryResult) { value.ContentHash = strings.Repeat("b", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.value
			test.mutate(&result)
			if err := result.ValidateAgainst(request); err == nil {
				t.Fatal("RecoveryResult.ValidateAgainst() accepted invalid state union")
			}
		})
	}

	invalidRequest := request
	invalidRequest.TenantID = "tenant"
	if err := pending.ValidateAgainst(invalidRequest); err == nil {
		t.Fatal("RecoveryResult.ValidateAgainst() accepted an invalid comparison request")
	}
}

func TestCommittedResultAcceptsReceiptOnlyEvidence(t *testing.T) {
	now := time.Date(2026, 7, 12, 15, 0, 0, 123456000, time.UTC)
	descriptor := validDescriptor(t)
	attempt, fence := runningAttempt(t, descriptor, now)
	projection, err := readtask.ProjectCompletion(descriptor, attempt, readtask.Completion{
		Fence: fence, Outcome: readtask.CompletionEvidence,
		Evidence: &readtask.EvidenceCompletion{
			CollectedAt: now, Items: []json.RawMessage{json.RawMessage(`{"value":1}`)},
		},
	}, now)
	if err != nil {
		t.Fatalf("ProjectCompletion() error = %v", err)
	}
	completed := completedAttempt(attempt, projection, now)
	result := readtask.CommittedResult{
		Attempt: completed, Receipt: projection.Receipt(), TaskStatus: domain.ReadTaskEvidence,
		EvidenceID: "12121212-1212-4121-8121-121212121212",
		ReceiptID:  "13131313-1313-4131-8131-131313131313",
	}
	if err := result.ValidateAgainst(descriptor); err != nil {
		t.Fatalf("CommittedResult.ValidateAgainst() error = %v", err)
	}
}

func TestCommittedResultAcceptsReceiptOnlyFailureAndCancellation(t *testing.T) {
	now := time.Date(2026, 7, 12, 15, 15, 0, 123456000, time.UTC)
	descriptor := validDescriptor(t)
	tests := []struct {
		name        string
		outcome     readtask.CompletionOutcome
		failureCode readtask.FailureCode
		taskStatus  domain.ReadTaskStatus
	}{
		{"failed", readtask.CompletionFailed, readtask.FailureTimeout, domain.ReadTaskFailed},
		{"cancelled", readtask.CompletionCancelled, readtask.FailureCancelled, domain.ReadTaskCancelled},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attempt, fence := runningAttempt(t, descriptor, now)
			projection, err := readtask.ProjectCompletion(descriptor, attempt, readtask.Completion{
				Fence: fence, Outcome: test.outcome, FailureCode: test.failureCode,
			}, now)
			if err != nil {
				t.Fatalf("ProjectCompletion() error = %v", err)
			}
			result := readtask.CommittedResult{
				Attempt: completedAttempt(attempt, projection, now), Receipt: projection.Receipt(),
				TaskStatus: test.taskStatus, ReceiptID: "13131313-1313-4131-8131-131313131313",
			}
			if err := result.ValidateAgainst(descriptor); err != nil {
				t.Fatalf("CommittedResult.ValidateAgainst() error = %v", err)
			}
		})
	}
}

func completedAttempt(
	attempt readtask.Attempt,
	projection readtask.ProjectedCompletion,
	terminalAt time.Time,
) readtask.Attempt {
	attempt.Status = readtask.AttemptCompleted
	attempt.TerminalAt = terminalAt
	attempt.UpdatedAt = terminalAt
	attempt.RequestHash = projection.RequestHash()
	attempt.ReceiptHash = projection.ReceiptHash()
	attempt.RequestHashVersion = readtask.CompletionRequestHashVersionV3
	attempt.ReceiptHashVersion = readtask.CompletionReceiptHashVersionV3
	return attempt
}

func committedEvidenceResult(
	t *testing.T,
	descriptor readtask.Descriptor,
	now time.Time,
) readtask.CommittedResult {
	t.Helper()
	attempt, fence := runningAttempt(t, descriptor, now)
	projection, err := readtask.ProjectCompletion(descriptor, attempt, readtask.Completion{
		Fence: fence, Outcome: readtask.CompletionEvidence,
		Evidence: &readtask.EvidenceCompletion{
			CollectedAt: now, Items: []json.RawMessage{json.RawMessage(`{"value":1}`)},
		},
	}, now)
	if err != nil {
		t.Fatalf("ProjectCompletion() error = %v", err)
	}
	return readtask.CommittedResult{
		Attempt: completedAttempt(attempt, projection, now), Receipt: projection.Receipt(),
		TaskStatus: domain.ReadTaskEvidence, EvidenceID: "12121212-1212-4121-8121-121212121212",
		ReceiptID: "13131313-1313-4131-8131-131313131313",
	}
}

func recoveryRequest(descriptor readtask.Descriptor) readtask.RecoveryRequest {
	return readtask.RecoveryRequest{
		TenantID: descriptor.TenantID, WorkspaceID: descriptor.WorkspaceID,
		IncidentID: descriptor.IncidentID, InvestigationID: descriptor.InvestigationID,
		TaskID: descriptor.TaskID, Position: descriptor.Position, PlanBinding: descriptor.PlanBinding,
	}
}
