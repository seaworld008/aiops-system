package domain_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
)

func TestInvestigationValidateEnforcesBoundedStateAndIntegrityMetadata(t *testing.T) {
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	valid := domain.Investigation{
		ID:             "investigation-1",
		WorkspaceID:    "workspace-1",
		IncidentID:     "incident-1",
		Status:         domain.InvestigationQueued,
		ModelStatus:    domain.ModelPending,
		IdempotencyKey: "investigate:incident-1:v1",
		RequestHash:    strings.Repeat("a", 64),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want valid investigation", err)
	}

	for name, mutate := range map[string]func(*domain.Investigation){
		"status":          func(value *domain.Investigation) { value.Status = "UNKNOWN" },
		"model status":    func(value *domain.Investigation) { value.ModelStatus = "UNKNOWN" },
		"uppercase hash":  func(value *domain.Investigation) { value.RequestHash = strings.Repeat("A", 64) },
		"oversized key":   func(value *domain.Investigation) { value.IdempotencyKey = strings.Repeat("a", 129) },
		"unsafe key":      func(value *domain.Investigation) { value.IdempotencyKey = "incident 1" },
		"failure detail":  func(value *domain.Investigation) { value.FailureCode = "raw backend error: timeout" },
		"backward update": func(value *domain.Investigation) { value.UpdatedAt = value.CreatedAt.Add(-time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			item := valid
			mutate(&item)
			if err := item.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want contract rejection")
			}
		})
	}
}

func TestReadTaskAndEvidenceRejectUnsafeOrUnboundedJSON(t *testing.T) {
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	input := json.RawMessage(`{"lookback_minutes":15}`)
	task := domain.ReadTask{
		ID: "task-1", WorkspaceID: "workspace-1", IncidentID: "incident-1", InvestigationID: "investigation-1",
		Key: "metrics", Position: 1, ConnectorID: "prometheus-prod", Operation: "range_query", Input: input,
		InputHash: sha256Hex(input), Status: domain.ReadTaskQueued, CreatedAt: now, UpdatedAt: now,
	}
	if err := task.Validate(); err != nil {
		t.Fatalf("ReadTask.Validate() error = %v", err)
	}
	evidencePayload := json.RawMessage(`{"series_count":3}`)
	evidence := domain.Evidence{
		ID: "evidence-1", WorkspaceID: "workspace-1", IncidentID: "incident-1",
		InvestigationID: "investigation-1", TaskID: "task-1", ConnectorID: "prometheus-prod",
		ContentHash: sha256Hex(evidencePayload), Payload: evidencePayload, CollectedAt: now, CreatedAt: now,
	}
	if err := evidence.Validate(); err != nil {
		t.Fatalf("Evidence.Validate() error = %v", err)
	}

	for name, unsafe := range map[string]json.RawMessage{
		"array":          json.RawMessage(`[]`),
		"credential":     json.RawMessage(`{"nested":{"credential":"redacted"}}`),
		"authorization":  json.RawMessage(`{"headers":{"Authorization":"Bearer redacted"}}`),
		"raw error body": json.RawMessage(`{"raw_error_body":"backend response"}`),
		"oversized":      json.RawMessage(`{"value":"` + strings.Repeat("x", domain.MaxInvestigationJSONBytes) + `"}`),
	} {
		t.Run(name, func(t *testing.T) {
			item := task
			item.Input = unsafe
			item.InputHash = sha256Hex(unsafe)
			if err := item.Validate(); err == nil {
				t.Fatal("ReadTask.Validate() error = nil, want unsafe JSON rejection")
			}
		})
	}
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func TestFeedbackAndRunnerReceiptExposeOnlyBoundedStructuredMetadata(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	feedback := domain.Feedback{
		ID: "feedback-1", WorkspaceID: "workspace-1", IncidentID: "incident-1",
		InvestigationID: "investigation-1", HypothesisID: "hypothesis-1",
		Actor: domain.Actor{Type: domain.ActorHuman, ID: "user-1"}, Verdict: domain.FeedbackConfirmed,
		Details: json.RawMessage(`{"reason_code":"evidence_matches"}`), CreatedAt: now,
	}
	if err := feedback.Validate(); err != nil {
		t.Fatalf("Feedback.Validate() error = %v", err)
	}
	receipt := domain.RunnerEvidenceReceipt{
		ID: "receipt-1", WorkspaceID: "workspace-1", InvestigationID: "investigation-1", TaskID: "task-1",
		RunnerID: "runner-1", ConnectorID: "prometheus-prod", EvidenceID: "evidence-1",
		ContentHash: strings.Repeat("a", 64), IdempotencyKey: "task-1:attempt-1", ReceivedAt: now,
	}
	if err := receipt.Validate(); err != nil {
		t.Fatalf("RunnerEvidenceReceipt.Validate() error = %v", err)
	}

	feedback.Actor.Type = domain.ActorModel
	if err := feedback.Validate(); err == nil {
		t.Fatal("Feedback.Validate() accepted non-human actor")
	}
	receipt.FailureCode = "upstream returned: 401 Authorization: Bearer secret"
	if err := receipt.Validate(); err == nil {
		t.Fatal("RunnerEvidenceReceipt.Validate() accepted raw failure detail")
	}
}

func TestInvestigationAndReadTaskValidateLifecycleShape(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 30, 0, 0, time.UTC)
	queued := domain.Investigation{
		ID: "investigation-1", WorkspaceID: "workspace-1", IncidentID: "incident-1",
		Status: domain.InvestigationQueued, ModelStatus: domain.ModelPending,
		IdempotencyKey: "investigate:1", RequestHash: strings.Repeat("a", 64), CreatedAt: now, UpdatedAt: now,
	}
	queued.StartedAt = now
	if err := queued.Validate(); err == nil {
		t.Fatal("queued Investigation accepted StartedAt")
	}
	running := queued
	running.Status = domain.InvestigationRunning
	running.StartedAt = time.Time{}
	if err := running.Validate(); err == nil {
		t.Fatal("running Investigation accepted missing StartedAt")
	}
	completed := queued
	completed.Status = domain.InvestigationCompleted
	completed.ModelStatus = domain.ModelCompleted
	completed.StartedAt = now
	if err := completed.Validate(); err == nil {
		t.Fatal("completed Investigation accepted missing CompletedAt")
	}

	input := json.RawMessage(`{"lookback_minutes":15}`)
	task := domain.ReadTask{
		ID: "task-1", WorkspaceID: "workspace-1", IncidentID: "incident-1", InvestigationID: "investigation-1",
		Key: "metrics", Position: 1, ConnectorID: "prometheus-prod", Operation: "range_query",
		Input: input, InputHash: sha256Hex(input), Status: domain.ReadTaskQueued, CreatedAt: now, UpdatedAt: now,
	}
	task.EvidenceID = "evidence-1"
	if err := task.Validate(); err == nil {
		t.Fatal("queued ReadTask accepted EvidenceID")
	}
	task.Status = domain.ReadTaskEvidence
	task.StartedAt = now
	task.CompletedAt = now
	task.EvidenceID = ""
	if err := task.Validate(); err == nil {
		t.Fatal("EVIDENCE ReadTask accepted missing EvidenceID")
	}
}
