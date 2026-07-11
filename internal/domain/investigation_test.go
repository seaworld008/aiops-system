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

func TestSafeJSONObjectRejectsSensitivePathsNamesAndValuesWithoutEcho(t *testing.T) {
	const canary = "sensitive-canary-value"
	unsafe := map[string]json.RawMessage{
		"duplicate field hides bearer": json.RawMessage(`{"message":"Bearer ` + canary + `","message":"ok"}`),
		"error body path":              json.RawMessage(`{"error":{"body":"` + canary + `"}}`),
		"nested raw error path":        json.RawMessage(`{"error":{"details":{"body":"raw-error-` + canary + `"}}}`),
		"authorization name value": json.RawMessage(
			`{"headers":[{"name":"Authorization","value":"` + canary + `"}]}`,
		),
		"authorization key value": json.RawMessage(
			`{"headers":[{"key":"Authorization","value":"` + canary + `"}]}`,
		),
		"bearer value":              json.RawMessage(`{"message":"Bearer ` + canary + `"}`),
		"password assignment value": json.RawMessage(`{"message":"password=` + canary + `"}`),
		"cookie value":              json.RawMessage(`{"message":"Cookie: session=` + canary + `"}`),
		"private key value":         json.RawMessage(`{"message":"-----BEGIN PRIVATE KEY-----` + canary + `"}`),
	}
	for name, value := range unsafe {
		t.Run(name, func(t *testing.T) {
			err := domain.ValidateSafeJSONObject(value)
			if err == nil {
				t.Fatal("ValidateSafeJSONObject() error = nil, want sensitive input rejection")
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatalf("error echoed sensitive input: %v", err)
			}
		})
	}
}

func TestValidateSafeJSONObjectRejectsRawInvalidUTF8WithoutEcho(t *testing.T) {
	value := append([]byte(`{"message":"pass`), 0xff)
	value = append(value, []byte(`word=canary"}`)...)

	err := domain.ValidateSafeJSONObject(value)
	if err == nil {
		t.Fatal("ValidateSafeJSONObject() error = nil, want invalid UTF-8 rejection")
	}
	if strings.Contains(err.Error(), "canary") {
		t.Fatalf("ValidateSafeJSONObject() echoed invalid input: %v", err)
	}
}

func TestValidateSafeJSONObjectRejectsReplacementRuneInKeysAndStringsWithoutEcho(t *testing.T) {
	for name, value := range map[string]json.RawMessage{
		"escaped lone surrogate value": json.RawMessage(`{"message":"canary-\ud800"}`),
		"escaped lone surrogate key":   json.RawMessage(`{"\ud800":"canary"}`),
		"replacement rune value":       json.RawMessage(`{"message":"canary-�"}`),
		"replacement rune key":         json.RawMessage(`{"�":"canary"}`),
	} {
		t.Run(name, func(t *testing.T) {
			err := domain.ValidateSafeJSONObject(value)
			if err == nil {
				t.Fatal("ValidateSafeJSONObject() error = nil, want invalid Unicode rejection")
			}
			if strings.Contains(err.Error(), "canary") {
				t.Fatalf("ValidateSafeJSONObject() echoed invalid input: %v", err)
			}
		})
	}
}

func TestEvidenceAttributesRejectSensitiveNamesAndValues(t *testing.T) {
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	payload := json.RawMessage(`{"series_count":3}`)
	valid := domain.Evidence{
		ID: "evidence-1", WorkspaceID: "workspace-1", IncidentID: "incident-1",
		InvestigationID: "investigation-1", TaskID: "task-1", ConnectorID: "prometheus-prod",
		ContentHash: sha256Hex(payload), Payload: payload, CollectedAt: now, CreatedAt: now,
	}
	const canary = "attribute-sensitive-canary"
	unsafe := []map[string]string{
		{"authorization": canary},
		{"credential_ref": canary},
		{"raw_error_body": canary},
		{"secret": canary},
		{"access_token": canary},
		{"password": canary},
		{"name": "Authorization", "value": canary},
		{"message": "Bearer " + canary},
		{"message": "password : " + canary},
	}
	for _, attributes := range unsafe {
		item := valid
		item.Attributes = attributes
		err := item.Validate()
		if err == nil {
			t.Fatalf("Evidence.Validate() accepted unsafe attributes %#v", attributes)
		}
		if strings.Contains(err.Error(), canary) {
			t.Fatalf("Evidence.Validate() echoed sensitive attribute: %v", err)
		}
	}
}

func TestValidSafeTextRejectsCredentialAssignmentVariants(t *testing.T) {
	for name, value := range map[string]string{
		"password":      "password=canary",
		"token":         "TOKEN : canary",
		"secret":        "secret = canary",
		"credential":    "credential:canary",
		"authorization": "authorization = canary",
		"cookie":        "cookie: canary",
		"api key":       "api-key = canary",
		"accessor":      "accessor=canary",
		"private key":   "private.key: canary",
	} {
		t.Run(name, func(t *testing.T) {
			if domain.ValidSafeText(value) {
				t.Fatalf("ValidSafeText(%q) = true, want credential assignment rejection", value)
			}
		})
	}
}

func TestIdempotencyKeyUsesDedicatedLowercaseBoundedGrammar(t *testing.T) {
	for _, valid := range []string{"investigate:incident-1", "task/complete_1", "a.b-c:d/e"} {
		if !domain.ValidIdempotencyKey(valid) {
			t.Fatalf("ValidIdempotencyKey(%q) = false, want true", valid)
		}
	}
	for _, invalid := range []string{
		"Investigate:incident-1", "user@example", "with space", "line\nbreak", "nul\x00byte", strings.Repeat("a", 129),
	} {
		if domain.ValidIdempotencyKey(invalid) {
			t.Fatalf("ValidIdempotencyKey(%q) = true, want false", invalid)
		}
	}
}

func TestInvestigationFailureCodeIsBoundToFailureStates(t *testing.T) {
	now := time.Date(2026, 7, 12, 11, 30, 0, 0, time.UTC)
	queued := domain.Investigation{
		ID: "investigation-1", WorkspaceID: "workspace-1", IncidentID: "incident-1",
		Status: domain.InvestigationQueued, ModelStatus: domain.ModelPending,
		IdempotencyKey: "investigate:1", RequestHash: strings.Repeat("a", 64),
		CreatedAt: now, UpdatedAt: now,
	}
	queued.FailureCode = "internal_failure"
	if err := queued.Validate(); err == nil {
		t.Fatal("QUEUED Investigation accepted FailureCode")
	}

	failed := queued
	failed.Status = domain.InvestigationFailed
	failed.ModelStatus = domain.ModelFailed
	failed.ModelFailureCode = "model_unavailable"
	failed.FailureCode = ""
	failed.CompletedAt = now
	if err := failed.Validate(); err == nil {
		t.Fatal("FAILED Investigation accepted empty FailureCode")
	}
	failed.FailureCode = "internal_failure"
	if err := failed.Validate(); err != nil {
		t.Fatalf("FAILED Investigation valid failure code error = %v", err)
	}
}

func TestCancelledInvestigationUsesDistinctModelCancelledStatus(t *testing.T) {
	now := time.Date(2026, 7, 12, 13, 30, 0, 0, time.UTC)
	cancelled := domain.Investigation{
		ID: "investigation-1", WorkspaceID: "workspace-1", IncidentID: "incident-1",
		Status: domain.InvestigationCancelled, ModelStatus: domain.ModelSkipped, FailureCode: "cancelled",
		IdempotencyKey: "investigate:1", RequestHash: strings.Repeat("a", 64),
		CreatedAt: now, CompletedAt: now, UpdatedAt: now,
	}
	if err := cancelled.Validate(); err == nil {
		t.Fatal("CANCELLED Investigation accepted SKIPPED model status")
	}
	cancelled.ModelStatus = domain.ModelCancelled
	if err := cancelled.Validate(); err != nil {
		t.Fatalf("CANCELLED Investigation with ModelCancelled error = %v", err)
	}
}
