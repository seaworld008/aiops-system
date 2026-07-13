package readtask_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

func TestProjectCompletionBuildsCanonicalServerOwnedEvidenceAndHashes(t *testing.T) {
	now := time.Date(2026, 7, 12, 8, 30, 0, 123456000, time.UTC)
	descriptor := validDescriptor(t)
	attempt, fence := runningAttempt(t, descriptor, now)
	completion := readtask.Completion{
		Fence: fence, Outcome: readtask.CompletionEvidence,
		Evidence: &readtask.EvidenceCompletion{
			CollectedAt: now.Add(-250 * time.Millisecond),
			Items: []json.RawMessage{
				json.RawMessage(`{"value":1,"labels":{"instance":"a"}}`),
				json.RawMessage(` { "labels": {"instance":"b"}, "value": 2 } `),
			},
		},
	}
	projected, err := readtask.ProjectCompletion(descriptor, attempt, completion, now)
	if err != nil {
		t.Fatalf("ProjectCompletion() error = %v", err)
	}
	if projected.Outcome() != readtask.CompletionEvidence || projected.ContentHash() == "" ||
		projected.RequestHash() == "" || projected.ReceiptHash() == "" || projected.FailureCode() != "" ||
		projected.IdempotencyKey() != "read-task:"+descriptor.TaskID+":7" {
		t.Fatalf("ProjectedCompletion = outcome=%q content=%q request=%q receipt=%q failure=%q",
			projected.Outcome(), projected.ContentHash(), projected.RequestHash(), projected.ReceiptHash(), projected.FailureCode())
	}
	payload := projected.Payload()
	canonical, err := jsoncanonicalizer.Transform(payload)
	if err != nil || !bytes.Equal(payload, canonical) {
		t.Fatalf("Payload is not canonical JCS: %s, %v", payload, err)
	}
	var document struct {
		Source      string            `json:"source"`
		CollectedAt time.Time         `json:"collected_at"`
		ItemCount   int               `json:"item_count"`
		Truncated   bool              `json:"truncated"`
		Items       []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(payload, &document); err != nil || document.Source != descriptor.ConnectorID ||
		document.ItemCount != 2 || document.Truncated || len(document.Items) != 2 {
		t.Fatalf("projected evidence payload = %s, %v", payload, err)
	}
	attributes := projected.Attributes()
	if attributes["source"] != descriptor.ConnectorID || attributes["operation"] != descriptor.Operation ||
		attributes["item_count"] != "2" || attributes["truncated"] != "false" {
		t.Fatalf("projected attributes = %#v", attributes)
	}
	attributes["source"] = "mutated"
	payload[0] = 'X'
	if projected.Attributes()["source"] != descriptor.ConnectorID || projected.Payload()[0] == 'X' {
		t.Fatal("ProjectedCompletion getter exposed shared mutable state")
	}
	if err := projected.ValidateAgainst(descriptor, attempt); err != nil {
		t.Fatalf("ValidateAgainst() error = %v", err)
	}
	receiptJSON, err := json.Marshal(projected.Receipt())
	if err != nil {
		t.Fatal(err)
	}
	var receiptDocument map[string]any
	if err := json.Unmarshal(receiptJSON, &receiptDocument); err != nil ||
		receiptDocument["schema_version"] != readtask.RunnerEvidenceSchemaVersionV3 || receiptDocument["lease_epoch"] != "7" ||
		receiptDocument["scope_revision"] != "3" || receiptDocument["service_id"] != descriptor.ServiceID ||
		bytes.Contains(receiptJSON, []byte(testToken)) {
		t.Fatalf("safe receipt wire = %s, %v", receiptJSON, err)
	}
	terminal := attempt
	terminal.Status = readtask.AttemptCompleted
	terminal.TerminalAt = now
	terminal.RequestHash = projected.RequestHash()
	terminal.ReceiptHash = projected.ReceiptHash()
	terminal.RequestHashVersion = readtask.CompletionRequestHashVersionV3
	terminal.ReceiptHashVersion = readtask.CompletionReceiptHashVersionV3
	completionResult := readtask.CompletionResult{
		Attempt: terminal, Projection: projected,
		EvidenceID: "12121212-1212-4121-8121-121212121212",
		ReceiptID:  "13131313-1313-4131-8131-131313131313",
	}
	if err := completionResult.ValidateAgainst(descriptor); err != nil {
		t.Fatalf("CompletionResult.ValidateAgainst() error = %v", err)
	}
	changedService := descriptor
	changedService.ServiceID = "c2000000-0000-4000-8000-000000000002"
	if err := projected.ValidateAgainst(changedService, attempt); err == nil {
		t.Fatal("ProjectedCompletion accepted a different trusted service binding")
	}
	rebindDescriptorRuntime(t, &changedService)
	changedServiceAttempt := attempt
	changedServiceAttempt.RuntimeBinding = changedService.RuntimeBinding
	changedServiceProjection, err := readtask.ProjectCompletion(changedService, changedServiceAttempt, completion, now)
	if err != nil || changedServiceProjection.RequestHash() == projected.RequestHash() ||
		changedServiceProjection.ReceiptHash() == projected.ReceiptHash() {
		t.Fatalf("service binding did not change completion hashes: %#v, %v", changedServiceProjection.Receipt(), err)
	}
	for _, value := range []any{projected, completionResult} {
		encoded, marshalErr := json.Marshal(value)
		rendered := fmt.Sprintf("%+v %#v", value, value)
		if marshalErr != nil || bytes.Contains(encoded, []byte(`"instance"`)) || strings.Contains(rendered, "instance") {
			t.Fatalf("projected completion rendering leaked Evidence: %s / %s / %v", encoded, rendered, marshalErr)
		}
	}
	replayedProjection, err := readtask.ProjectCompletion(descriptor, terminal, completion, projected.ReceivedAt())
	if err != nil || replayedProjection.RequestHash() != projected.RequestHash() ||
		replayedProjection.ReceiptHash() != projected.ReceiptHash() {
		t.Fatalf("committed completion replay changed projection: %#v, %v", replayedProjection.Receipt(), err)
	}

	equivalent := completion
	equivalent.Evidence = &readtask.EvidenceCompletion{
		CollectedAt: now.Add(-250 * time.Millisecond),
		Items: []json.RawMessage{
			json.RawMessage(` { "labels": { "instance": "a" }, "value": 1 } `),
			json.RawMessage(`{"value":2,"labels":{"instance":"b"}}`),
		},
	}
	second, err := readtask.ProjectCompletion(descriptor, attempt, equivalent, now)
	if err != nil || second.ContentHash() != projected.ContentHash() || second.RequestHash() != projected.RequestHash() ||
		second.ReceiptHash() != projected.ReceiptHash() {
		t.Fatalf("semantic equivalent projection changed hashes: %#v, %v", second.Receipt(), err)
	}
}

func TestProjectCompletionEnforcesBoundsExpiryAndDatabaseReceiptTime(t *testing.T) {
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	descriptor := validDescriptor(t)
	attempt, fence := runningAttempt(t, descriptor, now)
	valid := readtask.Completion{
		Fence: fence, Outcome: readtask.CompletionEvidence,
		Evidence: &readtask.EvidenceCompletion{CollectedAt: now, Items: []json.RawMessage{}},
	}
	projected, err := readtask.ProjectCompletion(descriptor, attempt, valid, now)
	if err != nil {
		t.Fatal(err)
	}
	databaseTime := now.Add(time.Microsecond)
	bound, err := projected.WithReceivedAt(databaseTime, descriptor, attempt)
	if err != nil || !bound.ReceivedAt().Equal(databaseTime) || bound.RequestHash() != projected.RequestHash() ||
		bound.ReceiptHash() != projected.ReceiptHash() || !projected.ReceivedAt().Equal(now) {
		t.Fatalf("WithReceivedAt() = time=%v request=%q receipt=%q, %v",
			bound.ReceivedAt(), bound.RequestHash(), bound.ReceiptHash(), err)
	}
	if _, err := readtask.ProjectCompletion(descriptor, attempt, valid, attempt.LeaseExpiresAt); err == nil {
		t.Fatal("ProjectCompletion() accepted transition exactly at lease expiry")
	}
	ahead := valid
	ahead.Evidence = &readtask.EvidenceCompletion{
		CollectedAt: now.Add(readtask.MaxEvidenceClockSkew), Items: []json.RawMessage{},
	}
	aheadProjection, err := readtask.ProjectCompletion(descriptor, attempt, ahead, now)
	if err != nil {
		t.Fatalf("ProjectCompletion(bounded ahead clock) error = %v", err)
	}
	if _, err := aheadProjection.WithReceivedAt(now.Add(-time.Microsecond), descriptor, attempt); err == nil {
		t.Fatal("WithReceivedAt() accepted source time beyond the clock-skew bound")
	}
	completed := attempt
	completed.Status = readtask.AttemptCompleted
	completed.TerminalAt = attempt.LeaseExpiresAt.Add(-time.Microsecond)
	completed.UpdatedAt = completed.TerminalAt
	completed.RequestHash = projected.RequestHash()
	completed.ReceiptHash = projected.ReceiptHash()
	completed.RequestHashVersion = readtask.CompletionRequestHashVersionV3
	completed.ReceiptHashVersion = readtask.CompletionReceiptHashVersionV3
	lateDatabaseACK := attempt.LeaseExpiresAt.Add(time.Microsecond)
	lateBound, err := projected.WithReceivedAt(lateDatabaseACK, descriptor, completed)
	if err != nil || !lateBound.ReceivedAt().Equal(lateDatabaseACK) || lateBound.ReceiptHash() != projected.ReceiptHash() {
		t.Fatalf("WithReceivedAt(late DB ACK) = time=%v hash=%q, %v", lateBound.ReceivedAt(), lateBound.ReceiptHash(), err)
	}
	replayedAfterExpiry, err := readtask.ProjectCompletion(descriptor, completed, valid, lateDatabaseACK)
	if err != nil || replayedAfterExpiry.RequestHash() != projected.RequestHash() ||
		replayedAfterExpiry.ReceiptHash() != projected.ReceiptHash() {
		t.Fatalf("completed replay after lease expiry changed result: %#v, %v", replayedAfterExpiry.Receipt(), err)
	}
	invalidTerminal := completed
	invalidTerminal.TerminalAt = attempt.LeaseExpiresAt
	invalidTerminal.UpdatedAt = invalidTerminal.TerminalAt
	if err := invalidTerminal.ValidateAgainst(descriptor); err == nil {
		t.Fatal("AttemptCompleted accepted terminal transition exactly at lease expiry")
	}

	tooMany := make([]json.RawMessage, readtask.MaxEvidenceItems+1)
	for index := range tooMany {
		tooMany[index] = json.RawMessage(`{}`)
	}
	deep := json.RawMessage(strings.Repeat(`{"child":`, readtask.MaxEvidenceJSONDepth) + `{}` + strings.Repeat(`}`, readtask.MaxEvidenceJSONDepth))
	for name, items := range map[string][]json.RawMessage{"too many": tooMany, "too deep": {deep}} {
		t.Run(name, func(t *testing.T) {
			completion := valid
			completion.Evidence = &readtask.EvidenceCompletion{CollectedAt: now, Items: items}
			if _, err := readtask.ProjectCompletion(descriptor, attempt, completion, now); err == nil {
				t.Fatal("ProjectCompletion() accepted unbounded items")
			}
		})
	}
}

func TestProjectCompletionAllowsOnlyBoundedRunnerClockSkew(t *testing.T) {
	now := time.Date(2026, 7, 12, 10, 30, 0, 0, time.UTC)
	descriptor := validDescriptor(t)
	attempt, fence := runningAttempt(t, descriptor, now)

	for name, collectedAt := range map[string]time.Time{
		"runner behind database":   attempt.StartedAt.Add(-readtask.MaxEvidenceClockSkew),
		"runner ahead of database": now.Add(readtask.MaxEvidenceClockSkew),
	} {
		t.Run(name, func(t *testing.T) {
			completion := readtask.Completion{
				Fence: fence, Outcome: readtask.CompletionEvidence,
				Evidence: &readtask.EvidenceCompletion{CollectedAt: collectedAt, Items: []json.RawMessage{}},
			}
			if _, err := readtask.ProjectCompletion(descriptor, attempt, completion, now); err != nil {
				t.Fatalf("ProjectCompletion() rejected bounded clock skew: %v", err)
			}
		})
	}

	for name, collectedAt := range map[string]time.Time{
		"runner too far behind database":   attempt.StartedAt.Add(-readtask.MaxEvidenceClockSkew - time.Microsecond),
		"runner too far ahead of database": now.Add(readtask.MaxEvidenceClockSkew + time.Microsecond),
	} {
		t.Run(name, func(t *testing.T) {
			completion := readtask.Completion{
				Fence: fence, Outcome: readtask.CompletionEvidence,
				Evidence: &readtask.EvidenceCompletion{CollectedAt: collectedAt, Items: []json.RawMessage{}},
			}
			if _, err := readtask.ProjectCompletion(descriptor, attempt, completion, now); err == nil {
				t.Fatal("ProjectCompletion() accepted excessive Runner clock skew")
			}
		})
	}
}

func TestProjectCompletionRejectsUntrustedShapeAndKeepsFailuresBounded(t *testing.T) {
	now := time.Date(2026, 7, 12, 9, 0, 0, 0, time.UTC)
	descriptor := validDescriptor(t)
	attempt, fence := runningAttempt(t, descriptor, now)

	for name, completion := range map[string]readtask.Completion{
		"collected before start": {
			Fence: fence, Outcome: readtask.CompletionEvidence,
			Evidence: &readtask.EvidenceCompletion{
				CollectedAt: attempt.StartedAt.Add(-readtask.MaxEvidenceClockSkew - time.Microsecond),
				Items:       []json.RawMessage{},
			},
		},
		"failure code not allowlisted": {
			Fence: fence, Outcome: readtask.CompletionFailed,
			FailureCode: "dial_tcp_secret_host_refused",
		},
		"cancelled with failed code": {
			Fence: fence, Outcome: readtask.CompletionCancelled,
			FailureCode: readtask.FailureTimeout,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readtask.ProjectCompletion(descriptor, attempt, completion, now); err == nil {
				t.Fatal("ProjectCompletion() accepted unsafe completion")
			}
		})
	}

	for _, code := range []readtask.FailureCode{
		readtask.FailureConnectorUnavailable, readtask.FailureRateLimited, readtask.FailureTimeout,
		readtask.FailureAuthentication, readtask.FailurePermissionDenied, readtask.FailureInvalidResponse,
		readtask.FailureResultRejected, readtask.FailureUnknown,
	} {
		completion := readtask.Completion{
			Fence: fence, Outcome: readtask.CompletionFailed, FailureCode: code,
		}
		projected, err := readtask.ProjectCompletion(descriptor, attempt, completion, now)
		if err != nil || projected.FailureCode() != code || len(projected.Payload()) != 0 || projected.Attributes() != nil {
			t.Fatalf("ProjectCompletion(%q) = %#v, %v", code, projected.Receipt(), err)
		}
		encoded, marshalErr := json.Marshal(projected.Receipt())
		if marshalErr != nil || bytes.Contains(encoded, []byte("secret")) {
			t.Fatalf("failure receipt is unsafe: %s, %v", encoded, marshalErr)
		}
	}
}

func runningAttempt(t *testing.T, descriptor readtask.Descriptor, now time.Time) (readtask.Attempt, readtask.Fence) {
	t.Helper()
	fence, err := readtask.NewFence(descriptor.TaskID, testRunnerID, []byte(testToken), 7)
	if err != nil {
		t.Fatal(err)
	}
	tokenDigest := sha256.Sum256([]byte(testToken))
	attempt := readtask.Attempt{
		TaskID: descriptor.TaskID, RunnerID: testRunnerID, ScopeRevision: 3,
		Certificate: readtask.CertificateBinding{SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("certificate"))), NotAfter: now.Add(time.Minute)},
		TokenSHA256: fmt.Sprintf("%x", tokenDigest), Epoch: 7, Status: readtask.AttemptRunning,
		LeaseAcquiredAt: now.Add(-time.Second), LastHeartbeatAt: now.Add(-time.Second),
		LeaseExpiresAt: now.Add(30 * time.Second), StartedAt: now.Add(-500 * time.Millisecond), UpdatedAt: now,
		PlanBinding: descriptor.PlanBinding, RuntimeBinding: descriptor.RuntimeBinding,
	}
	if err := attempt.ValidateAgainst(descriptor); err != nil {
		t.Fatalf("running Attempt.ValidateAgainst() error = %v", err)
	}
	return attempt, fence
}
