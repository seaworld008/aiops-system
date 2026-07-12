package readexecutor

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/readtask"
)

func TestExecutionStartAndResultAreOpaqueDetachedCapabilities(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 12, 12, 0, 0, 123456000, time.UTC)
	start, err := NewExecutionStart("70000000-0000-4000-8000-000000000007", 2, 3, now)
	if err != nil || !start.ready() {
		t.Fatalf("NewExecutionStart() = %#v, %v", start, err)
	}
	copyStart := *start
	if copyStart.ready() {
		t.Fatal("copied ExecutionStart became ready")
	}
	for _, invalid := range []struct {
		taskID string
		epoch  int64
		scope  int64
		at     time.Time
	}{
		{"bad", 2, 3, now},
		{"70000000-0000-4000-8000-000000000007", 0, 3, now},
		{"70000000-0000-4000-8000-000000000007", 2, 0, now},
		{"70000000-0000-4000-8000-000000000007", 2, 3, time.Time{}},
	} {
		if candidate, err := NewExecutionStart(invalid.taskID, invalid.epoch, invalid.scope, invalid.at); candidate != nil ||
			!errors.Is(err, ErrStartRejected) {
			t.Fatalf("NewExecutionStart(invalid) = %#v, %v", candidate, err)
		}
	}

	evidence := readtask.EvidenceCompletion{CollectedAt: now, Items: []json.RawMessage{json.RawMessage(`{"ok":true}`)}}
	result := newEvidenceResult(evidence)
	evidence.Items[0][2] = 'x'
	got, ok := result.Evidence()
	if !ok || string(got.Items[0]) != `{"ok":true}` || !result.Valid() {
		t.Fatalf("detached evidence result = %#v / %t", got, ok)
	}
	got.Items[0][2] = 'y'
	again, _ := result.Evidence()
	if string(again.Items[0]) != `{"ok":true}` {
		t.Fatal("Evidence() returned shared storage")
	}
	for _, code := range []readtask.FailureCode{
		readtask.FailureConnectorUnavailable, readtask.FailureRateLimited, readtask.FailureTimeout,
		readtask.FailureAuthentication, readtask.FailurePermissionDenied, readtask.FailureInvalidResponse,
		readtask.FailureResultRejected, readtask.FailureUnknown, readtask.FailureCancelled,
	} {
		if result := newFailureResult(code); !result.Valid() || result.FailureCode() != code {
			t.Fatalf("failure result %q is invalid", code)
		}
	}

	canary := "result-secret-canary"
	encoded, marshalErr := json.Marshal(result)
	rendered := fmt.Sprintf("%v %+v %#v / %v %+v %#v", start, start, start, result, result, result)
	if marshalErr != nil || string(encoded) != `{"redacted":true}` || strings.Contains(rendered, canary) ||
		strings.Contains(rendered, "70000000") || strings.Contains(rendered, "ok") {
		t.Fatalf("opaque capability rendering = %s / %s / %v", encoded, rendered, marshalErr)
	}
}
