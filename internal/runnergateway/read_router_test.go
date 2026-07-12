package runnergateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/readgateway"
	"github.com/seaworld008/aiops-system/internal/readtask"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
)

const testReadTaskID = "11111111-1111-4111-8111-111111111111"

func TestNewRouterWithReadTasksRequiresIndependentBackend(t *testing.T) {
	t.Parallel()
	identity := testIdentity(t)
	var typedNil *fakeReadTaskBackend
	for _, backend := range []ReadTaskBackend{nil, typedNil} {
		handler, err := NewRouterWithReadTasks(&staticVerifier{identity: identity}, &fakeBackend{}, backend)
		if handler != nil || err == nil {
			t.Fatalf("NewRouterWithReadTasks(%T) = %#v, %v", backend, handler, err)
		}
	}
}

func TestReadTaskRouterSupportsBoundClaimStartHeartbeatReleaseAndComplete(t *testing.T) {
	t.Parallel()
	identity := testIdentity(t)
	fixture := newReadTaskFixture(t, identity)
	defer fixture.claim.Destroy()
	backend := &fakeReadTaskBackend{
		claim: fixture.claim, start: fixture.running, heartbeat: fixture.heartbeat,
		release: fixture.released, completion: fixture.completion,
	}
	handler := mustReadTaskRouter(t, identity, &fakeBackend{}, backend)

	response := serve(t, handler, http.MethodPost, readTaskPath(":claim"),
		[]byte(`{"schema_version":"runner-read-task-claim-request.v1"}`), jsonHeaders(nil))
	assertStatusAndBoundaryHeaders(t, response, http.StatusOK)
	var claimResponse ReadTaskClaimResponse
	decodeReadTaskResponse(t, response, &claimResponse)
	if claimResponse.LeaseToken != fixture.token || claimResponse.Task.ID != testReadTaskID ||
		claimResponse.SchemaVersion != "runner-read-task-claim-response.v2" ||
		claimResponse.Task.InputHash != fixture.descriptor.InputHash || claimResponse.LeaseEpoch.Int64() != 7 ||
		claimResponse.ScopeRevision.Int64() != 1 || claimResponse.HeartbeatAfterSeconds != 10 {
		t.Fatalf("claim response detached from persisted task: %#v", claimResponse)
	}
	if claimResponse.Task.PlanBinding.SchemaVersion != fixture.descriptor.PlanBinding.SchemaVersion ||
		claimResponse.Task.PlanBinding.ManifestDigest != fixture.descriptor.PlanBinding.ManifestDigest ||
		claimResponse.Task.PlanBinding.RegistryDigest != fixture.descriptor.PlanBinding.RegistryDigest ||
		claimResponse.Task.PlanBinding.ProfileDigest != fixture.descriptor.PlanBinding.ProfileDigest ||
		claimResponse.Task.PlanBinding.TasksHash != fixture.descriptor.PlanBinding.TasksHash ||
		claimResponse.Task.RuntimeBinding.SchemaVersion != fixture.descriptor.RuntimeBinding.SchemaVersion ||
		claimResponse.Task.RuntimeBinding.ConnectorDigest != fixture.descriptor.RuntimeBinding.ConnectorDigest ||
		claimResponse.Task.RuntimeBinding.TargetDigest != fixture.descriptor.RuntimeBinding.TargetDigest ||
		claimResponse.Task.RuntimeBinding.ExecutorDigest != fixture.descriptor.RuntimeBinding.ExecutorDigest ||
		claimResponse.Task.RuntimeBinding.RuntimeDigest != fixture.descriptor.RuntimeBinding.RuntimeDigest ||
		!claimResponse.Task.RuntimeBinding.BoundAt.Equal(fixture.descriptor.RuntimeBinding.BoundAt) {
		t.Fatalf("claim response changed immutable plan/runtime bindings: %#v", claimResponse.Task)
	}
	inputDigest := sha256.Sum256(claimResponse.Task.Input)
	if !bytes.Equal(claimResponse.Task.Input, fixture.descriptor.Input) ||
		hex.EncodeToString(inputDigest[:]) != claimResponse.Task.InputHash {
		t.Fatalf("claim input/hash changed across wire: input=%s hash=%s", claimResponse.Task.Input, claimResponse.Task.InputHash)
	}

	authorization := readTaskAuthorization(fixture.token)
	response = serve(t, handler, http.MethodPost, readTaskPath(":start"),
		[]byte(`{"schema_version":"runner-read-task-start-request.v1","lease_epoch":"7"}`), jsonHeaders(authorization))
	assertStatusAndBoundaryHeaders(t, response, http.StatusOK)
	var startResponse ReadTaskStartResponse
	decodeReadTaskResponse(t, response, &startResponse)
	if startResponse.TaskID != testReadTaskID || startResponse.AttemptStatus != "RUNNING" ||
		startResponse.LeaseEpoch.Int64() != 7 || startResponse.ScopeRevision.Int64() != 1 {
		t.Fatalf("start response = %#v", startResponse)
	}

	response = serve(t, handler, http.MethodPost, readTaskPath(":heartbeat"),
		[]byte(`{"schema_version":"runner-read-task-heartbeat-request.v1","lease_epoch":"7","sequence":"1"}`),
		jsonHeaders(authorization))
	assertStatusAndBoundaryHeaders(t, response, http.StatusOK)
	var heartbeatResponse ReadTaskHeartbeatResponse
	decodeReadTaskResponse(t, response, &heartbeatResponse)
	if heartbeatResponse.TaskID != testReadTaskID || heartbeatResponse.LeaseEpoch.Int64() != 7 ||
		heartbeatResponse.AcceptedSequence.Int64() != 1 || heartbeatResponse.Directive != "CONTINUE" ||
		heartbeatResponse.HeartbeatAfterSeconds != 10 {
		t.Fatalf("heartbeat response = %#v", heartbeatResponse)
	}

	response = serve(t, handler, http.MethodPost, readTaskPath(":release"),
		[]byte(`{"schema_version":"runner-read-task-release-request.v1","lease_epoch":"7","reason_code":"CONNECTOR_NOT_READY"}`),
		jsonHeaders(authorization))
	assertStatusAndBoundaryHeaders(t, response, http.StatusOK)
	var releaseResponse ReadTaskReleaseResponse
	decodeReadTaskResponse(t, response, &releaseResponse)
	if releaseResponse.TaskID != testReadTaskID || releaseResponse.AttemptStatus != "RELEASED" ||
		releaseResponse.LeaseEpoch.Int64() != 7 {
		t.Fatalf("release response = %#v", releaseResponse)
	}

	completionBody, err := json.Marshal(ReadTaskCompleteRequest{
		SchemaVersion: "runner-read-task-complete-request.v1", LeaseEpoch: 7,
		Outcome: readtask.CompletionEvidence,
		Evidence: &ReadTaskEvidenceCompletion{
			CollectedAt: fixture.collectedAt,
			Items:       []json.RawMessage{json.RawMessage(`{"metric":"up","value":1}`)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	response = serve(t, handler, http.MethodPost, readTaskPath(":complete"), completionBody, jsonHeaders(authorization))
	assertStatusAndBoundaryHeaders(t, response, http.StatusOK)
	var completeResponse ReadTaskCompleteResponse
	decodeReadTaskResponse(t, response, &completeResponse)
	if completeResponse.TaskID != testReadTaskID || completeResponse.AttemptStatus != "COMPLETED" ||
		completeResponse.SchemaVersion != "runner-read-task-complete-response.v2" ||
		completeResponse.TaskStatus != "EVIDENCE" || completeResponse.LeaseEpoch.Int64() != 7 ||
		completeResponse.EvidenceID != fixture.completion.EvidenceID || completeResponse.ReceiptID != fixture.completion.ReceiptID ||
		completeResponse.ContentHash != fixture.completion.Projection.ContentHash() ||
		completeResponse.ReceiptHash != fixture.completion.Projection.ReceiptHash() {
		t.Fatalf("complete response = %#v", completeResponse)
	}

	if backend.claimCalls != 1 || backend.startCalls != 1 || backend.heartbeatCalls != 1 ||
		backend.releaseCalls != 1 || backend.completeCalls != 1 {
		t.Fatalf("READ backend calls = claim:%d start:%d heartbeat:%d release:%d complete:%d",
			backend.claimCalls, backend.startCalls, backend.heartbeatCalls, backend.releaseCalls, backend.completeCalls)
	}
	for operation, token := range backend.tokens {
		if token != fixture.token {
			t.Errorf("%s received lease token %q", operation, token)
		}
	}
	if backend.claimTaskID != testReadTaskID || backend.lastSequence != 1 ||
		backend.lastReleaseReason != readtask.ReleaseConnectorNotReady || backend.lastOutcome != readtask.CompletionEvidence {
		t.Fatalf("backend request projection was not exact: %#v", backend)
	}
}

func TestReadTaskRoutesRejectCrossPoolDispatch(t *testing.T) {
	t.Parallel()
	t.Run("WRITE certificate cannot claim READ task", func(t *testing.T) {
		identity := testIdentityForPool(t, runneridentity.PoolWrite)
		backend := &fakeReadTaskBackend{}
		handler := mustReadTaskRouter(t, identity, &fakeBackend{}, backend)
		response := serve(t, handler, http.MethodPost, readTaskPath(":claim"),
			[]byte(`{"schema_version":"runner-read-task-claim-request.v1"}`), jsonHeaders(nil))
		assertProblemCode(t, response, http.StatusForbidden, "runner_identity_rejected")
		if backend.totalCalls() != 0 {
			t.Fatal("WRITE certificate reached READ backend")
		}
	})

	t.Run("READ certificate cannot start WRITE job", func(t *testing.T) {
		identity := testIdentity(t)
		writeBackend := &fakeBackend{startResponse: validStartResponse()}
		handler := mustReadTaskRouter(t, identity, writeBackend, &fakeReadTaskBackend{})
		response := serve(t, handler, http.MethodPost, "/runner/v1/jobs/job-1:start",
			[]byte(`{"schema_version":"runner-job-start-request.v1","lease_epoch":"1"}`),
			jsonHeaders([]string{"AIOPS-Job-Lease " + testLeaseToken}))
		assertProblemCode(t, response, http.StatusForbidden, "runner_identity_rejected")
		if writeBackend.startCalls != 0 {
			t.Fatal("READ certificate reached WRITE backend")
		}
	})
}

func TestReadTaskLeaseAuthorizationRequiresOneCanonical43CharacterBearerAndOwnChallenge(t *testing.T) {
	t.Parallel()
	identity := testIdentity(t)
	token := readTaskTestToken()
	body := []byte(`{"schema_version":"runner-read-task-start-request.v1","lease_epoch":"7"}`)
	invalid := [][]string{
		nil,
		{"Bearer " + token},
		{"AIOPS-Job-Lease " + token},
		{"AIOPS-Read-Task-Lease " + token[:42]},
		{"AIOPS-Read-Task-Lease " + token + "A"},
		{"AIOPS-Read-Task-Lease " + token + "="},
		{"AIOPS-Read-Task-Lease " + token[:42] + "B"},
		{"AIOPS-Read-Task-Lease " + token + " "},
		{"AIOPS-Read-Task-Lease " + token, "AIOPS-Read-Task-Lease " + token},
	}
	for _, values := range invalid {
		backend := &fakeReadTaskBackend{}
		handler := mustReadTaskRouter(t, identity, &fakeBackend{}, backend)
		response := serve(t, handler, http.MethodPost, readTaskPath(":start"), body, jsonHeaders(values))
		assertProblemCode(t, response, http.StatusUnauthorized, "runner_lease_authentication_failed")
		if got := response.Header.Get("WWW-Authenticate"); got != `AIOPS-Read-Task-Lease realm="runner-gateway"` {
			t.Fatalf("WWW-Authenticate = %q", got)
		}
		if backend.totalCalls() != 0 {
			t.Fatal("malformed READ bearer reached backend")
		}
	}

	fixture := newReadTaskFixture(t, identity)
	defer fixture.claim.Destroy()
	backend := &fakeReadTaskBackend{start: fixture.running}
	handler := mustReadTaskRouter(t, identity, &fakeBackend{}, backend)
	response := serve(t, handler, http.MethodPost, readTaskPath(":start"), body, jsonHeaders(readTaskAuthorization(token)))
	assertStatusAndBoundaryHeaders(t, response, http.StatusOK)
	if backend.startCalls != 1 || backend.tokens["start"] != token {
		t.Fatal("canonical READ bearer was not dispatched exactly once")
	}
}

func TestReadTaskRouterRejectsClaimAuthorizationAndStrictJSONOrUnionViolations(t *testing.T) {
	t.Parallel()
	token := readTaskTestToken()
	tests := []struct {
		name       string
		suffix     string
		body       string
		auth       []string
		wantCode   string
		wantStatus int
	}{
		{
			name: "claim authorization", suffix: ":claim", auth: readTaskAuthorization(token),
			body:       `{"schema_version":"runner-read-task-claim-request.v1"}`,
			wantStatus: 400, wantCode: "invalid_runner_request",
		},
		{
			name: "duplicate field", suffix: ":claim",
			body:       `{"schema_version":"runner-read-task-claim-request.v1","schema_version":"runner-read-task-claim-request.v1"}`,
			wantStatus: 400, wantCode: "invalid_runner_json",
		},
		{
			name: "unknown field", suffix: ":start", auth: readTaskAuthorization(token),
			body:       `{"schema_version":"runner-read-task-start-request.v1","lease_epoch":"7","command":"forged"}`,
			wantStatus: 400, wantCode: "invalid_runner_json",
		},
		{
			name: "nested duplicate", suffix: ":complete", auth: readTaskAuthorization(token),
			body:       `{"schema_version":"runner-read-task-complete-request.v1","lease_epoch":"7","outcome":"EVIDENCE","evidence":{"collected_at":"2039-01-01T00:00:00Z","items":[{"value":1,"value":2}]}}`,
			wantStatus: 400, wantCode: "invalid_runner_json",
		},
		{
			name: "evidence and failure union", suffix: ":complete", auth: readTaskAuthorization(token),
			body:       `{"schema_version":"runner-read-task-complete-request.v1","lease_epoch":"7","outcome":"EVIDENCE","evidence":{"collected_at":"2039-01-01T00:00:00Z","items":[]},"failure_code":"timeout"}`,
			wantStatus: 400, wantCode: "invalid_runner_json",
		},
		{
			name: "forbidden empty failure member", suffix: ":complete", auth: readTaskAuthorization(token),
			body:       `{"schema_version":"runner-read-task-complete-request.v1","lease_epoch":"7","outcome":"EVIDENCE","evidence":{"collected_at":"2039-01-01T00:00:00Z","items":[]},"failure_code":""}`,
			wantStatus: 400, wantCode: "invalid_runner_json",
		},
		{
			name: "cancelled requires cancelled code", suffix: ":complete", auth: readTaskAuthorization(token),
			body:       `{"schema_version":"runner-read-task-complete-request.v1","lease_epoch":"7","outcome":"CANCELLED","failure_code":"timeout"}`,
			wantStatus: 400, wantCode: "invalid_runner_request",
		},
		{
			name: "cookie smuggling", suffix: ":start", auth: readTaskAuthorization(token),
			body:       `{"schema_version":"runner-read-task-start-request.v1","lease_epoch":"7"}`,
			wantStatus: 400, wantCode: "invalid_runner_request",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity := testIdentity(t)
			fixture := newReadTaskFixture(t, identity)
			defer fixture.claim.Destroy()
			backend := &fakeReadTaskBackend{
				claim: fixture.claim, start: fixture.running, heartbeat: fixture.heartbeat,
				release: fixture.released, completion: fixture.completion,
			}
			handler := mustReadTaskRouter(t, identity, &fakeBackend{}, backend)
			headers := jsonHeaders(test.auth)
			if test.name == "cookie smuggling" {
				headers.Set("Cookie", "runner_id=forged")
			}
			response := serve(t, handler, http.MethodPost, readTaskPath(test.suffix), []byte(test.body), headers)
			assertProblemCode(t, response, test.wantStatus, test.wantCode)
			if backend.totalCalls() != 0 {
				t.Fatalf("invalid READ request reached backend %d times", backend.totalCalls())
			}
		})
	}
}

func TestReadTaskEvidenceJSONDepthMatchesTheWireContract(t *testing.T) {
	t.Parallel()
	collectedAt := time.Date(2040, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, test := range []struct {
		name  string
		depth int
		valid bool
	}{{"depth 16", 16, true}, {"depth 17", 17, false}} {
		t.Run(test.name, func(t *testing.T) {
			item := nestedReadTaskObject(test.depth)
			request := ReadTaskCompleteRequest{
				SchemaVersion: "runner-read-task-complete-request.v1", LeaseEpoch: 1,
				Outcome: readtask.CompletionEvidence,
				Evidence: &ReadTaskEvidenceCompletion{
					CollectedAt: collectedAt, Items: []json.RawMessage{item},
				},
			}
			if got := request.valid(); got != test.valid {
				t.Fatalf("ReadTaskCompleteRequest depth=%d valid=%t, want %t", test.depth, got, test.valid)
			}
		})
	}
}

func TestReadTaskEvidenceRejectsServerOwnedFieldsBeforeBackend(t *testing.T) {
	t.Parallel()
	items := map[string]json.RawMessage{
		"source":               json.RawMessage(`{"source":"runner"}`),
		"nested connector":     json.RawMessage(`{"nested":{"connector_id":"prometheus-read"}}`),
		"operation":            json.RawMessage(`{"operation":"query-range"}`),
		"truncated":            json.RawMessage(`{"truncated":false}`),
		"hash":                 json.RawMessage(`{"content_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`),
		"target":               json.RawMessage(`{"target":"service-a"}`),
		"URL":                  json.RawMessage(`{"URL":"https://example.invalid"}`),
		"headers":              json.RawMessage(`{"headers":{"accept":"application/json"}}`),
		"credential":           json.RawMessage(`{"credential":"opaque"}`),
		"raw error":            json.RawMessage(`{"raw_error":"upstream detail"}`),
		"symbolic source name": json.RawMessage(`{"name":"source"}`),
		"symbolic hash key":    json.RawMessage(`{"key":"receipt-hash"}`),
		"scope revision":       json.RawMessage(`{"scope_revision":2}`),
		"source URL":           json.RawMessage(`{"source_url":"https://example.invalid"}`),
		"camel source URL":     json.RawMessage(`{"sourceURL":"https://example.invalid"}`),
		"target URL":           json.RawMessage(`{"target_url":"https://example.invalid"}`),
		"request headers":      json.RawMessage(`{"request_headers":{"accept":"application/json"}}`),
		"connector name":       json.RawMessage(`{"connector_name":"prometheus"}`),
		"raw error message":    json.RawMessage(`{"raw_error_message":"upstream detail"}`),
		"sources":              json.RawMessage(`{"sources":["runner"]}`),
		"credentials":          json.RawMessage(`{"credentials":["opaque"]}`),
		"target URLs":          json.RawMessage(`{"target_urls":["https://example.invalid"]}`),
		"scope revisions":      json.RawMessage(`{"scope_revisions":[2]}`),
		"raw errors":           json.RawMessage(`{"raw_errors":["upstream detail"]}`),
		"error bodies":         json.RawMessage(`{"error_bodies":["upstream detail"]}`),
		"acronym URLs":         json.RawMessage(`{"URLs":["https://example.invalid"]}`),
	}
	for name, item := range items {
		t.Run(name, func(t *testing.T) {
			identity := testIdentity(t)
			backend := &fakeReadTaskBackend{}
			handler := mustReadTaskRouter(t, identity, &fakeBackend{}, backend)
			body, err := json.Marshal(ReadTaskCompleteRequest{
				SchemaVersion: "runner-read-task-complete-request.v1", LeaseEpoch: 7,
				Outcome: readtask.CompletionEvidence,
				Evidence: &ReadTaskEvidenceCompletion{
					CollectedAt: time.Date(2040, 1, 2, 3, 4, 5, 0, time.UTC),
					Items:       []json.RawMessage{item},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			response := serve(t, handler, http.MethodPost, readTaskPath(":complete"), body,
				jsonHeaders(readTaskAuthorization(readTaskTestToken())))
			assertProblemCode(t, response, http.StatusBadRequest, "invalid_runner_request")
			if backend.totalCalls() != 0 {
				t.Fatal("server-owned Evidence field reached the trusted completion boundary")
			}
		})
	}
	allowed := ReadTaskCompleteRequest{
		SchemaVersion: "runner-read-task-complete-request.v1", LeaseEpoch: 7,
		Outcome: readtask.CompletionEvidence,
		Evidence: &ReadTaskEvidenceCompletion{
			CollectedAt: time.Date(2040, 1, 2, 3, 4, 5, 0, time.UTC),
			Items: []json.RawMessage{json.RawMessage(
				`{"hashicorp_version":"1.2","hashrate":10,"resource":"pod","resource_id":"pod-1"}`,
			)},
		},
	}
	if !allowed.valid() {
		t.Fatal("semantic token matching rejected safe resource fields as source metadata")
	}
}

func TestReadTaskRouterCompletesFailedAndCancelledOutcomesWithoutEvidenceFields(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		outcome     readtask.CompletionOutcome
		failureCode readtask.FailureCode
		wantStatus  string
	}{
		{"failed timeout", readtask.CompletionFailed, readtask.FailureTimeout, "FAILED"},
		{"failed result rejected", readtask.CompletionFailed, readtask.FailureResultRejected, "FAILED"},
		{"cancelled", readtask.CompletionCancelled, readtask.FailureCancelled, "CANCELLED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity := testIdentity(t)
			fixture := newReadTaskFixture(t, identity)
			defer fixture.claim.Destroy()
			backend := &fakeReadTaskBackend{completion: completionResultForOutcome(
				t, fixture, test.outcome, test.failureCode,
			)}
			handler := mustReadTaskRouter(t, identity, &fakeBackend{}, backend)
			body, err := json.Marshal(ReadTaskCompleteRequest{
				SchemaVersion: "runner-read-task-complete-request.v1", LeaseEpoch: 7,
				Outcome: test.outcome, FailureCode: test.failureCode,
			})
			if err != nil {
				t.Fatal(err)
			}
			response := serve(t, handler, http.MethodPost, readTaskPath(":complete"), body,
				jsonHeaders(readTaskAuthorization(fixture.token)))
			assertStatusAndBoundaryHeaders(t, response, http.StatusOK)
			responseBody := readBody(t, response)
			var wire map[string]json.RawMessage
			if err := json.Unmarshal(responseBody, &wire); err != nil {
				t.Fatalf("decode completion response: %v; body=%s", err, responseBody)
			}
			if wire["evidence_id"] != nil || wire["content_hash"] != nil {
				t.Fatalf("%s response exposed Evidence-only fields: %s", test.outcome, responseBody)
			}
			var got ReadTaskCompleteResponse
			if err := json.Unmarshal(responseBody, &got); err != nil {
				t.Fatal(err)
			}
			if got.TaskStatus != test.wantStatus || got.AttemptStatus != string(readtask.AttemptCompleted) ||
				got.ReceiptID == "" || got.ReceiptHash == "" || got.EvidenceID != "" || got.ContentHash != "" {
				t.Fatalf("completion response = %#v", got)
			}
			if backend.lastOutcome != test.outcome || backend.lastFailureCode != test.failureCode {
				t.Fatalf("backend completion binding = outcome %q, failure %q", backend.lastOutcome, backend.lastFailureCode)
			}
		})
	}
}

func TestReadTaskChangedFailureReplayMapsToResultConflict(t *testing.T) {
	t.Parallel()
	identity := testIdentity(t)
	backend := &fakeReadTaskBackend{completeErr: readtask.ErrCompletionConflict}
	handler := mustReadTaskRouter(t, identity, &fakeBackend{}, backend)
	body := []byte(`{"schema_version":"runner-read-task-complete-request.v1","lease_epoch":"7","outcome":"FAILED","failure_code":"permission_denied"}`)
	response := serve(t, handler, http.MethodPost, readTaskPath(":complete"), body,
		jsonHeaders(readTaskAuthorization(readTaskTestToken())))
	assertProblemCode(t, response, http.StatusConflict, "runner_result_conflict")
}

func TestReadTaskEndpointProblemAllowlistsAreExact(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		suffix     string
		body       string
		configure  func(*fakeReadTaskBackend)
		wantStatus int
		wantCode   string
	}{
		{
			"claim does not expose stale fence", ":claim",
			`{"schema_version":"runner-read-task-claim-request.v1"}`,
			func(backend *fakeReadTaskBackend) { backend.claimErr = readtask.ErrStaleFence },
			http.StatusInternalServerError, "runner_internal_error",
		},
		{
			"start does not expose result rejection", ":start",
			`{"schema_version":"runner-read-task-start-request.v1","lease_epoch":"7"}`,
			func(backend *fakeReadTaskBackend) { backend.startErr = readtask.ErrProjectionRejected },
			http.StatusInternalServerError, "runner_internal_error",
		},
		{
			"heartbeat does not expose result conflict", ":heartbeat",
			`{"schema_version":"runner-read-task-heartbeat-request.v1","lease_epoch":"7","sequence":"1"}`,
			func(backend *fakeReadTaskBackend) { backend.heartbeatErr = readtask.ErrCompletionConflict },
			http.StatusInternalServerError, "runner_internal_error",
		},
		{
			"heartbeat does not expose claims disabled", ":heartbeat",
			`{"schema_version":"runner-read-task-heartbeat-request.v1","lease_epoch":"7","sequence":"1"}`,
			func(backend *fakeReadTaskBackend) { backend.heartbeatErr = readtask.ErrClaimsDisabled },
			http.StatusInternalServerError, "runner_internal_error",
		},
		{
			"release does not expose heartbeat conflict", ":release",
			`{"schema_version":"runner-read-task-release-request.v1","lease_epoch":"7","reason_code":"CONNECTOR_NOT_READY"}`,
			func(backend *fakeReadTaskBackend) { backend.releaseErr = readtask.ErrHeartbeatConflict },
			http.StatusInternalServerError, "runner_internal_error",
		},
		{
			"release does not expose claims disabled", ":release",
			`{"schema_version":"runner-read-task-release-request.v1","lease_epoch":"7","reason_code":"CONNECTOR_NOT_READY"}`,
			func(backend *fakeReadTaskBackend) { backend.releaseErr = readtask.ErrClaimsDisabled },
			http.StatusInternalServerError, "runner_internal_error",
		},
		{
			"complete exposes typed result rejection", ":complete",
			`{"schema_version":"runner-read-task-complete-request.v1","lease_epoch":"7","outcome":"FAILED","failure_code":"result_rejected"}`,
			func(backend *fakeReadTaskBackend) { backend.completeErr = readtask.ErrProjectionRejected },
			http.StatusUnprocessableEntity, "runner_result_rejected",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity := testIdentity(t)
			backend := &fakeReadTaskBackend{}
			test.configure(backend)
			handler := mustReadTaskRouter(t, identity, &fakeBackend{}, backend)
			var authorization []string
			if test.suffix != ":claim" {
				authorization = readTaskAuthorization(readTaskTestToken())
			}
			response := serve(t, handler, http.MethodPost, readTaskPath(test.suffix), []byte(test.body),
				jsonHeaders(authorization))
			assertProblemCode(t, response, test.wantStatus, test.wantCode)
			if backend.totalCalls() != 1 {
				t.Fatalf("backend calls = %d, want 1", backend.totalCalls())
			}
		})
	}
}

func TestReadTaskClaimNoWorkIs204AndCompletionProjectionRejectionIs422(t *testing.T) {
	t.Parallel()
	identity := testIdentity(t)
	backend := &fakeReadTaskBackend{claimErr: readtask.ErrNoClaimAvailable}
	handler := mustReadTaskRouter(t, identity, &fakeBackend{}, backend)
	response := serve(t, handler, http.MethodPost, readTaskPath(":claim"),
		[]byte(`{"schema_version":"runner-read-task-claim-request.v1"}`), jsonHeaders(nil))
	assertStatusAndBoundaryHeaders(t, response, http.StatusNoContent)
	if body := readBody(t, response); len(body) != 0 {
		t.Fatalf("204 body = %q", body)
	}

	backend.completeErr = readtask.ErrProjectionRejected
	completionBody := []byte(`{"schema_version":"runner-read-task-complete-request.v1","lease_epoch":"7","outcome":"FAILED","failure_code":"result_rejected"}`)
	response = serve(t, handler, http.MethodPost, readTaskPath(":complete"), completionBody,
		jsonHeaders(readTaskAuthorization(readTaskTestToken())))
	assertProblem(t, response, http.StatusUnprocessableEntity,
		"urn:aiops:problem:runner:result-rejected", "runner_result_rejected")
}

func TestReadTaskHeartbeatReturnsTerminateAfterAuthenticatedScopeRevisionDrift(t *testing.T) {
	t.Parallel()
	identity := testIdentity(t)
	fixture := newReadTaskFixture(t, identity)
	defer fixture.claim.Destroy()
	terminated := fixture.heartbeat.Attempt
	terminated.Status = readtask.AttemptCancelled
	terminated.TerminalAt = terminated.LastHeartbeatAt
	terminated.UpdatedAt = terminated.TerminalAt
	backend := &fakeReadTaskBackend{heartbeat: readtask.HeartbeatResult{
		Attempt: terminated, AcceptedSequence: terminated.HeartbeatSequence,
		Directive: readtask.HeartbeatTerminate, LeaseExpiresAt: terminated.LeaseExpiresAt,
	}}
	principal := testPrincipalForIdentity(identity, false)
	principal.scopeRevision = 2
	handler := mustReadTaskRouter(t, identity, &fakeBackend{principal: principal}, backend)
	response := serve(t, handler, http.MethodPost, readTaskPath(":heartbeat"),
		[]byte(`{"schema_version":"runner-read-task-heartbeat-request.v1","lease_epoch":"7","sequence":"1"}`),
		jsonHeaders(readTaskAuthorization(fixture.token)))
	assertStatusAndBoundaryHeaders(t, response, http.StatusOK)
	var got ReadTaskHeartbeatResponse
	decodeReadTaskResponse(t, response, &got)
	if got.Directive != string(readtask.HeartbeatTerminate) || got.AcceptedSequence.Int64() != 1 {
		t.Fatalf("scope-drift heartbeat = %#v", got)
	}
}

func TestReadTaskClaimBindsResponseToInnerTransactionIdentitySnapshot(t *testing.T) {
	t.Parallel()
	identity := testIdentity(t)
	fixture := newReadTaskFixture(t, identity)
	defer fixture.claim.Destroy()
	innerAttempt := fixture.leased
	innerAttempt.ScopeRevision = 2
	innerClaim, err := readtask.NewClaim(fixture.descriptor, innerAttempt, []byte(fixture.token))
	if err != nil {
		t.Fatal(err)
	}
	defer innerClaim.Destroy()
	outer := testPrincipalForIdentity(identity, false)
	inner := *outer
	inner.scopeRevision = 2
	readBackend := &fakeReadTaskBackend{claim: innerClaim, binding: &inner}
	handler := mustReadTaskRouter(t, identity, &fakeBackend{principal: outer}, readBackend)

	response := serve(t, handler, http.MethodPost, readTaskPath(":claim"),
		[]byte(`{"schema_version":"runner-read-task-claim-request.v1"}`), jsonHeaders(nil))
	assertStatusAndBoundaryHeaders(t, response, http.StatusOK)
	var got ReadTaskClaimResponse
	decodeReadTaskResponse(t, response, &got)
	if got.ScopeRevision.Int64() != 2 || got.LeaseEpoch.Int64() != innerAttempt.Epoch {
		t.Fatalf("claim used stale outer response binding: %#v", got)
	}
}

func TestReadTaskRoutesShareEncodedPathIdentityHeaderQueryAndBodyLimits(t *testing.T) {
	t.Parallel()
	identity := testIdentity(t)
	token := readTaskTestToken()
	tests := []struct {
		name       string
		target     string
		body       []byte
		headers    http.Header
		wantStatus int
		wantCode   string
	}{
		{
			name: "query", target: readTaskPath(":claim") + "?runner_id=forged",
			body: []byte(`{"schema_version":"runner-read-task-claim-request.v1"}`), headers: jsonHeaders(nil),
			wantStatus: http.StatusBadRequest, wantCode: "invalid_runner_request",
		},
		{
			name: "encoded path", target: "/runner/v1/read-tasks/11111111-1111-4111-8111-111111111111%2fother:start",
			body:    []byte(`{"schema_version":"runner-read-task-start-request.v1","lease_epoch":"7"}`),
			headers: jsonHeaders(readTaskAuthorization(token)), wantStatus: http.StatusBadRequest,
			wantCode: "forbidden_runner_identity_field",
		},
		{
			name: "identity header", target: readTaskPath(":claim"),
			body: []byte(`{"schema_version":"runner-read-task-claim-request.v1"}`),
			headers: func() http.Header {
				header := jsonHeaders(nil)
				header.Set("X-Runner-ID", "forged")
				return header
			}(),
			wantStatus: http.StatusBadRequest, wantCode: "forbidden_runner_identity_field",
		},
		{
			name: "claim body over limit", target: readTaskPath(":claim"),
			body: bytes.Repeat([]byte{' '}, int(leaseBodyLimit+1)), headers: jsonHeaders(nil),
			wantStatus: http.StatusRequestEntityTooLarge, wantCode: "runner_payload_too_large",
		},
		{
			name: "resource body over limit", target: readTaskPath(":start"),
			body: bytes.Repeat([]byte{' '}, int(defaultBodyLimit+1)), headers: jsonHeaders(readTaskAuthorization(token)),
			wantStatus: http.StatusRequestEntityTooLarge, wantCode: "runner_payload_too_large",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := &fakeReadTaskBackend{}
			handler := mustReadTaskRouter(t, identity, &fakeBackend{}, backend)
			response := serve(t, handler, http.MethodPost, test.target, test.body, test.headers)
			assertProblemCode(t, response, test.wantStatus, test.wantCode)
			if backend.totalCalls() != 0 {
				t.Fatalf("invalid boundary request reached backend %d times", backend.totalCalls())
			}
		})
	}
}

func TestReadTaskRouterFailsClosedOnBackendResponseBindingTampering(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		suffix string
		body   string
		claim  bool
		mutate func(*testing.T, *readTaskFixture, *fakeReadTaskBackend)
	}{
		{
			name: "claim scope revision", suffix: ":claim", claim: true,
			body: `{"schema_version":"runner-read-task-claim-request.v1"}`,
			mutate: func(t *testing.T, fixture *readTaskFixture, backend *fakeReadTaskBackend) {
				attempt := fixture.leased
				attempt.ScopeRevision = 2
				claim, err := readtask.NewClaim(fixture.descriptor, attempt, []byte(fixture.token))
				if err != nil {
					t.Fatal(err)
				}
				backend.claim = claim
			},
		},
		{
			name: "start task", suffix: ":start",
			body: `{"schema_version":"runner-read-task-start-request.v1","lease_epoch":"7"}`,
			mutate: func(_ *testing.T, _ *readTaskFixture, backend *fakeReadTaskBackend) {
				backend.start.TaskID = "22222222-2222-4222-8222-222222222222"
			},
		},
		{
			name: "start token hash", suffix: ":start",
			body: `{"schema_version":"runner-read-task-start-request.v1","lease_epoch":"7"}`,
			mutate: func(_ *testing.T, _ *readTaskFixture, backend *fakeReadTaskBackend) {
				backend.start.TokenSHA256 = hex.EncodeToString(make([]byte, 32))
			},
		},
		{
			name: "start partial plan binding", suffix: ":start",
			body: `{"schema_version":"runner-read-task-start-request.v1","lease_epoch":"7"}`,
			mutate: func(_ *testing.T, _ *readTaskFixture, backend *fakeReadTaskBackend) {
				backend.start.PlanBinding = domain.InvestigationPlanBinding{}
			},
		},
		{
			name: "heartbeat sequence", suffix: ":heartbeat",
			body: `{"schema_version":"runner-read-task-heartbeat-request.v1","lease_epoch":"7","sequence":"1"}`,
			mutate: func(_ *testing.T, _ *readTaskFixture, backend *fakeReadTaskBackend) {
				backend.heartbeat.AcceptedSequence = 2
			},
		},
		{
			name: "heartbeat partial runtime binding", suffix: ":heartbeat",
			body: `{"schema_version":"runner-read-task-heartbeat-request.v1","lease_epoch":"7","sequence":"1"}`,
			mutate: func(_ *testing.T, _ *readTaskFixture, backend *fakeReadTaskBackend) {
				backend.heartbeat.Attempt.RuntimeBinding = domain.ReadTaskRuntimeBinding{}
			},
		},
		{
			name: "release epoch", suffix: ":release",
			body: `{"schema_version":"runner-read-task-release-request.v1","lease_epoch":"7","reason_code":"LOCAL_CAPACITY_UNAVAILABLE"}`,
			mutate: func(_ *testing.T, _ *readTaskFixture, backend *fakeReadTaskBackend) {
				backend.release.Epoch = 8
			},
		},
		{
			name: "completion epoch", suffix: ":complete",
			body: `{"schema_version":"runner-read-task-complete-request.v1","lease_epoch":"7","outcome":"EVIDENCE","evidence":{"collected_at":"2039-01-01T00:00:00Z","items":[]}}`,
			mutate: func(_ *testing.T, _ *readTaskFixture, backend *fakeReadTaskBackend) {
				backend.completion.Attempt.Epoch = 8
			},
		},
		{
			name: "completion plan snapshot drift", suffix: ":complete",
			body: `{"schema_version":"runner-read-task-complete-request.v1","lease_epoch":"7","outcome":"EVIDENCE","evidence":{"collected_at":"2039-01-01T00:00:00Z","items":[]}}`,
			mutate: func(_ *testing.T, _ *readTaskFixture, backend *fakeReadTaskBackend) {
				backend.completion.Attempt.PlanBinding.ManifestDigest = hex.EncodeToString(bytes.Repeat([]byte{0xa1}, 32))
			},
		},
		{
			name: "completion runtime snapshot drift", suffix: ":complete",
			body: `{"schema_version":"runner-read-task-complete-request.v1","lease_epoch":"7","outcome":"EVIDENCE","evidence":{"collected_at":"2039-01-01T00:00:00Z","items":[]}}`,
			mutate: func(_ *testing.T, _ *readTaskFixture, backend *fakeReadTaskBackend) {
				backend.completion.Attempt.RuntimeBinding.RuntimeDigest = hex.EncodeToString(bytes.Repeat([]byte{0xa2}, 32))
			},
		},
		{
			name: "completion request hash version drift", suffix: ":complete",
			body: `{"schema_version":"runner-read-task-complete-request.v1","lease_epoch":"7","outcome":"EVIDENCE","evidence":{"collected_at":"2039-01-01T00:00:00Z","items":[]}}`,
			mutate: func(_ *testing.T, _ *readTaskFixture, backend *fakeReadTaskBackend) {
				backend.completion.Attempt.RequestHashVersion = "read-task-completion-request.v2"
			},
		},
		{
			name: "completion receipt hash version drift", suffix: ":complete",
			body: `{"schema_version":"runner-read-task-complete-request.v1","lease_epoch":"7","outcome":"EVIDENCE","evidence":{"collected_at":"2039-01-01T00:00:00Z","items":[]}}`,
			mutate: func(_ *testing.T, _ *readTaskFixture, backend *fakeReadTaskBackend) {
				backend.completion.Attempt.ReceiptHashVersion = "read-task-completion-receipt.v2"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity := testIdentity(t)
			fixture := newReadTaskFixture(t, identity)
			defer fixture.claim.Destroy()
			backend := &fakeReadTaskBackend{
				claim: fixture.claim, start: fixture.running, heartbeat: fixture.heartbeat,
				release: fixture.released, completion: fixture.completion,
			}
			test.mutate(t, fixture, backend)
			handler := mustReadTaskRouter(t, identity, &fakeBackend{}, backend)
			var authorization []string
			if !test.claim {
				authorization = readTaskAuthorization(fixture.token)
			}
			response := serve(t, handler, http.MethodPost, readTaskPath(test.suffix), []byte(test.body), jsonHeaders(authorization))
			assertProblemCode(t, response, http.StatusInternalServerError, "runner_internal_error")
		})
	}
}

func TestReadTaskClaimBindingRejectsPartialAndDriftedPlanRuntimeSnapshots(t *testing.T) {
	t.Parallel()
	identity := testIdentity(t)
	fixture := newReadTaskFixture(t, identity)
	defer fixture.claim.Destroy()
	response, err := readTaskClaimResponse(fixture.claim)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*ReadTaskDescriptor, *readtask.Descriptor, *readtask.Attempt)
	}{
		{
			name: "partial plan response",
			mutate: func(task *ReadTaskDescriptor, _ *readtask.Descriptor, _ *readtask.Attempt) {
				task.PlanBinding = ReadTaskPlanBinding{}
			},
		},
		{
			name: "partial runtime response",
			mutate: func(task *ReadTaskDescriptor, _ *readtask.Descriptor, _ *readtask.Attempt) {
				task.RuntimeBinding = ReadTaskRuntimeBinding{}
			},
		},
		{
			name: "plan response drift",
			mutate: func(task *ReadTaskDescriptor, _ *readtask.Descriptor, _ *readtask.Attempt) {
				task.PlanBinding.RegistryDigest = hex.EncodeToString(bytes.Repeat([]byte{0xb1}, 32))
			},
		},
		{
			name: "runtime response drift",
			mutate: func(task *ReadTaskDescriptor, _ *readtask.Descriptor, _ *readtask.Attempt) {
				task.RuntimeBinding.BoundAt = task.RuntimeBinding.BoundAt.Add(time.Microsecond)
			},
		},
		{
			name: "attempt plan snapshot drift",
			mutate: func(_ *ReadTaskDescriptor, _ *readtask.Descriptor, attempt *readtask.Attempt) {
				attempt.PlanBinding.TasksHash = hex.EncodeToString(bytes.Repeat([]byte{0xb2}, 32))
			},
		},
		{
			name: "attempt runtime snapshot drift",
			mutate: func(_ *ReadTaskDescriptor, _ *readtask.Descriptor, attempt *readtask.Attempt) {
				attempt.RuntimeBinding.ExecutorDigest = hex.EncodeToString(bytes.Repeat([]byte{0xb3}, 32))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			task := response.Task
			descriptor := fixture.descriptor
			attempt := fixture.leased
			test.mutate(&task, &descriptor, &attempt)
			if validReadTaskClaimSnapshotBinding(task, descriptor, attempt) {
				t.Fatal("partial or drifted plan/runtime snapshot was accepted")
			}
		})
	}
}

func TestReadTaskBindingComparisonChecksEveryPublishedField(t *testing.T) {
	t.Parallel()
	identity := testIdentity(t)
	fixture := newReadTaskFixture(t, identity)
	defer fixture.claim.Destroy()

	plan := fixture.descriptor.PlanBinding
	planMutations := []struct {
		name   string
		mutate func(*domain.InvestigationPlanBinding)
	}{
		{"schema version", func(value *domain.InvestigationPlanBinding) { value.SchemaVersion += ".drift" }},
		{"manifest digest", func(value *domain.InvestigationPlanBinding) { value.ManifestDigest = readTaskDriftDigest(0xc1) }},
		{"registry digest", func(value *domain.InvestigationPlanBinding) { value.RegistryDigest = readTaskDriftDigest(0xc2) }},
		{"profile digest", func(value *domain.InvestigationPlanBinding) { value.ProfileDigest = readTaskDriftDigest(0xc3) }},
		{"tasks hash", func(value *domain.InvestigationPlanBinding) { value.TasksHash = readTaskDriftDigest(0xc4) }},
	}
	for _, test := range planMutations {
		t.Run("plan "+test.name, func(t *testing.T) {
			drifted := plan
			test.mutate(&drifted)
			if readTaskPlanBindingsEqual(plan, drifted) ||
				readTaskWirePlanBindingEqual(readTaskPlanBinding(plan), drifted) {
				t.Fatal("plan binding field drift was accepted")
			}
		})
	}

	runtimeBinding := fixture.descriptor.RuntimeBinding
	runtimeMutations := []struct {
		name   string
		mutate func(*domain.ReadTaskRuntimeBinding)
	}{
		{"schema version", func(value *domain.ReadTaskRuntimeBinding) { value.SchemaVersion += ".drift" }},
		{"connector digest", func(value *domain.ReadTaskRuntimeBinding) { value.ConnectorDigest = readTaskDriftDigest(0xd1) }},
		{"target digest", func(value *domain.ReadTaskRuntimeBinding) { value.TargetDigest = readTaskDriftDigest(0xd2) }},
		{"executor digest", func(value *domain.ReadTaskRuntimeBinding) { value.ExecutorDigest = readTaskDriftDigest(0xd3) }},
		{"runtime digest", func(value *domain.ReadTaskRuntimeBinding) { value.RuntimeDigest = readTaskDriftDigest(0xd4) }},
		{"bound at", func(value *domain.ReadTaskRuntimeBinding) { value.BoundAt = value.BoundAt.Add(time.Microsecond) }},
	}
	for _, test := range runtimeMutations {
		t.Run("runtime "+test.name, func(t *testing.T) {
			drifted := runtimeBinding
			test.mutate(&drifted)
			if readTaskRuntimeBindingsEqual(runtimeBinding, drifted) ||
				readTaskWireRuntimeBindingEqual(readTaskRuntimeBinding(runtimeBinding), drifted) {
				t.Fatal("runtime binding field drift was accepted")
			}
		})
	}
}

func readTaskDriftDigest(seed byte) string {
	return hex.EncodeToString(bytes.Repeat([]byte{seed}, 32))
}

type fakeReadTaskBackend struct {
	claim      readtask.Claim
	start      readtask.Attempt
	heartbeat  readtask.HeartbeatResult
	release    readtask.Attempt
	completion readtask.CompletionResult
	binding    readgateway.ResponseBinding

	claimErr       error
	startErr       error
	heartbeatErr   error
	releaseErr     error
	completeErr    error
	claimCalls     int
	startCalls     int
	heartbeatCalls int
	releaseCalls   int
	completeCalls  int

	claimTaskID       string
	lastIdentity      string
	lastSequence      int64
	lastReleaseReason readtask.ReleaseReason
	lastOutcome       readtask.CompletionOutcome
	lastFailureCode   readtask.FailureCode
	tokens            map[string]string
}

func (backend *fakeReadTaskBackend) Claim(
	_ context.Context,
	identity runneridentity.Identity,
	taskID string,
) (readtask.Claim, readgateway.ResponseBinding, error) {
	backend.claimCalls++
	backend.lastIdentity = identity.Instance()
	backend.claimTaskID = taskID
	return backend.claim, backend.responseBinding(identity), backend.claimErr
}

func (backend *fakeReadTaskBackend) Start(
	_ context.Context,
	identity runneridentity.Identity,
	input readtask.Start,
) (readtask.Attempt, readgateway.ResponseBinding, error) {
	backend.startCalls++
	backend.lastIdentity = identity.Instance()
	backend.captureToken("start", input.Fence)
	return backend.start, backend.responseBinding(identity), backend.startErr
}

func (backend *fakeReadTaskBackend) Heartbeat(
	_ context.Context,
	identity runneridentity.Identity,
	input readtask.Heartbeat,
) (readtask.HeartbeatResult, readgateway.ResponseBinding, error) {
	backend.heartbeatCalls++
	backend.lastIdentity = identity.Instance()
	backend.lastSequence = input.Sequence
	backend.captureToken("heartbeat", input.Fence)
	return backend.heartbeat, backend.responseBinding(identity), backend.heartbeatErr
}

func (backend *fakeReadTaskBackend) Release(
	_ context.Context,
	identity runneridentity.Identity,
	input readtask.Release,
) (readtask.Attempt, readgateway.ResponseBinding, error) {
	backend.releaseCalls++
	backend.lastIdentity = identity.Instance()
	backend.lastReleaseReason = input.ReasonCode
	backend.captureToken("release", input.Fence)
	return backend.release, backend.responseBinding(identity), backend.releaseErr
}

func (backend *fakeReadTaskBackend) Complete(
	_ context.Context,
	identity runneridentity.Identity,
	input readtask.Completion,
) (readtask.CompletionResult, readgateway.ResponseBinding, error) {
	backend.completeCalls++
	backend.lastIdentity = identity.Instance()
	backend.lastOutcome = input.Outcome
	backend.lastFailureCode = input.FailureCode
	backend.captureToken("complete", input.Fence)
	return backend.completion, backend.responseBinding(identity), backend.completeErr
}

func (backend *fakeReadTaskBackend) responseBinding(identity runneridentity.Identity) readgateway.ResponseBinding {
	if backend.binding != nil {
		return backend.binding
	}
	return testPrincipalForIdentity(identity, false)
}

func (backend *fakeReadTaskBackend) captureToken(operation string, fence readtask.Fence) {
	if backend.tokens == nil {
		backend.tokens = make(map[string]string)
	}
	token, err := fence.TokenBytes()
	if err == nil {
		backend.tokens[operation] = string(token)
		clear(token)
	}
}

func (backend *fakeReadTaskBackend) totalCalls() int {
	return backend.claimCalls + backend.startCalls + backend.heartbeatCalls + backend.releaseCalls + backend.completeCalls
}

type readTaskFixture struct {
	token       string
	descriptor  readtask.Descriptor
	leased      readtask.Attempt
	running     readtask.Attempt
	heartbeat   readtask.HeartbeatResult
	released    readtask.Attempt
	claim       readtask.Claim
	completion  readtask.CompletionResult
	collectedAt time.Time
}

func newReadTaskFixture(t *testing.T, identity runneridentity.Identity) *readTaskFixture {
	t.Helper()
	token := readTaskTestToken()
	tokenDigest := sha256.Sum256([]byte(token))
	input := json.RawMessage(`{"query":"up > 0 & error_ratio < 1"}`)
	inputDigest := sha256.Sum256(input)
	planBinding := domain.InvestigationPlanBinding{
		SchemaVersion:  domain.InvestigationPlanBindingSchemaVersion,
		ManifestDigest: hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		RegistryDigest: hex.EncodeToString(bytes.Repeat([]byte{0x22}, 32)),
		ProfileDigest:  hex.EncodeToString(bytes.Repeat([]byte{0x33}, 32)),
		TasksHash:      hex.EncodeToString(bytes.Repeat([]byte{0x44}, 32)),
	}
	runtimeBinding := domain.ReadTaskRuntimeBinding{
		SchemaVersion:   domain.ReadTaskRuntimeBindingSchemaVersion,
		ConnectorDigest: hex.EncodeToString(bytes.Repeat([]byte{0x55}, 32)),
		TargetDigest:    hex.EncodeToString(bytes.Repeat([]byte{0x66}, 32)),
		ExecutorDigest:  hex.EncodeToString(bytes.Repeat([]byte{0x77}, 32)),
		RuntimeDigest:   hex.EncodeToString(bytes.Repeat([]byte{0x88}, 32)),
		BoundAt:         time.Date(2040, 1, 2, 2, 4, 5, 0, time.UTC),
	}
	descriptor := readtask.Descriptor{
		TenantID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", WorkspaceID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		EnvironmentID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", IncidentID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		ServiceID:       "c1000000-0000-4000-8000-000000000001",
		InvestigationID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", TaskID: testReadTaskID,
		TaskKey: "metrics", Position: 1,
		ConnectorID: "prometheus-read-v1-" + runtimeBinding.ConnectorDigest, Operation: "query-range",
		Input: input, InputHash: hex.EncodeToString(inputDigest[:]),
		PlanBinding: planBinding, RuntimeBinding: runtimeBinding,
	}
	runtimeDigest, err := investigation.ReadTaskRuntimeDigest(
		investigation.TaskSpecScope{
			TenantID: descriptor.TenantID, WorkspaceID: descriptor.WorkspaceID,
			EnvironmentID: descriptor.EnvironmentID, ServiceID: descriptor.ServiceID,
			MappingStatus: domain.MappingExact,
		},
		descriptor.PlanBinding,
		investigation.TaskSpec{
			Key: descriptor.TaskKey, ConnectorID: descriptor.ConnectorID,
			Operation: descriptor.Operation, Input: append([]byte(nil), descriptor.Input...),
		}, descriptor.Position,
		investigation.TaskRuntimeComponents{
			ConnectorDigest: descriptor.RuntimeBinding.ConnectorDigest,
			TargetDigest:    descriptor.RuntimeBinding.TargetDigest,
			ExecutorDigest:  descriptor.RuntimeBinding.ExecutorDigest,
		},
	)
	if err != nil {
		t.Fatalf("fixture runtime digest: %v", err)
	}
	descriptor.RuntimeBinding.RuntimeDigest = runtimeDigest
	runtimeBinding = descriptor.RuntimeBinding
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("fixture descriptor: %v", err)
	}
	certificate := readtask.CertificateBinding{
		SHA256: identity.Evidence().LeafSHA256(), NotAfter: identity.Evidence().NotAfter().UTC(),
	}
	acquiredAt := certificate.NotAfter.Add(-30 * time.Minute)
	startedAt := acquiredAt.Add(time.Minute)
	collectedAt := startedAt.Add(time.Minute)
	receivedAt := collectedAt.Add(time.Minute)
	leaseExpiresAt := certificate.NotAfter.Add(-5 * time.Minute)
	leased := readtask.Attempt{
		TaskID: descriptor.TaskID, RunnerID: identity.Instance(), ScopeRevision: 1, Certificate: certificate,
		TokenSHA256: hex.EncodeToString(tokenDigest[:]), Epoch: 7, Status: readtask.AttemptLeased,
		LeaseAcquiredAt: acquiredAt, LeaseExpiresAt: leaseExpiresAt, LastHeartbeatAt: acquiredAt, UpdatedAt: acquiredAt,
		PlanBinding: planBinding, RuntimeBinding: runtimeBinding,
	}
	if err := leased.ValidateAgainst(descriptor); err != nil {
		t.Fatalf("fixture leased attempt: %v", err)
	}
	claim, err := readtask.NewClaim(descriptor, leased, []byte(token))
	if err != nil {
		t.Fatal(err)
	}
	running := leased
	running.Status = readtask.AttemptRunning
	running.StartedAt = startedAt
	running.UpdatedAt = startedAt
	heartbeatAttempt := running
	heartbeatAttempt.HeartbeatSequence = 1
	heartbeatAttempt.LastHeartbeatAt = collectedAt
	heartbeatAttempt.UpdatedAt = collectedAt
	heartbeat := readtask.HeartbeatResult{
		Attempt: heartbeatAttempt, AcceptedSequence: 1, Directive: readtask.HeartbeatContinue,
		LeaseExpiresAt: heartbeatAttempt.LeaseExpiresAt,
	}
	released := leased
	released.Status = readtask.AttemptReleased
	released.TerminalAt = startedAt
	released.UpdatedAt = startedAt
	fence, err := readtask.NewFence(descriptor.TaskID, identity.Instance(), []byte(token), leased.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := readtask.ProjectCompletion(descriptor, running, readtask.Completion{
		Fence: fence, Outcome: readtask.CompletionEvidence,
		Evidence: &readtask.EvidenceCompletion{
			CollectedAt: collectedAt,
			Items:       []json.RawMessage{json.RawMessage(`{"metric":"up","value":1}`)},
		},
	}, receivedAt)
	fence.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	completed := running
	completed.Status = readtask.AttemptCompleted
	completed.TerminalAt = receivedAt
	completed.UpdatedAt = receivedAt
	completed.RequestHash = projection.RequestHash()
	completed.ReceiptHash = projection.ReceiptHash()
	completed.RequestHashVersion = readtask.CompletionRequestHashVersionV3
	completed.ReceiptHashVersion = readtask.CompletionReceiptHashVersionV3
	if err := projection.ValidateAgainst(descriptor, completed); err != nil {
		t.Fatal(err)
	}
	completion := readtask.CompletionResult{
		Attempt: completed, Projection: projection,
		EvidenceID: "ffffffff-ffff-4fff-8fff-ffffffffffff",
		ReceiptID:  "99999999-9999-4999-8999-999999999999",
	}
	if err := completion.ValidateAgainst(descriptor); err != nil {
		t.Fatal(err)
	}
	return &readTaskFixture{
		token: token, descriptor: descriptor, leased: leased, running: running, heartbeat: heartbeat,
		released: released, claim: claim, completion: completion, collectedAt: collectedAt,
	}
}

func completionResultForOutcome(
	t *testing.T,
	fixture *readTaskFixture,
	outcome readtask.CompletionOutcome,
	failureCode readtask.FailureCode,
) readtask.CompletionResult {
	t.Helper()
	fence, err := readtask.NewFence(
		fixture.descriptor.TaskID, fixture.running.RunnerID, []byte(fixture.token), fixture.running.Epoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Destroy()
	receivedAt := fixture.completion.Attempt.TerminalAt
	projection, err := readtask.ProjectCompletion(fixture.descriptor, fixture.running, readtask.Completion{
		Fence: fence, Outcome: outcome, FailureCode: failureCode,
	}, receivedAt)
	if err != nil {
		t.Fatal(err)
	}
	completed := fixture.running
	completed.Status = readtask.AttemptCompleted
	completed.TerminalAt = receivedAt
	completed.UpdatedAt = receivedAt
	completed.RequestHash = projection.RequestHash()
	completed.ReceiptHash = projection.ReceiptHash()
	completed.RequestHashVersion = readtask.CompletionRequestHashVersionV3
	completed.ReceiptHashVersion = readtask.CompletionReceiptHashVersionV3
	result := readtask.CompletionResult{
		Attempt: completed, Projection: projection,
		ReceiptID: "99999999-9999-4999-8999-999999999999",
	}
	if err := result.ValidateAgainst(fixture.descriptor); err != nil {
		t.Fatal(err)
	}
	return result
}

func mustReadTaskRouter(
	t *testing.T,
	identity runneridentity.Identity,
	writeBackend Backend,
	readBackend ReadTaskBackend,
) http.Handler {
	t.Helper()
	handler, err := NewRouterWithReadTasks(&staticVerifier{identity: identity}, writeBackend, readBackend)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func readTaskPath(suffix string) string {
	return "/runner/v1/read-tasks/" + testReadTaskID + suffix
}

func readTaskTestToken() string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
}

func nestedReadTaskObject(depth int) json.RawMessage {
	value := []byte("0")
	for range depth - 1 {
		value = append(append([]byte(`{"value":`), value...), '}')
	}
	return value
}

func readTaskAuthorization(token string) []string {
	return []string{"AIOPS-Read-Task-Lease " + token}
}

func jsonHeaders(authorization []string) http.Header {
	header := http.Header{"Content-Type": {"application/json"}}
	if authorization != nil {
		header["Authorization"] = append([]string(nil), authorization...)
	}
	return header
}

func decodeReadTaskResponse(t *testing.T, response *http.Response, target any) {
	t.Helper()
	body := readBody(t, response)
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("decode READ response: %v; body=%s", err, body)
	}
	if decoder.More() {
		t.Fatalf("trailing READ response JSON: %s", body)
	}
}

var _ ReadTaskBackend = (*fakeReadTaskBackend)(nil)
