package executoripc_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executoripc"
)

func TestServeCompletesBoundReadyGoResultExchange(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	request := validPrepareRequest(now)

	var prepare bytes.Buffer
	if err := executoripc.WritePrepare(&prepare, request); err != nil {
		t.Fatalf("WritePrepare() error = %v", err)
	}
	secret, err := credential.NewSensitiveValue([]byte("dynamic-secret-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveValue() error = %v", err)
	}
	defer secret.Destroy()
	var goInput bytes.Buffer
	if err := executoripc.WriteGo(&goInput, secret); err != nil {
		t.Fatalf("WriteGo() error = %v", err)
	}

	handler := &recordingHandler{
		result: execution.ExecutorResult{
			Outcome: execution.ExecutorSucceeded, Code: "ROLLOUT_VERIFIED",
			Verification: execution.VerificationPassed, Changed: true,
		},
	}
	var response bytes.Buffer
	if err := executoripc.Serve(context.Background(), &prepare, &goInput, &response, handler, func() time.Time { return now }); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if handler.validateCalls != 1 || handler.executeCalls != 1 {
		t.Fatalf("handler calls = validate %d, execute %d; want 1 each", handler.validateCalls, handler.executeCalls)
	}
	if handler.actionID != request.JobID || handler.secret != "dynamic-secret-canary" {
		t.Fatalf("handler binding = action %q secret %q", handler.actionID, handler.secret)
	}
	if retained := handler.retained.Bytes(); retained != nil {
		clear(retained)
		t.Fatalf("retained credential remained readable after Serve(): %q", retained)
	}

	ready, err := executoripc.ReadReady(&response, request)
	if err != nil {
		t.Fatalf("ReadReady() error = %v", err)
	}
	if ready.JobID != request.JobID || ready.PlanHash != request.PlanHash || ready.EnvironmentRevision != request.EnvironmentRevision {
		t.Fatalf("ReadReady() = %#v, want request binding", ready)
	}
	result, err := executoripc.ReadResult(&response, request)
	if err != nil {
		t.Fatalf("ReadResult() error = %v", err)
	}
	if result != handler.result {
		t.Fatalf("ReadResult() = %#v, want %#v", result, handler.result)
	}
}

func TestServeRejectsUnsupportedActionBeforeReadyAndNeverLeaksHandlerError(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	request := validPrepareRequest(now)
	prepare := encodedPrepare(t, request)
	goInput := encodedGo(t, []byte("secret-that-must-not-be-consumed"))
	handler := &recordingHandler{validateErr: errors.New("adapter-private-error-canary")}
	var response bytes.Buffer

	err := executoripc.Serve(context.Background(), &prepare, &goInput, &response, handler, func() time.Time { return now })
	if err == nil {
		t.Fatal("Serve() error = nil, want unsupported action rejection")
	}
	if strings.Contains(err.Error(), "adapter-private-error-canary") {
		t.Fatalf("Serve() leaked handler error: %v", err)
	}
	if response.Len() != 0 || handler.validateCalls != 1 || handler.executeCalls != 0 {
		t.Fatalf("rejected PREPARE produced %d response bytes and calls validate=%d execute=%d",
			response.Len(), handler.validateCalls, handler.executeCalls)
	}
}

func TestServeRejectsUnsafePrepareBindingsBeforeHandlerValidation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	tests := map[string]func(*executoripc.PrepareRequest){
		"production":   func(request *executoripc.PrepareRequest) { request.Production = true },
		"job mismatch": func(request *executoripc.PrepareRequest) { request.JobID = "another-action" },
		"plan mismatch": func(request *executoripc.PrepareRequest) {
			request.PlanHash = strings.Repeat("c", 64)
		},
		"environment revision missing": func(request *executoripc.PrepareRequest) { request.EnvironmentRevision = "" },
		"unsigned payload":             func(request *executoripc.PrepareRequest) { request.Payload.Signature = action.Signature{} },
		"expired payload": func(request *executoripc.PrepareRequest) {
			request.Payload.NotBefore = now.Add(-15 * time.Minute)
			request.Payload.ExpiresAt = now
		},
		"not active payload": func(request *executoripc.PrepareRequest) {
			request.Payload.NotBefore = now.Add(time.Second)
			request.Payload.ExpiresAt = now.Add(10 * time.Minute)
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := validPrepareRequest(now)
			mutate(&request)
			prepare := rawPrepare(t, request)
			goInput := encodedGo(t, []byte("unused-secret"))
			handler := &recordingHandler{result: validResult()}
			var response bytes.Buffer
			if err := executoripc.Serve(context.Background(), &prepare, &goInput, &response, handler, func() time.Time { return now }); err == nil {
				t.Fatal("Serve() error = nil, want unsafe PREPARE rejection")
			}
			if response.Len() != 0 || handler.validateCalls != 0 || handler.executeCalls != 0 {
				t.Fatalf("unsafe PREPARE crossed READY boundary: response=%d validate=%d execute=%d",
					response.Len(), handler.validateCalls, handler.executeCalls)
			}
		})
	}
}

func TestServeRejectsNonCanonicalJSONFieldNames(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	request := validPrepareRequest(now)
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	encoded = bytes.Replace(encoded, []byte(`"schema_version"`), []byte(`"SCHEMA_VERSION"`), 1)
	prepare := rawFrame(1, encoded)
	goInput := encodedGo(t, []byte("unused-secret"))
	handler := &recordingHandler{result: validResult()}
	var response bytes.Buffer

	if err := executoripc.Serve(context.Background(), &prepare, &goInput, &response, handler, func() time.Time { return now }); err == nil {
		t.Fatal("Serve() accepted a non-canonical JSON field name")
	}
	if response.Len() != 0 || handler.validateCalls != 0 || handler.executeCalls != 0 {
		t.Fatalf("non-canonical JSON crossed boundary: response=%d validate=%d execute=%d",
			response.Len(), handler.validateCalls, handler.executeCalls)
	}
}

func TestServeRejectsUnknownDuplicateAndTrailingJSON(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	request := validPrepareRequest(now)
	canonical, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	tests := map[string][]byte{
		"unknown top-level field":   append(bytes.Clone(canonical[:len(canonical)-1]), []byte(`,"unknown":true}`)...),
		"duplicate top-level field": append([]byte(`{"schema_version":"executor-prepare.v1",`), canonical[1:]...),
		"unknown nested field": bytes.Replace(canonical, []byte(`"payload":{`),
			[]byte(`"payload":{"unknown":true,`), 1),
		"duplicate nested field": bytes.Replace(canonical, []byte(`"payload":{`),
			[]byte(`"payload":{"action_id":"action-01",`), 1),
		"trailing JSON value": append(bytes.Clone(canonical), []byte(`{}`)...),
	}
	for name, body := range tests {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			prepare := rawFrame(1, body)
			goInput := encodedGo(t, []byte("unused-secret"))
			handler := &recordingHandler{result: validResult()}
			var response bytes.Buffer
			if err := executoripc.Serve(context.Background(), &prepare, &goInput, &response, handler, func() time.Time { return now }); err == nil {
				t.Fatal("Serve() accepted non-strict JSON")
			}
			if response.Len() != 0 || handler.validateCalls != 0 || handler.executeCalls != 0 {
				t.Fatalf("non-strict JSON crossed boundary: response=%d validate=%d execute=%d",
					response.Len(), handler.validateCalls, handler.executeCalls)
			}
		})
	}
}

func TestServeConvertsPostGoHandlerErrorToFixedUncertainResult(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	request := validPrepareRequest(now)
	prepare := encodedPrepare(t, request)
	goInput := encodedGo(t, []byte("dynamic-secret-canary"))
	handler := &recordingHandler{executeErr: errors.New("handler-secret-error-canary")}
	var response bytes.Buffer

	if err := executoripc.Serve(context.Background(), &prepare, &goInput, &response, handler, func() time.Time { return now }); err != nil {
		t.Fatalf("Serve() error = %v, want structured uncertain result", err)
	}
	if _, err := executoripc.ReadReady(&response, request); err != nil {
		t.Fatalf("ReadReady() error = %v", err)
	}
	result, err := executoripc.ReadResult(&response, request)
	if err != nil {
		t.Fatalf("ReadResult() error = %v", err)
	}
	want := execution.ExecutorResult{
		Outcome: execution.ExecutorUncertain, Code: "EXECUTOR_OUTCOME_UNKNOWN",
		Verification: execution.VerificationUnknown,
	}
	if result != want {
		t.Fatalf("ReadResult() = %#v, want %#v", result, want)
	}
	if strings.Contains(response.String(), "handler-secret-error-canary") {
		t.Fatal("response leaked Handler error")
	}
	if retained := handler.retained.Bytes(); retained != nil {
		clear(retained)
		t.Fatalf("retained credential remained readable: %q", retained)
	}
}

func TestServeContainsPostGoHandlerPanicAsFixedUncertainResult(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	request := validPrepareRequest(now)
	prepare := encodedPrepare(t, request)
	goInput := encodedGo(t, []byte("dynamic-secret-canary"))
	handler := &recordingHandler{executePanic: "panic-secret-canary"}
	var response bytes.Buffer

	if err := executoripc.Serve(context.Background(), &prepare, &goInput, &response, handler, func() time.Time { return now }); err != nil {
		t.Fatalf("Serve() error = %v, want contained panic", err)
	}
	if _, err := executoripc.ReadReady(&response, request); err != nil {
		t.Fatalf("ReadReady() error = %v", err)
	}
	result, err := executoripc.ReadResult(&response, request)
	if err != nil {
		t.Fatalf("ReadResult() error = %v", err)
	}
	if result.Outcome != execution.ExecutorUncertain || result.Code != "EXECUTOR_OUTCOME_UNKNOWN" ||
		result.Verification != execution.VerificationUnknown {
		t.Fatalf("ReadResult() = %#v, want fixed UNCERTAIN", result)
	}
	if strings.Contains(response.String(), "panic-secret-canary") {
		t.Fatal("response leaked panic value")
	}
	if retained := handler.retained.Bytes(); retained != nil {
		clear(retained)
		t.Fatalf("retained credential remained readable: %q", retained)
	}
}

func TestServeConvertsInvalidHandlerResultToFixedUncertainResult(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	request := validPrepareRequest(now)
	prepare := encodedPrepare(t, request)
	goInput := encodedGo(t, []byte("dynamic-secret-canary"))
	handler := &recordingHandler{result: execution.ExecutorResult{
		Outcome: execution.ExecutorSucceeded, Code: "INVALID RESULT WITH SPACES",
		Verification: execution.VerificationUnknown,
	}}
	var response bytes.Buffer

	if err := executoripc.Serve(context.Background(), &prepare, &goInput, &response, handler, func() time.Time { return now }); err != nil {
		t.Fatalf("Serve() error = %v, want contained invalid result", err)
	}
	if _, err := executoripc.ReadReady(&response, request); err != nil {
		t.Fatalf("ReadReady() error = %v", err)
	}
	result, err := executoripc.ReadResult(&response, request)
	if err != nil {
		t.Fatalf("ReadResult() error = %v", err)
	}
	if result.Outcome != execution.ExecutorUncertain || result.Code != "EXECUTOR_OUTCOME_UNKNOWN" ||
		result.Verification != execution.VerificationUnknown {
		t.Fatalf("ReadResult() = %#v, want fixed UNCERTAIN", result)
	}
}

func TestServeContainsPreReadyHandlerPanicWithoutResponse(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	request := validPrepareRequest(now)
	prepare := encodedPrepare(t, request)
	goInput := encodedGo(t, []byte("unused-secret"))
	handler := &recordingHandler{validatePanic: "validation-panic-canary"}
	var response bytes.Buffer

	err := executoripc.Serve(context.Background(), &prepare, &goInput, &response, handler, func() time.Time { return now })
	if err == nil {
		t.Fatal("Serve() error = nil, want contained validation panic")
	}
	if strings.Contains(err.Error(), "validation-panic-canary") {
		t.Fatalf("Serve() leaked panic value: %v", err)
	}
	if response.Len() != 0 || handler.executeCalls != 0 {
		t.Fatalf("validation panic crossed READY boundary: response=%d execute=%d", response.Len(), handler.executeCalls)
	}
}

func TestServeHonorsCancellationBeforePrepareWithoutCallingHandler(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	request := validPrepareRequest(now)
	prepare := encodedPrepare(t, request)
	goInput := encodedGo(t, []byte("unused-secret"))
	handler := &recordingHandler{result: validResult()}
	var response bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := executoripc.Serve(ctx, &prepare, &goInput, &response, handler, func() time.Time { return now })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve() error = %v, want context.Canceled", err)
	}
	if response.Len() != 0 || handler.validateCalls != 0 || handler.executeCalls != 0 {
		t.Fatalf("cancelled Serve crossed boundary: response=%d validate=%d execute=%d",
			response.Len(), handler.validateCalls, handler.executeCalls)
	}
}

func TestServeRejectsMalformedAndOversizedPrepareFramesBeforeHandler(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	request := validPrepareRequest(now)
	validFrame := encodedPrepare(t, request)
	valid := validFrame.Bytes()
	wrongMagic := bytes.Clone(valid)
	wrongMagic[0] ^= 0xff
	wrongVersion := bytes.Clone(valid)
	wrongVersion[8] = 2
	wrongType := bytes.Clone(valid)
	wrongType[9] = 2
	tests := map[string]struct {
		frame   []byte
		wantErr error
	}{
		"short header":       {frame: valid[:10], wantErr: executoripc.ErrProtocol},
		"wrong magic":        {frame: wrongMagic, wantErr: executoripc.ErrProtocol},
		"wrong version":      {frame: wrongVersion, wantErr: executoripc.ErrProtocol},
		"wrong type":         {frame: wrongType, wantErr: executoripc.ErrProtocol},
		"zero body":          {frame: rawDeclaredFrame(1, 0, nil), wantErr: executoripc.ErrProtocol},
		"truncated body":     {frame: rawDeclaredFrame(1, 10, []byte(`{}`)), wantErr: executoripc.ErrProtocol},
		"oversized declared": {frame: rawDeclaredFrame(1, (256<<10)+1, nil), wantErr: executoripc.ErrFrameTooLarge},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			prepare := bytes.NewReader(test.frame)
			goInput := encodedGo(t, []byte("unused-secret"))
			handler := &recordingHandler{result: validResult()}
			var response bytes.Buffer
			err := executoripc.Serve(context.Background(), prepare, &goInput, &response, handler, func() time.Time { return now })
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Serve() error = %v, want %v", err, test.wantErr)
			}
			if response.Len() != 0 || handler.validateCalls != 0 || handler.executeCalls != 0 {
				t.Fatalf("malformed frame crossed boundary: response=%d validate=%d execute=%d",
					response.Len(), handler.validateCalls, handler.executeCalls)
			}
		})
	}
}

func TestWriteGoUsesRawBytesAtTheExactSecretLimit(t *testing.T) {
	t.Parallel()
	material := bytes.Repeat([]byte{0xa5}, 64<<10)
	defer clear(material)
	secret, err := credential.NewSensitiveValue(material)
	if err != nil {
		t.Fatalf("NewSensitiveValue() error = %v", err)
	}
	var wire bytes.Buffer
	if err := executoripc.WriteGo(&wire, secret); err != nil {
		t.Fatalf("WriteGo() error = %v", err)
	}
	secret.Destroy()
	encoded := wire.Bytes()
	if len(encoded) != 14+len(material) || string(encoded[:8]) != "AIOPSIPC" || encoded[8] != 1 || encoded[9] != 2 {
		t.Fatalf("WriteGo() produced malformed header of %d bytes", len(encoded))
	}
	if got := binary.BigEndian.Uint32(encoded[10:14]); got != uint32(len(material)) {
		t.Fatalf("WriteGo() length = %d, want %d", got, len(material))
	}
	if !bytes.Equal(encoded[14:], material) {
		t.Fatal("WriteGo() did not preserve raw secret bytes")
	}
	if err := executoripc.WriteGo(&bytes.Buffer{}, secret); !errors.Is(err, executoripc.ErrInvalidInput) {
		t.Fatalf("WriteGo(destroyed secret) error = %v, want ErrInvalidInput", err)
	}
	clear(encoded[14:])
}

func TestServeRejectsMalformedAndOversizedGoFramesAfterReadyWithoutExecuting(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	request := validPrepareRequest(now)
	validGoFrame := encodedGo(t, []byte("valid-secret"))
	validGo := validGoFrame.Bytes()
	wrongMagic := bytes.Clone(validGo)
	wrongMagic[0] ^= 0xff
	wrongVersion := bytes.Clone(validGo)
	wrongVersion[8] = 2
	wrongType := bytes.Clone(validGo)
	wrongType[9] = 1
	tests := map[string]struct {
		frame   []byte
		wantErr error
	}{
		"short header":       {frame: validGo[:10], wantErr: executoripc.ErrProtocol},
		"wrong magic":        {frame: wrongMagic, wantErr: executoripc.ErrProtocol},
		"wrong version":      {frame: wrongVersion, wantErr: executoripc.ErrProtocol},
		"wrong type":         {frame: wrongType, wantErr: executoripc.ErrProtocol},
		"zero body":          {frame: rawDeclaredFrame(2, 0, nil), wantErr: executoripc.ErrProtocol},
		"truncated body":     {frame: rawDeclaredFrame(2, 10, []byte("short")), wantErr: executoripc.ErrProtocol},
		"oversized declared": {frame: rawDeclaredFrame(2, (64<<10)+1, nil), wantErr: executoripc.ErrFrameTooLarge},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			prepare := encodedPrepare(t, request)
			handler := &recordingHandler{result: validResult()}
			var response bytes.Buffer
			err := executoripc.Serve(context.Background(), &prepare, bytes.NewReader(test.frame), &response, handler, func() time.Time { return now })
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Serve() error = %v, want %v", err, test.wantErr)
			}
			if _, err := executoripc.ReadReady(&response, request); err != nil {
				t.Fatalf("ReadReady() error = %v", err)
			}
			if handler.validateCalls != 1 || handler.executeCalls != 0 {
				t.Fatalf("malformed GO calls = validate %d execute %d, want 1/0", handler.validateCalls, handler.executeCalls)
			}
		})
	}
}

func TestReadReadyRejectsCrossJobAndNonStrictResponses(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	request := validPrepareRequest(now)
	ready := executoripc.Ready{
		SchemaVersion: executoripc.ReadySchemaVersionV1, JobID: request.JobID,
		PlanHash: request.PlanHash, EnvironmentRevision: request.EnvironmentRevision,
	}
	canonical, err := json.Marshal(ready)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	tests := map[string][]byte{
		"wrong job": frameBytes(rawJSONFrame(t, 3, executoripc.Ready{
			SchemaVersion: executoripc.ReadySchemaVersionV1, JobID: "another-action",
			PlanHash: request.PlanHash, EnvironmentRevision: request.EnvironmentRevision,
		})),
		"wrong plan": frameBytes(rawJSONFrame(t, 3, executoripc.Ready{
			SchemaVersion: executoripc.ReadySchemaVersionV1, JobID: request.JobID,
			PlanHash: strings.Repeat("c", 64), EnvironmentRevision: request.EnvironmentRevision,
		})),
		"wrong environment revision": frameBytes(rawJSONFrame(t, 3, executoripc.Ready{
			SchemaVersion: executoripc.ReadySchemaVersionV1, JobID: request.JobID,
			PlanHash: request.PlanHash, EnvironmentRevision: "another-revision",
		})),
		"unknown field": frameBytes(rawFrame(3,
			append(bytes.Clone(canonical[:len(canonical)-1]), []byte(`,"unknown":true}`)...))),
		"duplicate field": frameBytes(rawFrame(3,
			append([]byte(`{"job_id":"action-01",`), canonical[1:]...))),
		"non-canonical field": frameBytes(rawFrame(3,
			bytes.Replace(canonical, []byte(`"schema_version"`), []byte(`"SCHEMA_VERSION"`), 1))),
		"trailing JSON":    frameBytes(rawFrame(3, append(bytes.Clone(canonical), []byte(`{}`)...))),
		"wrong frame type": frameBytes(rawFrame(4, canonical)),
		"oversized frame":  rawDeclaredFrame(3, (16<<10)+1, nil),
	}
	for name, wire := range tests {
		name, wire := name, wire
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := executoripc.ReadReady(bytes.NewReader(wire), request); err == nil {
				t.Fatal("ReadReady() accepted an unbound or non-strict response")
			}
		})
	}
}

func TestReadResultRejectsCrossJobAndInvalidResultResponses(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	request := validPrepareRequest(now)
	valid := map[string]any{
		"schema_version": executoripc.ResultSchemaVersionV1,
		"job_id":         request.JobID, "plan_hash": request.PlanHash,
		"environment_revision": request.EnvironmentRevision, "result": validResult(),
	}
	tests := map[string]map[string]any{
		"wrong job":                  cloneResultMap(valid, "job_id", "another-action"),
		"wrong plan":                 cloneResultMap(valid, "plan_hash", strings.Repeat("c", 64)),
		"wrong environment revision": cloneResultMap(valid, "environment_revision", "another-revision"),
		"invalid result": cloneResultMap(valid, "result", execution.ExecutorResult{
			Outcome: execution.ExecutorSucceeded, Code: "ROLLOUT_VERIFIED", Verification: execution.VerificationUnknown,
		}),
		"unknown field": cloneResultMap(valid, "unknown", true),
	}
	for name, response := range tests {
		name, response := name, response
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wire := rawJSONFrame(t, 4, response)
			if _, err := executoripc.ReadResult(&wire, request); err == nil {
				t.Fatal("ReadResult() accepted an unbound or invalid response")
			}
		})
	}
}

type recordingHandler struct {
	validateCalls int
	executeCalls  int
	actionID      string
	secret        string
	retained      credential.SensitiveValue
	result        execution.ExecutorResult
	validateErr   error
	executeErr    error
	validatePanic any
	executePanic  any
}

func (handler *recordingHandler) Validate(envelope action.Envelope) error {
	handler.validateCalls++
	handler.actionID = envelope.ActionID
	if handler.validatePanic != nil {
		panic(handler.validatePanic)
	}
	return handler.validateErr
}

func (handler *recordingHandler) Execute(_ context.Context, envelope action.Envelope, secret credential.SensitiveValue) (execution.ExecutorResult, error) {
	handler.executeCalls++
	handler.actionID = envelope.ActionID
	handler.retained = secret
	material := secret.Bytes()
	defer clear(material)
	handler.secret = string(material)
	if handler.executePanic != nil {
		panic(handler.executePanic)
	}
	return handler.result, handler.executeErr
}

func validPrepareRequest(now time.Time) executoripc.PrepareRequest {
	envelope := action.Envelope{
		SchemaVersion: action.SchemaVersionV1,
		ActionID:      "action-01",
		WorkspaceID:   "workspace-01",
		IncidentID:    "incident-01",
		RequestedBy:   "requester-01",
		ActionType:    action.ActionKubernetesRolloutRestart,
		Target: action.TargetRef{ServiceID: "service-payments", EnvironmentID: "STAGING", KubernetesDeployment: &action.KubernetesDeploymentTarget{
			ClusterID: "cluster-a", Namespace: "payments", Name: "payments-api", UID: "uid-01", ResourceVersion: "83",
		}},
		Parameters: action.ActionParameters{KubernetesRolloutRestart: &action.KubernetesRolloutRestartParameters{Reason: "recover deadlock"}},
		ObservedState: action.ObservedState{KubernetesDeployment: &action.KubernetesDeploymentObservedState{
			Generation: 17, Replicas: 3, AvailableReplicas: 3, UpdatedReplicas: 3,
		}},
		Preconditions: action.Preconditions{MappingResult: "EXACT", ExpectedResourceVersion: "83", RequireWhitelist: true},
		Verification:  action.VerificationPlan{Mode: "KUBERNETES_ROLLOUT", TimeoutSeconds: 300},
		Compensation:  action.CompensationPlan{Mode: "MANUAL_ONLY", Summary: "follow runbook"},
		Risk:          action.RiskAssessment{Level: "MEDIUM", ReasonCodes: []string{"RESTART"}},
		PolicyVersion: "policy.v1",
		CredentialScope: action.CredentialScope{
			ConnectorID: "kubernetes-staging", Permission: "PATCH_DEPLOYMENT_RESTART",
			Resource: "cluster-a/payments/deployment/payments-api", TTLSeconds: 600,
		},
		IdempotencyKey: "idem-action-01",
		NotBefore:      now.Add(-time.Minute),
		ExpiresAt:      now.Add(14 * time.Minute),
		TraceID:        strings.Repeat("a", 32),
		PlanHash:       strings.Repeat("b", 64),
		Signature: action.Signature{
			Algorithm: action.SignatureEd25519, KeyID: "control-plane-key",
			Value: strings.Repeat("A", 86),
		},
	}
	return executoripc.PrepareRequest{
		SchemaVersion: "executor-prepare.v1", JobID: envelope.ActionID,
		PlanHash: envelope.PlanHash, EnvironmentRevision: "staging-revision-17",
		Production: false, Payload: envelope,
	}
}

func validResult() execution.ExecutorResult {
	return execution.ExecutorResult{
		Outcome: execution.ExecutorSucceeded, Code: "ROLLOUT_VERIFIED",
		Verification: execution.VerificationPassed, Changed: true,
	}
}

func encodedPrepare(t *testing.T, request executoripc.PrepareRequest) bytes.Buffer {
	t.Helper()
	var output bytes.Buffer
	if err := executoripc.WritePrepare(&output, request); err != nil {
		t.Fatalf("WritePrepare() error = %v", err)
	}
	return output
}

func rawPrepare(t *testing.T, request executoripc.PrepareRequest) bytes.Buffer {
	t.Helper()
	return rawJSONFrame(t, 1, request)
}

func encodedGo(t *testing.T, material []byte) bytes.Buffer {
	t.Helper()
	secret, err := credential.NewSensitiveValue(material)
	if err != nil {
		t.Fatalf("NewSensitiveValue() error = %v", err)
	}
	defer secret.Destroy()
	var output bytes.Buffer
	if err := executoripc.WriteGo(&output, secret); err != nil {
		t.Fatalf("WriteGo() error = %v", err)
	}
	return output
}

func rawJSONFrame(t *testing.T, kind byte, value any) bytes.Buffer {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return rawFrame(kind, encoded)
}

func rawFrame(kind byte, body []byte) bytes.Buffer {
	var output bytes.Buffer
	output.WriteString("AIOPSIPC")
	output.WriteByte(1)
	output.WriteByte(kind)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(body)))
	output.Write(length[:])
	output.Write(body)
	return output
}

func rawDeclaredFrame(kind byte, length uint32, body []byte) []byte {
	var output bytes.Buffer
	output.WriteString("AIOPSIPC")
	output.WriteByte(1)
	output.WriteByte(kind)
	var encodedLength [4]byte
	binary.BigEndian.PutUint32(encodedLength[:], length)
	output.Write(encodedLength[:])
	output.Write(body)
	return output.Bytes()
}

func frameBytes(frame bytes.Buffer) []byte {
	return bytes.Clone(frame.Bytes())
}

func cloneResultMap(input map[string]any, key string, value any) map[string]any {
	cloned := make(map[string]any, len(input)+1)
	for name, item := range input {
		cloned[name] = item
	}
	cloned[key] = value
	return cloned
}
