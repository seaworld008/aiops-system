package investigationworkflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/readtask"
	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	failurepb "go.temporal.io/api/failure/v1"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"google.golang.org/protobuf/proto"
)

func TestRuntimeV2DataConverterCanonicalWorkflowInputRoundTrip(t *testing.T) {
	dataConverter, err := newRuntimeV2DataConverter()
	if err != nil {
		t.Fatalf("newRuntimeV2DataConverter() error = %v", err)
	}
	input := converterTestWorkflowInput()

	payloads, err := dataConverter.ToPayloads(input)
	if err != nil {
		t.Fatalf("ToPayloads() error = %v", err)
	}
	if payloads == nil || len(payloads.Payloads) != 1 || payloads.Payloads[0] == nil {
		t.Fatalf("ToPayloads() = %#v", payloads)
	}
	payload := payloads.Payloads[0]
	if proto.Size(payload) > maximumHistoryDTOBytes || proto.Size(payloads) > maximumHistoryDTOBytes ||
		len(payload.Metadata) != 1 || !bytes.Equal(payload.Metadata[converter.MetadataEncoding], []byte(converter.MetadataEncodingJSON)) {
		t.Fatalf("payload violates exact json/plain 4 KiB contract: %#v", payload)
	}

	var decoded WorkflowInputV2
	if err := dataConverter.FromPayloads(payloads, &decoded); err != nil {
		t.Fatalf("FromPayloads() error = %v", err)
	}
	if !reflect.DeepEqual(decoded, input) {
		t.Fatalf("decoded = %#v, want %#v", decoded, input)
	}
	second, err := dataConverter.ToPayload(decoded)
	if err != nil || !proto.Equal(second, payload) {
		t.Fatalf("second canonical payload = %#v, %v", second, err)
	}
}

func TestRuntimeV2DataConverterAllowsOnlyProtocolDTOsAndPrivateMemoIdentity(t *testing.T) {
	dataConverter, err := newRuntimeV2DataConverter()
	if err != nil {
		t.Fatal(err)
	}
	input := converterTestWorkflowInput()
	readInput := converterTestReadInput()
	allowed := []struct {
		name        string
		value       interface{}
		destination func() interface{}
	}{
		{"workflow input", input, func() interface{} { return &WorkflowInputV2{} }},
		{"workflow result", converterTestWorkflowResult(), func() interface{} { return &WorkflowResultV2{} }},
		{"preparation receipt", converterTestPreparationReceipt(), func() interface{} { return &PreparationReceiptV2{} }},
		{"read task input", readInput, func() interface{} { return &ReadTaskActivityInputV1{} }},
		{"read task output", converterTestReadOutput(), func() interface{} { return &ReadTaskActivityOutputV1{} }},
		{"recovery input", recoveryInputFromReadTask(readInput), func() interface{} { return &RecoveryActivityInput{} }},
		{"recovery output", converterTestRecoveryOutput(), func() interface{} { return &RecoveryActivityOutput{} }},
	}
	for _, testCase := range allowed {
		t.Run(testCase.name, func(t *testing.T) {
			payload, err := dataConverter.ToPayload(testCase.value)
			if err != nil {
				t.Fatalf("ToPayload() error = %v", err)
			}
			destination := testCase.destination()
			if err := dataConverter.FromPayload(payload, destination); err != nil {
				t.Fatalf("FromPayload() error = %v", err)
			}
			if !reflect.DeepEqual(reflect.ValueOf(destination).Elem().Interface(), testCase.value) {
				t.Fatalf("round trip = %#v, want %#v", destination, testCase.value)
			}
		})
	}

	identity, expected, err := newRuntimeV2MemoIdentity(input)
	if err != nil {
		t.Fatalf("newRuntimeV2MemoIdentity() error = %v", err)
	}
	payload, err := dataConverter.ToPayload(identity)
	if err != nil || !proto.Equal(payload, expected) {
		t.Fatalf("memo payload = %#v, %v; want %#v", payload, err, expected)
	}
	if _, err := json.Marshal(identity); !errors.Is(err, errRuntimeV2PayloadRejected) {
		t.Fatalf("json.Marshal(private identity) error = %v", err)
	}
	var decodedIdentity runtimeV2MemoIdentity
	if err := json.Unmarshal(expected.Data, &decodedIdentity); !errors.Is(err, errRuntimeV2PayloadRejected) {
		t.Fatalf("json.Unmarshal(private identity) error = %v", err)
	}

	unknown := []interface{}{struct{}{}, "secret", []byte("secret"), 1, nil, (*WorkflowInputV2)(nil), &identity}
	for _, value := range unknown {
		if _, err := dataConverter.ToPayload(value); !errors.Is(err, errRuntimeV2PayloadRejected) {
			t.Fatalf("ToPayload(%T) error = %v", value, err)
		}
	}
}

func TestRuntimeV2DataConverterRejectsNonCanonicalMalformedAndNonSinglePayloads(t *testing.T) {
	dataConverter, err := newRuntimeV2DataConverter()
	if err != nil {
		t.Fatal(err)
	}
	valid, err := dataConverter.ToPayload(converterTestWorkflowInput())
	if err != nil {
		t.Fatal(err)
	}
	invalidPayloads := map[string]*commonpb.Payload{
		"nil":                  nil,
		"missing metadata":     {Data: bytes.Clone(valid.Data)},
		"unknown metadata":     {Metadata: map[string][]byte{"encoding": []byte("json/plain"), "extra": []byte("x")}, Data: bytes.Clone(valid.Data)},
		"wrong encoding":       {Metadata: map[string][]byte{"encoding": []byte("binary/plain")}, Data: bytes.Clone(valid.Data)},
		"noncanonical":         {Metadata: map[string][]byte{"encoding": []byte("json/plain")}, Data: append([]byte(" "), valid.Data...)},
		"unknown field":        {Metadata: map[string][]byte{"encoding": []byte("json/plain")}, Data: append(bytes.TrimSuffix(valid.Data, []byte("}")), []byte(",\"unknown\":true}")...)},
		"malformed":            {Metadata: map[string][]byte{"encoding": []byte("json/plain")}, Data: []byte(`{"version":`)},
		"oversized data/proto": {Metadata: map[string][]byte{"encoding": []byte("json/plain")}, Data: bytes.Repeat([]byte{'x'}, maximumHistoryDTOBytes)},
	}
	for name, payload := range invalidPayloads {
		t.Run(name, func(t *testing.T) {
			destination := converterTestWorkflowInput()
			before := destination
			if err := dataConverter.FromPayload(payload, &destination); !errors.Is(err, errRuntimeV2PayloadRejected) {
				t.Fatalf("FromPayload() error = %v", err)
			}
			if destination != before {
				t.Fatalf("invalid decode mutated destination: %#v", destination)
			}
		})
	}

	if payloads, err := dataConverter.ToPayloads(); payloads != nil || err != nil {
		t.Fatalf("ToPayloads() = %#v, %v; want nil, nil for SDK empty error details", payloads, err)
	}
	if _, err := dataConverter.ToPayloads(converterTestWorkflowInput(), converterTestWorkflowInput()); !errors.Is(err, errRuntimeV2PayloadRejected) {
		t.Fatalf("ToPayloads(two) error = %v", err)
	}
	if err := dataConverter.FromPayloads(nil, &WorkflowInputV2{}); !errors.Is(err, errRuntimeV2PayloadRejected) {
		t.Fatalf("FromPayloads(nil) error = %v", err)
	}
	if err := dataConverter.FromPayloads(nil); err != nil {
		t.Fatalf("FromPayloads(nil, no destinations) error = %v", err)
	}
	if err := dataConverter.FromPayloads(&commonpb.Payloads{}); !errors.Is(err, errRuntimeV2PayloadRejected) {
		t.Fatalf("FromPayloads(non-nil empty) error = %v", err)
	}
	if err := dataConverter.FromPayloads(
		&commonpb.Payloads{Payloads: []*commonpb.Payload{valid, valid}}, &WorkflowInputV2{}, &WorkflowInputV2{},
	); !errors.Is(err, errRuntimeV2PayloadRejected) {
		t.Fatalf("FromPayloads(two) error = %v", err)
	}
	var typedNil *WorkflowResultV2
	if err := dataConverter.FromPayload(valid, typedNil); !errors.Is(err, errRuntimeV2PayloadRejected) {
		t.Fatalf("FromPayload(typed nil) error = %v", err)
	}
	if err := dataConverter.FromPayload(valid, &struct{}{}); !errors.Is(err, errRuntimeV2PayloadRejected) {
		t.Fatalf("FromPayload(unknown) error = %v", err)
	}
}

func TestRuntimeV2DataConverterCopiesAndInvalidDTOsFailClosed(t *testing.T) {
	dataConverter, err := newRuntimeV2DataConverter()
	if err != nil {
		t.Fatal(err)
	}
	copyOfConverter := *dataConverter
	invalidConverters := []*runtimeV2DataConverter{nil, {}, &copyOfConverter}
	for _, invalid := range invalidConverters {
		if _, err := invalid.ToPayload(converterTestWorkflowInput()); !errors.Is(err, errRuntimeV2PayloadRejected) {
			t.Fatalf("invalid converter ToPayload() error = %v", err)
		}
	}
	invalidInput := converterTestWorkflowInput()
	invalidInput.BundleDigest = "secret-invalid-digest"
	if _, err := dataConverter.ToPayload(invalidInput); !errors.Is(err, errRuntimeV2PayloadRejected) {
		t.Fatalf("ToPayload(invalid DTO) error = %v", err)
	}
	if got := dataConverter.ToString(&commonpb.Payload{Data: []byte("secret-canary")}); got != "<runtime-v2-payload>" {
		t.Fatalf("ToString() = %q", got)
	}
}

func TestRuntimeV2FailureConverterSupportsOnlyClosedLowSensitiveFailures(t *testing.T) {
	dataConverter, err := newRuntimeV2DataConverter()
	if err != nil {
		t.Fatal(err)
	}
	failureConverter, err := newRuntimeV2FailureConverter(dataConverter)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name         string
		err          error
		details      func() *commonpb.Payloads
		nonRetryable bool
	}{
		{
			name: "retryable", err: temporal.NewApplicationError(
				"investigation preparation dependency unavailable", "PREPARE_DEPENDENCY_UNAVAILABLE",
			),
			details: func() *commonpb.Payloads { return nil },
		},
		{
			name: "nonretryable", err: temporal.NewNonRetryableApplicationError(
				"investigation preparation fact rejected", "PREPARE_FACT_CONFLICT", nil,
			),
			details: func() *commonpb.Payloads { return nil }, nonRetryable: true,
		},
		{
			name: "canceled", err: temporal.NewCanceledError(),
			details: func() *commonpb.Payloads { return nil },
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			failure := failureConverter.ErrorToFailure(testCase.err)
			if failure == nil || failure.Source != runtimeV2FailureSource || failure.StackTrace != "" ||
				failure.EncodedAttributes != nil || strings.Contains(failure.Message, "fixed") {
				t.Fatal("ErrorToFailure() returned nil")
			}
			var details *commonpb.Payloads
			if application := failure.GetApplicationFailureInfo(); application != nil {
				details = application.Details
				if application.NonRetryable != testCase.nonRetryable {
					t.Fatalf("NonRetryable = %t", application.NonRetryable)
				}
			} else if canceled := failure.GetCanceledFailureInfo(); canceled != nil {
				details = canceled.Details
			} else {
				t.Fatalf("unexpected FailureInfo = %T", failure.FailureInfo)
			}
			if details != testCase.details() {
				t.Fatalf("Details = %#v, want nil", details)
			}
			if decoded := failureConverter.FailureToError(failure); decoded == nil {
				t.Fatal("FailureToError() returned nil")
			}
		})
	}

	for name, errorWithDetails := range map[string]error{
		"unknown detail": temporal.NewApplicationError(
			"secret-message", "PREPARE_FACT_CONFLICT", "secret-detail",
		),
		"allowlisted DTO detail": temporal.NewApplicationError(
			"secret-message", "PREPARE_FACT_CONFLICT", converterTestWorkflowInput(),
		),
	} {
		t.Run(name, func(t *testing.T) {
			assertRejectedRuntimeV2Failure(t, failureConverter.ErrorToFailure(errorWithDetails))
		})
	}

	validPayloads, err := dataConverter.ToPayloads(converterTestWorkflowInput())
	if err != nil {
		t.Fatal(err)
	}
	defaultConverter := temporal.NewDefaultFailureConverter(temporal.DefaultFailureConverterOptions{
		DataConverter: dataConverter,
	})
	malicious := &failurepb.Failure{
		Message: "failure-holder-secret-canary", Source: "foreign", StackTrace: "secret stack",
		FailureInfo: &failurepb.Failure_ApplicationFailureInfo{ApplicationFailureInfo: &failurepb.ApplicationFailureInfo{
			Type: "PREPARE_FACT_CONFLICT", NonRetryable: true, Details: validPayloads,
		}},
	}
	holder := defaultConverter.FailureToError(malicious)
	assertRejectedRuntimeV2Failure(t, failureConverter.ErrorToFailure(holder))
	decoded := failureConverter.FailureToError(malicious)
	assertRejectedRuntimeV2Failure(t, failureConverter.ErrorToFailure(decoded))
	cyclic := &failurepb.Failure{
		Message: "cycle-secret-canary",
		FailureInfo: &failurepb.Failure_ApplicationFailureInfo{ApplicationFailureInfo: &failurepb.ApplicationFailureInfo{
			Type: "PREPARE_FACT_CONFLICT", NonRetryable: true,
		}},
	}
	cyclic.Cause = cyclic
	assertRejectedRuntimeV2Failure(t, failureConverter.ErrorToFailure(failureConverter.FailureToError(cyclic)))

	activityFailure := &failurepb.Failure{
		Message: "activity-secret-canary", Source: "foreign",
		Cause: failureConverter.ErrorToFailure(temporal.NewNonRetryableApplicationError(
			"investigation preparation fact rejected", "PREPARE_FACT_CONFLICT", nil,
		)),
		FailureInfo: &failurepb.Failure_ActivityFailureInfo{ActivityFailureInfo: &failurepb.ActivityFailureInfo{
			ScheduledEventId: 1, StartedEventId: 2, Identity: "identity-secret-canary",
			ActivityType: &commonpb.ActivityType{Name: PrepareActivityNameV2},
			ActivityId:   "activity-id-secret-canary", RetryState: enumspb.RETRY_STATE_NON_RETRYABLE_FAILURE,
		}},
	}
	activityError := failureConverter.FailureToError(activityFailure)
	normalizedActivity := failureConverter.ErrorToFailure(activityError)
	activityInfo := normalizedActivity.GetActivityFailureInfo()
	if activityInfo == nil || activityInfo.Identity != "" || activityInfo.ActivityId != "" ||
		activityInfo.ActivityType.GetName() != PrepareActivityNameV2 ||
		strings.Contains(normalizedActivity.String(), "secret-canary") {
		t.Fatalf("normalized Activity failure = %#v", normalizedActivity)
	}
}

func assertRejectedRuntimeV2Failure(t *testing.T, failure *failurepb.Failure) {
	t.Helper()
	if failure == nil || failure.Message != errRuntimeV2FailureRejected.Error() ||
		failure.Source != runtimeV2FailureSource || failure.StackTrace != "" ||
		failure.EncodedAttributes != nil || failure.Cause != nil ||
		failure.GetApplicationFailureInfo() == nil ||
		failure.GetApplicationFailureInfo().Type != runtimeV2FailureRejectedType ||
		!failure.GetApplicationFailureInfo().NonRetryable ||
		failure.GetApplicationFailureInfo().Details != nil ||
		strings.Contains(failure.String(), "secret") {
		t.Fatalf("rejected failure = %#v", failure)
	}
}

func converterTestWorkflowInput() WorkflowInputV2 {
	return WorkflowInputV2{
		Version: RuntimeV2SchemaVersion, OutboxEventID: "11111111-1111-4111-8111-111111111111",
		TenantID: "22222222-2222-4222-8222-222222222222", WorkspaceID: "33333333-3333-4333-8333-333333333333",
		SignalID: "44444444-4444-4444-8444-444444444444", AggregateVersion: 1,
		ManifestDigest: strings.Repeat("a", 64), RegistryDigest: strings.Repeat("b", 64),
		BundleDigest: strings.Repeat("c", 64),
	}
}

func converterTestPreparationReceipt() PreparationReceiptV2 {
	input := converterTestWorkflowInput()
	return PreparationReceiptV2{
		Version: RuntimeV2SchemaVersion, State: StateNoActiveIncident,
		OutboxEventID: input.OutboxEventID, TenantID: input.TenantID, WorkspaceID: input.WorkspaceID,
		SignalID: input.SignalID, ManifestDigest: input.ManifestDigest, RegistryDigest: input.RegistryDigest,
		BundleDigest: input.BundleDigest, ProfileDigest: strings.Repeat("d", 64), TasksHash: strings.Repeat("e", 64),
	}
}

func converterTestWorkflowResult() WorkflowResultV2 {
	receipt := converterTestPreparationReceipt()
	return WorkflowResultV2{
		Version: RuntimeV2SchemaVersion, State: RuntimeStateNoActiveIncident,
		OutboxEventID: receipt.OutboxEventID, TenantID: receipt.TenantID, WorkspaceID: receipt.WorkspaceID,
		SignalID: receipt.SignalID, ManifestDigest: receipt.ManifestDigest, RegistryDigest: receipt.RegistryDigest,
		BundleDigest: receipt.BundleDigest, ProfileDigest: receipt.ProfileDigest, TasksHash: receipt.TasksHash,
	}
}

func converterTestReadInput() ReadTaskActivityInputV1 {
	input := converterTestWorkflowInput()
	return ReadTaskActivityInputV1{
		Version: ReadTaskActivitySchemaVersion, OutboxEventID: input.OutboxEventID,
		TenantID: input.TenantID, WorkspaceID: input.WorkspaceID,
		EnvironmentID: "55555555-5555-4555-8555-555555555555", ServiceID: "66666666-6666-4666-8666-666666666666",
		IncidentID: "77777777-7777-4777-8777-777777777777", InvestigationID: "88888888-8888-4888-8888-888888888888",
		TaskID: "99999999-9999-4999-8999-999999999999", Position: 1,
		ManifestDigest: input.ManifestDigest, RegistryDigest: input.RegistryDigest, BundleDigest: input.BundleDigest,
		ProfileDigest: strings.Repeat("d", 64), TasksHash: strings.Repeat("e", 64), Round: 1,
	}
}

func converterTestReadOutput() ReadTaskActivityOutputV1 {
	input := converterTestReadInput()
	return ReadTaskActivityOutputV1{
		Version: ReadTaskActivitySchemaVersion, State: ReadTaskActivityNotClaimed,
		InvestigationID: input.InvestigationID, TaskID: input.TaskID, Position: input.Position, Round: input.Round,
	}
}

func converterTestRecoveryOutput() RecoveryActivityOutput {
	input := converterTestReadInput()
	return RecoveryActivityOutput{
		Version: RecoveryActivitySchemaVersion, State: readtask.RecoveryPending,
		InvestigationID: input.InvestigationID, TaskID: input.TaskID, Position: input.Position,
		TaskStatus: domain.ReadTaskQueued,
	}
}
