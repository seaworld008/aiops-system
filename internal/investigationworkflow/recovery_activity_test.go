package investigationworkflow_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/seaworld008/aiops-system/internal/readtask"
	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

const (
	testOnlyRecoveryActivityName = "test.aiops.investigation.read-result.recover.v1"
	testOnlyRecoveryWorkflowName = "test.aiops.investigation.read-result.history.v1"
)

func TestTemporalDevServerRecoveryHistoryExcludesReceiptAndDependencyCanaries(t *testing.T) {
	if os.Getenv("AIOPS_TEMPORAL_INTEGRATION") != "1" {
		t.Skip("set AIOPS_TEMPORAL_INTEGRATION=1 to run the pinned Temporal dev-server contract")
	}
	if version := os.Getenv("AIOPS_TEMPORAL_CLI_VERSION"); version != "1.6.1" {
		t.Fatalf("AIOPS_TEMPORAL_CLI_VERSION = %q, want pinned 1.6.1", version)
	}
	address := os.Getenv("AIOPS_TEMPORAL_ADDRESS")
	if address == "" {
		t.Fatal("AIOPS_TEMPORAL_ADDRESS is required when integration is enabled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	temporalClient, err := client.DialContext(ctx, client.Options{
		HostPort: address, Namespace: "default", Identity: "aiops-recovery-history-test",
	})
	if err != nil {
		t.Fatalf("client.DialContext() error = %v", err)
	}
	defer temporalClient.Close()

	const (
		failureTaskID   = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		receiptID       = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		runnerCanary    = "runner-history-provenance-canary"
		dependencyToken = "Authorization Bearer recovery-history-secret"
	)
	receiptHash := strings.Repeat("8", 64)
	certificateCanary := strings.Repeat("7", 64)
	reader := historyCanaryRecoveryReader{
		failureTaskID: failureTaskID, receiptID: receiptID, receiptHash: receiptHash,
		runnerCanary: runnerCanary, certificateCanary: certificateCanary,
		dependencyCanary: dependencyToken,
	}
	activities, err := investigationworkflow.NewRecoveryActivities(reader)
	if err != nil {
		t.Fatalf("NewRecoveryActivities() error = %v", err)
	}
	queue := "test-aiops-recovery-history-" + uuid.NewString()
	runtimeWorker := worker.New(temporalClient, queue, worker.Options{
		DisableRegistrationAliasing: true, DisableEagerActivities: true,
	})
	runtimeWorker.RegisterWorkflowWithOptions(
		testOnlyRecoveryHistoryWorkflow,
		workflow.RegisterOptions{Name: testOnlyRecoveryWorkflowName},
	)
	runtimeWorker.RegisterActivityWithOptions(func(
		ctx context.Context,
		input investigationworkflow.RecoveryActivityInput,
	) (investigationworkflow.RecoveryActivityOutput, error) {
		return investigationworkflow.RecoverActivityForTest(activities, ctx, input)
	}, activity.RegisterOptions{Name: testOnlyRecoveryActivityName})
	if err := runtimeWorker.Start(); err != nil {
		t.Fatalf("test worker Start() error = %v", err)
	}
	defer runtimeWorker.Stop()

	successInput := validRecoveryActivityInput()
	successRun, err := temporalClient.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID: uuid.NewString(), TaskQueue: queue, WorkflowTaskTimeout: 10 * time.Second,
	}, testOnlyRecoveryWorkflowName, successInput)
	if err != nil {
		t.Fatalf("ExecuteWorkflow(success) error = %v", err)
	}
	var output investigationworkflow.RecoveryActivityOutput
	if err := successRun.Get(ctx, &output); err != nil || output.EvidenceID == "" || output.ContentHash == "" {
		t.Fatalf("recovery success result = %#v, %v", output, err)
	}
	successHistory := readCompleteHistory(t, ctx, temporalClient, successRun.GetID(), successRun.GetRunID())
	assertRecoveryHistoryExcludes(t, successHistory,
		receiptID, receiptHash, runnerCanary, certificateCanary, dependencyToken,
	)

	failureInput := successInput
	failureInput.TaskID = failureTaskID
	failureRun, err := temporalClient.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID: uuid.NewString(), TaskQueue: queue, WorkflowTaskTimeout: 10 * time.Second,
	}, testOnlyRecoveryWorkflowName, failureInput)
	if err != nil {
		t.Fatalf("ExecuteWorkflow(failure) error = %v", err)
	}
	if err := failureRun.Get(ctx, nil); err == nil {
		t.Fatal("dependency failure Workflow unexpectedly completed")
	}
	failureHistory := readCompleteHistory(t, ctx, temporalClient, failureRun.GetID(), failureRun.GetRunID())
	assertRecoveryHistoryExcludes(t, failureHistory,
		receiptID, receiptHash, runnerCanary, certificateCanary, dependencyToken,
	)
}

func testOnlyRecoveryHistoryWorkflow(
	ctx workflow.Context,
	input investigationworkflow.RecoveryActivityInput,
) (investigationworkflow.RecoveryActivityOutput, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		ActivityID: "recover-" + input.TaskID, StartToCloseTimeout: 5 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{MaximumAttempts: 1},
	})
	var output investigationworkflow.RecoveryActivityOutput
	err := workflow.ExecuteActivity(ctx, testOnlyRecoveryActivityName, input).Get(ctx, &output)
	return output, err
}

func assertRecoveryHistoryExcludes(t *testing.T, history *historypb.History, forbidden ...string) {
	t.Helper()
	// historyMaterial also walks byte payloads, so this checks both printable
	// protobuf fields and encoded Activity input/result/failure payloads.
	material := strings.ToLower(historyMaterial(t, history))
	for _, candidate := range append(forbidden,
		"receipt_id", "receipt_hash", "runner_id", "certificate_sha256",
		"scope_revision", "runtime_binding", "input_document", "payload_document",
	) {
		if strings.Contains(material, strings.ToLower(candidate)) {
			t.Fatalf("Temporal recovery History contains forbidden material %q", candidate)
		}
	}
}

type historyCanaryRecoveryReader struct {
	failureTaskID     string
	receiptID         string
	receiptHash       string
	runnerCanary      string
	certificateCanary string
	dependencyCanary  string
}

func (reader historyCanaryRecoveryReader) Recover(
	_ context.Context,
	request readtask.RecoveryRequest,
) (readtask.RecoveryResult, error) {
	if request.TaskID == reader.failureTaskID {
		return readtask.RecoveryResult{}, fmt.Errorf(
			"%s %s %s: %w", reader.dependencyCanary, reader.runnerCanary,
			reader.certificateCanary, readtask.ErrPersistence,
		)
	}
	return readtask.RecoveryResult{
		State: readtask.RecoveryCommitted, InvestigationID: request.InvestigationID,
		TaskID: request.TaskID, Position: request.Position, TaskStatus: domain.ReadTaskEvidence,
		EvidenceID: "99999999-9999-4999-8999-999999999999", ContentHash: strings.Repeat("9", 64),
		ReceiptID: reader.receiptID, ReceiptHash: reader.receiptHash,
	}, nil
}

func TestRecoveryActivityClassifiesReaderFailuresWithoutLeakingCauses(t *testing.T) {
	input := validRecoveryActivityInput()
	valid := readtask.RecoveryResult{
		State: readtask.RecoveryPending, InvestigationID: input.InvestigationID,
		TaskID: input.TaskID, Position: input.Position, TaskStatus: domain.ReadTaskQueued,
	}
	const canary = "postgres target Authorization Bearer recovery-canary"
	tests := []struct {
		name         string
		result       readtask.RecoveryResult
		err          error
		wantType     string
		nonRetryable bool
	}{
		{"invalid request", readtask.RecoveryResult{}, errors.Join(readtask.ErrInvalidRequest, errors.New(canary)), "READ_RESULT_RECOVERY_INPUT_INVALID", true},
		{"not found", readtask.RecoveryResult{}, errors.Join(readtask.ErrNotFound, errors.New(canary)), "READ_RESULT_RECOVERY_NOT_FOUND", true},
		{"integrity", readtask.RecoveryResult{}, errors.Join(readtask.ErrIntegrity, errors.New(canary)), "READ_RESULT_RECOVERY_INTEGRITY_REJECTED", true},
		{"persistence", readtask.RecoveryResult{}, errors.Join(readtask.ErrPersistence, errors.New(canary)), "READ_RESULT_RECOVERY_DEPENDENCY_UNAVAILABLE", false},
		{"unknown dependency", readtask.RecoveryResult{}, errors.New(canary), "READ_RESULT_RECOVERY_DEPENDENCY_UNAVAILABLE", false},
		{"invalid result", func() readtask.RecoveryResult {
			result := valid
			result.TaskID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			return result
		}(), nil, "READ_RESULT_RECOVERY_RESULT_INVALID", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			activities, err := investigationworkflow.NewRecoveryActivities(recoveryReaderFunc(func(
				context.Context,
				readtask.RecoveryRequest,
			) (readtask.RecoveryResult, error) {
				return test.result, test.err
			}))
			if err != nil {
				t.Fatalf("NewRecoveryActivities() error = %v", err)
			}
			result, err := investigationworkflow.RecoverActivityForTest(activities, context.Background(), input)
			if result.Version != 0 {
				t.Fatalf("failed recovery returned result %#v", result)
			}
			var applicationError *temporal.ApplicationError
			if !errors.As(err, &applicationError) || applicationError.Type() != test.wantType ||
				applicationError.NonRetryable() != test.nonRetryable {
				t.Fatalf("RecoverActivity() error = %v (%T), want type=%q nonRetryable=%t",
					err, err, test.wantType, test.nonRetryable)
			}
			if strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), workflowTaskID) ||
				strings.Contains(err.Error(), workflowWorkspace) {
				t.Fatalf("recovery error leaked sensitive detail: %v", err)
			}
		})
	}
}

func TestRecoveryActivityMapsReaderPanicToRetryableLowSensitivityError(t *testing.T) {
	const canary = "panic Authorization Bearer recovery-secret"
	activities, err := investigationworkflow.NewRecoveryActivities(recoveryReaderFunc(func(
		context.Context,
		readtask.RecoveryRequest,
	) (readtask.RecoveryResult, error) {
		panic(canary)
	}))
	if err != nil {
		t.Fatalf("NewRecoveryActivities() error = %v", err)
	}
	result, err := investigationworkflow.RecoverActivityForTest(
		activities, context.Background(), validRecoveryActivityInput(),
	)
	if result.Version != 0 {
		t.Fatalf("panic recovery returned result %#v", result)
	}
	var applicationError *temporal.ApplicationError
	if !errors.As(err, &applicationError) ||
		applicationError.Type() != "READ_RESULT_RECOVERY_DEPENDENCY_UNAVAILABLE" ||
		applicationError.NonRetryable() {
		t.Fatalf("RecoverActivity(panic) error = %v (%T)", err, err)
	}
	if strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), workflowTaskID) {
		t.Fatalf("panic error leaked sensitive detail: %v", err)
	}
}

func TestNewRecoveryActivitiesRejectsNilAndTypedNilReader(t *testing.T) {
	var typedNil *typedNilRecoveryReader
	for name, reader := range map[string]investigationworkflow.RecoveryReader{
		"nil": nil, "typed nil": typedNil,
	} {
		t.Run(name, func(t *testing.T) {
			activities, err := investigationworkflow.NewRecoveryActivities(reader)
			if activities != nil || !errors.Is(err, investigationworkflow.ErrInvalidRecoveryInput) {
				t.Fatalf("NewRecoveryActivities(%s) = %#v, %v", name, activities, err)
			}
		})
	}
}

func TestRecoveryActivityHonorsContextBeforeAndDuringReader(t *testing.T) {
	input := validRecoveryActivityInput()
	t.Run("pre-cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		calls := 0
		activities, err := investigationworkflow.NewRecoveryActivities(recoveryReaderFunc(func(
			context.Context,
			readtask.RecoveryRequest,
		) (readtask.RecoveryResult, error) {
			calls++
			return readtask.RecoveryResult{}, errors.New("must not run")
		}))
		if err != nil {
			t.Fatal(err)
		}
		result, err := investigationworkflow.RecoverActivityForTest(activities, ctx, input)
		if !errors.Is(err, context.Canceled) || calls != 0 || result.Version != 0 {
			t.Fatalf("RecoverActivity(pre-cancelled) = %#v, %v; calls=%d", result, err, calls)
		}
	})

	t.Run("cancelled during reader", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		activities, err := investigationworkflow.NewRecoveryActivities(recoveryReaderFunc(func(
			context.Context,
			readtask.RecoveryRequest,
		) (readtask.RecoveryResult, error) {
			cancel()
			return readtask.RecoveryResult{}, errors.New("dependency canary")
		}))
		if err != nil {
			t.Fatal(err)
		}
		result, err := investigationworkflow.RecoverActivityForTest(activities, ctx, input)
		if !errors.Is(err, context.Canceled) || result.Version != 0 {
			t.Fatalf("RecoverActivity(cancelled during reader) = %#v, %v", result, err)
		}
	})

	t.Run("reader cancellation and deadline", func(t *testing.T) {
		for name, readerErr := range map[string]error{
			"cancelled": errors.Join(context.Canceled, errors.New("context cancellation canary")),
			"deadline":  errors.Join(context.DeadlineExceeded, errors.New("context deadline canary")),
		} {
			t.Run(name, func(t *testing.T) {
				activities, err := investigationworkflow.NewRecoveryActivities(recoveryReaderFunc(func(
					context.Context,
					readtask.RecoveryRequest,
				) (readtask.RecoveryResult, error) {
					return readtask.RecoveryResult{}, readerErr
				}))
				if err != nil {
					t.Fatal(err)
				}
				result, err := investigationworkflow.RecoverActivityForTest(
					activities, context.Background(), input,
				)
				want := context.Canceled
				if name == "deadline" {
					want = context.DeadlineExceeded
				}
				if err != want || result.Version != 0 {
					t.Fatalf("RecoverActivity(reader %s) = %#v, %v; want %v", name, result, err, want)
				}
			})
		}
	})

	t.Run("pre-expired deadline", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		calls := 0
		activities, err := investigationworkflow.NewRecoveryActivities(recoveryReaderFunc(func(
			context.Context,
			readtask.RecoveryRequest,
		) (readtask.RecoveryResult, error) {
			calls++
			return readtask.RecoveryResult{}, errors.New("must not run")
		}))
		if err != nil {
			t.Fatal(err)
		}
		result, err := investigationworkflow.RecoverActivityForTest(activities, ctx, input)
		if err != context.DeadlineExceeded || calls != 0 || result.Version != 0 {
			t.Fatalf("RecoverActivity(expired deadline) = %#v, %v; calls=%d", result, err, calls)
		}
	})

	t.Run("nil context", func(t *testing.T) {
		calls := 0
		activities, err := investigationworkflow.NewRecoveryActivities(recoveryReaderFunc(func(
			context.Context,
			readtask.RecoveryRequest,
		) (readtask.RecoveryResult, error) {
			calls++
			return readtask.RecoveryResult{}, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		result, err := investigationworkflow.RecoverActivityForTest(activities, nil, input)
		var applicationError *temporal.ApplicationError
		if !errors.As(err, &applicationError) ||
			applicationError.Type() != "READ_RESULT_RECOVERY_INPUT_INVALID" ||
			!applicationError.NonRetryable() || calls != 0 || result.Version != 0 {
			t.Fatalf("RecoverActivity(nil context) = %#v, %v; calls=%d", result, err, calls)
		}
	})
}

func TestRecoveryActivityInputRejectsNonExactJSON(t *testing.T) {
	input := validRecoveryActivityInput()
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("json.Marshal(input) error = %v", err)
	}
	var roundTrip investigationworkflow.RecoveryActivityInput
	if err := json.Unmarshal(encoded, &roundTrip); err != nil || !reflect.DeepEqual(roundTrip, input) {
		t.Fatalf("input round trip = %#v, %v", roundTrip, err)
	}

	unknown := append([]byte(nil), encoded[:len(encoded)-1]...)
	unknown = append(unknown, []byte(`,"plan_schema_version":"investigation-plan-manifest.v1"}`)...)
	duplicate := append([]byte(`{"version":1,`), encoded[1:]...)
	missing := []byte(strings.Replace(string(encoded), `,"tasks_hash":"`+workflowTasks+`"`, "", 1))
	futureVersion := []byte(strings.Replace(string(encoded), `"version":1`, `"version":2`, 1))
	tests := map[string][]byte{
		"unknown field":   unknown,
		"duplicate field": duplicate,
		"missing field":   missing,
		"future version":  futureVersion,
		"trailing value":  append(append([]byte(nil), encoded...), []byte(` {}`)...),
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			var decoded investigationworkflow.RecoveryActivityInput
			err := json.Unmarshal(document, &decoded)
			if name == "trailing value" {
				if err == nil {
					t.Fatalf("json.Unmarshal(%s) error = nil", document)
				}
				return
			}
			if !errors.Is(err, investigationworkflow.ErrInvalidRecoveryInput) {
				t.Fatalf("json.Unmarshal(%s) error = %v, want ErrInvalidRecoveryInput", document, err)
			}
		})
	}
}

func TestRecoveryActivityOutputRejectsNonExactOrInvalidJSON(t *testing.T) {
	output := investigationworkflow.RecoveryActivityOutput{
		Version: investigationworkflow.RecoveryActivitySchemaVersion,
		State:   readtask.RecoveryCommitted, InvestigationID: workflowInvestigationID,
		TaskID: workflowTaskID, Position: 1, TaskStatus: domain.ReadTaskEvidence,
		EvidenceID: "99999999-9999-4999-8999-999999999999", ContentHash: strings.Repeat("9", 64),
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("json.Marshal(output) error = %v", err)
	}
	var roundTrip investigationworkflow.RecoveryActivityOutput
	if err := json.Unmarshal(encoded, &roundTrip); err != nil || !reflect.DeepEqual(roundTrip, output) {
		t.Fatalf("output round trip = %#v, %v", roundTrip, err)
	}

	unknown := append([]byte(nil), encoded[:len(encoded)-1]...)
	unknown = append(unknown, []byte(`,"receipt_id":"88888888-8888-4888-8888-888888888888"}`)...)
	duplicate := append([]byte(`{"version":1,`), encoded[1:]...)
	missing := []byte(strings.Replace(string(encoded), `,"content_hash":"`+strings.Repeat("9", 64)+`"`, "", 1))
	invalidState := []byte(strings.Replace(string(encoded), `"state":"COMMITTED"`, `"state":"UNKNOWN"`, 1))
	invalidUnion := []byte(strings.Replace(string(encoded), `"task_status":"EVIDENCE"`, `"task_status":"FAILED"`, 1))
	tests := map[string][]byte{
		"unknown receipt":       unknown,
		"duplicate field":       duplicate,
		"missing Evidence hash": missing,
		"unknown state":         invalidState,
		"failure with Evidence": invalidUnion,
		"trailing value":        append(append([]byte(nil), encoded...), []byte(` {}`)...),
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			var decoded investigationworkflow.RecoveryActivityOutput
			err := json.Unmarshal(document, &decoded)
			if name == "trailing value" {
				if err == nil {
					t.Fatalf("json.Unmarshal(%s) error = nil", document)
				}
				return
			}
			if !errors.Is(err, investigationworkflow.ErrInvalidRecoveryResult) {
				t.Fatalf("json.Unmarshal(%s) error = %v, want ErrInvalidRecoveryResult", document, err)
			}
		})
	}
}

func TestRecoveryActivityProjectsPendingResultFromFixedPlanInput(t *testing.T) {
	input := validRecoveryActivityInput()
	wantRequest := recoveryRequestFromInput(input)
	reader := recoveryReaderFunc(func(_ context.Context, request readtask.RecoveryRequest) (readtask.RecoveryResult, error) {
		if !reflect.DeepEqual(request, wantRequest) {
			t.Fatalf("Recover() request = %#v, want %#v", request, wantRequest)
		}
		return readtask.RecoveryResult{
			State: readtask.RecoveryPending, InvestigationID: request.InvestigationID,
			TaskID: request.TaskID, Position: request.Position, TaskStatus: domain.ReadTaskQueued,
		}, nil
	})
	activities, err := investigationworkflow.NewRecoveryActivities(reader)
	if err != nil {
		t.Fatalf("NewRecoveryActivities() error = %v", err)
	}
	result, err := investigationworkflow.RecoverActivityForTest(activities, context.Background(), input)
	if err != nil {
		t.Fatalf("RecoverActivity() error = %v", err)
	}
	want := investigationworkflow.RecoveryActivityOutput{
		Version: investigationworkflow.RecoveryActivitySchemaVersion,
		State:   readtask.RecoveryPending, InvestigationID: input.InvestigationID,
		TaskID: input.TaskID, Position: input.Position, TaskStatus: domain.ReadTaskQueued,
	}
	if !reflect.DeepEqual(result, want) {
		t.Fatalf("RecoverActivity() = %#v, want %#v", result, want)
	}
}

func TestRecoveryActivityProjectsTerminalResultsWithoutReceiptProvenance(t *testing.T) {
	input := validRecoveryActivityInput()
	common := readtask.RecoveryResult{
		State: readtask.RecoveryCommitted, InvestigationID: input.InvestigationID,
		TaskID: input.TaskID, Position: input.Position,
		ReceiptID:   "88888888-8888-4888-8888-888888888888",
		ReceiptHash: strings.Repeat("8", 64),
	}
	tests := []struct {
		name       string
		result     readtask.RecoveryResult
		wantStatus domain.ReadTaskStatus
		wantState  readtask.RecoveryState
	}{
		{
			name: "committed Evidence",
			result: func() readtask.RecoveryResult {
				result := common
				result.TaskStatus = domain.ReadTaskEvidence
				result.EvidenceID = "99999999-9999-4999-8999-999999999999"
				result.ContentHash = strings.Repeat("9", 64)
				return result
			}(),
			wantStatus: domain.ReadTaskEvidence, wantState: readtask.RecoveryCommitted,
		},
		{
			name: "committed failure",
			result: func() readtask.RecoveryResult {
				result := common
				result.TaskStatus = domain.ReadTaskFailed
				return result
			}(),
			wantStatus: domain.ReadTaskFailed, wantState: readtask.RecoveryCommitted,
		},
		{
			name: "committed cancellation",
			result: func() readtask.RecoveryResult {
				result := common
				result.TaskStatus = domain.ReadTaskCancelled
				return result
			}(),
			wantStatus: domain.ReadTaskCancelled, wantState: readtask.RecoveryCommitted,
		},
		{
			name: "control cancellation",
			result: readtask.RecoveryResult{
				State: readtask.RecoveryControlCancelled, InvestigationID: input.InvestigationID,
				TaskID: input.TaskID, Position: input.Position, TaskStatus: domain.ReadTaskCancelled,
			},
			wantStatus: domain.ReadTaskCancelled, wantState: readtask.RecoveryControlCancelled,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			activities, err := investigationworkflow.NewRecoveryActivities(recoveryReaderFunc(func(
				context.Context,
				readtask.RecoveryRequest,
			) (readtask.RecoveryResult, error) {
				return test.result, nil
			}))
			if err != nil {
				t.Fatalf("NewRecoveryActivities() error = %v", err)
			}
			output, err := investigationworkflow.RecoverActivityForTest(activities, context.Background(), input)
			if err != nil {
				t.Fatalf("RecoverActivity() error = %v", err)
			}
			if output.State != test.wantState || output.TaskStatus != test.wantStatus ||
				output.InvestigationID != input.InvestigationID || output.TaskID != input.TaskID ||
				output.Position != input.Position {
				t.Fatalf("RecoverActivity() = %#v", output)
			}
			if test.wantStatus == domain.ReadTaskEvidence {
				if output.EvidenceID != test.result.EvidenceID || output.ContentHash != test.result.ContentHash {
					t.Fatalf("Evidence output = %#v", output)
				}
			} else if output.EvidenceID != "" || output.ContentHash != "" {
				t.Fatalf("non-Evidence output leaked Evidence fields: %#v", output)
			}
			encoded, err := json.Marshal(output)
			if err != nil || strings.Contains(string(encoded), "receipt") ||
				test.result.ReceiptID != "" && strings.Contains(string(encoded), test.result.ReceiptID) ||
				test.result.ReceiptHash != "" && strings.Contains(string(encoded), test.result.ReceiptHash) {
				t.Fatalf("output JSON leaked receipt provenance: %s, %v", encoded, err)
			}
		})
	}
}

func validRecoveryActivityInput() investigationworkflow.RecoveryActivityInput {
	return investigationworkflow.RecoveryActivityInput{
		Version:  investigationworkflow.RecoveryActivitySchemaVersion,
		TenantID: workflowTenantID, WorkspaceID: workflowWorkspace,
		IncidentID: workflowIncidentID, InvestigationID: workflowInvestigationID,
		TaskID: workflowTaskID, Position: 1,
		ManifestDigest: workflowManifest, RegistryDigest: workflowRegistry,
		ProfileDigest: workflowProfile, TasksHash: workflowTasks,
	}
}

func recoveryRequestFromInput(input investigationworkflow.RecoveryActivityInput) readtask.RecoveryRequest {
	return readtask.RecoveryRequest{
		TenantID: input.TenantID, WorkspaceID: input.WorkspaceID, IncidentID: input.IncidentID,
		InvestigationID: input.InvestigationID, TaskID: input.TaskID, Position: input.Position,
		PlanBinding: domain.InvestigationPlanBinding{
			SchemaVersion:  domain.InvestigationPlanBindingSchemaVersion,
			ManifestDigest: input.ManifestDigest, RegistryDigest: input.RegistryDigest,
			ProfileDigest: input.ProfileDigest, TasksHash: input.TasksHash,
		},
	}
}

type recoveryReaderFunc func(context.Context, readtask.RecoveryRequest) (readtask.RecoveryResult, error)

func (reader recoveryReaderFunc) Recover(
	ctx context.Context,
	request readtask.RecoveryRequest,
) (readtask.RecoveryResult, error) {
	return reader(ctx, request)
}

type typedNilRecoveryReader struct{}

func (*typedNilRecoveryReader) Recover(
	context.Context,
	readtask.RecoveryRequest,
) (readtask.RecoveryResult, error) {
	return readtask.RecoveryResult{}, nil
}
