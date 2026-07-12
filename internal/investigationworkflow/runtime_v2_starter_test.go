package investigationworkflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unsafe"

	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	sdkpb "go.temporal.io/api/sdk/v1"
	"go.temporal.io/api/serviceerror"
	taskqueuepb "go.temporal.io/api/taskqueue/v1"
	workflowpb "go.temporal.io/api/workflow/v1"
	workflowservicepb "go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/seaworld008/aiops-system/internal/outbox"
)

const (
	runtimeV2StarterRunID   = "88888888-8888-4888-8888-888888888888"
	runtimeV2OutboxID       = "11111111-1111-4111-8111-111111111111"
	runtimeV2TenantID       = "22222222-2222-4222-8222-222222222222"
	runtimeV2WorkspaceID    = "33333333-3333-4333-8333-333333333333"
	runtimeV2SignalID       = "44444444-4444-4444-8444-444444444444"
	runtimeV2ManifestDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	runtimeV2RegistryDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	runtimeV2BundleDigest   = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func TestRuntimeV2StarterUsesOnlyExactCanonicalIdentity(t *testing.T) {
	input := validRuntimeV2StarterInput()
	queue := mustRuntimeV2ControlQueue(t)
	fake := &fakeRuntimeV2StarterTransport{
		run:      fakeRuntimeV2WorkflowRun{id: runtimeV2OutboxID, runID: runtimeV2StarterRunID},
		describe: validRuntimeV2Describe(t, input, runtimeV2StarterRunID, queue),
	}
	starter := newRuntimeV2StarterForFake(t, fake)

	outcome, err := starter.Start(context.Background(), validRuntimeV2SignalStart())
	if err != nil || outcome != outbox.StartOutcomeStarted {
		t.Fatalf("Start() = %q, %v", outcome, err)
	}
	if fake.workflow != WorkflowNameV2 || len(fake.args) != 1 {
		t.Fatalf("ExecuteWorkflow() workflow/args = %#v / %#v", fake.workflow, fake.args)
	}
	captured, ok := fake.args[0].(WorkflowInputV2)
	if !ok || captured != input {
		t.Fatalf("ExecuteWorkflow() input = %#v", fake.args[0])
	}
	options := fake.options
	if options.ID != runtimeV2OutboxID || options.TaskQueue != queue ||
		options.WorkflowIDConflictPolicy != enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL ||
		options.WorkflowIDReusePolicy != enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE ||
		!options.WorkflowExecutionErrorWhenAlreadyStarted || options.WorkflowTaskTimeout != 10*time.Second ||
		options.WorkflowExecutionTimeout != 0 || options.WorkflowRunTimeout != 0 || options.RetryPolicy != nil ||
		options.CronSchedule != "" || options.SearchAttributes != nil || options.TypedSearchAttributes.Size() != 0 ||
		options.EnableEagerStart || options.StartDelay != 0 || options.StaticSummary != "" ||
		options.StaticDetails != "" || options.VersioningOverride != nil || options.Priority != (temporal.Priority{}) ||
		len(options.Memo) != 1 {
		t.Fatalf("StartWorkflowOptions = %#v", options)
	}
	identity, ok := options.Memo[RuntimeMemoIdentityKeyV2].(runtimeV2MemoIdentity)
	canonical, canonicalErr := canonicalWorkflowInputV2Payload(input)
	if !ok || canonicalErr != nil || identity.payload == nil || !proto.Equal(identity.payload, canonical) {
		t.Fatalf("memo identity = %#v; canonical error = %v", options.Memo, canonicalErr)
	}
	if fake.describeCalls != 2 || fake.historyCalls != 1 ||
		fake.describeWorkflowID != runtimeV2OutboxID || fake.describeRunID != runtimeV2StarterRunID ||
		fake.historyWorkflowID != runtimeV2OutboxID || fake.historyRunID != runtimeV2StarterRunID {
		t.Fatalf("proof calls = describe:%d history:%d ids:%s/%s %s/%s", fake.describeCalls, fake.historyCalls,
			fake.describeWorkflowID, fake.describeRunID, fake.historyWorkflowID, fake.historyRunID)
	}
}

func TestRuntimeV2StarterACKLostDuplicateRequiresTheSameProof(t *testing.T) {
	input := validRuntimeV2StarterInput()
	queue := mustRuntimeV2ControlQueue(t)
	fake := &fakeRuntimeV2StarterTransport{
		run:      fakeRuntimeV2WorkflowRun{id: runtimeV2OutboxID, runID: runtimeV2StarterRunID},
		describe: validRuntimeV2Describe(t, input, runtimeV2StarterRunID, queue),
	}
	starter := newRuntimeV2StarterForFake(t, fake)
	if outcome, err := starter.Start(context.Background(), validRuntimeV2SignalStart()); err != nil || outcome != outbox.StartOutcomeStarted {
		t.Fatalf("Start(first) = %q, %v", outcome, err)
	}
	fake.run = nil
	fake.executeErr = &serviceerror.WorkflowExecutionAlreadyStarted{RunId: runtimeV2StarterRunID}
	if outcome, err := starter.Start(context.Background(), validRuntimeV2SignalStart()); err != nil || outcome != outbox.StartOutcomeAlreadyExists {
		t.Fatalf("Start(ACK-lost duplicate) = %q, %v", outcome, err)
	}
	if fake.describeCalls != 4 || fake.historyCalls != 2 {
		t.Fatalf("proof calls after duplicate = describe:%d history:%d", fake.describeCalls, fake.historyCalls)
	}
}

func TestRuntimeV2StarterRejectsEveryUntrustedStartFieldBeforeTemporal(t *testing.T) {
	mutations := map[string]func(*outbox.SignalWorkflowStart){
		"version":           func(value *outbox.SignalWorkflowStart) { value.Version = 2 },
		"workflow id":       func(value *outbox.SignalWorkflowStart) { value.WorkflowID = runtimeV2SignalID },
		"outbox id":         func(value *outbox.SignalWorkflowStart) { value.OutboxEventID = "invalid" },
		"tenant":            func(value *outbox.SignalWorkflowStart) { value.TenantID = "invalid" },
		"workspace":         func(value *outbox.SignalWorkflowStart) { value.WorkspaceID = "invalid" },
		"signal":            func(value *outbox.SignalWorkflowStart) { value.SignalID = "invalid" },
		"aggregate version": func(value *outbox.SignalWorkflowStart) { value.AggregateVersion = 2 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			fake := &fakeRuntimeV2StarterTransport{}
			starter := newRuntimeV2StarterForFake(t, fake)
			value := validRuntimeV2SignalStart()
			mutate(&value)
			outcome, err := starter.Start(context.Background(), value)
			if err == nil || outcome != "" || fake.workflow != nil || fake.describeCalls != 0 || fake.historyCalls != 0 {
				t.Fatalf("Start(mutated %s) = %q, %v; temporal=%#v", name, outcome, err, fake.workflow)
			}
			assertRuntimeV2FailureCode(t, err, "workflow_start_rejected")
		})
	}
}

func TestRuntimeV2StarterConstructorAndCopiesFailClosed(t *testing.T) {
	var typedNil *fakeRuntimeV2StarterTransport
	if roleClient, err := newRuntimeV2StarterClient(typedNil, "default"); err == nil || roleClient != nil {
		t.Fatalf("newRuntimeV2StarterClient(typed nil) = %#v, %v", roleClient, err)
	}
	fake := &fakeRuntimeV2StarterTransport{}
	roleClient, err := newRuntimeV2StarterClient(fake, "default")
	if err != nil {
		t.Fatalf("newRuntimeV2StarterClient() error = %v", err)
	}
	for name, values := range map[string][3]string{
		"manifest missing": {"", runtimeV2RegistryDigest, runtimeV2BundleDigest},
		"registry invalid": {runtimeV2ManifestDigest, "invalid", runtimeV2BundleDigest},
		"bundle missing":   {runtimeV2ManifestDigest, runtimeV2RegistryDigest, ""},
	} {
		t.Run(name, func(t *testing.T) {
			if starter, createErr := newRuntimeV2Starter(roleClient, values[0], values[1], values[2]); createErr == nil || starter != nil {
				t.Fatalf("NewRuntimeV2Starter(%s) = %#v, %v", name, starter, createErr)
			}
		})
	}
	if starter, createErr := newRuntimeV2Starter(nil, runtimeV2ManifestDigest, runtimeV2RegistryDigest, runtimeV2BundleDigest); createErr == nil || starter != nil {
		t.Fatalf("NewRuntimeV2Starter(nil) = %#v, %v", starter, createErr)
	}
	copiedClient := *roleClient
	for name, candidate := range map[string]*RuntimeV2StarterClient{
		"zero client":   {},
		"copied client": &copiedClient,
	} {
		if starter, createErr := newRuntimeV2Starter(candidate, runtimeV2ManifestDigest, runtimeV2RegistryDigest, runtimeV2BundleDigest); createErr == nil || starter != nil {
			t.Fatalf("NewRuntimeV2Starter(%s) = %#v, %v", name, starter, createErr)
		}
	}
	valid, err := newRuntimeV2Starter(roleClient, runtimeV2ManifestDigest, runtimeV2RegistryDigest, runtimeV2BundleDigest)
	if err != nil {
		t.Fatalf("NewRuntimeV2Starter(valid client) error = %v", err)
	}
	copied := *valid
	for name, starter := range map[string]*RuntimeV2Starter{
		"nil":  nil,
		"zero": {},
		"copy": &copied,
	} {
		t.Run(name, func(t *testing.T) {
			outcome, startErr := starter.Start(context.Background(), validRuntimeV2SignalStart())
			if startErr == nil || outcome != "" || fake.workflow != nil {
				t.Fatalf("Start(%s starter) = %q, %v; temporal=%#v", name, outcome, startErr, fake.workflow)
			}
		})
	}
	if closeErr := roleClient.Close(); closeErr != nil {
		t.Fatalf("Close() error = %v", closeErr)
	}
	if recreated, createErr := newRuntimeV2Starter(roleClient, runtimeV2ManifestDigest, runtimeV2RegistryDigest, runtimeV2BundleDigest); createErr == nil || recreated != nil {
		t.Fatalf("NewRuntimeV2Starter(closed client) = %#v, %v", recreated, createErr)
	}
	if outcome, startErr := valid.Start(context.Background(), validRuntimeV2SignalStart()); startErr == nil || outcome != "" || fake.workflow != nil {
		t.Fatalf("Start(closed client) = %q, %v", outcome, startErr)
	}
}

func TestRuntimeV2StarterRedactsFormattingAndRejectsJSONForEveryLifecycleState(t *testing.T) {
	starter := newRuntimeV2StarterForFake(t, &fakeRuntimeV2StarterTransport{})
	copied := *starter
	closed := newRuntimeV2StarterForFake(t, &fakeRuntimeV2StarterTransport{})
	if err := closed.client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	const redacted = "<aiops-runtime-v2-starter>"
	for name, value := range map[string]RuntimeV2Starter{
		"valid":  *starter,
		"copy":   copied,
		"closed": *closed,
		"zero":   {},
	} {
		t.Run(name, func(t *testing.T) {
			for format, rendered := range map[string]string{
				"%s":  fmt.Sprintf("%s", value),
				"%v":  fmt.Sprintf("%v", value),
				"%+v": fmt.Sprintf("%+v", value),
				"%#v": fmt.Sprintf("%#v", value),
			} {
				if rendered != redacted || strings.Contains(rendered, runtimeV2ManifestDigest) ||
					strings.Contains(rendered, runtimeV2RegistryDigest) || strings.Contains(rendered, runtimeV2BundleDigest) {
					t.Fatalf("format %s = %q", format, rendered)
				}
			}
			if encoded, err := json.Marshal(value); err == nil || encoded != nil {
				t.Fatalf("json.Marshal() = %q, %v", encoded, err)
			}
		})
	}
	var decoded RuntimeV2Starter
	if err := json.Unmarshal([]byte(`{"client":"forged","manifestDigest":"canary"}`), &decoded); err == nil || decoded.valid() {
		t.Fatalf("json.Unmarshal() error = %v; decoded valid=%t", err, decoded.valid())
	}
}

func TestRuntimeV2StarterClonesEveryRoutingDigest(t *testing.T) {
	manifestBytes := []byte(runtimeV2ManifestDigest)
	registryBytes := []byte(runtimeV2RegistryDigest)
	bundleBytes := []byte(runtimeV2BundleDigest)
	manifest := unsafe.String(unsafe.SliceData(manifestBytes), len(manifestBytes))
	registry := unsafe.String(unsafe.SliceData(registryBytes), len(registryBytes))
	bundle := unsafe.String(unsafe.SliceData(bundleBytes), len(bundleBytes))
	input := validRuntimeV2StarterInput()
	queue := mustRuntimeV2ControlQueue(t)
	fake := &fakeRuntimeV2StarterTransport{
		run:      fakeRuntimeV2WorkflowRun{id: runtimeV2OutboxID, runID: runtimeV2StarterRunID},
		describe: validRuntimeV2Describe(t, input, runtimeV2StarterRunID, queue),
	}
	roleClient, err := newRuntimeV2StarterClient(fake, "default")
	if err != nil {
		t.Fatalf("newRuntimeV2StarterClient() error = %v", err)
	}
	starter, err := newRuntimeV2Starter(roleClient, manifest, registry, bundle)
	if err != nil {
		t.Fatalf("NewRuntimeV2Starter() error = %v", err)
	}
	manifestBytes[0], registryBytes[0], bundleBytes[0] = 'd', 'e', 'f'
	if outcome, startErr := starter.Start(context.Background(), validRuntimeV2SignalStart()); startErr != nil || outcome != outbox.StartOutcomeStarted {
		t.Fatalf("Start(after caller backing bytes changed) = %q, %v", outcome, startErr)
	}
}

func TestRuntimeV2StarterRejectsInvalidSuccessfulRunIdentity(t *testing.T) {
	for name, run := range map[string]client.WorkflowRun{
		"nil":            nil,
		"workflow id":    fakeRuntimeV2WorkflowRun{id: runtimeV2SignalID, runID: runtimeV2StarterRunID},
		"missing run id": fakeRuntimeV2WorkflowRun{id: runtimeV2OutboxID},
		"invalid run id": fakeRuntimeV2WorkflowRun{id: runtimeV2OutboxID, runID: "invalid"},
	} {
		t.Run(name, func(t *testing.T) {
			starter := newRuntimeV2StarterForFake(t, &fakeRuntimeV2StarterTransport{run: run})
			outcome, err := starter.Start(context.Background(), validRuntimeV2SignalStart())
			if err == nil || outcome != "" {
				t.Fatalf("Start(%s run) = %q, %v", name, outcome, err)
			}
			assertRuntimeV2FailureCode(t, err, "workflow_identity_mismatch")
		})
	}
	for name, runID := range map[string]string{"missing": "", "invalid": "canary-run"} {
		t.Run("already_started_"+name, func(t *testing.T) {
			fake := &fakeRuntimeV2StarterTransport{
				executeErr: &serviceerror.WorkflowExecutionAlreadyStarted{RunId: runID},
			}
			outcome, err := newRuntimeV2StarterForFake(t, fake).Start(context.Background(), validRuntimeV2SignalStart())
			if err == nil || outcome != "" || fake.describeCalls != 0 {
				t.Fatalf("Start(AlreadyStarted %s run) = %q, %v; describe=%d", name, outcome, err, fake.describeCalls)
			}
			assertRuntimeV2FailureCode(t, err, "workflow_identity_mismatch")
		})
	}
}

func TestRuntimeV2StarterRejectsEveryMutatedDescriptionField(t *testing.T) {
	input := validRuntimeV2StarterInput()
	queue := mustRuntimeV2ControlQueue(t)
	other := input
	other.SignalID = "99999999-9999-4999-8999-999999999999"
	otherPayload, err := canonicalWorkflowInputV2Payload(other)
	if err != nil {
		t.Fatalf("canonicalWorkflowInputV2Payload(other) error = %v", err)
	}
	mutations := map[string]func(*workflowservicepb.DescribeWorkflowExecutionResponse){
		"nil info":   func(value *workflowservicepb.DescribeWorkflowExecutionResponse) { value.WorkflowExecutionInfo = nil },
		"nil config": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) { value.ExecutionConfig = nil },
		"nil execution": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.Execution = nil
		},
		"workflow id": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.Execution.WorkflowId = runtimeV2SignalID
		},
		"run id": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.Execution.RunId = runtimeV2SignalID
		},
		"nil type": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.Type = nil
		},
		"type": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.Type.Name = WorkflowName
		},
		"status": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.Status = enumspb.WORKFLOW_EXECUTION_STATUS_CANCELED
		},
		"info queue": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.TaskQueue = "wrong-queue"
		},
		"nil config queue": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.ExecutionConfig.TaskQueue = nil
		},
		"config queue": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.ExecutionConfig.TaskQueue.Name = "wrong-queue"
		},
		"parent": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.ParentExecution = &commonpb.WorkflowExecution{
				WorkflowId: runtimeV2OutboxID, RunId: runtimeV2StarterRunID,
			}
		},
		"parent namespace": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.ParentNamespaceId = runtimeV2TenantID
		},
		"root workflow": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.RootExecution = &commonpb.WorkflowExecution{
				WorkflowId: runtimeV2SignalID, RunId: runtimeV2StarterRunID,
			}
		},
		"root run": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.RootExecution = &commonpb.WorkflowExecution{
				WorkflowId: runtimeV2OutboxID, RunId: runtimeV2SignalID,
			}
		},
		"first run": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.FirstRunId = runtimeV2SignalID
		},
		"nil memo": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.Memo = nil
		},
		"memo missing": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.Memo.Fields = map[string]*commonpb.Payload{}
		},
		"memo nil payload": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.Memo.Fields[RuntimeMemoIdentityKeyV2] = nil
		},
		"memo extra": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.Memo.Fields["extra"] = &commonpb.Payload{}
		},
		"memo mismatch": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.Memo.Fields[RuntimeMemoIdentityKeyV2] = proto.Clone(otherPayload).(*commonpb.Payload)
		},
		"memo metadata": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.Memo.Fields[RuntimeMemoIdentityKeyV2].Metadata["extra"] = []byte("canary")
		},
		"memo unknown": func(value *workflowservicepb.DescribeWorkflowExecutionResponse) {
			value.WorkflowExecutionInfo.Memo.Fields[RuntimeMemoIdentityKeyV2].ProtoReflect().SetUnknown([]byte{0x98, 0x06, 0x01})
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			response := validRuntimeV2Describe(t, input, runtimeV2StarterRunID, queue)
			mutate(response)
			fake := &fakeRuntimeV2StarterTransport{
				executeErr: &serviceerror.WorkflowExecutionAlreadyStarted{RunId: runtimeV2StarterRunID},
				describe:   response,
			}
			outcome, startErr := newRuntimeV2StarterForFake(t, fake).Start(context.Background(), validRuntimeV2SignalStart())
			if startErr == nil || outcome != "" || fake.historyCalls != 0 {
				t.Fatalf("Start(mutated description %s) = %q, %v; history=%d", name, outcome, startErr, fake.historyCalls)
			}
			assertRuntimeV2FailureCode(t, startErr, "workflow_identity_mismatch")
		})
	}
}

func TestRuntimeV2StarterRechecksDescriptionAfterImmutableStartedEvent(t *testing.T) {
	input := validRuntimeV2StarterInput()
	queue := mustRuntimeV2ControlQueue(t)
	final := validRuntimeV2Describe(t, input, runtimeV2StarterRunID, queue)
	final.WorkflowExecutionInfo.Status = enumspb.WORKFLOW_EXECUTION_STATUS_TERMINATED
	fake := &fakeRuntimeV2StarterTransport{
		executeErr:         &serviceerror.WorkflowExecutionAlreadyStarted{RunId: runtimeV2StarterRunID},
		describe:           validRuntimeV2Describe(t, input, runtimeV2StarterRunID, queue),
		describeAfterProof: final,
	}
	outcome, err := newRuntimeV2StarterForFake(t, fake).Start(context.Background(), validRuntimeV2SignalStart())
	if err == nil || outcome != "" || fake.describeCalls != 2 || fake.historyCalls != 1 {
		t.Fatalf("Start(status changed after History) = %q, %v; describe=%d history=%d",
			outcome, err, fake.describeCalls, fake.historyCalls)
	}
}

func TestRuntimeV2StarterOnlyAcknowledgesSafeTerminalStatuses(t *testing.T) {
	accepted := []enumspb.WorkflowExecutionStatus{
		enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING,
		enumspb.WORKFLOW_EXECUTION_STATUS_COMPLETED,
		enumspb.WORKFLOW_EXECUTION_STATUS_FAILED,
	}
	for _, status := range accepted {
		t.Run("accept_"+status.String(), func(t *testing.T) {
			input := validRuntimeV2StarterInput()
			response := validRuntimeV2Describe(t, input, runtimeV2StarterRunID, mustRuntimeV2ControlQueue(t))
			response.WorkflowExecutionInfo.Status = status
			fake := &fakeRuntimeV2StarterTransport{
				executeErr: &serviceerror.WorkflowExecutionAlreadyStarted{RunId: runtimeV2StarterRunID}, describe: response,
			}
			if outcome, err := newRuntimeV2StarterForFake(t, fake).Start(context.Background(), validRuntimeV2SignalStart()); err != nil || outcome != outbox.StartOutcomeAlreadyExists {
				t.Fatalf("Start(%s) = %q, %v", status, outcome, err)
			}
		})
	}
}

func TestRuntimeV2StarterAcceptsOnlyTheExactOptionalRootDescription(t *testing.T) {
	input := validRuntimeV2StarterInput()
	response := validRuntimeV2Describe(t, input, runtimeV2StarterRunID, mustRuntimeV2ControlQueue(t))
	response.WorkflowExecutionInfo.RootExecution = &commonpb.WorkflowExecution{
		WorkflowId: runtimeV2OutboxID,
		RunId:      runtimeV2StarterRunID,
	}
	fake := &fakeRuntimeV2StarterTransport{
		executeErr: &serviceerror.WorkflowExecutionAlreadyStarted{RunId: runtimeV2StarterRunID},
		describe:   response,
	}
	if outcome, err := newRuntimeV2StarterForFake(t, fake).Start(context.Background(), validRuntimeV2SignalStart()); err != nil || outcome != outbox.StartOutcomeAlreadyExists {
		t.Fatalf("Start(exact root) = %q, %v", outcome, err)
	}
}

func TestRuntimeV2StarterRejectsEveryMutatedStartedIdentityField(t *testing.T) {
	input := validRuntimeV2StarterInput()
	queue := mustRuntimeV2ControlQueue(t)
	other := input
	other.SignalID = "99999999-9999-4999-8999-999999999999"
	otherPayload, err := canonicalWorkflowInputV2Payload(other)
	if err != nil {
		t.Fatalf("canonicalWorkflowInputV2Payload(other) error = %v", err)
	}
	mutations := map[string]func(*historypb.HistoryEvent){
		"event id":        func(value *historypb.HistoryEvent) { value.EventId = 2 },
		"event type":      func(value *historypb.HistoryEvent) { value.EventType = enumspb.EVENT_TYPE_WORKFLOW_TASK_STARTED },
		"worker ignore":   func(value *historypb.HistoryEvent) { value.WorkerMayIgnore = true },
		"event metadata":  func(value *historypb.HistoryEvent) { value.UserMetadata = &sdkpb.UserMetadata{} },
		"event principal": func(value *historypb.HistoryEvent) { value.Principal = &commonpb.Principal{} },
		"event unknown": func(value *historypb.HistoryEvent) {
			value.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 0x01})
		},
		"nil attributes": func(value *historypb.HistoryEvent) { value.Attributes = nil },
		"started unknown": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().ProtoReflect().SetUnknown([]byte{0x98, 0x06, 0x01})
		},
		"workflow id": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().WorkflowId = runtimeV2SignalID
		},
		"nil workflow type": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().WorkflowType = nil
		},
		"workflow type": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().WorkflowType.Name = WorkflowName
		},
		"nil queue": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().TaskQueue = nil
		},
		"queue name": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().TaskQueue.Name = "wrong-queue"
		},
		"queue kind": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().TaskQueue.Kind = enumspb.TASK_QUEUE_KIND_STICKY
		},
		"queue alias": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().TaskQueue.NormalName = queue
		},
		"nil input": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().Input = nil
		},
		"input missing": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().Input.Payloads = nil
		},
		"input extra": func(value *historypb.HistoryEvent) {
			started := value.GetWorkflowExecutionStartedEventAttributes()
			started.Input.Payloads = append(started.Input.Payloads, proto.Clone(started.Input.Payloads[0]).(*commonpb.Payload))
		},
		"input mismatch": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().Input.Payloads[0] = proto.Clone(otherPayload).(*commonpb.Payload)
		},
		"input metadata": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().Input.Payloads[0].Metadata["extra"] = []byte("canary")
		},
		"parent namespace": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().ParentWorkflowNamespace = "default"
		},
		"parent namespace id": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().ParentWorkflowNamespaceId = runtimeV2TenantID
		},
		"parent execution": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().ParentWorkflowExecution = &commonpb.WorkflowExecution{
				WorkflowId: runtimeV2OutboxID, RunId: runtimeV2StarterRunID,
			}
		},
		"root execution": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().RootWorkflowExecution = &commonpb.WorkflowExecution{
				WorkflowId: runtimeV2OutboxID, RunId: runtimeV2StarterRunID,
			}
		},
		"continued run": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().ContinuedExecutionRunId = runtimeV2StarterRunID
		},
		"retry": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().RetryPolicy = &commonpb.RetryPolicy{MaximumAttempts: 2}
		},
		"attempt": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().Attempt = 2
		},
		"cron": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().CronSchedule = "* * * * *"
		},
		"execution timeout": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().WorkflowExecutionTimeout = durationpb.New(time.Minute)
		},
		"run timeout": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().WorkflowRunTimeout = durationpb.New(time.Minute)
		},
		"task timeout": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().WorkflowTaskTimeout = durationpb.New(time.Second)
		},
		"identity": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().Identity = "forged-starter"
		},
		"eager": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().EagerExecutionAccepted = true
		},
		"nil memo": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().Memo = nil
		},
		"memo extra": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().Memo.Fields["extra"] = &commonpb.Payload{}
		},
		"memo mismatch": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().Memo.Fields[RuntimeMemoIdentityKeyV2] =
				proto.Clone(otherPayload).(*commonpb.Payload)
		},
		"header": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().Header = &commonpb.Header{Fields: map[string]*commonpb.Payload{
				"trace": {Data: []byte("canary")},
			}}
		},
		"search": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().SearchAttributes = &commonpb.SearchAttributes{
				IndexedFields: map[string]*commonpb.Payload{"Custom": {Data: []byte("canary")}},
			}
		},
		"priority": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().Priority = &commonpb.Priority{PriorityKey: 1}
		},
		"original run": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().OriginalExecutionRunId = runtimeV2SignalID
		},
		"first run": func(value *historypb.HistoryEvent) {
			value.GetWorkflowExecutionStartedEventAttributes().FirstExecutionRunId = runtimeV2SignalID
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			started, createErr := validRuntimeV2StartedEvent(input, runtimeV2StarterRunID, queue)
			if createErr != nil {
				t.Fatalf("validRuntimeV2StartedEvent() error = %v", createErr)
			}
			mutate(started)
			fake := &fakeRuntimeV2StarterTransport{
				executeErr: &serviceerror.WorkflowExecutionAlreadyStarted{RunId: runtimeV2StarterRunID},
				describe:   validRuntimeV2Describe(t, input, runtimeV2StarterRunID, queue),
				started:    started,
			}
			outcome, startErr := newRuntimeV2StarterForFake(t, fake).Start(context.Background(), validRuntimeV2SignalStart())
			if startErr == nil || outcome != "" || fake.describeCalls != 2 || fake.historyCalls != 1 {
				t.Fatalf("Start(mutated Started %s) = %q, %v; describe=%d history=%d",
					name, outcome, startErr, fake.describeCalls, fake.historyCalls)
			}
			assertRuntimeV2FailureCode(t, startErr, "workflow_identity_mismatch")
		})
	}
}

func TestRuntimeV2StarterRemoteFailuresAreCodedAndCanarySafe(t *testing.T) {
	const canary = "secret-temporal-canary-7d384b"
	input := validRuntimeV2StarterInput()
	queue := mustRuntimeV2ControlQueue(t)
	validDescribe := func() *workflowservicepb.DescribeWorkflowExecutionResponse {
		return validRuntimeV2Describe(t, input, runtimeV2StarterRunID, queue)
	}
	for name, fake := range map[string]*fakeRuntimeV2StarterTransport{
		"execute": {executeErr: errors.New(canary)},
		"describe": {
			executeErr:  &serviceerror.WorkflowExecutionAlreadyStarted{RunId: runtimeV2StarterRunID},
			describeErr: errors.New(canary),
		},
		"history": {
			executeErr: &serviceerror.WorkflowExecutionAlreadyStarted{RunId: runtimeV2StarterRunID},
			describe:   validDescribe(), historyErr: errors.New(canary),
		},
		"second describe": {
			executeErr: &serviceerror.WorkflowExecutionAlreadyStarted{RunId: runtimeV2StarterRunID},
			describe:   validDescribe(), describeAfterProofErr: errors.New(canary),
		},
		"panic": {panicValue: canary},
	} {
		t.Run(name, func(t *testing.T) {
			outcome, err := newRuntimeV2StarterForFake(t, fake).Start(context.Background(), validRuntimeV2SignalStart())
			if err == nil || outcome != "" {
				t.Fatalf("Start(%s failure) = %q, %v", name, outcome, err)
			}
			assertRuntimeV2FailureCode(t, err, "workflow_start_unavailable")
			for _, rendered := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
				if strings.Contains(rendered, canary) {
					t.Fatalf("Start(%s) leaked canary: %q", name, rendered)
				}
			}
			if errors.Is(err, fake.executeErr) || errors.Is(err, fake.describeErr) ||
				errors.Is(err, fake.historyErr) || errors.Is(err, fake.describeAfterProofErr) {
				t.Fatalf("Start(%s) retained raw remote error", name)
			}
		})
	}
}

func TestRuntimeV2StarterPreservesOnlyCanonicalContextTermination(t *testing.T) {
	for name, cause := range map[string]error{
		"canceled": fmt.Errorf("remote canary: %w", context.Canceled),
		"deadline": fmt.Errorf("remote canary: %w", context.DeadlineExceeded),
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeRuntimeV2StarterTransport{executeErr: cause}
			outcome, err := newRuntimeV2StarterForFake(t, fake).Start(context.Background(), validRuntimeV2SignalStart())
			if err == nil || outcome != "" {
				t.Fatalf("Start(%s) = %q, %v", name, outcome, err)
			}
			want := context.Canceled
			if name == "deadline" {
				want = context.DeadlineExceeded
			}
			if !errors.Is(err, want) || strings.Contains(fmt.Sprintf("%+v", err), "remote canary") {
				t.Fatalf("Start(%s) error = %#v", name, err)
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	fake := &fakeRuntimeV2StarterTransport{}
	if outcome, err := newRuntimeV2StarterForFake(t, fake).Start(canceled, validRuntimeV2SignalStart()); err == nil || outcome != "" || !errors.Is(err, context.Canceled) || fake.workflow != nil {
		t.Fatalf("Start(pre-canceled) = %q, %v; temporal=%#v", outcome, err, fake.workflow)
	}
	if outcome, err := newRuntimeV2StarterForFake(t, &fakeRuntimeV2StarterTransport{}).Start(nil, validRuntimeV2SignalStart()); err == nil || outcome != "" {
		t.Fatalf("Start(nil context) = %q, %v", outcome, err)
	}
}

func assertRuntimeV2FailureCode(t *testing.T, err error, expected string) {
	t.Helper()
	var coded interface{ FailureCode() string }
	actual := ""
	if errors.As(err, &coded) {
		actual = coded.FailureCode()
	}
	if actual != expected || err == nil || err.Error() != expected {
		t.Fatalf("dispatch error = %#v; code=%q, want %q", err, actual, expected)
	}
}

func validRuntimeV2SignalStart() outbox.SignalWorkflowStart {
	return outbox.SignalWorkflowStart{
		Version: 1, WorkflowID: runtimeV2OutboxID, OutboxEventID: runtimeV2OutboxID,
		TenantID: runtimeV2TenantID, WorkspaceID: runtimeV2WorkspaceID,
		SignalID: runtimeV2SignalID, AggregateVersion: 1,
	}
}

func validRuntimeV2StarterInput() WorkflowInputV2 {
	return WorkflowInputV2{
		Version: RuntimeV2SchemaVersion, OutboxEventID: runtimeV2OutboxID,
		TenantID: runtimeV2TenantID, WorkspaceID: runtimeV2WorkspaceID,
		SignalID: runtimeV2SignalID, AggregateVersion: 1,
		ManifestDigest: runtimeV2ManifestDigest, RegistryDigest: runtimeV2RegistryDigest,
		BundleDigest: runtimeV2BundleDigest,
	}
}

func mustRuntimeV2ControlQueue(t *testing.T) string {
	t.Helper()
	queue, err := ControlTaskQueue(runtimeV2ManifestDigest, runtimeV2RegistryDigest, runtimeV2BundleDigest)
	if err != nil {
		t.Fatalf("ControlTaskQueue() error = %v", err)
	}
	return queue
}

func newRuntimeV2StarterForFake(t *testing.T, fake *fakeRuntimeV2StarterTransport) *RuntimeV2Starter {
	t.Helper()
	roleClient, err := newRuntimeV2StarterClient(fake, "default")
	if err != nil {
		t.Fatalf("newRuntimeV2StarterClient() error = %v", err)
	}
	starter, err := newRuntimeV2Starter(roleClient, runtimeV2ManifestDigest, runtimeV2RegistryDigest, runtimeV2BundleDigest)
	if err != nil {
		t.Fatalf("NewRuntimeV2Starter() error = %v", err)
	}
	return starter
}

type fakeRuntimeV2StarterTransport struct {
	options               client.StartWorkflowOptions
	workflow              interface{}
	args                  []interface{}
	run                   client.WorkflowRun
	executeErr            error
	describe              *workflowservicepb.DescribeWorkflowExecutionResponse
	describeAfterProof    *workflowservicepb.DescribeWorkflowExecutionResponse
	describeErr           error
	describeAfterProofErr error
	describeCalls         int
	describeWorkflowID    string
	describeRunID         string
	started               *historypb.HistoryEvent
	historyErr            error
	historyCalls          int
	historyWorkflowID     string
	historyRunID          string
	panicValue            interface{}
}

func (fake *fakeRuntimeV2StarterTransport) ExecuteWorkflow(
	_ context.Context,
	options client.StartWorkflowOptions,
	workflow interface{},
	args ...interface{},
) (client.WorkflowRun, error) {
	if fake.panicValue != nil {
		panic(fake.panicValue)
	}
	fake.options, fake.workflow, fake.args = options, workflow, args
	return fake.run, fake.executeErr
}

func (fake *fakeRuntimeV2StarterTransport) DescribeWorkflowExecution(
	_ context.Context,
	workflowID string,
	runID string,
) (*workflowservicepb.DescribeWorkflowExecutionResponse, error) {
	fake.describeCalls++
	fake.describeWorkflowID, fake.describeRunID = workflowID, runID
	response := fake.describe
	err := fake.describeErr
	if fake.describeCalls > 1 && fake.describeAfterProof != nil {
		response = fake.describeAfterProof
	}
	if fake.describeCalls > 1 && fake.describeAfterProofErr != nil {
		err = fake.describeAfterProofErr
	}
	if response == nil {
		return nil, err
	}
	return proto.Clone(response).(*workflowservicepb.DescribeWorkflowExecutionResponse), err
}

func (fake *fakeRuntimeV2StarterTransport) FirstWorkflowHistoryEvent(
	_ context.Context,
	workflowID string,
	runID string,
) (*historypb.HistoryEvent, error) {
	fake.historyCalls++
	fake.historyWorkflowID, fake.historyRunID = workflowID, runID
	if fake.started != nil || fake.historyErr != nil {
		if fake.started == nil {
			return nil, fake.historyErr
		}
		return proto.Clone(fake.started).(*historypb.HistoryEvent), fake.historyErr
	}
	if len(fake.args) != 1 {
		return nil, errors.New("missing workflow input")
	}
	input, ok := fake.args[0].(WorkflowInputV2)
	if !ok {
		return nil, errors.New("wrong workflow input")
	}
	return validRuntimeV2StartedEvent(input, runID, fake.options.TaskQueue)
}

type fakeRuntimeV2WorkflowRun struct{ id, runID string }

func (run fakeRuntimeV2WorkflowRun) GetID() string                      { return run.id }
func (run fakeRuntimeV2WorkflowRun) GetRunID() string                   { return run.runID }
func (fakeRuntimeV2WorkflowRun) Get(context.Context, interface{}) error { return nil }
func (fakeRuntimeV2WorkflowRun) GetWithOptions(context.Context, interface{}, client.WorkflowRunGetOptions) error {
	return nil
}

func validRuntimeV2Describe(
	t *testing.T,
	input WorkflowInputV2,
	runID string,
	queue string,
) *workflowservicepb.DescribeWorkflowExecutionResponse {
	t.Helper()
	payload, err := canonicalWorkflowInputV2Payload(input)
	if err != nil {
		t.Fatalf("canonicalWorkflowInputV2Payload() error = %v", err)
	}
	return &workflowservicepb.DescribeWorkflowExecutionResponse{
		WorkflowExecutionInfo: &workflowpb.WorkflowExecutionInfo{
			Execution: &commonpb.WorkflowExecution{WorkflowId: input.OutboxEventID, RunId: runID},
			Type:      &commonpb.WorkflowType{Name: WorkflowNameV2}, TaskQueue: queue,
			Status: enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING, FirstRunId: runID,
			Memo: &commonpb.Memo{Fields: map[string]*commonpb.Payload{
				RuntimeMemoIdentityKeyV2: proto.Clone(payload).(*commonpb.Payload),
			}},
		},
		ExecutionConfig: &workflowpb.WorkflowExecutionConfig{
			TaskQueue: &taskqueuepb.TaskQueue{Name: queue},
		},
	}
}

func validRuntimeV2StartedEvent(input WorkflowInputV2, runID, queue string) (*historypb.HistoryEvent, error) {
	payload, err := canonicalWorkflowInputV2Payload(input)
	if err != nil {
		return nil, err
	}
	return &historypb.HistoryEvent{
		EventId: 1, EventType: enumspb.EVENT_TYPE_WORKFLOW_EXECUTION_STARTED,
		Attributes: &historypb.HistoryEvent_WorkflowExecutionStartedEventAttributes{
			WorkflowExecutionStartedEventAttributes: &historypb.WorkflowExecutionStartedEventAttributes{
				WorkflowId: input.OutboxEventID, WorkflowType: &commonpb.WorkflowType{Name: WorkflowNameV2},
				TaskQueue:           &taskqueuepb.TaskQueue{Name: queue, Kind: enumspb.TASK_QUEUE_KIND_NORMAL},
				Input:               &commonpb.Payloads{Payloads: []*commonpb.Payload{proto.Clone(payload).(*commonpb.Payload)}},
				WorkflowTaskTimeout: durationpb.New(10 * time.Second), OriginalExecutionRunId: runID,
				FirstExecutionRunId: runID, Identity: runtimeV2StarterIdentity, Attempt: 1,
				Memo: &commonpb.Memo{Fields: map[string]*commonpb.Payload{
					RuntimeMemoIdentityKeyV2: proto.Clone(payload).(*commonpb.Payload),
				}},
			},
		},
	}, nil
}

var _ runtimeV2StarterTransport = (*fakeRuntimeV2StarterTransport)(nil)

var _ = serviceerror.WorkflowExecutionAlreadyStarted{}
