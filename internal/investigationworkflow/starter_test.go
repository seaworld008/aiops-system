package investigationworkflow_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/api/serviceerror"
	taskqueuepb "go.temporal.io/api/taskqueue/v1"
	workflowpb "go.temporal.io/api/workflow/v1"
	workflowservicepb "go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/seaworld008/aiops-system/internal/outbox"
)

const starterRunID = "88888888-8888-4888-8888-888888888888"

func TestStarterUsesExactSafeTemporalOptionsAndExplicitWorkflowName(t *testing.T) {
	input := validWorkflowInput()
	queue := mustTaskQueue(t, input)
	clientFake := &fakeTemporalClient{
		run:      fakeWorkflowRun{id: workflowOutboxID, runID: starterRunID},
		describe: validDescribeResponse(t, input, starterRunID, queue),
	}
	starter := newStarterForFake(t, clientFake)
	outcome, err := starter.Start(context.Background(), validSignalWorkflowStart())
	if err != nil || outcome != outbox.StartOutcomeStarted {
		t.Fatalf("Start() = %s, %v", outcome, err)
	}
	if clientFake.workflow != investigationworkflow.WorkflowName || len(clientFake.args) != 1 {
		t.Fatalf("ExecuteWorkflow name/args = %#v / %#v", clientFake.workflow, clientFake.args)
	}
	capturedInput, ok := clientFake.args[0].(investigationworkflow.WorkflowInput)
	if !ok || capturedInput.OutboxEventID != workflowOutboxID || capturedInput.ManifestDigest != workflowManifest || capturedInput.RegistryDigest != workflowRegistry {
		t.Fatalf("WorkflowInput = %#v", clientFake.args[0])
	}
	options := clientFake.options
	if options.ID != workflowOutboxID || options.TaskQueue != queue || !options.WorkflowExecutionErrorWhenAlreadyStarted ||
		options.WorkflowIDConflictPolicy.String() != "Fail" || options.WorkflowIDReusePolicy.String() != "RejectDuplicate" ||
		len(options.Memo) != 1 || options.RetryPolicy != nil || options.EnableEagerStart ||
		options.WorkflowExecutionTimeout != 0 || options.WorkflowRunTimeout != 0 || options.WorkflowTaskTimeout != 10*time.Second {
		t.Fatalf("StartWorkflowOptions = %#v", options)
	}
	memoPayload, ok := investigationworkflow.MemoIdentityPayloadForTest(options.Memo[investigationworkflow.MemoIdentityKey])
	wantMemo, memoErr := investigationworkflow.CanonicalMemoPayloadForTest(capturedInput)
	if !ok || memoErr != nil || !proto.Equal(memoPayload, wantMemo) {
		t.Fatalf("memo identity = %#v", options.Memo)
	}
	if clientFake.describeWorkflowID != workflowOutboxID || clientFake.describeRunID != starterRunID {
		t.Fatalf("successful Start did not verify exact execution: %s/%s", clientFake.describeWorkflowID, clientFake.describeRunID)
	}
	if clientFake.describeCalls != 2 || strings.Join(clientFake.callOrder, ",") != "describe,history,describe" {
		t.Fatalf("identity verification order = %#v; describe calls = %d", clientFake.callOrder, clientFake.describeCalls)
	}
}

func TestStarterAcceptsAlreadyStartedOnlyAfterExactDescribeVerification(t *testing.T) {
	input := validWorkflowInput()
	queue := mustTaskQueue(t, input)
	clientFake := &fakeTemporalClient{
		executeErr: &serviceerror.WorkflowExecutionAlreadyStarted{RunId: starterRunID},
		describe:   validDescribeResponse(t, input, starterRunID, queue),
	}
	starter := newStarterForFake(t, clientFake)
	outcome, err := starter.Start(context.Background(), validSignalWorkflowStart())
	if err != nil || outcome != outbox.StartOutcomeAlreadyExists || clientFake.describeWorkflowID != workflowOutboxID ||
		clientFake.describeRunID != starterRunID {
		t.Fatalf("Start(already) = %s, %v; describe=%s/%s", outcome, err, clientFake.describeWorkflowID, clientFake.describeRunID)
	}
}

func TestStarterRejectsInvalidStartBeforeTemporalCall(t *testing.T) {
	mutations := map[string]func(*outbox.SignalWorkflowStart){
		"version":     func(start *outbox.SignalWorkflowStart) { start.Version = 2 },
		"workflow id": func(start *outbox.SignalWorkflowStart) { start.WorkflowID = workflowSignalID },
		"outbox id":   func(start *outbox.SignalWorkflowStart) { start.OutboxEventID = workflowSignalID },
		"tenant":      func(start *outbox.SignalWorkflowStart) { start.TenantID = "invalid" },
		"workspace":   func(start *outbox.SignalWorkflowStart) { start.WorkspaceID = "invalid" },
		"signal":      func(start *outbox.SignalWorkflowStart) { start.SignalID = "invalid" },
		"aggregate":   func(start *outbox.SignalWorkflowStart) { start.AggregateVersion = 2 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			clientFake := &fakeTemporalClient{}
			starter := newStarterForFake(t, clientFake)
			start := validSignalWorkflowStart()
			mutate(&start)
			if _, err := starter.Start(context.Background(), start); err == nil || clientFake.workflow != nil {
				t.Fatalf("Start(%s) = %v; temporal workflow=%#v", name, err, clientFake.workflow)
			}
		})
	}
}

func TestStarterRejectsInvalidSuccessfulRunIdentity(t *testing.T) {
	for name, run := range map[string]client.WorkflowRun{
		"nil":            nil,
		"workflow id":    fakeWorkflowRun{id: workflowSignalID, runID: starterRunID},
		"empty run id":   fakeWorkflowRun{id: workflowOutboxID},
		"invalid run id": fakeWorkflowRun{id: workflowOutboxID, runID: "invalid"},
	} {
		t.Run(name, func(t *testing.T) {
			starter := newStarterForFake(t, &fakeTemporalClient{run: run})
			if outcome, err := starter.Start(context.Background(), validSignalWorkflowStart()); err == nil || outcome != "" {
				t.Fatalf("Start(%s run) = %s, %v", name, outcome, err)
			}
		})
	}
}

func TestStarterRejectsMutatedAlreadyStartedExecution(t *testing.T) {
	mutations := map[string]func(*workflowservicepb.DescribeWorkflowExecutionResponse){
		"nil info": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			response.WorkflowExecutionInfo = nil
		},
		"nil config": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) { response.ExecutionConfig = nil },
		"workflow id": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			response.WorkflowExecutionInfo.Execution.WorkflowId = workflowSignalID
		},
		"run id": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			response.WorkflowExecutionInfo.Execution.RunId = workflowSignalID
		},
		"type": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			response.WorkflowExecutionInfo.Type.Name = "wrong.workflow"
		},
		"parent execution": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			response.WorkflowExecutionInfo.ParentExecution = &commonpb.WorkflowExecution{WorkflowId: workflowSignalID, RunId: starterRunID}
		},
		"parent namespace": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			response.WorkflowExecutionInfo.ParentNamespaceId = workflowTenantID
		},
		"root execution": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			response.WorkflowExecutionInfo.RootExecution = &commonpb.WorkflowExecution{WorkflowId: workflowSignalID, RunId: starterRunID}
		},
		"first run": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			response.WorkflowExecutionInfo.FirstRunId = "invalid"
		},
		"info queue": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			response.WorkflowExecutionInfo.TaskQueue = "wrong-queue"
		},
		"config queue": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			response.ExecutionConfig.TaskQueue.Name = "wrong-queue"
		},
		"memo missing": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			response.WorkflowExecutionInfo.Memo.Fields = map[string]*commonpb.Payload{}
		},
		"memo nil payload": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			response.WorkflowExecutionInfo.Memo.Fields[investigationworkflow.MemoIdentityKey] = nil
		},
		"memo extra": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			response.WorkflowExecutionInfo.Memo.Fields["extra"] = &commonpb.Payload{}
		},
		"memo tenant": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			setDescribeMemo(t, response, func(input *investigationworkflow.WorkflowInput) { input.TenantID = workflowWorkspace })
		},
		"memo version": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			setDescribeMemo(t, response, func(input *investigationworkflow.WorkflowInput) { input.Version = 2 })
		},
		"memo outbox": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			setDescribeMemo(t, response, func(input *investigationworkflow.WorkflowInput) { input.OutboxEventID = workflowSignalID })
		},
		"memo aggregate": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			setDescribeMemo(t, response, func(input *investigationworkflow.WorkflowInput) { input.AggregateVersion = 2 })
		},
		"memo workspace": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			setDescribeMemo(t, response, func(input *investigationworkflow.WorkflowInput) { input.WorkspaceID = workflowTenantID })
		},
		"memo signal": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			setDescribeMemo(t, response, func(input *investigationworkflow.WorkflowInput) { input.SignalID = workflowIncidentID })
		},
		"memo manifest": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			setDescribeMemo(t, response, func(input *investigationworkflow.WorkflowInput) { input.ManifestDigest = strings.Repeat("e", 64) })
		},
		"memo registry": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			setDescribeMemo(t, response, func(input *investigationworkflow.WorkflowInput) { input.RegistryDigest = strings.Repeat("e", 64) })
		},
		"memo metadata extra": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			response.WorkflowExecutionInfo.Memo.Fields[investigationworkflow.MemoIdentityKey].Metadata["extra"] = []byte("value")
		},
		"memo encoding": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			response.WorkflowExecutionInfo.Memo.Fields[investigationworkflow.MemoIdentityKey].Metadata["encoding"] = []byte("binary/plain")
		},
		"memo oversized": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			response.WorkflowExecutionInfo.Memo.Fields[investigationworkflow.MemoIdentityKey].Data = bytes.Repeat([]byte{'x'}, 2049)
		},
		"memo malformed": func(response *workflowservicepb.DescribeWorkflowExecutionResponse) {
			response.WorkflowExecutionInfo.Memo.Fields[investigationworkflow.MemoIdentityKey].Data = []byte(`{"version":`)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			input := validWorkflowInput()
			queue := mustTaskQueue(t, input)
			response := validDescribeResponse(t, input, starterRunID, queue)
			mutate(response)
			clientFake := &fakeTemporalClient{executeErr: &serviceerror.WorkflowExecutionAlreadyStarted{RunId: starterRunID}, describe: response}
			starter := newStarterForFake(t, clientFake)
			outcome, err := starter.Start(context.Background(), validSignalWorkflowStart())
			if err == nil || outcome == outbox.StartOutcomeAlreadyExists {
				t.Fatalf("Start(mutated describe) = %s, %v", outcome, err)
			}
		})
	}
}

func TestStarterAcceptsValidResetLineageWithDifferentFirstRun(t *testing.T) {
	input := validWorkflowInput()
	queue := mustTaskQueue(t, input)
	response := validDescribeResponse(t, input, starterRunID, queue)
	response.WorkflowExecutionInfo.RootExecution = &commonpb.WorkflowExecution{
		WorkflowId: workflowOutboxID, RunId: starterRunID,
	}
	response.WorkflowExecutionInfo.FirstRunId = "77777777-7777-4777-8777-777777777777"
	clientFake := &fakeTemporalClient{
		executeErr: &serviceerror.WorkflowExecutionAlreadyStarted{RunId: starterRunID}, describe: response,
	}
	starter := newStarterForFake(t, clientFake)
	if outcome, err := starter.Start(context.Background(), validSignalWorkflowStart()); err != nil || outcome != outbox.StartOutcomeAlreadyExists {
		t.Fatalf("Start(reset lineage) = %s, %v", outcome, err)
	}
}

func TestStarterAcknowledgesOnlySafeWorkflowStatuses(t *testing.T) {
	accepted := []enumspb.WorkflowExecutionStatus{
		enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING,
		enumspb.WORKFLOW_EXECUTION_STATUS_COMPLETED,
		enumspb.WORKFLOW_EXECUTION_STATUS_FAILED,
	}
	for _, status := range accepted {
		t.Run("accept_"+status.String(), func(t *testing.T) {
			input := validWorkflowInput()
			queue := mustTaskQueue(t, input)
			response := validDescribeResponse(t, input, starterRunID, queue)
			response.WorkflowExecutionInfo.Status = status
			fake := &fakeTemporalClient{
				executeErr: &serviceerror.WorkflowExecutionAlreadyStarted{RunId: starterRunID}, describe: response,
			}
			if outcome, err := newStarterForFake(t, fake).Start(context.Background(), validSignalWorkflowStart()); err != nil || outcome != outbox.StartOutcomeAlreadyExists {
				t.Fatalf("Start(%s) = %s, %v", status, outcome, err)
			}
		})
	}
	rejected := []enumspb.WorkflowExecutionStatus{
		enumspb.WORKFLOW_EXECUTION_STATUS_UNSPECIFIED,
		enumspb.WORKFLOW_EXECUTION_STATUS_CANCELED,
		enumspb.WORKFLOW_EXECUTION_STATUS_TERMINATED,
		enumspb.WORKFLOW_EXECUTION_STATUS_TIMED_OUT,
		enumspb.WORKFLOW_EXECUTION_STATUS_CONTINUED_AS_NEW,
	}
	for _, status := range rejected {
		t.Run("reject_"+status.String(), func(t *testing.T) {
			input := validWorkflowInput()
			queue := mustTaskQueue(t, input)
			response := validDescribeResponse(t, input, starterRunID, queue)
			response.WorkflowExecutionInfo.Status = status
			fake := &fakeTemporalClient{
				executeErr: &serviceerror.WorkflowExecutionAlreadyStarted{RunId: starterRunID}, describe: response,
			}
			if outcome, err := newStarterForFake(t, fake).Start(context.Background(), validSignalWorkflowStart()); err == nil || outcome != "" {
				t.Fatalf("Start(%s) = %s, %v", status, outcome, err)
			}
		})
	}
}

func TestStarterRechecksExactRunStatusAfterReadingStartedHistory(t *testing.T) {
	tests := map[string]struct {
		finalStatus enumspb.WorkflowExecutionStatus
		wantACK     bool
	}{
		"completed":  {finalStatus: enumspb.WORKFLOW_EXECUTION_STATUS_COMPLETED, wantACK: true},
		"failed":     {finalStatus: enumspb.WORKFLOW_EXECUTION_STATUS_FAILED, wantACK: true},
		"terminated": {finalStatus: enumspb.WORKFLOW_EXECUTION_STATUS_TERMINATED},
		"canceled":   {finalStatus: enumspb.WORKFLOW_EXECUTION_STATUS_CANCELED},
		"timed out":  {finalStatus: enumspb.WORKFLOW_EXECUTION_STATUS_TIMED_OUT},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			input := validWorkflowInput()
			queue := mustTaskQueue(t, input)
			initial := validDescribeResponse(t, input, starterRunID, queue)
			final := validDescribeResponse(t, input, starterRunID, queue)
			final.WorkflowExecutionInfo.Status = test.finalStatus
			fake := &fakeTemporalClient{
				executeErr: &serviceerror.WorkflowExecutionAlreadyStarted{RunId: starterRunID},
				describe:   initial, describeAfterHistory: final,
			}
			outcome, err := newStarterForFake(t, fake).Start(context.Background(), validSignalWorkflowStart())
			if test.wantACK {
				if err != nil || outcome != outbox.StartOutcomeAlreadyExists {
					t.Fatalf("Start(%s after History) = %s, %v", test.finalStatus, outcome, err)
				}
			} else if err == nil || outcome != "" {
				t.Fatalf("Start(%s after History) = %s, %v", test.finalStatus, outcome, err)
			}
			if fake.describeCalls != 2 || strings.Join(fake.callOrder, ",") != "describe,history,describe" {
				t.Fatalf("verification order = %#v; describe calls = %d", fake.callOrder, fake.describeCalls)
			}
		})
	}
}

func TestStarterRejectsMutatedFirstStartedEventBeforeAcknowledging(t *testing.T) {
	input := validWorkflowInput()
	queue := mustTaskQueue(t, input)
	other := input
	other.SignalID = "99999999-9999-4999-8999-999999999999"
	otherPayload, err := investigationworkflow.CanonicalMemoPayloadForTest(other)
	if err != nil {
		t.Fatalf("CanonicalMemoPayloadForTest(other) error = %v", err)
	}
	mutations := map[string]func(*historypb.HistoryEvent){
		"event id":      func(event *historypb.HistoryEvent) { event.EventId = 2 },
		"event type":    func(event *historypb.HistoryEvent) { event.EventType = enumspb.EVENT_TYPE_WORKFLOW_TASK_STARTED },
		"worker ignore": func(event *historypb.HistoryEvent) { event.WorkerMayIgnore = true },
		"event unknown": func(event *historypb.HistoryEvent) { event.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 0x01}) },
		"started unknown": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().ProtoReflect().SetUnknown([]byte{0x98, 0x06, 0x01})
		},
		"workflow id": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().WorkflowId = workflowSignalID
		},
		"workflow type": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().WorkflowType.Name = "wrong.workflow"
		},
		"queue": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().TaskQueue.Name = "wrong-queue"
		},
		"queue kind": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().TaskQueue.Kind = enumspb.TASK_QUEUE_KIND_STICKY
		},
		"queue normal alias": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().TaskQueue.NormalName = queue
		},
		"input missing": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().Input = nil
		},
		"input mismatch": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().Input.Payloads[0] = otherPayload
		},
		"input opaque": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().Input.Payloads[0] = &commonpb.Payload{
				Metadata: map[string][]byte{converter.MetadataEncoding: []byte("binary/zlib")}, Data: []byte("opaque"),
			}
		},
		"input extra": func(event *historypb.HistoryEvent) {
			started := event.GetWorkflowExecutionStartedEventAttributes()
			started.Input.Payloads = append(started.Input.Payloads, proto.Clone(started.Input.Payloads[0]).(*commonpb.Payload))
		},
		"memo mismatch": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().Memo.Fields[investigationworkflow.MemoIdentityKey] = otherPayload
		},
		"memo extra": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().Memo.Fields["extra"] = &commonpb.Payload{}
		},
		"parent": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().ParentWorkflowExecution = &commonpb.WorkflowExecution{WorkflowId: workflowSignalID, RunId: starterRunID}
		},
		"header": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().Header = &commonpb.Header{Fields: map[string]*commonpb.Payload{"trace": {Data: []byte("x")}}}
		},
		"search attributes": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().SearchAttributes = &commonpb.SearchAttributes{IndexedFields: map[string]*commonpb.Payload{"Custom": {Data: []byte("x")}}}
		},
		"retry": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().RetryPolicy = &commonpb.RetryPolicy{MaximumAttempts: 2}
		},
		"cron": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().CronSchedule = "* * * * *"
		},
		"identity": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().Identity = "forged-identity"
		},
		"attempt": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().Attempt = 2
		},
		"task timeout": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().WorkflowTaskTimeout = durationpb.New(time.Second)
		},
		"continued run": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().ContinuedExecutionRunId = starterRunID
		},
		"original run": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().OriginalExecutionRunId = "invalid"
		},
		"original run differs from first run": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().OriginalExecutionRunId = "77777777-7777-4777-8777-777777777777"
		},
		"first run": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().FirstExecutionRunId = "invalid"
		},
		"root": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().RootWorkflowExecution = &commonpb.WorkflowExecution{WorkflowId: workflowOutboxID, RunId: starterRunID}
		},
		"eager": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().EagerExecutionAccepted = true
		},
		"priority": func(event *historypb.HistoryEvent) {
			event.GetWorkflowExecutionStartedEventAttributes().Priority = &commonpb.Priority{PriorityKey: 1}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			started, err := validStartedHistoryEvent(input, starterRunID, queue, starterRunID)
			if err != nil {
				t.Fatalf("validStartedHistoryEvent() error = %v", err)
			}
			mutate(started)
			fake := &fakeTemporalClient{
				executeErr: &serviceerror.WorkflowExecutionAlreadyStarted{RunId: starterRunID},
				describe:   validDescribeResponse(t, input, starterRunID, queue), started: started,
			}
			if outcome, err := newStarterForFake(t, fake).Start(context.Background(), validSignalWorkflowStart()); err == nil || outcome != "" {
				t.Fatalf("Start(mutated started %s) = %s, %v", name, outcome, err)
			}
		})
	}
}

func validSignalWorkflowStart() outbox.SignalWorkflowStart {
	return outbox.SignalWorkflowStart{
		Version: 1, WorkflowID: workflowOutboxID, OutboxEventID: workflowOutboxID,
		TenantID: workflowTenantID, WorkspaceID: workflowWorkspace, SignalID: workflowSignalID, AggregateVersion: 1,
	}
}

type fakeTemporalClient struct {
	options                 client.StartWorkflowOptions
	workflow                interface{}
	args                    []interface{}
	run                     client.WorkflowRun
	executeErr              error
	describe                *workflowservicepb.DescribeWorkflowExecutionResponse
	describeErr             error
	describeAfterHistory    *workflowservicepb.DescribeWorkflowExecutionResponse
	describeAfterHistoryErr error
	describeCalls           int
	describeWorkflowID      string
	describeRunID           string
	started                 *historypb.HistoryEvent
	startedErr              error
	startedWorkflowID       string
	startedRunID            string
	dataConverter           converter.DataConverter
	namespace               string
	callOrder               []string
}

func (fake *fakeTemporalClient) ExecuteWorkflow(_ context.Context, options client.StartWorkflowOptions, workflow interface{}, args ...interface{}) (client.WorkflowRun, error) {
	fake.options, fake.workflow, fake.args = options, workflow, args
	return fake.run, fake.executeErr
}

func (fake *fakeTemporalClient) DescribeWorkflowExecution(_ context.Context, workflowID, runID string) (*workflowservicepb.DescribeWorkflowExecutionResponse, error) {
	fake.callOrder = append(fake.callOrder, "describe")
	fake.describeCalls++
	fake.describeWorkflowID, fake.describeRunID = workflowID, runID
	response, err := fake.describe, fake.describeErr
	if fake.describeCalls > 1 && (fake.describeAfterHistory != nil || fake.describeAfterHistoryErr != nil) {
		response, err = fake.describeAfterHistory, fake.describeAfterHistoryErr
	}
	if response == nil {
		return nil, err
	}
	return proto.Clone(response).(*workflowservicepb.DescribeWorkflowExecutionResponse), err
}

func (fake *fakeTemporalClient) FirstWorkflowHistoryEvent(_ context.Context, workflowID, runID string) (*historypb.HistoryEvent, error) {
	fake.callOrder = append(fake.callOrder, "history")
	fake.startedWorkflowID, fake.startedRunID = workflowID, runID
	if fake.started != nil || fake.startedErr != nil {
		return fake.started, fake.startedErr
	}
	if len(fake.args) != 1 {
		return nil, errors.New("missing fake workflow input")
	}
	input, ok := fake.args[0].(investigationworkflow.WorkflowInput)
	if !ok {
		return nil, errors.New("invalid fake workflow input")
	}
	firstRunID := runID
	if fake.describe != nil && fake.describe.WorkflowExecutionInfo != nil && fake.describe.WorkflowExecutionInfo.FirstRunId != "" {
		firstRunID = fake.describe.WorkflowExecutionInfo.FirstRunId
	}
	return validStartedHistoryEvent(input, runID, fake.options.TaskQueue, firstRunID)
}

func validStartedHistoryEvent(input investigationworkflow.WorkflowInput, runID, queue, firstRunID string) (*historypb.HistoryEvent, error) {
	payload, err := investigationworkflow.CanonicalMemoPayloadForTest(input)
	if err != nil {
		return nil, err
	}
	return &historypb.HistoryEvent{
		EventId: 1, EventType: enumspb.EVENT_TYPE_WORKFLOW_EXECUTION_STARTED,
		Attributes: &historypb.HistoryEvent_WorkflowExecutionStartedEventAttributes{
			WorkflowExecutionStartedEventAttributes: &historypb.WorkflowExecutionStartedEventAttributes{
				WorkflowId:             input.OutboxEventID,
				WorkflowType:           &commonpb.WorkflowType{Name: investigationworkflow.WorkflowName},
				TaskQueue:              &taskqueuepb.TaskQueue{Name: queue, Kind: enumspb.TASK_QUEUE_KIND_NORMAL},
				Input:                  &commonpb.Payloads{Payloads: []*commonpb.Payload{payload}},
				WorkflowTaskTimeout:    durationpb.New(10 * time.Second),
				OriginalExecutionRunId: firstRunID, FirstExecutionRunId: firstRunID,
				Identity: investigationworkflow.TemporalClientIdentityForTest(), Attempt: 1,
				Memo: &commonpb.Memo{Fields: map[string]*commonpb.Payload{investigationworkflow.MemoIdentityKey: proto.Clone(payload).(*commonpb.Payload)}},
			},
		},
	}, nil
}

type fakeWorkflowRun struct{ id, runID string }

func (run fakeWorkflowRun) GetID() string                      { return run.id }
func (run fakeWorkflowRun) GetRunID() string                   { return run.runID }
func (fakeWorkflowRun) Get(context.Context, interface{}) error { return nil }
func (fakeWorkflowRun) GetWithOptions(context.Context, interface{}, client.WorkflowRunGetOptions) error {
	return nil
}

func validDescribeResponse(t *testing.T, input investigationworkflow.WorkflowInput, runID, queue string) *workflowservicepb.DescribeWorkflowExecutionResponse {
	t.Helper()
	payload, err := investigationworkflow.CanonicalMemoPayloadForTest(input)
	if err != nil {
		t.Fatalf("CanonicalMemoPayloadForTest() error = %v", err)
	}
	return &workflowservicepb.DescribeWorkflowExecutionResponse{
		WorkflowExecutionInfo: &workflowpb.WorkflowExecutionInfo{
			Execution: &commonpb.WorkflowExecution{WorkflowId: input.OutboxEventID, RunId: runID},
			Type:      &commonpb.WorkflowType{Name: investigationworkflow.WorkflowName}, TaskQueue: queue,
			Status: enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING, FirstRunId: runID,
			Memo: &commonpb.Memo{Fields: map[string]*commonpb.Payload{investigationworkflow.MemoIdentityKey: payload}},
		},
		ExecutionConfig: &workflowpb.WorkflowExecutionConfig{TaskQueue: &taskqueuepb.TaskQueue{Name: queue}},
	}
}

func setDescribeMemo(t *testing.T, response *workflowservicepb.DescribeWorkflowExecutionResponse, mutate func(*investigationworkflow.WorkflowInput)) {
	t.Helper()
	payload := response.WorkflowExecutionInfo.Memo.Fields[investigationworkflow.MemoIdentityKey]
	var input investigationworkflow.WorkflowInput
	if err := converter.GetDefaultDataConverter().FromPayload(payload, &input); err != nil {
		t.Fatalf("FromPayload() error = %v", err)
	}
	mutate(&input)
	wire, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	canonical, err := jsoncanonicalizer.Transform(wire)
	if err != nil {
		t.Fatalf("jsoncanonicalizer.Transform() error = %v", err)
	}
	response.WorkflowExecutionInfo.Memo.Fields[investigationworkflow.MemoIdentityKey] = &commonpb.Payload{
		Metadata: map[string][]byte{converter.MetadataEncoding: []byte(converter.MetadataEncodingJSON)}, Data: canonical,
	}
}

func newStarterForFake(t *testing.T, fake *fakeTemporalClient) *investigationworkflow.Starter {
	t.Helper()
	dataConverter := fake.dataConverter
	if dataConverter == nil {
		dataConverter = converter.GetDefaultDataConverter()
	}
	namespace := fake.namespace
	if namespace == "" {
		namespace = "default"
	}
	temporalClient, err := investigationworkflow.NewTemporalClientForTest(fake, dataConverter, namespace)
	if err != nil {
		t.Fatalf("NewTemporalClientForTest() error = %v", err)
	}
	starter, err := investigationworkflow.NewStarter(temporalClient, workflowManifest, workflowRegistry)
	if err != nil {
		t.Fatalf("NewStarter() error = %v", err)
	}
	return starter
}
