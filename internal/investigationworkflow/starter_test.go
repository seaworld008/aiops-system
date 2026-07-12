package investigationworkflow_test

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/api/serviceerror"
	taskqueuepb "go.temporal.io/api/taskqueue/v1"
	workflowpb "go.temporal.io/api/workflow/v1"
	workflowservicepb "go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"

	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/seaworld008/aiops-system/internal/outbox"
)

const starterRunID = "88888888-8888-4888-8888-888888888888"

func TestStarterUsesExactSafeTemporalOptionsAndExplicitWorkflowName(t *testing.T) {
	clientFake := &fakeTemporalClient{run: fakeWorkflowRun{id: workflowOutboxID, runID: starterRunID}}
	starter, err := investigationworkflow.NewStarter(clientFake, workflowManifest, workflowRegistry)
	if err != nil {
		t.Fatalf("NewStarter() error = %v", err)
	}
	outcome, err := starter.Start(context.Background(), validSignalWorkflowStart())
	if err != nil || outcome != outbox.StartOutcomeStarted {
		t.Fatalf("Start() = %s, %v", outcome, err)
	}
	if clientFake.workflow != investigationworkflow.WorkflowName || len(clientFake.args) != 1 {
		t.Fatalf("ExecuteWorkflow name/args = %#v / %#v", clientFake.workflow, clientFake.args)
	}
	input, ok := clientFake.args[0].(investigationworkflow.WorkflowInput)
	if !ok || input.OutboxEventID != workflowOutboxID || input.ManifestDigest != workflowManifest || input.RegistryDigest != workflowRegistry {
		t.Fatalf("WorkflowInput = %#v", clientFake.args[0])
	}
	queue := mustTaskQueue(t, input)
	options := clientFake.options
	if options.ID != workflowOutboxID || options.TaskQueue != queue || !options.WorkflowExecutionErrorWhenAlreadyStarted ||
		options.WorkflowIDConflictPolicy.String() != "Fail" || options.WorkflowIDReusePolicy.String() != "RejectDuplicate" ||
		len(options.Memo) != 1 || options.RetryPolicy != nil || options.EnableEagerStart ||
		options.WorkflowExecutionTimeout != 0 || options.WorkflowRunTimeout != 0 {
		t.Fatalf("StartWorkflowOptions = %#v", options)
	}
	memoInput, ok := options.Memo[investigationworkflow.MemoIdentityKey].(investigationworkflow.WorkflowInput)
	if !ok || !reflect.DeepEqual(memoInput, input) {
		t.Fatalf("memo identity = %#v", options.Memo)
	}
}

func TestStarterAcceptsAlreadyStartedOnlyAfterExactDescribeVerification(t *testing.T) {
	input := validWorkflowInput()
	queue := mustTaskQueue(t, input)
	clientFake := &fakeTemporalClient{
		executeErr: &serviceerror.WorkflowExecutionAlreadyStarted{RunId: starterRunID},
		describe:   validDescribeResponse(t, input, starterRunID, queue),
	}
	starter, err := investigationworkflow.NewStarter(clientFake, workflowManifest, workflowRegistry)
	if err != nil {
		t.Fatalf("NewStarter() error = %v", err)
	}
	outcome, err := starter.Start(context.Background(), validSignalWorkflowStart())
	if err != nil || outcome != outbox.StartOutcomeAlreadyExists || clientFake.describeWorkflowID != workflowOutboxID ||
		clientFake.describeRunID != starterRunID {
		t.Fatalf("Start(already) = %s, %v; describe=%s/%s", outcome, err, clientFake.describeWorkflowID, clientFake.describeRunID)
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
			response.WorkflowExecutionInfo.FirstRunId = workflowSignalID
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
			starter, err := investigationworkflow.NewStarter(clientFake, workflowManifest, workflowRegistry)
			if err != nil {
				t.Fatalf("NewStarter() error = %v", err)
			}
			outcome, err := starter.Start(context.Background(), validSignalWorkflowStart())
			if err == nil || outcome == outbox.StartOutcomeAlreadyExists {
				t.Fatalf("Start(mutated describe) = %s, %v", outcome, err)
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
	options            client.StartWorkflowOptions
	workflow           interface{}
	args               []interface{}
	run                client.WorkflowRun
	executeErr         error
	describe           *workflowservicepb.DescribeWorkflowExecutionResponse
	describeErr        error
	describeWorkflowID string
	describeRunID      string
}

func (fake *fakeTemporalClient) ExecuteWorkflow(_ context.Context, options client.StartWorkflowOptions, workflow interface{}, args ...interface{}) (client.WorkflowRun, error) {
	fake.options, fake.workflow, fake.args = options, workflow, args
	return fake.run, fake.executeErr
}

func (fake *fakeTemporalClient) DescribeWorkflowExecution(_ context.Context, workflowID, runID string) (*workflowservicepb.DescribeWorkflowExecutionResponse, error) {
	fake.describeWorkflowID, fake.describeRunID = workflowID, runID
	return fake.describe, fake.describeErr
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
	payload, err := converter.GetDefaultDataConverter().ToPayload(input)
	if err != nil {
		t.Fatalf("ToPayload() error = %v", err)
	}
	return &workflowservicepb.DescribeWorkflowExecutionResponse{
		WorkflowExecutionInfo: &workflowpb.WorkflowExecutionInfo{
			Execution: &commonpb.WorkflowExecution{WorkflowId: input.OutboxEventID, RunId: runID},
			Type:      &commonpb.WorkflowType{Name: investigationworkflow.WorkflowName}, TaskQueue: queue,
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
	encoded, err := converter.GetDefaultDataConverter().ToPayload(input)
	if err != nil {
		t.Fatalf("ToPayload() error = %v", err)
	}
	response.WorkflowExecutionInfo.Memo.Fields[investigationworkflow.MemoIdentityKey] = encoded
}
