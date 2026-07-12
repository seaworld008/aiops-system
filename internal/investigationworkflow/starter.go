package investigationworkflow

import (
	"context"
	"errors"
	"reflect"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	workflowservicepb "go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"google.golang.org/protobuf/proto"

	"github.com/seaworld008/aiops-system/internal/outbox"
)

const MemoIdentityKey = "aiops.investigation.prepare.identity.v1"

type TemporalStarterClient interface {
	ExecuteWorkflow(context.Context, client.StartWorkflowOptions, interface{}, ...interface{}) (client.WorkflowRun, error)
	DescribeWorkflowExecution(context.Context, string, string) (*workflowservicepb.DescribeWorkflowExecutionResponse, error)
}

type Starter struct {
	client         TemporalStarterClient
	manifestDigest string
	registryDigest string
}

var _ outbox.SignalStarter = (*Starter)(nil)

func NewStarter(client TemporalStarterClient, manifestDigest, registryDigest string) (*Starter, error) {
	if nilInterface(client) {
		return nil, ErrInvalidInput
	}
	if _, err := TaskQueue(manifestDigest, registryDigest); err != nil {
		return nil, ErrInvalidInput
	}
	return &Starter{client: client, manifestDigest: manifestDigest, registryDigest: registryDigest}, nil
}

func (starter *Starter) Start(ctx context.Context, start outbox.SignalWorkflowStart) (outbox.StartOutcome, error) {
	if ctx == nil || starter == nil || nilInterface(starter.client) || start.Version != SchemaVersion ||
		start.AggregateVersion != 1 || start.WorkflowID != start.OutboxEventID ||
		!workflowUUID.MatchString(start.WorkflowID) || !workflowUUID.MatchString(start.TenantID) ||
		!workflowUUID.MatchString(start.WorkspaceID) || !workflowUUID.MatchString(start.SignalID) {
		return "", outbox.NewDispatchError("workflow_start_rejected", ErrInvalidInput)
	}
	if err := ctx.Err(); err != nil {
		return "", outbox.NewDispatchError("workflow_start_unavailable", err)
	}
	input := WorkflowInput{
		Version: SchemaVersion, OutboxEventID: start.OutboxEventID,
		TenantID: start.TenantID, WorkspaceID: start.WorkspaceID, SignalID: start.SignalID,
		AggregateVersion: start.AggregateVersion,
		ManifestDigest:   starter.manifestDigest, RegistryDigest: starter.registryDigest,
	}
	queue, err := TaskQueue(input.ManifestDigest, input.RegistryDigest)
	if err != nil || validateInput(input) != nil {
		return "", outbox.NewDispatchError("workflow_start_rejected", ErrInvalidInput)
	}
	run, err := starter.client.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID:                                       input.OutboxEventID,
		TaskQueue:                                queue,
		WorkflowIDConflictPolicy:                 enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL,
		WorkflowIDReusePolicy:                    enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE,
		WorkflowExecutionErrorWhenAlreadyStarted: true,
		Memo:                                     map[string]interface{}{MemoIdentityKey: input},
	}, WorkflowName, input)
	if err == nil {
		if run == nil || run.GetID() != input.OutboxEventID || !workflowUUID.MatchString(run.GetRunID()) {
			return "", outbox.NewDispatchError("workflow_identity_mismatch", ErrInvalidInput)
		}
		return outbox.StartOutcomeStarted, nil
	}
	var alreadyStarted *serviceerror.WorkflowExecutionAlreadyStarted
	if !errors.As(err, &alreadyStarted) {
		return "", outbox.NewDispatchError("workflow_start_unavailable", err)
	}
	if alreadyStarted == nil || !workflowUUID.MatchString(alreadyStarted.RunId) {
		return "", outbox.NewDispatchError("workflow_identity_mismatch", ErrInvalidInput)
	}
	described, describeErr := starter.client.DescribeWorkflowExecution(ctx, input.OutboxEventID, alreadyStarted.RunId)
	if describeErr != nil {
		return "", outbox.NewDispatchError("workflow_start_unavailable", describeErr)
	}
	if !matchesStartedIdentity(described, input, alreadyStarted.RunId, queue) {
		return "", outbox.NewDispatchError("workflow_identity_mismatch", ErrInvalidInput)
	}
	return outbox.StartOutcomeAlreadyExists, nil
}

func matchesStartedIdentity(
	described *workflowservicepb.DescribeWorkflowExecutionResponse,
	input WorkflowInput,
	runID string,
	queue string,
) bool {
	if described == nil || described.WorkflowExecutionInfo == nil || described.ExecutionConfig == nil {
		return false
	}
	info := described.WorkflowExecutionInfo
	if info.Execution == nil || info.Execution.WorkflowId != input.OutboxEventID || info.Execution.RunId != runID ||
		info.Type == nil || info.Type.Name != WorkflowName || info.TaskQueue != queue ||
		described.ExecutionConfig.TaskQueue == nil || described.ExecutionConfig.TaskQueue.Name != queue ||
		info.ParentExecution != nil || info.ParentNamespaceId != "" ||
		(info.RootExecution != nil && (info.RootExecution.WorkflowId != input.OutboxEventID || info.RootExecution.RunId != runID)) ||
		(info.FirstRunId != "" && info.FirstRunId != runID) || info.Memo == nil || len(info.Memo.Fields) != 1 {
		return false
	}
	payload, found := info.Memo.Fields[MemoIdentityKey]
	if !found || payload == nil || len(payload.Data) > 2048 || len(payload.Metadata) != 1 ||
		string(payload.Metadata["encoding"]) != "json/plain" {
		return false
	}
	expected, err := converter.GetDefaultDataConverter().ToPayload(input)
	if err != nil || !proto.Equal(payload, expected) {
		return false
	}
	var decoded WorkflowInput
	if err := converter.GetDefaultDataConverter().FromPayload(payload, &decoded); err != nil ||
		!reflect.DeepEqual(decoded, input) || validateInput(decoded) != nil {
		return false
	}
	return true
}
