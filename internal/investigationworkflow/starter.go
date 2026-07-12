package investigationworkflow

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"time"

	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/api/serviceerror"
	workflowservicepb "go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"google.golang.org/protobuf/proto"

	"github.com/seaworld008/aiops-system/internal/outbox"
)

const MemoIdentityKey = "aiops.investigation.prepare.identity.v1"

var temporalNamespacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)

type Starter struct {
	client         *TemporalClient
	manifestDigest string
	registryDigest string
}

var _ outbox.SignalStarter = (*Starter)(nil)

// NewStarter is the legacy shared-role v1 compatibility constructor.
// Deprecated: repository architecture tests require zero production callsites.
func NewStarter(temporalClient *TemporalClient, manifestDigest, registryDigest string) (*Starter, error) {
	if !temporalClient.validForStarter() {
		return nil, ErrInvalidInput
	}
	if _, err := TaskQueue(manifestDigest, registryDigest); err != nil {
		return nil, ErrInvalidInput
	}
	return &Starter{
		client:         temporalClient,
		manifestDigest: manifestDigest, registryDigest: registryDigest,
	}, nil
}

func (starter *Starter) Start(ctx context.Context, start outbox.SignalWorkflowStart) (outbox.StartOutcome, error) {
	if ctx == nil || starter == nil || !starter.client.validForStarter() || start.Version != SchemaVersion ||
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
	identity, expectedMemo, err := newMemoIdentity(input)
	if err != nil {
		return "", outbox.NewDispatchError("workflow_start_rejected", ErrInvalidInput)
	}
	routedMemo, err := starter.client.router.ToPayload(identity)
	if err != nil || !proto.Equal(routedMemo, expectedMemo) {
		return "", outbox.NewDispatchError("workflow_start_rejected", ErrInvalidInput)
	}
	run, err := starter.client.starter.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID:                                       input.OutboxEventID,
		TaskQueue:                                queue,
		WorkflowIDConflictPolicy:                 enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL,
		WorkflowIDReusePolicy:                    enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE,
		WorkflowExecutionErrorWhenAlreadyStarted: true,
		WorkflowTaskTimeout:                      10 * time.Second,
		Memo:                                     map[string]interface{}{MemoIdentityKey: identity},
	}, WorkflowName, input)
	if err == nil {
		if run == nil || run.GetID() != input.OutboxEventID || !temporalRunUUID.MatchString(run.GetRunID()) {
			return "", outbox.NewDispatchError("workflow_identity_mismatch", ErrInvalidInput)
		}
		if verifyErr := starter.verifyStartedIdentity(ctx, input, run.GetRunID(), queue, expectedMemo); verifyErr != nil {
			return "", verifyErr
		}
		return outbox.StartOutcomeStarted, nil
	}
	var alreadyStarted *serviceerror.WorkflowExecutionAlreadyStarted
	if !errors.As(err, &alreadyStarted) {
		return "", outbox.NewDispatchError("workflow_start_unavailable", err)
	}
	if alreadyStarted == nil || !temporalRunUUID.MatchString(alreadyStarted.RunId) {
		return "", outbox.NewDispatchError("workflow_identity_mismatch", ErrInvalidInput)
	}
	if verifyErr := starter.verifyStartedIdentity(ctx, input, alreadyStarted.RunId, queue, expectedMemo); verifyErr != nil {
		return "", verifyErr
	}
	return outbox.StartOutcomeAlreadyExists, nil
}

func (starter *Starter) verifyStartedIdentity(
	ctx context.Context,
	input WorkflowInput,
	runID string,
	queue string,
	expectedMemo *commonpb.Payload,
) error {
	described, describeErr := starter.client.starter.DescribeWorkflowExecution(ctx, input.OutboxEventID, runID)
	if describeErr != nil {
		return outbox.NewDispatchError("workflow_start_unavailable", describeErr)
	}
	if !starter.matchesStartedIdentity(described, input, runID, queue, expectedMemo) {
		return outbox.NewDispatchError("workflow_identity_mismatch", ErrInvalidInput)
	}
	firstEvent, historyErr := starter.client.starter.FirstWorkflowHistoryEvent(ctx, input.OutboxEventID, runID)
	if historyErr != nil {
		return outbox.NewDispatchError("workflow_start_unavailable", historyErr)
	}
	// Describe again after reading History. The second exact-run response is the
	// final network observation before ACK and narrows the material status-change
	// window after the initial cheap rejection and immutable Started event read.
	described, describeErr = starter.client.starter.DescribeWorkflowExecution(ctx, input.OutboxEventID, runID)
	if describeErr != nil {
		return outbox.NewDispatchError("workflow_start_unavailable", describeErr)
	}
	if !starter.matchesStartedIdentity(described, input, runID, queue, expectedMemo) ||
		!starter.matchesStartedEvent(firstEvent, described, input, runID, queue, expectedMemo) {
		return outbox.NewDispatchError("workflow_identity_mismatch", ErrInvalidInput)
	}
	return nil
}

func (starter *Starter) matchesStartedIdentity(
	described *workflowservicepb.DescribeWorkflowExecutionResponse,
	input WorkflowInput,
	runID string,
	queue string,
	expectedMemo *commonpb.Payload,
) (matches bool) {
	defer func() {
		if recover() != nil {
			matches = false
		}
	}()
	if described == nil || described.WorkflowExecutionInfo == nil || described.ExecutionConfig == nil {
		return false
	}
	info := described.WorkflowExecutionInfo
	if info.Execution == nil || info.Execution.WorkflowId != input.OutboxEventID || info.Execution.RunId != runID ||
		info.Type == nil || info.Type.Name != WorkflowName || info.TaskQueue != queue ||
		!acknowledgeableWorkflowStatus(info.Status) ||
		described.ExecutionConfig.TaskQueue == nil || described.ExecutionConfig.TaskQueue.Name != queue ||
		info.ParentExecution != nil || info.ParentNamespaceId != "" ||
		(info.RootExecution != nil && (info.RootExecution.WorkflowId != input.OutboxEventID || info.RootExecution.RunId != runID)) ||
		(info.FirstRunId != "" && !temporalRunUUID.MatchString(info.FirstRunId)) || info.Memo == nil || len(info.Memo.Fields) != 1 {
		return false
	}
	payload, found := info.Memo.Fields[MemoIdentityKey]
	if !found || payload == nil || expectedMemo == nil || proto.Size(payload) > maximumMemoPayloadBytes ||
		!proto.Equal(payload, expectedMemo) {
		return false
	}
	decoded, err := decodeWorkflowInputPayload(payload)
	if err != nil ||
		!reflect.DeepEqual(decoded, input) || validateInput(decoded) != nil {
		return false
	}
	return true
}

func (starter *Starter) matchesStartedEvent(
	event *historypb.HistoryEvent,
	described *workflowservicepb.DescribeWorkflowExecutionResponse,
	input WorkflowInput,
	runID string,
	queue string,
	expectedPayload *commonpb.Payload,
) bool {
	if event == nil || event.EventId != 1 || event.EventType != enumspb.EVENT_TYPE_WORKFLOW_EXECUTION_STARTED ||
		event.WorkerMayIgnore || event.UserMetadata != nil || len(event.Links) != 0 || event.Principal != nil ||
		len(event.EventGroupMarkers) != 0 || len(event.ProtoReflect().GetUnknown()) != 0 {
		return false
	}
	started := event.GetWorkflowExecutionStartedEventAttributes()
	if started == nil || len(started.ProtoReflect().GetUnknown()) != 0 || started.WorkflowId != input.OutboxEventID ||
		started.WorkflowType == nil || started.WorkflowType.Name != WorkflowName ||
		started.TaskQueue == nil || started.TaskQueue.Name != queue ||
		started.TaskQueue.Kind != enumspb.TASK_QUEUE_KIND_NORMAL || started.TaskQueue.NormalName != "" ||
		len(started.Input.GetPayloads()) != 1 || expectedPayload == nil ||
		proto.Size(started.Input.Payloads[0]) > maximumMemoPayloadBytes ||
		!proto.Equal(started.Input.Payloads[0], expectedPayload) ||
		started.ParentWorkflowNamespace != "" || started.ParentWorkflowNamespaceId != "" ||
		started.ParentWorkflowExecution != nil || started.ParentInitiatedEventId != 0 ||
		started.ParentInitiatedEventVersion != 0 || started.RootWorkflowExecution != nil ||
		started.ContinuedExecutionRunId != "" || started.Initiator != enumspb.CONTINUE_AS_NEW_INITIATOR_UNSPECIFIED ||
		started.ContinuedFailure != nil || started.LastCompletionResult != nil ||
		started.RetryPolicy != nil || started.Attempt != 1 || started.CronSchedule != "" ||
		!zeroProtoDuration(started.FirstWorkflowTaskBackoff) || started.WorkflowExecutionExpirationTime != nil ||
		!zeroProtoDuration(started.WorkflowExecutionTimeout) || !zeroProtoDuration(started.WorkflowRunTimeout) ||
		!exactProtoDuration(started.WorkflowTaskTimeout, 10*time.Second) ||
		started.Identity != temporalClientIdentity || started.EagerExecutionAccepted ||
		!emptyMemoMatches(started.Memo, expectedPayload) || !emptyHeader(started.Header) ||
		!emptySearchAttributes(started.SearchAttributes) || len(started.CompletionCallbacks) != 0 ||
		started.SourceVersionStamp != nil || started.InheritedBuildId != "" || started.VersioningOverride != nil ||
		started.ParentPinnedWorkerDeploymentVersion != "" ||
		started.InheritedPinnedVersion != nil || started.InheritedAutoUpgradeInfo != nil ||
		started.DeclinedTargetVersionUpgrade != nil || started.Priority != nil ||
		started.TimeSkippingConfig != nil || started.TimeSkippingStatePropagation != nil ||
		started.PrevAutoResetPoints != nil || !temporalRunUUID.MatchString(started.OriginalExecutionRunId) ||
		!temporalRunUUID.MatchString(started.FirstExecutionRunId) {
		return false
	}
	decoded, err := decodeWorkflowInputPayload(started.Input.Payloads[0])
	if err != nil || !reflect.DeepEqual(decoded, input) {
		return false
	}
	info := described.GetWorkflowExecutionInfo()
	if info == nil || info.Execution == nil || info.Execution.RunId != runID {
		return false
	}
	if started.OriginalExecutionRunId != started.FirstExecutionRunId ||
		info.FirstRunId != started.FirstExecutionRunId {
		return false
	}
	return true
}

func zeroProtoDuration(value interface {
	GetSeconds() int64
	GetNanos() int32
}) bool {
	return value == nil || value.GetSeconds() == 0 && value.GetNanos() == 0
}

func exactProtoDuration(value interface {
	GetSeconds() int64
	GetNanos() int32
}, expected time.Duration) bool {
	return value != nil && value.GetSeconds() == int64(expected/time.Second) && value.GetNanos() == 0
}

func emptyMemoMatches(memo *commonpb.Memo, expected *commonpb.Payload) bool {
	return memo != nil && len(memo.Fields) == 1 && memo.Fields[MemoIdentityKey] != nil &&
		proto.Equal(memo.Fields[MemoIdentityKey], expected)
}

func emptyHeader(header *commonpb.Header) bool {
	return header == nil || len(header.Fields) == 0
}

func emptySearchAttributes(attributes *commonpb.SearchAttributes) bool {
	return attributes == nil || len(attributes.IndexedFields) == 0
}

func acknowledgeableWorkflowStatus(status enumspb.WorkflowExecutionStatus) bool {
	switch status {
	case enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING,
		enumspb.WORKFLOW_EXECUTION_STATUS_COMPLETED,
		enumspb.WORKFLOW_EXECUTION_STATUS_FAILED:
		return true
	default:
		return false
	}
}
