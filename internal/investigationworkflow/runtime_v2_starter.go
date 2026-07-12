package investigationworkflow

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
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

const runtimeV2WorkflowTaskTimeout = 10 * time.Second

var (
	errRuntimeV2StarterRejected = errors.New("investigation READ workflow start rejected")
	errRuntimeV2StarterRemote   = errors.New("investigation READ workflow start unavailable")
	runtimeV2StarterSeal        = &runtimeV2StarterMarker{value: 1}
)

var _ outbox.SignalStarter = (*RuntimeV2Starter)(nil)

type runtimeV2StarterMarker struct{ value byte }

// RuntimeV2Starter is the sealed outbox-to-Temporal start boundary for the
// v2 READ workflow. Its routing identity is fixed at construction time and is
// never accepted from an outbox event or caller-controlled workflow options.
type RuntimeV2Starter struct {
	client         *RuntimeV2StarterClient
	manifestDigest string
	registryDigest string
	bundleDigest   string
	taskQueue      string
	seal           *runtimeV2StarterMarker
	self           *RuntimeV2Starter
}

// newRuntimeV2Starter validates and clones the immutable runtime identity.
// Production assembly is available only through the bound roles constructor.
func newRuntimeV2Starter(
	roleClient *RuntimeV2StarterClient,
	manifestDigest string,
	registryDigest string,
	bundleDigest string,
) (*RuntimeV2Starter, error) {
	if roleClient == nil || !roleClient.validForStarter() {
		return nil, errRuntimeV2StarterRejected
	}
	queue, err := ControlTaskQueue(manifestDigest, registryDigest, bundleDigest)
	if err != nil {
		return nil, errRuntimeV2StarterRejected
	}
	created := &RuntimeV2Starter{
		client:         roleClient,
		manifestDigest: strings.Clone(manifestDigest),
		registryDigest: strings.Clone(registryDigest),
		bundleDigest:   strings.Clone(bundleDigest),
		taskQueue:      strings.Clone(queue),
		seal:           runtimeV2StarterSeal,
	}
	created.self = created
	return created, nil
}

func (starter *RuntimeV2Starter) valid() bool {
	return starter != nil && starter.seal == runtimeV2StarterSeal && starter.self == starter &&
		starter.client != nil && starter.client.validForStarter() &&
		starter.manifestDigest != "" && starter.registryDigest != "" && starter.bundleDigest != "" &&
		starter.taskQueue != ""
}

func (RuntimeV2Starter) String() string   { return "<aiops-runtime-v2-starter>" }
func (RuntimeV2Starter) GoString() string { return "<aiops-runtime-v2-starter>" }

func (RuntimeV2Starter) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-runtime-v2-starter>")
}

func (RuntimeV2Starter) MarshalJSON() ([]byte, error) {
	return nil, errRuntimeV2StarterRejected
}

func (*RuntimeV2Starter) UnmarshalJSON([]byte) error {
	return errRuntimeV2StarterRejected
}

// Start implements outbox.SignalStarter. Both a newly started execution and
// an AlreadyStarted response are acknowledged only after the same exact-run
// Describe -> immutable Started event -> Describe proof succeeds.
func (starter *RuntimeV2Starter) Start(
	ctx context.Context,
	start outbox.SignalWorkflowStart,
) (outcome outbox.StartOutcome, failure error) {
	defer func() {
		if recover() != nil {
			outcome = ""
			failure = runtimeV2DispatchRemoteError(nil)
		}
	}()
	if ctx == nil || !starter.valid() || !validRuntimeV2SignalRequest(start) {
		return "", runtimeV2DispatchError("workflow_start_rejected", errRuntimeV2StarterRejected)
	}
	if err := ctx.Err(); err != nil {
		return "", runtimeV2DispatchRemoteError(err)
	}
	input := WorkflowInputV2{
		Version:          RuntimeV2SchemaVersion,
		OutboxEventID:    start.OutboxEventID,
		TenantID:         start.TenantID,
		WorkspaceID:      start.WorkspaceID,
		SignalID:         start.SignalID,
		AggregateVersion: start.AggregateVersion,
		ManifestDigest:   starter.manifestDigest,
		RegistryDigest:   starter.registryDigest,
		BundleDigest:     starter.bundleDigest,
	}
	if input.Validate() != nil {
		return "", runtimeV2DispatchError("workflow_start_rejected", errRuntimeV2StarterRejected)
	}
	queue, err := ControlTaskQueue(input.ManifestDigest, input.RegistryDigest, input.BundleDigest)
	if err != nil || queue != starter.taskQueue {
		return "", runtimeV2DispatchError("workflow_start_rejected", errRuntimeV2StarterRejected)
	}
	memoIdentity, expectedPayload, err := newRuntimeV2MemoIdentity(input)
	if err != nil || expectedPayload == nil || proto.Size(expectedPayload) > maximumHistoryDTOBytes {
		return "", runtimeV2DispatchError("workflow_start_rejected", errRuntimeV2StarterRejected)
	}
	transport := starter.client.starterTransportValue()
	if nilInterface(transport) {
		return "", runtimeV2DispatchError("workflow_start_rejected", errRuntimeV2StarterRejected)
	}
	run, err := transport.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID:                                       input.OutboxEventID,
		TaskQueue:                                starter.taskQueue,
		WorkflowIDConflictPolicy:                 enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL,
		WorkflowIDReusePolicy:                    enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE,
		WorkflowExecutionErrorWhenAlreadyStarted: true,
		WorkflowTaskTimeout:                      runtimeV2WorkflowTaskTimeout,
		Memo:                                     map[string]interface{}{RuntimeMemoIdentityKeyV2: memoIdentity},
	}, WorkflowNameV2, input)
	if err == nil {
		if run == nil {
			return "", runtimeV2DispatchError("workflow_identity_mismatch", errRuntimeV2StarterRejected)
		}
		workflowID, runID := run.GetID(), strings.Clone(run.GetRunID())
		if workflowID != input.OutboxEventID || !ValidTemporalRunID(runID) {
			return "", runtimeV2DispatchError("workflow_identity_mismatch", errRuntimeV2StarterRejected)
		}
		if proofErr := starter.proveStarted(ctx, transport, input, runID, expectedPayload); proofErr != nil {
			return "", proofErr
		}
		return outbox.StartOutcomeStarted, nil
	}
	var alreadyStarted *serviceerror.WorkflowExecutionAlreadyStarted
	if !errors.As(err, &alreadyStarted) {
		return "", runtimeV2DispatchRemoteError(err)
	}
	if alreadyStarted == nil {
		return "", runtimeV2DispatchError("workflow_identity_mismatch", errRuntimeV2StarterRejected)
	}
	runID := strings.Clone(alreadyStarted.RunId)
	if !ValidTemporalRunID(runID) {
		return "", runtimeV2DispatchError("workflow_identity_mismatch", errRuntimeV2StarterRejected)
	}
	if proofErr := starter.proveStarted(ctx, transport, input, runID, expectedPayload); proofErr != nil {
		return "", proofErr
	}
	return outbox.StartOutcomeAlreadyExists, nil
}

func validRuntimeV2SignalRequest(start outbox.SignalWorkflowStart) bool {
	return start.Version == SchemaVersion && start.AggregateVersion == 1 &&
		start.WorkflowID == start.OutboxEventID && workflowUUID.MatchString(start.WorkflowID) &&
		workflowUUID.MatchString(start.TenantID) && workflowUUID.MatchString(start.WorkspaceID) &&
		workflowUUID.MatchString(start.SignalID)
}

func (starter *RuntimeV2Starter) proveStarted(
	ctx context.Context,
	transport runtimeV2StarterTransport,
	input WorkflowInputV2,
	runID string,
	expectedPayload *commonpb.Payload,
) error {
	described, err := transport.DescribeWorkflowExecution(ctx, input.OutboxEventID, runID)
	if err != nil {
		return runtimeV2DispatchRemoteError(err)
	}
	if !starter.matchesRuntimeV2Description(described, input, runID, expectedPayload) {
		return runtimeV2DispatchError("workflow_identity_mismatch", errRuntimeV2StarterRejected)
	}
	first, err := transport.FirstWorkflowHistoryEvent(ctx, input.OutboxEventID, runID)
	if err != nil {
		return runtimeV2DispatchRemoteError(err)
	}
	described, err = transport.DescribeWorkflowExecution(ctx, input.OutboxEventID, runID)
	if err != nil {
		return runtimeV2DispatchRemoteError(err)
	}
	if !starter.matchesRuntimeV2Description(described, input, runID, expectedPayload) ||
		!starter.matchesRuntimeV2StartedEvent(first, described, input, runID, expectedPayload) {
		return runtimeV2DispatchError("workflow_identity_mismatch", errRuntimeV2StarterRejected)
	}
	return nil
}

func (starter *RuntimeV2Starter) matchesRuntimeV2Description(
	described *workflowservicepb.DescribeWorkflowExecutionResponse,
	input WorkflowInputV2,
	runID string,
	expectedPayload *commonpb.Payload,
) (matches bool) {
	defer func() {
		if recover() != nil {
			matches = false
		}
	}()
	if described == nil || described.WorkflowExecutionInfo == nil || described.ExecutionConfig == nil ||
		expectedPayload == nil || proto.Size(expectedPayload) > maximumHistoryDTOBytes {
		return false
	}
	info := described.WorkflowExecutionInfo
	if info.Execution == nil || info.Execution.WorkflowId != input.OutboxEventID || info.Execution.RunId != runID ||
		info.Type == nil || info.Type.Name != WorkflowNameV2 || info.TaskQueue != starter.taskQueue ||
		!acknowledgeableWorkflowStatus(info.Status) || info.FirstRunId != runID ||
		described.ExecutionConfig.TaskQueue == nil || described.ExecutionConfig.TaskQueue.Name != starter.taskQueue ||
		info.ParentExecution != nil || info.ParentNamespaceId != "" ||
		(info.RootExecution != nil && (info.RootExecution.WorkflowId != input.OutboxEventID ||
			info.RootExecution.RunId != runID)) || info.Memo == nil || len(info.Memo.Fields) != 1 {
		return false
	}
	payload := info.Memo.Fields[RuntimeMemoIdentityKeyV2]
	return payload != nil && proto.Size(payload) <= maximumHistoryDTOBytes && proto.Equal(payload, expectedPayload)
}

func (starter *RuntimeV2Starter) matchesRuntimeV2StartedEvent(
	event *historypb.HistoryEvent,
	described *workflowservicepb.DescribeWorkflowExecutionResponse,
	input WorkflowInputV2,
	runID string,
	expectedPayload *commonpb.Payload,
) (matches bool) {
	defer func() {
		if recover() != nil {
			matches = false
		}
	}()
	if event == nil || event.EventId != 1 || event.EventType != enumspb.EVENT_TYPE_WORKFLOW_EXECUTION_STARTED ||
		event.WorkerMayIgnore || event.UserMetadata != nil || len(event.Links) != 0 || event.Principal != nil ||
		len(event.EventGroupMarkers) != 0 || len(event.ProtoReflect().GetUnknown()) != 0 {
		return false
	}
	started := event.GetWorkflowExecutionStartedEventAttributes()
	if started == nil || len(started.ProtoReflect().GetUnknown()) != 0 || expectedPayload == nil ||
		started.WorkflowId != input.OutboxEventID || started.WorkflowType == nil ||
		started.WorkflowType.Name != WorkflowNameV2 || started.TaskQueue == nil ||
		started.TaskQueue.Name != starter.taskQueue || started.TaskQueue.Kind != enumspb.TASK_QUEUE_KIND_NORMAL ||
		started.TaskQueue.NormalName != "" || len(started.Input.GetPayloads()) != 1 ||
		proto.Size(started.Input.Payloads[0]) > maximumHistoryDTOBytes ||
		!proto.Equal(started.Input.Payloads[0], expectedPayload) ||
		started.ParentWorkflowNamespace != "" || started.ParentWorkflowNamespaceId != "" ||
		started.ParentWorkflowExecution != nil || started.ParentInitiatedEventId != 0 ||
		started.ParentInitiatedEventVersion != 0 || started.RootWorkflowExecution != nil ||
		started.ContinuedExecutionRunId != "" || started.Initiator != enumspb.CONTINUE_AS_NEW_INITIATOR_UNSPECIFIED ||
		started.ContinuedFailure != nil || started.LastCompletionResult != nil || started.RetryPolicy != nil ||
		started.Attempt != 1 || started.CronSchedule != "" || !zeroProtoDuration(started.FirstWorkflowTaskBackoff) ||
		started.WorkflowExecutionExpirationTime != nil || !zeroProtoDuration(started.WorkflowExecutionTimeout) ||
		!zeroProtoDuration(started.WorkflowRunTimeout) ||
		!exactProtoDuration(started.WorkflowTaskTimeout, runtimeV2WorkflowTaskTimeout) ||
		started.Identity != runtimeV2StarterIdentity || started.EagerExecutionAccepted ||
		!runtimeV2MemoMatches(started.Memo, expectedPayload) || !emptyHeader(started.Header) ||
		!emptySearchAttributes(started.SearchAttributes) || len(started.CompletionCallbacks) != 0 ||
		started.SourceVersionStamp != nil || started.InheritedBuildId != "" || started.VersioningOverride != nil ||
		started.ParentPinnedWorkerDeploymentVersion != "" || started.InheritedPinnedVersion != nil ||
		started.InheritedAutoUpgradeInfo != nil || started.DeclinedTargetVersionUpgrade != nil ||
		started.Priority != nil || started.TimeSkippingConfig != nil || started.TimeSkippingStatePropagation != nil ||
		started.PrevAutoResetPoints != nil || started.OriginalExecutionRunId != runID ||
		started.FirstExecutionRunId != runID {
		return false
	}
	info := described.GetWorkflowExecutionInfo()
	return info != nil && info.Execution != nil && info.Execution.WorkflowId == input.OutboxEventID &&
		info.Execution.RunId == runID && info.FirstRunId == runID
}

func runtimeV2MemoMatches(memo *commonpb.Memo, expected *commonpb.Payload) bool {
	return memo != nil && len(memo.Fields) == 1 && memo.Fields[RuntimeMemoIdentityKeyV2] != nil &&
		proto.Size(memo.Fields[RuntimeMemoIdentityKeyV2]) <= maximumHistoryDTOBytes &&
		proto.Equal(memo.Fields[RuntimeMemoIdentityKeyV2], expected)
}

func runtimeV2DispatchRemoteError(cause error) error {
	switch {
	case errors.Is(cause, context.Canceled):
		return runtimeV2DispatchError("workflow_start_unavailable", context.Canceled)
	case errors.Is(cause, context.DeadlineExceeded):
		return runtimeV2DispatchError("workflow_start_unavailable", context.DeadlineExceeded)
	default:
		return runtimeV2DispatchError("workflow_start_unavailable", errRuntimeV2StarterRemote)
	}
}

func runtimeV2DispatchError(code string, cause error) error {
	return outbox.NewDispatchError(code, cause)
}
