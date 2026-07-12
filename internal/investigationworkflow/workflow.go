package investigationworkflow

import (
	"time"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/proto"
)

func preparationWorkflow(ctx workflow.Context, input WorkflowInput) (PreparationReceipt, error) {
	if err := validateInput(input); err != nil {
		return PreparationReceipt{}, temporal.NewNonRetryableApplicationError(
			"investigation preparation input rejected", "PREPARE_INPUT_INVALID", nil,
		)
	}
	queue, err := TaskQueue(input.ManifestDigest, input.RegistryDigest)
	if err != nil {
		return PreparationReceipt{}, temporal.NewNonRetryableApplicationError(
			"investigation preparation input rejected", "PREPARE_INPUT_INVALID", nil,
		)
	}
	info := workflow.GetInfo(ctx)
	expectedIdentity, err := canonicalWorkflowInputPayload(input)
	if err != nil || !validWorkflowExecutionInfo(info, input, queue, expectedIdentity) {
		return PreparationReceipt{}, temporal.NewNonRetryableApplicationError(
			"investigation preparation execution rejected", "PREPARE_EXECUTION_MISMATCH", nil,
		)
	}
	activityContext, _ := workflow.NewDisconnectedContext(ctx)
	activityContext = workflow.WithActivityOptions(activityContext, workflow.ActivityOptions{
		TaskQueue:           queue,
		ActivityID:          "prepare-" + input.OutboxEventID,
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    time.Second,
			BackoffCoefficient: 2,
			MaximumInterval:    15 * time.Second,
			MaximumAttempts:    0,
			NonRetryableErrorTypes: []string{
				"PREPARE_INPUT_INVALID", "PREPARE_FACT_CONFLICT", "PREPARE_INTEGRITY_REJECTED", "PREPARE_RECEIPT_INVALID",
			},
		},
		WaitForCancellation: true,
	})
	var receipt PreparationReceipt
	if err := workflow.ExecuteActivity(activityContext, ActivityName, input).Get(activityContext, &receipt); err != nil {
		return PreparationReceipt{}, err
	}
	if err := validateReceipt(input, receipt); err != nil {
		return PreparationReceipt{}, temporal.NewNonRetryableApplicationError(
			"investigation preparation receipt rejected", "PREPARE_RECEIPT_INVALID", nil,
		)
	}
	return receipt, nil
}

func validWorkflowExecutionInfo(info *workflow.Info, input WorkflowInput, queue string, expectedIdentity *commonpb.Payload) bool {
	return info != nil && info.WorkflowExecution.ID == input.OutboxEventID &&
		info.WorkflowExecution.RunID != "" && temporalNamespacePattern.MatchString(info.Namespace) &&
		info.WorkflowType.Name == WorkflowName && info.TaskQueueName == queue &&
		info.WorkflowExecutionTimeout == 0 && info.WorkflowRunTimeout == 0 && info.WorkflowTaskTimeout == 10*time.Second &&
		info.Attempt == 1 && info.RetryPolicy == nil && info.CronSchedule == "" && info.ContinuedExecutionRunID == "" &&
		info.ParentWorkflowNamespace == "" && info.ParentWorkflowExecution == nil && info.RootWorkflowExecution == nil &&
		(info.SearchAttributes == nil || len(info.SearchAttributes.IndexedFields) == 0) &&
		info.Priority.PriorityKey == 0 && info.Priority.FairnessKey == "" && info.Priority.FairnessWeight == 0 &&
		info.Memo != nil && len(info.Memo.Fields) == 1 && info.Memo.Fields[MemoIdentityKey] != nil &&
		proto.Size(info.Memo.Fields[MemoIdentityKey]) <= maximumMemoPayloadBytes &&
		proto.Equal(info.Memo.Fields[MemoIdentityKey], expectedIdentity)
}
