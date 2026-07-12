package investigationworkflow

import (
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

func PreparationWorkflow(ctx workflow.Context, input WorkflowInput) (PreparationReceipt, error) {
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
	if info.WorkflowExecution.ID != input.OutboxEventID || info.WorkflowType.Name != WorkflowName || info.TaskQueueName != queue {
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
