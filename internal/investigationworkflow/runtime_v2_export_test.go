package investigationworkflow

import (
	"context"
	"time"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/workflow"
)

func ReadWorkflowV2ForTest(ctx workflow.Context, input WorkflowInputV2) (WorkflowResultV2, error) {
	info := workflow.GetInfo(ctx)
	info.WorkflowExecutionTimeout = 0
	info.WorkflowRunTimeout = 0
	info.WorkflowTaskTimeout = 10 * time.Second
	info.WorkflowExecution.RunID = "99999999-9999-4999-8999-999999999999"
	info.Namespace = "default"
	return readWorkflowV2ForNamespace(ctx, input, "default")
}

func ProductionReadWorkflowV2ForTest(ctx workflow.Context, input WorkflowInputV2) (WorkflowResultV2, error) {
	return readWorkflowV2ForNamespace(ctx, input, "default")
}

func CanonicalWorkflowInputV2PayloadForTest(input WorkflowInputV2) (*commonpb.Payload, error) {
	return canonicalWorkflowInputV2Payload(input)
}

func PrepareActivityV2ForTest(
	activities *RuntimeV2Activities,
	ctx context.Context,
	input WorkflowInputV2,
) (PreparationReceiptV2, error) {
	return activities.prepareV2(ctx, input)
}
