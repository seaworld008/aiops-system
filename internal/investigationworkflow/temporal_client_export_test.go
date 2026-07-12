package investigationworkflow

import (
	"context"
	"time"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/proto"
)

// TemporalStarterTransportForTest exposes the narrow transport only to external
// package tests. Production callers cannot bypass DialTemporalClient.
type TemporalStarterTransportForTest = temporalStarterTransport

func NewTemporalClientForTest(
	transport TemporalStarterTransportForTest,
	delegate converter.DataConverter,
	namespace string,
) (*TemporalClient, error) {
	router, err := newMemoRoutingDataConverter(delegate)
	if err != nil {
		return nil, err
	}
	return newTemporalClient(transport, nil, router, namespace)
}

func MemoIdentityPayloadForTest(value interface{}) (*commonpb.Payload, bool) {
	identity, ok := value.(memoIdentityV1)
	if !ok || identity.payload == nil {
		return nil, false
	}
	return proto.Clone(identity.payload).(*commonpb.Payload), true
}

func CanonicalMemoPayloadForTest(input WorkflowInput) (*commonpb.Payload, error) {
	return canonicalWorkflowInputPayload(input)
}

func SDKClientForTest(temporalClient *TemporalClient) client.Client {
	if !temporalClient.validForWorker() {
		return nil
	}
	return temporalClient.sdk
}

func MemoIdentityValueForTest(input WorkflowInput) (interface{}, error) {
	identity, _, err := newMemoIdentity(input)
	if err != nil {
		return nil, err
	}
	return identity, nil
}

func TemporalClientIdentityForTest() string { return temporalClientIdentity }

func PreparationWorkflowForTest(ctx workflow.Context, input WorkflowInput) (PreparationReceipt, error) {
	info := workflow.GetInfo(ctx)
	info.WorkflowExecutionTimeout = 0
	info.WorkflowRunTimeout = 0
	info.WorkflowTaskTimeout = 10 * time.Second
	return preparationWorkflow(ctx, input)
}

var ProductionPreparationWorkflowForTest = preparationWorkflow

func PrepareActivityForTest(activities *Activities, ctx context.Context, input WorkflowInput) (PreparationReceipt, error) {
	return activities.prepareActivity(ctx, input)
}

func WorkerOptionsForTest() worker.Options { return workerOptions() }
