package investigationworkflow

import (
	"context"
	"time"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/grpc"
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

func RegisterRuntimeV2ForTest(registry RuntimeV2Registry, activities *RuntimeV2Activities) error {
	return registerRuntimeV2(registry, activities)
}

func NewRuntimeV2StarterForTest(
	roleClient *RuntimeV2StarterClient,
	manifestDigest string,
	registryDigest string,
	bundleDigest string,
) (*RuntimeV2Starter, error) {
	return newRuntimeV2Starter(roleClient, manifestDigest, registryDigest, bundleDigest)
}

func NewRuntimeV2ControlWorkerForTest(
	controlClient *RuntimeV2ControlClient,
	activities *RuntimeV2Activities,
	manifestDigest string,
	registryDigest string,
	bundleDigest string,
) (*RuntimeV2ControlWorker, error) {
	return newRuntimeV2ControlWorker(
		controlClient,
		activities,
		manifestDigest,
		registryDigest,
		bundleDigest,
		runtimeV2ProductionControlWorkerFactory,
	)
}

func NewRuntimeV2WorkflowReplayerForTest() (worker.WorkflowReplayer, error) {
	dataConverter, err := newRuntimeV2DataConverter()
	if err != nil {
		return nil, errRuntimeV2PayloadRejected
	}
	failureConverter, err := newRuntimeV2FailureConverter(dataConverter)
	if err != nil {
		return nil, errRuntimeV2FailureRejected
	}
	return worker.NewWorkflowReplayerWithOptions(worker.WorkflowReplayerOptions{
		DataConverter: dataConverter, FailureConverter: failureConverter,
		DisableRegistrationAliasing: true,
	})
}

// DialRuntimeV2PlaintextRolesForTest is a test-only bridge for the pinned
// plaintext Temporal dev server. Production callers only have the TLS 1.3
// mTLS dialers in runtime_v2_client.go.
func DialRuntimeV2PlaintextRolesForTest(
	ctx context.Context,
	address string,
	namespace string,
) (*RuntimeV2StarterClient, *RuntimeV2ControlClient, error) {
	if ctx == nil || address == "" || !temporalNamespacePattern.MatchString(namespace) {
		return nil, nil, errRuntimeV2ClientRejected
	}
	dataConverter, err := newRuntimeV2DataConverter()
	if err != nil {
		return nil, nil, errRuntimeV2ClientRejected
	}
	starterFailureConverter, err := newRuntimeV2FailureConverter(dataConverter)
	if err != nil {
		return nil, nil, errRuntimeV2ClientRejected
	}
	starterSDK, err := client.DialContext(ctx, client.Options{
		HostPort: address, Namespace: namespace, Identity: runtimeV2StarterIdentity,
		DataConverter: dataConverter, FailureConverter: starterFailureConverter,
		ConnectionOptions: client.ConnectionOptions{
			DialOptions: []grpc.DialOption{grpc.WithNoProxy()},
		},
	})
	if err != nil {
		return nil, nil, err
	}
	starter, err := newRuntimeV2StarterClient(
		&runtimeV2SDKStarterTransport{Client: starterSDK}, namespace,
	)
	if err != nil {
		starterSDK.Close()
		return nil, nil, errRuntimeV2ClientRejected
	}
	dataConverter, err = newRuntimeV2DataConverter()
	if err != nil {
		_ = starter.Close()
		return nil, nil, errRuntimeV2ClientRejected
	}
	controlFailureConverter, err := newRuntimeV2FailureConverter(dataConverter)
	if err != nil {
		_ = starter.Close()
		return nil, nil, errRuntimeV2ClientRejected
	}
	controlSDK, err := client.DialContext(ctx, client.Options{
		HostPort: address, Namespace: namespace, Identity: runtimeV2ControlIdentity,
		DataConverter: dataConverter, FailureConverter: controlFailureConverter,
		ConnectionOptions: client.ConnectionOptions{
			DialOptions: []grpc.DialOption{grpc.WithNoProxy()},
		},
	})
	if err != nil {
		_ = starter.Close()
		return nil, nil, err
	}
	control, err := newRuntimeV2ControlClient(controlSDK, namespace)
	if err != nil {
		controlSDK.Close()
		_ = starter.Close()
		return nil, nil, errRuntimeV2ClientRejected
	}
	return starter, control, nil
}

func PrepareActivityV2ForTest(
	activities *RuntimeV2Activities,
	ctx context.Context,
	input WorkflowInputV2,
) (PreparationReceiptV2, error) {
	return activities.prepareV2(ctx, input)
}
