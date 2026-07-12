package investigationworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	workflowservicepb "go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/proto"
)

const (
	defaultTemporalNamespace = "default"
	maximumMemoPayloadBytes  = 2048
	temporalClientIdentity   = "aiops-investigation-preparation-v1"
)

var (
	errTemporalClientRejected = errors.New("investigation Temporal client rejected")
	errMemoIdentityRejected   = errors.New("investigation Temporal memo identity rejected")
	temporalClientSeal        = &temporalClientMarker{value: 1}
)

type temporalClientMarker struct{ value byte }

type temporalClientLifecycle struct {
	closeOnce sync.Once
	closed    atomic.Bool
	closeErr  error
}

type temporalStarterTransport interface {
	ExecuteWorkflow(context.Context, client.StartWorkflowOptions, interface{}, ...interface{}) (client.WorkflowRun, error)
	DescribeWorkflowExecution(context.Context, string, string) (*workflowservicepb.DescribeWorkflowExecutionResponse, error)
	FirstWorkflowHistoryEvent(context.Context, string, string) (*historypb.HistoryEvent, error)
}

type sdkStarterTransport struct{ client.Client }

func (transport *sdkStarterTransport) FirstWorkflowHistoryEvent(
	ctx context.Context,
	workflowID string,
	runID string,
) (*historypb.HistoryEvent, error) {
	iterator := transport.GetWorkflowHistory(
		ctx, workflowID, runID, false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT,
	)
	if iterator == nil || !iterator.HasNext() {
		return nil, errTemporalClientRejected
	}
	event, err := iterator.Next()
	if err != nil || event == nil {
		return nil, errTemporalClientRejected
	}
	return event, nil
}

// TemporalClient is the sealed client boundary shared by the preparation
// Starter and Worker. It can only be initialized by DialTemporalClient.
type TemporalClient struct {
	sdk       client.Client
	starter   temporalStarterTransport
	router    *memoRoutingDataConverter
	namespace string
	seal      *temporalClientMarker
	self      *TemporalClient
	lifecycle *temporalClientLifecycle
}

// DialTemporalClient installs the package-owned memo routing converter over
// Temporal's fixed default converter. Custom converter profiles are rejected
// until a profile digest can be bound to the task queue and workflow identity.
//
// Deprecated: this shared-role v1 compatibility path is test-only. A repository
// architecture gate requires zero production callsites; new assembly must use
// the separate Runtime v2 mTLS role capabilities.
func DialTemporalClient(ctx context.Context, options client.Options) (*TemporalClient, error) {
	if ctx == nil {
		return nil, errTemporalClientRejected
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateTemporalClientOptions(options); err != nil {
		return nil, err
	}
	if options.Namespace == "" {
		options.Namespace = defaultTemporalNamespace
	}
	options.Identity = temporalClientIdentity
	router, err := newMemoRoutingDataConverter(converter.GetDefaultDataConverter())
	if err != nil {
		return nil, err
	}
	options.DataConverter = router
	created, err := client.DialContext(ctx, options)
	if err != nil {
		return nil, err
	}
	if nilInterface(created) {
		return nil, errTemporalClientRejected
	}
	return newTemporalClient(&sdkStarterTransport{Client: created}, created, router, options.Namespace)
}

func validateTemporalClientOptions(options client.Options) error {
	if options.Namespace != "" && !temporalNamespacePattern.MatchString(options.Namespace) {
		return errTemporalClientRejected
	}
	if options.Identity != "" {
		return errTemporalClientRejected
	}
	if options.DataConverter != nil {
		return errTemporalClientRejected
	}
	if len(options.Plugins) != 0 || len(options.ExternalStorage.Drivers) != 0 ||
		options.ExternalStorage.DriverSelector != nil || options.ExternalStorage.PayloadSizeThreshold != 0 ||
		len(options.Interceptors) != 0 ||
		options.TrafficController != nil || len(options.ConnectionOptions.DialOptions) != 0 ||
		len(options.ContextPropagators) != 0 || options.FailureConverter != nil {
		return errTemporalClientRejected
	}
	return nil
}

func newTemporalClient(
	starter temporalStarterTransport,
	sdk client.Client,
	router *memoRoutingDataConverter,
	namespace string,
) (*TemporalClient, error) {
	if nilInterface(starter) || router == nil || nilInterface(router.delegate) ||
		!temporalNamespacePattern.MatchString(namespace) {
		return nil, errTemporalClientRejected
	}
	created := &TemporalClient{
		sdk: sdk, starter: starter, router: router, namespace: namespace, seal: temporalClientSeal,
		lifecycle: &temporalClientLifecycle{},
	}
	created.self = created
	return created, nil
}

func (temporalClient *TemporalClient) structurallyValidForStarter() bool {
	return temporalClient != nil && temporalClient.seal == temporalClientSeal &&
		temporalClient.self == temporalClient &&
		temporalClient.lifecycle != nil &&
		!nilInterface(temporalClient.starter) && temporalClient.router != nil &&
		!nilInterface(temporalClient.router.delegate) &&
		temporalNamespacePattern.MatchString(temporalClient.namespace)
}

func (temporalClient *TemporalClient) validForStarter() bool {
	return temporalClient.structurallyValidForStarter() && !temporalClient.lifecycle.closed.Load()
}

func (temporalClient *TemporalClient) structurallyValidForWorker() bool {
	return temporalClient.structurallyValidForStarter() && !nilInterface(temporalClient.sdk)
}

func (temporalClient *TemporalClient) validForWorker() bool {
	return temporalClient.structurallyValidForWorker() && !temporalClient.lifecycle.closed.Load()
}

// Close closes the underlying SDK client at most once and permanently makes
// this sealed client unusable by Starters and Workers.
func (temporalClient *TemporalClient) Close() error {
	if !temporalClient.structurallyValidForWorker() {
		return errTemporalClientRejected
	}
	lifecycle := temporalClient.lifecycle
	lifecycle.closeOnce.Do(func() {
		lifecycle.closed.Store(true)
		defer func() {
			if recover() != nil {
				lifecycle.closeErr = errTemporalClientRejected
			}
		}()
		temporalClient.sdk.Close()
	})
	return lifecycle.closeErr
}

func (*TemporalClient) String() string   { return "<aiops-temporal-client>" }
func (*TemporalClient) GoString() string { return "<aiops-temporal-client>" }

func (*TemporalClient) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-temporal-client>")
}

func (*TemporalClient) MarshalJSON() ([]byte, error) {
	return nil, errTemporalClientRejected
}

func (*TemporalClient) UnmarshalJSON([]byte) error {
	return errTemporalClientRejected
}

type memoIdentityV1 struct {
	payload *commonpb.Payload
}

// MarshalJSON intentionally rejects SDK fallback serialization. The routing
// converter must recognize this private type and return its canonical payload.
func (memoIdentityV1) MarshalJSON() ([]byte, error) {
	return nil, errMemoIdentityRejected
}

func (*memoIdentityV1) UnmarshalJSON([]byte) error {
	return errMemoIdentityRejected
}

func newMemoIdentity(input WorkflowInput) (memoIdentityV1, *commonpb.Payload, error) {
	payload, err := canonicalWorkflowInputPayload(input)
	if err != nil {
		return memoIdentityV1{}, nil, err
	}
	return memoIdentityV1{payload: proto.Clone(payload).(*commonpb.Payload)}, payload, nil
}

func canonicalWorkflowInputPayload(input WorkflowInput) (*commonpb.Payload, error) {
	if validateInput(input) != nil {
		return nil, errMemoIdentityRejected
	}
	wire, err := json.Marshal(input)
	if err != nil {
		return nil, errMemoIdentityRejected
	}
	canonical, err := jsoncanonicalizer.Transform(wire)
	if err != nil {
		return nil, errMemoIdentityRejected
	}
	payload := &commonpb.Payload{
		Metadata: map[string][]byte{converter.MetadataEncoding: []byte(converter.MetadataEncodingJSON)},
		Data:     canonical,
	}
	if _, err := decodeWorkflowInputPayload(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func decodeWorkflowInputPayload(payload *commonpb.Payload) (WorkflowInput, error) {
	if payload == nil || proto.Size(payload) > maximumMemoPayloadBytes || len(payload.Metadata) != 1 ||
		!bytes.Equal(payload.Metadata[converter.MetadataEncoding], []byte(converter.MetadataEncodingJSON)) {
		return WorkflowInput{}, errMemoIdentityRejected
	}
	var input WorkflowInput
	if err := json.Unmarshal(payload.Data, &input); err != nil || validateInput(input) != nil {
		return WorkflowInput{}, errMemoIdentityRejected
	}
	canonical, err := jsoncanonicalizer.Transform(payload.Data)
	if err != nil || !bytes.Equal(canonical, payload.Data) {
		return WorkflowInput{}, errMemoIdentityRejected
	}
	return input, nil
}

type memoRoutingDataConverter struct {
	delegate converter.DataConverter
}

var (
	_ converter.DataConverter                         = (*memoRoutingDataConverter)(nil)
	_ converter.DataConverterWithSerializationContext = (*memoRoutingDataConverter)(nil)
	_ workflow.ContextAware                           = (*memoRoutingDataConverter)(nil)
)

func newMemoRoutingDataConverter(delegate converter.DataConverter) (*memoRoutingDataConverter, error) {
	if nilInterface(delegate) {
		return nil, errTemporalClientRejected
	}
	if _, nested := delegate.(*memoRoutingDataConverter); nested {
		return nil, errTemporalClientRejected
	}
	return &memoRoutingDataConverter{delegate: delegate}, nil
}

func (dataConverter *memoRoutingDataConverter) ToPayload(value interface{}) (*commonpb.Payload, error) {
	if dataConverter == nil || nilInterface(dataConverter.delegate) {
		return nil, errTemporalClientRejected
	}
	if identity, ok := value.(memoIdentityV1); ok {
		if _, err := decodeWorkflowInputPayload(identity.payload); err != nil {
			return nil, errMemoIdentityRejected
		}
		return proto.Clone(identity.payload).(*commonpb.Payload), nil
	}
	if _, pointerIdentity := value.(*memoIdentityV1); pointerIdentity {
		return nil, errMemoIdentityRejected
	}
	switch input := value.(type) {
	case WorkflowInput:
		return canonicalWorkflowInputPayload(input)
	case *WorkflowInput:
		if input == nil {
			return nil, errMemoIdentityRejected
		}
		return canonicalWorkflowInputPayload(*input)
	}
	return dataConverter.delegate.ToPayload(value)
}

func (dataConverter *memoRoutingDataConverter) FromPayload(payload *commonpb.Payload, valuePtr interface{}) error {
	if dataConverter == nil || nilInterface(dataConverter.delegate) {
		return errTemporalClientRejected
	}
	if _, identity := valuePtr.(*memoIdentityV1); identity {
		return errMemoIdentityRejected
	}
	if input, ok := valuePtr.(*WorkflowInput); ok {
		if input == nil {
			return errMemoIdentityRejected
		}
		decoded, err := decodeWorkflowInputPayload(payload)
		if err != nil {
			return err
		}
		*input = decoded
		return nil
	}
	return dataConverter.delegate.FromPayload(payload, valuePtr)
}

func (dataConverter *memoRoutingDataConverter) ToPayloads(values ...interface{}) (*commonpb.Payloads, error) {
	if dataConverter == nil || nilInterface(dataConverter.delegate) {
		return nil, errTemporalClientRejected
	}
	for _, value := range values {
		switch value.(type) {
		case memoIdentityV1, *memoIdentityV1:
			return nil, errMemoIdentityRejected
		}
	}
	if len(values) == 1 {
		switch values[0].(type) {
		case WorkflowInput, *WorkflowInput:
			payload, err := dataConverter.ToPayload(values[0])
			if err != nil {
				return nil, err
			}
			return &commonpb.Payloads{Payloads: []*commonpb.Payload{payload}}, nil
		}
	}
	for _, value := range values {
		switch value.(type) {
		case WorkflowInput, *WorkflowInput:
			return nil, errMemoIdentityRejected
		}
	}
	return dataConverter.delegate.ToPayloads(values...)
}

func (dataConverter *memoRoutingDataConverter) FromPayloads(payloads *commonpb.Payloads, valuePtrs ...interface{}) error {
	if dataConverter == nil || nilInterface(dataConverter.delegate) {
		return errTemporalClientRejected
	}
	for _, valuePtr := range valuePtrs {
		if _, identity := valuePtr.(*memoIdentityV1); identity {
			return errMemoIdentityRejected
		}
	}
	if len(valuePtrs) == 1 {
		if _, ok := valuePtrs[0].(*WorkflowInput); ok {
			if payloads == nil || len(payloads.Payloads) != 1 {
				return errMemoIdentityRejected
			}
			return dataConverter.FromPayload(payloads.Payloads[0], valuePtrs[0])
		}
	}
	for _, valuePtr := range valuePtrs {
		if _, ok := valuePtr.(*WorkflowInput); ok {
			return errMemoIdentityRejected
		}
	}
	return dataConverter.delegate.FromPayloads(payloads, valuePtrs...)
}

func (dataConverter *memoRoutingDataConverter) ToString(payload *commonpb.Payload) string {
	if dataConverter == nil || nilInterface(dataConverter.delegate) {
		return "<temporal-payload-unavailable>"
	}
	return dataConverter.delegate.ToString(payload)
}

func (dataConverter *memoRoutingDataConverter) ToStrings(payloads *commonpb.Payloads) []string {
	if dataConverter == nil || nilInterface(dataConverter.delegate) {
		return nil
	}
	return dataConverter.delegate.ToStrings(payloads)
}

func (dataConverter *memoRoutingDataConverter) WithContext(ctx context.Context) converter.DataConverter {
	if dataConverter == nil || nilInterface(dataConverter.delegate) {
		return &memoRoutingDataConverter{}
	}
	delegate := dataConverter.delegate
	if aware, ok := delegate.(workflow.ContextAware); ok {
		delegate = aware.WithContext(ctx)
	}
	return &memoRoutingDataConverter{delegate: delegate}
}

func (dataConverter *memoRoutingDataConverter) WithWorkflowContext(ctx workflow.Context) converter.DataConverter {
	if dataConverter == nil || nilInterface(dataConverter.delegate) {
		return &memoRoutingDataConverter{}
	}
	delegate := dataConverter.delegate
	if aware, ok := delegate.(workflow.ContextAware); ok {
		delegate = aware.WithWorkflowContext(ctx)
	}
	return &memoRoutingDataConverter{delegate: delegate}
}

func (dataConverter *memoRoutingDataConverter) WithSerializationContext(ctx converter.SerializationContext) converter.DataConverter {
	if dataConverter == nil || nilInterface(dataConverter.delegate) {
		return &memoRoutingDataConverter{}
	}
	delegate := dataConverter.delegate
	if aware, ok := delegate.(converter.DataConverterWithSerializationContext); ok {
		delegate = aware.WithSerializationContext(ctx)
	}
	return &memoRoutingDataConverter{delegate: delegate}
}
